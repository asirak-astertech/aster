//! Infrastructure-free UDP link, local discovery, NAT rendezvous, and optional
//! opaque ciphertext relay for the Aster protocol.
//!
//! The adapter never interprets protocol content. Inbound DATA remains
//! unauthenticated carrier input until the core runtime verifies its handshake
//! flight or protected session record.

#![forbid(unsafe_code)]

mod relay;

pub use relay::{CipherRelayServer, RelayLink};

use aster_mesh::link::{Link, LinkCharacteristics, ReceivedFrame};
use aster_mesh::model::NodeId;
use hkdf::Hkdf;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

const DATA: u8 = 0;
const DISCOVERY: u8 = 1;
const RENDEZVOUS_REGISTER: u8 = 2;
const RENDEZVOUS_PEER: u8 = 3;
const PUNCH: u8 = 4;
const DISCOVERY_CHALLENGE: u8 = 5;
const DISCOVERY_RESPONSE: u8 = 6;
const MAX_DATAGRAM: usize = 65_507;
const DISCOVERY_PACKET_LEN: usize = 64;
const DISCOVERY_ANNOUNCEMENT_BODY_LEN: usize = 33;
const DISCOVERY_CONFIRMATION_BODY_LEN: usize = 49;
const MAX_DATAGRAMS_PER_POLL: usize = 64;
const MAX_PEERS: usize = 4_096;
const MAX_DISCOVERED: usize = 4_096;
const MAX_RECENT_ANNOUNCEMENTS: usize = 128;
const MAX_PENDING_DISCOVERY: usize = 256;
const MAX_PENDING_DISCOVERY_PER_SOURCE: usize = 8;
const MAX_DISCOVERY_RESPONSES: usize = 1_024;
const MAX_DISCOVERY_RESPONSES_PER_SOURCE: usize = 32;
const MAX_PUNCH_TOKENS: usize = 128;
const MAX_RENDEZVOUS_WAITING: usize = 4_096;
const MAX_RENDEZVOUS_WAITING_PER_SOURCE: usize = 64;
const MAX_RENDEZVOUS_DATAGRAMS_PER_POLL: usize = 64;
const RENDEZVOUS_REGISTER_LEN: usize = 160;
const RENDEZVOUS_PUNCH_LEN: usize = 33;
const CONSERVATIVE_UDP_IP_HEADER_LEN: usize = 48;
const RENDEZVOUS_MAX_PEER_RESPONSE_LEN: usize = 52;
const RENDEZVOUS_RESPONSE_BURST_BYTES: u64 = 4_096;
const RENDEZVOUS_RESPONSE_REFILL_BYTES_PER_SECOND: u64 = 1_024;
const MAX_RENDEZVOUS_RESPONSE_SOURCES: usize = 4_096;
const RENDEZVOUS_SOURCE_RESPONSE_BURST_BYTES: u64 = 1_024;
const RENDEZVOUS_SOURCE_RESPONSE_REFILL_BYTES_PER_SECOND: u64 = 256;
const RENDEZVOUS_SOURCE_RESPONSE_TTL: Duration = Duration::from_secs(120);
const NANOS_PER_SECOND: u128 = 1_000_000_000;
const _: () = assert!(
    RENDEZVOUS_REGISTER_LEN + CONSERVATIVE_UDP_IP_HEADER_LEN
        >= RENDEZVOUS_MAX_PEER_RESPONSE_LEN
            + RENDEZVOUS_PUNCH_LEN
            + (2 * CONSERVATIVE_UDP_IP_HEADER_LEN)
);
const DISCOVERY_STATE_TTL: Duration = Duration::from_secs(30);
const RENDEZVOUS_REGISTRATION_TTL: Duration = Duration::from_secs(120);
const DISCOVERY_PROOF_DOMAIN: &[u8] = b"aster/ip-discovery-proof/v1";
const DISCOVERY_CONFIRMATION_DOMAIN: &[u8] = b"aster/ip-discovery-confirmation/v1";
const ENDPOINT_HANDLE_DOMAIN: &[u8] = b"aster/ip-endpoint-handle/v1";

type PendingDiscoveryKey = (SocketAddr, [u8; 16]);
type DiscoveryResponseKey = (SocketAddr, [u8; 16], [u8; 16]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DiscoveryConfirmationRole {
    Challenge = 1,
    Response = 2,
}

#[derive(Clone, Copy, Debug)]
struct PendingDiscovery {
    source: SocketAddr,
    challenge: [u8; 16],
    issued_at: Instant,
}

#[derive(Clone, Copy, Debug)]
struct DiscoveryResponse {
    source: IpAddr,
    emitted_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClientRendezvous {
    issued_at: Instant,
    server: Option<SocketAddr>,
    response_pending: bool,
    expected_peer: Option<SocketAddr>,
    allow_unbound_punch: bool,
}

/// Opaque high-entropy value used only to pair rendezvous registrations.
pub type RendezvousToken = [u8; 32];

/// Nonblocking UDP adapter with manual and local-discovery paths.
#[derive(Debug)]
pub struct IpLink {
    name: String,
    socket: UdpSocket,
    peers: RwLock<BTreeMap<NodeId, SocketAddr>>,
    reverse_peers: RwLock<BTreeMap<SocketAddr, NodeId>>,
    discovered: Mutex<BTreeSet<SocketAddr>>,
    recent_announcements: Mutex<BTreeMap<[u8; 16], Instant>>,
    pending_discovery: Mutex<BTreeMap<PendingDiscoveryKey, PendingDiscovery>>,
    discovery_responses: Mutex<BTreeMap<DiscoveryResponseKey, DiscoveryResponse>>,
    rendezvous_attempts: Mutex<BTreeMap<RendezvousToken, ClientRendezvous>>,
    discovery_token: [u8; 16],
    endpoint_handle_seed: [u8; 32],
    discovery_target: Option<SocketAddr>,
    discovery_enabled: AtomicBool,
}

impl IpLink {
    /// Binds a nonblocking UDP link.
    ///
    /// `discovery_token` is provisioned opaque material, not an identity. It is
    /// never transmitted: each advertisement carries a fresh nonce and HKDF
    /// proof. An endpoint becomes a discovery candidate only after it answers a
    /// receiver-chosen challenge from the same source socket. A zero token is
    /// rejected so an unprovisioned default cannot form a group.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when binding or configuring the socket fails, or
    /// `InvalidInput` for a zero discovery token.
    pub fn bind(
        name: impl Into<String>,
        address: SocketAddr,
        discovery_token: [u8; 16],
        discovery_target: Option<SocketAddr>,
    ) -> io::Result<Self> {
        if discovery_token == [0; 16] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "discovery token must be provisioned",
            ));
        }
        let socket = UdpSocket::bind(address)?;
        socket.set_nonblocking(true)?;
        let mut endpoint_handle_seed = [0u8; 32];
        getrandom::fill(&mut endpoint_handle_seed).map_err(io::Error::other)?;
        if let Some(SocketAddr::V4(target)) = discovery_target
            && target.ip().is_multicast()
        {
            socket.join_multicast_v4(target.ip(), &Ipv4Addr::UNSPECIFIED)?;
            socket.set_multicast_loop_v4(true)?;
        }
        Ok(Self {
            name: name.into(),
            socket,
            peers: RwLock::new(BTreeMap::new()),
            reverse_peers: RwLock::new(BTreeMap::new()),
            discovered: Mutex::new(BTreeSet::new()),
            recent_announcements: Mutex::new(BTreeMap::new()),
            pending_discovery: Mutex::new(BTreeMap::new()),
            discovery_responses: Mutex::new(BTreeMap::new()),
            rendezvous_attempts: Mutex::new(BTreeMap::new()),
            discovery_token,
            endpoint_handle_seed,
            discovery_target,
            discovery_enabled: AtomicBool::new(true),
        })
    }

    /// Returns the bound local address.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the operating system cannot report the address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Adds a manually provisioned or authenticated peer endpoint.
    pub fn register_peer(&self, peer: NodeId, address: SocketAddr) -> io::Result<()> {
        let mut peers = self.peers.write().map_err(lock_error)?;
        let mut reverse = self.reverse_peers.write().map_err(lock_error)?;
        let address_owner = reverse.get(&address).copied();
        if !peers.contains_key(&peer) && address_owner.is_none() && peers.len() >= MAX_PEERS {
            return Err(io::Error::other("IP peer capacity reached"));
        }
        if let Some(previous) = peers.insert(peer, address)
            && previous != address
        {
            reverse.remove(&previous);
        }
        if let Some(previous_peer) = address_owner
            && previous_peer != peer
        {
            peers.remove(&previous_peer);
        }
        reverse.insert(address, peer);
        Ok(())
    }

    /// Removes a peer endpoint.
    pub fn remove_peer(&self, peer: &NodeId) {
        let mut peers = self
            .peers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(address) = peers.remove(peer) {
            self.reverse_peers
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&address);
        }
    }

    /// Returns a process-local routing handle for a discovered endpoint.
    ///
    /// The handle occupies the `NodeId`-shaped slot required by [`Link`], but it
    /// is never treated as an authenticated identity. The hybrid session yields
    /// the actual identity independently. Repeated calls for one endpoint are
    /// stable only for this adapter instance.
    pub fn register_endpoint(&self, address: SocketAddr) -> io::Result<NodeId> {
        if let Some(handle) = self
            .reverse_peers
            .read()
            .map_err(lock_error)?
            .get(&address)
            .copied()
        {
            return Ok(handle);
        }
        let encoded = encode_socket_addr(address);
        for counter in 0..16u8 {
            let hkdf =
                Hkdf::<Sha256>::new(Some(ENDPOINT_HANDLE_DOMAIN), &self.endpoint_handle_seed);
            let mut info = encoded.clone();
            info.push(counter);
            let mut handle = [0u8; 32];
            hkdf.expand(&info, &mut handle)
                .map_err(|_| io::Error::other("IP endpoint handle derivation failed"))?;
            if handle != [0; 32] {
                if self
                    .peers
                    .read()
                    .map_err(lock_error)?
                    .get(&handle)
                    .is_some_and(|candidate| candidate != &address)
                {
                    continue;
                }
                self.register_peer(handle, address)?;
                return Ok(handle);
            }
        }
        Err(io::Error::other("could not allocate IP endpoint handle"))
    }

    /// Broadcasts an opaque local-discovery advertisement once.
    ///
    /// # Errors
    ///
    /// Returns `PermissionDenied` when discovery is disabled, `NotConnected`
    /// without a discovery target, or an operating-system send error.
    pub fn announce(&self) -> io::Result<()> {
        if !self.discovery_enabled.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "discovery disabled by emission policy",
            ));
        }
        let target = self
            .discovery_target
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no discovery target"))?;
        let now = Instant::now();
        let mut announcements = self.recent_announcements.lock().map_err(lock_error)?;
        retain_fresh(&mut announcements, now);
        if announcements.len() >= MAX_RECENT_ANNOUNCEMENTS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "recent discovery-announcement capacity reached",
            ));
        }
        let mut nonce = [0_u8; 16];
        for _ in 0..4 {
            getrandom::fill(&mut nonce).map_err(io::Error::other)?;
            if !announcements.contains_key(&nonce) {
                break;
            }
        }
        if announcements.contains_key(&nonce) {
            return Err(io::Error::other(
                "could not allocate unique discovery nonce",
            ));
        }
        let proof = discovery_proof(&self.discovery_token, &nonce)?;
        let mut packet = [0_u8; DISCOVERY_PACKET_LEN];
        packet[0] = DISCOVERY;
        packet[1..17].copy_from_slice(&nonce);
        packet[17..DISCOVERY_ANNOUNCEMENT_BODY_LEN].copy_from_slice(&proof);
        announcements.insert(nonce, now);
        drop(announcements);
        if let Err(error) = self.socket.send_to(&packet, target) {
            self.recent_announcements
                .lock()
                .map_err(lock_error)?
                .remove(&nonce);
            return Err(error);
        }
        Ok(())
    }

    /// Drains endpoints that completed discovery confirmation under the
    /// provisioned opaque token.
    pub fn take_discovered(&self) -> Vec<SocketAddr> {
        let mut discovered = self
            .discovered
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = discovered.iter().copied().collect();
        discovered.clear();
        result
    }

    /// Registers a high-entropy token accepted for an incoming NAT punch.
    pub fn accept_punch(&self, token: RendezvousToken) -> io::Result<()> {
        if token == [0; 32] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "NAT punch token must be random",
            ));
        }
        let now = Instant::now();
        let mut attempts = self.rendezvous_attempts.lock().map_err(lock_error)?;
        retain_client_rendezvous(&mut attempts, now);
        if !attempts.contains_key(&token) && attempts.len() >= MAX_PUNCH_TOKENS {
            return Err(io::Error::other("NAT punch-token capacity reached"));
        }
        attempts
            .entry(token)
            .and_modify(|attempt| attempt.allow_unbound_punch = true)
            .or_insert(ClientRendezvous {
                issued_at: now,
                server: None,
                response_pending: false,
                expected_peer: None,
                allow_unbound_punch: true,
            });
        Ok(())
    }

    /// Sends a strict, zero-padded 160-byte rendezvous registration from this
    /// exact UDP socket. A server sees the translated endpoint and returns
    /// another registration's endpoint.
    ///
    /// The token is an opaque pairing value, not authentication. The mandatory
    /// core handshake authenticates the resulting path.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the datagram cannot be sent.
    pub fn request_rendezvous(&self, server: SocketAddr, token: RendezvousToken) -> io::Result<()> {
        if token == [0; 32] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "rendezvous token must be random",
            ));
        }
        let now = Instant::now();
        let mut attempts = self.rendezvous_attempts.lock().map_err(lock_error)?;
        retain_client_rendezvous(&mut attempts, now);
        let previous_attempt = attempts.get(&token).copied();
        if previous_attempt.is_none() && attempts.len() >= MAX_PUNCH_TOKENS {
            return Err(io::Error::other("NAT punch-token capacity reached"));
        }
        attempts.insert(
            token,
            ClientRendezvous {
                issued_at: now,
                server: Some(server),
                response_pending: true,
                expected_peer: None,
                allow_unbound_punch: false,
            },
        );
        let packet = rendezvous_registration_packet(token);
        match self.socket.send_to(&packet, server) {
            Ok(_) => Ok(()),
            Err(error) => {
                match previous_attempt {
                    Some(previous) => {
                        attempts.insert(token, previous);
                    }
                    None => {
                        attempts.remove(&token);
                    }
                }
                Err(error)
            }
        }
    }

    fn process_control(&self, source: SocketAddr, packet: &[u8]) -> io::Result<bool> {
        match packet.first().copied() {
            Some(DISCOVERY) => {
                if !self.discovery_enabled.load(Ordering::Acquire) {
                    return Ok(true);
                }
                if !valid_discovery_padding(packet, DISCOVERY_ANNOUNCEMENT_BODY_LEN) {
                    return Ok(true);
                }
                let mut nonce = [0_u8; 16];
                nonce.copy_from_slice(&packet[1..17]);
                if bool::from(
                    discovery_proof(&self.discovery_token, &nonce)?
                        .as_slice()
                        .ct_eq(&packet[17..DISCOVERY_ANNOUNCEMENT_BODY_LEN]),
                ) {
                    self.challenge_discovery(source, nonce)?;
                }
                Ok(true)
            }
            Some(DISCOVERY_CHALLENGE) => {
                if !self.discovery_enabled.load(Ordering::Acquire) {
                    return Ok(true);
                }
                if !valid_discovery_padding(packet, DISCOVERY_CONFIRMATION_BODY_LEN) {
                    return Ok(true);
                }
                let mut announcement = [0_u8; 16];
                announcement.copy_from_slice(&packet[1..17]);
                let mut challenge = [0_u8; 16];
                challenge.copy_from_slice(&packet[17..33]);
                let expected = discovery_confirmation_proof(
                    &self.discovery_token,
                    DiscoveryConfirmationRole::Challenge,
                    &announcement,
                    &challenge,
                )?;
                if bool::from(
                    expected
                        .as_slice()
                        .ct_eq(&packet[33..DISCOVERY_CONFIRMATION_BODY_LEN]),
                ) {
                    self.answer_discovery_challenge(source, announcement, challenge)?;
                }
                Ok(true)
            }
            Some(DISCOVERY_RESPONSE) => {
                if !self.discovery_enabled.load(Ordering::Acquire) {
                    return Ok(true);
                }
                if !valid_discovery_padding(packet, DISCOVERY_CONFIRMATION_BODY_LEN) {
                    return Ok(true);
                }
                let mut announcement = [0_u8; 16];
                announcement.copy_from_slice(&packet[1..17]);
                let mut challenge = [0_u8; 16];
                challenge.copy_from_slice(&packet[17..33]);
                let expected = discovery_confirmation_proof(
                    &self.discovery_token,
                    DiscoveryConfirmationRole::Response,
                    &announcement,
                    &challenge,
                )?;
                if bool::from(
                    expected
                        .as_slice()
                        .ct_eq(&packet[33..DISCOVERY_CONFIRMATION_BODY_LEN]),
                ) && self.confirm_discovery(source, announcement, challenge)?
                {
                    self.remember_discovered(source)?;
                }
                Ok(true)
            }
            Some(RENDEZVOUS_PEER) => {
                if packet.len() < 34 {
                    return Ok(true);
                }
                let mut token = [0_u8; 32];
                token.copy_from_slice(&packet[1..33]);
                let peer = match decode_socket_addr(&packet[33..]) {
                    Ok(peer) => peer,
                    Err(_) => return Ok(true),
                };
                let now = Instant::now();
                let mut attempts = self.rendezvous_attempts.lock().map_err(lock_error)?;
                retain_client_rendezvous(&mut attempts, now);
                let Some(attempt) = attempts.get_mut(&token) else {
                    return Ok(true);
                };
                if attempt.server != Some(source) || !attempt.response_pending {
                    return Ok(true);
                }
                attempt.response_pending = false;
                attempt.expected_peer = Some(peer);
                attempt.allow_unbound_punch = false;
                drop(attempts);
                let mut punch = [0_u8; 33];
                punch[0] = PUNCH;
                punch[1..].copy_from_slice(&token);
                self.socket.send_to(&punch, peer)?;
                self.remember_discovered(peer)?;
                Ok(true)
            }
            Some(PUNCH) if packet.len() == 33 => {
                let mut token = [0_u8; 32];
                token.copy_from_slice(&packet[1..]);
                let now = Instant::now();
                let mut attempts = self.rendezvous_attempts.lock().map_err(lock_error)?;
                retain_client_rendezvous(&mut attempts, now);
                let accepted = attempts.get(&token).is_some_and(|attempt| {
                    attempt.allow_unbound_punch || attempt.expected_peer == Some(source)
                });
                if accepted {
                    attempts.remove(&token);
                    drop(attempts);
                    self.remember_discovered(source)?;
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn challenge_discovery(&self, source: SocketAddr, announcement: [u8; 16]) -> io::Result<()> {
        let now = Instant::now();
        let mut pending = self.pending_discovery.lock().map_err(lock_error)?;
        retain_pending(&mut pending, now);
        let source_ip = canonical_ip(source.ip());
        let source_count = pending
            .values()
            .filter(|candidate| canonical_ip(candidate.source.ip()) == source_ip)
            .count();
        let pending_key = (source, announcement);
        if pending.contains_key(&pending_key)
            || pending.len() >= MAX_PENDING_DISCOVERY
            || source_count >= MAX_PENDING_DISCOVERY_PER_SOURCE
        {
            return Ok(());
        }

        let mut challenge = [0_u8; 16];
        getrandom::fill(&mut challenge).map_err(io::Error::other)?;
        let proof = discovery_confirmation_proof(
            &self.discovery_token,
            DiscoveryConfirmationRole::Challenge,
            &announcement,
            &challenge,
        )?;
        let packet =
            discovery_confirmation_packet(DISCOVERY_CHALLENGE, announcement, challenge, proof);
        pending.insert(
            pending_key,
            PendingDiscovery {
                source,
                challenge,
                issued_at: now,
            },
        );
        if let Err(error) = self.socket.send_to(&packet, source) {
            pending.remove(&pending_key);
            return Err(error);
        }
        Ok(())
    }

    fn answer_discovery_challenge(
        &self,
        source: SocketAddr,
        announcement: [u8; 16],
        challenge: [u8; 16],
    ) -> io::Result<()> {
        let now = Instant::now();
        let mut announcements = self.recent_announcements.lock().map_err(lock_error)?;
        retain_fresh(&mut announcements, now);
        if !announcements.contains_key(&announcement) {
            return Ok(());
        }
        drop(announcements);

        let response_key = (source, announcement, challenge);
        let mut responses = self.discovery_responses.lock().map_err(lock_error)?;
        retain_responses(&mut responses, now);
        let source_ip = canonical_ip(source.ip());
        let source_count = responses
            .values()
            .filter(|response| response.source == source_ip)
            .count();
        if responses.contains_key(&response_key)
            || responses.len() >= MAX_DISCOVERY_RESPONSES
            || source_count >= MAX_DISCOVERY_RESPONSES_PER_SOURCE
        {
            return Ok(());
        }
        let proof = discovery_confirmation_proof(
            &self.discovery_token,
            DiscoveryConfirmationRole::Response,
            &announcement,
            &challenge,
        )?;
        let packet =
            discovery_confirmation_packet(DISCOVERY_RESPONSE, announcement, challenge, proof);
        responses.insert(
            response_key,
            DiscoveryResponse {
                source: source_ip,
                emitted_at: now,
            },
        );
        if let Err(error) = self.socket.send_to(&packet, source) {
            responses.remove(&response_key);
            return Err(error);
        }
        Ok(())
    }

    fn confirm_discovery(
        &self,
        source: SocketAddr,
        announcement: [u8; 16],
        challenge: [u8; 16],
    ) -> io::Result<bool> {
        let now = Instant::now();
        let mut pending = self.pending_discovery.lock().map_err(lock_error)?;
        retain_pending(&mut pending, now);
        let pending_key = (source, announcement);
        if pending
            .get(&pending_key)
            .is_some_and(|candidate| candidate.challenge == challenge)
        {
            pending.remove(&pending_key);
            return Ok(true);
        }
        Ok(false)
    }

    fn remember_discovered(&self, source: SocketAddr) -> io::Result<()> {
        let mut discovered = self.discovered.lock().map_err(lock_error)?;
        if discovered.contains(&source) || discovered.len() < MAX_DISCOVERED {
            discovered.insert(source);
        }
        Ok(())
    }
}

impl Drop for IpLink {
    fn drop(&mut self) {
        self.discovery_token.fill(0);
        self.endpoint_handle_seed.fill(0);
        if let Ok(attempts) = self.rendezvous_attempts.get_mut() {
            for (mut token, _) in std::mem::take(attempts) {
                token.fill(0);
            }
        }
    }
}

impl Link for IpLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn characteristics(&self) -> LinkCharacteristics {
        LinkCharacteristics {
            mtu: 1_200,
            bits_per_second: None,
            cost: 16,
            emission: 32,
            broadcast: self.discovery_target.is_some(),
        }
    }

    fn send(&self, peer: Option<NodeId>, frame: &[u8]) -> io::Result<()> {
        if frame.len() + 1 > MAX_DATAGRAM {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame exceeds UDP datagram limit",
            ));
        }
        let target = if let Some(peer) = peer {
            self.peers
                .read()
                .map_err(lock_error)?
                .get(&peer)
                .copied()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "unknown peer"))?
        } else {
            self.discovery_target.ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "broadcast unavailable")
            })?
        };
        let mut packet = Vec::with_capacity(frame.len() + 1);
        packet.push(DATA);
        packet.extend_from_slice(frame);
        self.socket.send_to(&packet, target)?;
        Ok(())
    }

    fn try_receive(&self) -> io::Result<Option<ReceivedFrame>> {
        let mut packet = [0_u8; MAX_DATAGRAM];
        for _ in 0..MAX_DATAGRAMS_PER_POLL {
            match self.socket.recv_from(&mut packet) {
                Ok((length, source)) if length > 0 => {
                    let packet = &packet[..length];
                    if self.process_control(source, packet)? {
                        continue;
                    }
                    if packet[0] != DATA {
                        continue;
                    }
                    // Discovery and rendezvous only identify endpoint candidates. A DATA
                    // source becomes admissible after explicit peer or endpoint registration.
                    let peer = self
                        .reverse_peers
                        .read()
                        .map_err(lock_error)?
                        .get(&source)
                        .copied();
                    let Some(peer) = peer else {
                        continue;
                    };
                    return Ok(Some(ReceivedFrame {
                        peer: Some(peer),
                        bytes: packet[1..].to_vec(),
                    }));
                }
                Ok(_) => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
                Err(error) => return Err(error),
            }
        }
        Ok(None)
    }

    fn set_discovery(&self, enabled: bool) -> io::Result<()> {
        self.discovery_enabled.store(enabled, Ordering::Release);
        if !enabled {
            self.recent_announcements
                .lock()
                .map_err(lock_error)?
                .clear();
            self.pending_discovery.lock().map_err(lock_error)?.clear();
            self.discovery_responses.lock().map_err(lock_error)?.clear();
        }
        Ok(())
    }

    fn next_wakeup(&self) -> Option<Instant> {
        None
    }

    fn retry_floor(&self) -> Duration {
        Duration::from_millis(100)
    }
}

/// Minimal UDP rendezvous service. It exchanges observed endpoints for two
/// clients presenting the same opaque token; it never receives mesh payloads.
///
/// Registrations are fixed 160-byte datagrams. With a conservative 48-byte
/// UDP/IP header, one 208-byte request exceeds a worst-case 52-byte peer response
/// plus a 33-byte punch and two such headers (181 bytes). Waiting state is
/// bounded at 4,096 entries and 64 per canonical source IP; IPv4 and its
/// IPv4-mapped IPv6 form share the same count. A global 4,096-byte response
/// bucket refills at 1,024 bytes per second. Each distinct canonical source in a
/// pair is also charged the full pair against a 1,024-byte bucket refilling at
/// 256 bytes per second; same-IP pairs are charged once. Source-budget state is
/// capped at 4,096 entries and expires after 120 idle seconds. No destination
/// bucket is retained. These controls limit reflection but cannot prove a UDP
/// source address was not spoofed; public deployments should retain edge
/// anti-spoofing and rate controls. Large shared-NAT deployments share the
/// per-source quota and response budget.
#[derive(Clone, Copy, Debug)]
struct RendezvousRegistration {
    source: SocketAddr,
    registered_at: Instant,
}

#[derive(Debug)]
struct RendezvousResponseBudget {
    available_bytes: u64,
    capacity_bytes: u64,
    refill_bytes_per_second: u64,
    last_refill: Instant,
    refill_remainder: u128,
}

impl RendezvousResponseBudget {
    fn new(capacity_bytes: u64, refill_bytes_per_second: u64, now: Instant) -> Self {
        Self {
            available_bytes: capacity_bytes,
            capacity_bytes,
            refill_bytes_per_second,
            last_refill: now,
            refill_remainder: 0,
        }
    }

    fn global(now: Instant) -> Self {
        Self::new(
            RENDEZVOUS_RESPONSE_BURST_BYTES,
            RENDEZVOUS_RESPONSE_REFILL_BYTES_PER_SECOND,
            now,
        )
    }

    fn source(now: Instant) -> Self {
        Self::new(
            RENDEZVOUS_SOURCE_RESPONSE_BURST_BYTES,
            RENDEZVOUS_SOURCE_RESPONSE_REFILL_BYTES_PER_SECOND,
            now,
        )
    }

    #[cfg(test)]
    fn take(&mut self, bytes: usize, now: Instant) -> bool {
        self.refill(now);
        let Ok(bytes) = u64::try_from(bytes) else {
            return false;
        };
        if self.available_bytes < bytes {
            return false;
        }
        self.available_bytes -= bytes;
        true
    }

    fn can_take(&self, bytes: u64) -> bool {
        self.available_bytes >= bytes
    }

    fn deduct(&mut self, bytes: u64) {
        debug_assert!(self.can_take(bytes));
        self.available_bytes -= bytes;
    }

    fn refill(&mut self, now: Instant) {
        if now <= self.last_refill {
            return;
        }
        if self.available_bytes == self.capacity_bytes {
            self.last_refill = now;
            self.refill_remainder = 0;
            return;
        }
        let scaled = now
            .saturating_duration_since(self.last_refill)
            .as_nanos()
            .saturating_mul(u128::from(self.refill_bytes_per_second))
            .saturating_add(self.refill_remainder);
        let added = scaled / NANOS_PER_SECOND;
        self.refill_remainder = scaled % NANOS_PER_SECOND;
        self.last_refill = now;
        self.available_bytes = self
            .available_bytes
            .saturating_add(u64::try_from(added).unwrap_or(u64::MAX))
            .min(self.capacity_bytes);
        if self.available_bytes == self.capacity_bytes {
            self.refill_remainder = 0;
        }
    }
}

#[derive(Debug)]
struct RendezvousSourceResponseBudget {
    budget: RendezvousResponseBudget,
    last_used: Instant,
}

impl RendezvousSourceResponseBudget {
    fn new(now: Instant) -> Self {
        Self {
            budget: RendezvousResponseBudget::source(now),
            last_used: now,
        }
    }

    fn touch(&mut self, now: Instant) {
        self.budget.refill(now);
        if now > self.last_used {
            self.last_used = now;
        }
    }
}

#[derive(Debug)]
pub struct RendezvousServer {
    socket: UdpSocket,
    waiting: BTreeMap<RendezvousToken, RendezvousRegistration>,
    source_counts: BTreeMap<IpAddr, usize>,
    response_budget: RendezvousResponseBudget,
    source_response_budgets: BTreeMap<IpAddr, RendezvousSourceResponseBudget>,
}

impl RendezvousServer {
    /// Binds a nonblocking rendezvous service.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the socket cannot bind or become nonblocking.
    pub fn bind(address: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(address)?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket,
            waiting: BTreeMap::new(),
            source_counts: BTreeMap::new(),
            response_budget: RendezvousResponseBudget::global(Instant::now()),
            source_response_budgets: BTreeMap::new(),
        })
    }

    /// Returns the listening address.
    ///
    /// # Errors
    ///
    /// Returns an operating-system address error.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Processes a bounded batch of queued registrations without blocking.
    ///
    /// # Errors
    ///
    /// Returns an I/O error for socket failures. Malformed, legacy-sized, and
    /// zero-token registrations are ignored after counting against this poll's
    /// datagram budget.
    pub fn poll(&mut self) -> io::Result<usize> {
        let mut processed = 0;
        let now = Instant::now();
        self.expire_waiting(now);
        self.expire_source_response_budgets(now);
        // One extra byte distinguishes the exact format from a truncated
        // oversized datagram whose first 160 bytes happen to be valid.
        let mut packet = [0_u8; RENDEZVOUS_REGISTER_LEN + 1];
        for _ in 0..MAX_RENDEZVOUS_DATAGRAMS_PER_POLL {
            match self.socket.recv_from(&mut packet) {
                Ok((length, source)) => {
                    processed += 1;
                    if let Some(token) = decode_rendezvous_registration(&packet[..length]) {
                        self.process_registration(source, token, Instant::now())?;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(processed),
                Err(error) => return Err(error),
            }
        }
        Ok(processed)
    }

    fn process_registration(
        &mut self,
        source: SocketAddr,
        token: RendezvousToken,
        now: Instant,
    ) -> io::Result<()> {
        if token == [0; 32] {
            return Ok(());
        }
        if let Some(first) = self.waiting.get(&token).copied() {
            if first.source == source {
                // A duplicate cannot extend the absolute registration lifetime.
                return Ok(());
            }
            // Keep the original registration until both datagrams are accepted
            // by the local UDP socket. A transient failure can then be retried
            // without granting either endpoint an unbounded lifetime.
            let response_bytes = rendezvous_peer_packet_len(source)
                .checked_add(rendezvous_peer_packet_len(first.source))
                .ok_or_else(|| io::Error::other("rendezvous response length overflow"))?;
            if !self.reserve_pair_responses(first.source, source, response_bytes, now) {
                return Ok(());
            }
            let socket = &self.socket;
            return deliver_rendezvous_pair(
                &mut self.waiting,
                &mut self.source_counts,
                first,
                source,
                token,
                &mut |destination, token, peer| send_peer(socket, destination, token, peer),
            );
        }
        let source_ip = canonical_ip(source.ip());
        let source_count = self.source_counts.get(&source_ip).copied().unwrap_or(0);
        if self.waiting.len() >= MAX_RENDEZVOUS_WAITING
            || source_count >= MAX_RENDEZVOUS_WAITING_PER_SOURCE
        {
            return Ok(());
        }
        self.waiting.insert(
            token,
            RendezvousRegistration {
                source,
                registered_at: now,
            },
        );
        self.source_counts
            .entry(source_ip)
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
        Ok(())
    }

    fn expire_waiting(&mut self, now: Instant) {
        let expired = self
            .waiting
            .iter()
            .filter_map(|(token, registration)| {
                (now.saturating_duration_since(registration.registered_at)
                    > RENDEZVOUS_REGISTRATION_TTL)
                    .then_some((*token, registration.source.ip()))
            })
            .collect::<Vec<_>>();
        for (token, source) in expired {
            self.waiting.remove(&token);
            self.decrement_source(source);
        }
    }

    fn expire_source_response_budgets(&mut self, now: Instant) {
        self.source_response_budgets.retain(|_, source| {
            now.saturating_duration_since(source.last_used) <= RENDEZVOUS_SOURCE_RESPONSE_TTL
        });
    }

    fn reserve_pair_responses(
        &mut self,
        first: SocketAddr,
        second: SocketAddr,
        response_bytes: usize,
        now: Instant,
    ) -> bool {
        let Ok(response_bytes) = u64::try_from(response_bytes) else {
            return false;
        };
        let first_source = canonical_ip(first.ip());
        let second_source = canonical_ip(second.ip());
        let sources = [
            Some(first_source),
            (second_source != first_source).then_some(second_source),
        ];
        let missing_sources = sources
            .iter()
            .flatten()
            .filter(|source| !self.source_response_budgets.contains_key(source))
            .count();
        if self
            .source_response_budgets
            .len()
            .checked_add(missing_sources)
            .is_none_or(|next| next > MAX_RENDEZVOUS_RESPONSE_SOURCES)
        {
            return false;
        }

        self.response_budget.refill(now);
        for source in sources.iter().flatten() {
            if let Some(budget) = self.source_response_budgets.get_mut(source) {
                budget.touch(now);
            }
        }
        if !self.response_budget.can_take(response_bytes)
            || sources.iter().flatten().any(|source| {
                self.source_response_budgets
                    .get(source)
                    .is_some_and(|budget| !budget.budget.can_take(response_bytes))
            })
        {
            return false;
        }

        self.response_budget.deduct(response_bytes);
        for source in sources.into_iter().flatten() {
            let budget = self
                .source_response_budgets
                .entry(source)
                .or_insert_with(|| RendezvousSourceResponseBudget::new(now));
            budget.budget.deduct(response_bytes);
        }
        true
    }

    fn decrement_source(&mut self, source: IpAddr) {
        decrement_rendezvous_source(&mut self.source_counts, source);
    }
}

fn decrement_rendezvous_source(source_counts: &mut BTreeMap<IpAddr, usize>, source: IpAddr) {
    let source = canonical_ip(source);
    if let Some(count) = source_counts.get_mut(&source) {
        *count = count.saturating_sub(1);
        if *count == 0 {
            source_counts.remove(&source);
        }
    }
}

fn deliver_rendezvous_pair<F>(
    waiting: &mut BTreeMap<RendezvousToken, RendezvousRegistration>,
    source_counts: &mut BTreeMap<IpAddr, usize>,
    first: RendezvousRegistration,
    second: SocketAddr,
    token: RendezvousToken,
    send: &mut F,
) -> io::Result<()>
where
    F: FnMut(SocketAddr, RendezvousToken, SocketAddr) -> io::Result<()>,
{
    send(first.source, token, second)?;
    send(second, token, first.source)?;
    waiting.remove(&token);
    decrement_rendezvous_source(source_counts, first.source.ip());
    Ok(())
}

fn rendezvous_registration_packet(token: RendezvousToken) -> [u8; RENDEZVOUS_REGISTER_LEN] {
    let mut packet = [0_u8; RENDEZVOUS_REGISTER_LEN];
    packet[0] = RENDEZVOUS_REGISTER;
    packet[1..33].copy_from_slice(&token);
    packet
}

fn decode_rendezvous_registration(packet: &[u8]) -> Option<RendezvousToken> {
    if packet.len() != RENDEZVOUS_REGISTER_LEN
        || packet.first().copied() != Some(RENDEZVOUS_REGISTER)
        || packet[33..].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let mut token = [0_u8; 32];
    token.copy_from_slice(&packet[1..33]);
    (token != [0; 32]).then_some(token)
}

fn rendezvous_peer_packet_len(peer: SocketAddr) -> usize {
    33 + match peer {
        SocketAddr::V4(_) => 7,
        SocketAddr::V6(_) => 19,
    }
}

fn send_peer(
    socket: &UdpSocket,
    destination: SocketAddr,
    token: RendezvousToken,
    peer: SocketAddr,
) -> io::Result<()> {
    let encoded = encode_socket_addr(peer);
    let mut packet = Vec::with_capacity(encoded.len() + 33);
    packet.push(RENDEZVOUS_PEER);
    packet.extend_from_slice(&token);
    packet.extend_from_slice(&encoded);
    socket.send_to(&packet, destination)?;
    Ok(())
}

fn discovery_proof(token: &[u8; 16], nonce: &[u8; 16]) -> io::Result<[u8; 16]> {
    let hkdf = Hkdf::<Sha256>::new(Some(DISCOVERY_PROOF_DOMAIN), token);
    let mut proof = [0u8; 16];
    hkdf.expand(nonce, &mut proof)
        .map_err(|_| io::Error::other("IP discovery proof derivation failed"))?;
    Ok(proof)
}

fn discovery_confirmation_proof(
    token: &[u8; 16],
    role: DiscoveryConfirmationRole,
    announcement: &[u8; 16],
    challenge: &[u8; 16],
) -> io::Result<[u8; 16]> {
    let hkdf = Hkdf::<Sha256>::new(Some(DISCOVERY_CONFIRMATION_DOMAIN), token);
    let mut transcript = [0u8; 33];
    transcript[0] = role as u8;
    transcript[1..17].copy_from_slice(announcement);
    transcript[17..].copy_from_slice(challenge);
    let mut proof = [0u8; 16];
    hkdf.expand(&transcript, &mut proof)
        .map_err(|_| io::Error::other("IP discovery confirmation derivation failed"))?;
    Ok(proof)
}

fn discovery_confirmation_packet(
    kind: u8,
    announcement: [u8; 16],
    challenge: [u8; 16],
    proof: [u8; 16],
) -> [u8; DISCOVERY_PACKET_LEN] {
    let mut packet = [0u8; DISCOVERY_PACKET_LEN];
    packet[0] = kind;
    packet[1..17].copy_from_slice(&announcement);
    packet[17..33].copy_from_slice(&challenge);
    packet[33..DISCOVERY_CONFIRMATION_BODY_LEN].copy_from_slice(&proof);
    packet
}

fn valid_discovery_padding(packet: &[u8], body_len: usize) -> bool {
    packet.len() == DISCOVERY_PACKET_LEN && packet[body_len..].iter().all(|byte| *byte == 0)
}

fn retain_fresh<K: Ord>(entries: &mut BTreeMap<K, Instant>, now: Instant) {
    entries
        .retain(|_, created_at| now.saturating_duration_since(*created_at) <= DISCOVERY_STATE_TTL);
}

fn retain_pending(entries: &mut BTreeMap<PendingDiscoveryKey, PendingDiscovery>, now: Instant) {
    entries.retain(|_, pending| {
        now.saturating_duration_since(pending.issued_at) <= DISCOVERY_STATE_TTL
    });
}

fn retain_responses(entries: &mut BTreeMap<DiscoveryResponseKey, DiscoveryResponse>, now: Instant) {
    entries.retain(|_, response| {
        now.saturating_duration_since(response.emitted_at) <= DISCOVERY_STATE_TTL
    });
}

fn retain_client_rendezvous(
    entries: &mut BTreeMap<RendezvousToken, ClientRendezvous>,
    now: Instant,
) {
    entries.retain(|_, attempt| {
        now.saturating_duration_since(attempt.issued_at) <= RENDEZVOUS_REGISTRATION_TTL
    });
}

fn canonical_ip(source: IpAddr) -> IpAddr {
    match source {
        IpAddr::V6(source) => source
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(source), IpAddr::V4),
        IpAddr::V4(_) => source,
    }
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("IP adapter state lock poisoned")
}

fn encode_socket_addr(address: SocketAddr) -> Vec<u8> {
    match address {
        SocketAddr::V4(address) => {
            let mut bytes = Vec::with_capacity(7);
            bytes.push(4);
            bytes.extend_from_slice(&address.ip().octets());
            bytes.extend_from_slice(&address.port().to_be_bytes());
            bytes
        }
        SocketAddr::V6(address) => {
            let mut bytes = Vec::with_capacity(19);
            bytes.push(6);
            bytes.extend_from_slice(&address.ip().octets());
            bytes.extend_from_slice(&address.port().to_be_bytes());
            bytes
        }
    }
}

fn decode_socket_addr(bytes: &[u8]) -> io::Result<SocketAddr> {
    match bytes.first().copied() {
        Some(4) if bytes.len() == 7 => {
            let ip = Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]);
            let port = u16::from_be_bytes([bytes[5], bytes[6]]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        Some(6) if bytes.len() == 19 => {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&bytes[1..17]);
            let port = u16::from_be_bytes([bytes[17], bytes[18]]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid rendezvous address",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CONSERVATIVE_UDP_IP_HEADER_LEN, DISCOVERY, DISCOVERY_ANNOUNCEMENT_BODY_LEN,
        DISCOVERY_CHALLENGE, DISCOVERY_CONFIRMATION_BODY_LEN, DISCOVERY_PACKET_LEN,
        DISCOVERY_RESPONSE, DISCOVERY_STATE_TTL, DiscoveryConfirmationRole, DiscoveryResponse,
        IpLink, MAX_DATAGRAMS_PER_POLL, MAX_DISCOVERY_RESPONSES,
        MAX_DISCOVERY_RESPONSES_PER_SOURCE, MAX_PENDING_DISCOVERY,
        MAX_PENDING_DISCOVERY_PER_SOURCE, MAX_RECENT_ANNOUNCEMENTS,
        MAX_RENDEZVOUS_DATAGRAMS_PER_POLL, MAX_RENDEZVOUS_RESPONSE_SOURCES, MAX_RENDEZVOUS_WAITING,
        MAX_RENDEZVOUS_WAITING_PER_SOURCE, PUNCH, PendingDiscovery,
        RENDEZVOUS_MAX_PEER_RESPONSE_LEN, RENDEZVOUS_PEER, RENDEZVOUS_PUNCH_LEN,
        RENDEZVOUS_REGISTER_LEN, RENDEZVOUS_REGISTRATION_TTL, RENDEZVOUS_RESPONSE_BURST_BYTES,
        RENDEZVOUS_RESPONSE_REFILL_BYTES_PER_SECOND, RENDEZVOUS_SOURCE_RESPONSE_BURST_BYTES,
        RENDEZVOUS_SOURCE_RESPONSE_REFILL_BYTES_PER_SECOND, RENDEZVOUS_SOURCE_RESPONSE_TTL,
        RendezvousResponseBudget, RendezvousServer, RendezvousSourceResponseBudget, canonical_ip,
        decode_rendezvous_registration, deliver_rendezvous_pair, discovery_confirmation_packet,
        discovery_confirmation_proof, discovery_proof, encode_socket_addr,
        rendezvous_peer_packet_len, rendezvous_registration_packet, valid_discovery_padding,
    };
    use aster_mesh::link::Link;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
    use std::thread;
    use std::time::{Duration, Instant};

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn rendezvous_token(index: usize) -> [u8; 32] {
        let mut token = [0_u8; 32];
        token[..8].copy_from_slice(&u64::try_from(index + 1).unwrap().to_be_bytes());
        token
    }

    fn rendezvous_peer_packet(token: [u8; 32], peer: SocketAddr) -> Vec<u8> {
        let encoded = encode_socket_addr(peer);
        let mut packet = Vec::with_capacity(33 + encoded.len());
        packet.push(RENDEZVOUS_PEER);
        packet.extend_from_slice(&token);
        packet.extend_from_slice(&encoded);
        packet
    }

    fn punch_packet(token: [u8; 32]) -> [u8; 33] {
        let mut packet = [0_u8; 33];
        packet[0] = PUNCH;
        packet[1..].copy_from_slice(&token);
        packet
    }

    fn assert_rendezvous_source_counts(server: &RendezvousServer) {
        let mut rebuilt = BTreeMap::new();
        for registration in server.waiting.values() {
            *rebuilt
                .entry(canonical_ip(registration.source.ip()))
                .or_insert(0_usize) += 1;
        }
        assert_eq!(server.source_counts, rebuilt);
        assert_eq!(
            server.source_counts.values().sum::<usize>(),
            server.waiting.len()
        );
    }

    fn complete_rendezvous_with<F>(
        server: &mut RendezvousServer,
        second: SocketAddr,
        token: [u8; 32],
        now: Instant,
        send: &mut F,
    ) -> std::io::Result<bool>
    where
        F: FnMut(SocketAddr, [u8; 32], SocketAddr) -> std::io::Result<()>,
    {
        let Some(first) = server.waiting.get(&token).copied() else {
            return Ok(false);
        };
        if first.source == second {
            return Ok(false);
        }
        let response_bytes = rendezvous_peer_packet_len(second)
            .checked_add(rendezvous_peer_packet_len(first.source))
            .expect("fixed rendezvous response lengths fit usize");
        if !server.reserve_pair_responses(first.source, second, response_bytes, now) {
            return Ok(false);
        }
        deliver_rendezvous_pair(
            &mut server.waiting,
            &mut server.source_counts,
            first,
            second,
            token,
            send,
        )?;
        Ok(true)
    }

    #[test]
    fn discovery_proofs_do_not_expose_or_reuse_the_provisioned_token() {
        let token = [7; 16];
        let first = discovery_proof(&token, &[1; 16]).unwrap();
        let second = discovery_proof(&token, &[2; 16]).unwrap();
        assert_ne!(first, token);
        assert_ne!(first, second);
        assert_ne!(first, discovery_proof(&[8; 16], &[1; 16]).unwrap());

        let challenge = discovery_confirmation_proof(
            &token,
            DiscoveryConfirmationRole::Challenge,
            &[1; 16],
            &[2; 16],
        )
        .unwrap();
        let response = discovery_confirmation_proof(
            &token,
            DiscoveryConfirmationRole::Response,
            &[1; 16],
            &[2; 16],
        )
        .unwrap();
        assert_ne!(challenge, response);
    }

    #[test]
    fn discovery_packets_are_strict_fixed_size_and_non_amplifying() {
        let token = [8; 16];
        let announcement = [1; 16];
        let challenge = [2; 16];
        let mut advertisement = [0_u8; DISCOVERY_PACKET_LEN];
        advertisement[0] = DISCOVERY;
        advertisement[1..17].copy_from_slice(&announcement);
        advertisement[17..DISCOVERY_ANNOUNCEMENT_BODY_LEN]
            .copy_from_slice(&discovery_proof(&token, &announcement).unwrap());
        let confirmation = discovery_confirmation_packet(
            DISCOVERY_CHALLENGE,
            announcement,
            challenge,
            discovery_confirmation_proof(
                &token,
                DiscoveryConfirmationRole::Challenge,
                &announcement,
                &challenge,
            )
            .unwrap(),
        );
        let response_confirmation = discovery_confirmation_packet(
            DISCOVERY_RESPONSE,
            announcement,
            challenge,
            discovery_confirmation_proof(
                &token,
                DiscoveryConfirmationRole::Response,
                &announcement,
                &challenge,
            )
            .unwrap(),
        );

        assert!(valid_discovery_padding(
            &advertisement,
            DISCOVERY_ANNOUNCEMENT_BODY_LEN
        ));
        assert!(valid_discovery_padding(
            &confirmation,
            DISCOVERY_CONFIRMATION_BODY_LEN
        ));
        assert!(valid_discovery_padding(
            &response_confirmation,
            DISCOVERY_CONFIRMATION_BODY_LEN
        ));
        assert!(!valid_discovery_padding(
            &advertisement[..DISCOVERY_ANNOUNCEMENT_BODY_LEN],
            DISCOVERY_ANNOUNCEMENT_BODY_LEN
        ));
        let mut trailing = advertisement.to_vec();
        trailing.push(0);
        assert!(!valid_discovery_padding(
            &trailing,
            DISCOVERY_ANNOUNCEMENT_BODY_LEN
        ));
        let mut nonzero_padding = confirmation;
        nonzero_padding[DISCOVERY_CONFIRMATION_BODY_LEN] = 1;
        assert!(!valid_discovery_padding(
            &nonzero_padding,
            DISCOVERY_CONFIRMATION_BODY_LEN
        ));

        for header_len in [28, CONSERVATIVE_UDP_IP_HEADER_LEN] {
            assert!(DISCOVERY_PACKET_LEN + header_len >= confirmation.len() + header_len);
            assert!(DISCOVERY_PACKET_LEN + header_len >= response_confirmation.len() + header_len);
        }

        let sink = UdpSocket::bind(loopback()).unwrap();
        let source = sink.local_addr().unwrap();
        let receiver = IpLink::bind("receiver", loopback(), token, None).unwrap();
        assert!(
            receiver
                .process_control(source, &advertisement[..DISCOVERY_ANNOUNCEMENT_BODY_LEN])
                .unwrap()
        );
        assert!(receiver.pending_discovery.lock().unwrap().is_empty());
        assert!(receiver.process_control(source, &trailing).unwrap());
        assert!(receiver.pending_discovery.lock().unwrap().is_empty());
        let mut malformed_advertisement = advertisement;
        malformed_advertisement[DISCOVERY_ANNOUNCEMENT_BODY_LEN] = 1;
        assert!(
            receiver
                .process_control(source, &malformed_advertisement)
                .unwrap()
        );
        assert!(receiver.pending_discovery.lock().unwrap().is_empty());
        assert!(receiver.process_control(source, &advertisement).unwrap());
        assert_eq!(receiver.pending_discovery.lock().unwrap().len(), 1);

        let announcer = IpLink::bind("announcer", loopback(), token, None).unwrap();
        announcer
            .recent_announcements
            .lock()
            .unwrap()
            .insert(announcement, Instant::now());
        assert!(
            announcer
                .process_control(source, &confirmation[..DISCOVERY_CONFIRMATION_BODY_LEN])
                .unwrap()
        );
        assert!(announcer.discovery_responses.lock().unwrap().is_empty());
        assert!(announcer.process_control(source, &nonzero_padding).unwrap());
        assert!(announcer.discovery_responses.lock().unwrap().is_empty());
        assert!(announcer.process_control(source, &confirmation).unwrap());
        assert_eq!(announcer.discovery_responses.lock().unwrap().len(), 1);
    }

    #[test]
    fn challenge_for_an_unannounced_nonce_gets_no_response() {
        let token = [9; 16];
        let advertiser = IpLink::bind("advertiser", loopback(), token, None).unwrap();
        let challenger = UdpSocket::bind(loopback()).unwrap();
        challenger.set_nonblocking(true).unwrap();
        let announcement = [3; 16];
        let challenge = [4; 16];
        let proof = discovery_confirmation_proof(
            &token,
            DiscoveryConfirmationRole::Challenge,
            &announcement,
            &challenge,
        )
        .unwrap();
        let packet =
            discovery_confirmation_packet(DISCOVERY_CHALLENGE, announcement, challenge, proof);

        assert!(
            advertiser
                .process_control(challenger.local_addr().unwrap(), &packet)
                .unwrap()
        );
        assert!(advertiser.discovery_responses.lock().unwrap().is_empty());
        let mut response = [0u8; DISCOVERY_PACKET_LEN];
        assert_eq!(
            challenger.recv_from(&mut response).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn captured_advertisement_cannot_redirect_discovery_to_replayer() {
        let token = [10; 16];
        let capture = UdpSocket::bind(loopback()).unwrap();
        capture
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let advertiser = IpLink::bind(
            "advertiser",
            loopback(),
            token,
            Some(capture.local_addr().unwrap()),
        )
        .unwrap();
        let receiver = IpLink::bind("receiver", loopback(), token, None).unwrap();
        let attacker = UdpSocket::bind(loopback()).unwrap();
        attacker
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();

        advertiser.announce().unwrap();
        let mut advertisement = [0u8; DISCOVERY_PACKET_LEN];
        let (length, _) = capture.recv_from(&mut advertisement).unwrap();
        assert_eq!(length, advertisement.len());
        assert_eq!(advertisement[0], DISCOVERY);

        attacker
            .send_to(&advertisement, receiver.local_addr().unwrap())
            .unwrap();
        attacker
            .send_to(&advertisement, receiver.local_addr().unwrap())
            .unwrap();
        for _ in 0..50 {
            assert!(receiver.try_receive().unwrap().is_none());
            if receiver.pending_discovery.lock().unwrap().len() == 1 {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(receiver.pending_discovery.lock().unwrap().len(), 1);

        let mut reflected = [0u8; DISCOVERY_PACKET_LEN];
        let (length, _) = attacker.recv_from(&mut reflected).unwrap();
        assert_eq!(length, reflected.len());
        assert_eq!(reflected[0], DISCOVERY_CHALLENGE);
        reflected[0] = DISCOVERY_RESPONSE;
        attacker
            .send_to(&reflected, receiver.local_addr().unwrap())
            .unwrap();
        assert!(receiver.try_receive().unwrap().is_none());
        assert!(receiver.take_discovered().is_empty());

        // The legitimate exact source can still use the same captured
        // announcement transcript; the attacker's front-run is source-bound.
        advertiser
            .socket
            .send_to(&advertisement, receiver.local_addr().unwrap())
            .unwrap();
        for _ in 0..100 {
            let _ = receiver.try_receive().unwrap();
            let _ = advertiser.try_receive().unwrap();
            if let Some(discovered) = receiver.take_discovered().into_iter().next() {
                assert_eq!(discovered, advertiser.local_addr().unwrap());
                assert_ne!(discovered, attacker.local_addr().unwrap());
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        panic!("legitimate advertiser did not complete discovery confirmation");
    }

    #[test]
    fn replayed_challenge_from_another_socket_cannot_suppress_legitimate_response() {
        let token = [15; 16];
        let announcer = IpLink::bind("announcer", loopback(), token, None).unwrap();
        let attacker = UdpSocket::bind(loopback()).unwrap();
        let legitimate = UdpSocket::bind(loopback()).unwrap();
        let announcement = [21; 16];
        let challenge = [22; 16];
        announcer
            .recent_announcements
            .lock()
            .unwrap()
            .insert(announcement, Instant::now());

        announcer
            .answer_discovery_challenge(attacker.local_addr().unwrap(), announcement, challenge)
            .unwrap();
        announcer
            .answer_discovery_challenge(legitimate.local_addr().unwrap(), announcement, challenge)
            .unwrap();

        let responses = announcer.discovery_responses.lock().unwrap();
        assert_eq!(responses.len(), 2);
        assert!(responses.contains_key(&(attacker.local_addr().unwrap(), announcement, challenge)));
        assert!(responses.contains_key(&(
            legitimate.local_addr().unwrap(),
            announcement,
            challenge
        )));
    }

    #[test]
    fn duplicate_discovery_response_is_rejected_after_first_confirmation() {
        let token = [11; 16];
        let receiver = IpLink::bind("receiver", loopback(), token, None).unwrap();
        let sender = UdpSocket::bind(loopback()).unwrap();
        sender
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let announcement = [12; 16];
        let mut advertisement = [0u8; DISCOVERY_PACKET_LEN];
        advertisement[0] = DISCOVERY;
        advertisement[1..17].copy_from_slice(&announcement);
        advertisement[17..DISCOVERY_ANNOUNCEMENT_BODY_LEN]
            .copy_from_slice(&discovery_proof(&token, &announcement).unwrap());
        sender
            .send_to(&advertisement, receiver.local_addr().unwrap())
            .unwrap();
        for _ in 0..50 {
            assert!(receiver.try_receive().unwrap().is_none());
            if receiver.pending_discovery.lock().unwrap().len() == 1 {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(receiver.pending_discovery.lock().unwrap().len(), 1);

        let mut challenge_packet = [0u8; DISCOVERY_PACKET_LEN];
        let (length, _) = sender.recv_from(&mut challenge_packet).unwrap();
        assert_eq!(length, challenge_packet.len());
        assert_eq!(challenge_packet[0], DISCOVERY_CHALLENGE);
        let mut challenge = [0u8; 16];
        challenge.copy_from_slice(&challenge_packet[17..33]);
        let response_proof = discovery_confirmation_proof(
            &token,
            DiscoveryConfirmationRole::Response,
            &announcement,
            &challenge,
        )
        .unwrap();
        let response = discovery_confirmation_packet(
            DISCOVERY_RESPONSE,
            announcement,
            challenge,
            response_proof,
        );

        let wrong_source = UdpSocket::bind(loopback()).unwrap();
        wrong_source
            .send_to(&response, receiver.local_addr().unwrap())
            .unwrap();
        assert!(receiver.try_receive().unwrap().is_none());
        assert!(receiver.take_discovered().is_empty());
        assert_eq!(receiver.pending_discovery.lock().unwrap().len(), 1);

        sender
            .send_to(&response, receiver.local_addr().unwrap())
            .unwrap();
        let mut discovered = Vec::new();
        for _ in 0..50 {
            assert!(receiver.try_receive().unwrap().is_none());
            discovered = receiver.take_discovered();
            if !discovered.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(discovered, vec![sender.local_addr().unwrap()]);

        sender
            .send_to(&response, receiver.local_addr().unwrap())
            .unwrap();
        for _ in 0..10 {
            assert!(receiver.try_receive().unwrap().is_none());
            thread::sleep(Duration::from_millis(2));
        }
        assert!(receiver.take_discovered().is_empty());
    }

    #[test]
    fn discovery_state_is_bounded_and_expired_before_reuse() {
        fn indexed_nonce(index: usize) -> [u8; 16] {
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&(index as u64).to_be_bytes());
            nonce
        }

        let token = [13; 16];
        let sink = UdpSocket::bind(loopback()).unwrap();
        let sink_address = sink.local_addr().unwrap();
        let receiver = IpLink::bind("receiver", loopback(), token, None).unwrap();
        {
            let mut pending = receiver.pending_discovery.lock().unwrap();
            for index in 0..MAX_PENDING_DISCOVERY {
                let source = SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(
                        127,
                        0,
                        1,
                        u8::try_from(1 + index.div_ceil(MAX_PENDING_DISCOVERY_PER_SOURCE)).unwrap(),
                    )),
                    u16::try_from(10_000 + index).unwrap(),
                );
                pending.insert(
                    (source, indexed_nonce(index)),
                    PendingDiscovery {
                        source,
                        challenge: indexed_nonce(index + 1),
                        issued_at: Instant::now(),
                    },
                );
            }
        }
        receiver
            .challenge_discovery(sink_address, indexed_nonce(MAX_PENDING_DISCOVERY))
            .unwrap();
        assert_eq!(
            receiver.pending_discovery.lock().unwrap().len(),
            MAX_PENDING_DISCOVERY
        );

        let expired = Instant::now()
            .checked_sub(DISCOVERY_STATE_TTL + Duration::from_millis(1))
            .unwrap();
        for pending in receiver.pending_discovery.lock().unwrap().values_mut() {
            pending.issued_at = expired;
        }
        receiver
            .challenge_discovery(sink_address, indexed_nonce(MAX_PENDING_DISCOVERY + 1))
            .unwrap();
        assert_eq!(receiver.pending_discovery.lock().unwrap().len(), 1);

        let announcer = IpLink::bind("announcer", loopback(), token, Some(sink_address)).unwrap();
        {
            let mut announcements = announcer.recent_announcements.lock().unwrap();
            for index in 0..MAX_RECENT_ANNOUNCEMENTS {
                announcements.insert(indexed_nonce(index), Instant::now());
            }
        }
        assert_eq!(
            announcer.announce().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        for created_at in announcer.recent_announcements.lock().unwrap().values_mut() {
            *created_at = expired;
        }
        announcer.announce().unwrap();
        assert_eq!(announcer.recent_announcements.lock().unwrap().len(), 1);

        let announcement = *announcer
            .recent_announcements
            .lock()
            .unwrap()
            .keys()
            .next()
            .unwrap();
        {
            let mut responses = announcer.discovery_responses.lock().unwrap();
            for index in 0..MAX_DISCOVERY_RESPONSES {
                let source = IpAddr::V4(Ipv4Addr::new(
                    127,
                    1,
                    u8::try_from(index / (u8::MAX as usize + 1)).unwrap(),
                    u8::try_from(index % (u8::MAX as usize + 1)).unwrap(),
                ));
                responses.insert(
                    (
                        SocketAddr::new(source, u16::try_from(index).unwrap()),
                        announcement,
                        indexed_nonce(index),
                    ),
                    DiscoveryResponse {
                        source,
                        emitted_at: Instant::now(),
                    },
                );
            }
        }
        announcer
            .answer_discovery_challenge(
                sink_address,
                announcement,
                indexed_nonce(MAX_DISCOVERY_RESPONSES),
            )
            .unwrap();
        assert_eq!(
            announcer.discovery_responses.lock().unwrap().len(),
            MAX_DISCOVERY_RESPONSES
        );
        for response in announcer.discovery_responses.lock().unwrap().values_mut() {
            response.emitted_at = expired;
        }
        announcer
            .answer_discovery_challenge(
                sink_address,
                announcement,
                indexed_nonce(MAX_DISCOVERY_RESPONSES + 1),
            )
            .unwrap();
        assert_eq!(announcer.discovery_responses.lock().unwrap().len(), 1);
    }

    #[test]
    fn discovery_port_churn_is_source_bounded_and_another_source_progresses() {
        fn indexed_nonce(index: usize) -> [u8; 16] {
            let mut nonce = [0u8; 16];
            nonce[..8].copy_from_slice(&(index as u64).to_be_bytes());
            nonce
        }

        let token = [14; 16];
        let receiver = IpLink::bind("receiver", loopback(), token, None).unwrap();
        let attacker_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));
        let legitimate_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 11));

        for port in 20_000..20_100 {
            receiver
                .challenge_discovery(SocketAddr::new(attacker_ip, port), indexed_nonce(1))
                .unwrap();
        }
        assert_eq!(
            receiver.pending_discovery.lock().unwrap().len(),
            MAX_PENDING_DISCOVERY_PER_SOURCE
        );
        receiver
            .challenge_discovery(
                SocketAddr::new(attacker_ip, 22_000),
                indexed_nonce(MAX_PENDING_DISCOVERY_PER_SOURCE + 1),
            )
            .unwrap();
        assert_eq!(
            receiver.pending_discovery.lock().unwrap().len(),
            MAX_PENDING_DISCOVERY_PER_SOURCE
        );

        let legitimate_announcement = indexed_nonce(MAX_PENDING_DISCOVERY_PER_SOURCE + 2);
        let legitimate_source = SocketAddr::new(legitimate_ip, 23_000);
        receiver
            .challenge_discovery(legitimate_source, legitimate_announcement)
            .unwrap();
        let pending = receiver.pending_discovery.lock().unwrap();
        assert_eq!(pending.len(), MAX_PENDING_DISCOVERY_PER_SOURCE + 1);
        assert_eq!(
            pending[&(legitimate_source, legitimate_announcement)].source,
            legitimate_source
        );

        let announcer = IpLink::bind("announcer", loopback(), token, None).unwrap();
        announcer
            .recent_announcements
            .lock()
            .unwrap()
            .insert(legitimate_announcement, Instant::now());
        drop(pending);
        for port in 24_000..24_100 {
            announcer
                .answer_discovery_challenge(
                    SocketAddr::new(attacker_ip, port),
                    legitimate_announcement,
                    indexed_nonce(50),
                )
                .unwrap();
        }
        assert_eq!(
            announcer.discovery_responses.lock().unwrap().len(),
            MAX_DISCOVERY_RESPONSES_PER_SOURCE
        );
        announcer
            .answer_discovery_challenge(
                SocketAddr::new(attacker_ip, 26_000),
                legitimate_announcement,
                indexed_nonce(100),
            )
            .unwrap();
        assert_eq!(
            announcer.discovery_responses.lock().unwrap().len(),
            MAX_DISCOVERY_RESPONSES_PER_SOURCE
        );
        announcer
            .answer_discovery_challenge(
                legitimate_source,
                legitimate_announcement,
                indexed_nonce(101),
            )
            .unwrap();
        let responses = announcer.discovery_responses.lock().unwrap();
        assert_eq!(responses.len(), MAX_DISCOVERY_RESPONSES_PER_SOURCE + 1);
        assert!(
            responses
                .values()
                .any(|response| { response.source == canonical_ip(legitimate_source.ip()) })
        );
    }

    #[test]
    fn ipv4_mapped_ipv6_uses_the_ipv4_source_quota_identity() {
        let ipv4 = Ipv4Addr::new(192, 0, 2, 9);
        assert_eq!(
            canonical_ip(IpAddr::V4(ipv4)),
            canonical_ip(IpAddr::V6(ipv4.to_ipv6_mapped()))
        );
    }

    #[test]
    fn direct_udp_frames_remain_opaque() {
        let token = [7; 16];
        let a = IpLink::bind("a", loopback(), token, None).unwrap();
        let b = IpLink::bind("b", loopback(), token, None).unwrap();
        a.register_peer([2; 32], b.local_addr().unwrap()).unwrap();
        b.register_peer([1; 32], a.local_addr().unwrap()).unwrap();
        a.send(Some([2; 32]), b"ciphertext-canary").unwrap();
        for _ in 0..50 {
            if let Some(frame) = b.try_receive().unwrap() {
                assert_eq!(frame.peer, Some([1; 32]));
                assert_eq!(frame.bytes, b"ciphertext-canary");
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        panic!("frame not received");
    }

    #[test]
    fn unknown_data_is_dropped_without_registering_a_route() {
        let token = [6; 16];
        let a = IpLink::bind("a", loopback(), token, None).unwrap();
        let b = IpLink::bind("b", loopback(), token, None).unwrap();
        a.register_peer([2; 32], b.local_addr().unwrap()).unwrap();
        a.send(Some([2; 32]), b"").unwrap();

        let mut queued = false;
        for _ in 0..50 {
            let mut byte = [0_u8; 1];
            match b.socket.peek_from(&mut byte) {
                Ok((length, source)) => {
                    assert_eq!(length, 1);
                    assert_eq!(source, a.local_addr().unwrap());
                    assert_eq!(byte, [super::DATA]);
                    queued = true;
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("could not inspect queued DATA datagram: {error}"),
            }
        }
        assert!(queued, "one-byte DATA datagram did not arrive");
        assert!(b.try_receive().unwrap().is_none());
        assert!(
            b.reverse_peers
                .read()
                .unwrap()
                .get(&a.local_addr().unwrap())
                .is_none()
        );
    }

    #[test]
    fn ignored_datagram_flood_is_bounded_and_known_peer_still_progresses() {
        let token = [5; 16];
        let receiver = IpLink::bind("receiver", loopback(), token, None).unwrap();
        let known = IpLink::bind("known", loopback(), token, None).unwrap();
        let attacker = UdpSocket::bind(loopback()).unwrap();
        receiver
            .register_peer([7; 32], known.local_addr().unwrap())
            .unwrap();

        for _ in 0..MAX_DATAGRAMS_PER_POLL {
            attacker
                .send_to(&[super::DATA], receiver.local_addr().unwrap())
                .unwrap();
        }
        known
            .register_peer([7; 32], receiver.local_addr().unwrap())
            .unwrap();
        known.send(Some([7; 32]), b"known-after-flood").unwrap();

        assert!(receiver.try_receive().unwrap().is_none());
        for _ in 0..50 {
            if let Some(frame) = receiver.try_receive().unwrap() {
                assert_eq!(frame.peer, Some([7; 32]));
                assert_eq!(frame.bytes, b"known-after-flood");
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        panic!("known peer did not progress after the bounded ignored-datagram batch");
    }

    #[test]
    fn discovered_endpoint_can_be_explicitly_registered_for_data() {
        let token = [6; 16];
        let b = IpLink::bind("b", loopback(), token, None).unwrap();
        let a = IpLink::bind("a", loopback(), token, Some(b.local_addr().unwrap())).unwrap();

        a.announce().unwrap();
        let mut discovered = None;
        for _ in 0..100 {
            let _ = b.try_receive().unwrap();
            let _ = a.try_receive().unwrap();
            if let Some(address) = b.take_discovered().into_iter().next() {
                discovered = Some(address);
                break;
            }
            thread::sleep(Duration::from_millis(2));
        }
        let discovered = discovered.expect("discovery advertisement not received");
        assert_eq!(discovered, a.local_addr().unwrap());
        let route = b.register_endpoint(discovered).unwrap();

        a.register_peer([2; 32], b.local_addr().unwrap()).unwrap();
        a.send(Some([2; 32]), b"discovered fragment").unwrap();
        for _ in 0..50 {
            if let Some(received) = b.try_receive().unwrap() {
                assert_eq!(received.peer, Some(route));
                assert_eq!(received.bytes, b"discovered fragment");
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        panic!("registered discovered endpoint did not deliver DATA");
    }

    #[test]
    fn rendezvous_exchanges_observed_endpoints() {
        let token = [8; 16];
        let mut server = RendezvousServer::bind(loopback()).unwrap();
        let a = IpLink::bind("a", loopback(), token, None).unwrap();
        let b = IpLink::bind("b", loopback(), token, None).unwrap();
        let pair = [9; 32];
        a.request_rendezvous(server.local_addr().unwrap(), pair)
            .unwrap();
        b.request_rendezvous(server.local_addr().unwrap(), pair)
            .unwrap();
        for _ in 0..100 {
            server.poll().unwrap();
            let _ = a.try_receive().unwrap();
            let _ = b.try_receive().unwrap();
            if !a.take_discovered().is_empty() && !b.take_discovered().is_empty() {
                assert!(server.waiting.is_empty());
                assert!(server.source_counts.is_empty());
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        panic!("rendezvous did not pair clients");
    }

    #[test]
    fn rendezvous_rejects_zero_tokens_and_expires_client_attempts() {
        let discovery = [8; 16];
        let client = IpLink::bind("client", loopback(), discovery, None).unwrap();
        assert_eq!(
            client.accept_punch([0; 32]).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            client
                .request_rendezvous(loopback(), [0; 32])
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );

        let expired = rendezvous_token(0);
        let replacement = rendezvous_token(1);
        client.accept_punch(expired).unwrap();
        client
            .rendezvous_attempts
            .lock()
            .unwrap()
            .get_mut(&expired)
            .unwrap()
            .issued_at = Instant::now()
            .checked_sub(RENDEZVOUS_REGISTRATION_TTL + Duration::from_millis(1))
            .unwrap();
        client.accept_punch(replacement).unwrap();
        let attempts = client.rendezvous_attempts.lock().unwrap();
        assert!(!attempts.contains_key(&expired));
        assert!(attempts.contains_key(&replacement));
    }

    #[test]
    fn failed_rendezvous_request_rolls_back_client_state() {
        let discovery = [8; 16];
        let client = IpLink::bind("client", loopback(), discovery, None).unwrap();
        let token = rendezvous_token(0);
        // An IPv4-only UDP socket cannot send to an IPv6 destination.
        let invalid_destination = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9);

        assert!(
            client
                .request_rendezvous(invalid_destination, token)
                .is_err()
        );
        assert!(
            !client
                .rendezvous_attempts
                .lock()
                .unwrap()
                .contains_key(&token)
        );
    }

    #[test]
    fn rendezvous_response_is_bound_to_the_server_for_each_token() {
        let discovery = [8; 16];
        let client = IpLink::bind("client", loopback(), discovery, None).unwrap();
        let first_server = UdpSocket::bind(loopback()).unwrap();
        let second_server = UdpSocket::bind(loopback()).unwrap();
        let peer = UdpSocket::bind(loopback()).unwrap();
        let first_token = rendezvous_token(0);
        let second_token = rendezvous_token(1);
        client
            .request_rendezvous(first_server.local_addr().unwrap(), first_token)
            .unwrap();
        client
            .request_rendezvous(second_server.local_addr().unwrap(), second_token)
            .unwrap();

        let response = rendezvous_peer_packet(first_token, peer.local_addr().unwrap());
        client
            .process_control(second_server.local_addr().unwrap(), &response)
            .unwrap();
        assert!(client.take_discovered().is_empty());
        assert!(client.rendezvous_attempts.lock().unwrap()[&first_token].response_pending);

        client
            .process_control(first_server.local_addr().unwrap(), &response)
            .unwrap();
        assert_eq!(client.take_discovered(), vec![peer.local_addr().unwrap()]);
        assert!(!client.rendezvous_attempts.lock().unwrap()[&first_token].response_pending);
    }

    #[test]
    fn rendezvous_peer_response_is_one_shot_and_punch_is_endpoint_bound() {
        let discovery = [8; 16];
        let client = IpLink::bind("client", loopback(), discovery, None).unwrap();
        let server = UdpSocket::bind(loopback()).unwrap();
        let selected_peer = UdpSocket::bind(loopback()).unwrap();
        let wrong_peer = UdpSocket::bind(loopback()).unwrap();
        selected_peer
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        wrong_peer.set_nonblocking(true).unwrap();
        let token = rendezvous_token(0);
        client
            .request_rendezvous(server.local_addr().unwrap(), token)
            .unwrap();

        let selected = selected_peer.local_addr().unwrap();
        let replay_target = wrong_peer.local_addr().unwrap();
        assert!(
            client
                .process_control(
                    server.local_addr().unwrap(),
                    &rendezvous_peer_packet(token, selected),
                )
                .unwrap()
        );
        assert_eq!(client.take_discovered(), vec![selected]);

        let mut punch = [0_u8; 33];
        let (length, source) = selected_peer.recv_from(&mut punch).unwrap();
        assert_eq!(length, punch.len());
        assert_eq!(source, client.local_addr().unwrap());
        assert_eq!(punch, punch_packet(token));

        assert!(
            client
                .process_control(
                    server.local_addr().unwrap(),
                    &rendezvous_peer_packet(token, replay_target),
                )
                .unwrap()
        );
        assert!(client.take_discovered().is_empty());
        assert_eq!(
            wrong_peer.recv_from(&mut punch).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );

        assert!(
            client
                .process_control(replay_target, &punch_packet(token))
                .unwrap()
        );
        assert!(client.take_discovered().is_empty());
        assert!(
            client
                .rendezvous_attempts
                .lock()
                .unwrap()
                .contains_key(&token)
        );

        assert!(
            client
                .process_control(selected, &punch_packet(token))
                .unwrap()
        );
        assert_eq!(client.take_discovered(), vec![selected]);
        assert!(
            !client
                .rendezvous_attempts
                .lock()
                .unwrap()
                .contains_key(&token)
        );
    }

    #[test]
    fn rendezvous_registration_is_strict_and_non_amplifying() {
        let token = rendezvous_token(0);
        let valid = rendezvous_registration_packet(token);
        assert_eq!(valid.len(), RENDEZVOUS_REGISTER_LEN);
        assert_eq!(decode_rendezvous_registration(&valid), Some(token));

        let mut legacy = [0_u8; 33];
        legacy[0] = super::RENDEZVOUS_REGISTER;
        legacy[1..].copy_from_slice(&token);
        assert_eq!(decode_rendezvous_registration(&legacy), None);
        let mut superseded = [0_u8; 64];
        superseded[0] = super::RENDEZVOUS_REGISTER;
        superseded[1..33].copy_from_slice(&token);
        assert_eq!(decode_rendezvous_registration(&superseded), None);

        let mut nonzero_padding = valid;
        *nonzero_padding.last_mut().unwrap() = 1;
        assert_eq!(decode_rendezvous_registration(&nonzero_padding), None);
        assert_eq!(
            decode_rendezvous_registration(&rendezvous_registration_packet([0; 32])),
            None
        );

        let ipv4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), u16::MAX);
        let ipv6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), u16::MAX);
        assert_eq!(rendezvous_peer_packet_len(ipv4), 40);
        assert_eq!(
            rendezvous_peer_packet_len(ipv6),
            RENDEZVOUS_MAX_PEER_RESPONSE_LEN
        );
        let request_wire_bytes = RENDEZVOUS_REGISTER_LEN + CONSERVATIVE_UDP_IP_HEADER_LEN;
        let reflected_chain_wire_bytes = RENDEZVOUS_MAX_PEER_RESPONSE_LEN
            + RENDEZVOUS_PUNCH_LEN
            + (2 * CONSERVATIVE_UDP_IP_HEADER_LEN);
        assert_eq!(request_wire_bytes, 208);
        assert_eq!(reflected_chain_wire_bytes, 181);
        assert!(request_wire_bytes >= reflected_chain_wire_bytes);
    }

    #[test]
    fn rendezvous_response_budget_refills_monotonically() {
        let now = Instant::now();
        let mut budget = RendezvousResponseBudget::global(now);
        assert!(budget.take(RENDEZVOUS_RESPONSE_BURST_BYTES as usize, now));
        assert!(!budget.take(1, now));
        assert!(!budget.take(1, now.checked_sub(Duration::from_secs(1)).unwrap()));

        let half_second = now + Duration::from_millis(500);
        let half_refill = RENDEZVOUS_RESPONSE_REFILL_BYTES_PER_SECOND / 2;
        assert!(budget.take(half_refill as usize, half_second));
        assert!(!budget.take(1, half_second));

        let full_again = half_second + Duration::from_secs(10);
        budget.refill(full_again);
        assert_eq!(budget.available_bytes, RENDEZVOUS_RESPONSE_BURST_BYTES);
        assert_eq!(budget.refill_remainder, 0);

        let mut source_budget = RendezvousResponseBudget::source(now);
        assert!(source_budget.take(RENDEZVOUS_SOURCE_RESPONSE_BURST_BYTES as usize, now));
        assert!(source_budget.take(
            RENDEZVOUS_SOURCE_RESPONSE_REFILL_BYTES_PER_SECOND as usize,
            now + Duration::from_secs(1),
        ));
    }

    #[test]
    fn rendezvous_repeated_completed_pairings_cannot_bypass_global_egress_budget() {
        let mut server = RendezvousServer::bind(loopback()).unwrap();
        let now = Instant::now();
        server.response_budget = RendezvousResponseBudget::global(now);
        server.source_response_budgets.clear();
        let pair_bytes =
            2 * rendezvous_peer_packet_len(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1));
        let admitted_pairs = RENDEZVOUS_RESPONSE_BURST_BYTES as usize / pair_bytes;
        let sent = Cell::new(0_usize);
        let mut sender = |_: SocketAddr, _: [u8; 32], _: SocketAddr| {
            sent.set(sent.get() + 1);
            Ok(())
        };

        for index in 0..admitted_pairs {
            let token = rendezvous_token(index);
            let first_address =
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, index as u8, 1)), 10_000);
            let second_address =
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 2, index as u8, 1)), 20_000);
            server
                .process_registration(first_address, token, now)
                .unwrap();
            assert!(
                complete_rendezvous_with(&mut server, second_address, token, now, &mut sender)
                    .unwrap()
            );
            assert!(!server.waiting.contains_key(&token));
        }
        assert_eq!(sent.get(), admitted_pairs * 2);
        assert_eq!(
            server.response_budget.available_bytes,
            RENDEZVOUS_RESPONSE_BURST_BYTES - u64::try_from(admitted_pairs * pair_bytes).unwrap()
        );
        let source_budget_count = server.source_response_budgets.len();

        let throttled = rendezvous_token(admitted_pairs);
        let throttled_first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 30_000);
        let throttled_second = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 40_000);
        server
            .process_registration(throttled_first, throttled, now)
            .unwrap();
        assert!(
            !complete_rendezvous_with(&mut server, throttled_second, throttled, now, &mut sender,)
                .unwrap()
        );
        assert_eq!(server.waiting[&throttled].source, throttled_first);
        assert_eq!(server.source_response_budgets.len(), source_budget_count);
        assert_rendezvous_source_counts(&server);

        let refilled = now + Duration::from_secs(1);
        assert!(
            complete_rendezvous_with(
                &mut server,
                throttled_second,
                throttled,
                refilled,
                &mut sender,
            )
            .unwrap()
        );
        assert!(!server.waiting.contains_key(&throttled));
        assert!(server.source_counts.is_empty());
        assert_eq!(
            server.response_budget.available_bytes,
            RENDEZVOUS_RESPONSE_BURST_BYTES - u64::try_from(admitted_pairs * pair_bytes).unwrap()
                + RENDEZVOUS_RESPONSE_REFILL_BYTES_PER_SECOND
                - u64::try_from(pair_bytes).unwrap()
        );
    }

    #[test]
    fn rendezvous_noisy_source_exhaustion_preserves_budget_for_another_source() {
        let mut server = RendezvousServer::bind(loopback()).unwrap();
        let now = Instant::now();
        server.response_budget = RendezvousResponseBudget::global(now);
        server.source_response_budgets.clear();
        let noisy_ip = Ipv4Addr::new(192, 0, 2, 40);
        let noisy_first = SocketAddr::new(IpAddr::V4(noisy_ip), 10_000);
        let noisy_second = SocketAddr::new(IpAddr::V4(noisy_ip), 20_000);
        let pair_bytes =
            rendezvous_peer_packet_len(noisy_first) + rendezvous_peer_packet_len(noisy_second);
        let admitted_pairs = RENDEZVOUS_SOURCE_RESPONSE_BURST_BYTES as usize / pair_bytes;
        let mut sent = 0_usize;
        let mut sender = |_: SocketAddr, _: [u8; 32], _: SocketAddr| {
            sent += 1;
            Ok(())
        };

        for index in 0..admitted_pairs {
            let token = rendezvous_token(index);
            server
                .process_registration(noisy_first, token, now)
                .unwrap();
            assert!(
                complete_rendezvous_with(&mut server, noisy_second, token, now, &mut sender)
                    .unwrap()
            );
        }
        let noisy_source = IpAddr::V4(noisy_ip);
        assert_eq!(
            server.source_response_budgets[&noisy_source]
                .budget
                .available_bytes,
            RENDEZVOUS_SOURCE_RESPONSE_BURST_BYTES
                - u64::try_from(admitted_pairs * pair_bytes).unwrap()
        );

        let throttled = rendezvous_token(admitted_pairs);
        server
            .process_registration(noisy_first, throttled, now)
            .unwrap();
        let global_before_denial = server.response_budget.available_bytes;
        assert!(
            !complete_rendezvous_with(&mut server, noisy_second, throttled, now, &mut sender,)
                .unwrap()
        );
        assert_eq!(server.response_budget.available_bytes, global_before_denial);
        assert_eq!(server.waiting[&throttled].source, noisy_first);

        let other_ip = Ipv4Addr::new(198, 51, 100, 40);
        let other_first = SocketAddr::new(IpAddr::V4(other_ip), 30_000);
        let other_second = SocketAddr::new(IpAddr::V4(other_ip), 40_000);
        let other = rendezvous_token(admitted_pairs + 1);
        server
            .process_registration(other_first, other, now)
            .unwrap();
        assert!(
            complete_rendezvous_with(&mut server, other_second, other, now, &mut sender).unwrap()
        );
        assert_eq!(
            server.response_budget.available_bytes,
            global_before_denial - u64::try_from(pair_bytes).unwrap()
        );
        assert_eq!(
            server.source_response_budgets[&IpAddr::V4(other_ip)]
                .budget
                .available_bytes,
            RENDEZVOUS_SOURCE_RESPONSE_BURST_BYTES - u64::try_from(pair_bytes).unwrap()
        );
        assert_rendezvous_source_counts(&server);
        assert_eq!(sent, (admitted_pairs + 1) * 2);
    }

    #[test]
    fn rendezvous_mixed_ipv4_ipv6_pair_reserves_exact_hierarchical_bytes() {
        let mut server = RendezvousServer::bind(loopback()).unwrap();
        let now = Instant::now();
        server.response_budget = RendezvousResponseBudget::global(now);
        server.source_response_budgets.clear();
        let ipv4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)), 10_000);
        let ipv6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 20_000);
        let pair_bytes = rendezvous_peer_packet_len(ipv4) + rendezvous_peer_packet_len(ipv6);
        assert_eq!(pair_bytes, 92);
        let token = rendezvous_token(0);
        let mut peer_lengths = Vec::new();
        let mut sender = |_: SocketAddr, _: [u8; 32], peer: SocketAddr| {
            peer_lengths.push(rendezvous_peer_packet_len(peer));
            Ok(())
        };
        server.process_registration(ipv4, token, now).unwrap();
        assert!(complete_rendezvous_with(&mut server, ipv6, token, now, &mut sender).unwrap());
        assert_eq!(peer_lengths, vec![52, 40]);
        assert_eq!(
            server.response_budget.available_bytes,
            RENDEZVOUS_RESPONSE_BURST_BYTES - 92
        );
        for source in [canonical_ip(ipv4.ip()), canonical_ip(ipv6.ip())] {
            assert_eq!(
                server.source_response_budgets[&source]
                    .budget
                    .available_bytes,
                RENDEZVOUS_SOURCE_RESPONSE_BURST_BYTES - 92
            );
        }

        let mut canonical_server = RendezvousServer::bind(loopback()).unwrap();
        canonical_server.response_budget = RendezvousResponseBudget::global(now);
        let shared_ipv4 = Ipv4Addr::new(192, 0, 2, 51);
        let mapped_ipv6 = Ipv6Addr::from(shared_ipv4.to_ipv6_mapped().octets());
        let first = SocketAddr::new(IpAddr::V4(shared_ipv4), 30_000);
        let second = SocketAddr::new(IpAddr::V6(mapped_ipv6), 40_000);
        let token = rendezvous_token(1);
        let mut sender = |_: SocketAddr, _: [u8; 32], _: SocketAddr| Ok(());
        canonical_server
            .process_registration(first, token, now)
            .unwrap();
        assert!(
            complete_rendezvous_with(&mut canonical_server, second, token, now, &mut sender)
                .unwrap()
        );
        assert_eq!(canonical_server.source_response_budgets.len(), 1);
        assert_eq!(
            canonical_server.source_response_budgets[&IpAddr::V4(shared_ipv4)]
                .budget
                .available_bytes,
            RENDEZVOUS_SOURCE_RESPONSE_BURST_BYTES - 92
        );
    }

    #[test]
    fn rendezvous_source_response_budget_state_is_bounded_and_expires() {
        let mut server = RendezvousServer::bind(loopback()).unwrap();
        let now = Instant::now();
        server.response_budget = RendezvousResponseBudget::global(now);
        for index in 0..MAX_RENDEZVOUS_RESPONSE_SOURCES {
            server.source_response_budgets.insert(
                IpAddr::V6(Ipv6Addr::from(index as u128 + 1)),
                RendezvousSourceResponseBudget::new(now),
            );
        }
        let global_before = server.response_budget.available_bytes;
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 60)), 10_000);
        let second = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 60)), 20_000);
        assert!(!server.reserve_pair_responses(first, second, 80, now));
        assert_eq!(
            server.source_response_budgets.len(),
            MAX_RENDEZVOUS_RESPONSE_SOURCES
        );
        assert_eq!(server.response_budget.available_bytes, global_before);

        let expired = now + RENDEZVOUS_SOURCE_RESPONSE_TTL + Duration::from_millis(1);
        server.expire_source_response_budgets(expired);
        assert!(server.source_response_budgets.is_empty());
        assert!(server.reserve_pair_responses(first, second, 80, expired));
        assert_eq!(server.source_response_budgets.len(), 2);
    }

    #[test]
    fn rendezvous_send_failure_spends_budgets_and_preserves_waiting_invariants() {
        let mut server = RendezvousServer::bind(loopback()).unwrap();
        let now = Instant::now();
        server.response_budget = RendezvousResponseBudget::global(now);
        server.source_response_budgets.clear();
        let first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 70)), 10_000);
        let second = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 20_000);
        let pair_bytes = rendezvous_peer_packet_len(first) + rendezvous_peer_packet_len(second);
        let token = rendezvous_token(0);
        server.process_registration(first, token, now).unwrap();
        let mut calls = 0_usize;
        let mut failing_sender = |_: SocketAddr, _: [u8; 32], _: SocketAddr| {
            calls += 1;
            if calls == 2 {
                Err(std::io::Error::other("injected second response failure"))
            } else {
                Ok(())
            }
        };
        assert!(
            complete_rendezvous_with(&mut server, second, token, now, &mut failing_sender).is_err()
        );
        assert_eq!(calls, 2);
        assert_eq!(server.waiting[&token].source, first);
        assert_rendezvous_source_counts(&server);
        assert_eq!(
            server.response_budget.available_bytes,
            RENDEZVOUS_RESPONSE_BURST_BYTES - u64::try_from(pair_bytes).unwrap()
        );
        for source in [canonical_ip(first.ip()), canonical_ip(second.ip())] {
            assert_eq!(
                server.source_response_budgets[&source]
                    .budget
                    .available_bytes,
                RENDEZVOUS_SOURCE_RESPONSE_BURST_BYTES - u64::try_from(pair_bytes).unwrap()
            );
        }

        let mut successful_sender = |_: SocketAddr, _: [u8; 32], _: SocketAddr| Ok(());
        assert!(
            complete_rendezvous_with(&mut server, second, token, now, &mut successful_sender)
                .unwrap()
        );
        assert!(!server.waiting.contains_key(&token));
        assert!(server.source_counts.is_empty());
        assert_eq!(
            server.response_budget.available_bytes,
            RENDEZVOUS_RESPONSE_BURST_BYTES - (2 * u64::try_from(pair_bytes).unwrap())
        );
        for source in [canonical_ip(first.ip()), canonical_ip(second.ip())] {
            assert_eq!(
                server.source_response_budgets[&source]
                    .budget
                    .available_bytes,
                RENDEZVOUS_SOURCE_RESPONSE_BURST_BYTES - (2 * u64::try_from(pair_bytes).unwrap())
            );
        }
    }

    #[test]
    fn rendezvous_server_limits_port_churn_but_admits_another_source() {
        let mut server = RendezvousServer::bind(loopback()).unwrap();
        let now = Instant::now();
        let noisy_ip = Ipv4Addr::new(192, 0, 2, 10);
        for index in 0..MAX_RENDEZVOUS_WAITING_PER_SOURCE {
            server
                .process_registration(
                    SocketAddr::new(IpAddr::V4(noisy_ip), 10_000 + index as u16),
                    rendezvous_token(index),
                    now,
                )
                .unwrap();
        }
        let rejected = rendezvous_token(MAX_RENDEZVOUS_WAITING_PER_SOURCE);
        server
            .process_registration(SocketAddr::new(IpAddr::V4(noisy_ip), 60_000), rejected, now)
            .unwrap();
        assert_eq!(server.waiting.len(), MAX_RENDEZVOUS_WAITING_PER_SOURCE);
        assert!(!server.waiting.contains_key(&rejected));

        let other = rendezvous_token(MAX_RENDEZVOUS_WAITING_PER_SOURCE + 1);
        server
            .process_registration(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)), 20_000),
                other,
                now,
            )
            .unwrap();
        assert!(server.waiting.contains_key(&other));
        assert_rendezvous_source_counts(&server);
        assert_eq!(server.source_counts[&IpAddr::V4(noisy_ip)], 64);
    }

    #[test]
    fn rendezvous_server_canonicalizes_ipv4_mapped_source_quotas() {
        let mut server = RendezvousServer::bind(loopback()).unwrap();
        let now = Instant::now();
        let ipv4 = Ipv4Addr::new(192, 0, 2, 11);
        let mapped = Ipv6Addr::from(ipv4.to_ipv6_mapped().octets());
        for index in 0..MAX_RENDEZVOUS_WAITING_PER_SOURCE {
            let ip = if index % 2 == 0 {
                IpAddr::V4(ipv4)
            } else {
                IpAddr::V6(mapped)
            };
            server
                .process_registration(
                    SocketAddr::new(ip, 10_000 + index as u16),
                    rendezvous_token(index),
                    now,
                )
                .unwrap();
        }
        let rejected = rendezvous_token(MAX_RENDEZVOUS_WAITING_PER_SOURCE);
        server
            .process_registration(SocketAddr::new(IpAddr::V6(mapped), 60_000), rejected, now)
            .unwrap();
        assert_eq!(server.waiting.len(), MAX_RENDEZVOUS_WAITING_PER_SOURCE);
        assert!(!server.waiting.contains_key(&rejected));
        assert_rendezvous_source_counts(&server);
        assert_eq!(server.source_counts.len(), 1);
    }

    #[test]
    fn rendezvous_server_global_capacity_expires_on_absolute_time() {
        let mut server = RendezvousServer::bind(loopback()).unwrap();
        let registered_at = Instant::now();
        for index in 0..MAX_RENDEZVOUS_WAITING {
            let source_index = index / MAX_RENDEZVOUS_WAITING_PER_SOURCE;
            let source = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, source_index as u8, 1)),
                10_000 + (index % MAX_RENDEZVOUS_WAITING_PER_SOURCE) as u16,
            );
            server
                .process_registration(source, rendezvous_token(index), registered_at)
                .unwrap();
        }
        assert_eq!(server.waiting.len(), MAX_RENDEZVOUS_WAITING);

        let extra = rendezvous_token(MAX_RENDEZVOUS_WAITING);
        let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 30_000);
        server
            .process_registration(other, extra, registered_at)
            .unwrap();
        assert!(!server.waiting.contains_key(&extra));

        // A duplicate immediately before expiry cannot refresh the original
        // registration's absolute lifetime.
        server
            .process_registration(
                server.waiting[&rendezvous_token(0)].source,
                rendezvous_token(0),
                registered_at + RENDEZVOUS_REGISTRATION_TTL,
            )
            .unwrap();
        let after_expiry = registered_at + RENDEZVOUS_REGISTRATION_TTL + Duration::from_millis(1);
        server.expire_waiting(after_expiry);
        server
            .process_registration(other, extra, after_expiry)
            .unwrap();
        assert_eq!(server.waiting.len(), 1);
        assert!(server.waiting.contains_key(&extra));
        assert_rendezvous_source_counts(&server);
        assert_eq!(server.source_counts.get(&other.ip()), Some(&1));
    }

    #[test]
    fn rendezvous_poll_yields_and_queued_pairing_still_progresses() {
        let mut server = RendezvousServer::bind(loopback()).unwrap();
        let attacker = UdpSocket::bind(loopback()).unwrap();
        let legitimate = UdpSocket::bind(loopback()).unwrap();
        legitimate
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let server_address = server.local_addr().unwrap();
        let paired_token = rendezvous_token(0);
        for index in 0..MAX_RENDEZVOUS_DATAGRAMS_PER_POLL {
            let packet = rendezvous_registration_packet(rendezvous_token(index));
            attacker.send_to(&packet, server_address).unwrap();
        }
        let packet = rendezvous_registration_packet(paired_token);
        legitimate.send_to(&packet, server_address).unwrap();

        assert_eq!(server.poll().unwrap(), MAX_RENDEZVOUS_DATAGRAMS_PER_POLL);
        assert!(server.waiting.contains_key(&paired_token));
        for _ in 0..50 {
            assert!(server.poll().unwrap() <= MAX_RENDEZVOUS_DATAGRAMS_PER_POLL);
            let mut response = [0_u8; 64];
            match legitimate.recv_from(&mut response) {
                Ok((length, _)) => {
                    assert!(length >= 40);
                    assert_eq!(response[0], RENDEZVOUS_PEER);
                    assert_eq!(&response[1..33], &paired_token);
                    assert!(!server.waiting.contains_key(&paired_token));
                    return;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => panic!("could not receive rendezvous response: {error}"),
            }
        }
        panic!("queued legitimate rendezvous registration did not progress");
    }
}
