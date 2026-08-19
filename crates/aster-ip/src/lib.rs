//! Infrastructure-free UDP link, local discovery, NAT rendezvous, and optional
//! opaque ciphertext relay for the Aster protocol.
//!
//! The adapter never interprets protocol content. All data frames are expected
//! to have already passed through the core's authenticated-adjacency layer.

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

const DATA: u8 = 0;
const DISCOVERY: u8 = 1;
const RENDEZVOUS_REGISTER: u8 = 2;
const RENDEZVOUS_PEER: u8 = 3;
const PUNCH: u8 = 4;
const MAX_DATAGRAM: usize = 65_507;
const MAX_PEERS: usize = 4_096;
const MAX_DISCOVERED: usize = 4_096;
const MAX_PUNCH_TOKENS: usize = 128;
const MAX_RENDEZVOUS_WAITING: usize = 4_096;
const RENDEZVOUS_REGISTRATION_TTL: Duration = Duration::from_secs(120);
const DISCOVERY_PROOF_DOMAIN: &[u8] = b"aster/ip-discovery-proof/v1";
const ENDPOINT_HANDLE_DOMAIN: &[u8] = b"aster/ip-endpoint-handle/v1";

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
    punch_tokens: Mutex<BTreeSet<RendezvousToken>>,
    discovery_token: [u8; 16],
    endpoint_handle_seed: [u8; 32],
    discovery_target: Option<SocketAddr>,
    discovery_enabled: AtomicBool,
    rendezvous_server: Mutex<Option<SocketAddr>>,
}

impl IpLink {
    /// Binds a nonblocking UDP link.
    ///
    /// `discovery_token` is provisioned opaque material, not an identity. It is
    /// never transmitted: each advertisement carries a fresh nonce and HKDF
    /// proof. A zero token is rejected so an unprovisioned default cannot form
    /// a group.
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
            punch_tokens: Mutex::new(BTreeSet::new()),
            discovery_token,
            endpoint_handle_seed,
            discovery_target,
            discovery_enabled: AtomicBool::new(true),
            rendezvous_server: Mutex::new(None),
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
        if let Some(address) = self.peers.write().expect("peer lock poisoned").remove(peer) {
            self.reverse_peers
                .write()
                .expect("peer lock poisoned")
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
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(io::Error::other)?;
        let proof = discovery_proof(&self.discovery_token, &nonce)?;
        let mut packet = [0_u8; 33];
        packet[0] = DISCOVERY;
        packet[1..17].copy_from_slice(&nonce);
        packet[17..].copy_from_slice(&proof);
        self.socket.send_to(&packet, target)?;
        Ok(())
    }

    /// Drains addresses that advertised the provisioned opaque token.
    pub fn take_discovered(&self) -> Vec<SocketAddr> {
        let mut discovered = self.discovered.lock().expect("discovery lock poisoned");
        let result = discovered.iter().copied().collect();
        discovered.clear();
        result
    }

    /// Registers a high-entropy token accepted for an incoming NAT punch.
    pub fn accept_punch(&self, token: RendezvousToken) -> io::Result<()> {
        let mut tokens = self.punch_tokens.lock().map_err(lock_error)?;
        if !tokens.contains(&token) && tokens.len() >= MAX_PUNCH_TOKENS {
            return Err(io::Error::other("NAT punch-token capacity reached"));
        }
        tokens.insert(token);
        Ok(())
    }

    /// Sends a rendezvous registration from this exact UDP socket. A server sees
    /// the translated endpoint and returns another registration's endpoint.
    ///
    /// The token is an opaque pairing value, not authentication. The mandatory
    /// core handshake authenticates the resulting path.
    ///
    /// # Errors
    ///
    /// Returns an I/O error when the datagram cannot be sent.
    pub fn request_rendezvous(&self, server: SocketAddr, token: RendezvousToken) -> io::Result<()> {
        self.accept_punch(token)?;
        *self.rendezvous_server.lock().map_err(lock_error)? = Some(server);
        let mut packet = [0_u8; 33];
        packet[0] = RENDEZVOUS_REGISTER;
        packet[1..].copy_from_slice(&token);
        self.socket.send_to(&packet, server)?;
        Ok(())
    }

    fn process_control(&self, source: SocketAddr, packet: &[u8]) -> io::Result<bool> {
        match packet.first().copied() {
            Some(DISCOVERY) if packet.len() == 33 => {
                let mut nonce = [0_u8; 16];
                nonce.copy_from_slice(&packet[1..17]);
                if discovery_proof(&self.discovery_token, &nonce)?.as_slice() == &packet[17..] {
                    self.remember_discovered(source)?;
                }
                Ok(true)
            }
            Some(RENDEZVOUS_PEER) => {
                let server = *self
                    .rendezvous_server
                    .lock()
                    .expect("rendezvous lock poisoned");
                if server != Some(source) {
                    return Ok(true);
                }
                if packet.len() < 34 {
                    return Ok(true);
                }
                let mut token = [0_u8; 32];
                token.copy_from_slice(&packet[1..33]);
                if !self
                    .punch_tokens
                    .lock()
                    .map_err(lock_error)?
                    .contains(&token)
                {
                    return Ok(true);
                }
                let peer = decode_socket_addr(&packet[33..])?;
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
                if self.punch_tokens.lock().map_err(lock_error)?.remove(&token) {
                    self.remember_discovered(source)?;
                }
                Ok(true)
            }
            _ => Ok(false),
        }
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
        if let Ok(tokens) = self.punch_tokens.get_mut() {
            for mut token in std::mem::take(tokens) {
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
                .expect("peer lock poisoned")
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
        loop {
            match self.socket.recv_from(&mut packet) {
                Ok((length, source)) if length > 0 => {
                    let packet = &packet[..length];
                    if self.process_control(source, packet)? {
                        continue;
                    }
                    if packet[0] != DATA {
                        continue;
                    }
                    let known = self
                        .reverse_peers
                        .read()
                        .expect("peer lock poisoned")
                        .get(&source)
                        .copied();
                    let peer = known.or_else(|| self.register_endpoint(source).ok());
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
    }

    fn set_discovery(&self, enabled: bool) -> io::Result<()> {
        self.discovery_enabled.store(enabled, Ordering::Release);
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
#[derive(Debug)]
pub struct RendezvousServer {
    socket: UdpSocket,
    waiting: BTreeMap<RendezvousToken, (SocketAddr, Instant)>,
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

    /// Processes all currently queued registrations without blocking.
    ///
    /// # Errors
    ///
    /// Returns an I/O error for malformed addresses or socket failures.
    pub fn poll(&mut self) -> io::Result<usize> {
        let mut processed = 0;
        let now = Instant::now();
        self.waiting.retain(|_, (_, registered)| {
            now.saturating_duration_since(*registered) <= RENDEZVOUS_REGISTRATION_TTL
        });
        let mut packet = [0_u8; 128];
        loop {
            match self.socket.recv_from(&mut packet) {
                Ok((33, source)) if packet[0] == RENDEZVOUS_REGISTER => {
                    processed += 1;
                    let mut token = [0_u8; 32];
                    token.copy_from_slice(&packet[1..33]);
                    if let Some((first, _)) = self.waiting.remove(&token) {
                        if first != source {
                            send_peer(&self.socket, first, token, source)?;
                            send_peer(&self.socket, source, token, first)?;
                        } else {
                            self.waiting.insert(token, (source, Instant::now()));
                        }
                    } else if self.waiting.len() < MAX_RENDEZVOUS_WAITING {
                        self.waiting.insert(token, (source, Instant::now()));
                    }
                }
                Ok(_) => {
                    processed += 1;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(processed),
                Err(error) => return Err(error),
            }
        }
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
    use super::{IpLink, RendezvousServer, discovery_proof};
    use aster_mesh::link::Link;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::thread;
    use std::time::Duration;

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[test]
    fn discovery_proofs_do_not_expose_or_reuse_the_provisioned_token() {
        let token = [7; 16];
        let first = discovery_proof(&token, &[1; 16]).unwrap();
        let second = discovery_proof(&token, &[2; 16]).unwrap();
        assert_ne!(first, token);
        assert_ne!(first, second);
        assert_ne!(first, discovery_proof(&[8; 16], &[1; 16]).unwrap());
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
    fn unknown_endpoint_uses_a_local_handle_until_identity_is_authenticated() {
        let token = [6; 16];
        let a = IpLink::bind("a", loopback(), token, None).unwrap();
        let b = IpLink::bind("b", loopback(), token, None).unwrap();
        a.register_peer([2; 32], b.local_addr().unwrap()).unwrap();
        a.send(Some([2; 32]), b"first-flight fragment").unwrap();
        let first = loop {
            if let Some(frame) = b.try_receive().unwrap() {
                break frame;
            }
        };
        let route = first.peer.unwrap();
        assert_ne!(route, [1; 32]);
        assert_eq!(b.register_endpoint(a.local_addr().unwrap()).unwrap(), route);

        b.register_peer([1; 32], a.local_addr().unwrap()).unwrap();
        a.send(Some([2; 32]), b"authenticated fragment").unwrap();
        let second = loop {
            if let Some(frame) = b.try_receive().unwrap() {
                break frame;
            }
        };
        assert_eq!(second.peer, Some([1; 32]));
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
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        panic!("rendezvous did not pair clients");
    }
}
