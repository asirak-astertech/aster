use crate::{
    behaviour::{ActivationError, AsterBehaviour, AsterEvent, SendFrameError},
    framing::FrameLimits,
    protocol::ASTER_PROTOCOL,
    types::{
        CarrierDescriptor, CarrierPath, CarrierSelectionError, DialCandidate, NatReachability,
        ProviderEvent, SessionId, select_preferred_carrier,
    },
};
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, connection_limits,
    core::transport::ListenerId,
    dcutr, identify,
    identity::Keypair,
    memory_connection_limits, noise, relay,
    swarm::{
        ConnectionId, NetworkBehaviour, SwarmEvent,
        dial_opts::{DialOpts, PeerCondition},
    },
    tcp, yamux,
};
use libp2p_autonat as autonat;
use std::{
    collections::{HashMap, HashSet},
    convert::Infallible,
    fmt,
    num::NonZeroUsize,
    time::Duration,
};

const MAX_CONNECTIONS_HARD: u32 = 1024;
const MAX_FRAME_BYTES_HARD: usize = 1_048_576;
const MAX_QUEUED_FRAMES_HARD: usize = 1024;
const MAX_QUEUED_BYTES_HARD: usize = 16 * 1_048_576;
const MAX_RELAY_RESERVATIONS_HARD: usize = 8;
const MAX_AUTONAT_SERVERS_HARD: usize = 32;
const MAX_IDENTIFY_CACHE_HARD: usize = 1024;
const MAX_YAMUX_STREAMS_HARD: usize = 256;

/// All provider-local limits. The host supervisor separately owns the
/// process-wide resource budget and reserves provider capacity as a unit.
#[derive(Clone, Debug)]
pub struct AdapterConfig {
    pub max_pending_connections: u32,
    pub max_established_connections: u32,
    pub max_connections_per_peer: u32,
    pub max_yamux_streams_per_connection: usize,
    pub max_frame_bytes: usize,
    pub max_queued_frames_per_session: usize,
    pub max_queued_bytes_per_session: usize,
    pub max_process_memory_bytes: usize,
    pub max_relay_reservations: usize,
    pub max_autonat_servers: usize,
    pub max_autonat_peer_addresses: usize,
    pub identify_cache_size: usize,
    pub connection_timeout: Duration,
    pub stream_negotiation_timeout: Duration,
    pub idle_connection_timeout: Duration,
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            max_pending_connections: 32,
            max_established_connections: 16,
            max_connections_per_peer: 2,
            max_yamux_streams_per_connection: 32,
            max_frame_bytes: MAX_FRAME_BYTES_HARD,
            max_queued_frames_per_session: 16,
            max_queued_bytes_per_session: 4 * MAX_FRAME_BYTES_HARD,
            max_process_memory_bytes: 1024 * MAX_FRAME_BYTES_HARD,
            max_relay_reservations: 2,
            max_autonat_servers: 4,
            max_autonat_peer_addresses: 4,
            identify_cache_size: 32,
            connection_timeout: Duration::from_secs(10),
            stream_negotiation_timeout: Duration::from_secs(10),
            idle_connection_timeout: Duration::from_secs(90),
        }
    }
}

impl AdapterConfig {
    fn validate(&self) -> Result<(), AdapterError> {
        if self.max_pending_connections == 0 || self.max_pending_connections > MAX_CONNECTIONS_HARD
        {
            return Err(AdapterError::InvalidConfig("pending connection bound"));
        }
        if self.max_established_connections == 0
            || self.max_established_connections > MAX_CONNECTIONS_HARD
        {
            return Err(AdapterError::InvalidConfig("established connection bound"));
        }
        if self.max_connections_per_peer < 2
            || self.max_connections_per_peer > self.max_established_connections
        {
            return Err(AdapterError::InvalidConfig(
                "per-peer bound must allow relay/direct coexistence",
            ));
        }
        if self.max_yamux_streams_per_connection == 0
            || self.max_yamux_streams_per_connection > MAX_YAMUX_STREAMS_HARD
        {
            return Err(AdapterError::InvalidConfig("yamux stream bound"));
        }
        if self.max_frame_bytes == 0 || self.max_frame_bytes > MAX_FRAME_BYTES_HARD {
            return Err(AdapterError::InvalidConfig("frame byte bound"));
        }
        if self.max_queued_frames_per_session == 0
            || self.max_queued_frames_per_session > MAX_QUEUED_FRAMES_HARD
        {
            return Err(AdapterError::InvalidConfig("outbound frame queue bound"));
        }
        if self.max_queued_bytes_per_session < self.max_frame_bytes
            || self.max_queued_bytes_per_session > MAX_QUEUED_BYTES_HARD
        {
            return Err(AdapterError::InvalidConfig("outbound byte queue bound"));
        }
        if self.max_process_memory_bytes == 0 {
            return Err(AdapterError::InvalidConfig("process memory threshold"));
        }
        if self.max_relay_reservations == 0
            || self.max_relay_reservations > MAX_RELAY_RESERVATIONS_HARD
        {
            return Err(AdapterError::InvalidConfig("relay reservation bound"));
        }
        if self.max_autonat_servers == 0
            || self.max_autonat_servers > MAX_AUTONAT_SERVERS_HARD
            || self.max_autonat_peer_addresses == 0
            || self.max_autonat_peer_addresses > MAX_AUTONAT_SERVERS_HARD
        {
            return Err(AdapterError::InvalidConfig("AutoNAT v1 bound"));
        }
        if self.identify_cache_size == 0 || self.identify_cache_size > MAX_IDENTIFY_CACHE_HARD {
            return Err(AdapterError::InvalidConfig("Identify cache bound"));
        }
        if self.connection_timeout.is_zero()
            || self.stream_negotiation_timeout.is_zero()
            || self.idle_connection_timeout.is_zero()
        {
            return Err(AdapterError::InvalidConfig("zero provider timeout"));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum AdapterError {
    InvalidConfig(&'static str),
    Build(String),
    Transport(String),
    Capacity(&'static str),
    UnknownRelayReservation,
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(message) => write!(formatter, "invalid adapter config: {message}"),
            Self::Build(message) => write!(formatter, "failed to build libp2p swarm: {message}"),
            Self::Transport(message) => write!(formatter, "libp2p transport error: {message}"),
            Self::Capacity(message) => write!(formatter, "provider capacity reached: {message}"),
            Self::UnknownRelayReservation => formatter.write_str("unknown relay reservation"),
        }
    }
}

impl std::error::Error for AdapterError {}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "CompositeEvent")]
struct CompositeBehaviour {
    aster: AsterBehaviour,
    identify: identify::Behaviour,
    autonat_v1: autonat::Behaviour,
    relay_client: relay::client::Behaviour,
    dcutr: dcutr::Behaviour,
    connection_limits: connection_limits::Behaviour,
    memory_limits: memory_connection_limits::Behaviour,
}

#[derive(Debug)]
enum CompositeEvent {
    Aster(AsterEvent),
    Identify(Box<identify::Event>),
    AutonatV1(autonat::Event),
    RelayClient(relay::client::Event),
    Dcutr(dcutr::Event),
    Infallible(Infallible),
}

impl From<AsterEvent> for CompositeEvent {
    fn from(event: AsterEvent) -> Self {
        Self::Aster(event)
    }
}
impl From<identify::Event> for CompositeEvent {
    fn from(event: identify::Event) -> Self {
        Self::Identify(Box::new(event))
    }
}
impl From<autonat::Event> for CompositeEvent {
    fn from(event: autonat::Event) -> Self {
        Self::AutonatV1(event)
    }
}
impl From<relay::client::Event> for CompositeEvent {
    fn from(event: relay::client::Event) -> Self {
        Self::RelayClient(event)
    }
}
impl From<dcutr::Event> for CompositeEvent {
    fn from(event: dcutr::Event) -> Self {
        Self::Dcutr(event)
    }
}
impl From<Infallible> for CompositeEvent {
    fn from(event: Infallible) -> Self {
        Self::Infallible(event)
    }
}

/// One provider instance owns exactly one persistent libp2p `Swarm`.
pub struct Libp2pAdapter {
    swarm: Swarm<CompositeBehaviour>,
    config: AdapterConfig,
    pending_dials: HashSet<ConnectionId>,
    relay_listeners: HashMap<ListenerId, Multiaddr>,
    autonat_servers: HashSet<PeerId>,
}

impl Libp2pAdapter {
    pub fn new(keypair: Keypair, config: AdapterConfig) -> Result<Self, AdapterError> {
        config.validate()?;
        let max_yamux_streams = config.max_yamux_streams_per_connection;
        let behaviour_config = config.clone();
        let frame_limits = FrameLimits {
            max_frame_bytes: config.max_frame_bytes,
            max_queued_frames: config.max_queued_frames_per_session,
            max_queued_bytes: config.max_queued_bytes_per_session,
        };
        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                move || bounded_yamux(max_yamux_streams),
            )
            .map_err(|error| AdapterError::Build(error.to_string()))?
            .with_relay_client(noise::Config::new, move || bounded_yamux(max_yamux_streams))
            .map_err(|error| AdapterError::Build(error.to_string()))?
            .with_behaviour(move |key, relay_client| {
                let local_peer_id = key.public().to_peer_id();
                let autonat_config = autonat::Config {
                    use_connected: false,
                    max_peer_addresses: behaviour_config.max_autonat_peer_addresses,
                    throttle_clients_global_max: behaviour_config
                        .max_autonat_servers
                        .saturating_mul(2),
                    throttle_clients_peer_max: 2,
                    only_global_ips: false,
                    ..autonat::Config::default()
                };
                let identify = identify::Behaviour::new(
                    identify::Config::new_with_signed_peer_record(
                        "/aster/ip-mesh/2".to_owned(),
                        key,
                    )
                    .with_agent_version(format!(
                        "aster-libp2p-provider/{}",
                        env!("CARGO_PKG_VERSION")
                    ))
                    .with_cache_size(behaviour_config.identify_cache_size)
                    .with_push_listen_addr_updates(true),
                );
                let connection_limits = connection_limits::Behaviour::new(
                    connection_limits::ConnectionLimits::default()
                        .with_max_pending_incoming(Some(behaviour_config.max_pending_connections))
                        .with_max_pending_outgoing(Some(behaviour_config.max_pending_connections))
                        .with_max_established(Some(behaviour_config.max_established_connections))
                        .with_max_established_per_peer(Some(
                            behaviour_config.max_connections_per_peer,
                        )),
                );
                CompositeBehaviour {
                    aster: AsterBehaviour::new(
                        local_peer_id,
                        frame_limits,
                        behaviour_config.stream_negotiation_timeout,
                    ),
                    identify,
                    autonat_v1: autonat::Behaviour::new(local_peer_id, autonat_config),
                    relay_client,
                    dcutr: dcutr::Behaviour::new(local_peer_id),
                    connection_limits,
                    memory_limits: memory_connection_limits::Behaviour::with_max_bytes(
                        behaviour_config.max_process_memory_bytes,
                    ),
                }
            })
            .map_err(|error| AdapterError::Build(error.to_string()))?
            .with_swarm_config(|swarm_config| {
                swarm_config
                    .with_idle_connection_timeout(config.idle_connection_timeout)
                    .with_notify_handler_buffer_size(
                        NonZeroUsize::new(config.max_queued_frames_per_session)
                            .expect("validated nonzero queue bound"),
                    )
                    .with_per_connection_event_buffer_size(config.max_queued_frames_per_session)
                    .with_max_negotiating_inbound_streams(config.max_yamux_streams_per_connection)
            })
            .with_connection_timeout(config.connection_timeout)
            .build();
        Ok(Self {
            swarm,
            config,
            pending_dials: HashSet::new(),
            relay_listeners: HashMap::new(),
            autonat_servers: HashSet::new(),
        })
    }

    pub fn local_peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    pub fn listen(&mut self, address: Multiaddr) -> Result<ListenerId, AdapterError> {
        self.swarm
            .listen_on(address)
            .map_err(|e| AdapterError::Transport(format!("{e:?}")))
    }

    pub fn dial(&mut self, candidate: DialCandidate) -> Result<ConnectionId, AdapterError> {
        // A discovery dial is an ordinary carrier attempt, not a hole punch.
        // A fresh source port prevents simultaneous dials from collapsing into
        // one TCP simultaneous-open where both Noise sides assume dialer role.
        let opts = match candidate.expected_peer_id {
            Some(peer_id) => DialOpts::peer_id(peer_id)
                .addresses(vec![candidate.address])
                .allocate_new_port()
                .build(),
            None => DialOpts::unknown_peer_id()
                .address(candidate.address)
                .allocate_new_port()
                .build(),
        };
        self.submit_dial(opts)
    }

    /// Dials a known peer even while its predecessor connection remains live.
    ///
    /// The caller must still use the two-phase replacement API before the new
    /// connection can carry Aster traffic. This method changes only libp2p's
    /// dial condition; it does not select or activate the new session.
    pub fn dial_replacement(
        &mut self,
        candidate: DialCandidate,
    ) -> Result<ConnectionId, AdapterError> {
        let peer_id = candidate
            .expected_peer_id
            .ok_or(AdapterError::InvalidConfig(
                "replacement dial requires an expected PeerId",
            ))?;
        let opts = DialOpts::peer_id(peer_id)
            .condition(PeerCondition::Always)
            .addresses(vec![candidate.address])
            .allocate_new_port()
            .build();
        self.submit_dial(opts)
    }

    fn submit_dial(&mut self, opts: DialOpts) -> Result<ConnectionId, AdapterError> {
        if self.pending_dials.len() >= self.config.max_pending_connections as usize {
            return Err(AdapterError::Capacity("pending dial candidates"));
        }
        let connection_id = opts.connection_id();
        self.swarm
            .dial(opts)
            .map_err(|e| AdapterError::Transport(format!("{e:?}")))?;
        self.pending_dials.insert(connection_id);
        Ok(connection_id)
    }

    pub fn activate_session(&mut self, session: SessionId) -> Result<(), ActivationError> {
        self.swarm.behaviour_mut().aster.activate(session)
    }

    pub fn preferred_carrier(
        &self,
        remote_peer_id: PeerId,
        carriers: &[CarrierDescriptor],
    ) -> Result<Option<SessionId>, CarrierSelectionError> {
        select_preferred_carrier(self.local_peer_id(), remote_peer_id, carriers)
    }

    pub fn deactivate_session(&mut self, session: SessionId) -> Result<(), ActivationError> {
        self.swarm.behaviour_mut().aster.deactivate(session)
    }

    pub fn begin_replacement(
        &mut self,
        old: SessionId,
        new: SessionId,
    ) -> Result<(), ActivationError> {
        self.swarm.behaviour_mut().aster.begin_replacement(old, new)
    }

    pub fn complete_replacement(
        &mut self,
        old: SessionId,
        new: SessionId,
    ) -> Result<(), ActivationError> {
        self.swarm
            .behaviour_mut()
            .aster
            .complete_replacement(old, new)
    }

    pub fn send_frame(&mut self, session: SessionId, frame: Vec<u8>) -> Result<(), SendFrameError> {
        self.swarm.behaviour_mut().aster.send_frame(session, frame)
    }

    pub fn close_connection(&mut self, session: SessionId) -> bool {
        self.swarm.close_connection(session.connection_id)
    }

    pub fn reserve_relay(
        &mut self,
        mut relay_address: Multiaddr,
    ) -> Result<ListenerId, AdapterError> {
        if self.relay_listeners.len() >= self.config.max_relay_reservations {
            return Err(AdapterError::Capacity("relay reservations"));
        }
        if !relay_address
            .iter()
            .any(|protocol| protocol == libp2p::multiaddr::Protocol::P2pCircuit)
        {
            relay_address.push(libp2p::multiaddr::Protocol::P2pCircuit);
        }
        if self.relay_listeners.values().any(|a| a == &relay_address) {
            return Err(AdapterError::Capacity("duplicate relay reservation"));
        }
        let listener = self
            .swarm
            .listen_on(relay_address.clone())
            .map_err(|e| AdapterError::Transport(format!("{e:?}")))?;
        self.relay_listeners.insert(listener, relay_address);
        Ok(listener)
    }

    pub fn remove_relay_reservation(&mut self, listener: ListenerId) -> Result<(), AdapterError> {
        if self.relay_listeners.remove(&listener).is_none() {
            return Err(AdapterError::UnknownRelayReservation);
        }
        let _ = self.swarm.remove_listener(listener);
        Ok(())
    }

    pub fn add_autonat_server(
        &mut self,
        peer_id: PeerId,
        address: Option<Multiaddr>,
    ) -> Result<(), AdapterError> {
        if !self.autonat_servers.contains(&peer_id)
            && self.autonat_servers.len() >= self.config.max_autonat_servers
        {
            return Err(AdapterError::Capacity("AutoNAT servers"));
        }
        self.autonat_servers.insert(peer_id);
        self.swarm
            .behaviour_mut()
            .autonat_v1
            .add_server(peer_id, address);
        Ok(())
    }

    pub fn remove_autonat_server(&mut self, peer_id: &PeerId) {
        self.autonat_servers.remove(peer_id);
        self.swarm.behaviour_mut().autonat_v1.remove_server(peer_id);
    }

    pub async fn next_event(&mut self) -> ProviderEvent {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(event) => {
                    if let Some(event) = map_behaviour_event(event) {
                        return event;
                    }
                }
                SwarmEvent::IncomingConnection {
                    connection_id,
                    local_addr,
                    send_back_addr,
                } => {
                    return ProviderEvent::IncomingCarrier {
                        connection_id,
                        local_address: local_addr,
                        remote_address: send_back_addr,
                    };
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id,
                    connection_id,
                    endpoint,
                    ..
                } => {
                    self.pending_dials.remove(&connection_id);
                    return ProviderEvent::CarrierEstablished {
                        session: SessionId {
                            peer_id,
                            connection_id,
                        },
                        path: if endpoint.is_relayed() {
                            CarrierPath::Relayed
                        } else {
                            CarrierPath::Direct
                        },
                        outbound: endpoint.is_dialer(),
                        remote_address: endpoint.get_remote_address().clone(),
                    };
                }
                SwarmEvent::ConnectionClosed {
                    peer_id,
                    connection_id,
                    cause,
                    ..
                } => {
                    self.pending_dials.remove(&connection_id);
                    return ProviderEvent::CarrierClosed {
                        session: SessionId {
                            peer_id,
                            connection_id,
                        },
                        cause: cause.map(|error| error.to_string()),
                    };
                }
                SwarmEvent::IncomingConnectionError {
                    connection_id,
                    peer_id,
                    error,
                    ..
                } => {
                    return ProviderEvent::TransportFailure {
                        connection_id: Some(connection_id),
                        peer_id,
                        error: error.to_string(),
                    };
                }
                SwarmEvent::OutgoingConnectionError {
                    connection_id,
                    peer_id,
                    error,
                } => {
                    self.pending_dials.remove(&connection_id);
                    return ProviderEvent::TransportFailure {
                        connection_id: Some(connection_id),
                        peer_id,
                        error: error.to_string(),
                    };
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    return ProviderEvent::Listening { address };
                }
                SwarmEvent::ListenerClosed {
                    listener_id,
                    reason,
                    ..
                } => {
                    self.relay_listeners.remove(&listener_id);
                    if let Err(error) = reason {
                        return ProviderEvent::TransportFailure {
                            connection_id: None,
                            peer_id: None,
                            error: error.to_string(),
                        };
                    }
                }
                SwarmEvent::ListenerError { error, .. } => {
                    return ProviderEvent::TransportFailure {
                        connection_id: None,
                        peer_id: None,
                        error: error.to_string(),
                    };
                }
                SwarmEvent::NewExternalAddrCandidate { address } => {
                    return ProviderEvent::ExternalAddressCandidate { address };
                }
                SwarmEvent::ExternalAddrConfirmed { address } => {
                    return ProviderEvent::ExternalAddressConfirmed { address };
                }
                _ => {}
            }
        }
    }
}

fn bounded_yamux(max_streams: usize) -> yamux::Config {
    let mut config = yamux::Config::default();
    config.set_max_num_streams(max_streams);
    config
}

fn map_behaviour_event(event: CompositeEvent) -> Option<ProviderEvent> {
    match event {
        CompositeEvent::Aster(AsterEvent::StreamOpened { session, direction }) => {
            Some(ProviderEvent::StreamOpened { session, direction })
        }
        CompositeEvent::Aster(AsterEvent::FrameReceived { session, frame }) => {
            Some(ProviderEvent::FrameReceived { session, frame })
        }
        CompositeEvent::Aster(AsterEvent::FrameSent { session, bytes }) => {
            Some(ProviderEvent::FrameSent { session, bytes })
        }
        CompositeEvent::Aster(AsterEvent::SendRejected {
            session,
            bytes,
            reason,
        }) => Some(ProviderEvent::SendRejected {
            session,
            bytes,
            reason: format!("{reason:?}"),
        }),
        CompositeEvent::Aster(AsterEvent::StreamFailed { session, reason }) => {
            Some(ProviderEvent::StreamFailed { session, reason })
        }
        CompositeEvent::Aster(AsterEvent::ReplacementReady {
            retired,
            replacement,
        }) => Some(ProviderEvent::ReplacementReady {
            retired,
            replacement,
        }),
        CompositeEvent::Identify(event) => match *event {
            identify::Event::Received {
                connection_id,
                peer_id,
                info,
            } => Some(ProviderEvent::IdentifyObserved {
                session: SessionId {
                    peer_id,
                    connection_id,
                },
                observed_address: info.observed_addr,
                supports_aster: info
                    .protocols
                    .iter()
                    .any(|protocol| protocol.as_ref() == ASTER_PROTOCOL),
            }),
            _ => None,
        },
        CompositeEvent::AutonatV1(autonat::Event::StatusChanged { old, new }) => {
            Some(ProviderEvent::NatStatusChanged {
                old: map_nat_status(old),
                new: map_nat_status(new),
            })
        }
        CompositeEvent::AutonatV1(_) => None,
        CompositeEvent::RelayClient(relay::client::Event::ReservationReqAccepted {
            relay_peer_id,
            renewal,
            ..
        }) => Some(ProviderEvent::RelayReservationAccepted {
            relay_peer_id,
            renewal,
        }),
        CompositeEvent::RelayClient(relay::client::Event::OutboundCircuitEstablished {
            relay_peer_id,
            ..
        }) => Some(ProviderEvent::RelayCircuitEstablished {
            peer_id: relay_peer_id,
            inbound: false,
        }),
        CompositeEvent::RelayClient(relay::client::Event::InboundCircuitEstablished {
            src_peer_id,
            ..
        }) => Some(ProviderEvent::RelayCircuitEstablished {
            peer_id: src_peer_id,
            inbound: true,
        }),
        CompositeEvent::Dcutr(event) => match event.result {
            Ok(connection_id) => Some(ProviderEvent::HolePunchFinished {
                peer_id: event.remote_peer_id,
                direct_connection: Some(connection_id),
                error: None,
            }),
            Err(error) => Some(ProviderEvent::HolePunchFinished {
                peer_id: event.remote_peer_id,
                direct_connection: None,
                error: Some(error.to_string()),
            }),
        },
        CompositeEvent::Infallible(event) => match event {},
    }
}

fn map_nat_status(status: autonat::NatStatus) -> NatReachability {
    match status {
        autonat::NatStatus::Unknown => NatReachability::Unknown,
        autonat::NatStatus::Private => NatReachability::Private,
        autonat::NatStatus::Public(address) => NatReachability::Public(address),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(NetworkBehaviour)]
    struct ControlledRelayBehaviour {
        relay: relay::Behaviour,
        identify: identify::Behaviour,
    }

    fn controlled_relay_server() -> Swarm<ControlledRelayBehaviour> {
        SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                || bounded_yamux(8),
            )
            .expect("controlled relay transport must build")
            .with_behaviour(|key| {
                let local_peer_id = key.public().to_peer_id();
                ControlledRelayBehaviour {
                    relay: relay::Behaviour::new(
                        local_peer_id,
                        relay::Config {
                            max_reservations: 2,
                            max_reservations_per_peer: 1,
                            reservation_duration: Duration::from_secs(30),
                            reservation_rate_limiters: Vec::new(),
                            max_circuits: 2,
                            max_circuits_per_peer: 1,
                            max_circuit_duration: Duration::from_secs(30),
                            max_circuit_bytes: 1_048_576,
                            circuit_src_rate_limiters: Vec::new(),
                        },
                    ),
                    identify: identify::Behaviour::new(identify::Config::new(
                        "/aster/controlled-relay/1".to_owned(),
                        key.public(),
                    )),
                }
            })
            .expect("controlled relay behaviour must build")
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_secs(30))
            })
            .build()
    }

    #[test]
    fn stable_composite_swarm_builds_without_mdns_or_stream_alpha() {
        let adapter =
            Libp2pAdapter::new(Keypair::generate_ed25519(), AdapterConfig::default()).unwrap();
        assert_ne!(adapter.local_peer_id(), PeerId::random());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn identify_and_controlled_autonat_v1_are_live_behaviours() {
        tokio::time::timeout(Duration::from_secs(35), async {
            let mut client =
                Libp2pAdapter::new(Keypair::generate_ed25519(), AdapterConfig::default()).unwrap();
            let mut server =
                Libp2pAdapter::new(Keypair::generate_ed25519(), AdapterConfig::default()).unwrap();
            let client_peer = client.local_peer_id();
            let server_peer = server.local_peer_id();

            client
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();
            server
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();
            let client_address = loop {
                if let ProviderEvent::Listening { address } = client.next_event().await {
                    break address;
                }
            };
            let server_address = loop {
                if let ProviderEvent::Listening { address } = server.next_event().await {
                    break address;
                }
            };

            client
                .add_autonat_server(server_peer, Some(server_address.clone()))
                .unwrap();
            client
                .dial(DialCandidate {
                    expected_peer_id: Some(server_peer),
                    address: server_address,
                })
                .unwrap();

            let mut client_identified_server = false;
            let mut server_identified_client = false;
            let mut client_observed_public = false;
            while !client_identified_server || !server_identified_client || !client_observed_public
            {
                tokio::select! {
                    event = client.next_event() => match event {
                        ProviderEvent::IdentifyObserved {
                            session,
                            observed_address,
                            supports_aster,
                        } if session.peer_id == server_peer => {
                            assert!(supports_aster);
                            assert!(!observed_address.is_empty());
                            client_identified_server = true;
                        }
                        ProviderEvent::NatStatusChanged {
                            old: NatReachability::Unknown,
                            new: NatReachability::Public(address),
                        } => {
                            let mut expected_address = client_address.clone();
                            expected_address
                                .push(libp2p::multiaddr::Protocol::P2p(client_peer));
                            assert_eq!(address, expected_address);
                            client_observed_public = true;
                        }
                        _ => {}
                    },
                    event = server.next_event() => match event {
                        ProviderEvent::IdentifyObserved {
                            session,
                            observed_address,
                            supports_aster,
                        } if session.peer_id == client_peer => {
                            assert!(supports_aster);
                            assert!(!observed_address.is_empty());
                            server_identified_client = true;
                        }
                        _ => {}
                    },
                }
            }
        })
        .await
        .expect("Identify and controlled AutoNAT v1 must finish before the hard deadline");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn controlled_relay_and_dcutr_upgrade_emit_exact_path_events() {
        tokio::time::timeout(Duration::from_secs(30), async {
            let mut relay = controlled_relay_server();
            let relay_peer = *relay.local_peer_id();
            relay
                .listen_on("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();
            let relay_address = loop {
                if let SwarmEvent::NewListenAddr { address, .. } = relay.select_next_some().await {
                    break address;
                }
            };
            relay.add_external_address(relay_address.clone());
            let mut relay_dial_address = relay_address.clone();
            relay_dial_address.push(libp2p::multiaddr::Protocol::P2p(relay_peer));

            let mut source =
                Libp2pAdapter::new(Keypair::generate_ed25519(), AdapterConfig::default()).unwrap();
            let mut destination =
                Libp2pAdapter::new(Keypair::generate_ed25519(), AdapterConfig::default()).unwrap();
            let source_peer = source.local_peer_id();
            let destination_peer = destination.local_peer_id();
            source
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();
            destination
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();
            while !matches!(source.next_event().await, ProviderEvent::Listening { .. }) {}
            while !matches!(
                destination.next_event().await,
                ProviderEvent::Listening { .. }
            ) {}

            destination
                .reserve_relay(relay_dial_address.clone())
                .unwrap();
            let mut reservation_accepted = false;
            let mut destination_relay_address = None;
            while !reservation_accepted || destination_relay_address.is_none() {
                tokio::select! {
                    event = destination.next_event() => match event {
                        ProviderEvent::RelayReservationAccepted {
                            relay_peer_id,
                            renewal: false,
                        } if relay_peer_id == relay_peer => {
                            reservation_accepted = true;
                        }
                        ProviderEvent::Listening { address }
                            if address.iter().any(|protocol| {
                                protocol == libp2p::multiaddr::Protocol::P2pCircuit
                            }) => {
                            destination_relay_address = Some(address);
                        }
                        _ => {}
                    },
                    _ = relay.select_next_some() => {}
                }
            }

            source
                .dial(DialCandidate {
                    expected_peer_id: Some(destination_peer),
                    address: destination_relay_address.expect("relay listener was observed"),
                })
                .unwrap();

            let mut source_relayed = None;
            let mut destination_relayed = None;
            let mut source_direct = None;
            let mut destination_direct = None;
            let mut source_circuit = false;
            let mut destination_circuit = false;
            let mut successful_hole_punches = 0_u8;
            // DCUtR reports completion for locally initiated direct attempts.
            // TCP simultaneous-open may resolve the other peer's attempt as an
            // inbound connection, so require one successful completion plus a
            // direct carrier on both peers instead of a completion per peer.
            while source_relayed.is_none()
                || destination_relayed.is_none()
                || source_direct.is_none()
                || destination_direct.is_none()
                || !source_circuit
                || !destination_circuit
                || successful_hole_punches == 0
            {
                tokio::select! {
                    event = source.next_event() => match event {
                        ProviderEvent::CarrierEstablished {
                            session,
                            path: CarrierPath::Relayed,
                            ..
                        } if session.peer_id == destination_peer => source_relayed = Some(session),
                        ProviderEvent::CarrierEstablished {
                            session,
                            path: CarrierPath::Direct,
                            ..
                        } if session.peer_id == destination_peer => source_direct = Some(session),
                        ProviderEvent::RelayCircuitEstablished {
                            peer_id,
                            inbound: false,
                        } if peer_id == relay_peer => source_circuit = true,
                        ProviderEvent::HolePunchFinished {
                            peer_id,
                            direct_connection,
                            error,
                        } if peer_id == destination_peer => {
                            assert_eq!(direct_connection.is_some(), error.is_none());
                            successful_hole_punches += u8::from(direct_connection.is_some());
                        }
                        _ => {}
                    },
                    event = destination.next_event() => match event {
                        ProviderEvent::CarrierEstablished {
                            session,
                            path: CarrierPath::Relayed,
                            ..
                        } if session.peer_id == source_peer => destination_relayed = Some(session),
                        ProviderEvent::CarrierEstablished {
                            session,
                            path: CarrierPath::Direct,
                            ..
                        } if session.peer_id == source_peer => destination_direct = Some(session),
                        ProviderEvent::RelayCircuitEstablished {
                            peer_id,
                            inbound: true,
                        } if peer_id == source_peer => destination_circuit = true,
                        ProviderEvent::HolePunchFinished {
                            peer_id,
                            direct_connection,
                            error,
                        } if peer_id == source_peer => {
                            assert_eq!(direct_connection.is_some(), error.is_none());
                            successful_hole_punches += u8::from(direct_connection.is_some());
                        }
                        _ => {}
                    },
                    _ = relay.select_next_some() => {}
                }
            }

            assert!(successful_hole_punches >= 1);

            assert_ne!(
                source_relayed
                    .expect("source relayed carrier")
                    .connection_id,
                source_direct.expect("source direct carrier").connection_id,
            );
            assert_ne!(
                destination_relayed
                    .expect("destination relayed carrier")
                    .connection_id,
                destination_direct
                    .expect("destination direct carrier")
                    .connection_id,
            );
        })
        .await
        .expect("controlled relay and DCUtR upgrade must finish before the hard deadline");
    }

    #[test]
    fn dcutr_requires_room_for_relay_and_direct_connections() {
        let config = AdapterConfig {
            max_connections_per_peer: 1,
            ..AdapterConfig::default()
        };
        assert!(matches!(
            Libp2pAdapter::new(Keypair::generate_ed25519(), config),
            Err(AdapterError::InvalidConfig(_))
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn simultaneous_dials_select_one_matching_physical_link_across_repeated_trials() {
        const TRIALS: usize = 8;
        tokio::time::timeout(Duration::from_secs(30), async {
            for trial in 0..TRIALS {
                let mut first = Libp2pAdapter::new(
                    Keypair::generate_ed25519(),
                    AdapterConfig::default(),
                )
                .unwrap();
                let mut second = Libp2pAdapter::new(
                    Keypair::generate_ed25519(),
                    AdapterConfig::default(),
                )
                .unwrap();
                let first_peer = first.local_peer_id();
                let second_peer = second.local_peer_id();

                first
                    .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                    .unwrap();
                second
                    .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                    .unwrap();
                let first_address = loop {
                    if let ProviderEvent::Listening { address } = first.next_event().await {
                        break address;
                    }
                };
                let second_address = loop {
                    if let ProviderEvent::Listening { address } = second.next_event().await {
                        break address;
                    }
                };

                // Both dials are submitted before either swarm is polled again.
                // Each endpoint therefore observes one local outbound and one
                // local inbound physical connection to the same peer.
                first
                    .dial(DialCandidate {
                        expected_peer_id: Some(second_peer),
                        address: second_address,
                    })
                    .unwrap();
                second
                    .dial(DialCandidate {
                        expected_peer_id: Some(first_peer),
                        address: first_address,
                    })
                    .unwrap();

                let mut first_carriers = Vec::new();
                let mut second_carriers = Vec::new();
                while first_carriers.len() < 2 || second_carriers.len() < 2 {
                    tokio::select! {
                        event = first.next_event(), if first_carriers.len() < 2 => match event {
                            ProviderEvent::CarrierEstablished {
                                session,
                                path,
                                outbound,
                                ..
                            } if session.peer_id == second_peer => {
                                assert_eq!(path, CarrierPath::Direct, "trial {trial}");
                                first_carriers.push(CarrierDescriptor {
                                    session,
                                    path,
                                    outbound,
                                });
                            }
                            ProviderEvent::TransportFailure { error, .. } => {
                                panic!("simultaneous dial trial {trial} failed first transport: {error}");
                            }
                            ProviderEvent::StreamFailed { reason, .. } => {
                                panic!("simultaneous dial trial {trial} failed first contact: {reason}");
                            }
                            _ => {}
                        },
                        event = second.next_event(), if second_carriers.len() < 2 => match event {
                            ProviderEvent::CarrierEstablished {
                                session,
                                path,
                                outbound,
                                ..
                            } if session.peer_id == first_peer => {
                                assert_eq!(path, CarrierPath::Direct, "trial {trial}");
                                second_carriers.push(CarrierDescriptor {
                                    session,
                                    path,
                                    outbound,
                                });
                            }
                            ProviderEvent::TransportFailure { error, .. } => {
                                panic!("simultaneous dial trial {trial} failed second transport: {error}");
                            }
                            ProviderEvent::StreamFailed { reason, .. } => {
                                panic!("simultaneous dial trial {trial} failed second contact: {reason}");
                            }
                            _ => {}
                        },
                    }
                }
                assert_eq!(
                    first_carriers.iter().filter(|carrier| carrier.outbound).count(),
                    1,
                    "trial {trial}"
                );
                assert_eq!(
                    second_carriers
                        .iter()
                        .filter(|carrier| carrier.outbound)
                        .count(),
                    1,
                    "trial {trial}"
                );

                let first_selected = first
                    .preferred_carrier(second_peer, &first_carriers)
                    .unwrap()
                    .unwrap();
                let second_selected = second
                    .preferred_carrier(first_peer, &second_carriers)
                    .unwrap()
                    .unwrap();
                let lower_is_first = first_peer.to_bytes() < second_peer.to_bytes();
                assert_eq!(
                    first_carriers
                        .iter()
                        .find(|carrier| carrier.session == first_selected)
                        .unwrap()
                        .outbound,
                    lower_is_first,
                    "trial {trial}"
                );
                assert_eq!(
                    second_carriers
                        .iter()
                        .find(|carrier| carrier.session == second_selected)
                        .unwrap()
                        .outbound,
                    !lower_is_first,
                    "trial {trial}"
                );

                first.activate_session(first_selected).unwrap();
                second.activate_session(second_selected).unwrap();
                let mut first_open = false;
                let mut second_open = false;
                while !first_open || !second_open {
                    tokio::select! {
                        event = first.next_event(), if !first_open => match event {
                            ProviderEvent::StreamOpened { session, .. }
                                if session == first_selected =>
                            {
                                first_open = true;
                            }
                            ProviderEvent::StreamOpened { session, .. } => {
                                panic!("trial {trial} opened unselected first carrier {session:?}");
                            }
                            ProviderEvent::StreamFailed { reason, .. } => {
                                panic!("simultaneous dial trial {trial} failed first contact: {reason}");
                            }
                            ProviderEvent::CarrierClosed { session, cause }
                                if session == first_selected =>
                            {
                                panic!("trial {trial} closed selected first carrier: {cause:?}");
                            }
                            _ => {}
                        },
                        event = second.next_event(), if !second_open => match event {
                            ProviderEvent::StreamOpened { session, .. }
                                if session == second_selected =>
                            {
                                second_open = true;
                            }
                            ProviderEvent::StreamOpened { session, .. } => {
                                panic!("trial {trial} opened unselected second carrier {session:?}");
                            }
                            ProviderEvent::StreamFailed { reason, .. } => {
                                panic!("simultaneous dial trial {trial} failed second contact: {reason}");
                            }
                            ProviderEvent::CarrierClosed { session, cause }
                                if session == second_selected =>
                            {
                                panic!("trial {trial} closed selected second carrier: {cause:?}");
                            }
                            _ => {}
                        },
                    }
                }
                assert_eq!(first.swarm.behaviour().aster.open_stream_count(), 1);
                assert_eq!(second.swarm.behaviour().aster.open_stream_count(), 1);

                let expected = format!("simultaneous-dial-trial-{trial}").into_bytes();
                first
                    .send_frame(first_selected, expected.clone())
                    .unwrap();
                loop {
                    tokio::select! {
                        event = first.next_event() => match event {
                            ProviderEvent::StreamOpened { session, .. } => {
                                panic!("trial {trial} opened an extra first stream on {session:?}");
                            }
                            ProviderEvent::StreamFailed { reason, .. } => {
                                panic!("trial {trial} failed first stream during exchange: {reason}");
                            }
                            _ => {}
                        },
                        event = second.next_event() => match event {
                            ProviderEvent::FrameReceived { session, frame }
                                if session == second_selected =>
                            {
                                assert_eq!(frame, expected, "trial {trial}");
                                break;
                            }
                            ProviderEvent::StreamOpened { session, .. } => {
                                panic!("trial {trial} opened an extra second stream on {session:?}");
                            }
                            ProviderEvent::StreamFailed { reason, .. } => {
                                panic!("trial {trial} failed second stream during exchange: {reason}");
                            }
                            _ => {}
                        },
                    }
                }

            }
        })
        .await
        .expect("repeated simultaneous-dial selection test timed out");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inactive_responder_holds_one_negotiated_stream_until_activation() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut first =
                Libp2pAdapter::new(Keypair::generate_ed25519(), AdapterConfig::default()).unwrap();
            let mut second =
                Libp2pAdapter::new(Keypair::generate_ed25519(), AdapterConfig::default()).unwrap();
            let first_peer = first.local_peer_id();
            let second_peer = second.local_peer_id();
            second
                .listen("/ip4/127.0.0.1/tcp/0".parse().unwrap())
                .unwrap();
            let listen_address = loop {
                if let ProviderEvent::Listening { address } = second.next_event().await {
                    break address;
                }
            };
            first
                .dial(DialCandidate {
                    expected_peer_id: None,
                    address: listen_address,
                })
                .unwrap();

            let mut first_session = None;
            let mut second_session = None;
            while first_session.is_none() || second_session.is_none() {
                tokio::select! {
                    event = first.next_event() => {
                        if let ProviderEvent::CarrierEstablished { session, .. } = event {
                            first_session = Some(session);
                        }
                    }
                    event = second.next_event() => {
                        if let ProviderEvent::CarrierEstablished { session, .. } = event {
                            second_session = Some(session);
                        }
                    }
                }
            }
            let first_session = first_session.unwrap();
            let second_session = second_session.unwrap();
            assert_eq!(first_session.peer_id, second_peer);
            assert_eq!(second_session.peer_id, first_peer);

            let first_initiates = first_peer.to_bytes() < second_peer.to_bytes();
            if first_initiates {
                first.activate_session(first_session).unwrap();
            } else {
                second.activate_session(second_session).unwrap();
            }

            let mut initiator_open = false;
            while !initiator_open {
                tokio::select! {
                    event = first.next_event() => match event {
                        ProviderEvent::StreamOpened { session, .. }
                            if first_initiates && session == first_session =>
                        {
                            initiator_open = true;
                        }
                        ProviderEvent::StreamFailed { reason, .. } => {
                            panic!("activation skew failed first side: {reason}");
                        }
                        _ => {}
                    },
                    event = second.next_event() => match event {
                        ProviderEvent::StreamOpened { session, .. }
                            if !first_initiates && session == second_session =>
                        {
                            initiator_open = true;
                        }
                        ProviderEvent::StreamFailed { reason, .. } => {
                            panic!("activation skew failed second side: {reason}");
                        }
                        _ => {}
                    }
                }
            }

            if first_initiates {
                second.activate_session(second_session).unwrap();
            } else {
                first.activate_session(first_session).unwrap();
            }
            let mut responder_open = false;
            while !responder_open {
                tokio::select! {
                    event = first.next_event() => match event {
                        ProviderEvent::StreamOpened { session, .. }
                            if !first_initiates && session == first_session =>
                        {
                            responder_open = true;
                        }
                        ProviderEvent::StreamFailed { reason, .. } => {
                            panic!("responder activation failed first side: {reason}");
                        }
                        _ => {}
                    },
                    event = second.next_event() => match event {
                        ProviderEvent::StreamOpened { session, .. }
                            if first_initiates && session == second_session =>
                        {
                            responder_open = true;
                        }
                        ProviderEvent::StreamFailed { reason, .. } => {
                            panic!("responder activation failed second side: {reason}");
                        }
                        _ => {}
                    }
                }
            }

            let expected = b"bounded-frame-over-stable-handler".to_vec();
            if first_initiates {
                first.send_frame(first_session, expected.clone()).unwrap();
            } else {
                second.send_frame(second_session, expected.clone()).unwrap();
            }
            loop {
                tokio::select! {
                    event = first.next_event() => match event {
                        ProviderEvent::FrameReceived { frame, .. } if !first_initiates => {
                            assert_eq!(frame, expected);
                            break;
                        }
                        ProviderEvent::StreamFailed { reason, .. } => {
                            panic!("frame exchange failed first side: {reason}");
                        }
                        _ => {}
                    },
                    event = second.next_event() => match event {
                        ProviderEvent::FrameReceived { frame, .. } if first_initiates => {
                            assert_eq!(frame, expected);
                            break;
                        }
                        ProviderEvent::StreamFailed { reason, .. } => {
                            panic!("frame exchange failed second side: {reason}");
                        }
                        _ => {}
                    }
                }
            }
        })
        .await
        .expect("stable handler activation-skew test timed out");
    }
}
