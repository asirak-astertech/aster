//! Real libp2p carrier integration for the shared-node supervisor.
//!
//! This stays test-only and behind `libp2p-candidate`: the Gate-H native
//! provider remains the default experiment until the libp2p arm earns its
//! own acceptance evidence.

use super::{
    LabResult, MeshPrepareConfig, NativeMeshNodeConfig, invalid, ip_mesh_application_options,
    native_contact_resource_claims, native_node_resource_limits, native_runtime_limits,
    open_native_shared_supervisor_with_limits, prepare_ip_mesh,
};
use aster_host::{
    CandidateId, CandidateLocator, CandidateProvenance, CarrierIdentity, ContactDirection,
    ContactId, ContactOpening, ContactPath, ContactSessionRole, HostAction, NodeResourceClaim,
    NodeResourceLimits, SharedNodeContactSupervisor,
};
use aster_libp2p_provider::{
    AdapterConfig, CarrierPath as ProviderCarrierPath, DialCandidate, Keypair, Libp2pAdapter,
    Multiaddr, ProviderEvent, SessionId, StreamDirection, expected_stream_direction,
};
use aster_mesh::link::{Link, LinkCharacteristics, ReceivedFrame};
use aster_mesh::{
    ApplicationNode, DataClass, EmissionPolicy, ItemId, NodeId, Priority, PublishRequest,
};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CONTACT: ContactId = ContactId(1);
const LINK_FRAME_CAPACITY: usize = 1_024;
const VOLUME_PAYLOAD_BYTES: usize = 1_048_576;
const REQUIRED_FRAMES_PER_DIRECTION: u64 = 10_000;
const PROVIDER_MAX_PENDING_CONNECTIONS: u32 = 1;
const PROVIDER_MAX_ESTABLISHED_CONNECTIONS: u32 = 2;
const PROVIDER_DESCRIPTOR_CAPACITY: usize = 1
    + 2 * PROVIDER_MAX_PENDING_CONNECTIONS as usize
    + PROVIDER_MAX_ESTABLISHED_CONNECTIONS as usize;

/// The provider-wide maps, task, frame slots, and scratch buffers exist before
/// a candidate/contact lifecycle lease does. Retaining this base reservation
/// makes those allocations visible to the same node-global authority without
/// inventing a second provider-owned lifecycle budget.
fn provider_base_claim() -> NodeResourceClaim {
    NodeResourceClaim {
        tasks: 1,
        // Covers the maximum Link, adapter-outbound, and adapter-to-Link
        // queues for the one-contact candidate profile.
        frames: 4 * LINK_FRAME_CAPACITY,
        inbound_bytes: 4 * 1_024 * 1_024,
        outbound_bytes: 4 * 1_024 * 1_024,
        // One TCP listener, one pending inbound plus one pending outbound
        // transport, and the two established connections required to permit
        // a bounded relay-to-direct upgrade.
        descriptors: PROVIDER_DESCRIPTOR_CAPACITY,
        ..NodeResourceClaim::default()
    }
}

fn libp2p_node_resource_limits(config: &NativeMeshNodeConfig) -> LabResult<NodeResourceLimits> {
    let mut limits = native_node_resource_limits(config)?;
    limits.descriptors = PROVIDER_DESCRIPTOR_CAPACITY;
    Ok(limits)
}

fn admitted_resource_total(base: NodeResourceClaim) -> LabResult<NodeResourceClaim> {
    let contact = native_contact_resource_claims(native_runtime_limits())?.admitted();
    Ok(NodeResourceClaim {
        candidates: 1,
        admitted_contacts: 1,
        streams: contact.streams,
        tasks: base.tasks + contact.tasks,
        frames: base.frames + contact.frames,
        inbound_bytes: base.inbound_bytes + contact.inbound_bytes,
        outbound_bytes: base.outbound_bytes + contact.outbound_bytes,
        descriptors: base.descriptors + contact.descriptors,
        relay_reservations: contact.relay_reservations,
        ..NodeResourceClaim::default()
    })
}

fn claim_is_within_limits(claim: NodeResourceClaim, limits: NodeResourceLimits) -> bool {
    claim.candidates <= limits.candidates
        && claim.pending_connections <= limits.pending_connections
        && claim.pre_authentication_contacts <= limits.pre_authentication_contacts
        && claim.admitted_contacts <= limits.admitted_contacts
        && claim.streams <= limits.streams
        && claim.tasks <= limits.tasks
        && claim.frames <= limits.frames
        && claim.inbound_bytes <= limits.inbound_bytes
        && claim.outbound_bytes <= limits.outbound_bytes
        && claim.descriptors <= limits.descriptors
        && claim.relay_reservations <= limits.relay_reservations
}

struct ScratchRoot(PathBuf);

impl ScratchRoot {
    fn fresh() -> Self {
        let mut suffix = [0_u8; 8];
        getrandom::fill(&mut suffix).expect("test entropy must be available");
        let suffix = suffix
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Self(std::env::temp_dir().join(format!("aster-libp2p-bridge-{suffix}")))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Runtime-facing half of one bounded carrier bridge.
struct ChannelLink {
    remote: NodeId,
    stream_open: Arc<AtomicBool>,
    accepted_sends: Arc<AtomicU64>,
    runtime_receives: Arc<AtomicU64>,
    queued_to_provider: Arc<AtomicU64>,
    outbound_high_water: Arc<AtomicU64>,
    queue_backpressure: Arc<AtomicU64>,
    pre_stream_backpressure: Arc<AtomicU64>,
    runtime_mtu: Arc<AtomicU64>,
    to_provider: SyncSender<Vec<u8>>,
    from_provider: Mutex<Receiver<ReceivedFrame>>,
}

/// Coordinator-facing half. It is driven on the same current-thread runtime
/// as its persistent `Libp2pAdapter`; no provider task owns Aster authority.
struct ChannelBridge {
    stream_open: Arc<AtomicBool>,
    accepted_sends: Arc<AtomicU64>,
    runtime_receives: Arc<AtomicU64>,
    queued_to_provider: Arc<AtomicU64>,
    outbound_high_water: Arc<AtomicU64>,
    queue_backpressure: Arc<AtomicU64>,
    pre_stream_backpressure: Arc<AtomicU64>,
    runtime_mtu: Arc<AtomicU64>,
    to_provider: Receiver<Vec<u8>>,
    from_provider: SyncSender<ReceivedFrame>,
}

impl ChannelLink {
    fn bounded(remote: NodeId) -> (Self, ChannelBridge) {
        let (to_provider_tx, to_provider_rx) = mpsc::sync_channel(LINK_FRAME_CAPACITY);
        let (from_provider_tx, from_provider_rx) = mpsc::sync_channel(LINK_FRAME_CAPACITY);
        let stream_open = Arc::new(AtomicBool::new(false));
        let accepted_sends = Arc::new(AtomicU64::new(0));
        let runtime_receives = Arc::new(AtomicU64::new(0));
        let queued_to_provider = Arc::new(AtomicU64::new(0));
        let outbound_high_water = Arc::new(AtomicU64::new(0));
        let queue_backpressure = Arc::new(AtomicU64::new(0));
        let pre_stream_backpressure = Arc::new(AtomicU64::new(0));
        let runtime_mtu = Arc::new(AtomicU64::new(1_400));
        (
            Self {
                remote,
                stream_open: Arc::clone(&stream_open),
                accepted_sends: Arc::clone(&accepted_sends),
                runtime_receives: Arc::clone(&runtime_receives),
                queued_to_provider: Arc::clone(&queued_to_provider),
                outbound_high_water: Arc::clone(&outbound_high_water),
                queue_backpressure: Arc::clone(&queue_backpressure),
                pre_stream_backpressure: Arc::clone(&pre_stream_backpressure),
                runtime_mtu: Arc::clone(&runtime_mtu),
                to_provider: to_provider_tx,
                from_provider: Mutex::new(from_provider_rx),
            },
            ChannelBridge {
                stream_open,
                accepted_sends,
                runtime_receives,
                queued_to_provider,
                outbound_high_water,
                queue_backpressure,
                pre_stream_backpressure,
                runtime_mtu,
                to_provider: to_provider_rx,
                from_provider: from_provider_tx,
            },
        )
    }
}

impl Link for ChannelLink {
    fn name(&self) -> &str {
        "libp2p-candidate-channel"
    }

    fn characteristics(&self) -> LinkCharacteristics {
        LinkCharacteristics {
            mtu: u16::try_from(self.runtime_mtu.load(Ordering::Relaxed))
                .expect("test MTU remains a u16"),
            bits_per_second: None,
            cost: 0,
            emission: 0,
            broadcast: false,
        }
    }

    fn send(&self, peer: Option<NodeId>, frame: &[u8]) -> io::Result<()> {
        if peer.is_some_and(|peer| peer != self.remote) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "runtime selected a peer other than this contact",
            ));
        }
        if !self.stream_open.load(Ordering::Acquire) {
            self.pre_stream_backpressure.fetch_add(1, Ordering::Relaxed);
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        match self.to_provider.try_send(frame.to_vec()) {
            Ok(()) => {
                self.accepted_sends.fetch_add(1, Ordering::Relaxed);
                let queued = self.queued_to_provider.fetch_add(1, Ordering::Relaxed) + 1;
                self.outbound_high_water
                    .fetch_max(queued, Ordering::Relaxed);
                Ok(())
            }
            Err(TrySendError::Full(_)) => {
                self.queue_backpressure.fetch_add(1, Ordering::Relaxed);
                Err(io::Error::from(io::ErrorKind::WouldBlock))
            }
            Err(TrySendError::Disconnected(_)) => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
        }
    }

    fn try_receive(&self) -> io::Result<Option<ReceivedFrame>> {
        match self
            .from_provider
            .lock()
            .map_err(|_| io::Error::other("libp2p bridge receive lock poisoned"))?
            .try_recv()
        {
            Ok(frame) => {
                self.runtime_receives.fetch_add(1, Ordering::Relaxed);
                Ok(Some(frame))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
        }
    }

    fn set_discovery(&self, _enabled: bool) -> io::Result<()> {
        Ok(())
    }

    fn retry_floor(&self) -> Duration {
        Duration::from_millis(1)
    }
}

impl ChannelBridge {
    fn mark_stream_open(&self) {
        self.stream_open.store(true, Ordering::Release);
    }

    fn accepted_sends(&self) -> u64 {
        self.accepted_sends.load(Ordering::Relaxed)
    }

    fn runtime_receives(&self) -> u64 {
        self.runtime_receives.load(Ordering::Relaxed)
    }

    fn outbound_high_water(&self) -> u64 {
        self.outbound_high_water.load(Ordering::Relaxed)
    }

    fn queue_backpressure(&self) -> u64 {
        self.queue_backpressure.load(Ordering::Relaxed)
    }

    fn pre_stream_backpressure(&self) -> u64 {
        self.pre_stream_backpressure.load(Ordering::Relaxed)
    }

    fn set_volume_mtu(&self) {
        // This forces the RuntimeDriver's real DATA messages through its
        // production fragmenter; no adapter-only traffic is synthesized.
        self.runtime_mtu.store(128, Ordering::Relaxed);
    }

    fn drain_to_provider(&self, limit: usize) -> LabResult<Vec<Vec<u8>>> {
        let mut frames = Vec::new();
        while frames.len() < limit {
            match self.to_provider.try_recv() {
                Ok(frame) => {
                    self.queued_to_provider.fetch_sub(1, Ordering::Relaxed);
                    frames.push(frame);
                }
                Err(TryRecvError::Empty) => return Ok(frames),
                Err(TryRecvError::Disconnected) => {
                    return Err(invalid("supervisor dropped the libp2p bridge"));
                }
            }
        }
        Ok(frames)
    }

    fn deliver_from_provider(&self, peer: NodeId, bytes: Vec<u8>) -> LabResult<()> {
        self.from_provider
            .try_send(ReceivedFrame {
                peer: Some(peer),
                bytes,
            })
            .map_err(|error| match error {
                TrySendError::Full(_) => invalid("bounded libp2p inbound bridge is full"),
                TrySendError::Disconnected(_) => {
                    invalid("supervisor dropped the libp2p inbound bridge")
                }
            })
    }
}

#[derive(Clone, Copy)]
struct EstablishedCarrier {
    session: SessionId,
    outbound: bool,
}

struct ProviderObservations {
    expected_session: SessionId,
    expected_direction: StreamDirection,
    remote_aster_peer: NodeId,
    stream_opened: usize,
    frames_received: u64,
    frames_submitted: u64,
    frames_sent: u64,
}

async fn listen_address(adapter: &mut Libp2pAdapter) -> LabResult<Multiaddr> {
    loop {
        match adapter.next_event().await {
            ProviderEvent::Listening { address } => return Ok(address),
            ProviderEvent::TransportFailure { error, .. } => {
                return Err(invalid(format!("libp2p listen failed: {error}")));
            }
            _ => {}
        }
    }
}

fn observe_established(
    event: ProviderEvent,
    remote_peer: aster_libp2p_provider::PeerId,
) -> LabResult<Option<EstablishedCarrier>> {
    match event {
        ProviderEvent::CarrierEstablished {
            session,
            path,
            outbound,
            ..
        } if session.peer_id == remote_peer => {
            if path != ProviderCarrierPath::Direct {
                return Err(invalid("localhost carrier was unexpectedly relayed"));
            }
            Ok(Some(EstablishedCarrier { session, outbound }))
        }
        ProviderEvent::TransportFailure { error, .. } => {
            Err(invalid(format!("libp2p connection failed: {error}")))
        }
        _ => Ok(None),
    }
}

fn role_for(direction: StreamDirection, remote: NodeId) -> ContactSessionRole {
    match direction {
        StreamDirection::Outbound => ContactSessionRole::Initiator {
            peer_hint: Some(remote),
        },
        StreamDirection::Inbound => ContactSessionRole::Responder {
            peer_hint: Some(remote),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn open_supervised_contact(
    supervisor: &mut SharedNodeContactSupervisor,
    candidate: CandidateId,
    locator: CandidateLocator,
    remote_aster_peer: NodeId,
    remote_carrier_identity: Vec<u8>,
    carrier: EstablishedCarrier,
    stream_direction: StreamDirection,
    link: ChannelLink,
) -> LabResult<()> {
    let report = supervisor.open_contact_with_factory(
        ContactOpening {
            contact: CONTACT,
            candidate,
            locator,
            carrier_identity: Some(CarrierIdentity::new(remote_carrier_identity)?),
            direction: if carrier.outbound {
                ContactDirection::Outbound
            } else {
                ContactDirection::Inbound
            },
            path: ContactPath::Direct,
            role: role_for(stream_direction, remote_aster_peer),
        },
        Instant::now(),
        move || link,
    )?;
    if !report.opened || !report.actions.is_empty() {
        return Err(invalid("shared supervisor refused the selected carrier"));
    }
    Ok(())
}

fn flush_runtime_frames(
    adapter: &mut Libp2pAdapter,
    bridge: &ChannelBridge,
    observations: &mut ProviderObservations,
) -> LabResult<()> {
    let in_flight = observations
        .frames_submitted
        .saturating_sub(observations.frames_sent);
    let available = (LINK_FRAME_CAPACITY as u64)
        .saturating_sub(in_flight)
        .try_into()
        .map_err(|_| invalid("provider queue availability does not fit usize"))?;
    for frame in bridge.drain_to_provider(available)? {
        adapter.send_frame(observations.expected_session, frame)?;
        observations.frames_submitted = observations.frames_submitted.saturating_add(1);
    }
    Ok(())
}

fn handle_provider_event(
    event: ProviderEvent,
    bridge: &ChannelBridge,
    observations: &mut ProviderObservations,
) -> LabResult<()> {
    match event {
        ProviderEvent::StreamOpened { session, direction } => {
            if session != observations.expected_session
                || direction != observations.expected_direction
                || observations.stream_opened != 0
            {
                return Err(invalid(
                    "provider opened a duplicate or non-selected Aster stream",
                ));
            }
            observations.stream_opened = 1;
            bridge.mark_stream_open();
        }
        ProviderEvent::FrameReceived { session, frame } => {
            if session != observations.expected_session {
                return Err(invalid("provider attributed a frame to another carrier"));
            }
            bridge.deliver_from_provider(observations.remote_aster_peer, frame)?;
            observations.frames_received = observations.frames_received.saturating_add(1);
        }
        ProviderEvent::FrameSent { session, .. } if session == observations.expected_session => {
            observations.frames_sent = observations.frames_sent.saturating_add(1);
        }
        ProviderEvent::CarrierEstablished { session, .. }
            if session.peer_id == observations.expected_session.peer_id =>
        {
            return Err(invalid("provider created a second physical carrier"));
        }
        ProviderEvent::CarrierClosed { session, cause }
            if session == observations.expected_session =>
        {
            return Err(invalid(format!(
                "selected libp2p carrier closed: {}",
                cause.as_deref().unwrap_or("clean close")
            )));
        }
        ProviderEvent::StreamFailed { session, reason }
            if session == observations.expected_session =>
        {
            return Err(invalid(format!("Aster stream failed: {reason}")));
        }
        ProviderEvent::SendRejected {
            session, reason, ..
        } if session == observations.expected_session => {
            return Err(invalid(format!(
                "provider rejected a runtime frame: {reason}"
            )));
        }
        ProviderEvent::TransportFailure { error, .. } => {
            return Err(invalid(format!("libp2p transport failed: {error}")));
        }
        _ => {}
    }
    Ok(())
}

fn direction_fully_delivered(
    source: &ProviderObservations,
    source_bridge: &ChannelBridge,
    destination: &ProviderObservations,
    destination_bridge: &ChannelBridge,
) -> bool {
    source.frames_submitted >= REQUIRED_FRAMES_PER_DIRECTION
        && source_bridge.accepted_sends() == source.frames_submitted
        && source.frames_sent == source.frames_submitted
        && destination.frames_received == source.frames_submitted
        && destination_bridge.runtime_receives() == destination.frames_received
}

fn node_config(
    root: &Path,
    role: &str,
    topic: aster_mesh::Topic,
    scope: aster_mesh::Scope,
    expected_peer: NodeId,
) -> NativeMeshNodeConfig {
    NativeMeshNodeConfig {
        invocation: format!("libp2p-{role}"),
        root: root.join(role),
        credential_path: root.join(format!("private/{role}.bundle")),
        topic,
        scope,
        discovery_token: [0x71; 16],
        bind: "127.0.0.1:47101".parse().expect("static socket"),
        discovery_target: "127.0.0.1:47101".parse().expect("static socket"),
        max_candidates: 2,
        max_active_contacts: 1,
        run_for: Duration::from_secs(1),
        discovery_enabled: false,
        expected_peers: BTreeSet::from([expected_peer]),
        manual_peers: String::new(),
        emission_mode: "normal".to_owned(),
        gate_h_control_path: None,
        gate_h_stale_target_peer: None,
        durable_item_probe: None,
    }
}

fn publish_volume_item(
    root: &Path,
    role: &str,
    expected_identity: NodeId,
    logical_key: &[u8],
    fill: u8,
) -> LabResult<ItemId> {
    let credential = fs::read(root.join(format!("private/{role}.bundle")))?;
    let mut node = ApplicationNode::open(
        root.join(format!("{role}/state.sqlite")),
        &credential,
        ip_mesh_application_options(VOLUME_PAYLOAD_BYTES)?,
    )?;
    if node.identity() != expected_identity {
        return Err(invalid("member identity changed before volume publish"));
    }
    let published = node.publish(PublishRequest {
        class: DataClass::Event,
        topic: aster_mesh::Topic::new("lab.ip-mesh.commands")?,
        scope: aster_mesh::Scope::new("lab/ip-mesh")?,
        priority: Priority::Immediate,
        ttl_ms: None,
        logical_key: logical_key.to_vec(),
        payload: vec![fill; VOLUME_PAYLOAD_BYTES],
        tombstone: false,
    })?;
    Ok(published.id)
}

async fn real_two_node_bridge() -> LabResult<()> {
    let scratch = ScratchRoot::fresh();
    let prepared = prepare_ip_mesh(&MeshPrepareConfig {
        root: scratch.path().to_path_buf(),
        seed: 0x1b2f_0002,
        payload_bytes: VOLUME_PAYLOAD_BYTES,
    })?;
    let a_second_item = publish_volume_item(
        scratch.path(),
        "a",
        prepared.publisher,
        b"libp2p-volume-a-second",
        0xa2,
    )?;
    let c_first_item = publish_volume_item(
        scratch.path(),
        "c",
        prepared.consumer,
        b"libp2p-volume-c-first",
        0xc1,
    )?;
    let c_second_item = publish_volume_item(
        scratch.path(),
        "c",
        prepared.consumer,
        b"libp2p-volume-c-second",
        0xc2,
    )?;
    let a_config = node_config(
        scratch.path(),
        "a",
        prepared.topic.clone(),
        prepared.scope.clone(),
        prepared.consumer,
    );
    let b_config = node_config(
        scratch.path(),
        "c",
        prepared.topic.clone(),
        prepared.scope.clone(),
        prepared.publisher,
    );
    let (a_identity, mut a_supervisor, _) = open_native_shared_supervisor_with_limits(
        &a_config,
        EmissionPolicy::default(),
        fs::read(&a_config.credential_path)?,
        libp2p_node_resource_limits(&a_config)?,
    )?;
    let (b_identity, mut b_supervisor, _) = open_native_shared_supervisor_with_limits(
        &b_config,
        EmissionPolicy::default(),
        fs::read(&b_config.credential_path)?,
        libp2p_node_resource_limits(&b_config)?,
    )?;
    if a_identity != prepared.publisher || b_identity != prepared.consumer {
        return Err(invalid(
            "prepared Aster identities changed on supervisor open",
        ));
    }

    let base_claim = provider_base_claim();
    let a_provider_base = a_supervisor.reserve_provider_resources(base_claim)?;
    let b_provider_base = b_supervisor.reserve_provider_resources(base_claim)?;
    if a_supervisor.resource_snapshot()?.current != base_claim
        || b_supervisor.resource_snapshot()?.current != base_claim
    {
        return Err(invalid("provider base reservation was not node-global"));
    }

    // The leases above deliberately precede both Swarm constructions.
    let a_key = Keypair::generate_ed25519();
    let b_key = Keypair::generate_ed25519();
    let adapter_config = AdapterConfig {
        max_pending_connections: PROVIDER_MAX_PENDING_CONNECTIONS,
        max_established_connections: PROVIDER_MAX_ESTABLISHED_CONNECTIONS,
        max_connections_per_peer: PROVIDER_MAX_ESTABLISHED_CONNECTIONS,
        max_frame_bytes: 1_400,
        max_queued_frames_per_session: LINK_FRAME_CAPACITY,
        max_queued_bytes_per_session: LINK_FRAME_CAPACITY * 1_400,
        ..AdapterConfig::default()
    };
    let mut a_adapter = Libp2pAdapter::new(a_key, adapter_config.clone())?;
    let mut b_adapter = Libp2pAdapter::new(b_key, adapter_config)?;
    let a_carrier_peer = a_adapter.local_peer_id();
    let b_carrier_peer = b_adapter.local_peer_id();

    a_adapter.listen("/ip4/127.0.0.1/tcp/0".parse()?)?;
    b_adapter.listen("/ip4/127.0.0.1/tcp/0".parse()?)?;
    let a_address = listen_address(&mut a_adapter).await?;
    let b_address = listen_address(&mut b_adapter).await?;

    let a_candidate = CandidateId::new("libp2p-b")?;
    let b_candidate = CandidateId::new("libp2p-a")?;
    let a_locator = CandidateLocator::new(b_address.to_string())?;
    let b_locator = CandidateLocator::new(a_address.to_string())?;
    let observed = Instant::now();
    a_supervisor.observe_candidate(
        a_candidate.clone(),
        a_locator.clone(),
        CandidateProvenance::Manual,
        ContactPath::Direct,
        Some(b_identity),
        observed,
    )?;
    b_supervisor.observe_candidate(
        b_candidate.clone(),
        b_locator.clone(),
        CandidateProvenance::Manual,
        ContactPath::Direct,
        Some(a_identity),
        observed,
    )?;
    let plan = a_supervisor.plan(observed)?;
    if !plan.actions.iter().any(|action| {
        matches!(
            action,
            HostAction::Dial { candidate, locator }
                if candidate == &a_candidate && locator == &a_locator
        )
    }) {
        return Err(invalid("shared supervisor did not select the libp2p dial"));
    }
    a_adapter.dial(DialCandidate {
        expected_peer_id: Some(b_carrier_peer),
        address: b_address,
    })?;

    let mut a_carrier = None;
    let mut b_carrier = None;
    while a_carrier.is_none() || b_carrier.is_none() {
        tokio::select! {
            event = a_adapter.next_event(), if a_carrier.is_none() => {
                a_carrier = observe_established(event, b_carrier_peer)?;
            }
            event = b_adapter.next_event(), if b_carrier.is_none() => {
                b_carrier = observe_established(event, a_carrier_peer)?;
            }
        }
    }
    let a_carrier = a_carrier.expect("loop requires A carrier");
    let b_carrier = b_carrier.expect("loop requires B carrier");
    if !a_carrier.outbound || b_carrier.outbound {
        return Err(invalid("one-way dial did not preserve carrier direction"));
    }

    let a_stream_direction = expected_stream_direction(a_carrier_peer, b_carrier_peer)?;
    let b_stream_direction = expected_stream_direction(b_carrier_peer, a_carrier_peer)?;
    if a_stream_direction == b_stream_direction {
        return Err(invalid(
            "libp2p peers did not choose complementary stream roles",
        ));
    }
    let (a_link, a_bridge) = ChannelLink::bounded(b_identity);
    let (b_link, b_bridge) = ChannelLink::bounded(a_identity);

    // The supervisor owns the RuntimeDriver and reserves the complete contact
    // claim before either provider is allowed to activate `/aster/sync/2`.
    open_supervised_contact(
        &mut a_supervisor,
        a_candidate,
        a_locator,
        b_identity,
        b_carrier_peer.to_bytes(),
        a_carrier,
        a_stream_direction,
        a_link,
    )?;
    open_supervised_contact(
        &mut b_supervisor,
        b_candidate,
        b_locator,
        a_identity,
        a_carrier_peer.to_bytes(),
        b_carrier,
        b_stream_direction,
        b_link,
    )?;

    let a_pre_activation = a_supervisor.drive_contact(CONTACT, Instant::now())?;
    let b_pre_activation = b_supervisor.drive_contact(CONTACT, Instant::now())?;
    let selected_initiator_blocked = match a_stream_direction {
        StreamDirection::Outbound => a_pre_activation.outbound_blocked,
        StreamDirection::Inbound => b_pre_activation.outbound_blocked,
    };
    if !selected_initiator_blocked
        || a_bridge.accepted_sends() != 0
        || b_bridge.accepted_sends() != 0
    {
        return Err(invalid(
            "RuntimeDriver emitted before the selected libp2p stream opened",
        ));
    }

    a_adapter.activate_session(a_carrier.session)?;
    b_adapter.activate_session(b_carrier.session)?;
    let mut a_observations = ProviderObservations {
        expected_session: a_carrier.session,
        expected_direction: a_stream_direction,
        remote_aster_peer: b_identity,
        stream_opened: 0,
        frames_received: 0,
        frames_submitted: 0,
        frames_sent: 0,
    };
    let mut b_observations = ProviderObservations {
        expected_session: b_carrier.session,
        expected_direction: b_stream_direction,
        remote_aster_peer: a_identity,
        stream_opened: 0,
        frames_received: 0,
        frames_submitted: 0,
        frames_sent: 0,
    };
    let mut volume_mtu_enabled = false;
    let volume_started = Instant::now();
    let mut next_progress = Duration::from_secs(10);

    loop {
        let now = Instant::now();
        a_supervisor.drive_contact(CONTACT, now)?;
        b_supervisor.drive_contact(CONTACT, now)?;
        flush_runtime_frames(&mut a_adapter, &a_bridge, &mut a_observations)?;
        flush_runtime_frames(&mut b_adapter, &b_bridge, &mut b_observations)?;

        let a_admitted = a_supervisor
            .contact_status()
            .into_iter()
            .any(|status| status.contact == CONTACT && status.admitted);
        let b_admitted = b_supervisor
            .contact_status()
            .into_iter()
            .any(|status| status.contact == CONTACT && status.admitted);
        if a_admitted && b_admitted && !volume_mtu_enabled {
            a_bridge.set_volume_mtu();
            b_bridge.set_volume_mtu();
            volume_mtu_enabled = true;
        }
        if volume_mtu_enabled
            && direction_fully_delivered(&a_observations, &a_bridge, &b_observations, &b_bridge)
            && direction_fully_delivered(&b_observations, &b_bridge, &a_observations, &a_bridge)
            && a_supervisor.durable_item_present(c_first_item)?
            && a_supervisor.durable_item_present(c_second_item)?
            && b_supervisor.durable_item_present(prepared.item_id)?
            && b_supervisor.durable_item_present(a_second_item)?
        {
            break;
        }
        if volume_started.elapsed() >= next_progress {
            eprintln!(
                "libp2p volume progress: elapsed_s={} A_submitted={} A_sent={} C_received={}; C_submitted={} C_sent={} A_received={}",
                volume_started.elapsed().as_secs(),
                a_observations.frames_submitted,
                a_observations.frames_sent,
                b_observations.frames_received,
                b_observations.frames_submitted,
                b_observations.frames_sent,
                a_observations.frames_received,
            );
            next_progress = next_progress.saturating_add(Duration::from_secs(10));
        }

        tokio::select! {
            event = a_adapter.next_event() => {
                handle_provider_event(event, &a_bridge, &mut a_observations)?;
            }
            event = b_adapter.next_event() => {
                handle_provider_event(event, &b_bridge, &mut b_observations)?;
            }
            () = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
    }

    eprintln!(
        "libp2p volume proof: elapsed_ms={} A->C accepted={} submitted={} sent={} received={} runtime_received={} high_water={} full_blocks={}; C->A accepted={} submitted={} sent={} received={} runtime_received={} high_water={} full_blocks={}",
        volume_started.elapsed().as_millis(),
        a_bridge.accepted_sends(),
        a_observations.frames_submitted,
        a_observations.frames_sent,
        b_observations.frames_received,
        b_bridge.runtime_receives(),
        a_bridge.outbound_high_water(),
        a_bridge.queue_backpressure(),
        b_bridge.accepted_sends(),
        b_observations.frames_submitted,
        b_observations.frames_sent,
        a_observations.frames_received,
        a_bridge.runtime_receives(),
        b_bridge.outbound_high_water(),
        b_bridge.queue_backpressure(),
    );

    if a_observations.stream_opened != 1 || b_observations.stream_opened != 1 {
        return Err(invalid("expected exactly one /aster/sync/2 stream"));
    }
    for (label, supervisor, expected_peer) in [
        ("A", &a_supervisor, b_identity),
        ("C", &b_supervisor, a_identity),
    ] {
        let statuses = supervisor.contact_status();
        if statuses.len() != 1
            || statuses[0].contact != CONTACT
            || !statuses[0].admitted
            || statuses[0].authenticated_peer != Some(expected_peer)
        {
            return Err(invalid(format!(
                "{label} did not bind its sole admitted contact to the expected Aster peer"
            )));
        }
    }
    for (label, bridge) in [("A", &a_bridge), ("C", &b_bridge)] {
        if bridge.outbound_high_water() != LINK_FRAME_CAPACITY as u64
            || bridge.queue_backpressure() == 0
        {
            return Err(invalid(format!(
                "{label} did not exercise the exact bounded Link backpressure path"
            )));
        }
    }
    if a_bridge
        .pre_stream_backpressure()
        .saturating_add(b_bridge.pre_stream_backpressure())
        == 0
    {
        return Err(invalid(
            "volume run did not saturate the bounded RuntimeDriver Link queue",
        ));
    }
    let expected_resources = admitted_resource_total(base_claim)?;
    for supervisor in [&a_supervisor, &b_supervisor] {
        let snapshot = supervisor.resource_snapshot()?;
        if snapshot.current != expected_resources
            || !claim_is_within_limits(snapshot.current, snapshot.limits)
            || !claim_is_within_limits(snapshot.high_water, snapshot.limits)
        {
            return Err(invalid(
                "admitted libp2p queues/contact escaped exact node-global accounting",
            ));
        }
    }

    // Keep the base leases alive until after the persistent Swarms are gone.
    drop(a_adapter);
    drop(b_adapter);
    a_provider_base.release()?;
    b_provider_base.release()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn two_persistent_swarms_drive_ten_thousand_runtime_frames_each_way() -> LabResult<()> {
    tokio::time::timeout(Duration::from_secs(120), real_two_node_bridge())
        .await
        .map_err(|_| invalid("real libp2p volume bridge timed out after 120 seconds"))??;
    Ok(())
}
