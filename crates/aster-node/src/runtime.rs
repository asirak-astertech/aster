use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self, File},
    io,
    net::{SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::{
    ffi::{OsStrExt as _, OsStringExt as _},
    fs::{DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _},
};

use aster_iroh::{CarrierError, Endpoint, EndpointConfig, EndpointId, ExpectedPeer};
use aster_mesh::{
    EventContentVerification, NodeId, Priority, ProvisioningAccess, ReferenceEnvelopeSealer,
    ReferenceProvisioner, RouteVerifiedEventEnvelope, Scope, ScopeRekeyRecipient, Topic,
    VerifiedControlEnvelope, VerifiedControlKind, engine::EnvelopeError,
};
use aster_negentropy::{
    Difference, Initiator, InitiatorStep, ReconciliationError, ReconciliationLimits, Responder,
};
use aster_profile::{InventorySnapshot, ItemId};
use aster_redb_store::{
    ControlOutcome, ControlPolicySnapshot, ControlRejectionReason, ControlTransferId,
    EventOnceOutcome, EventOperationKey, EventReplicationPolicySnapshot, EventSemanticId,
    EventSubscriptionKey, EventSubscriptionMode, EventSubscriptionSpec, EventTransferId,
    MAX_EVENT_PAGE, RejectedControl, RouteCacheOutcome, ScopeRekeyPublicationIntent, Store,
    StoreBackingIdentity, StoreError, StoreInspection, StoreZeroizationState, StoredControl,
    StoredControlEffect, StoredEvent, StoredEventTransfer, ZeroizationArtifact, ZeroizationIntent,
    ZeroizationStore,
};
#[cfg(unix)]
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{UnixListener, UnixStream},
};
use tokio::{
    sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock, mpsc, oneshot},
    task::{Id as TaskId, JoinHandle, JoinSet},
    time::{MissedTickBehavior, sleep, timeout},
};
use zeroize::Zeroize as _;

use crate::{
    NodeIdentity,
    application::{
        AuthenticatedPeerStatus, ContactSyncStatus, EventSyncStatus, PeerAuthorization,
        SelectedEventCommand, SelectedEventHandle, SelectedEventNode, SelectedEventStatus,
        runtime_application_error,
    },
    format_node_id, format_path_field, format_receipt_field,
    frame::{EventDirection, EventInterest, EventInterestSelector, Frame, MAX_OBJECT_BYTES},
    mission::{
        MissionHandshakeReceipt, MissionPeerBinding, MissionProvisioningError, MissionSession,
        MissionSessionError, PreparedIdentityErasure, PreparedMissionErasure,
        ResumedSoftwareErasure, SoftwareErasureError, SoftwareErasureTarget,
        SoftwareSecretArtifact, UnprotectedReferenceMission, initiate_over_iroh_metered,
        respond_over_iroh_metered,
    },
    parse_node_id,
};

pub(crate) const STORE_FILE: &str = "mesh.redb";
const MAX_CONFIGURED_PEERS: usize = 256;
const MAX_INBOUND_CONTACTS: usize = 16;
const MAX_OUTBOUND_CONTACTS: usize = 16;
const APPLICATION_COMMAND_CAPACITY: usize = 32;
const APPLICATION_COMMAND_BUDGET: usize = 8;
const NETWORK_EVENT_BUDGET: usize = 8;
const MAX_CONTACT_ITEMS: usize = 3_500;
const MAX_CONTACT_FRAMES: usize = 8_192;
const MAX_CONTACT_BYTES: usize = 64 * 1024 * 1024;
const CONTACT_DEADLINE: Duration = Duration::from_secs(30);
const DEMO_MISSION_BUNDLE_FILE: &str = "mission.unprotected-reference.bundle";
const DEMO_SIGNED_REGISTRY_FILE: &str = "signed-public-rekey-registry.bin";
const DEMO_SCOPE: &str = "demo/mesh";
const DEMO_EVENT_TOPIC: &str = "mesh.ping-pong";
const DEMO_PING_PAYLOAD: &[u8] = b"ASTER_SAMPLE_PING_V1";
const DEMO_PONG_PAYLOAD: &[u8] = b"ASTER_SAMPLE_PONG_V1";
const DEMO_PING_LOGICAL_KEY: &[u8] = b"ping";
const DEMO_PING_OPERATION: &[u8] = b"aster.sample.ping-pong.v1/ping";
const DEMO_PONG_OPERATION_PREFIX: &[u8] = b"aster.sample.ping-pong.v1/pong/";
const DEMO_EVENT_SUBSCRIPTION_KEY: &[u8] = b"aster.sample.ping-pong.v1/receive";
const MAX_EVENT_PUBLISH_RETRIES: usize = 4;
pub(crate) const EVENT_OPERATION_CONFLICT: &str =
    "durable Event operation differs from the requested application Event";
const MAX_CONTROL_PUBLISH_RETRIES: usize = 4;
#[cfg(unix)]
const LOCAL_ZEROIZATION_REQUEST_MAGIC: &[u8] = b"ASTER-ZEROIZE-LOCAL-V1\0";
#[cfg(unix)]
const MAX_LOCAL_ZEROIZATION_PATH_BYTES: usize = 8 * 1024;
#[cfg(unix)]
const MAX_LOCAL_ZEROIZATION_RESPONSE_BYTES: usize = 8 * 1024;
#[cfg(unix)]
const LOCAL_ZEROIZATION_IO_DEADLINE: Duration = Duration::from_secs(10);
#[cfg(unix)]
const LOCAL_ZEROIZATION_INTEGRITY_INTERVAL: Duration = Duration::from_millis(250);
#[cfg(unix)]
const LOCAL_ZEROIZATION_DISCOVERY_INTERVAL: Duration = Duration::from_millis(50);

/// Optional source-authenticated sample application hosted by one node process.
///
/// These roles select application behavior only. They do not alter the Aster
/// Event envelope, reconciliation, carrier, or mission-session protocols.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum NodeApplication {
    /// Replicate admitted Events without producing sample application data.
    #[default]
    Relay,
    /// Emit the virtual-mesh sample Ping exactly once from durable local state.
    PingEmitter,
    /// Emit Ping only after recipient-filtered control activates epoch two.
    EpochTwoPingEmitter,
    /// Emit one causally correlated Pong for the admitted sample Ping.
    PongResponder,
}

impl NodeApplication {
    /// Parses the stable CLI spelling for a sample application role.
    pub fn parse(value: &str) -> Result<Self, NodeError> {
        match value {
            "relay" => Ok(Self::Relay),
            "ping-emitter" => Ok(Self::PingEmitter),
            "epoch2-ping-emitter" => Ok(Self::EpochTwoPingEmitter),
            "pong-responder" => Ok(Self::PongResponder),
            _ => Err(NodeError::Configuration(format!(
                "application must be relay, ping-emitter, epoch2-ping-emitter, or pong-responder; got {value:?}"
            ))),
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::PingEmitter => "ping-emitter",
            Self::EpochTwoPingEmitter => "epoch2-ping-emitter",
            Self::PongResponder => "pong-responder",
        }
    }
}

/// Explicit virtual-mesh acceptance scenario selected by the demo CLI.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum DemoScenario {
    /// N-instance source-authenticated Ping/Pong with temporal forwarding.
    #[default]
    PingPong,
    /// Four-role control propagation, rekey, exclusion, and Ping/Pong acceptance.
    Control,
}

impl DemoScenario {
    /// Parses the stable CLI spelling without deriving behavior from node count.
    pub fn parse(value: &str) -> Result<Self, NodeError> {
        match value {
            "ping-pong" => Ok(Self::PingPong),
            "control" => Ok(Self::Control),
            _ => Err(NodeError::Configuration(format!(
                "demo scenario must be ping-pong or control; got {value:?}"
            ))),
        }
    }
}

/// Exact carrier address and independently authenticated mission identity.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MissionExpectedPeer {
    /// Iroh carrier identity and direct address.
    pub carrier: ExpectedPeer,
    /// Authority-provisioned Aster mission identity.
    pub mission: NodeId,
}

impl fmt::Display for MissionExpectedPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}={}",
            self.carrier,
            format_node_id(self.mission)
        )
    }
}

impl FromStr for MissionExpectedPeer {
    type Err = NodeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (carrier, mission) = value.split_once('=').ok_or_else(|| {
            NodeError::Configuration("peer must be CARRIER_ID@IP:PORT=MISSION_NODE_ID_HEX64".into())
        })?;
        if mission.contains('=') {
            return Err(NodeError::Configuration(
                "peer contains more than one mission identity separator".into(),
            ));
        }
        Ok(Self {
            carrier: carrier.parse()?,
            mission: parse_node_id(mission)?,
        })
    }
}

/// One selected-stack node process configuration.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Independent durable root for this process.
    pub state: PathBuf,
    /// Direct local Iroh bind address.
    pub bind: SocketAddr,
    /// Required mission credentials; no unauthenticated runtime mode exists.
    pub mission: UnprotectedReferenceMission,
    /// Exact manually admitted carrier-to-mission peer bindings.
    pub peers: Vec<MissionExpectedPeer>,
    /// Delay between bounded contacts.
    pub sync_interval: Duration,
    /// Optional process lifetime, primarily for deterministic orchestration.
    pub run_for: Option<Duration>,
    /// Explicit sample application hosted by this process.
    pub application: NodeApplication,
}

/// Metrics for one completed contact from this local node's point of view.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PeerReceipt {
    /// Authenticated remote endpoint.
    pub peer: Option<EndpointId>,
    /// Independently hybrid-authenticated Aster identity.
    pub mission_peer: Option<NodeId>,
    /// Negentropy response rounds.
    pub rounds: u32,
    /// Items offered from local to remote.
    pub offered: usize,
    /// Items fetched from remote.
    pub fetched: usize,
    /// Newly inserted remote items.
    pub inserted: usize,
    /// Harmless duplicate transfers observed.
    pub duplicates: usize,
    /// Negotiated item identifiers deferred to a later bounded contact.
    pub remaining: usize,
    /// Mission-control transfers offered from local durable state.
    pub controls_offered: usize,
    /// Mission-control transfers fetched from the remote durable state.
    pub controls_fetched: usize,
    /// Newly retained remote mission-control transfers, including pending links.
    pub controls_retained: usize,
    /// Exact duplicate mission-control transfers observed.
    pub control_duplicates: usize,
    /// Newly contiguous mission-control links activated after durable commit.
    pub controls_activated: usize,
    /// Control difference deferred by the per-contact bound.
    pub controls_remaining: usize,
    /// Mission-handshake flights, emitted only after the full handshake succeeds.
    pub handshake_frames: usize,
    /// Mission-handshake wire bytes, emitted only after full authentication.
    pub handshake_bytes: usize,
    /// Successfully sealed and opened application frames.
    pub protected_frames: usize,
    /// Successfully sealed and opened application wire bytes.
    pub protected_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ContactEventPolicy {
    control_head: Option<(u64, ControlTransferId)>,
    selector_generation: u64,
}

impl ContactEventPolicy {
    fn capture(policy: &EventReplicationPolicySnapshot) -> Self {
        Self {
            control_head: policy.control_policy().head(),
            selector_generation: policy.selector_generation(),
        }
    }
}

#[derive(Debug)]
struct CompletedPeerContact {
    receipt: PeerReceipt,
    event_policy: ContactEventPolicy,
}

impl std::ops::Deref for CompletedPeerContact {
    type Target = PeerReceipt;

    fn deref(&self) -> &Self::Target {
        &self.receipt
    }
}

/// Terminal node-process summary.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeReceipt {
    /// Number of successful mission-authenticated contacts in either direction.
    pub contacts: usize,
    /// Number of contact attempts that failed visibly and were retried later.
    pub contact_errors: usize,
    /// Final durable item count.
    pub items: u64,
    /// Final durable acceptance marker count.
    pub acceptance_markers: u64,
    /// Content-verified semantic Event representations.
    pub events: u64,
    /// Semantic Event acceptance markers.
    pub event_acceptance_markers: u64,
    /// Route-verified exact representations retained without content acceptance.
    pub route_cached_events: u64,
    /// Retained exact mission-control transfers.
    pub controls: u64,
    /// Applied contiguous mission-control links.
    pub applied_controls: u64,
    /// Authenticated out-of-order mission-control links without active effects.
    pub pending_controls: u64,
    /// Durable mission-control chain highwater.
    pub control_highwater: u64,
}

/// Owned lifecycle for one running selected-stack node actor.
pub struct RunningNode {
    selected_events: SelectedEventHandle,
    application_admission: Arc<AtomicBool>,
    shutdown: Option<mpsc::Sender<()>>,
    task: Option<JoinHandle<Result<NodeReceipt, NodeError>>>,
}

impl RunningNode {
    /// Returns a cloneable, bounded live selected-Event application handle.
    pub fn selected_events(&self) -> SelectedEventHandle {
        self.selected_events.clone()
    }

    /// Requests graceful shutdown, closes command admission, and waits for cleanup.
    pub async fn shutdown(mut self) -> Result<NodeReceipt, NodeError> {
        self.application_admission.store(false, Ordering::Release);
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(()).await;
        }
        self.await_task().await
    }

    /// Waits for the configured deadline, signal, zeroization, or fatal failure.
    pub async fn wait(mut self) -> Result<NodeReceipt, NodeError> {
        self.await_task().await
    }

    async fn await_task(&mut self) -> Result<NodeReceipt, NodeError> {
        let task = self
            .task
            .take()
            .ok_or_else(|| NodeError::Protocol("running node task was already consumed".into()))?;
        task.await.map_err(node_actor_join_error)?
    }
}

impl Drop for RunningNode {
    fn drop(&mut self) {
        self.application_admission.store(false, Ordering::Release);
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.try_send(());
        }
    }
}

fn node_actor_join_error(error: tokio::task::JoinError) -> NodeError {
    NodeError::Protocol(format!("running node actor stopped unexpectedly: {error}"))
}

#[derive(Default)]
struct SelectedEventStatusTracker {
    configured_peers: BTreeSet<NodeId>,
    authenticated: BTreeMap<NodeId, AuthenticatedContactObservation>,
}

#[derive(Clone, Copy)]
struct AuthenticatedContactObservation {
    contacts: u64,
    complete: bool,
    policy: ContactEventPolicy,
}

enum ApplicationPolicyLease {
    Read { _guard: OwnedRwLockReadGuard<()> },
    Write { _guard: OwnedRwLockWriteGuard<()> },
}

async fn acquire_application_policy_lease(
    policy_lock: Arc<RwLock<()>>,
    write: bool,
) -> ApplicationPolicyLease {
    if write {
        ApplicationPolicyLease::Write {
            _guard: policy_lock.write_owned().await,
        }
    } else {
        ApplicationPolicyLease::Read {
            _guard: policy_lock.read_owned().await,
        }
    }
}

fn account_network_event(counter: &mut usize) -> bool {
    *counter = counter.saturating_add(1).min(NETWORK_EVENT_BUDGET);
    *counter >= NETWORK_EVENT_BUDGET
}

impl SelectedEventStatusTracker {
    fn new(configured_peers: BTreeSet<NodeId>) -> Self {
        Self {
            configured_peers,
            authenticated: BTreeMap::new(),
        }
    }

    fn record(&mut self, contact: &CompletedPeerContact) -> Result<(), NodeError> {
        let receipt = &contact.receipt;
        let peer = receipt.mission_peer.ok_or_else(|| {
            NodeError::Protocol("successful contact omitted its authenticated mission peer".into())
        })?;
        if !self.configured_peers.contains(&peer) {
            return Err(NodeError::Protocol(
                "successful contact identified an unconfigured mission peer".into(),
            ));
        }
        let next_contacts = self.authenticated.get(&peer).map_or(Ok(1), |observation| {
            observation
                .contacts
                .checked_add(1)
                .ok_or_else(|| NodeError::Protocol("authenticated contact count overflow".into()))
        })?;
        self.authenticated.insert(
            peer,
            AuthenticatedContactObservation {
                contacts: next_contacts,
                complete: receipt.remaining == 0 && receipt.controls_remaining == 0,
                policy: contact.event_policy,
            },
        );
        Ok(())
    }

    fn snapshot(
        &self,
        store: &Store,
        current: &EventReplicationPolicySnapshot,
        failed_contact_attempts: usize,
    ) -> Result<SelectedEventStatus, NodeError> {
        let current_policy = ContactEventPolicy::capture(current);
        let mut peers = Vec::with_capacity(self.authenticated.len());
        let mut authenticated_contacts = 0u64;
        for (peer, observation) in &self.authenticated {
            authenticated_contacts = authenticated_contacts
                .checked_add(observation.contacts)
                .ok_or_else(|| {
                    NodeError::Protocol("authenticated contact count overflow".into())
                })?;
            let revoked = store.is_control_principal_revoked(*peer)?;
            let last_contact = if revoked || observation.policy != current_policy {
                ContactSyncStatus::PolicyChangedSinceContact
            } else if observation.complete {
                ContactSyncStatus::CompleteForLastNegotiatedContact
            } else {
                ContactSyncStatus::WorkRemained
            };
            peers.push(AuthenticatedPeerStatus {
                peer: *peer,
                contacts: observation.contacts,
                authorization: if revoked {
                    PeerAuthorization::Revoked
                } else {
                    PeerAuthorization::Active
                },
                last_contact,
            });
        }

        let mut active_configured = 0usize;
        let mut active_without_contact = false;
        let mut active_policy_changed = false;
        let mut active_work_remained = false;
        for peer in &self.configured_peers {
            if store.is_control_principal_revoked(*peer)? {
                continue;
            }
            active_configured += 1;
            match self.authenticated.get(peer) {
                None => active_without_contact = true,
                Some(observation) if observation.policy != current_policy => {
                    active_policy_changed = true;
                }
                Some(observation) if !observation.complete => active_work_remained = true,
                Some(_) => {}
            }
        }
        let sync = if self.configured_peers.is_empty() {
            EventSyncStatus::Offline
        } else if active_configured == 0 {
            EventSyncStatus::NoActiveConfiguredPeers
        } else if active_without_contact {
            EventSyncStatus::AwaitingAuthenticatedContact
        } else if active_policy_changed {
            EventSyncStatus::PolicyChangedSinceContact
        } else if active_work_remained {
            EventSyncStatus::WorkRemained
        } else {
            EventSyncStatus::LastContactComplete
        };
        let failed_contact_attempts = u64::try_from(failed_contact_attempts)
            .map_err(|_| NodeError::Protocol("failed contact count exceeds u64".into()))?;
        Ok(SelectedEventStatus {
            sync,
            authenticated_contacts,
            failed_contact_attempts,
            peers,
        })
    }
}

/// Read-only logical store receipt.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoreReceipt {
    /// Canonical item IDs.
    pub ids: Vec<ItemId>,
    /// Accepted item count.
    pub items: u64,
    /// Paired acceptance marker count.
    pub acceptance_markers: u64,
    /// Sum of exact opaque payload bytes.
    pub payload_bytes: u64,
    /// Content-verified semantic Event representations.
    pub events: u64,
    /// Semantic Event acceptance markers.
    pub event_acceptance_markers: u64,
    /// Exact source-sealed bytes in the semantic Event namespace.
    pub event_sealed_bytes: u64,
    /// Route-verified exact representations retained without content acceptance.
    pub route_cached_events: u64,
    /// Exact bytes retained in the route-only cache.
    pub route_cached_bytes: u64,
    /// Retained exact mission-control transfers.
    pub controls: u64,
    /// Applied contiguous mission-control links.
    pub applied_controls: u64,
    /// Authenticated pending mission-control links.
    pub pending_controls: u64,
    /// Durable mission-control chain highwater.
    pub control_highwater: u64,
    /// Durable local software-zeroization lifecycle.
    pub zeroization: SoftwareZeroizationState,
}

/// Operator-visible durable software-zeroization lifecycle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum SoftwareZeroizationState {
    /// Normal mission-bound operation remains enabled.
    #[default]
    Live,
    /// Terminal lockout is durable and neither artifact receipt exists yet.
    CleanupPending,
    /// Mission-bundle contents have an exact-FD destruction receipt.
    MissionDestroyed,
    /// Mission and carrier-identity contents both have destruction receipts.
    IdentityDestroyed,
    /// Both receipts exist and cleanup has been durably finalized.
    Complete,
}

impl SoftwareZeroizationState {
    /// Stable receipt spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::CleanupPending => "cleanup-pending",
            Self::MissionDestroyed => "mission-destroyed",
            Self::IdentityDestroyed => "identity-destroyed",
            Self::Complete => "complete",
        }
    }

    /// Whether normal runtime/data APIs are durably locked out.
    pub const fn is_terminal(self) -> bool {
        !matches!(self, Self::Live)
    }
}

impl From<StoreZeroizationState> for SoftwareZeroizationState {
    fn from(state: StoreZeroizationState) -> Self {
        match state {
            StoreZeroizationState::Live => Self::Live,
            StoreZeroizationState::CleanupPending => Self::CleanupPending,
            StoreZeroizationState::MissionDestroyed => Self::MissionDestroyed,
            StoreZeroizationState::IdentityDestroyed => Self::IdentityDestroyed,
            StoreZeroizationState::Complete => Self::Complete,
        }
    }
}

/// Current pathname disposition after exact-FD software erasure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SoftwareZeroizationPathState {
    /// The exact original inode remains owner-only, regular, and zero length.
    RetainedZeroLength,
    /// The pathname exists but no longer names the exact protected tombstone.
    RetainedExternalChange,
    /// External action removed the pathname after exact-FD destruction.
    Absent,
    /// The pathname could not be inspected for the operator receipt.
    Indeterminate,
}

impl SoftwareZeroizationPathState {
    /// Stable receipt spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RetainedZeroLength => "retained-zero-length",
            Self::RetainedExternalChange => "retained-external-change",
            Self::Absent => "absent",
            Self::Indeterminate => "indeterminate",
        }
    }
}

/// Completed or idempotently replayed local zeroization receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SoftwareZeroizationReceipt {
    /// True when a live process performed drain-and-destroy over local IPC.
    pub live_request: bool,
    /// Final durable lifecycle phase.
    pub state: SoftwareZeroizationState,
    /// Durable mission-bundle destruction receipt.
    pub mission_destroyed: bool,
    /// Durable carrier-identity destruction receipt.
    pub identity_destroyed: bool,
    /// Current disposition of the original mission pathname.
    pub mission_pathname: SoftwareZeroizationPathState,
    /// Current disposition of the original carrier-identity pathname.
    pub identity_pathname: SoftwareZeroizationPathState,
    /// Terminal-safe full audit of rows preserved by zeroization.
    pub preserved: StoreReceipt,
}

/// Crash-idempotent authority publication receipt for one durable control effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlPublicationReceipt {
    /// Exact source-sealed control transfer identity.
    pub transfer_id: ControlTransferId,
    /// Nonzero stable-authority chain position.
    pub sequence: u64,
    /// True only when this process committed the exact control row.
    pub emitted: bool,
    /// Ordered controls activated after this durable transaction.
    pub activated: usize,
}

/// Selected-stack composition failure.
#[derive(Debug)]
pub enum NodeError {
    /// Invalid operator or coordinator configuration.
    Configuration(String),
    /// Persisted identity failure.
    Identity(crate::IdentityError),
    /// Required mission provisioning artifact failed closed.
    MissionProvisioning(MissionProvisioningError),
    /// Retained local secret artifact failed the software-erasure contract.
    SoftwareErasure(SoftwareErasureError),
    /// Source Event sealing, verification, or content authorization failed.
    SourceEnvelope(EnvelopeError),
    /// Mission handshake, peer binding, or protected frame failed.
    Mission(MissionSessionError),
    /// A principal is durably revoked by the applied mission-control chain.
    Revoked(NodeId),
    /// Durable store failure.
    Store(StoreError),
    /// Set reconciliation failure.
    Reconciliation(ReconciliationError),
    /// Authenticated carrier failure.
    Carrier(CarrierError),
    /// Strict mechanics-frame failure.
    Protocol(String),
    /// Filesystem or child-process I/O failure.
    Io(io::Error),
    /// A real child process or demo invariant failed.
    Demo(String),
}

impl fmt::Display for NodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => write!(formatter, "node configuration: {message}"),
            Self::Identity(error) => write!(formatter, "{error}"),
            Self::MissionProvisioning(error) => write!(formatter, "{error}"),
            Self::SoftwareErasure(error) => write!(formatter, "software zeroization: {error}"),
            Self::SourceEnvelope(error) => write!(formatter, "source Event: {error}"),
            Self::Mission(error) => write!(formatter, "{error}"),
            Self::Revoked(principal) => write!(
                formatter,
                "mission principal {} is durably revoked",
                format_node_id(*principal)
            ),
            Self::Store(error) => write!(formatter, "{error}"),
            Self::Reconciliation(error) => write!(formatter, "{error}"),
            Self::Carrier(error) => write!(formatter, "{error}"),
            Self::Protocol(message) => write!(formatter, "mechanics protocol: {message}"),
            Self::Io(error) => write!(formatter, "node I/O: {error}"),
            Self::Demo(message) => write!(formatter, "virtual mesh demo: {message}"),
        }
    }
}

impl Error for NodeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            Self::MissionProvisioning(error) => Some(error),
            Self::SoftwareErasure(error) => Some(error),
            Self::SourceEnvelope(error) => Some(error),
            Self::Mission(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Reconciliation(error) => Some(error),
            Self::Carrier(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Configuration(_) | Self::Revoked(_) | Self::Protocol(_) | Self::Demo(_) => None,
        }
    }
}

impl From<crate::IdentityError> for NodeError {
    fn from(value: crate::IdentityError) -> Self {
        Self::Identity(value)
    }
}

impl From<MissionProvisioningError> for NodeError {
    fn from(value: MissionProvisioningError) -> Self {
        Self::MissionProvisioning(value)
    }
}

impl From<SoftwareErasureError> for NodeError {
    fn from(value: SoftwareErasureError) -> Self {
        Self::SoftwareErasure(value)
    }
}

impl From<EnvelopeError> for NodeError {
    fn from(value: EnvelopeError) -> Self {
        Self::SourceEnvelope(value)
    }
}

impl From<MissionSessionError> for NodeError {
    fn from(value: MissionSessionError) -> Self {
        Self::Mission(value)
    }
}

impl From<StoreError> for NodeError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<ReconciliationError> for NodeError {
    fn from(value: ReconciliationError) -> Self {
        Self::Reconciliation(value)
    }
}

impl From<CarrierError> for NodeError {
    fn from(value: CarrierError) -> Self {
        Self::Carrier(value)
    }
}

impl From<io::Error> for NodeError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// Stores one caller-identified opaque object while the node process is stopped.
pub fn put_opaque(state: &Path, id: ItemId, bytes: &[u8]) -> Result<bool, NodeError> {
    if bytes.len() > MAX_OBJECT_BYTES {
        return Err(NodeError::Configuration(format!(
            "opaque object is {} bytes; first-slice maximum is {MAX_OBJECT_BYTES}",
            bytes.len()
        )));
    }
    fs::create_dir_all(state)?;
    let store = Store::open(state.join(STORE_FILE))?;
    Ok(store.apply(id, bytes)?.inserted())
}

/// Audits and reports the logical selected store while the node is stopped.
pub fn inspect_store(state: &Path) -> Result<StoreReceipt, NodeError> {
    let inspection = Store::inspect_existing(state.join(STORE_FILE))?;
    Ok(store_receipt_from_inspection(inspection))
}

fn store_receipt_from_inspection(inspection: StoreInspection) -> StoreReceipt {
    let stats = inspection.stats;
    let event_stats = inspection.event_stats;
    let control_stats = inspection.control_stats;
    StoreReceipt {
        ids: inspection.inventory.iter().copied().collect(),
        items: stats.items,
        acceptance_markers: stats.acceptance_markers,
        payload_bytes: stats.total_payload_bytes,
        events: event_stats.events,
        event_acceptance_markers: event_stats.acceptance_markers,
        event_sealed_bytes: event_stats.total_sealed_bytes,
        route_cached_events: event_stats.route_cached,
        route_cached_bytes: event_stats.route_cached_bytes,
        controls: control_stats.controls,
        applied_controls: control_stats.applied,
        pending_controls: control_stats.pending,
        control_highwater: control_stats.head_sequence,
        zeroization: inspection.zeroization.state().into(),
    }
}

/// Rejects a durably terminal state before a CLI loads or creates credentials.
///
/// Read-only inspection is used normally. Only redb's exact `RepairAborted`
/// signal enters the recovery-only store path, which performs backend recovery
/// and lifecycle inspection without application migration. Recovered terminal
/// state is still rejected before the caller loads mission artifacts, creates a
/// carrier identity, or binds sockets.
pub fn ensure_state_accepts_normal_operation(state: &Path) -> Result<(), NodeError> {
    let store_path = state.join(STORE_FILE);
    if !store_path.exists() {
        return Ok(());
    }
    let status = match Store::inspect_zeroization_state(&store_path) {
        Ok(status) => status,
        Err(error) if error.is_read_only_repair_required() => {
            Store::recover_zeroization_state(&store_path)?
        }
        Err(error) => return Err(error.into()),
    };
    if status.state().is_terminal() {
        return Err(StoreError::StoreZeroized(status.state()).into());
    }
    Ok(())
}

#[cfg(unix)]
struct PreparedSoftwareZeroization {
    intent: ZeroizationIntent,
    mission_authority: NodeId,
    store_identity: Option<(u64, u64)>,
    mission: PreparedMissionErasure,
    identity: PreparedIdentityErasure,
}

#[cfg(not(unix))]
struct PreparedSoftwareZeroization;

#[cfg(unix)]
enum MissionErasureHandle {
    Prepared(PreparedMissionErasure),
    Resumed(ResumedSoftwareErasure),
}

#[cfg(unix)]
impl MissionErasureHandle {
    fn destroy_contents(&mut self) -> Result<crate::mission::SoftwareErasureReceipt, NodeError> {
        match self {
            Self::Prepared(handle) => Ok(handle.destroy_contents()?),
            Self::Resumed(handle) => Ok(handle.destroy_contents()?),
        }
    }
}

#[cfg(unix)]
enum IdentityErasureHandle {
    Prepared(PreparedIdentityErasure),
    Resumed(ResumedSoftwareErasure),
}

#[cfg(unix)]
impl IdentityErasureHandle {
    fn destroy_contents(&mut self) -> Result<crate::mission::SoftwareErasureReceipt, NodeError> {
        match self {
            Self::Prepared(handle) => Ok(handle.destroy_contents()?),
            Self::Resumed(handle) => Ok(handle.destroy_contents()?),
        }
    }
}

/// Runs or resumes the binding local software-zeroization hook.
///
/// A same-UID live request uses owner-only local IPC. With no live owner, the
/// caller acquires the exact redb writer and performs the identical durable
/// per-artifact state machine. This makes no physical-media sanitization claim.
pub async fn zeroize_node(
    state: &Path,
    mission_bundle: &Path,
    wait: Duration,
) -> Result<SoftwareZeroizationReceipt, NodeError> {
    #[cfg(not(unix))]
    {
        let _ = (state, mission_bundle, wait);
        return Err(SoftwareErasureError::PlatformUnavailable.into());
    }
    #[cfg(unix)]
    {
        let _ = local_state_identity(state)?;
        let discovery_deadline = Instant::now().checked_add(wait).ok_or_else(|| {
            NodeError::Configuration("local zeroization wait exceeds the monotonic clock".into())
        })?;
        if let Some(response) = request_live_zeroization(state, mission_bundle, wait).await? {
            require_live_zeroization_success(&response)?;
            return completed_zeroization_receipt(state, mission_bundle, true);
        }
        match zeroize_stopped_node(state, mission_bundle) {
            Err(error) if is_zeroization_discovery_contention(&error) => loop {
                let now = Instant::now();
                if now >= discovery_deadline {
                    return Err(NodeError::Configuration(
                        "state remained writable elsewhere without an authenticated local zeroization endpoint before the wait deadline"
                            .into(),
                    ));
                }
                let remaining = discovery_deadline.duration_since(now);
                if let Some(response) =
                    request_live_zeroization(state, mission_bundle, remaining).await?
                {
                    require_live_zeroization_success(&response)?;
                    break completed_zeroization_receipt(state, mission_bundle, true);
                }
                match zeroize_stopped_node(state, mission_bundle) {
                    Err(error) if is_zeroization_discovery_contention(&error) => {}
                    result => break result,
                }
                let remaining = discovery_deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    continue;
                }
                sleep(LOCAL_ZEROIZATION_DISCOVERY_INTERVAL.min(remaining)).await;
            },
            result => result,
        }
    }
}

#[cfg(unix)]
fn require_live_zeroization_success(response: &str) -> Result<(), NodeError> {
    if response != "ASTER-ZEROIZE-LOCAL-OK" {
        return Err(NodeError::Configuration(format!(
            "live zeroization failed: {}",
            format_receipt_field(response)
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn is_zeroization_discovery_contention(error: &NodeError) -> bool {
    matches!(
        error,
        NodeError::Store(StoreError::StoreInUse)
            | NodeError::SoftwareErasure(SoftwareErasureError::InUse(_))
            | NodeError::MissionProvisioning(MissionProvisioningError::Artifact(
                SoftwareErasureError::InUse(_)
            ))
            | NodeError::Identity(crate::IdentityError::Artifact(SoftwareErasureError::InUse(
                _
            )))
    )
}

#[cfg(unix)]
fn zeroize_stopped_node(
    state: &Path,
    mission_bundle: &Path,
) -> Result<SoftwareZeroizationReceipt, NodeError> {
    let store_path = state.join(STORE_FILE);
    // Clean state is classified without a writable open. Only redb's exact
    // read-only repair signal enters the recovery-only writer, whose backend
    // mutation is unavoidable after an unclean process exit.
    let mut expected_store = None;
    let status = match fs::symlink_metadata(&store_path) {
        Ok(_) => {
            let identity = local_store_identity(&store_path)?;
            expected_store = Some(identity);
            match Store::inspect_zeroization_state(&store_path) {
                Ok(status) => Some(status),
                Err(error) if error.is_read_only_repair_required() => {
                    Some(Store::recover_zeroization_state(&store_path)?)
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if status
        .as_ref()
        .is_some_and(|status| status.state().is_terminal())
    {
        let mut cleanup = Store::open_for_zeroization(&store_path)?;
        cleanup.require_process_exclusive_lock()?;
        let expected_store = expected_store.expect("an inspected store has an exact identity");
        require_store_backing_identity(cleanup.backing_identity(), expected_store)?;
        require_local_store_identity(&store_path, expected_store)?;
        drive_zeroization_cleanup(&mut cleanup, None, state, mission_bundle)?;
        require_store_path_matches_backing(&store_path, cleanup.backing_identity())?;
        return completed_zeroization_receipt_from_cleanup(&cleanup, false);
    }

    // Both exact secret handles are retained before acquiring/creating the
    // store writer. A failure here leaves no terminal marker and erases nothing.
    let plan = prepare_stopped_zeroization(state, mission_bundle)?;
    if let Some(bound) = status
        .as_ref()
        .and_then(|status| status.mission_authority())
        && bound != plan.mission_authority
    {
        return Err(StoreError::MissionAuthorityMismatch {
            bound,
            received: plan.mission_authority,
        }
        .into());
    }
    let mut cleanup = if status
        .as_ref()
        .and_then(|status| status.mission_authority())
        .is_some()
    {
        let mut cleanup = Store::open_for_zeroization(&store_path)?;
        cleanup.require_process_exclusive_lock()?;
        let expected_store = expected_store.expect("an inspected store has an exact identity");
        require_store_backing_identity(cleanup.backing_identity(), expected_store)?;
        require_local_store_identity(&store_path, expected_store)?;
        if cleanup.mission_authority() != plan.mission_authority {
            return Err(StoreError::MissionAuthorityMismatch {
                bound: cleanup.mission_authority(),
                received: plan.mission_authority,
            }
            .into());
        }
        cleanup.begin_zeroization(&plan.intent)?;
        require_local_store_identity(&store_path, expected_store)?;
        cleanup
    } else {
        // `aster init` and an opaque-only compatibility store have no mission
        // binding yet. Reuse the normal binding path, then immediately enter
        // terminal state before either exact artifact is destroyed.
        let store = Store::open_for_mission(&store_path, plan.mission_authority)?;
        store.require_process_exclusive_lock()?;
        let opened_store = local_store_identity(&store_path)?;
        let expected_store = expected_store.unwrap_or(opened_store);
        require_store_backing_identity(store.backing_identity(), expected_store)?;
        require_local_store_identity(&store_path, expected_store)?;
        if store.mission_authority() != Some(plan.mission_authority) {
            return Err(StoreError::MissionNotBound.into());
        }
        store.begin_zeroization(&plan.intent)?;
        require_local_store_identity(&store_path, expected_store)?;
        let cleanup = store.into_zeroization()?;
        cleanup.require_process_exclusive_lock()?;
        require_store_backing_identity(cleanup.backing_identity(), expected_store)?;
        require_local_store_identity(&store_path, expected_store)?;
        cleanup
    };
    drive_zeroization_cleanup(&mut cleanup, Some(plan), state, mission_bundle)?;
    require_store_path_matches_backing(&store_path, cleanup.backing_identity())?;
    completed_zeroization_receipt_from_cleanup(&cleanup, false)
}

#[cfg(unix)]
fn prepare_stopped_zeroization(
    state: &Path,
    mission_bundle: &Path,
) -> Result<PreparedSoftwareZeroization, NodeError> {
    let mission = UnprotectedReferenceMission::load(mission_bundle)?;
    let mission_authority = mission.mission_authority_id();
    let identity = NodeIdentity::load_existing(state)?;
    let mission = mission.prepare_software_erasure()?;
    let identity = identity.prepare_software_erasure()?;
    let intent = ZeroizationIntent::new(mission.target().to_bytes(), identity.target().to_bytes())?;
    Ok(PreparedSoftwareZeroization {
        intent,
        mission_authority,
        store_identity: None,
        mission,
        identity,
    })
}

#[cfg(unix)]
fn prepare_live_zeroization(
    mission: &UnprotectedReferenceMission,
    identity: &NodeIdentity,
    request: &LocalZeroizationRequest,
) -> Result<PreparedSoftwareZeroization, NodeError> {
    let mission_authority = mission.mission_authority_id();
    let mission = mission.prepare_software_erasure()?;
    let identity = identity.prepare_software_erasure()?;
    let mission_path = fs::canonicalize(mission.target().path())?;
    if !request.mission_matches(
        &mission_path,
        mission.target().device(),
        mission.target().inode(),
    ) {
        return Err(NodeError::Configuration(
            "live zeroization request differs from the retained mission artifact".into(),
        ));
    }
    let intent = ZeroizationIntent::new(mission.target().to_bytes(), identity.target().to_bytes())?;
    Ok(PreparedSoftwareZeroization {
        intent,
        mission_authority,
        store_identity: Some((request.binding.store_device, request.binding.store_inode)),
        mission,
        identity,
    })
}

#[cfg(not(unix))]
fn prepare_live_zeroization(
    _mission: &UnprotectedReferenceMission,
    _identity: &NodeIdentity,
    _request: &LocalZeroizationRequest,
) -> Result<PreparedSoftwareZeroization, NodeError> {
    Err(SoftwareErasureError::PlatformUnavailable.into())
}

#[cfg(unix)]
fn drive_zeroization_cleanup(
    cleanup: &mut ZeroizationStore,
    prepared: Option<PreparedSoftwareZeroization>,
    state: &Path,
    mission_bundle: &Path,
) -> Result<(), NodeError> {
    let intent = cleanup
        .zeroization_intent()
        .cloned()
        .ok_or(StoreError::ZeroizationInvariant(
            "terminal cleanup lacks artifact intent",
        ))?;
    let mission_target = decode_zeroization_target(
        &intent,
        ZeroizationArtifact::MissionBundle,
        SoftwareSecretArtifact::MissionBundle,
    )?;
    let identity_target = decode_zeroization_target(
        &intent,
        ZeroizationArtifact::CarrierIdentity,
        SoftwareSecretArtifact::CarrierIdentity,
    )?;
    require_operator_target(mission_bundle, &mission_target, "mission bundle")?;
    require_operator_target(
        &state.join("identity.key"),
        &identity_target,
        "carrier identity",
    )?;

    let (prepared_mission, prepared_identity) = match prepared {
        Some(plan) => {
            if plan.intent != intent {
                return Err(StoreError::ZeroizationIntentConflict.into());
            }
            (Some(plan.mission), Some(plan.identity))
        }
        None => (None, None),
    };

    // On crash recovery, retain every still-unflagged exact inode before
    // continuing destruction. A missing/replaced second target therefore
    // cannot cause a new partial cleanup step.
    let mut mission_handle = if cleanup.mission_destroyed() {
        None
    } else if let Some(handle) = prepared_mission {
        if handle.target() != &mission_target {
            return Err(StoreError::ZeroizationIntentConflict.into());
        }
        Some(MissionErasureHandle::Prepared(handle))
    } else {
        Some(MissionErasureHandle::Resumed(
            mission_target.resume_pending()?,
        ))
    };
    let mut identity_handle = if cleanup.identity_destroyed() {
        None
    } else if let Some(handle) = prepared_identity {
        if handle.target() != &identity_target {
            return Err(StoreError::ZeroizationIntentConflict.into());
        }
        Some(IdentityErasureHandle::Prepared(handle))
    } else {
        Some(IdentityErasureHandle::Resumed(
            identity_target.resume_pending()?,
        ))
    };

    if let Some(handle) = mission_handle.as_mut() {
        let receipt = handle.destroy_contents()?;
        if receipt.target() != &mission_target || !receipt.bounded_software_erasure() {
            return Err(NodeError::Configuration(
                "mission software-erasure receipt differs from durable intent".into(),
            ));
        }
        cleanup.mark_mission_destroyed()?;
    }
    if let Some(handle) = identity_handle.as_mut() {
        let receipt = handle.destroy_contents()?;
        if receipt.target() != &identity_target || !receipt.bounded_software_erasure() {
            return Err(NodeError::Configuration(
                "carrier-identity software-erasure receipt differs from durable intent".into(),
            ));
        }
        cleanup.mark_identity_destroyed()?;
    }
    cleanup.finalize_zeroization()?;
    Ok(())
}

#[cfg(unix)]
fn finish_live_zeroization(
    store: Arc<Store>,
    plan: PreparedSoftwareZeroization,
    state: &Path,
    mission_bundle: &Path,
) -> Result<SoftwareZeroizationReceipt, NodeError> {
    let store_path = state.join(STORE_FILE);
    let expected_store = plan.store_identity.ok_or_else(|| {
        NodeError::Configuration("live zeroization plan lacks an exact store identity".into())
    })?;
    let store = Arc::try_unwrap(store).map_err(|_| {
        NodeError::Configuration(
            "live zeroization could not obtain sole ownership after draining store tasks".into(),
        )
    })?;
    require_store_backing_identity(store.backing_identity(), expected_store)?;
    require_local_store_identity(&store_path, expected_store)?;
    let bound = store
        .mission_authority()
        .ok_or(StoreError::MissionNotBound)?;
    if bound != plan.mission_authority {
        return Err(StoreError::MissionAuthorityMismatch {
            bound,
            received: plan.mission_authority,
        }
        .into());
    }
    store.begin_zeroization(&plan.intent)?;
    require_local_store_identity(&store_path, expected_store)?;
    let mut cleanup = store.into_zeroization()?;
    cleanup.require_process_exclusive_lock()?;
    require_store_backing_identity(cleanup.backing_identity(), expected_store)?;
    require_local_store_identity(&store_path, expected_store)?;
    if cleanup.mission_authority() != plan.mission_authority {
        return Err(StoreError::MissionAuthorityMismatch {
            bound: cleanup.mission_authority(),
            received: plan.mission_authority,
        }
        .into());
    }
    drive_zeroization_cleanup(&mut cleanup, Some(plan), state, mission_bundle)?;
    require_store_path_matches_backing(&store_path, cleanup.backing_identity())?;
    completed_zeroization_receipt_from_cleanup(&cleanup, true)
}

#[cfg(not(unix))]
fn finish_live_zeroization(
    _store: Arc<Store>,
    _plan: PreparedSoftwareZeroization,
    _state: &Path,
    _mission_bundle: &Path,
) -> Result<SoftwareZeroizationReceipt, NodeError> {
    Err(SoftwareErasureError::PlatformUnavailable.into())
}

#[cfg(unix)]
fn decode_zeroization_target(
    intent: &ZeroizationIntent,
    stored: ZeroizationArtifact,
    expected: SoftwareSecretArtifact,
) -> Result<SoftwareErasureTarget, NodeError> {
    let target = SoftwareErasureTarget::from_bytes(intent.descriptor(stored))?;
    if target.artifact() != expected {
        return Err(NodeError::Configuration(
            "durable zeroization descriptor names the wrong artifact kind".into(),
        ));
    }
    Ok(target)
}

#[cfg(unix)]
fn require_operator_target(
    supplied: &Path,
    target: &SoftwareErasureTarget,
    label: &str,
) -> Result<(), NodeError> {
    let supplied = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        std::env::current_dir()?.join(supplied)
    };
    if supplied != target.path() {
        return Err(NodeError::Configuration(format!(
            "zeroization {label} path differs from the durable exact target"
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn completed_zeroization_receipt(
    state: &Path,
    mission_bundle: &Path,
    live_request: bool,
) -> Result<SoftwareZeroizationReceipt, NodeError> {
    let store_path = state.join(STORE_FILE);
    let expected_store = local_store_identity(&store_path)?;
    let cleanup = Store::open_for_zeroization(&store_path)?;
    require_store_backing_identity(cleanup.backing_identity(), expected_store)?;
    require_local_store_identity(&store_path, expected_store)?;
    let intent = cleanup
        .zeroization_intent()
        .ok_or(StoreError::ZeroizationInvariant(
            "completed cleanup lacks artifact intent",
        ))?;
    let mission_target = decode_zeroization_target(
        intent,
        ZeroizationArtifact::MissionBundle,
        SoftwareSecretArtifact::MissionBundle,
    )?;
    let identity_target = decode_zeroization_target(
        intent,
        ZeroizationArtifact::CarrierIdentity,
        SoftwareSecretArtifact::CarrierIdentity,
    )?;
    require_operator_target(mission_bundle, &mission_target, "mission bundle")?;
    require_operator_target(
        &state.join("identity.key"),
        &identity_target,
        "carrier identity",
    )?;
    completed_zeroization_receipt_from_cleanup(&cleanup, live_request)
}

#[cfg(unix)]
fn completed_zeroization_receipt_from_cleanup(
    cleanup: &ZeroizationStore,
    live_request: bool,
) -> Result<SoftwareZeroizationReceipt, NodeError> {
    let preserved = store_receipt_from_inspection(cleanup.inspect_preserved()?);
    let final_state: SoftwareZeroizationState = cleanup.zeroization_state().into();
    if final_state != SoftwareZeroizationState::Complete {
        return Err(NodeError::Configuration(format!(
            "zeroization remains terminal but incomplete in {} state",
            final_state.as_str()
        )));
    }
    let intent = cleanup
        .zeroization_intent()
        .ok_or(StoreError::ZeroizationInvariant(
            "completed cleanup lacks artifact intent",
        ))?;
    let mission_target = decode_zeroization_target(
        intent,
        ZeroizationArtifact::MissionBundle,
        SoftwareSecretArtifact::MissionBundle,
    )?;
    let identity_target = decode_zeroization_target(
        intent,
        ZeroizationArtifact::CarrierIdentity,
        SoftwareSecretArtifact::CarrierIdentity,
    )?;
    Ok(SoftwareZeroizationReceipt {
        live_request,
        state: final_state,
        mission_destroyed: cleanup.mission_destroyed(),
        identity_destroyed: cleanup.identity_destroyed(),
        mission_pathname: software_zeroization_path_state(&mission_target),
        identity_pathname: software_zeroization_path_state(&identity_target),
        preserved,
    })
}

#[cfg(unix)]
fn software_zeroization_path_state(target: &SoftwareErasureTarget) -> SoftwareZeroizationPathState {
    match fs::symlink_metadata(target.path()) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.dev() == target.device()
                && metadata.ino() == target.inode()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.permissions().mode() & 0o077 == 0
                && metadata.len() == 0 =>
        {
            SoftwareZeroizationPathState::RetainedZeroLength
        }
        Ok(_) => SoftwareZeroizationPathState::RetainedExternalChange,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            SoftwareZeroizationPathState::Absent
        }
        Err(_) => SoftwareZeroizationPathState::Indeterminate,
    }
}

fn demo_scope() -> Result<Scope, NodeError> {
    Scope::new(DEMO_SCOPE).map_err(|error| NodeError::Configuration(error.to_string()))
}

fn demo_event_topic() -> Result<Topic, NodeError> {
    Topic::new(DEMO_EVENT_TOPIC).map_err(|error| NodeError::Configuration(error.to_string()))
}

fn seed_demo_event_subscription(
    state: &Path,
    mission: &UnprotectedReferenceMission,
    mode: EventSubscriptionMode,
) -> Result<(), NodeError> {
    let store = Store::open_for_mission(state.join(STORE_FILE), mission.mission_authority_id())?;
    store.require_process_exclusive_lock()?;
    let policy = store.control_policy_snapshot()?;
    store.create_event_subscription_with_policy(
        &policy,
        &EventSubscriptionKey::new(DEMO_EVENT_SUBSCRIPTION_KEY.to_vec())?,
        EventSubscriptionSpec {
            mode,
            topic: demo_event_topic()?,
            scope: demo_scope()?,
            include_descendant_scopes: false,
        },
    )?;
    let snapshot = store.event_replication_policy_snapshot()?;
    if snapshot.selectors().len() != 1 {
        return Err(NodeError::Demo(
            "demo Event subscription projection differs from its one explicit selector".into(),
        ));
    }
    Ok(())
}

fn ping_operation_key() -> Result<EventOperationKey, NodeError> {
    EventOperationKey::new(DEMO_PING_OPERATION.to_vec()).map_err(Into::into)
}

fn pong_operation_key(ping: EventSemanticId) -> Result<EventOperationKey, NodeError> {
    let mut bytes = Vec::with_capacity(DEMO_PONG_OPERATION_PREFIX.len() + 32);
    bytes.extend_from_slice(DEMO_PONG_OPERATION_PREFIX);
    bytes.extend_from_slice(ping.as_bytes());
    EventOperationKey::new(bytes).map_err(Into::into)
}

pub(crate) struct SelectedEventPublish<'a> {
    pub operation: &'a EventOperationKey,
    pub predecessor: Option<EventSemanticId>,
    pub topic: &'a Topic,
    pub scope: &'a Scope,
    pub priority: Priority,
    pub logical_key: &'a [u8],
    pub payload: &'a [u8],
    pub tombstone: bool,
}

pub(crate) fn publish_selected_event_once(
    store: &Store,
    policy: &ControlPolicySnapshot,
    sealer: &mut ReferenceEnvelopeSealer,
    request: SelectedEventPublish<'_>,
) -> Result<(StoredEvent, bool), NodeError> {
    let SelectedEventPublish {
        operation,
        predecessor,
        topic,
        scope,
        priority,
        logical_key,
        payload,
        tombstone,
    } = request;
    if tombstone && !payload.is_empty() {
        return Err(NodeError::Configuration(
            "Event tombstones must carry an empty payload".into(),
        ));
    }
    let key_epoch = store
        .active_scope_epoch(scope)?
        .map_or(1, |(epoch, _)| epoch);
    for _ in 0..MAX_EVENT_PUBLISH_RETRIES {
        let reservation = match predecessor {
            Some(predecessor) => store.reserve_reaction_event_with_policy(
                policy,
                sealer.identity(),
                topic,
                scope,
                predecessor,
            )?,
            None => store.reserve_event_with_policy(policy, sealer.identity(), topic, scope)?,
        };
        let header = reservation.header(
            priority,
            logical_key.to_vec(),
            None,
            u64::try_from(payload.len())
                .map_err(|_| NodeError::Protocol("Event payload length overflows u64".into()))?,
            tombstone,
            key_epoch,
        )?;
        let sealed = sealer.seal_event(&header, payload)?;
        let route_verified = sealer.verify_event(&sealed.bytes)?;
        let verified = match sealer.verify_event_content(route_verified, &sealed.bytes)? {
            EventContentVerification::ContentVerified {
                event,
                payload: opened,
            } if opened == payload => event,
            EventContentVerification::ContentVerified { .. } => {
                return Err(NodeError::Protocol(
                    "locally sealed Event reopened with different content".into(),
                ));
            }
            EventContentVerification::RouteOnly(_) => {
                return Err(NodeError::Protocol(
                    "local Event publisher lacks content authorization".into(),
                ));
            }
        };
        match store.commit_reserved_event_once_with_policy(
            policy,
            operation,
            predecessor,
            &reservation,
            &verified,
            &sealed.bytes,
        ) {
            Ok(outcome) => {
                let (transfer_id, semantic_id, inserted) = match outcome {
                    EventOnceOutcome::Inserted {
                        transfer_id,
                        semantic_id,
                        ..
                    } => (transfer_id, semantic_id, true),
                    EventOnceOutcome::BoundExisting {
                        transfer_id,
                        semantic_id,
                        ..
                    }
                    | EventOnceOutcome::Existing {
                        transfer_id,
                        semantic_id,
                        ..
                    } => (transfer_id, semantic_id, false),
                };
                let stored = match store.get_transfer_with_policy(policy, transfer_id)? {
                    Some(StoredEventTransfer::Accepted(stored)) => stored,
                    Some(StoredEventTransfer::RouteCached(_)) => {
                        return Err(NodeError::Protocol(
                            "committed local Event operation resolved only to route cache".into(),
                        ));
                    }
                    None => {
                        return Err(NodeError::Protocol(
                            "committed Event operation is missing its exact representation".into(),
                        ));
                    }
                };
                if stored.semantic_id != semantic_id {
                    return Err(NodeError::Protocol(
                        "committed Event operation changed semantic identity".into(),
                    ));
                }
                let stored_route = sealer.verify_event(&stored.sealed)?;
                verify_stored_claim(
                    &stored_route,
                    stored.transfer_id,
                    stored.semantic_id,
                    &stored.header,
                )?;
                let reopened = match sealer.verify_event_content(stored_route, &stored.sealed)? {
                    EventContentVerification::ContentVerified {
                        event,
                        payload: reopened,
                    } => {
                        verify_content_stored_claim(&event, &stored)?;
                        reopened
                    }
                    EventContentVerification::RouteOnly(_) => {
                        return Err(NodeError::Protocol(
                            "durable local Event operation lost content authorization".into(),
                        ));
                    }
                };
                if reopened != payload
                    || stored.header.stamp.dot.publisher != sealer.identity()
                    || &stored.header.topic != topic
                    || &stored.header.scope != scope
                    || stored.header.priority != priority
                    || stored.header.logical_key.as_slice() != logical_key
                    || stored.header.ttl_ms.is_some()
                    || stored.header.tombstone != tombstone
                    || (inserted && stored.header.key_epoch != key_epoch)
                {
                    return Err(NodeError::Protocol(EVENT_OPERATION_CONFLICT.into()));
                }
                return Ok((stored, inserted));
            }
            Err(StoreError::ReservationChanged) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(NodeError::Protocol(format!(
        "Event publication reservation changed {MAX_EVENT_PUBLISH_RETRIES} times"
    )))
}

fn publish_event_once(
    store: &Store,
    policy: &ControlPolicySnapshot,
    sealer: &mut ReferenceEnvelopeSealer,
    operation: &EventOperationKey,
    predecessor: Option<EventSemanticId>,
    logical_key: Vec<u8>,
    payload: &[u8],
) -> Result<(StoredEvent, bool), NodeError> {
    publish_selected_event_once(
        store,
        policy,
        sealer,
        SelectedEventPublish {
            operation,
            predecessor,
            topic: &demo_event_topic()?,
            scope: &demo_scope()?,
            priority: Priority::Immediate,
            logical_key: &logical_key,
            payload,
            tombstone: false,
        },
    )
}

fn drive_sample_application(
    role: NodeApplication,
    store: &Store,
    policy: &ControlPolicySnapshot,
    sealer: &mut ReferenceEnvelopeSealer,
    cursor: &mut u64,
    initial_receipt_emitted: &mut bool,
) -> Result<(), NodeError> {
    match role {
        NodeApplication::Relay => Ok(()),
        NodeApplication::PingEmitter | NodeApplication::EpochTwoPingEmitter => {
            if matches!(role, NodeApplication::EpochTwoPingEmitter)
                && store
                    .active_scope_epoch(&demo_scope()?)?
                    .is_none_or(|(epoch, _)| epoch < 2)
            {
                return Ok(());
            }
            if *initial_receipt_emitted {
                return Ok(());
            }
            let (ping, inserted) = publish_event_once(
                store,
                policy,
                sealer,
                &ping_operation_key()?,
                None,
                DEMO_PING_LOGICAL_KEY.to_vec(),
                DEMO_PING_PAYLOAD,
            )?;
            println!(
                "APPLICATION status={} kind=ping transfer_id={} semantic_id={} publisher={} source_authenticated=true ttl=none",
                if inserted { "emitted" } else { "existing" },
                format_transfer_id(ping.transfer_id),
                format_semantic_id(ping.semantic_id),
                format_node_id(ping.header.stamp.dot.publisher),
            );
            *initial_receipt_emitted = true;
            Ok(())
        }
        NodeApplication::PongResponder => {
            let page = store.events_after_with_policy(policy, *cursor, MAX_EVENT_PAGE)?;
            for event in page {
                *cursor = event.acceptance_marker;
                let route_verified = sealer.verify_event(&event.sealed)?;
                verify_stored_claim(
                    &route_verified,
                    event.transfer_id,
                    event.semantic_id,
                    &event.header,
                )?;
                if event_is_inactive(store, &route_verified)? {
                    continue;
                }
                let payload = match sealer.verify_event_content(route_verified, &event.sealed)? {
                    EventContentVerification::ContentVerified {
                        event: content_verified,
                        payload,
                    } => {
                        verify_content_stored_claim(&content_verified, &event)?;
                        payload
                    }
                    EventContentVerification::RouteOnly(_) => {
                        return Err(NodeError::Protocol(
                            "semantic Event lost required content authorization on restart".into(),
                        ));
                    }
                };
                if event.header.topic.as_str() != DEMO_EVENT_TOPIC
                    || event.header.scope.as_str() != DEMO_SCOPE
                {
                    continue;
                }
                if payload != DEMO_PING_PAYLOAD
                    || event.header.logical_key != DEMO_PING_LOGICAL_KEY
                    || event.header.tombstone
                {
                    continue;
                }
                let operation = pong_operation_key(event.semantic_id)?;
                let (pong, inserted) = publish_event_once(
                    store,
                    policy,
                    sealer,
                    &operation,
                    Some(event.semantic_id),
                    event.semantic_id.as_bytes().to_vec(),
                    DEMO_PONG_PAYLOAD,
                )?;
                println!(
                    "APPLICATION status={} kind=pong transfer_id={} semantic_id={} publisher={} correlation_semantic_id={} ping_publisher={} source_authenticated=true causal_observation=verified ttl=none",
                    if inserted { "emitted" } else { "existing" },
                    format_transfer_id(pong.transfer_id),
                    format_semantic_id(pong.semantic_id),
                    format_node_id(pong.header.stamp.dot.publisher),
                    format_semantic_id(event.semantic_id),
                    format_node_id(event.header.stamp.dot.publisher),
                );
            }
            Ok(())
        }
    }
}

pub(crate) fn verify_stored_claim(
    verified: &RouteVerifiedEventEnvelope,
    transfer_id: EventTransferId,
    semantic_id: EventSemanticId,
    header: &aster_mesh::engine::EnvelopeHeader,
) -> Result<(), NodeError> {
    if EventTransferId::new(verified.envelope_id()) != transfer_id
        || EventSemanticId::new(verified.item_id()) != semantic_id
        || verified.header() != header
    {
        return Err(NodeError::Protocol(
            "persisted Event claim differs from fresh source verification".into(),
        ));
    }
    Ok(())
}

pub(crate) fn verify_content_stored_claim(
    verified: &aster_mesh::ContentVerifiedEventEnvelope,
    stored: &StoredEvent,
) -> Result<(), NodeError> {
    if EventTransferId::new(verified.envelope_id()) != stored.transfer_id
        || EventSemanticId::new(verified.item_id()) != stored.semantic_id
        || verified.header() != &stored.header
    {
        return Err(NodeError::Protocol(
            "persisted semantic Event differs from fresh content verification".into(),
        ));
    }
    Ok(())
}

fn verify_stored_control_claim(
    verified: &VerifiedControlEnvelope,
    stored: &StoredControl,
) -> Result<(), NodeError> {
    verified.verify_exact_sealed(&stored.sealed)?;
    let predecessor = verified.previous_control().map(ControlTransferId::new);
    let effect_matches = match (&stored.effect, verified.kind()) {
        (
            StoredControlEffect::Revocation {
                subject,
                generation,
            },
            VerifiedControlKind::Revocation,
        ) => {
            verified.revocation_subject() == Some(*subject)
                && verified.revocation_generation() == Some(*generation)
                && verified.scope().is_none()
                && verified.scope_epoch().is_none()
        }
        (StoredControlEffect::ScopeEpoch { scope, epoch }, VerifiedControlKind::ScopeEpoch) => {
            verified.scope() == Some(scope)
                && verified.scope_epoch() == Some(*epoch)
                && verified.revocation_subject().is_none()
                && verified.revocation_generation().is_none()
        }
        _ => false,
    };
    if ControlTransferId::new(verified.envelope_id()) != stored.transfer_id
        || verified.mission_authority_id() != stored.authority
        || verified.signer() != stored.signer
        || verified.control_sequence() != stored.sequence
        || predecessor != stored.previous_control
        || verified.kind() != stored.kind()
        || !effect_matches
    {
        return Err(NodeError::Protocol(
            "persisted mission-control claim differs from fresh source authentication".into(),
        ));
    }
    Ok(())
}

pub(crate) fn ensure_principal_active(store: &Store, principal: NodeId) -> Result<(), NodeError> {
    if store.is_control_principal_revoked(principal)? {
        return Err(NodeError::Revoked(principal));
    }
    Ok(())
}

fn ensure_contact_principals_active(
    store: &Store,
    local: NodeId,
    peer: NodeId,
) -> Result<(), NodeError> {
    ensure_principal_active(store, local)?;
    ensure_principal_active(store, peer)
}

struct EventLaneGuard {
    local: NodeId,
    peer: NodeId,
    policy: EventReplicationPolicySnapshot,
    _lease: OwnedRwLockReadGuard<()>,
}

impl EventLaneGuard {
    fn capture(
        lease: OwnedRwLockReadGuard<()>,
        store: &Store,
        local: NodeId,
        peer: NodeId,
        controls_remaining: usize,
    ) -> Result<Self, NodeError> {
        ensure_contact_principals_active(store, local, peer)?;
        if controls_remaining != 0 {
            return Err(NodeError::Protocol(
                "control reconciliation is incomplete; Event lane deferred".into(),
            ));
        }
        // Snapshot capture itself fails closed while a control gap is pending
        // and binds the complete Event lane to the exact durable receive intent.
        let policy = store.event_replication_policy_snapshot()?;
        Ok(Self {
            local,
            peer,
            policy,
            _lease: lease,
        })
    }

    fn check(&self, store: &Store) -> Result<(), NodeError> {
        ensure_contact_principals_active(store, self.local, self.peer)?;
        store.require_event_replication_policy(&self.policy)?;
        Ok(())
    }

    const fn policy(&self) -> &ControlPolicySnapshot {
        self.policy.control_policy()
    }

    const fn replication_policy(&self) -> &EventReplicationPolicySnapshot {
        &self.policy
    }

    fn interest(&self) -> Result<EventInterest, NodeError> {
        if self.policy.selectors().is_empty() {
            return Ok(EventInterest::empty());
        }
        EventInterest::new(
            self.policy
                .selectors()
                .iter()
                .map(|selector| {
                    EventInterestSelector::new(
                        selector.topic.clone(),
                        selector.scope.clone(),
                        selector.include_descendant_scopes,
                    )
                })
                .collect(),
        )
    }
}

#[derive(Clone, Copy)]
struct DirectedEventLane<'a> {
    guard: &'a EventLaneGuard,
    receiver_interest: &'a EventInterest,
    direction: EventDirection,
}

#[derive(Clone, Copy)]
struct EventReceiveAuthority<'a> {
    peer: NodeId,
    peer_route_commitments: &'a [[u8; 32]],
    receiver_interest: &'a EventInterest,
    local_replication_policy: &'a EventReplicationPolicySnapshot,
}

fn activate_committed_controls(
    store: &Store,
    verifier: &mut ReferenceEnvelopeSealer,
    controls: &[StoredControl],
    authenticated_peer: Option<NodeId>,
) -> Result<usize, NodeError> {
    let local = verifier.identity();
    for stored in controls {
        if !stored.applied {
            return Err(NodeError::Protocol(
                "redb returned a pending control in an activation suffix".into(),
            ));
        }
        let verified = verifier.verify_control(&stored.sealed)?;
        verify_stored_control_claim(&verified, stored)?;
        let ready = verifier.prepare_committed_control_activation(&verified, &stored.sealed)?;
        // This disposition comes only from the transactionally applied redb
        // revocation state. Neither caller configuration nor the just-received
        // uncommitted input can manufacture it.
        let local_revoked = store.is_control_principal_revoked(local)?;
        verifier.activate_committed_control(ready, local_revoked)?;
    }
    // The transaction may have committed more than one previously pending
    // link. Finish the complete already-durable ordered suffix before closing;
    // stopping after its first revocation would leave later provider state
    // stale until restart.
    if let Some(peer) = authenticated_peer {
        ensure_principal_active(store, local)?;
        ensure_principal_active(store, peer)?;
    }
    Ok(controls.len())
}

fn replay_applied_controls(
    store: &Store,
    verifier: &mut ReferenceEnvelopeSealer,
) -> Result<usize, NodeError> {
    let controls = store.applied_controls()?;
    // `applied_controls` is the store's audited strict sequence order. Every
    // row is still freshly authenticated and compared before provider mutation.
    activate_committed_controls(store, verifier, &controls, None)
}

pub(crate) fn open_replayed_verifier(
    store: &Store,
    credentials: &UnprotectedReferenceMission,
) -> Result<ReferenceEnvelopeSealer, NodeError> {
    let mut verifier = ReferenceEnvelopeSealer::open(credentials.fresh_bundle()?)?;
    replay_applied_controls(store, &mut verifier)?;
    Ok(verifier)
}

pub(crate) fn refresh_application_policy(
    store: &Store,
    credentials: &UnprotectedReferenceMission,
    verifier: &mut ReferenceEnvelopeSealer,
    verifier_head: &mut Option<(u64, ControlTransferId)>,
) -> Result<Option<ControlPolicySnapshot>, NodeError> {
    let durable_head = store.control_head()?;
    if durable_head != *verifier_head {
        *verifier = open_replayed_verifier(store, credentials)?;
        *verifier_head = store.control_head()?;
    }
    ensure_principal_active(store, verifier.identity())?;
    let policy = match store.control_policy_snapshot() {
        Ok(policy) => policy,
        Err(StoreError::ControlPolicyUnsettled { .. }) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if policy.head() != *verifier_head {
        return Err(NodeError::Protocol(
            "application verifier replay differs from captured control policy".into(),
        ));
    }
    Ok(Some(policy))
}

fn existing_control_receipt(
    store: &Store,
    verifier: &mut ReferenceEnvelopeSealer,
    transfer_id: ControlTransferId,
    expected: &StoredControlEffect,
) -> Result<ControlPublicationReceipt, NodeError> {
    let stored = store
        .get_control(transfer_id)?
        .ok_or_else(|| NodeError::Protocol("active control index points to no row".into()))?;
    if !stored.applied || &stored.effect != expected {
        return Err(NodeError::Protocol(
            "active control index differs from its exact applied effect".into(),
        ));
    }
    let verified = verifier.verify_control(&stored.sealed)?;
    verify_stored_control_claim(&verified, &stored)?;
    Ok(ControlPublicationReceipt {
        transfer_id,
        sequence: stored.sequence,
        emitted: false,
        activated: 0,
    })
}

fn rejected_control_error(rejected: &RejectedControl) -> NodeError {
    match rejected.reason {
        ControlRejectionReason::AuthorityRevoked(principal)
        | ControlRejectionReason::SignerRevoked(principal) => NodeError::Revoked(principal),
        ControlRejectionReason::InvalidatedPredecessor(predecessor) => {
            NodeError::Protocol(format!(
                "control {} was invalidated by rejected predecessor {}",
                format_control_transfer_id(rejected.transfer_id),
                format_control_transfer_id(predecessor),
            ))
        }
    }
}

fn finish_local_control_publication(
    store: &Store,
    verifier: &mut ReferenceEnvelopeSealer,
    expected_id: ControlTransferId,
    expected_effect: &StoredControlEffect,
    outcome: ControlOutcome,
) -> Result<ControlPublicationReceipt, NodeError> {
    let activated = activate_committed_controls(store, verifier, outcome.activated(), None)?;
    if let Some(rejected) = outcome.rejected_input() {
        return Err(rejected_control_error(&rejected));
    }
    match outcome {
        ControlOutcome::Applied { transfer_id, .. } if transfer_id == expected_id => {}
        ControlOutcome::Duplicate { .. } => {
            return existing_control_receipt(store, verifier, expected_id, expected_effect);
        }
        ControlOutcome::Pending { .. } => {
            return Err(NodeError::Protocol(
                "reserved local control became pending instead of contiguous".into(),
            ));
        }
        ControlOutcome::Rejected { .. } | ControlOutcome::Applied { .. } => {
            return Err(NodeError::Protocol(
                "local control commit returned another input disposition".into(),
            ));
        }
    }
    let mut receipt = existing_control_receipt(store, verifier, expected_id, expected_effect)?;
    receipt.emitted = true;
    receipt.activated = activated;
    ensure_principal_active(store, verifier.identity())?;
    Ok(receipt)
}

/// Publishes or reloads one authority-signed revocation by durable effect identity.
pub fn publish_revocation_control(
    state: &Path,
    mission: &UnprotectedReferenceMission,
    subject: NodeId,
    generation: u64,
) -> Result<ControlPublicationReceipt, NodeError> {
    if generation == 0 {
        return Err(NodeError::Configuration(
            "revocation generation must be nonzero".into(),
        ));
    }
    fs::create_dir_all(state)?;
    let store_path = state.join(STORE_FILE);
    let store = Store::open_for_mission(&store_path, mission.mission_authority_id())?;
    store.require_process_exclusive_lock()?;
    let mut verifier = open_replayed_verifier(&store, mission)?;
    ensure_principal_active(&store, verifier.identity())?;
    let principal = verifier.verified_control_principal().ok_or_else(|| {
        NodeError::Configuration("mission node is not a control authority".into())
    })?;
    let expected_effect = StoredControlEffect::Revocation {
        subject,
        generation,
    };
    for _ in 0..MAX_CONTROL_PUBLISH_RETRIES {
        if let Some((active_generation, transfer_id)) = store.active_revocation(subject)? {
            if active_generation == generation {
                return existing_control_receipt(
                    &store,
                    &mut verifier,
                    transfer_id,
                    &expected_effect,
                );
            }
            if active_generation > generation {
                return Err(NodeError::Protocol(format!(
                    "revocation generation {generation} rolls back active generation {active_generation}"
                )));
            }
        }
        if store.control_stats()?.pending != 0 {
            return Err(NodeError::Protocol(
                "pending control gap blocks local authority publication".into(),
            ));
        }
        let reservation = store.reserve_control(principal)?;
        let sealed = verifier.seal_chained_revocation_control(
            subject,
            generation,
            reservation.sequence(),
            reservation.previous_control().map(|id| *id.as_bytes()),
        )?;
        let verified = verifier.verify_control(&sealed)?;
        let transfer_id = ControlTransferId::new(verified.envelope_id());
        match store.commit_reserved_control(&reservation, &verified, &sealed) {
            Ok(outcome) => {
                return finish_local_control_publication(
                    &store,
                    &mut verifier,
                    transfer_id,
                    &expected_effect,
                    outcome,
                );
            }
            Err(StoreError::ControlReservationChanged) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(NodeError::Protocol(format!(
        "control reservation changed {MAX_CONTROL_PUBLISH_RETRIES} times"
    )))
}

/// Publishes or reloads one recipient-filtered scope rekey by durable effect identity.
pub fn publish_scope_rekey_control(
    state: &Path,
    mission: &UnprotectedReferenceMission,
    signed_public_registry: &[u8],
    minimum_registry_generation: u64,
    scope: Scope,
    epoch: u64,
    recipients: Vec<ScopeRekeyRecipient>,
) -> Result<ControlPublicationReceipt, NodeError> {
    if epoch == 0 || recipients.is_empty() {
        return Err(NodeError::Configuration(
            "scope rekey requires a nonzero epoch and at least one recipient".into(),
        ));
    }
    fs::create_dir_all(state)?;
    let store_path = state.join(STORE_FILE);
    let store = Store::open_for_mission(&store_path, mission.mission_authority_id())?;
    store.require_process_exclusive_lock()?;
    let mut verifier = open_replayed_verifier(&store, mission)?;
    ensure_principal_active(&store, verifier.identity())?;
    let principal = verifier.verified_control_principal().ok_or_else(|| {
        NodeError::Configuration("mission node is not a control authority".into())
    })?;
    let expected_effect = StoredControlEffect::ScopeEpoch {
        scope: scope.clone(),
        epoch,
    };
    for _ in 0..MAX_CONTROL_PUBLISH_RETRIES {
        if let Some((active_epoch, _)) = store.active_scope_epoch(&scope)?
            && active_epoch > epoch
        {
            return Err(NodeError::Protocol(format!(
                "scope epoch {epoch} rolls back active epoch {active_epoch}"
            )));
        }
        if store.control_stats()?.pending != 0 {
            return Err(NodeError::Protocol(
                "pending control gap blocks local authority publication".into(),
            ));
        }
        let reservation = store.reserve_control(principal)?;
        let (sealed, registry_generation) = verifier
            .seal_chained_scope_rekey_control_from_registry(
                signed_public_registry,
                minimum_registry_generation,
                scope.clone(),
                epoch,
                recipients.clone(),
                reservation.sequence(),
                reservation.previous_control().map(|id| *id.as_bytes()),
            )?;
        let intent = ScopeRekeyPublicationIntent::new(
            principal,
            signed_public_registry,
            registry_generation,
            scope.clone(),
            epoch,
            &recipients,
        )?;
        if let Some((active_epoch, active_id)) = store.active_scope_epoch(&scope)? {
            if active_epoch > epoch {
                return Err(NodeError::Protocol(format!(
                    "scope epoch {epoch} rolls back active epoch {active_epoch}"
                )));
            }
            if active_epoch == epoch {
                store.verify_scope_rekey_publication_intent(active_id, &intent)?;
                return existing_control_receipt(
                    &store,
                    &mut verifier,
                    active_id,
                    &expected_effect,
                );
            }
        }
        let verified = verifier.verify_control(&sealed)?;
        let transfer_id = ControlTransferId::new(verified.envelope_id());
        match store.commit_reserved_scope_rekey_control(&reservation, &verified, &sealed, &intent) {
            Ok(outcome) => {
                return finish_local_control_publication(
                    &store,
                    &mut verifier,
                    transfer_id,
                    &expected_effect,
                    outcome,
                );
            }
            Err(StoreError::ControlReservationChanged) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Err(NodeError::Protocol(format!(
        "control reservation changed {MAX_CONTROL_PUBLISH_RETRIES} times"
    )))
}

fn load_verified_control(
    store: &Store,
    verifier: &mut ReferenceEnvelopeSealer,
    transfer_id: ControlTransferId,
) -> Result<Vec<u8>, NodeError> {
    let stored = store
        .get_control(transfer_id)?
        .ok_or_else(|| NodeError::Protocol("authorized mission control is missing".into()))?;
    let verified = verifier.verify_control(&stored.sealed)?;
    verify_stored_control_claim(&verified, &stored)?;
    Ok(stored.sealed)
}

#[derive(Debug)]
struct ControlAcceptResult {
    retained: bool,
    activated: usize,
    activated_head: Option<(u64, ControlTransferId)>,
}

fn accept_received_control(
    store: &Store,
    verifier: &mut ReferenceEnvelopeSealer,
    authenticated_peer: NodeId,
    transfer_id: ControlTransferId,
    sealed: &[u8],
) -> Result<ControlAcceptResult, NodeError> {
    let verified = verifier.verify_control(sealed)?;
    if ControlTransferId::new(verified.envelope_id()) != transfer_id {
        return Err(NodeError::Protocol(
            "received control bytes do not match their exact transfer identity".into(),
        ));
    }
    let outcome = store.ingest_verified_control(&verified, sealed)?;
    let activated_head = outcome
        .activated()
        .last()
        .map(|control| (control.sequence, control.transfer_id));
    let activated = activate_committed_controls(
        store,
        verifier,
        outcome.activated(),
        Some(authenticated_peer),
    )?;
    if let Some(rejected) = outcome.rejected_input() {
        return Err(rejected_control_error(&rejected));
    }
    let retained = match outcome {
        ControlOutcome::Duplicate { .. } => false,
        ControlOutcome::Pending { .. } | ControlOutcome::Applied { .. } => true,
        ControlOutcome::Rejected { .. } => {
            return Err(NodeError::Protocol(
                "rejected control input omitted its rejection attribution".into(),
            ));
        }
    };
    Ok(ControlAcceptResult {
        retained,
        activated,
        activated_head,
    })
}

fn ensure_control_lane_state(
    store: &Store,
    local: NodeId,
    peer: NodeId,
    verifier_head: Option<(u64, ControlTransferId)>,
) -> Result<(), NodeError> {
    ensure_contact_principals_active(store, local, peer)?;
    if store.control_head()? != verifier_head {
        return Err(NodeError::Protocol(
            "mission-control head changed outside this contact; reconnect required".into(),
        ));
    }
    Ok(())
}

/// Loads one exact transfer and reconstructs a fresh route capability before use.
///
/// Redb metadata is durable structure, not a live cryptographic capability. Every
/// outbound serve therefore authenticates the source envelope again and compares
/// all persisted claims before releasing its exact bytes.
fn load_verified_transfer(
    store: &Store,
    policy: &ControlPolicySnapshot,
    verifier: &mut ReferenceEnvelopeSealer,
    transfer_id: EventTransferId,
) -> Result<Vec<u8>, NodeError> {
    let (verified, sealed, _) = load_route_verified_transfer(store, policy, verifier, transfer_id)?;
    ensure_event_epoch_active(store, &verified)?;
    Ok(sealed)
}

/// Reauthenticates one exact outbound Event against both the negotiated receive
/// interest and the authenticated peer's current route grant before disclosure.
fn load_verified_transfer_for_peer(
    store: &Store,
    policy: &ControlPolicySnapshot,
    verifier: &mut ReferenceEnvelopeSealer,
    transfer_id: EventTransferId,
    peer: NodeId,
    peer_route_commitments: &[[u8; 32]],
    receiver_interest: &EventInterest,
) -> Result<Vec<u8>, NodeError> {
    let (verified, sealed, _) = load_route_verified_transfer(store, policy, verifier, transfer_id)?;
    ensure_event_epoch_active(store, &verified)?;
    if !receiver_interest.matches(verified.topic(), verified.scope()) {
        return Err(NodeError::Protocol(
            "outbound Event is outside the peer's protected receive interest".into(),
        ));
    }
    if !verifier.peer_can_route(
        peer,
        peer_route_commitments,
        verified.scope(),
        verified.key_epoch(),
    ) {
        return Err(NodeError::Protocol(
            "authenticated peer no longer has the Event route grant for this scope and epoch"
                .into(),
        ));
    }
    Ok(sealed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EventTransferState {
    Accepted,
    RouteCached,
}

fn load_route_verified_transfer(
    store: &Store,
    policy: &ControlPolicySnapshot,
    verifier: &mut ReferenceEnvelopeSealer,
    transfer_id: EventTransferId,
) -> Result<(RouteVerifiedEventEnvelope, Vec<u8>, EventTransferState), NodeError> {
    let transfer = store
        .get_transfer_with_policy(policy, transfer_id)?
        .ok_or_else(|| NodeError::Protocol("authorized Event transfer is missing".into()))?;
    match transfer {
        StoredEventTransfer::Accepted(event) => {
            let verified = verifier.verify_event(&event.sealed)?;
            verify_stored_claim(
                &verified,
                event.transfer_id,
                event.semantic_id,
                &event.header,
            )?;
            Ok((verified, event.sealed, EventTransferState::Accepted))
        }
        StoredEventTransfer::RouteCached(event) => {
            let verified = verifier.verify_event(&event.sealed)?;
            verify_stored_claim(
                &verified,
                event.transfer_id,
                event.semantic_claim,
                &event.header_claim,
            )?;
            Ok((verified, event.sealed, EventTransferState::RouteCached))
        }
    }
}

fn transfer_inventory_for_peer(
    store: &Store,
    policy: &ControlPolicySnapshot,
    verifier: &mut ReferenceEnvelopeSealer,
    peer: NodeId,
    peer_route_commitments: &[[u8; 32]],
    receiver_interest: &EventInterest,
) -> Result<InventorySnapshot, NodeError> {
    if receiver_interest.is_empty() {
        return Ok(InventorySnapshot::default());
    }
    let inventory = store.transfer_inventory_with_policy(policy)?;
    let mut authorized = Vec::new();
    for transfer_id in inventory.iter().copied() {
        let (verified, _, _) = load_route_verified_transfer(store, policy, verifier, transfer_id)?;
        if event_is_inactive(store, &verified)? {
            continue;
        }
        if !receiver_interest.matches(verified.topic(), verified.scope()) {
            continue;
        }
        if verifier.peer_can_route(
            peer,
            peer_route_commitments,
            verified.scope(),
            verified.key_epoch(),
        ) {
            authorized.push(transfer_id.reconciliation_item_id());
        }
    }
    Ok(InventorySnapshot::new(authorized))
}

/// Builds the local receiver baseline for one directed lane.
///
/// Fresh envelope verification above the store boundary proves the local node's
/// current route capability. A receiver baseline must not substitute the
/// sender peer's grants for that local authority check.
fn transfer_inventory_for_receiver(
    store: &Store,
    policy: &EventReplicationPolicySnapshot,
    verifier: &mut ReferenceEnvelopeSealer,
    receiver_interest: &EventInterest,
) -> Result<InventorySnapshot, NodeError> {
    if receiver_interest.is_empty() {
        return Ok(InventorySnapshot::default());
    }
    let inventory = store.transfer_inventory_with_policy(policy.control_policy())?;
    let mut authorized = Vec::new();
    for transfer_id in inventory.iter().copied() {
        let (verified, _, state) =
            load_route_verified_transfer(store, policy.control_policy(), verifier, transfer_id)?;
        if event_is_inactive(store, &verified)? {
            continue;
        }
        if !receiver_interest.matches(verified.topic(), verified.scope()) {
            continue;
        }
        let Some(mode) = policy.effective_mode(verified.topic(), verified.scope()) else {
            continue;
        };
        if state == EventTransferState::RouteCached && mode == EventSubscriptionMode::Consume {
            continue;
        }
        authorized.push(transfer_id.reconciliation_item_id());
    }
    Ok(InventorySnapshot::new(authorized))
}

fn event_epoch_is_stale(
    store: &Store,
    verified: &RouteVerifiedEventEnvelope,
) -> Result<bool, NodeError> {
    Ok(store
        .active_scope_epoch(verified.scope())?
        .is_some_and(|(epoch, _)| verified.key_epoch() < epoch))
}

fn event_source_is_revoked(
    store: &Store,
    verified: &RouteVerifiedEventEnvelope,
) -> Result<bool, NodeError> {
    Ok(store.is_control_principal_revoked(verified.publisher())?)
}

pub(crate) fn event_is_inactive(
    store: &Store,
    verified: &RouteVerifiedEventEnvelope,
) -> Result<bool, NodeError> {
    Ok(event_epoch_is_stale(store, verified)? || event_source_is_revoked(store, verified)?)
}

fn ensure_event_epoch_active(
    store: &Store,
    verified: &RouteVerifiedEventEnvelope,
) -> Result<(), NodeError> {
    if let Some((current, _)) = store.active_scope_epoch(verified.scope())?
        && verified.key_epoch() < current
    {
        return Err(NodeError::Protocol(format!(
            "Event key epoch {} is stale behind active scope epoch {current}",
            verified.key_epoch()
        )));
    }
    ensure_principal_active(store, verified.publisher())?;
    Ok(())
}

fn accept_received_transfer(
    store: &Store,
    verifier: &mut ReferenceEnvelopeSealer,
    authority: EventReceiveAuthority<'_>,
    transfer_id: EventTransferId,
    sealed: &[u8],
) -> Result<bool, NodeError> {
    let route_verified = verifier.verify_event(sealed)?;
    if EventTransferId::new(route_verified.envelope_id()) != transfer_id {
        return Err(NodeError::Protocol(
            "received Event bytes do not match their exact transfer identity".into(),
        ));
    }
    ensure_event_epoch_active(store, &route_verified)?;
    if !authority
        .receiver_interest
        .matches(route_verified.topic(), route_verified.scope())
    {
        return Err(NodeError::Protocol(
            "received Event is outside the durable receive interest captured for this contact"
                .into(),
        ));
    }
    if !verifier.peer_can_route(
        authority.peer,
        authority.peer_route_commitments,
        route_verified.scope(),
        route_verified.key_epoch(),
    ) {
        return Err(NodeError::Protocol(
            "authenticated peer lacks the Event route grant for this scope and epoch".into(),
        ));
    }
    let Some(mode) = authority
        .local_replication_policy
        .effective_mode(route_verified.topic(), route_verified.scope())
    else {
        return Err(NodeError::Protocol(
            "received Event is outside the durable local receive-mode snapshot".into(),
        ));
    };
    if mode == EventSubscriptionMode::Carry {
        let outcome = store.cache_route_verified_event_with_replication_policy(
            authority.local_replication_policy,
            &route_verified,
            sealed,
        )?;
        return Ok(matches!(outcome, RouteCacheOutcome::Inserted { .. }));
    }
    match verifier.verify_event_content(route_verified, sealed)? {
        EventContentVerification::ContentVerified { event, .. } => Ok(store
            .apply_verified_event_with_replication_policy(
                authority.local_replication_policy,
                &event,
                sealed,
            )?
            .inserted()),
        EventContentVerification::RouteOnly(event) => {
            let outcome = store.cache_route_verified_event_with_replication_policy(
                authority.local_replication_policy,
                &event,
                sealed,
            )?;
            Ok(matches!(outcome, RouteCacheOutcome::Inserted { .. }))
        }
    }
}

fn format_transfer_id(id: EventTransferId) -> String {
    format_digest(id.as_bytes())
}

/// Formats a complete exact mission-control transfer identifier.
pub fn format_control_transfer_id(id: ControlTransferId) -> String {
    format_digest(id.as_bytes())
}

fn format_semantic_id(id: EventSemanticId) -> String {
    format_digest(id.as_bytes())
}

fn format_digest(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalPathIdentity {
    canonical_path: PathBuf,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct LocalZeroizationBinding {
    state: LocalPathIdentity,
    store_device: u64,
    store_inode: u64,
    mission: LocalPathIdentity,
}

#[cfg(unix)]
struct LocalZeroizationControl {
    listener: UnixListener,
    control_directory: LocalPathIdentity,
    socket_path: PathBuf,
    socket_device: u64,
    socket_inode: u64,
    state: LocalPathIdentity,
    store_device: u64,
    store_inode: u64,
}

#[cfg(unix)]
struct LocalZeroizationRequest {
    stream: UnixStream,
    binding: LocalZeroizationBinding,
}

#[derive(Debug)]
struct LocalZeroizationAcceptError {
    error: NodeError,
    integrity_failure: bool,
}

impl LocalZeroizationAcceptError {
    fn request(error: impl Into<NodeError>) -> Self {
        Self {
            error: error.into(),
            integrity_failure: false,
        }
    }

    fn integrity(error: impl Into<NodeError>) -> Self {
        Self {
            error: error.into(),
            integrity_failure: true,
        }
    }

    const fn is_integrity_failure(&self) -> bool {
        self.integrity_failure
    }

    fn into_node_error(self) -> NodeError {
        self.error
    }
}

#[cfg(not(unix))]
struct LocalZeroizationRequest;

#[cfg(unix)]
impl LocalZeroizationControl {
    fn bind(state: &Path, store_path: &Path) -> Result<Self, NodeError> {
        let control_directory = local_zeroization_control_directory(true)?;
        Self::bind_with_control_directory(state, store_path, control_directory)
    }

    #[cfg(test)]
    fn bind_in_control_directory(
        state: &Path,
        store_path: &Path,
        control_directory: &Path,
    ) -> Result<Self, NodeError> {
        let control_directory = local_zeroization_control_directory_at(control_directory, true)?;
        Self::bind_with_control_directory(state, store_path, control_directory)
    }

    fn bind_with_control_directory(
        state: &Path,
        store_path: &Path,
        control_directory: LocalPathIdentity,
    ) -> Result<Self, NodeError> {
        let state = local_state_identity(state)?;
        let (store_device, store_inode) = local_store_identity(store_path)?;
        let socket_path = local_zeroization_socket_path(
            &control_directory.canonical_path,
            store_device,
            store_inode,
        );
        remove_owned_stale_local_socket(&socket_path)?;
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
        File::open(&control_directory.canonical_path)?.sync_all()?;
        let socket = validate_local_socket(&socket_path)?;
        Ok(Self {
            listener,
            control_directory,
            socket_path,
            socket_device: socket.dev(),
            socket_inode: socket.ino(),
            state,
            store_device,
            store_inode,
        })
    }

    async fn accept(&self) -> Result<LocalZeroizationRequest, LocalZeroizationAcceptError> {
        let (mut stream, _) = loop {
            self.revalidate()
                .map_err(LocalZeroizationAcceptError::integrity)?;
            match timeout(LOCAL_ZEROIZATION_INTEGRITY_INTERVAL, self.listener.accept()).await {
                Ok(Ok(accepted)) => break accepted,
                Ok(Err(error)) => return Err(LocalZeroizationAcceptError::integrity(error)),
                Err(_) => {}
            }
        };
        self.revalidate()
            .map_err(LocalZeroizationAcceptError::integrity)?;
        let credentials = stream
            .peer_cred()
            .map_err(LocalZeroizationAcceptError::request)?;
        if credentials.uid() != rustix::process::geteuid().as_raw() {
            return Err(LocalZeroizationAcceptError::request(
                NodeError::Configuration(
                    "local zeroization requester does not have the node owner's effective UID"
                        .into(),
                ),
            ));
        }
        let binding = timeout(
            LOCAL_ZEROIZATION_IO_DEADLINE,
            read_local_zeroization_request(&mut stream),
        )
        .await
        .map_err(|_| {
            LocalZeroizationAcceptError::request(NodeError::Configuration(
                "local zeroization request exceeded its deadline".into(),
            ))
        })?
        .map_err(LocalZeroizationAcceptError::request)?;
        self.revalidate()
            .map_err(LocalZeroizationAcceptError::integrity)?;
        if binding.state != self.state
            || binding.store_device != self.store_device
            || binding.store_inode != self.store_inode
        {
            return Err(LocalZeroizationAcceptError::request(
                NodeError::Configuration(
                    "local zeroization request names a different exact node state".into(),
                ),
            ));
        }
        Ok(LocalZeroizationRequest { stream, binding })
    }

    fn revalidate(&self) -> Result<(), NodeError> {
        let control_directory =
            local_zeroization_control_directory_at(&self.control_directory.canonical_path, false)?;
        if control_directory != self.control_directory {
            return Err(NodeError::Configuration(
                "local zeroization control directory changed while control was live".into(),
            ));
        }
        let state = local_state_identity(&self.state.canonical_path)?;
        if state != self.state {
            return Err(NodeError::Configuration(
                "node state directory changed while local zeroization control was live".into(),
            ));
        }
        let store_path = self.state.canonical_path.join(STORE_FILE);
        let (device, inode) = local_store_identity(&store_path)?;
        if device != self.store_device || inode != self.store_inode {
            return Err(NodeError::Configuration(
                "node store changed while local zeroization control was live".into(),
            ));
        }
        let socket = validate_local_socket(&self.socket_path)?;
        if socket.dev() != self.socket_device || socket.ino() != self.socket_inode {
            return Err(NodeError::Configuration(
                "local zeroization control socket was replaced".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(unix)]
async fn run_local_zeroization_accept_loop(
    control: LocalZeroizationControl,
    sender: mpsc::Sender<Result<LocalZeroizationRequest, LocalZeroizationAcceptError>>,
    #[cfg(test)] mut queued: Option<oneshot::Sender<()>>,
) {
    loop {
        let request = control.accept().await;
        let integrity_failure = request
            .as_ref()
            .is_err_and(LocalZeroizationAcceptError::is_integrity_failure);
        if sender.send(request).await.is_err() {
            break;
        }
        #[cfg(test)]
        if let Some(queued) = queued.take() {
            let _ = queued.send(());
        }
        if integrity_failure {
            break;
        }
    }
}

#[cfg(unix)]
impl Drop for LocalZeroizationControl {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.socket_path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.socket_device
            && metadata.ino() == self.socket_inode
        {
            let _ = fs::remove_file(&self.socket_path);
            if let Some(parent) = self.socket_path.parent() {
                let _ = File::open(parent).and_then(|directory| directory.sync_all());
            }
        }
    }
}

#[cfg(unix)]
impl LocalZeroizationRequest {
    fn mission_matches(&self, path: &Path, device: u64, inode: u64) -> bool {
        self.binding.mission.canonical_path == path
            && self.binding.mission.device == device
            && self.binding.mission.inode == inode
    }

    async fn respond(mut self, response: &str) -> Result<(), NodeError> {
        timeout(
            LOCAL_ZEROIZATION_IO_DEADLINE,
            write_local_zeroization_response(&mut self.stream, response),
        )
        .await
        .map_err(|_| {
            NodeError::Configuration("local zeroization response exceeded its deadline".into())
        })??;
        Ok(())
    }
}

#[cfg(not(unix))]
impl LocalZeroizationRequest {
    async fn respond(self, _response: &str) -> Result<(), NodeError> {
        Err(SoftwareErasureError::PlatformUnavailable.into())
    }
}

#[cfg(unix)]
async fn request_live_zeroization(
    state: &Path,
    mission_bundle: &Path,
    wait: Duration,
) -> Result<Option<String>, NodeError> {
    if wait.is_zero() {
        return Err(NodeError::Configuration(
            "local zeroization wait must be nonzero".into(),
        ));
    }
    let state = local_state_identity(state)?;
    let store_path = state.canonical_path.join(STORE_FILE);
    match fs::symlink_metadata(&store_path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let (store_device, store_inode) = local_store_identity(&store_path)?;
    let tentative_control_directory = local_zeroization_control_directory_path()?;
    match fs::symlink_metadata(&tentative_control_directory) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let control_directory = local_zeroization_control_directory(false)?;
    let socket_path =
        local_zeroization_socket_path(&control_directory.canonical_path, store_device, store_inode);
    let before = match fs::symlink_metadata(&socket_path) {
        Ok(_) => validate_local_socket(&socket_path)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mission = local_mission_request_identity(mission_bundle)?;
    let mut stream = match timeout(wait, UnixStream::connect(&socket_path)).await {
        Err(_) => {
            return Err(NodeError::Configuration(
                "local zeroization connect timed out".into(),
            ));
        }
        Ok(Ok(stream)) => stream,
        Ok(Err(error))
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
            ) =>
        {
            return Ok(None);
        }
        Ok(Err(error)) => return Err(error.into()),
    };
    let credentials = stream.peer_cred()?;
    if credentials.uid() != rustix::process::geteuid().as_raw() {
        return Err(NodeError::Configuration(
            "local zeroization server does not have the operator's effective UID".into(),
        ));
    }
    let after = validate_local_socket(&socket_path)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(NodeError::Configuration(
            "local zeroization control socket changed while connecting".into(),
        ));
    }
    let binding = LocalZeroizationBinding {
        state,
        store_device,
        store_inode,
        mission,
    };
    timeout(wait, write_local_zeroization_request(&mut stream, &binding))
        .await
        .map_err(|_| NodeError::Configuration("local zeroization request timed out".into()))??;
    timeout(wait, read_local_zeroization_response(&mut stream))
        .await
        .map_err(|_| NodeError::Configuration("local zeroization cleanup timed out".into()))?
        .map(Some)
}

#[cfg(not(unix))]
async fn request_live_zeroization(
    _state: &Path,
    _mission_bundle: &Path,
    _wait: Duration,
) -> Result<Option<String>, NodeError> {
    Err(NodeError::Configuration(
        "live local zeroization control requires Unix peer credentials and file identity".into(),
    ))
}

#[cfg(unix)]
fn local_state_identity(path: &Path) -> Result<LocalPathIdentity, NodeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(NodeError::Configuration(format!(
            "local zeroization state must be a non-symbolic-link directory: {}",
            path.display()
        )));
    }
    let effective_uid = rustix::process::geteuid().as_raw();
    if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o022 != 0 {
        return Err(NodeError::Configuration(format!(
            "local zeroization state directory must be owned by the effective UID and not group/world writable: {}",
            path.display()
        )));
    }
    let canonical_path = fs::canonicalize(path)?;
    let canonical = fs::metadata(&canonical_path)?;
    if canonical.dev() != metadata.dev() || canonical.ino() != metadata.ino() {
        return Err(NodeError::Configuration(
            "local zeroization state directory changed while resolving".into(),
        ));
    }
    Ok(LocalPathIdentity {
        canonical_path,
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn local_store_identity(path: &Path) -> Result<(u64, u64), NodeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o022 != 0
        || metadata.nlink() != 1
    {
        return Err(NodeError::Configuration(format!(
            "local zeroization store must be an owner-controlled uniquely linked regular file that is not group/world writable: {}",
            path.display()
        )));
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(unix)]
fn require_local_store_identity(path: &Path, expected: (u64, u64)) -> Result<(), NodeError> {
    if local_store_identity(path)? != expected {
        return Err(NodeError::Configuration(
            "local zeroization store changed after exact-state validation".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn require_store_backing_identity(
    backing: StoreBackingIdentity,
    expected: (u64, u64),
) -> Result<(), NodeError> {
    if backing.unix_device_inode() != Some(expected) {
        return Err(NodeError::Configuration(
            "opened store handle differs from the exact validated state inode".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn require_store_path_matches_backing(
    path: &Path,
    backing: StoreBackingIdentity,
) -> Result<(), NodeError> {
    let expected = backing.unix_device_inode().ok_or_else(|| {
        NodeError::Configuration("opened store handle has no Unix backing identity".into())
    })?;
    require_local_store_identity(path, expected)
}

#[cfg(unix)]
fn local_mission_request_identity(path: &Path) -> Result<LocalPathIdentity, NodeError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.nlink() != 1
    {
        return Err(NodeError::Configuration(format!(
            "local zeroization mission bundle must be an exact owner-only uniquely linked regular file: {}",
            path.display()
        )));
    }
    let canonical_path = fs::canonicalize(path)?;
    let canonical = fs::metadata(&canonical_path)?;
    if canonical.dev() != metadata.dev() || canonical.ino() != metadata.ino() {
        return Err(NodeError::Configuration(
            "local zeroization mission bundle changed while resolving".into(),
        ));
    }
    Ok(LocalPathIdentity {
        canonical_path,
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn local_zeroization_control_directory(create: bool) -> Result<LocalPathIdentity, NodeError> {
    let directory = local_zeroization_control_directory_path()?;
    local_zeroization_control_directory_at(&directory, create)
}

#[cfg(unix)]
fn local_zeroization_control_directory_at(
    directory: &Path,
    create: bool,
) -> Result<LocalPathIdentity, NodeError> {
    let effective_uid = rustix::process::geteuid().as_raw();
    if create {
        match fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => File::open(
                directory
                    .parent()
                    .expect("local zeroization control directory has a parent"),
            )?
            .sync_all()?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_uid
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(NodeError::Configuration(format!(
            "local zeroization control directory must be owner-only and non-symbolic-link: {}",
            directory.display()
        )));
    }
    let canonical_path = fs::canonicalize(directory)?;
    let canonical = fs::metadata(&canonical_path)?;
    if canonical.dev() != metadata.dev() || canonical.ino() != metadata.ino() {
        return Err(NodeError::Configuration(
            "local zeroization control directory changed while resolving".into(),
        ));
    }
    Ok(LocalPathIdentity {
        canonical_path,
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn local_zeroization_control_directory_path() -> Result<PathBuf, NodeError> {
    let temporary_root = fs::canonicalize("/tmp")?;
    Ok(temporary_root.join(format!(
        "aster-zeroize-{}",
        rustix::process::geteuid().as_raw()
    )))
}

#[cfg(unix)]
fn local_zeroization_socket_path(directory: &Path, device: u64, inode: u64) -> PathBuf {
    directory.join(format!("mesh-{device:016x}-{inode:016x}.sock"))
}

#[cfg(unix)]
fn validate_local_socket(path: &Path) -> Result<fs::Metadata, NodeError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(NodeError::Configuration(format!(
            "local zeroization control socket is not an exact owner-only Unix socket: {}",
            path.display()
        )));
    }
    Ok(metadata)
}

#[cfg(unix)]
fn remove_owned_stale_local_socket(path: &Path) -> Result<(), NodeError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_socket()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(NodeError::Configuration(format!(
            "refusing to replace an unsafe local zeroization socket path: {}",
            path.display()
        )));
    }
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(NodeError::Configuration(
            "another live local zeroization server owns the exact socket".into(),
        )),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            let current = fs::symlink_metadata(path)?;
            if !current.file_type().is_socket()
                || current.dev() != metadata.dev()
                || current.ino() != metadata.ino()
            {
                return Err(NodeError::Configuration(
                    "local zeroization socket changed during stale cleanup".into(),
                ));
            }
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
async fn write_local_zeroization_request(
    stream: &mut UnixStream,
    binding: &LocalZeroizationBinding,
) -> io::Result<()> {
    stream.write_all(LOCAL_ZEROIZATION_REQUEST_MAGIC).await?;
    write_local_path(stream, &binding.state.canonical_path).await?;
    stream
        .write_all(&binding.state.device.to_be_bytes())
        .await?;
    stream.write_all(&binding.state.inode.to_be_bytes()).await?;
    stream
        .write_all(&binding.store_device.to_be_bytes())
        .await?;
    stream.write_all(&binding.store_inode.to_be_bytes()).await?;
    write_local_path(stream, &binding.mission.canonical_path).await?;
    stream
        .write_all(&binding.mission.device.to_be_bytes())
        .await?;
    stream
        .write_all(&binding.mission.inode.to_be_bytes())
        .await?;
    stream.flush().await
}

#[cfg(unix)]
async fn read_local_zeroization_request(
    stream: &mut UnixStream,
) -> Result<LocalZeroizationBinding, NodeError> {
    let mut magic = vec![0u8; LOCAL_ZEROIZATION_REQUEST_MAGIC.len()];
    stream.read_exact(&mut magic).await?;
    if magic != LOCAL_ZEROIZATION_REQUEST_MAGIC {
        return Err(NodeError::Configuration(
            "local zeroization request magic/version differs".into(),
        ));
    }
    let state_path = read_local_path(stream, "state").await?;
    let state_device = read_local_u64(stream).await?;
    let state_inode = read_local_u64(stream).await?;
    let store_device = read_local_u64(stream).await?;
    let store_inode = read_local_u64(stream).await?;
    let mission_path = read_local_path(stream, "mission bundle").await?;
    let mission_device = read_local_u64(stream).await?;
    let mission_inode = read_local_u64(stream).await?;
    Ok(LocalZeroizationBinding {
        state: LocalPathIdentity {
            canonical_path: state_path,
            device: state_device,
            inode: state_inode,
        },
        store_device,
        store_inode,
        mission: LocalPathIdentity {
            canonical_path: mission_path,
            device: mission_device,
            inode: mission_inode,
        },
    })
}

#[cfg(unix)]
async fn write_local_path(stream: &mut UnixStream, path: &Path) -> io::Result<()> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_LOCAL_ZEROIZATION_PATH_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local zeroization path length is outside its bound",
        ));
    }
    let length = u32::try_from(bytes.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "local zeroization path is too long",
        )
    })?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(bytes).await
}

#[cfg(unix)]
async fn read_local_path(stream: &mut UnixStream, label: &str) -> Result<PathBuf, NodeError> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let length = usize::try_from(u32::from_be_bytes(length)).expect("u32 fits usize");
    if length == 0 || length > MAX_LOCAL_ZEROIZATION_PATH_BYTES {
        return Err(NodeError::Configuration(format!(
            "local zeroization {label} path length is outside its bound"
        )));
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).await?;
    Ok(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

#[cfg(unix)]
async fn read_local_u64(stream: &mut UnixStream) -> io::Result<u64> {
    let mut bytes = [0u8; 8];
    stream.read_exact(&mut bytes).await?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(unix)]
async fn write_local_zeroization_response(
    stream: &mut UnixStream,
    response: &str,
) -> io::Result<()> {
    if response.is_empty() || response.len() > MAX_LOCAL_ZEROIZATION_RESPONSE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "local zeroization response length is outside its bound",
        ));
    }
    let length = u32::try_from(response.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "local zeroization response is too long",
        )
    })?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await
}

#[cfg(unix)]
async fn read_local_zeroization_response(stream: &mut UnixStream) -> Result<String, NodeError> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await?;
    let length = usize::try_from(u32::from_be_bytes(length)).expect("u32 fits usize");
    if length == 0 || length > MAX_LOCAL_ZEROIZATION_RESPONSE_BYTES {
        return Err(NodeError::Configuration(
            "local zeroization response length is outside its bound".into(),
        ));
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).await?;
    String::from_utf8(bytes)
        .map_err(|_| NodeError::Configuration("local zeroization response is not UTF-8".into()))
}

fn validate_node_config(config: &NodeConfig) -> Result<BTreeMap<EndpointId, NodeId>, NodeError> {
    if config.sync_interval.is_zero() {
        return Err(NodeError::Configuration(
            "sync interval must be nonzero".into(),
        ));
    }
    if config.peers.len() > MAX_CONFIGURED_PEERS {
        return Err(NodeError::Configuration(format!(
            "peer count {} exceeds {MAX_CONFIGURED_PEERS}",
            config.peers.len()
        )));
    }
    let allowed = config
        .peers
        .iter()
        .map(|peer| (peer.carrier.id, peer.mission))
        .collect::<BTreeMap<_, _>>();
    if allowed.len() != config.peers.len() {
        return Err(NodeError::Configuration(
            "peer endpoint identities must be unique".into(),
        ));
    }
    let addresses = config
        .peers
        .iter()
        .map(|peer| peer.carrier.address)
        .collect::<BTreeSet<_>>();
    if addresses.len() != config.peers.len() {
        return Err(NodeError::Configuration(
            "peer direct socket addresses must be unique".into(),
        ));
    }
    let missions = config
        .peers
        .iter()
        .map(|peer| peer.mission)
        .collect::<BTreeSet<_>>();
    if missions.len() != config.peers.len() {
        return Err(NodeError::Configuration(
            "peer mission identities must be unique".into(),
        ));
    }
    if missions.contains(&config.mission.identity()) {
        return Err(NodeError::Configuration(
            "a node cannot configure its own mission identity as a peer".into(),
        ));
    }
    Ok(allowed)
}

fn execute_selected_event_command(
    application: &mut SelectedEventNode,
    store: &Store,
    status: &SelectedEventStatusTracker,
    receipt: &NodeReceipt,
    command: SelectedEventCommand,
) {
    match command {
        SelectedEventCommand::Publish { request, response } => {
            let result = application.publish(request);
            let _ = response.send(result);
        }
        SelectedEventCommand::Query { query, response } => {
            let result = application.query(query);
            let _ = response.send(result);
        }
        SelectedEventCommand::Subscribe { request, response } => {
            let result = application.subscribe(request);
            let _ = response.send(result);
        }
        SelectedEventCommand::Poll { request, response } => {
            let result = application.poll(request);
            let _ = response.send(result);
        }
        SelectedEventCommand::Acknowledge {
            subscription,
            event,
            response,
        } => {
            let result = application.acknowledge(subscription, event);
            let _ = response.send(result);
        }
        SelectedEventCommand::Unsubscribe {
            subscription,
            response,
        } => {
            let result = application.unsubscribe(subscription);
            let _ = response.send(result);
        }
        SelectedEventCommand::Gaps { query, response } => {
            let result = application.gaps(query);
            let _ = response.send(result);
        }
        SelectedEventCommand::Status { response } => {
            let result = application.runtime_policy_for_status().and_then(|current| {
                status
                    .snapshot(store, &current, receipt.contact_errors)
                    .map_err(|error| runtime_application_error("status", error))
            });
            let _ = response.send(result);
        }
    }
}

/// Starts one readiness-driven selected-stack node and its bounded application actor.
pub async fn start_node(config: NodeConfig) -> Result<RunningNode, NodeError> {
    let identity = config.mission.identity();
    let mission_authority = config.mission.mission_authority_id();
    let (application_sender, application_receiver) = mpsc::channel(APPLICATION_COMMAND_CAPACITY);
    let application_admission = Arc::new(AtomicBool::new(true));
    let selected_events = SelectedEventHandle::new(
        application_sender,
        application_admission.clone(),
        identity,
        mission_authority,
    );
    let (shutdown_sender, shutdown_receiver) = mpsc::channel(1);
    let (ready_sender, ready_receiver) = oneshot::channel();
    let task = tokio::spawn(run_node_actor(
        config,
        application_receiver,
        application_admission.clone(),
        shutdown_receiver,
        ready_sender,
    ));
    if ready_receiver.await.is_err() {
        return match task.await.map_err(node_actor_join_error)? {
            Err(error) => Err(error),
            Ok(_) => Err(NodeError::Protocol(
                "running node stopped before readiness".into(),
            )),
        };
    }
    Ok(RunningNode {
        selected_events,
        application_admission,
        shutdown: Some(shutdown_sender),
        task: Some(task),
    })
}

/// Runs one selected-stack node until its deadline or signal.
pub async fn run_node(config: NodeConfig) -> Result<NodeReceipt, NodeError> {
    start_node(config).await?.wait().await
}

#[cfg(all(test, unix))]
struct RunNodeActorTestControl {
    before_loop_ready: oneshot::Sender<()>,
    before_loop_release: oneshot::Receiver<()>,
    zeroization_queued: oneshot::Sender<()>,
}

async fn run_node_actor(
    config: NodeConfig,
    application_receiver: mpsc::Receiver<SelectedEventCommand>,
    application_admission: Arc<AtomicBool>,
    shutdown_receiver: mpsc::Receiver<()>,
    ready: oneshot::Sender<Vec<SocketAddr>>,
) -> Result<NodeReceipt, NodeError> {
    #[cfg(all(test, unix))]
    let result = run_node_actor_inner(
        config,
        application_receiver,
        application_admission,
        shutdown_receiver,
        ready,
        None,
    )
    .await;
    #[cfg(not(all(test, unix)))]
    let result = run_node_actor_inner(
        config,
        application_receiver,
        application_admission,
        shutdown_receiver,
        ready,
    )
    .await;
    result
}

async fn run_node_actor_inner(
    config: NodeConfig,
    mut application_receiver: mpsc::Receiver<SelectedEventCommand>,
    application_admission: Arc<AtomicBool>,
    mut shutdown_receiver: mpsc::Receiver<()>,
    ready: oneshot::Sender<Vec<SocketAddr>>,
    #[cfg(all(test, unix))] mut test_control: Option<RunNodeActorTestControl>,
) -> Result<NodeReceipt, NodeError> {
    let stop_deadline = config
        .run_for
        .map(|duration| {
            Instant::now().checked_add(duration).ok_or_else(|| {
                NodeError::Configuration("node run_for exceeds the monotonic clock".into())
            })
        })
        .transpose()?;
    let peer_missions = validate_node_config(&config)?;
    let allowed = peer_missions.keys().copied().collect::<BTreeSet<_>>();
    let mission_authority = config.mission.mission_authority_id();
    fs::create_dir_all(&config.state)?;
    // Bind durable semantic/cache state before creating carrier identity or a
    // network endpoint. Reopening with another mission authority fails through
    // redb's read-only preflight before migration or state/network mutation.
    let store_path = config.state.join(STORE_FILE);
    #[cfg(unix)]
    match fs::symlink_metadata(&store_path) {
        Ok(_) => {
            let _ = local_store_identity(&store_path)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let store = Arc::new(Store::open_for_mission(&store_path, mission_authority)?);
    store.require_process_exclusive_lock()?;
    #[cfg(unix)]
    {
        let store_identity = local_store_identity(&store_path)?;
        require_store_backing_identity(store.backing_identity(), store_identity)?;
    }
    let mut application_sealer = ReferenceEnvelopeSealer::open(config.mission.fresh_bundle()?)?;
    let policy_lock = Arc::new(RwLock::new(()));
    // The exact applied control prefix is freshly reauthenticated and replayed
    // before any persisted carrier identity is created or any socket is bound.
    replay_applied_controls(&store, &mut application_sealer)?;
    ensure_principal_active(&store, application_sealer.identity())?;
    let application_control_head = store.control_head()?;
    let mut application = SelectedEventNode::from_runtime(
        config.mission.clone(),
        store.clone(),
        application_sealer,
        application_control_head,
    );
    let identity = NodeIdentity::load_or_create(&config.state)?;
    let local_id = identity.id();
    if allowed.contains(&local_id) {
        return Err(NodeError::Configuration(
            "a node cannot configure its own endpoint identity as a peer".into(),
        ));
    }
    #[cfg(unix)]
    let zeroization_control = LocalZeroizationControl::bind(&config.state, &store_path)?;
    let endpoint = Endpoint::bind(identity.secret()?, EndpointConfig::direct(config.bind)).await?;
    let (zeroization_sender, mut zeroization_receiver) = mpsc::channel(1);
    let bound_sockets = endpoint.bound_sockets();
    let sockets = bound_sockets
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "READY selected=true pid={} carrier_id={} mission_id={} mission_authority={} sockets={} state={} peers={} application={} mission_auth=hybrid-pq provisioning=unprotected-reference semantics=source-authenticated-event controls=source-authenticated-flash commit_before_activate=true content_admission=capability-gated",
        std::process::id(),
        local_id,
        format_node_id(config.mission.identity()),
        format_node_id(mission_authority),
        sockets,
        format_path_field(&config.state),
        allowed.len(),
        config.application.as_str()
    );
    // Cancellation before the readiness handoff skips all operational work but
    // still follows the single task/endpoint cleanup path below.
    let owner_ready = ready.send(bound_sockets).is_ok();
    #[cfg(all(test, unix))]
    let (before_loop_ready, before_loop_release, zeroization_queued) = match test_control.take() {
        Some(control) => (
            Some(control.before_loop_ready),
            Some(control.before_loop_release),
            Some(control.zeroization_queued),
        ),
        None => (None, None, None),
    };
    #[cfg(all(test, unix))]
    let mut zeroization_task = if owner_ready {
        Some(tokio::spawn(run_local_zeroization_accept_loop(
            zeroization_control,
            zeroization_sender,
            zeroization_queued,
        )))
    } else {
        None
    };
    #[cfg(all(not(test), unix))]
    let mut zeroization_task = if owner_ready {
        Some(tokio::spawn(run_local_zeroization_accept_loop(
            zeroization_control,
            zeroization_sender,
        )))
    } else {
        None
    };
    #[cfg(not(unix))]
    let _zeroization_sender_guard = zeroization_sender;
    #[cfg(not(unix))]
    let mut zeroization_task = None::<tokio::task::JoinHandle<()>>;

    let mut ticker = tokio::time::interval(config.sync_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let stop = async move {
        if let Some(deadline) = stop_deadline {
            sleep(deadline.saturating_duration_since(Instant::now())).await;
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    };
    tokio::pin!(stop);
    let mut receipt = NodeReceipt::default();
    let mut selected_event_status =
        SelectedEventStatusTracker::new(config.peers.iter().map(|peer| peer.mission).collect());
    let mut application_commands_open = true;
    let mut pending_application_command = None::<SelectedEventCommand>;
    let mut application_tick_pending = false;
    let mut application_tick_yield_required = false;
    let mut application_commands_since_yield = 0usize;
    let mut network_events_since_application = 0usize;
    let mut inbound: JoinSet<(EndpointId, Result<CompletedPeerContact, NodeError>)> =
        JoinSet::new();
    let mut inbound_peers = BTreeSet::new();
    let mut inbound_tasks = BTreeMap::<TaskId, EndpointId>::new();
    let mut outbound: JoinSet<(MissionExpectedPeer, Result<CompletedPeerContact, NodeError>)> =
        JoinSet::new();
    let mut outbound_peers = BTreeSet::new();
    let mut outbound_tasks = BTreeMap::<TaskId, MissionExpectedPeer>::new();
    let mut next_outbound_peer = 0usize;
    let mut application_cursor = 0u64;
    let mut initial_application_receipt_emitted = false;
    let mut fatal_error = None;
    let mut live_zeroization = None;
    // Keep one accept future alive independently from the scheduler select.
    // Reconstructing `Endpoint::accept` on every 100 ms tick can cancel a
    // handshake indefinitely on an accept-only node.
    let (accepted_sender, mut accepted_receiver) = mpsc::channel(1);
    let mut accept_task = if !owner_ready || allowed.is_empty() {
        None
    } else {
        let endpoint = endpoint.clone();
        let allowed = allowed.clone();
        Some(tokio::spawn(async move {
            loop {
                match endpoint.accept(&allowed).await {
                    Ok(connection) => {
                        if accepted_sender.send(Ok(connection)).await.is_err() {
                            break;
                        }
                    }
                    Err(CarrierError::Timeout(_)) => {}
                    Err(error) => {
                        if accepted_sender.send(Err(error)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }))
    };

    #[cfg(all(test, unix))]
    if owner_ready {
        if let Some(ready) = before_loop_ready {
            let _ = ready.send(());
        }
        if let Some(release) = before_loop_release {
            let _ = release.await;
        }
    }

    if owner_ready {
        loop {
            if network_events_since_application >= NETWORK_EVENT_BUDGET
                && pending_application_command.is_none()
                && application_commands_open
            {
                match application_receiver.try_recv() {
                    Ok(command) => pending_application_command = Some(command),
                    Err(mpsc::error::TryRecvError::Empty) => {
                        network_events_since_application = 0;
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        application_commands_open = false;
                        network_events_since_application = 0;
                    }
                }
            }
            tokio::select! {
            biased;
            zeroization = zeroization_receiver.recv() => {
                match zeroization {
                    Some(Ok(request)) => match prepare_live_zeroization(
                        &config.mission,
                        &identity,
                        &request,
                    ) {
                        Ok(plan) => {
                            application_admission.store(false, Ordering::Release);
                            live_zeroization = Some((request, plan));
                            break;
                        }
                        Err(error) => {
                            let response = format!(
                                "ASTER-ZEROIZE-LOCAL-ERROR {}",
                                format_receipt_field(&error.to_string())
                            );
                            if let Err(response_error) = request.respond(&response).await {
                                eprintln!(
                                    "ZEROIZE lifecycle=live preflight=failed response=failed error={}",
                                    format_receipt_field(&response_error.to_string())
                                );
                            }
                            eprintln!(
                                "ZEROIZE lifecycle=live preflight=failed error={} assurance=bounded-software",
                                format_receipt_field(&error.to_string())
                            );
                        }
                    },
                    Some(Err(error)) if error.is_integrity_failure() => {
                        let error = error.into_node_error();
                        eprintln!(
                            "ZEROIZE lifecycle=live control=failed error={}",
                            format_receipt_field(&error.to_string())
                        );
                        fatal_error = Some(error);
                        break;
                    }
                    Some(Err(error)) => {
                        let error = error.into_node_error();
                        eprintln!(
                            "ZEROIZE lifecycle=live request=denied error={}",
                            format_receipt_field(&error.to_string())
                        );
                    }
                    None => {
                        fatal_error = Some(NodeError::Configuration(
                            "local zeroization control task stopped".into(),
                        ));
                        break;
                    }
                }
            }
            _ = shutdown_receiver.recv() => break,
            _ = &mut stop => break,
            _ = ticker.tick(), if !application_tick_pending => {
                application_tick_pending = true;
            }
            _policy_read = policy_lock.clone().read_owned(),
                if application_tick_pending
                    && !application_tick_yield_required
                    && pending_application_command.is_none() => {
                application_tick_pending = false;
                let application_policy = match application.refresh_runtime_policy() {
                    Ok(policy) => policy,
                    Err(error) => {
                        fatal_error = Some(error);
                        break;
                    }
                };
                if let Some(application_policy) = application_policy
                    && let Err(error) = drive_sample_application(
                        config.application,
                        &store,
                        &application_policy,
                        application.runtime_verifier_mut(),
                        &mut application_cursor,
                        &mut initial_application_receipt_emitted,
                    )
                {
                    fatal_error = Some(error);
                    break;
                }
                // A continuously overdue ticker gets one operational turn
                // before it may run again. The bottom select arm clears this
                // after one scheduler turn when no lower-class work is ready.
                application_tick_yield_required = true;
                let peer_count = config.peers.len();
                if peer_count == 0 {
                    continue;
                }
                let start = next_outbound_peer % peer_count;
                next_outbound_peer = (start + 1) % peer_count;
                for offset in 0..peer_count {
                    if outbound.len() >= MAX_OUTBOUND_CONTACTS {
                        break;
                    }
                    let peer = &config.peers[(start + offset) % peer_count];
                    // Exactly one endpoint initiates each configured edge. This avoids
                    // symmetric connect/accept deadlocks without assigning topology meaning.
                    if local_id >= peer.carrier.id || !outbound_peers.insert(peer.carrier.id) {
                        continue;
                    }
                    let store = store.clone();
                    let endpoint = endpoint.clone();
                    let policy_lock = policy_lock.clone();
                    let peer = *peer;
                    let mission = config.mission.clone();
                    let task = outbound.spawn(async move {
                        (
                            peer,
                            sync_once_with_policy(
                                &store,
                                &endpoint,
                                mission,
                                peer,
                                policy_lock,
                            )
                            .await,
                        )
                    });
                    outbound_tasks.insert(task.id(), peer);
                }
            }
            lease = acquire_application_policy_lease(
                policy_lock.clone(),
                pending_application_command
                    .as_ref()
                    .is_some_and(SelectedEventCommand::mutates_selectors),
            ), if pending_application_command.is_some()
                && network_events_since_application >= NETWORK_EVENT_BUDGET => {
                let _lease = lease;
                let command = pending_application_command
                    .take()
                    .expect("application policy lease requires a pending command");
                execute_selected_event_command(
                    &mut application,
                    &store,
                    &selected_event_status,
                    &receipt,
                    command,
                );
                application_tick_yield_required = false;
                network_events_since_application = 0;
                application_commands_since_yield += 1;
                if application_commands_since_yield >= APPLICATION_COMMAND_BUDGET {
                    application_commands_since_yield = 0;
                    tokio::task::yield_now().await;
                }
            }
            accepted = accepted_receiver.recv(), if accept_task.is_some() && inbound.len() < MAX_INBOUND_CONTACTS => {
                application_tick_yield_required = false;
                let yield_for_network =
                    account_network_event(&mut network_events_since_application);
                match accepted {
                    Some(Ok(connection)) => {
                        let peer = connection.remote_id();
                        if !inbound_peers.insert(peer) {
                            connection.close();
                            receipt.contact_errors += 1;
                            eprintln!("CONTACT direction=in carrier_peer={peer} status=error error=duplicate_concurrent_carrier_contact");
                            if yield_for_network {
                                tokio::task::yield_now().await;
                            }
                            continue;
                        }
                        let store = store.clone();
                        let policy_lock = policy_lock.clone();
                        let mission = config.mission.clone();
                        let mission_peer = peer_missions
                            .get(&peer)
                            .copied()
                            .expect("accepted carrier came from the exact configured set");
                        let task = inbound.spawn(async move {
                            (
                                peer,
                                serve_connection(
                                    store,
                                    connection,
                                    mission,
                                    MissionPeerBinding::new(peer, mission_peer),
                                    policy_lock,
                                )
                                .await,
                            )
                        });
                        inbound_tasks.insert(task.id(), peer);
                    }
                    Some(Err(error)) => {
                        receipt.contact_errors += 1;
                        eprintln!("CONTACT direction=in status=error error={}", format_receipt_field(&error.to_string()));
                    }
                    None => {
                        // Disable this select arm permanently. A closed channel
                        // is immediately ready and would otherwise hot-spin and
                        // log-flood until shutdown.
                        if let Some(task) = accept_task.take() {
                            let _ = task.await;
                        }
                        receipt.contact_errors += 1;
                        eprintln!("CONTACT direction=in status=error error=accept_task_stopped");
                    }
                }
                if yield_for_network {
                    tokio::task::yield_now().await;
                }
            }
            completed = inbound.join_next_with_id(), if !inbound.is_empty() => {
                application_tick_yield_required = false;
                let yield_for_network =
                    account_network_event(&mut network_events_since_application);
                match completed {
                    Some(Ok((task, (peer, Ok(server_receipt))))) => {
                        inbound_tasks.remove(&task);
                        inbound_peers.remove(&peer);
                        if let Err(error) = selected_event_status.record(&server_receipt) {
                            fatal_error = Some(error);
                            break;
                        }
                        receipt.contacts += 1;
                        println!(
                            "CONTACT direction=in carrier_peer={} mission_peer={} rounds={} control_offered={} control_fetched={} control_retained={} control_duplicates={} control_activated={} control_remaining={} offered={} fetched={} inserted={} duplicates={} remaining={} handshake_frames={} handshake_bytes={} protected_frames={} protected_bytes={} mission_auth=hybrid-pq semantics=source-authenticated-event controls=source-authenticated-flash content_admission=capability-gated status={}",
                            peer,
                            format_node_id(server_receipt.mission_peer.expect("successful mission contact has peer identity")),
                            server_receipt.rounds,
                            server_receipt.controls_offered,
                            server_receipt.controls_fetched,
                            server_receipt.controls_retained,
                            server_receipt.control_duplicates,
                            server_receipt.controls_activated,
                            server_receipt.controls_remaining,
                            server_receipt.offered,
                            server_receipt.fetched,
                            server_receipt.inserted,
                            server_receipt.duplicates,
                            server_receipt.remaining,
                            server_receipt.handshake_frames,
                            server_receipt.handshake_bytes,
                            server_receipt.protected_frames,
                            server_receipt.protected_bytes,
                            contact_status(&server_receipt),
                        );
                    }
                    Some(Ok((task, (peer, Err(error))))) => {
                        inbound_tasks.remove(&task);
                        inbound_peers.remove(&peer);
                        if matches!(error, NodeError::Revoked(principal) if principal == config.mission.identity()) {
                            fatal_error = Some(error);
                            break;
                        }
                        receipt.contact_errors += 1;
                        eprintln!("CONTACT direction=in carrier_peer={peer} status=error error={}", format_receipt_field(&error.to_string()));
                    }
                    Some(Err(error)) => {
                        let peer = inbound_tasks.remove(&error.id());
                        if let Some(peer) = peer {
                            inbound_peers.remove(&peer);
                        }
                        receipt.contact_errors += 1;
                        eprintln!("CONTACT direction=in carrier_peer={} status=error error={}", peer.map_or_else(|| "unknown".into(), |peer| peer.to_string()), format_receipt_field(&format!("task failed: {error}")));
                    }
                    None => {}
                }
                if yield_for_network {
                    tokio::task::yield_now().await;
                }
            }
            completed = outbound.join_next_with_id(), if !outbound.is_empty() => {
                application_tick_yield_required = false;
                let yield_for_network =
                    account_network_event(&mut network_events_since_application);
                match completed {
                    Some(Ok((task, (peer, Ok(peer_receipt))))) => {
                        outbound_tasks.remove(&task);
                        outbound_peers.remove(&peer.carrier.id);
                        if let Err(error) = selected_event_status.record(&peer_receipt) {
                            fatal_error = Some(error);
                            break;
                        }
                        receipt.contacts += 1;
                        println!(
                            "CONTACT direction=out carrier_peer={} mission_peer={} rounds={} control_offered={} control_fetched={} control_retained={} control_duplicates={} control_activated={} control_remaining={} offered={} fetched={} inserted={} duplicates={} remaining={} handshake_frames={} handshake_bytes={} protected_frames={} protected_bytes={} mission_auth=hybrid-pq semantics=source-authenticated-event controls=source-authenticated-flash content_admission=capability-gated status={}",
                            peer.carrier.id,
                            format_node_id(peer_receipt.mission_peer.expect("successful mission contact has peer identity")),
                            peer_receipt.rounds,
                            peer_receipt.controls_offered,
                            peer_receipt.controls_fetched,
                            peer_receipt.controls_retained,
                            peer_receipt.control_duplicates,
                            peer_receipt.controls_activated,
                            peer_receipt.controls_remaining,
                            peer_receipt.offered,
                            peer_receipt.fetched,
                            peer_receipt.inserted,
                            peer_receipt.duplicates,
                            peer_receipt.remaining,
                            peer_receipt.handshake_frames,
                            peer_receipt.handshake_bytes,
                            peer_receipt.protected_frames,
                            peer_receipt.protected_bytes,
                            contact_status(&peer_receipt),
                        );
                    }
                    Some(Ok((task, (peer, Err(error))))) => {
                        outbound_tasks.remove(&task);
                        outbound_peers.remove(&peer.carrier.id);
                        if matches!(error, NodeError::Revoked(principal) if principal == config.mission.identity()) {
                            fatal_error = Some(error);
                            break;
                        }
                        receipt.contact_errors += 1;
                        eprintln!("CONTACT direction=out carrier_peer={} expected_mission_peer={} status=error error={}", peer.carrier.id, format_node_id(peer.mission), format_receipt_field(&error.to_string()));
                    }
                    Some(Err(error)) => {
                        let peer = outbound_tasks.remove(&error.id());
                        if let Some(peer) = peer {
                            outbound_peers.remove(&peer.carrier.id);
                        }
                        receipt.contact_errors += 1;
                        eprintln!("CONTACT direction=out carrier_peer={} status=error error={}", peer.map_or_else(|| "unknown".into(), |peer| peer.carrier.id.to_string()), format_receipt_field(&format!("task failed: {error}")));
                    }
                    None => {}
                }
                if yield_for_network {
                    tokio::task::yield_now().await;
                }
            }
            command = application_receiver.recv(),
                if application_commands_open
                    && pending_application_command.is_none()
                    && network_events_since_application < NETWORK_EVENT_BUDGET => {
                match command {
                    Some(command) => pending_application_command = Some(command),
                    None => application_commands_open = false,
                }
            }
            lease = acquire_application_policy_lease(
                policy_lock.clone(),
                pending_application_command
                    .as_ref()
                    .is_some_and(SelectedEventCommand::mutates_selectors),
            ), if pending_application_command.is_some()
                && network_events_since_application < NETWORK_EVENT_BUDGET => {
                let _lease = lease;
                let command = pending_application_command
                    .take()
                    .expect("application policy lease requires a pending command");
                execute_selected_event_command(
                    &mut application,
                    &store,
                    &selected_event_status,
                    &receipt,
                    command,
                );
                application_tick_yield_required = false;
                network_events_since_application = 0;
                application_commands_since_yield += 1;
                if application_commands_since_yield >= APPLICATION_COMMAND_BUDGET {
                    application_commands_since_yield = 0;
                    tokio::task::yield_now().await;
                }
            }
            _ = tokio::task::yield_now(),
                if application_tick_pending && application_tick_yield_required => {
                application_tick_yield_required = false;
            }
            }
        }
    }

    application_admission.store(false, Ordering::Release);
    application_receiver.close();
    if let Some(command) = pending_application_command.take() {
        command.reject();
    }
    while let Ok(command) = application_receiver.try_recv() {
        command.reject();
    }
    if let Some(task) = zeroization_task.take() {
        task.abort();
        let _ = task.await;
    }
    drop(zeroization_receiver);
    if let Some(accept_task) = accept_task {
        accept_task.abort();
        let _ = accept_task.await;
    }
    drop(accepted_receiver);
    inbound.shutdown().await;
    outbound.shutdown().await;
    endpoint.close().await;
    drop(endpoint);
    drop(application);
    if let Some(error) = fatal_error {
        return Err(error);
    }
    if let Some((request, plan)) = live_zeroization {
        let mission_path = plan.mission.target().path().to_path_buf();
        let result = finish_live_zeroization(store, plan, &config.state, &mission_path);
        match result {
            Ok(completed) => {
                receipt.items = completed.preserved.items;
                receipt.acceptance_markers = completed.preserved.acceptance_markers;
                receipt.events = completed.preserved.events;
                receipt.event_acceptance_markers = completed.preserved.event_acceptance_markers;
                receipt.route_cached_events = completed.preserved.route_cached_events;
                receipt.controls = completed.preserved.controls;
                receipt.applied_controls = completed.preserved.applied_controls;
                receipt.pending_controls = completed.preserved.pending_controls;
                receipt.control_highwater = completed.preserved.control_highwater;
                request.respond("ASTER-ZEROIZE-LOCAL-OK").await?;
                println!(
                    "STOP lifecycle=zeroized sync_status=terminal-lockout carrier_id={} mission_id={} contacts={} contact_errors={} opaque_items={} opaque_acceptance_markers={} events={} event_acceptance_markers={} route_cached_events={} controls={} applied_controls={} pending_controls={} control_highwater={} mission_auth=hybrid-pq provisioning=unprotected-reference assurance=bounded-software physical_sanitization=not-claimed",
                    local_id,
                    format_node_id(config.mission.identity()),
                    receipt.contacts,
                    receipt.contact_errors,
                    receipt.items,
                    receipt.acceptance_markers,
                    receipt.events,
                    receipt.event_acceptance_markers,
                    receipt.route_cached_events,
                    receipt.controls,
                    receipt.applied_controls,
                    receipt.pending_controls,
                    receipt.control_highwater,
                );
                return Ok(receipt);
            }
            Err(error) => {
                let response = format!(
                    "ASTER-ZEROIZE-LOCAL-ERROR {}",
                    format_receipt_field(&error.to_string())
                );
                let _ = request.respond(&response).await;
                return Err(error);
            }
        }
    }
    let stats = store.stats()?;
    let event_stats = store.event_stats()?;
    let control_stats = store.control_stats()?;
    receipt.items = stats.items;
    receipt.acceptance_markers = stats.acceptance_markers;
    receipt.events = event_stats.events;
    receipt.event_acceptance_markers = event_stats.acceptance_markers;
    receipt.route_cached_events = event_stats.route_cached;
    receipt.controls = control_stats.controls;
    receipt.applied_controls = control_stats.applied;
    receipt.pending_controls = control_stats.pending;
    receipt.control_highwater = control_stats.head_sequence;
    let sync_status = if receipt.contacts == 0 {
        "no_successful_contact"
    } else {
        "contacts_observed"
    };
    println!(
        "STOP lifecycle=complete sync_status={} carrier_id={} mission_id={} contacts={} contact_errors={} opaque_items={} opaque_acceptance_markers={} events={} event_acceptance_markers={} route_cached_events={} controls={} applied_controls={} pending_controls={} control_highwater={} mission_auth=hybrid-pq provisioning=unprotected-reference semantics=source-authenticated-event controls_semantics=source-authenticated-flash",
        sync_status,
        local_id,
        format_node_id(config.mission.identity()),
        receipt.contacts,
        receipt.contact_errors,
        receipt.items,
        receipt.acceptance_markers,
        receipt.events,
        receipt.event_acceptance_markers,
        receipt.route_cached_events,
        receipt.controls,
        receipt.applied_controls,
        receipt.pending_controls,
        receipt.control_highwater,
    );
    Ok(receipt)
}

// Direct one-shot synchronization is test-only. Production contacts must be
// created by `run_node`, which owns the single shared policy coordinator for
// every inbound, outbound, control, and application task using this Store.
#[cfg(test)]
async fn sync_once(
    store: &Store,
    endpoint: &Endpoint,
    mission: UnprotectedReferenceMission,
    peer: MissionExpectedPeer,
) -> Result<PeerReceipt, NodeError> {
    Ok(
        sync_once_with_policy(store, endpoint, mission, peer, Arc::new(RwLock::new(())))
            .await?
            .receipt,
    )
}

async fn sync_once_with_policy(
    store: &Store,
    endpoint: &Endpoint,
    mission: UnprotectedReferenceMission,
    peer: MissionExpectedPeer,
    policy_lock: Arc<RwLock<()>>,
) -> Result<CompletedPeerContact, NodeError> {
    timeout(
        CONTACT_DEADLINE,
        sync_session(store, endpoint, mission, peer, policy_lock),
    )
    .await
    .map_err(|_| NodeError::Protocol("contact exceeded its total deadline".into()))?
}

async fn sync_session(
    store: &Store,
    endpoint: &Endpoint,
    credentials: UnprotectedReferenceMission,
    peer: MissionExpectedPeer,
    policy_lock: Arc<RwLock<()>>,
) -> Result<CompletedPeerContact, NodeError> {
    let connection = endpoint.connect(peer.carrier).await?;
    let result =
        sync_authenticated_session(store, &connection, credentials, peer, policy_lock).await;
    if result.is_err() {
        connection.close();
    }
    result
}

async fn sync_control_lane(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    verifier: &mut ReferenceEnvelopeSealer,
    receipt: &mut PeerReceipt,
) -> Result<(), NodeError> {
    let local = verifier.identity();
    let peer = mission.peer().mission_id();
    let mut verifier_head = store.control_head()?;
    ensure_control_lane_state(store, local, peer, verifier_head)?;
    let inventory = store.control_inventory()?.reconciliation_snapshot();
    let limits = ReconciliationLimits::default();
    let mut initiator = Initiator::new(&inventory, limits)?;
    let mut query = initiator.initiate()?;
    let difference = loop {
        ensure_control_lane_state(store, local, peer, verifier_head)?;
        let response = request_mission_frame(
            connection,
            mission,
            Frame::ControlInventoryQuery(query),
            receipt,
        )
        .await?;
        let Frame::ControlInventoryReply(response) = response else {
            return Err(NodeError::Protocol(
                "control inventory query received a different response".into(),
            ));
        };
        match initiator.reconcile_response(&response)? {
            InitiatorStep::Continue(next) => query = next,
            InitiatorStep::Complete(difference) => {
                break ControlDifference::from_reconciliation(difference);
            }
        }
    };
    let first_rounds = initiator.rounds();
    ensure_control_lane_state(store, local, peer, verifier_head)?;
    if request_mission_frame(
        connection,
        mission,
        Frame::ControlInventoryComplete,
        receipt,
    )
    .await?
        != Frame::ControlInventoryCompleteAck
    {
        return Err(NodeError::Protocol(
            "control inventory completion acknowledgement differs".into(),
        ));
    }

    let mut reverse = Responder::new(&inventory, limits)?;
    loop {
        ensure_control_lane_state(store, local, peer, verifier_head)?;
        let wire_budget = exchange_wire_budget(receipt)?;
        let (complete, request_bytes, response_bytes) = respond_mission_frame(
            connection,
            mission,
            wire_budget,
            |frame, _request_wire_len| {
                ensure_control_lane_state(store, local, peer, verifier_head)?;
                match frame {
                    Frame::ControlDifferenceQuery(query) => Ok((
                        Frame::ControlDifferenceReply(reverse.reconcile_query(&query)?),
                        false,
                    )),
                    Frame::ControlDifferenceBound if reverse.rounds() > 0 => {
                        Ok((Frame::ControlDifferenceBoundAck, true))
                    }
                    Frame::ControlDifferenceBound => Err(NodeError::Protocol(
                        "control difference bound preceded reverse reconciliation".into(),
                    )),
                    _ => Err(NodeError::Protocol(
                        "control reverse reconciliation received an out-of-phase frame".into(),
                    )),
                }
            },
        )
        .await?;
        account(receipt, request_bytes, response_bytes)?;
        if complete {
            break;
        }
    }
    receipt.rounds = receipt
        .rounds
        .checked_add(first_rounds)
        .and_then(|rounds| rounds.checked_add(reverse.rounds()))
        .ok_or_else(|| NodeError::Protocol("combined round count overflow".into()))?;

    let (local_limit, remote_limit) =
        transfer_limits(difference.local_only.len(), difference.remote_only.len());
    let difference_items = difference
        .local_only
        .len()
        .checked_add(difference.remote_only.len())
        .ok_or_else(|| NodeError::Protocol("control difference count overflow".into()))?;
    receipt.controls_remaining = difference_items.saturating_sub(
        local_limit
            .checked_add(remote_limit)
            .ok_or_else(|| NodeError::Protocol("control schedule count overflow".into()))?,
    );
    for id in difference.local_only.iter().take(local_limit) {
        ensure_control_lane_state(store, local, peer, verifier_head)?;
        let bytes = load_verified_control(store, verifier, *id)?;
        let response = request_mission_frame(
            connection,
            mission,
            Frame::ControlOffer { id: *id, bytes },
            receipt,
        )
        .await?;
        let Frame::ControlApplyResult {
            id: applied,
            retained,
        } = response
        else {
            return Err(NodeError::Protocol(
                "control offer acknowledgement differs".into(),
            ));
        };
        if applied != *id {
            return Err(NodeError::Protocol(
                "control offer acknowledgement identifies another transfer".into(),
            ));
        }
        receipt.controls_offered += 1;
        if !retained {
            receipt.control_duplicates += 1;
        }
    }
    for id in difference.remote_only.iter().take(remote_limit) {
        ensure_control_lane_state(store, local, peer, verifier_head)?;
        let response =
            request_mission_frame(connection, mission, Frame::ControlFetch(*id), receipt).await?;
        let Frame::ControlObject {
            id: received,
            bytes,
        } = response
        else {
            return Err(NodeError::Protocol("control fetch response differs".into()));
        };
        if received != *id || bytes.len() > MAX_OBJECT_BYTES {
            return Err(NodeError::Protocol(
                "fetched control transfer identity or bound differs".into(),
            ));
        }
        let accepted = accept_received_control(store, verifier, peer, received, &bytes)?;
        if let Some(head) = accepted.activated_head {
            verifier_head = Some(head);
        }
        receipt.controls_fetched += 1;
        receipt.controls_activated = receipt
            .controls_activated
            .checked_add(accepted.activated)
            .ok_or_else(|| NodeError::Protocol("control activation count overflow".into()))?;
        if accepted.retained {
            receipt.controls_retained += 1;
        } else {
            receipt.control_duplicates += 1;
        }
        ensure_control_lane_state(store, local, peer, verifier_head)?;
    }
    ensure_control_lane_state(store, local, peer, verifier_head)?;
    if request_mission_frame(connection, mission, Frame::ControlFinish, receipt).await?
        != Frame::ControlFinished
    {
        return Err(NodeError::Protocol(
            "control finish acknowledgement differs".into(),
        ));
    }
    Ok(())
}

async fn sync_event_interests(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    event_guard: &EventLaneGuard,
    receipt: &mut PeerReceipt,
) -> Result<(EventInterest, EventInterest), NodeError> {
    event_guard.check(store)?;
    let local_interest = event_guard.interest()?;
    let response = request_mission_frame(
        connection,
        mission,
        Frame::EventInterest(local_interest.clone()),
        receipt,
    )
    .await?;
    let Frame::EventInterestReply(peer_interest) = response else {
        return Err(NodeError::Protocol(
            "protected Event interest request received another response".into(),
        ));
    };
    event_guard.check(store)?;
    Ok((local_interest, peer_interest))
}

async fn sync_event_reconciliation_lane(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    event_verifier: &mut ReferenceEnvelopeSealer,
    lane: DirectedEventLane<'_>,
    receipt: &mut PeerReceipt,
) -> Result<EventDifference, NodeError> {
    let DirectedEventLane {
        guard: event_guard,
        receiver_interest,
        direction,
    } = lane;
    event_guard.check(store)?;
    let inventory = match direction {
        EventDirection::ToSessionResponder => transfer_inventory_for_peer(
            store,
            event_guard.policy(),
            event_verifier,
            mission.peer().mission_id(),
            mission.peer_route_grant_commitments(),
            receiver_interest,
        )?,
        EventDirection::ToSessionInitiator => transfer_inventory_for_receiver(
            store,
            event_guard.replication_policy(),
            event_verifier,
            receiver_interest,
        )?,
    };
    let limits = ReconciliationLimits::default();
    let mut initiator = Initiator::new(&inventory, limits)?;
    let mut query = initiator.initiate()?;
    let difference = loop {
        event_guard.check(store)?;
        let response = request_mission_frame(
            connection,
            mission,
            Frame::InventoryQuery {
                direction,
                bytes: query,
            },
            receipt,
        )
        .await?;
        let Frame::InventoryReply {
            direction: response_direction,
            bytes: response,
        } = response
        else {
            return Err(NodeError::Protocol(
                "directional inventory query received another response".into(),
            ));
        };
        if response_direction != direction {
            return Err(NodeError::Protocol(
                "inventory reply crossed Event reconciliation lanes".into(),
            ));
        }
        match initiator.reconcile_response(&response)? {
            InitiatorStep::Continue(next) => query = next,
            InitiatorStep::Complete(difference) => {
                break EventDifference::from_reconciliation(difference);
            }
        }
    };
    let first_rounds = initiator.rounds();
    event_guard.check(store)?;
    if request_mission_frame(
        connection,
        mission,
        Frame::InventoryComplete { direction },
        receipt,
    )
    .await?
        != (Frame::InventoryCompleteAck { direction })
    {
        return Err(NodeError::Protocol(
            "directional inventory completion acknowledgement differs".into(),
        ));
    }

    let mut reverse = Responder::new(&inventory, limits)?;
    loop {
        event_guard.check(store)?;
        let wire_budget = exchange_wire_budget(receipt)?;
        let (complete, request_bytes, response_bytes) = respond_mission_frame(
            connection,
            mission,
            wire_budget,
            |frame, _request_wire_len| match frame {
                Frame::DifferenceQuery {
                    direction: request_direction,
                    bytes: query,
                } if request_direction == direction => {
                    event_guard.check(store)?;
                    Ok((
                        Frame::DifferenceReply {
                            direction,
                            bytes: reverse.reconcile_query(&query)?,
                        },
                        false,
                    ))
                }
                Frame::DifferenceBound {
                    direction: request_direction,
                } if request_direction == direction && reverse.rounds() > 0 => {
                    event_guard.check(store)?;
                    Ok((Frame::DifferenceBoundAck { direction }, true))
                }
                Frame::DifferenceBound {
                    direction: request_direction,
                } if request_direction == direction => Err(NodeError::Protocol(
                    "difference bound preceded directional reverse reconciliation".into(),
                )),
                _ => Err(NodeError::Protocol(
                    "reverse reconciliation crossed Event lanes or phases".into(),
                )),
            },
        )
        .await?;
        account(receipt, request_bytes, response_bytes)?;
        if complete {
            break;
        }
    }
    receipt.rounds = receipt
        .rounds
        .checked_add(first_rounds)
        .and_then(|rounds| rounds.checked_add(reverse.rounds()))
        .ok_or_else(|| NodeError::Protocol("combined round count overflow".into()))?;
    Ok(difference)
}

fn event_transfer_capacity(receipt: &PeerReceipt) -> Result<usize, NodeError> {
    let transferred = receipt
        .offered
        .checked_add(receipt.fetched)
        .ok_or_else(|| NodeError::Protocol("contact item count overflow".into()))?;
    MAX_CONTACT_ITEMS
        .checked_sub(transferred)
        .ok_or_else(|| NodeError::Protocol("contact item count exceeds its bound".into()))
}

fn add_unscheduled_events(receipt: &mut PeerReceipt, remaining: usize) -> Result<(), NodeError> {
    receipt.remaining = receipt
        .remaining
        .checked_add(remaining)
        .ok_or_else(|| NodeError::Protocol("remaining Event count overflow".into()))?;
    Ok(())
}

async fn sync_event_transfer_lane(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    event_verifier: &mut ReferenceEnvelopeSealer,
    lane: DirectedEventLane<'_>,
    difference: &EventDifference,
    receipt: &mut PeerReceipt,
) -> Result<(), NodeError> {
    let DirectedEventLane {
        guard: event_guard,
        receiver_interest,
        direction,
    } = lane;
    let authenticated_peer = mission.peer().mission_id();
    let peer_route_commitments = mission.peer_route_grant_commitments().to_vec();
    let capacity = event_transfer_capacity(receipt)?;
    match direction {
        EventDirection::ToSessionResponder => {
            let limit = difference.local_only.len().min(capacity);
            add_unscheduled_events(receipt, difference.local_only.len() - limit)?;
            for id in difference.local_only.iter().take(limit) {
                event_guard.check(store)?;
                let bytes = load_verified_transfer_for_peer(
                    store,
                    event_guard.policy(),
                    event_verifier,
                    *id,
                    authenticated_peer,
                    &peer_route_commitments,
                    receiver_interest,
                )?;
                let response = request_mission_frame(
                    connection,
                    mission,
                    Frame::Offer {
                        direction,
                        id: *id,
                        bytes,
                    },
                    receipt,
                )
                .await?;
                let Frame::ApplyResult {
                    direction: response_direction,
                    id: applied,
                    inserted,
                } = response
                else {
                    return Err(NodeError::Protocol(
                        "directional offer acknowledgement differs".into(),
                    ));
                };
                if response_direction != direction || applied != *id {
                    return Err(NodeError::Protocol(
                        "offer acknowledgement crossed Event lanes or identifies another item"
                            .into(),
                    ));
                }
                receipt.offered += 1;
                if !inserted {
                    receipt.duplicates += 1;
                }
            }
        }
        EventDirection::ToSessionInitiator => {
            let limit = difference.remote_only.len().min(capacity);
            add_unscheduled_events(receipt, difference.remote_only.len() - limit)?;
            for id in difference.remote_only.iter().take(limit) {
                event_guard.check(store)?;
                let response = request_mission_frame(
                    connection,
                    mission,
                    Frame::Fetch { direction, id: *id },
                    receipt,
                )
                .await?;
                let Frame::Object {
                    direction: response_direction,
                    id: received,
                    bytes,
                } = response
                else {
                    return Err(NodeError::Protocol(
                        "directional fetch response differs".into(),
                    ));
                };
                if response_direction != direction
                    || received != *id
                    || bytes.len() > MAX_OBJECT_BYTES
                {
                    return Err(NodeError::Protocol(
                        "fetched Event crossed lanes or its identity or bound differs".into(),
                    ));
                }
                event_guard.check(store)?;
                if accept_received_transfer(
                    store,
                    event_verifier,
                    EventReceiveAuthority {
                        peer: authenticated_peer,
                        peer_route_commitments: &peer_route_commitments,
                        receiver_interest,
                        local_replication_policy: event_guard.replication_policy(),
                    },
                    received,
                    &bytes,
                )? {
                    receipt.inserted += 1;
                } else {
                    receipt.duplicates += 1;
                }
                receipt.fetched += 1;
                event_guard.check(store)?;
            }
        }
    }
    event_guard.check(store)?;
    if request_mission_frame(connection, mission, Frame::Finish { direction }, receipt).await?
        != (Frame::Finished { direction })
    {
        return Err(NodeError::Protocol(
            "directional finish acknowledgement differs".into(),
        ));
    }
    Ok(())
}

async fn sync_authenticated_session(
    store: &Store,
    connection: &aster_iroh::Connection,
    credentials: UnprotectedReferenceMission,
    peer: MissionExpectedPeer,
    policy_lock: Arc<RwLock<()>>,
) -> Result<CompletedPeerContact, NodeError> {
    // Mission authentication is deliberately first. No inventory bytes or
    // object operation can reach the carrier before this returns a session.
    let (mut mission, handshake) = initiate_over_iroh_metered(
        connection,
        credentials.fresh_bundle()?,
        MissionPeerBinding::new(peer.carrier.id, peer.mission),
    )
    .await?;
    let mut receipt = authenticated_receipt(connection, &mission, handshake)?;

    // Replay and reconcile mission controls under the exclusive policy lease.
    // The verifier must not predate this lease: another contact may have
    // advanced the durable head after mission authentication completed.
    let policy_write = policy_lock.clone().write_owned().await;
    let mut control_verifier = open_replayed_verifier(store, &credentials)?;
    ensure_contact_principals_active(
        store,
        control_verifier.identity(),
        mission.peer().mission_id(),
    )?;
    sync_control_lane(
        store,
        connection,
        &mut mission,
        &mut control_verifier,
        &mut receipt,
    )
    .await?;
    drop(policy_write);

    // Switching from write to read is intentionally followed by a fresh full
    // replay while the read lease is held. This closes both lock-transition
    // windows: the Event verifier and its provider grants correspond exactly
    // to the head protected for the complete Event lane.
    let event_lease = policy_lock.read_owned().await;
    let mut event_verifier = open_replayed_verifier(store, &credentials)?;
    let event_guard = EventLaneGuard::capture(
        event_lease,
        store,
        event_verifier.identity(),
        mission.peer().mission_id(),
        receipt.controls_remaining,
    )?;
    let (local_interest, peer_interest) =
        sync_event_interests(store, connection, &mut mission, &event_guard, &mut receipt).await?;

    // Each receiver's protected interest defines a separate reconciliation
    // universe. Both endpoints independently derive each exact one-way plan.
    let to_responder_lane = DirectedEventLane {
        guard: &event_guard,
        receiver_interest: &peer_interest,
        direction: EventDirection::ToSessionResponder,
    };
    let to_responder = sync_event_reconciliation_lane(
        store,
        connection,
        &mut mission,
        &mut event_verifier,
        to_responder_lane,
        &mut receipt,
    )
    .await?;
    sync_event_transfer_lane(
        store,
        connection,
        &mut mission,
        &mut event_verifier,
        to_responder_lane,
        &to_responder,
        &mut receipt,
    )
    .await?;

    let to_initiator_lane = DirectedEventLane {
        guard: &event_guard,
        receiver_interest: &local_interest,
        direction: EventDirection::ToSessionInitiator,
    };
    let to_initiator = sync_event_reconciliation_lane(
        store,
        connection,
        &mut mission,
        &mut event_verifier,
        to_initiator_lane,
        &mut receipt,
    )
    .await?;
    sync_event_transfer_lane(
        store,
        connection,
        &mut mission,
        &mut event_verifier,
        to_initiator_lane,
        &to_initiator,
        &mut receipt,
    )
    .await?;
    event_guard.check(store)?;
    let event_policy = ContactEventPolicy::capture(event_guard.replication_policy());
    connection.close();
    Ok(CompletedPeerContact {
        receipt,
        event_policy,
    })
}

async fn serve_connection(
    store: Arc<Store>,
    connection: aster_iroh::Connection,
    credentials: UnprotectedReferenceMission,
    peer: MissionPeerBinding,
    policy_lock: Arc<RwLock<()>>,
) -> Result<CompletedPeerContact, NodeError> {
    let close = connection.clone();
    match timeout(
        CONTACT_DEADLINE,
        serve_session(store, connection, credentials, peer, policy_lock),
    )
    .await
    {
        Ok(Ok(receipt)) => Ok(receipt),
        Ok(Err(error)) => {
            close.close();
            Err(error)
        }
        Err(_) => {
            close.close();
            Err(NodeError::Protocol(
                "inbound contact exceeded its total deadline".into(),
            ))
        }
    }
}

async fn serve_control_lane(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    verifier: &mut ReferenceEnvelopeSealer,
    receipt: &mut PeerReceipt,
) -> Result<(), NodeError> {
    let local = verifier.identity();
    let peer = mission.peer().mission_id();
    let mut verifier_head = store.control_head()?;
    ensure_control_lane_state(store, local, peer, verifier_head)?;
    let inventory = store.control_inventory()?.reconciliation_snapshot();
    let limits = ReconciliationLimits::default();
    let mut responder = Responder::new(&inventory, limits)?;

    loop {
        ensure_control_lane_state(store, local, peer, verifier_head)?;
        let wire_budget = exchange_wire_budget(receipt)?;
        let (complete, request_bytes, response_bytes) = respond_mission_frame(
            connection,
            mission,
            wire_budget,
            |frame, _request_wire_len| {
                ensure_control_lane_state(store, local, peer, verifier_head)?;
                match frame {
                    Frame::ControlInventoryQuery(query) => Ok((
                        Frame::ControlInventoryReply(responder.reconcile_query(&query)?),
                        false,
                    )),
                    Frame::ControlInventoryComplete if responder.rounds() > 0 => {
                        Ok((Frame::ControlInventoryCompleteAck, true))
                    }
                    Frame::ControlInventoryComplete => Err(NodeError::Protocol(
                        "control inventory completion preceded reconciliation".into(),
                    )),
                    _ => Err(NodeError::Protocol(
                        "control inventory reconciliation received an out-of-phase frame".into(),
                    )),
                }
            },
        )
        .await?;
        account(receipt, request_bytes, response_bytes)?;
        if complete {
            break;
        }
    }

    let mut reverse = Initiator::new(&inventory, limits)?;
    let mut query = reverse.initiate()?;
    let difference = loop {
        ensure_control_lane_state(store, local, peer, verifier_head)?;
        let response = request_mission_frame(
            connection,
            mission,
            Frame::ControlDifferenceQuery(query),
            receipt,
        )
        .await?;
        let Frame::ControlDifferenceReply(response) = response else {
            return Err(NodeError::Protocol(
                "control reverse difference query received another response".into(),
            ));
        };
        match reverse.reconcile_response(&response)? {
            InitiatorStep::Continue(next) => query = next,
            InitiatorStep::Complete(difference) => {
                break ControlDifference::from_reconciliation(difference);
            }
        }
    };
    ensure_control_lane_state(store, local, peer, verifier_head)?;
    if request_mission_frame(connection, mission, Frame::ControlDifferenceBound, receipt).await?
        != Frame::ControlDifferenceBoundAck
    {
        return Err(NodeError::Protocol(
            "control difference-bound acknowledgement differs".into(),
        ));
    }
    receipt.rounds = receipt
        .rounds
        .checked_add(responder.rounds())
        .and_then(|rounds| rounds.checked_add(reverse.rounds()))
        .ok_or_else(|| NodeError::Protocol("combined round count overflow".into()))?;

    let mut authorization = ControlTransferAuthorization::for_peer(&difference);
    receipt.controls_remaining = authorization.remaining;
    loop {
        ensure_control_lane_state(store, local, peer, verifier_head)?;
        let wire_budget = exchange_wire_budget(receipt)?;
        let (complete, request_bytes, response_bytes) = respond_mission_frame(
            connection,
            mission,
            wire_budget,
            |frame, request_wire_len| {
                ensure_control_lane_state(store, local, peer, verifier_head)?;
                match frame {
                    Frame::ControlFetch(id) => {
                        authorize_transfer_item(
                            authorization.fetches_by_peer.remove(&id),
                            receipt,
                            "control fetch",
                        )?;
                        let bytes = load_verified_control(store, verifier, id)?;
                        receipt.controls_offered += 1;
                        Ok((Frame::ControlObject { id, bytes }, false))
                    }
                    Frame::ControlOffer { id, bytes } => {
                        authorize_transfer_item(
                            authorization.offers_from_peer.remove(&id),
                            receipt,
                            "control offer",
                        )?;
                        if bytes.len() > MAX_OBJECT_BYTES {
                            return Err(NodeError::Protocol(format!(
                                "offered control exceeds {MAX_OBJECT_BYTES} bytes"
                            )));
                        }
                        check_account(receipt, request_wire_len, 4_096)?;
                        let accepted = accept_received_control(store, verifier, peer, id, &bytes)?;
                        if let Some(head) = accepted.activated_head {
                            verifier_head = Some(head);
                        }
                        receipt.controls_fetched += 1;
                        receipt.controls_activated = receipt
                            .controls_activated
                            .checked_add(accepted.activated)
                            .ok_or_else(|| {
                                NodeError::Protocol("control activation count overflow".into())
                            })?;
                        if accepted.retained {
                            receipt.controls_retained += 1;
                        } else {
                            receipt.control_duplicates += 1;
                        }
                        ensure_control_lane_state(store, local, peer, verifier_head)?;
                        Ok((
                            Frame::ControlApplyResult {
                                id,
                                retained: accepted.retained,
                            },
                            false,
                        ))
                    }
                    Frame::ControlFinish if authorization.is_consumed() => {
                        Ok((Frame::ControlFinished, true))
                    }
                    Frame::ControlFinish => Err(NodeError::Protocol(
                        "control finish preceded authorized transfer completion".into(),
                    )),
                    _ => Err(NodeError::Protocol(
                        "control transfer phase received an unauthorized frame".into(),
                    )),
                }
            },
        )
        .await?;
        account(receipt, request_bytes, response_bytes)?;
        if complete {
            break;
        }
    }
    Ok(())
}

async fn serve_event_interests(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    event_guard: &EventLaneGuard,
    receipt: &mut PeerReceipt,
) -> Result<(EventInterest, EventInterest), NodeError> {
    event_guard.check(store)?;
    let local_interest = event_guard.interest()?;
    let mut peer_interest = None;
    let wire_budget = exchange_wire_budget(receipt)?;
    let (complete, request_bytes, response_bytes) = respond_mission_frame(
        connection,
        mission,
        wire_budget,
        |frame, _request_wire_len| match frame {
            Frame::EventInterest(interest) => {
                peer_interest = Some(interest);
                Ok((Frame::EventInterestReply(local_interest.clone()), true))
            }
            _ => Err(NodeError::Protocol(
                "Event inventory preceded the protected interest request".into(),
            )),
        },
    )
    .await?;
    account(receipt, request_bytes, response_bytes)?;
    if !complete {
        return Err(NodeError::Protocol(
            "protected Event interest exchange did not complete".into(),
        ));
    }
    event_guard.check(store)?;
    Ok((
        local_interest,
        peer_interest.ok_or_else(|| {
            NodeError::Protocol("protected Event interest request disappeared".into())
        })?,
    ))
}

async fn serve_event_reconciliation_lane(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    event_verifier: &mut ReferenceEnvelopeSealer,
    lane: DirectedEventLane<'_>,
    receipt: &mut PeerReceipt,
) -> Result<EventDifference, NodeError> {
    let DirectedEventLane {
        guard: event_guard,
        receiver_interest,
        direction,
    } = lane;
    event_guard.check(store)?;
    let inventory = match direction {
        EventDirection::ToSessionResponder => transfer_inventory_for_receiver(
            store,
            event_guard.replication_policy(),
            event_verifier,
            receiver_interest,
        )?,
        EventDirection::ToSessionInitiator => transfer_inventory_for_peer(
            store,
            event_guard.policy(),
            event_verifier,
            mission.peer().mission_id(),
            mission.peer_route_grant_commitments(),
            receiver_interest,
        )?,
    };
    let limits = ReconciliationLimits::default();
    let mut responder = Responder::new(&inventory, limits)?;
    loop {
        event_guard.check(store)?;
        let wire_budget = exchange_wire_budget(receipt)?;
        let (complete, request_bytes, response_bytes) = respond_mission_frame(
            connection,
            mission,
            wire_budget,
            |frame, _request_wire_len| match frame {
                Frame::InventoryQuery {
                    direction: request_direction,
                    bytes: query,
                } if request_direction == direction => {
                    event_guard.check(store)?;
                    Ok((
                        Frame::InventoryReply {
                            direction,
                            bytes: responder.reconcile_query(&query)?,
                        },
                        false,
                    ))
                }
                Frame::InventoryComplete {
                    direction: request_direction,
                } if request_direction == direction && responder.rounds() > 0 => {
                    event_guard.check(store)?;
                    Ok((Frame::InventoryCompleteAck { direction }, true))
                }
                Frame::InventoryComplete {
                    direction: request_direction,
                } if request_direction == direction => Err(NodeError::Protocol(
                    "inventory completion preceded directional reconciliation".into(),
                )),
                _ => Err(NodeError::Protocol(
                    "inventory reconciliation crossed Event lanes or phases".into(),
                )),
            },
        )
        .await?;
        account(receipt, request_bytes, response_bytes)?;
        if complete {
            break;
        }
    }

    let mut reverse = Initiator::new(&inventory, limits)?;
    let mut query = reverse.initiate()?;
    let difference = loop {
        event_guard.check(store)?;
        let response = request_mission_frame(
            connection,
            mission,
            Frame::DifferenceQuery {
                direction,
                bytes: query,
            },
            receipt,
        )
        .await?;
        let Frame::DifferenceReply {
            direction: response_direction,
            bytes: response,
        } = response
        else {
            return Err(NodeError::Protocol(
                "directional reverse difference query received another response".into(),
            ));
        };
        if response_direction != direction {
            return Err(NodeError::Protocol(
                "difference reply crossed Event reconciliation lanes".into(),
            ));
        }
        match reverse.reconcile_response(&response)? {
            InitiatorStep::Continue(next) => query = next,
            InitiatorStep::Complete(difference) => {
                break EventDifference::from_reconciliation(difference);
            }
        }
    };
    event_guard.check(store)?;
    if request_mission_frame(
        connection,
        mission,
        Frame::DifferenceBound { direction },
        receipt,
    )
    .await?
        != (Frame::DifferenceBoundAck { direction })
    {
        return Err(NodeError::Protocol(
            "directional difference-bound acknowledgement differs".into(),
        ));
    }
    receipt.rounds = receipt
        .rounds
        .checked_add(responder.rounds())
        .and_then(|rounds| rounds.checked_add(reverse.rounds()))
        .ok_or_else(|| NodeError::Protocol("combined round count overflow".into()))?;
    Ok(difference)
}

async fn serve_event_transfer_lane(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    event_verifier: &mut ReferenceEnvelopeSealer,
    lane: DirectedEventLane<'_>,
    difference: &EventDifference,
    receipt: &mut PeerReceipt,
) -> Result<(), NodeError> {
    let DirectedEventLane {
        guard: event_guard,
        receiver_interest,
        direction,
    } = lane;
    let capacity = event_transfer_capacity(receipt)?;
    let mut authorization = TransferAuthorization::for_peer(difference, direction, capacity);
    add_unscheduled_events(receipt, authorization.remaining)?;
    let authenticated_peer = mission.peer().mission_id();
    let peer_route_commitments = mission.peer_route_grant_commitments().to_vec();
    loop {
        event_guard.check(store)?;
        let wire_budget = exchange_wire_budget(receipt)?;
        let (complete, request_bytes, response_bytes) = respond_mission_frame(
            connection,
            mission,
            wire_budget,
            |frame, request_wire_len| match frame {
                Frame::Offer {
                    direction: request_direction,
                    id,
                    bytes,
                } if direction == EventDirection::ToSessionResponder
                    && request_direction == direction =>
                {
                    event_guard.check(store)?;
                    authorize_transfer_item(
                        authorization.offers_from_peer.remove(&id),
                        receipt,
                        "offer",
                    )?;
                    if bytes.len() > MAX_OBJECT_BYTES {
                        return Err(NodeError::Protocol(format!(
                            "offered object exceeds {MAX_OBJECT_BYTES} bytes"
                        )));
                    }
                    check_account(receipt, request_wire_len, 4_096)?;
                    event_guard.check(store)?;
                    let inserted = accept_received_transfer(
                        store,
                        event_verifier,
                        EventReceiveAuthority {
                            peer: authenticated_peer,
                            peer_route_commitments: &peer_route_commitments,
                            receiver_interest,
                            local_replication_policy: event_guard.replication_policy(),
                        },
                        id,
                        &bytes,
                    )?;
                    if inserted {
                        receipt.inserted += 1;
                    } else {
                        receipt.duplicates += 1;
                    }
                    receipt.fetched += 1;
                    event_guard.check(store)?;
                    Ok((
                        Frame::ApplyResult {
                            direction,
                            id,
                            inserted,
                        },
                        false,
                    ))
                }
                Frame::Fetch {
                    direction: request_direction,
                    id,
                } if direction == EventDirection::ToSessionInitiator
                    && request_direction == direction =>
                {
                    event_guard.check(store)?;
                    authorize_transfer_item(
                        authorization.fetches_by_peer.remove(&id),
                        receipt,
                        "fetch",
                    )?;
                    let bytes = load_verified_transfer_for_peer(
                        store,
                        event_guard.policy(),
                        event_verifier,
                        id,
                        authenticated_peer,
                        &peer_route_commitments,
                        receiver_interest,
                    )?;
                    receipt.offered += 1;
                    Ok((
                        Frame::Object {
                            direction,
                            id,
                            bytes,
                        },
                        false,
                    ))
                }
                Frame::Finish {
                    direction: request_direction,
                } if request_direction == direction && authorization.is_consumed() => {
                    event_guard.check(store)?;
                    Ok((Frame::Finished { direction }, true))
                }
                Frame::Finish {
                    direction: request_direction,
                } if request_direction == direction => Err(NodeError::Protocol(
                    "finish preceded consumption of the directional transfer plan".into(),
                )),
                _ => Err(NodeError::Protocol(
                    "transfer crossed Event lanes or used an unauthorized phase operation".into(),
                )),
            },
        )
        .await?;
        account(receipt, request_bytes, response_bytes)?;
        if complete {
            return Ok(());
        }
    }
}

async fn serve_session(
    store: Arc<Store>,
    connection: aster_iroh::Connection,
    credentials: UnprotectedReferenceMission,
    peer: MissionPeerBinding,
    policy_lock: Arc<RwLock<()>>,
) -> Result<CompletedPeerContact, NodeError> {
    // No inventory is even loaded until the independent mission handshake and
    // exact configured mission NodeId check both finish.
    let (mut mission, handshake) =
        respond_over_iroh_metered(&connection, credentials.fresh_bundle()?, peer).await?;
    let mut receipt = authenticated_receipt(&connection, &mission, handshake)?;

    let policy_write = policy_lock.clone().write_owned().await;
    let mut control_verifier = open_replayed_verifier(&store, &credentials)?;
    ensure_contact_principals_active(
        &store,
        control_verifier.identity(),
        mission.peer().mission_id(),
    )?;
    serve_control_lane(
        &store,
        &connection,
        &mut mission,
        &mut control_verifier,
        &mut receipt,
    )
    .await?;
    drop(policy_write);

    let event_lease = policy_lock.read_owned().await;
    let mut event_verifier = open_replayed_verifier(&store, &credentials)?;
    let event_guard = EventLaneGuard::capture(
        event_lease,
        &store,
        event_verifier.identity(),
        mission.peer().mission_id(),
        receipt.controls_remaining,
    )?;
    let (local_interest, peer_interest) = serve_event_interests(
        &store,
        &connection,
        &mut mission,
        &event_guard,
        &mut receipt,
    )
    .await?;

    let to_responder_lane = DirectedEventLane {
        guard: &event_guard,
        receiver_interest: &local_interest,
        direction: EventDirection::ToSessionResponder,
    };
    let to_responder = serve_event_reconciliation_lane(
        &store,
        &connection,
        &mut mission,
        &mut event_verifier,
        to_responder_lane,
        &mut receipt,
    )
    .await?;
    serve_event_transfer_lane(
        &store,
        &connection,
        &mut mission,
        &mut event_verifier,
        to_responder_lane,
        &to_responder,
        &mut receipt,
    )
    .await?;

    let to_initiator_lane = DirectedEventLane {
        guard: &event_guard,
        receiver_interest: &peer_interest,
        direction: EventDirection::ToSessionInitiator,
    };
    let to_initiator = serve_event_reconciliation_lane(
        &store,
        &connection,
        &mut mission,
        &mut event_verifier,
        to_initiator_lane,
        &mut receipt,
    )
    .await?;
    serve_event_transfer_lane(
        &store,
        &connection,
        &mut mission,
        &mut event_verifier,
        to_initiator_lane,
        &to_initiator,
        &mut receipt,
    )
    .await?;
    event_guard.check(&store)?;
    let event_policy = ContactEventPolicy::capture(event_guard.replication_policy());
    connection.close();
    Ok(CompletedPeerContact {
        receipt,
        event_policy,
    })
}

#[derive(Debug)]
struct EventDifference {
    local_only: Vec<EventTransferId>,
    remote_only: Vec<EventTransferId>,
}

struct ControlDifference {
    local_only: Vec<ControlTransferId>,
    remote_only: Vec<ControlTransferId>,
}

impl ControlDifference {
    fn from_reconciliation(difference: Difference) -> Self {
        Self {
            local_only: difference
                .local_only
                .into_iter()
                .map(ControlTransferId::from_reconciliation_item_id)
                .collect(),
            remote_only: difference
                .remote_only
                .into_iter()
                .map(ControlTransferId::from_reconciliation_item_id)
                .collect(),
        }
    }
}

impl EventDifference {
    fn from_reconciliation(difference: Difference) -> Self {
        Self {
            local_only: difference
                .local_only
                .into_iter()
                .map(EventTransferId::from_reconciliation_item_id)
                .collect(),
            remote_only: difference
                .remote_only
                .into_iter()
                .map(EventTransferId::from_reconciliation_item_id)
                .collect(),
        }
    }
}

#[derive(Debug)]
struct TransferAuthorization {
    offers_from_peer: BTreeSet<EventTransferId>,
    fetches_by_peer: BTreeSet<EventTransferId>,
    remaining: usize,
}

#[derive(Debug)]
struct ControlTransferAuthorization {
    offers_from_peer: BTreeSet<ControlTransferId>,
    fetches_by_peer: BTreeSet<ControlTransferId>,
    remaining: usize,
}

impl ControlTransferAuthorization {
    fn for_peer(local_difference: &ControlDifference) -> Self {
        let (peer_offer_limit, peer_fetch_limit) = transfer_limits(
            local_difference.remote_only.len(),
            local_difference.local_only.len(),
        );
        let total = local_difference
            .local_only
            .len()
            .saturating_add(local_difference.remote_only.len());
        Self {
            offers_from_peer: local_difference
                .remote_only
                .iter()
                .take(peer_offer_limit)
                .copied()
                .collect(),
            fetches_by_peer: local_difference
                .local_only
                .iter()
                .take(peer_fetch_limit)
                .copied()
                .collect(),
            remaining: total.saturating_sub(peer_offer_limit.saturating_add(peer_fetch_limit)),
        }
    }

    fn is_consumed(&self) -> bool {
        self.offers_from_peer.is_empty() && self.fetches_by_peer.is_empty()
    }
}

impl TransferAuthorization {
    fn for_peer(
        local_difference: &EventDifference,
        direction: EventDirection,
        capacity: usize,
    ) -> Self {
        match direction {
            EventDirection::ToSessionResponder => {
                // The responder is the receiver, so only initiator-only items
                // (remote-only from this endpoint's view) may arrive as offers.
                let limit = local_difference.remote_only.len().min(capacity);
                Self {
                    offers_from_peer: local_difference
                        .remote_only
                        .iter()
                        .take(limit)
                        .copied()
                        .collect(),
                    fetches_by_peer: BTreeSet::new(),
                    remaining: local_difference.remote_only.len() - limit,
                }
            }
            EventDirection::ToSessionInitiator => {
                // The initiator is the receiver, so it may fetch only items
                // local to this responder in the independently derived lane.
                let limit = local_difference.local_only.len().min(capacity);
                Self {
                    offers_from_peer: BTreeSet::new(),
                    fetches_by_peer: local_difference
                        .local_only
                        .iter()
                        .take(limit)
                        .copied()
                        .collect(),
                    remaining: local_difference.local_only.len() - limit,
                }
            }
        }
    }

    fn is_consumed(&self) -> bool {
        self.offers_from_peer.is_empty() && self.fetches_by_peer.is_empty()
    }
}

fn transfer_limits(local_only: usize, remote_only: usize) -> (usize, usize) {
    let local_limit = local_only.min(MAX_CONTACT_ITEMS / 2);
    let remote_limit = remote_only.min(MAX_CONTACT_ITEMS - local_limit);
    let local_limit = local_only.min(MAX_CONTACT_ITEMS - remote_limit);
    (local_limit, remote_limit)
}

fn authorize_transfer_item(
    authorized: bool,
    receipt: &PeerReceipt,
    operation: &str,
) -> Result<(), NodeError> {
    if !authorized {
        return Err(NodeError::Protocol(format!(
            "{operation} identifier is outside this authenticated contact's negotiated difference"
        )));
    }
    let items = receipt
        .offered
        .checked_add(receipt.fetched)
        .ok_or_else(|| NodeError::Protocol("contact item count overflow".into()))?;
    if items >= MAX_CONTACT_ITEMS {
        return Err(NodeError::Protocol(format!(
            "contact item count exceeds {MAX_CONTACT_ITEMS}"
        )));
    }
    Ok(())
}

async fn request_mission_frame(
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    request: Frame,
    receipt: &mut PeerReceipt,
) -> Result<Frame, NodeError> {
    let wire_budget = exchange_wire_budget(receipt)?;
    let plaintext = request.encode()?;
    let protected_request = mission.seal_application_frame(&plaintext)?;
    let protected_response = connection
        .request_with_total_limit(&protected_request, wire_budget)
        .await?;
    let response = mission.open_application_frame(&protected_response)?;
    let response = Frame::decode(&response)?;
    account(receipt, protected_request.len(), protected_response.len())?;
    Ok(response)
}

async fn respond_mission_frame<F>(
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    wire_budget: usize,
    handler: F,
) -> Result<(bool, usize, usize), NodeError>
where
    F: FnOnce(Frame, usize) -> Result<(Frame, bool), NodeError>,
{
    let mut application_error = None;
    let mut request_len = None;
    let mut response_len = None;
    let mut complete = None;
    let carrier_result = connection
        .respond_once_with_total_limit(wire_budget, |protected_request| {
            request_len = Some(protected_request.len());
            let handled = (|| -> Result<Vec<u8>, NodeError> {
                let plaintext = mission.open_application_frame(protected_request)?;
                let frame = Frame::decode(&plaintext)?;
                let (response, session_complete) = handler(frame, protected_request.len())?;
                let response = response.encode()?;
                let protected_response = mission.seal_application_frame(&response)?;
                response_len = Some(protected_response.len());
                complete = Some(session_complete);
                Ok(protected_response)
            })();
            match handled {
                Ok(response) => Ok((response, complete.unwrap_or(false))),
                Err(error) => {
                    application_error = Some(error);
                    Err(CarrierError::Transport(
                        "mission-protected application frame rejected".into(),
                    ))
                }
            }
        })
        .await;
    if let Some(error) = application_error {
        return Err(error);
    }
    let carrier_complete = carrier_result?;
    let response_len = response_len.ok_or_else(|| {
        NodeError::Protocol("mission response completed without a protected frame".into())
    })?;
    let handler_complete = complete.ok_or_else(|| {
        NodeError::Protocol("mission response completed without a phase disposition".into())
    })?;
    if carrier_complete != handler_complete {
        return Err(NodeError::Protocol(
            "carrier and mission phase completion dispositions differ".into(),
        ));
    }
    let request_len = request_len.ok_or_else(|| {
        NodeError::Protocol("mission response completed without a protected request".into())
    })?;
    Ok((carrier_complete, request_len, response_len))
}

fn authenticated_receipt(
    connection: &aster_iroh::Connection,
    mission: &MissionSession,
    handshake: MissionHandshakeReceipt,
) -> Result<PeerReceipt, NodeError> {
    if handshake.frames > MAX_CONTACT_FRAMES || handshake.bytes > MAX_CONTACT_BYTES {
        return Err(NodeError::Protocol(
            "mission handshake exceeded the total contact budget".into(),
        ));
    }
    Ok(PeerReceipt {
        peer: Some(connection.remote_id()),
        mission_peer: Some(mission.peer().mission_id()),
        handshake_frames: handshake.frames,
        handshake_bytes: handshake.bytes,
        ..PeerReceipt::default()
    })
}

fn exchange_wire_budget(receipt: &PeerReceipt) -> Result<usize, NodeError> {
    let mission_frames = receipt
        .handshake_frames
        .checked_add(receipt.protected_frames)
        .ok_or_else(|| NodeError::Protocol("contact frame count overflow".into()))?;
    let next_frames = mission_frames
        .checked_add(2)
        .ok_or_else(|| NodeError::Protocol("contact frame count overflow".into()))?;
    if next_frames > MAX_CONTACT_FRAMES {
        return Err(NodeError::Protocol(format!(
            "contact frame count {next_frames} exceeds {MAX_CONTACT_FRAMES}"
        )));
    }
    let mission_bytes = receipt
        .handshake_bytes
        .checked_add(receipt.protected_bytes)
        .ok_or_else(|| NodeError::Protocol("contact byte count overflow".into()))?;
    MAX_CONTACT_BYTES
        .checked_sub(mission_bytes)
        .filter(|remaining| *remaining > 0)
        .ok_or_else(|| NodeError::Protocol("contact byte budget is exhausted".into()))
}

const fn contact_status(receipt: &PeerReceipt) -> &'static str {
    if receipt.remaining == 0 && receipt.controls_remaining == 0 {
        "pass"
    } else {
        "partial"
    }
}

fn account(receipt: &mut PeerReceipt, request: usize, response: usize) -> Result<(), NodeError> {
    let (frames, bytes) = check_account(receipt, request, response)?;
    receipt.protected_frames = frames;
    receipt.protected_bytes = bytes;
    Ok(())
}

fn check_account(
    receipt: &PeerReceipt,
    request: usize,
    response: usize,
) -> Result<(usize, usize), NodeError> {
    let frames = receipt
        .protected_frames
        .checked_add(2)
        .ok_or_else(|| NodeError::Protocol("contact frame count overflow".into()))?;
    let mission_frames = receipt
        .handshake_frames
        .checked_add(frames)
        .ok_or_else(|| NodeError::Protocol("contact frame count overflow".into()))?;
    if mission_frames > MAX_CONTACT_FRAMES {
        return Err(NodeError::Protocol(format!(
            "contact frame count {mission_frames} exceeds {MAX_CONTACT_FRAMES}"
        )));
    }
    let bytes = receipt
        .protected_bytes
        .checked_add(request)
        .and_then(|bytes| bytes.checked_add(response))
        .ok_or_else(|| NodeError::Protocol("contact byte count overflow".into()))?;
    let mission_bytes = receipt
        .handshake_bytes
        .checked_add(bytes)
        .ok_or_else(|| NodeError::Protocol("contact byte count overflow".into()))?;
    if mission_bytes > MAX_CONTACT_BYTES {
        return Err(NodeError::Protocol(format!(
            "contact byte count {mission_bytes} exceeds {MAX_CONTACT_BYTES}"
        )));
    }
    Ok((frames, bytes))
}

/// Runs the default real N-process Ping/Pong, temporal-forwarding, and restart demonstration.
pub fn run_demo(nodes: usize, root: &Path, base_port: u16) -> Result<(), NodeError> {
    run_demo_scenario(DemoScenario::PingPong, nodes, root, base_port)
}

/// Runs one explicitly selected real-process virtual-mesh acceptance scenario.
pub fn run_demo_scenario(
    scenario: DemoScenario,
    nodes: usize,
    root: &Path,
    base_port: u16,
) -> Result<(), NodeError> {
    if !(2..=32).contains(&nodes) {
        return Err(NodeError::Configuration(
            "demo node count must be within 2..=32".into(),
        ));
    }
    if matches!(scenario, DemoScenario::Control) && nodes != 4 {
        return Err(NodeError::Configuration(
            "the control acceptance scenario requires exactly four role-bound nodes".into(),
        ));
    }
    if root.exists() {
        return Err(NodeError::Configuration(format!(
            "demo root already exists: {}",
            root.display()
        )));
    }
    fs::create_dir_all(root)?;
    let base_port = if base_port == 0 {
        find_port_block(nodes)?
    } else {
        validate_port_block(base_port, nodes)?;
        base_port
    };
    let states = (0..nodes)
        .map(|index| root.join(format!("node-{index}")))
        .collect::<Vec<_>>();
    let identities = states
        .iter()
        .map(|state| NodeIdentity::load_or_create(state).map(|identity| identity.id()))
        .collect::<Result<Vec<_>, _>>()?;
    let demo_scope =
        Scope::new(DEMO_SCOPE).map_err(|error| NodeError::Configuration(error.to_string()))?;
    let demo_topics = [DEMO_EVENT_TOPIC]
        .into_iter()
        .map(Topic::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| NodeError::Configuration(error.to_string()))?;
    let mut authority_seed = aster_iroh::SecretKey::generate().to_bytes();
    let provisioner = ReferenceProvisioner::from_seed(authority_seed);
    authority_seed.zeroize();
    let mut provisioner = provisioner.map_err(MissionSessionError::from)?;
    let controlled_demo = matches!(scenario, DemoScenario::Control);
    let mut missions = Vec::with_capacity(nodes);
    for (index, state) in states.iter().enumerate() {
        let serial = u64::try_from(index)
            .map_err(|_| NodeError::Configuration("demo node index overflows u64".into()))?
            .checked_add(1)
            .ok_or_else(|| NodeError::Configuration("demo serial overflow".into()))?;
        let member = if controlled_demo {
            matches!(index, 0 | 2 | 3)
        } else {
            index == 0 || index + 1 == nodes
        };
        let access = if member {
            ProvisioningAccess::member(demo_scope.clone(), vec![1], demo_topics.clone())
        } else {
            ProvisioningAccess::relay(demo_scope.clone(), vec![1])
        }
        .map_err(MissionSessionError::from)?;
        let bundle = if controlled_demo && index == 0 {
            provisioner.issue_control_authority(serial, &[access])
        } else {
            provisioner.issue_node(serial, &[access])
        }
        .map_err(MissionSessionError::from)?;
        let bytes = bundle.to_bytes().map_err(MissionSessionError::from)?;
        let path = state.join(DEMO_MISSION_BUNDLE_FILE);
        let mission = UnprotectedReferenceMission::persist(&path, bytes)?;
        seed_demo_event_subscription(
            state,
            &mission,
            if member {
                EventSubscriptionMode::Consume
            } else {
                EventSubscriptionMode::Carry
            },
        )?;
        missions.push(DemoMission {
            path,
            identity: mission.identity(),
        });
    }
    let consume_selectors = if controlled_demo { 3 } else { 2 };
    println!(
        "SUBSCRIPTIONS status=seeded consume={} carry={} selectors={} interest_exchange=mission-protected lanes=receiver-directed",
        consume_selectors,
        nodes - consume_selectors,
        nodes,
    );
    let signed_registry = controlled_demo
        .then(|| {
            provisioner
                .export_rekey_registry()
                .map_err(MissionSessionError::from)
        })
        .transpose()?;
    let addresses = (0..nodes)
        .map(|index| SocketAddr::from(([127, 0, 0, 1], base_port + index as u16)))
        .collect::<Vec<_>>();
    let topology = DemoTopology {
        root,
        states: &states,
        identities: &identities,
        missions: &missions,
        addresses: &addresses,
    };
    if let Some(signed_registry) = signed_registry {
        let registry_path = root.join(DEMO_SIGNED_REGISTRY_FILE);
        fs::write(&registry_path, &signed_registry)?;
        return run_controlled_n4_demo(&topology, &registry_path);
    }
    let relay_applications = vec![NodeApplication::Relay; nodes];
    let mut ping_applications = relay_applications.clone();
    ping_applications[0] = NodeApplication::PingEmitter;

    // A peerless live origin process reserves, source-seals, content-verifies,
    // and atomically commits Ping. Every later phase therefore reconciles an
    // Event representation that was already durable when its processes began.
    run_demo_phase(&topology, "ping-publish", &[0], &ping_applications)?;
    require_application_receipt(root, "ping-publish", 0, "emitted", "ping")?;
    let ping = load_demo_operation(&states[0], &missions[0], &ping_operation_key()?)?
        .ok_or_else(|| NodeError::Demo("origin process did not durably publish Ping".into()))?;
    verify_demo_event(&states[0], &missions[0], &ping, DEMO_PING_PAYLOAD)?;
    if ping.header.stamp.dot.publisher != missions[0].identity()
        || ping.header.topic.as_str() != DEMO_EVENT_TOPIC
        || ping.header.scope.as_str() != DEMO_SCOPE
        || ping.header.logical_key != DEMO_PING_LOGICAL_KEY
        || ping.header.ttl_ms.is_some()
    {
        return Err(NodeError::Demo(
            "origin Ping differs from the authenticated sample Event contract".into(),
        ));
    }
    require_event_convergence(&states[..1], &missions[..1], 1)?;

    // Stop after each two-node hop. Before every contact, the source has one
    // exact Ping representation the destination lacks; after it, the pair's
    // stopped stores must have identical one-transfer inventories.
    for left in 0..nodes - 1 {
        let right = left + 1;
        require_exact_event_difference(
            &states[left],
            &missions[left],
            &states[right],
            &missions[right],
            &ping,
            "Ping forward",
        )?;
        let phase = format!("ping-forward-{left}-to-{right}");
        run_demo_phase(&topology, &phase, &[left, right], &relay_applications)?;
        require_single_event_transfer_receipt(root, &phase, left, right)?;
        require_event_convergence_at(&states[left..=right], &missions[left..=right], 1, left)?;
    }
    let destination_ping =
        load_demo_semantic(&states[nodes - 1], &missions[nodes - 1], ping.semantic_id)?
            .ok_or_else(|| {
                NodeError::Demo("destination did not semantically accept Ping".into())
            })?;
    if destination_ping.transfer_id != ping.transfer_id || destination_ping.sealed != ping.sealed {
        return Err(NodeError::Demo(
            "destination Ping is not the origin's exact source-sealed representation".into(),
        ));
    }

    // With no peer process, the destination observes the already-durable Ping
    // and atomically commits its causal Pong. Forwarding cannot begin until the
    // publisher has stopped and the representation has been reread from disk.
    let mut pong_applications = relay_applications.clone();
    pong_applications[nodes - 1] = NodeApplication::PongResponder;
    run_demo_phase(&topology, "pong-publish", &[nodes - 1], &pong_applications)?;
    require_application_receipt(root, "pong-publish", nodes - 1, "emitted", "pong")?;
    let pong = load_demo_operation(
        &states[nodes - 1],
        &missions[nodes - 1],
        &pong_operation_key(ping.semantic_id)?,
    )?
    .ok_or_else(|| NodeError::Demo("destination process did not durably emit Pong".into()))?;
    verify_demo_event(
        &states[nodes - 1],
        &missions[nodes - 1],
        &pong,
        DEMO_PONG_PAYLOAD,
    )?;
    if pong.header.stamp.dot.publisher != missions[nodes - 1].identity()
        || pong.header.topic != ping.header.topic
        || pong.header.scope != ping.header.scope
        || pong.header.logical_key != ping.semantic_id.as_bytes()
        || pong.header.ttl_ms.is_some()
        || !pong.header.stamp.context.observes(ping.header.stamp.dot)
    {
        return Err(NodeError::Demo(
            "reactive Pong lacks its authenticated Ping correlation or causal observation".into(),
        ));
    }
    println!(
        "PING status=received emitted_by=origin-process producer_state=node-0 destination_state=node-{} transfer_id={} semantic_id={} producer_process_absent=true source_authenticated=true ttl=none",
        nodes - 1,
        format_transfer_id(ping.transfer_id),
        format_semantic_id(ping.semantic_id),
    );

    // Return Pong one stopped edge at a time. Ping is already common, so each
    // source/destination pair differs by exactly the authenticated Pong bytes
    // before contact and has the same two transfers after contact.
    for left in (0..nodes - 1).rev() {
        let right = left + 1;
        require_exact_event_difference(
            &states[right],
            &missions[right],
            &states[left],
            &missions[left],
            &pong,
            "Pong return",
        )?;
        let phase = format!("pong-return-{right}-to-{left}");
        run_demo_phase(&topology, &phase, &[left, right], &relay_applications)?;
        require_single_event_transfer_receipt(root, &phase, right, left)?;
        require_event_convergence_at(&states[left..=right], &missions[left..=right], 2, left)?;
    }
    let all_nodes = (0..nodes).collect::<Vec<_>>();
    require_event_convergence(&states, &missions, 2)?;
    let returned_pong = load_demo_semantic(&states[0], &missions[0], pong.semantic_id)?
        .ok_or_else(|| NodeError::Demo("origin did not receive reactive Pong".into()))?;
    verify_demo_event(&states[0], &missions[0], &returned_pong, DEMO_PONG_PAYLOAD)?;
    if returned_pong.transfer_id != pong.transfer_id || returned_pong.sealed != pong.sealed {
        return Err(NodeError::Demo(
            "returned Pong differs from the destination's exact source-sealed representation"
                .into(),
        ));
    }
    if nodes > 2 {
        verify_payload_blind_relays(&states, &missions, &ping, &pong)?;
        println!(
            "RELAY status=pass intermediates={} exact_forward=true content_access=denied semantic_acceptance=none",
            nodes - 2
        );
    } else {
        println!("RELAY status=not-applicable intermediates=0");
    }
    println!(
        "PONG status=received emitted_by=destination-process producer_state=node-{} destination_state=node-0 correlation_semantic_id={} transfer_id={} semantic_id={} source_authenticated=true causal_observation=verified ttl=none",
        nodes - 1,
        format_semantic_id(ping.semantic_id),
        format_transfer_id(pong.transfer_id),
        format_semantic_id(pong.semantic_id),
    );

    // A final full restart runs both application roles. Durable operation rows
    // must win, no second Ping/Pong may appear, and equal inventories transfer
    // no exact representation.
    let mut noop_applications = pong_applications;
    noop_applications[0] = NodeApplication::PingEmitter;
    run_demo_phase(&topology, "noop", &all_nodes, &noop_applications)?;
    require_application_receipt(root, "noop", 0, "existing", "ping")?;
    require_application_receipt(root, "noop", nodes - 1, "existing", "pong")?;
    require_event_convergence(&states, &missions, 2)?;
    println!(
        "DEMO_RESULT status=pass scenario=ping-pong nodes={} processes={} contacts=real-iroh mission_auth=hybrid-pq provisioning=unprotected-reference stores=independent-redb reconciliation=negentropy producer_process_absent=true restarts=pass atomic_reaction=pass equal_inventory_noop=pass transfers_each=2 semantics=source-authenticated-event emitted_by=running-node-processes payload_blind_relays={} ttl=durable-none root={}",
        nodes,
        nodes * 5 - 2,
        if nodes > 2 { "pass" } else { "not-applicable" },
        format_path_field(root)
    );
    Ok(())
}

fn run_controlled_n4_demo(
    topology: &DemoTopology<'_>,
    registry_path: &Path,
) -> Result<(), NodeError> {
    let DemoTopology {
        root,
        states,
        missions,
        ..
    } = topology;
    if states.len() != 4 || missions.len() != 4 {
        return Err(NodeError::Configuration(
            "controlled acceptance requires exactly four nodes".into(),
        ));
    }
    let executable = std::env::current_exe()?;
    let authority_bundle = states[0].join(DEMO_MISSION_BUNDLE_FILE);
    let revoked = format_node_id(missions[3].identity());
    let logs = root.join("logs");
    fs::create_dir_all(&logs)?;

    let mut revoke = Command::new(&executable);
    revoke
        .arg("control-revoke")
        .arg("--state")
        .arg(&states[0])
        .arg("--mission-bundle-unprotected-reference")
        .arg(&authority_bundle)
        .arg("--subject")
        .arg(&revoked)
        .arg("--generation")
        .arg("1");
    let revoke_receipt = run_demo_authority_process(root, "authority-revoke", revoke)?;
    if !revoke_receipt.contains("status=emitted")
        || !revoke_receipt.contains("emitted_by=authority-process")
    {
        return Err(NodeError::Demo(
            "authority revocation process omitted its durable emission receipt".into(),
        ));
    }

    let member_authority = format!(
        "{}={}",
        format_node_id(missions[0].identity()),
        DEMO_EVENT_TOPIC
    );
    let member_survivor = format!(
        "{}={}",
        format_node_id(missions[2].identity()),
        DEMO_EVENT_TOPIC
    );
    let mut rekey = Command::new(&executable);
    rekey
        .arg("control-rekey")
        .arg("--state")
        .arg(&states[0])
        .arg("--mission-bundle-unprotected-reference")
        .arg(&authority_bundle)
        .arg("--signed-public-registry")
        .arg(registry_path)
        .arg("--minimum-registry-generation")
        .arg("4")
        .arg("--scope")
        .arg(DEMO_SCOPE)
        .arg("--epoch")
        .arg("2")
        .arg("--route-recipient")
        .arg(format_node_id(missions[1].identity()))
        .arg("--member-recipient")
        .arg(member_authority)
        .arg("--member-recipient")
        .arg(member_survivor);
    let rekey_receipt = run_demo_authority_process(root, "authority-rekey", rekey)?;
    if !rekey_receipt.contains("status=emitted")
        || !rekey_receipt.contains("emitted_by=authority-process")
        || !rekey_receipt.contains("recipients=3")
    {
        return Err(NodeError::Demo(
            "authority rekey process omitted its exact recipient-filtered emission receipt".into(),
        ));
    }
    require_control_convergence(&states[..1], &missions[..1], 2)?;

    let relay_applications = vec![NodeApplication::Relay; 4];
    run_demo_phase(
        topology,
        "control-authority-seed",
        &[0, 1],
        &relay_applications,
    )?;
    require_control_convergence(&states[..2], &missions[..2], 2)?;

    // The authority process and node are absent from all remaining propagation.
    run_demo_phase(
        topology,
        "control-authority-absent-forward",
        &[1, 2],
        &relay_applications,
    )?;
    require_control_convergence(&states[..3], &missions[..3], 2)?;

    // Run the newly authorized source without a peer so publication is a
    // distinct process boundary after the authority-absent control prefix is
    // durable. The later forwarding phase therefore begins with both control
    // heads and the exact Ping already present; no correctness claim depends
    // on a second contact racing the phase watchdog.
    let mut survivor_applications = relay_applications.clone();
    survivor_applications[2] = NodeApplication::EpochTwoPingEmitter;
    run_demo_phase(
        topology,
        "control-authority-absent-publish",
        &[2],
        &survivor_applications,
    )?;
    require_application_receipt(
        root,
        "control-authority-absent-publish",
        2,
        "emitted",
        "ping",
    )?;
    let ping = load_demo_operation(&states[2], &missions[2], &ping_operation_key()?)?
        .ok_or_else(|| NodeError::Demo("surviving member did not emit epoch-two Ping".into()))?;
    if ping.header.key_epoch != 2 || ping.header.stamp.dot.publisher != missions[2].identity() {
        return Err(NodeError::Demo(
            "surviving member Ping is not bound to active epoch two".into(),
        ));
    }
    verify_demo_event(&states[2], &missions[2], &ping, DEMO_PING_PAYLOAD)?;

    // Start a fresh authority-absent cohort with the settled control prefix
    // and durable Ping so a successful contact proves the payload-blind relay
    // received the exact Event.
    run_demo_phase(
        topology,
        "control-authority-absent-event-forward",
        &[1, 2],
        &relay_applications,
    )?;
    verify_controlled_route_cache(&states[1], &missions[1], &ping)?;

    let mut captured_applications = relay_applications.clone();
    captured_applications[3] = NodeApplication::PingEmitter;
    run_demo_denied_phase(
        topology,
        "captured-publication-denied",
        &[2, 3],
        &captured_applications,
    )?;
    require_denied_mesh_contact(root, "captured-publication-denied", &[2, 3])?;
    let captured_ping = load_demo_operation(&states[3], &missions[3], &ping_operation_key()?)?
        .ok_or_else(|| {
            NodeError::Demo("captured node did not exercise stale local signing".into())
        })?;
    if captured_ping.header.key_epoch != 1
        || load_demo_semantic(&states[3], &missions[3], ping.semantic_id)?.is_some()
    {
        return Err(NodeError::Demo(
            "captured node learned epoch-two content or did not remain on stale epoch one".into(),
        ));
    }
    require_survivor_unchanged(&states[2], &missions[2], &ping)?;

    run_demo_denied_phase(
        topology,
        "captured-rejoin-denied",
        &[2, 3],
        &captured_applications,
    )?;
    require_denied_mesh_contact(root, "captured-rejoin-denied", &[2, 3])?;
    require_application_receipt(root, "captured-rejoin-denied", 3, "existing", "ping")?;
    require_survivor_unchanged(&states[2], &missions[2], &ping)?;

    let captured_store = open_demo_store(&states[3], &missions[3])?.0;
    let captured_controls = captured_store.control_stats()?;
    if captured_controls.controls != 0
        || captured_controls.applied != 0
        || captured_controls.pending != 0
    {
        return Err(NodeError::Demo(
            "revoked captured node received control inventory after revocation".into(),
        ));
    }

    // Restart the surviving epoch-two line after the control authority carrier
    // was absent during forwarding. Each causal step gets its own stopped-state
    // boundary so the demo never asks a phase watchdog to provide a second
    // contact after application work becomes durable.
    run_demo_phase(topology, "pong-ping-forward", &[0, 1], &relay_applications)?;
    let delivered_ping = load_demo_semantic(&states[0], &missions[0], ping.semantic_id)?
        .ok_or_else(|| NodeError::Demo("eligible Pong member did not receive Ping".into()))?;
    verify_demo_event(&states[0], &missions[0], &delivered_ping, DEMO_PING_PAYLOAD)?;
    if delivered_ping.transfer_id != ping.transfer_id || delivered_ping.sealed != ping.sealed {
        return Err(NodeError::Demo(
            "eligible Pong member received a changed Ping representation".into(),
        ));
    }

    // Node 0 is now only an ordinary admitted member application process: the
    // short-lived authority CLIs remain gone. With no peer, it observes the
    // already-durable Ping and commits the causal Pong before forwarding starts.
    let mut pong_applications = relay_applications.clone();
    pong_applications[0] = NodeApplication::PongResponder;
    pong_applications[2] = NodeApplication::EpochTwoPingEmitter;
    run_demo_phase(topology, "pong-publish", &[0], &pong_applications)?;
    require_application_receipt(root, "pong-publish", 0, "emitted", "pong")?;
    let pong = load_demo_operation(
        &states[0],
        &missions[0],
        &pong_operation_key(ping.semantic_id)?,
    )?
    .ok_or_else(|| NodeError::Demo("eligible epoch-two member did not emit Pong".into()))?;
    verify_demo_event(&states[0], &missions[0], &pong, DEMO_PONG_PAYLOAD)?;
    if pong.header.key_epoch != 2
        || pong.header.stamp.dot.publisher != missions[0].identity()
        || pong.header.topic != ping.header.topic
        || pong.header.scope != ping.header.scope
        || pong.header.logical_key != ping.semantic_id.as_bytes()
        || pong.header.ttl_ms.is_some()
        || !pong.header.stamp.context.observes(ping.header.stamp.dot)
    {
        return Err(NodeError::Demo(
            "epoch-two Pong lacks authenticated Ping correlation or causality".into(),
        ));
    }

    // First move the already-durable Pong onto the payload-blind relay, then
    // use a fresh contact to return it to node 2. Each successful two-node
    // phase reconciles one pre-existing difference.
    run_demo_phase(topology, "pong-relay-forward", &[0, 1], &relay_applications)?;
    verify_payload_blind_relays(&states[..3], &missions[..3], &ping, &pong)?;
    run_demo_phase(topology, "pong-return", &[1, 2], &relay_applications)?;
    require_event_convergence(&states[..3], &missions[..3], 2)?;
    let returned_pong = load_demo_semantic(&states[2], &missions[2], pong.semantic_id)?
        .ok_or_else(|| NodeError::Demo("surviving Ping publisher did not receive Pong".into()))?;
    verify_demo_event(&states[2], &missions[2], &returned_pong, DEMO_PONG_PAYLOAD)?;
    if returned_pong.transfer_id != pong.transfer_id || returned_pong.sealed != pong.sealed {
        return Err(NodeError::Demo(
            "returned epoch-two Pong differs from its exact source-sealed representation".into(),
        ));
    }
    println!(
        "PING status=received emitted_by=surviving-member-process producer_state=node-2 destination_state=node-0 transfer_id={} semantic_id={} authority_absent_during_forwarding=true source_authenticated=true key_epoch=2 ttl=none",
        format_transfer_id(ping.transfer_id),
        format_semantic_id(ping.semantic_id),
    );
    println!(
        "PONG status=received emitted_by=eligible-member-process producer_state=node-0 destination_state=node-2 correlation_semantic_id={} transfer_id={} semantic_id={} source_authenticated=true causal_observation=verified key_epoch=2 ttl=none",
        format_semantic_id(ping.semantic_id),
        format_transfer_id(pong.transfer_id),
        format_semantic_id(pong.semantic_id),
    );
    println!(
        "RELAY status=pass intermediates=1 exact_forward=true content_access=denied semantic_acceptance=none key_epoch=2"
    );

    // One more complete process restart must reuse both durable application
    // operations and transfer nothing once the eligible inventories are equal.
    let eligible = [0, 1, 2];
    run_demo_phase(topology, "noop", &eligible, &pong_applications)?;
    require_application_receipt(root, "noop", 0, "existing", "pong")?;
    require_application_receipt(root, "noop", 2, "existing", "ping")?;
    require_event_convergence(&states[..3], &missions[..3], 2)?;
    println!(
        "CONTROL_RESULT status=pass nodes=4 authority_processes=2 emitted_by=authority-process controls=2 control_priority=flash authority_absent_forwarding=pass route_only_forward=pass survivor_epoch=2 captured_node=3 captured_sync=denied captured_epoch2_read=denied captured_mesh_publication=denied captured_rejoin=denied captured_local_signing=stale-only commit_before_activate=true mission_auth=hybrid-pq root={}",
        format_path_field(root)
    );
    println!(
        "DEMO_RESULT status=pass scenario=control nodes=4 processes=23 contacts=real-iroh mission_auth=hybrid-pq provisioning=unprotected-reference stores=independent-redb reconciliation=negentropy authority_absent_during_forwarding=true authority_cli_absent_after_commit=true authority_carrier_restart=pass controls=source-authenticated-flash recipient_filtered=true payload_blind_relay=pass captured_exclusion=pass epoch2_ping_pong=pass restarts=pass atomic_reaction=pass equal_inventory_noop=pass eligible_transfers_each=2 epoch2_publisher=node-2 root={}",
        format_path_field(root)
    );
    Ok(())
}

fn run_demo_authority_process(
    root: &Path,
    label: &str,
    mut command: Command,
) -> Result<String, NodeError> {
    let output = command.output()?;
    let logs = root.join("logs");
    fs::create_dir_all(&logs)?;
    fs::write(logs.join(format!("{label}.log")), &output.stdout)?;
    fs::write(logs.join(format!("{label}.err")), &output.stderr)?;
    if !output.status.success() {
        return Err(NodeError::Demo(format!(
            "{label} exited {}; stdout={} stderr={}",
            output.status,
            logs.join(format!("{label}.log")).display(),
            logs.join(format!("{label}.err")).display(),
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| NodeError::Demo(format!("{label} stdout is not UTF-8")))
}

fn require_control_convergence(
    states: &[PathBuf],
    missions: &[DemoMission],
    expected: usize,
) -> Result<(), NodeError> {
    let mut canonical: Option<Vec<StoredControl>> = None;
    for (state, mission) in states.iter().zip(missions) {
        let (store, _) = open_demo_store(state, mission)?;
        let stats = store.control_stats()?;
        if stats.applied != expected as u64
            || stats.pending != 0
            || stats.controls != expected as u64
        {
            return Err(NodeError::Demo(format!(
                "control state did not converge at {}: controls={} applied={} pending={} expected={expected}",
                state.display(),
                stats.controls,
                stats.applied,
                stats.pending,
            )));
        }
        let rows = store.applied_controls()?;
        if let Some(canonical) = &canonical {
            if &rows != canonical {
                return Err(NodeError::Demo(
                    "control replicas differ in exact ordered bytes or authenticated claims".into(),
                ));
            }
        } else {
            canonical = Some(rows);
        }
    }
    Ok(())
}

fn verify_controlled_route_cache(
    state: &Path,
    mission: &DemoMission,
    expected: &StoredEvent,
) -> Result<(), NodeError> {
    let (store, mut verifier) = open_demo_store(state, mission)?;
    let policy = store.control_policy_snapshot()?;
    let stats = store.event_stats()?;
    if stats.events != 0 || stats.route_cached != 1 {
        return Err(NodeError::Demo(format!(
            "route-only node crossed its content boundary: events={} route_cached={}",
            stats.events, stats.route_cached,
        )));
    }
    let Some(StoredEventTransfer::RouteCached(cached)) =
        store.get_transfer_with_policy(&policy, expected.transfer_id)?
    else {
        return Err(NodeError::Demo(
            "route-only node lacks the survivor's exact epoch-two Event".into(),
        ));
    };
    if cached.sealed != expected.sealed {
        return Err(NodeError::Demo(
            "route-only node changed the exact epoch-two Event bytes".into(),
        ));
    }
    let route = verifier.verify_event(&cached.sealed)?;
    if !matches!(
        verifier.verify_event_content(route, &cached.sealed)?,
        EventContentVerification::RouteOnly(_)
    ) {
        return Err(NodeError::Demo(
            "route-only node unexpectedly opened epoch-two content".into(),
        ));
    }
    Ok(())
}

fn require_denied_mesh_contact(root: &Path, phase: &str, nodes: &[usize]) -> Result<(), NodeError> {
    let mut saw_error = false;
    for node in nodes {
        let stdout =
            fs::read_to_string(root.join("logs").join(format!("{phase}-node-{node}.log")))?;
        let stderr =
            fs::read_to_string(root.join("logs").join(format!("{phase}-node-{node}.err")))?;
        if stdout
            .lines()
            .any(|line| line.starts_with("CONTACT ") && line.ends_with("status=pass"))
        {
            return Err(NodeError::Demo(format!(
                "{phase} unexpectedly completed a revoked peer contact"
            )));
        }
        saw_error |= stderr
            .lines()
            .any(|line| line.starts_with("CONTACT ") && line.contains(" status=error "));
    }
    if !saw_error {
        return Err(NodeError::Demo(format!(
            "{phase} omitted the expected revoked-peer rejection receipt"
        )));
    }
    Ok(())
}

fn require_survivor_unchanged(
    state: &Path,
    mission: &DemoMission,
    expected: &StoredEvent,
) -> Result<(), NodeError> {
    let (store, _) = open_demo_store(state, mission)?;
    if store.event_count()? != 1
        || store.event_by_semantic_id(expected.semantic_id)?.as_ref() != Some(expected)
    {
        return Err(NodeError::Demo(
            "eligible survivor accepted captured-node publication or lost epoch-two state".into(),
        ));
    }
    Ok(())
}

fn open_demo_store(
    state: &Path,
    mission: &DemoMission,
) -> Result<(Store, ReferenceEnvelopeSealer), NodeError> {
    let mission = mission.load()?;
    let mut sealer = ReferenceEnvelopeSealer::open(mission.fresh_bundle()?)?;
    let store = Store::open_for_mission(state.join(STORE_FILE), sealer.mission_authority_id())?;
    replay_applied_controls(&store, &mut sealer)?;
    Ok((store, sealer))
}

fn load_demo_operation(
    state: &Path,
    mission: &DemoMission,
    operation: &EventOperationKey,
) -> Result<Option<StoredEvent>, NodeError> {
    let (store, _) = open_demo_store(state, mission)?;
    store.event_for_operation(operation).map_err(Into::into)
}

fn load_demo_semantic(
    state: &Path,
    mission: &DemoMission,
    semantic_id: EventSemanticId,
) -> Result<Option<StoredEvent>, NodeError> {
    let (store, _) = open_demo_store(state, mission)?;
    store.event_by_semantic_id(semantic_id).map_err(Into::into)
}

fn verify_demo_event(
    state: &Path,
    mission: &DemoMission,
    stored: &StoredEvent,
    expected_payload: &[u8],
) -> Result<(), NodeError> {
    let (store, mut sealer) = open_demo_store(state, mission)?;
    let reread = store
        .get_event(stored.transfer_id)?
        .ok_or_else(|| NodeError::Demo("verified demo Event disappeared".into()))?;
    if &reread != stored {
        return Err(NodeError::Demo(
            "demo Event changed between stopped-state reads".into(),
        ));
    }
    let route = sealer.verify_event(&reread.sealed)?;
    verify_stored_claim(
        &route,
        reread.transfer_id,
        reread.semantic_id,
        &reread.header,
    )?;
    match sealer.verify_event_content(route, &reread.sealed)? {
        EventContentVerification::ContentVerified { event, payload } => {
            verify_content_stored_claim(&event, &reread)?;
            if payload != expected_payload {
                return Err(NodeError::Demo(
                    "demo Event authenticated content differs from expectation".into(),
                ));
            }
            Ok(())
        }
        EventContentVerification::RouteOnly(_) => Err(NodeError::Demo(
            "demo endpoint lacks required Event content authorization".into(),
        )),
    }
}

fn verify_payload_blind_relays(
    states: &[PathBuf],
    missions: &[DemoMission],
    ping: &StoredEvent,
    pong: &StoredEvent,
) -> Result<(), NodeError> {
    for index in 1..states.len().saturating_sub(1) {
        let (store, mut sealer) = open_demo_store(&states[index], &missions[index])?;
        let policy = store.control_policy_snapshot()?;
        let stats = store.event_stats()?;
        if stats.events != 0
            || stats.acceptance_markers != 0
            || stats.route_cached != 2
            || store.event_count()? != 0
        {
            return Err(NodeError::Demo(format!(
                "relay node {index} crossed the content/semantic boundary: events={} markers={} route_cached={}",
                stats.events, stats.acceptance_markers, stats.route_cached
            )));
        }
        for expected in [ping, pong] {
            let Some(StoredEventTransfer::RouteCached(cached)) =
                store.get_transfer_with_policy(&policy, expected.transfer_id)?
            else {
                return Err(NodeError::Demo(format!(
                    "relay node {index} did not retain transfer {} only in its route cache",
                    format_transfer_id(expected.transfer_id)
                )));
            };
            if cached.sealed != expected.sealed
                || cached.semantic_claim != expected.semantic_id
                || cached.header_claim != expected.header
            {
                return Err(NodeError::Demo(format!(
                    "relay node {index} changed an exact source-sealed representation"
                )));
            }
            let route = sealer.verify_event(&cached.sealed)?;
            verify_stored_claim(
                &route,
                cached.transfer_id,
                cached.semantic_claim,
                &cached.header_claim,
            )?;
            if !matches!(
                sealer.verify_event_content(route, &cached.sealed)?,
                EventContentVerification::RouteOnly(_)
            ) {
                return Err(NodeError::Demo(format!(
                    "relay node {index} unexpectedly opened Event content"
                )));
            }
        }
    }
    Ok(())
}

fn require_exact_event_difference(
    source_state: &Path,
    source_mission: &DemoMission,
    destination_state: &Path,
    destination_mission: &DemoMission,
    expected: &StoredEvent,
    label: &str,
) -> Result<(), NodeError> {
    let (source_store, mut source_sealer) = open_demo_store(source_state, source_mission)?;
    let source_policy = source_store.control_policy_snapshot()?;
    let source_inventory = source_store.transfer_inventory_with_policy(&source_policy)?;
    let (destination_store, _) = open_demo_store(destination_state, destination_mission)?;
    let destination_policy = destination_store.control_policy_snapshot()?;
    let destination_inventory =
        destination_store.transfer_inventory_with_policy(&destination_policy)?;
    let source_only = source_inventory
        .iter()
        .copied()
        .filter(|id| {
            !destination_inventory
                .iter()
                .any(|candidate| candidate == id)
        })
        .collect::<Vec<_>>();
    let destination_only = destination_inventory
        .iter()
        .copied()
        .filter(|id| !source_inventory.iter().any(|candidate| candidate == id))
        .collect::<Vec<_>>();
    if source_only.as_slice() != [expected.transfer_id] || !destination_only.is_empty() {
        return Err(NodeError::Demo(format!(
            "{label} edge does not begin with exactly the expected source-only Event transfer"
        )));
    }
    let exact = load_verified_transfer(
        &source_store,
        &source_policy,
        &mut source_sealer,
        expected.transfer_id,
    )?;
    if exact != expected.sealed {
        return Err(NodeError::Demo(format!(
            "{label} source changed the exact source-sealed representation before contact"
        )));
    }
    Ok(())
}

fn require_single_event_transfer_receipt(
    root: &Path,
    phase: &str,
    source: usize,
    destination: usize,
) -> Result<(), NodeError> {
    let source_path = root.join("logs").join(format!("{phase}-node-{source}.log"));
    let destination_path = root
        .join("logs")
        .join(format!("{phase}-node-{destination}.log"));
    let source_output = fs::read_to_string(&source_path)?;
    let destination_output = fs::read_to_string(&destination_path)?;
    let controls_are_zero = |line: &str| {
        [
            "control_offered",
            "control_fetched",
            "control_retained",
            "control_duplicates",
            "control_activated",
            "control_remaining",
        ]
        .into_iter()
        .all(|field| receipt_counter(line, field) == Some(0))
    };
    let offered = source_output.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.ends_with("status=pass")
            && controls_are_zero(line)
            && receipt_counter(line, "offered") == Some(1)
            && receipt_counter(line, "fetched") == Some(0)
            && receipt_counter(line, "inserted") == Some(0)
            && receipt_counter(line, "duplicates") == Some(0)
            && receipt_counter(line, "remaining") == Some(0)
    });
    let fetched = destination_output.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.ends_with("status=pass")
            && controls_are_zero(line)
            && receipt_counter(line, "offered") == Some(0)
            && receipt_counter(line, "fetched") == Some(1)
            && receipt_counter(line, "inserted") == Some(1)
            && receipt_counter(line, "duplicates") == Some(0)
            && receipt_counter(line, "remaining") == Some(0)
    });
    if !offered || !fetched {
        return Err(NodeError::Demo(format!(
            "{phase} did not reconcile exactly one pre-existing Event from node {source} to node {destination}; source_log={} destination_log={}",
            source_path.display(),
            destination_path.display()
        )));
    }
    Ok(())
}

fn require_application_receipt(
    root: &Path,
    phase: &str,
    node: usize,
    status: &str,
    kind: &str,
) -> Result<(), NodeError> {
    let path = root.join("logs").join(format!("{phase}-node-{node}.log"));
    let output = fs::read_to_string(&path)?;
    let expected = format!("APPLICATION status={status} kind={kind} ");
    if !output.lines().any(|line| line.starts_with(&expected)) {
        return Err(NodeError::Demo(format!(
            "{phase} node {node} omitted {status} {kind} application receipt; log={}",
            path.display()
        )));
    }
    Ok(())
}

fn require_event_convergence(
    states: &[PathBuf],
    missions: &[DemoMission],
    expected_transfers: usize,
) -> Result<(), NodeError> {
    require_event_convergence_at(states, missions, expected_transfers, 0)
}

fn require_event_convergence_at(
    states: &[PathBuf],
    missions: &[DemoMission],
    expected_transfers: usize,
    node_base: usize,
) -> Result<(), NodeError> {
    if states.len() != missions.len() {
        return Err(NodeError::Configuration(
            "demo state and mission slices differ".into(),
        ));
    }
    let mut canonical: Option<Vec<(EventTransferId, Vec<u8>)>> = None;
    for (offset, (state, mission)) in states.iter().zip(missions).enumerate() {
        let node = node_base + offset;
        let (store, mut sealer) = open_demo_store(state, mission)?;
        let opaque = store.stats()?;
        if opaque.items != 0 || opaque.acceptance_markers != 0 || opaque.total_payload_bytes != 0 {
            return Err(NodeError::Demo(format!(
                "demo node {node} unexpectedly used the retained opaque namespace"
            )));
        }
        let policy = store.control_policy_snapshot()?;
        let inventory = store.transfer_inventory_with_policy(&policy)?;
        if inventory.len() != expected_transfers {
            return Err(NodeError::Demo(format!(
                "demo node {node} has {} exact Event transfers; expected {expected_transfers}",
                inventory.len()
            )));
        }
        let rows = inventory
            .iter()
            .copied()
            .map(|id| {
                load_verified_transfer(&store, &policy, &mut sealer, id).map(|bytes| (id, bytes))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(expected) = &canonical {
            if &rows != expected {
                return Err(NodeError::Demo(format!(
                    "demo node {node} differs in exact Event transfer identity or bytes"
                )));
            }
        } else {
            canonical = Some(rows);
        }
    }
    Ok(())
}

struct DemoMission {
    path: PathBuf,
    identity: NodeId,
}

impl DemoMission {
    const fn identity(&self) -> NodeId {
        self.identity
    }

    fn load(&self) -> Result<UnprotectedReferenceMission, NodeError> {
        Ok(UnprotectedReferenceMission::load(&self.path)?)
    }
}

struct DemoTopology<'a> {
    root: &'a Path,
    states: &'a [PathBuf],
    identities: &'a [EndpointId],
    missions: &'a [DemoMission],
    addresses: &'a [SocketAddr],
}

fn run_demo_phase(
    topology: &DemoTopology<'_>,
    phase: &str,
    active: &[usize],
    applications: &[NodeApplication],
) -> Result<(), NodeError> {
    run_demo_phase_internal(topology, phase, active, applications, true)
}

fn run_demo_denied_phase(
    topology: &DemoTopology<'_>,
    phase: &str,
    active: &[usize],
    applications: &[NodeApplication],
) -> Result<(), NodeError> {
    run_demo_phase_internal(topology, phase, active, applications, false)
}

fn run_demo_phase_internal(
    topology: &DemoTopology<'_>,
    phase: &str,
    active: &[usize],
    applications: &[NodeApplication],
    require_successful_contacts: bool,
) -> Result<(), NodeError> {
    let DemoTopology {
        root,
        states,
        identities,
        missions,
        addresses,
    } = topology;
    if applications.len() != states.len() {
        return Err(NodeError::Configuration(
            "demo application-role count differs from state count".into(),
        ));
    }
    let executable = std::env::current_exe()?;
    let logs = root.join("logs");
    fs::create_dir_all(&logs)?;
    let mut children = Vec::new();
    let active = active.iter().copied().collect::<BTreeSet<_>>();
    // A line's propagation diameter grows with the active cohort. This is an
    // orchestration watchdog, not a throughput target: leave one second per
    // active node plus two seconds for process startup and QUIC scheduling so
    // the advertised node range does not inherit the three-node deadline.
    let run_seconds = demo_run_seconds(active.len());
    for &index in &active {
        let log_path = logs.join(format!("{phase}-node-{index}.log"));
        let error_path = logs.join(format!("{phase}-node-{index}.err"));
        let mut command = Command::new(&executable);
        command
            .arg("node")
            .arg("--state")
            .arg(&states[index])
            .arg("--bind")
            .arg(addresses[index].to_string())
            .arg("--mission-bundle-unprotected-reference")
            .arg(states[index].join(DEMO_MISSION_BUNDLE_FILE))
            .arg("--sync-ms")
            .arg("100")
            .arg("--run-for")
            .arg(run_seconds.to_string())
            .arg("--application")
            .arg(applications[index].as_str());
        for neighbor in neighbors(index, states.len()) {
            if !active.contains(&neighbor) {
                continue;
            }
            command.arg("--peer").arg(
                MissionExpectedPeer {
                    carrier: ExpectedPeer {
                        id: identities[neighbor],
                        address: addresses[neighbor],
                    },
                    mission: missions[neighbor].identity(),
                }
                .to_string(),
            );
        }
        let child = command
            .stdout(Stdio::from(File::create(&log_path)?))
            .stderr(Stdio::from(File::create(&error_path)?))
            .spawn()?;
        children.push((index, child, log_path, error_path, None));
    }
    let deadline = Instant::now() + Duration::from_secs(run_seconds + 15);
    loop {
        let mut all_finished = true;
        for (_, child, _, _, status) in &mut children {
            if status.is_none() {
                *status = child.try_wait()?;
            }
            all_finished &= status.is_some();
        }
        if all_finished {
            break;
        }
        if Instant::now() >= deadline {
            for (_, child, _, _, status) in &mut children {
                if status.is_none() {
                    let _ = child.kill();
                    *status = Some(child.wait()?);
                }
            }
            return Err(NodeError::Demo(format!(
                "{phase} exceeded its {}-second parent deadline",
                run_seconds + 15
            )));
        }
        thread::sleep(Duration::from_millis(25));
    }
    for (index, _, log_path, error_path, status) in children {
        let status = status.ok_or_else(|| NodeError::Demo("child status disappeared".into()))?;
        if !status.success() {
            return Err(NodeError::Demo(format!(
                "{phase} node {index} exited {status}; stdout={} stderr={}",
                log_path.display(),
                error_path.display()
            )));
        }
    }
    if require_successful_contacts {
        verify_phase_contacts(phase, &active, identities, missions, &logs)?;
    }
    let has_active_edge = active.iter().any(|index| {
        index
            .checked_add(1)
            .is_some_and(|right| active.contains(&right))
    });
    println!(
        "PHASE status=pass name={} processes={} carrier_authenticated_edges={} mission_authenticated_edges={} provisioning=unprotected-reference",
        phase,
        active.len(),
        if require_successful_contacts {
            if has_active_edge {
                "verified"
            } else {
                "not-applicable"
            }
        } else {
            "denied-as-required"
        },
        if require_successful_contacts {
            if has_active_edge {
                "verified"
            } else {
                "not-applicable"
            }
        } else {
            "denied-as-required"
        },
    );
    Ok(())
}

fn demo_run_seconds(active_nodes: usize) -> u64 {
    u64::try_from(active_nodes)
        .unwrap_or(u64::MAX)
        .saturating_add(2)
        .max(3)
}

fn verify_phase_contacts(
    phase: &str,
    active: &BTreeSet<usize>,
    identities: &[EndpointId],
    missions: &[DemoMission],
    logs: &Path,
) -> Result<(), NodeError> {
    for left in 0..identities.len().saturating_sub(1) {
        let right = left + 1;
        if !active.contains(&left) || !active.contains(&right) {
            continue;
        }
        let (initiator, remote, remote_mission) = if identities[left] < identities[right] {
            (left, identities[right], missions[right].identity())
        } else {
            (right, identities[left], missions[left].identity())
        };
        let log_path = logs.join(format!("{phase}-node-{initiator}.log"));
        let output = fs::read_to_string(&log_path)?;
        let prefix = format!(
            "CONTACT direction=out carrier_peer={remote} mission_peer={} ",
            format_node_id(remote_mission)
        );
        let contacts = output
            .lines()
            .filter(|line| {
                line.starts_with(&prefix)
                    && line.ends_with("status=pass")
                    && line.contains(" mission_auth=hybrid-pq ")
                    && receipt_counter(line, "handshake_frames") == Some(4)
                    && receipt_counter(line, "handshake_bytes").is_some_and(|bytes| bytes > 0)
                    && receipt_counter(line, "protected_frames").is_some_and(|frames| frames > 0)
                    && receipt_counter(line, "protected_bytes").is_some_and(|bytes| bytes > 0)
            })
            .collect::<Vec<_>>();
        if contacts.is_empty() {
            return Err(NodeError::Demo(format!(
                "{phase} has no successful carrier-and-mission-authenticated contact for edge {left}<->{right}; log={}",
                log_path.display()
            )));
        }
        if phase == "noop"
            && contacts
                .iter()
                .any(|line| !line.contains("offered=0 fetched=0 inserted=0 duplicates=0"))
        {
            return Err(NodeError::Demo(format!(
                "{phase} transferred an item despite equal inventories on edge {left}<->{right}"
            )));
        }
    }
    Ok(())
}

fn receipt_counter(line: &str, field: &str) -> Option<usize> {
    let prefix = format!("{field}=");
    line.split_ascii_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))?
        .parse()
        .ok()
}

fn neighbors(index: usize, count: usize) -> Vec<usize> {
    let mut output = Vec::new();
    if index > 0 {
        output.push(index - 1);
    }
    if index + 1 < count {
        output.push(index + 1);
    }
    output
}

fn find_port_block(count: usize) -> Result<u16, NodeError> {
    let start = 32_000u16.saturating_add((std::process::id() % 20_000) as u16);
    for offset in 0..256u16 {
        let candidate = start.saturating_add(offset.saturating_mul(37));
        if candidate.checked_add(count as u16).is_none() {
            continue;
        }
        if validate_port_block(candidate, count).is_ok() {
            return Ok(candidate);
        }
    }
    Err(NodeError::Demo(
        "could not find a free loopback UDP port block".into(),
    ))
}

fn validate_port_block(base: u16, count: usize) -> Result<(), NodeError> {
    if base == 0 || base.checked_add(count as u16).is_none() {
        return Err(NodeError::Configuration(
            "base port does not leave room for every node".into(),
        ));
    }
    let sockets = (0..count)
        .map(|index| UdpSocket::bind(("127.0.0.1", base + index as u16)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            NodeError::Configuration(format!("demo port block unavailable: {error}"))
        })?;
    drop(sockets);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mission::initiate_over_iroh;

    struct IssuedMission {
        credentials: UnprotectedReferenceMission,
        identity: NodeId,
    }

    fn issue_missions(count: u64) -> Vec<IssuedMission> {
        let access = ProvisioningAccess::member(
            Scope::new("test/runtime-contact").expect("scope"),
            vec![1],
            vec![Topic::new("opaque").expect("topic")],
        )
        .expect("access");
        let mut provisioner = ReferenceProvisioner::from_seed([0x72; 32]).expect("provisioner");
        (1..=count)
            .map(|serial| {
                let bundle = provisioner
                    .issue_node(serial, std::slice::from_ref(&access))
                    .expect("issue node");
                let credentials = UnprotectedReferenceMission::from_bytes(
                    bundle.to_bytes().expect("encode bundle"),
                )
                .expect("parse bundle");
                IssuedMission {
                    identity: credentials.identity(),
                    credentials,
                }
            })
            .collect()
    }

    fn exact_event_interest(topic: &Topic, scope: &Scope) -> EventInterest {
        EventInterest::new(vec![EventInterestSelector::new(
            topic.clone(),
            scope.clone(),
            false,
        )])
        .expect("bounded exact Event interest")
    }

    fn seed_test_event_subscription(
        store: &Store,
        mode: EventSubscriptionMode,
        topic: &Topic,
        scope: &Scope,
        key: &[u8],
    ) {
        let policy = store
            .control_policy_snapshot()
            .expect("settled subscription policy");
        store
            .create_event_subscription_with_policy(
                &policy,
                &EventSubscriptionKey::new(key.to_vec()).expect("subscription key"),
                EventSubscriptionSpec {
                    mode,
                    topic: topic.clone(),
                    scope: scope.clone(),
                    include_descendant_scopes: false,
                },
            )
            .expect("create explicit test Event subscription");
    }

    fn loopback(endpoint: &Endpoint) -> SocketAddr {
        endpoint
            .bound_sockets()
            .into_iter()
            .find(SocketAddr::is_ipv4)
            .expect("IPv4 loopback binding")
    }

    async fn finish_equal_difference(
        connection: &aster_iroh::Connection,
        mission: &mut MissionSession,
        inventory: aster_profile::InventorySnapshot,
        interest: EventInterest,
    ) -> PeerReceipt {
        let limits = ReconciliationLimits::default();
        let mut receipt = PeerReceipt {
            peer: Some(connection.remote_id()),
            mission_peer: Some(mission.peer().mission_id()),
            ..PeerReceipt::default()
        };
        let control_inventory = InventorySnapshot::default();
        let mut control_initiator =
            Initiator::new(&control_inventory, limits).expect("control initiator");
        let mut control_query = control_initiator.initiate().expect("control query");
        loop {
            let Frame::ControlInventoryReply(response) = request_mission_frame(
                connection,
                mission,
                Frame::ControlInventoryQuery(control_query),
                &mut receipt,
            )
            .await
            .expect("control inventory response") else {
                panic!("control inventory response frame differs");
            };
            match control_initiator
                .reconcile_response(&response)
                .expect("control reconcile response")
            {
                InitiatorStep::Continue(next) => control_query = next,
                InitiatorStep::Complete(difference) => {
                    assert!(difference.is_empty());
                    break;
                }
            }
        }
        assert_eq!(
            request_mission_frame(
                connection,
                mission,
                Frame::ControlInventoryComplete,
                &mut receipt,
            )
            .await
            .expect("control inventory complete"),
            Frame::ControlInventoryCompleteAck
        );
        let mut control_reverse =
            Responder::new(&control_inventory, limits).expect("control reverse responder");
        loop {
            let wire_budget = exchange_wire_budget(&receipt).expect("control wire budget");
            let (complete, request_bytes, response_bytes) =
                respond_mission_frame(connection, mission, wire_budget, |frame, _| match frame {
                    Frame::ControlDifferenceQuery(query) => Ok((
                        Frame::ControlDifferenceReply(control_reverse.reconcile_query(&query)?),
                        false,
                    )),
                    Frame::ControlDifferenceBound if control_reverse.rounds() > 0 => {
                        Ok((Frame::ControlDifferenceBoundAck, true))
                    }
                    _ => Err(NodeError::Protocol(
                        "test control reverse phase differs".into(),
                    )),
                })
                .await
                .expect("control reverse response");
            account(&mut receipt, request_bytes, response_bytes).expect("account control reverse");
            if complete {
                break;
            }
        }
        assert_eq!(
            request_mission_frame(connection, mission, Frame::ControlFinish, &mut receipt)
                .await
                .expect("control finish"),
            Frame::ControlFinished
        );

        assert!(matches!(
            request_mission_frame(
                connection,
                mission,
                Frame::EventInterest(interest),
                &mut receipt,
            )
            .await
            .expect("protected interest response"),
            Frame::EventInterestReply(interest) if interest.is_empty()
        ));

        let direction = EventDirection::ToSessionResponder;
        let mut initiator = Initiator::new(&inventory, limits).expect("initiator");
        let mut query = initiator.initiate().expect("initial query");
        loop {
            let Frame::InventoryReply {
                direction: response_direction,
                bytes: response,
            } = request_mission_frame(
                connection,
                mission,
                Frame::InventoryQuery {
                    direction,
                    bytes: query,
                },
                &mut receipt,
            )
            .await
            .expect("inventory response")
            else {
                panic!("inventory response frame differs");
            };
            assert_eq!(response_direction, direction);
            match initiator
                .reconcile_response(&response)
                .expect("reconcile response")
            {
                InitiatorStep::Continue(next) => query = next,
                InitiatorStep::Complete(difference) => {
                    assert!(difference.is_empty());
                    break;
                }
            }
        }
        assert_eq!(
            request_mission_frame(
                connection,
                mission,
                Frame::InventoryComplete { direction },
                &mut receipt,
            )
            .await
            .expect("inventory complete"),
            Frame::InventoryCompleteAck { direction }
        );
        let mut reverse = Responder::new(&inventory, limits).expect("reverse responder");
        loop {
            let wire_budget = exchange_wire_budget(&receipt).expect("wire budget");
            let (complete, request_bytes, response_bytes) =
                respond_mission_frame(connection, mission, wire_budget, |frame, _| match frame {
                    Frame::DifferenceQuery {
                        direction: request_direction,
                        bytes: query,
                    } if request_direction == direction => Ok((
                        Frame::DifferenceReply {
                            direction,
                            bytes: reverse.reconcile_query(&query)?,
                        },
                        false,
                    )),
                    Frame::DifferenceBound {
                        direction: request_direction,
                    } if request_direction == direction && reverse.rounds() > 0 => {
                        Ok((Frame::DifferenceBoundAck { direction }, true))
                    }
                    _ => Err(NodeError::Protocol("test reverse phase differs".into())),
                })
                .await
                .expect("reverse response");
            account(&mut receipt, request_bytes, response_bytes).expect("account reverse");
            if complete {
                break;
            }
        }
        receipt
    }

    async fn reconcile_equal_event_lane(
        connection: &aster_iroh::Connection,
        mission: &mut MissionSession,
        inventory: InventorySnapshot,
        direction: EventDirection,
        receipt: &mut PeerReceipt,
    ) {
        let limits = ReconciliationLimits::default();
        let mut initiator = Initiator::new(&inventory, limits).expect("lane initiator");
        let mut query = initiator.initiate().expect("lane initial query");
        loop {
            let Frame::InventoryReply {
                direction: response_direction,
                bytes: response,
            } = request_mission_frame(
                connection,
                mission,
                Frame::InventoryQuery {
                    direction,
                    bytes: query,
                },
                receipt,
            )
            .await
            .expect("lane inventory response")
            else {
                panic!("lane inventory response frame differs");
            };
            assert_eq!(response_direction, direction);
            match initiator
                .reconcile_response(&response)
                .expect("lane reconcile response")
            {
                InitiatorStep::Continue(next) => query = next,
                InitiatorStep::Complete(difference) => {
                    assert!(
                        difference.is_empty(),
                        "directional reconciliation disclosed an unauthorized difference"
                    );
                    break;
                }
            }
        }
        assert_eq!(
            request_mission_frame(
                connection,
                mission,
                Frame::InventoryComplete { direction },
                receipt,
            )
            .await
            .expect("lane inventory complete"),
            Frame::InventoryCompleteAck { direction }
        );
        let mut reverse = Responder::new(&inventory, limits).expect("lane reverse responder");
        loop {
            let wire_budget = exchange_wire_budget(receipt).expect("lane wire budget");
            let (complete, request_bytes, response_bytes) =
                respond_mission_frame(connection, mission, wire_budget, |frame, _| match frame {
                    Frame::DifferenceQuery {
                        direction: request_direction,
                        bytes: query,
                    } if request_direction == direction => Ok((
                        Frame::DifferenceReply {
                            direction,
                            bytes: reverse.reconcile_query(&query)?,
                        },
                        false,
                    )),
                    Frame::DifferenceBound {
                        direction: request_direction,
                    } if request_direction == direction && reverse.rounds() > 0 => {
                        Ok((Frame::DifferenceBoundAck { direction }, true))
                    }
                    _ => Err(NodeError::Protocol(
                        "test directional reverse phase differs".into(),
                    )),
                })
                .await
                .expect("lane reverse response");
            account(receipt, request_bytes, response_bytes).expect("account lane reverse");
            if complete {
                break;
            }
        }
    }

    async fn reject_hostile_transfer(frame: Frame, label: &str) {
        let mut issued = issue_missions(2);
        let client_mission = issued.remove(0);
        let server_mission = issued.remove(0);
        let server = Endpoint::bind(
            aster_iroh::SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("server address")),
        )
        .await
        .expect("server endpoint");
        let client = Endpoint::bind(
            aster_iroh::SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("client address")),
        )
        .await
        .expect("client endpoint");
        let server_root = root(&format!("hostile-{label}-server"));
        fs::create_dir_all(&server_root).expect("server root");
        let server_authority = ReferenceEnvelopeSealer::open(
            server_mission
                .credentials
                .fresh_bundle()
                .expect("server bundle"),
        )
        .expect("server sealer")
        .mission_authority_id();
        let server_store = Arc::new(
            Store::open_for_mission(server_root.join(STORE_FILE), server_authority)
                .expect("server store"),
        );
        let server_task = tokio::spawn({
            let server = server.clone();
            let server_store = server_store.clone();
            let credentials = server_mission.credentials.clone();
            let allowed = BTreeSet::from([client.id()]);
            let peer = MissionPeerBinding::new(client.id(), client_mission.identity);
            async move {
                let connection = server.accept(&allowed).await.expect("accept carrier");
                serve_connection(
                    server_store,
                    connection,
                    credentials,
                    peer,
                    Arc::new(RwLock::new(())),
                )
                .await
            }
        });

        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect carrier");
        let mut mission = initiate_over_iroh(
            &connection,
            client_mission.credentials.fresh_bundle().expect("bundle"),
            MissionPeerBinding::new(server.id(), server_mission.identity),
        )
        .await
        .expect("mission handshake");
        let mut receipt = finish_equal_difference(
            &connection,
            &mut mission,
            aster_profile::InventorySnapshot::default(),
            EventInterest::empty(),
        )
        .await;
        let client_error = request_mission_frame(&connection, &mut mission, frame, &mut receipt)
            .await
            .expect_err("out-of-difference transfer must fail");
        assert!(
            matches!(client_error, NodeError::Carrier(_) | NodeError::Mission(_)),
            "unexpected client rejection: {client_error}"
        );
        let server_error = server_task
            .await
            .expect("server task")
            .expect_err("server must reject transfer");
        assert!(
            server_error
                .to_string()
                .contains("outside this authenticated contact's negotiated difference")
                || server_error
                    .to_string()
                    .contains("transfer crossed Event lanes"),
            "unexpected server rejection: {server_error}"
        );
        let stats = server_store.stats().expect("server stats");
        assert_eq!(stats.items, 0);
        assert_eq!(stats.acceptance_markers, 0);
        assert_eq!(server_store.event_count().expect("Event count"), 0);
        client.close().await;
        server.close().await;
        fs::remove_dir_all(server_root).expect("cleanup");
    }

    fn root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("aster-node-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        path
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_zeroization_socket_is_owner_only_and_exact_state_bound() {
        let state = root("local-zeroization-control");
        fs::create_dir_all(&state).expect("state");
        let store_path = state.join(STORE_FILE);
        fs::write(&store_path, b"exact-store-identity").expect("store identity file");
        let mission_path = state.join("mission.bundle");
        fs::write(&mission_path, b"bounded-test-secret").expect("mission artifact");
        fs::set_permissions(&mission_path, fs::Permissions::from_mode(0o600))
            .expect("owner-only mission permissions");

        let control = LocalZeroizationControl::bind(&state, &store_path).expect("bind control");
        let socket_metadata = fs::symlink_metadata(&control.socket_path).expect("socket metadata");
        assert!(socket_metadata.file_type().is_socket());
        assert_eq!(socket_metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(socket_metadata.uid(), rustix::process::geteuid().as_raw());

        let server = tokio::spawn(async move {
            let request = control.accept().await.expect("same-owner request");
            assert_eq!(
                request.binding.mission.canonical_path,
                fs::canonicalize(&mission_path).expect("canonical mission")
            );
            request.respond("ASTER-ZEROIZE-LOCAL-OK").await
        });
        let response = request_live_zeroization(
            &state,
            &state.join("mission.bundle"),
            Duration::from_secs(5),
        )
        .await
        .expect("request")
        .expect("live response");
        assert_eq!(response, "ASTER-ZEROIZE-LOCAL-OK");
        server.await.expect("server task").expect("server response");
        fs::remove_dir_all(state).expect("cleanup state");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_zeroization_integrity_failure_stops_accept_loop() {
        let state = root("local-zeroization-integrity-failure");
        fs::create_dir_all(&state).expect("state");
        let store_path = state.join(STORE_FILE);
        fs::write(&store_path, b"exact-store-identity").expect("store identity file");
        let control = LocalZeroizationControl::bind(&state, &store_path).expect("bind control");
        let socket_path = control.socket_path.clone();
        let displaced_socket = socket_path.with_extension("sock.displaced");

        let (sender, mut receiver) = mpsc::channel(1);
        let task = tokio::spawn(run_local_zeroization_accept_loop(control, sender, None));
        sleep(LOCAL_ZEROIZATION_INTEGRITY_INTERVAL + Duration::from_millis(50)).await;
        fs::rename(&socket_path, &displaced_socket).expect("displace socket after accept began");
        let failure = timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("integrity failure deadline")
            .expect("one integrity failure");
        let error = match failure {
            Err(error) => error,
            Ok(_) => panic!("replaced store accepted a local zeroization request"),
        };
        assert!(error.is_integrity_failure());
        let _ = error.into_node_error();
        let closed = timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("accept loop closure deadline");
        assert!(
            closed.is_none(),
            "integrity failure was reported more than once"
        );
        task.await.expect("accept loop task");
        fs::remove_file(displaced_socket).expect("remove displaced socket");
        fs::remove_dir_all(state).expect("cleanup state");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn local_zeroization_directory_permission_loss_stops_accept_loop() {
        struct RestoreOwnerOnlyMode(PathBuf);

        impl Drop for RestoreOwnerOnlyMode {
            fn drop(&mut self) {
                let _ = fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700));
            }
        }

        let temporary_root = fs::canonicalize("/tmp").expect("canonical temporary root");
        let state = temporary_root.join(format!("aster-zdir-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&state);
        fs::create_dir_all(&state).expect("state");
        let store_path = state.join(STORE_FILE);
        fs::write(&store_path, b"exact-store-identity").expect("store identity file");
        let control_directory = state.join("control");
        let control = LocalZeroizationControl::bind_in_control_directory(
            &state,
            &store_path,
            &control_directory,
        )
        .expect("bind isolated control");
        let socket_path = control.socket_path.clone();
        let directory_path = control.control_directory.canonical_path.clone();
        let _restore_mode = RestoreOwnerOnlyMode(directory_path.clone());

        let (sender, mut receiver) = mpsc::channel(1);
        let task = tokio::spawn(run_local_zeroization_accept_loop(control, sender, None));
        sleep(LOCAL_ZEROIZATION_INTEGRITY_INTERVAL + Duration::from_millis(50)).await;
        fs::set_permissions(&directory_path, fs::Permissions::from_mode(0o750))
            .expect("make control directory unsafe after accept began");
        let failure = timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("directory integrity failure deadline")
            .expect("one directory integrity failure");
        let error = match failure {
            Err(error) => error,
            Ok(_) => panic!("unsafe control directory accepted a zeroization request"),
        };
        assert!(error.is_integrity_failure());
        let _ = error.into_node_error();
        let closed = timeout(Duration::from_secs(2), receiver.recv())
            .await
            .expect("accept loop closure deadline");
        assert!(
            closed.is_none(),
            "directory integrity failure was reported more than once"
        );
        task.await.expect("accept loop task");
        fs::set_permissions(&directory_path, fs::Permissions::from_mode(0o700))
            .expect("restore owner-only control directory");
        assert!(!socket_path.exists(), "control drop retained its socket");
        fs::remove_dir_all(state).expect("cleanup state");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn zeroization_waits_for_live_socket_during_writer_startup_window() {
        let root = root("zeroization-live-socket-startup-window");
        let state = root.join("state");
        let mission_path = root.join("mission.bundle");
        fs::create_dir_all(&state).expect("state");
        persist_zeroization_test_mission(&mission_path, 0xb6);
        let mission = UnprotectedReferenceMission::load(&mission_path).expect("mission");
        let mission_authority = mission.mission_authority_id();
        let store_path = state.join(STORE_FILE);

        let zeroize_state = state.clone();
        let zeroize_mission = mission_path.clone();
        let zeroize_task = tokio::spawn(async move {
            zeroize_node(&zeroize_state, &zeroize_mission, Duration::from_secs(3)).await
        });

        // Match the CLI's real startup ordering: main has retained the mission
        // artifact before run_node creates redb, then redb is writer-open
        // before the carrier identity and local control socket exist.
        sleep(LOCAL_ZEROIZATION_INTEGRITY_INTERVAL).await;
        let store = Store::open_for_mission(&store_path, mission_authority).expect("live writer");
        let identity = NodeIdentity::load_or_create(&state).expect("live identity");
        sleep(LOCAL_ZEROIZATION_INTEGRITY_INTERVAL).await;
        let control = LocalZeroizationControl::bind(&state, &store_path).expect("late bind");
        let server = tokio::spawn(async move {
            let request = control.accept().await.expect("late live request");
            request
                .respond("ASTER-ZEROIZE-LOCAL-ERROR startup-window-test")
                .await
        });

        let error = timeout(Duration::from_secs(3), zeroize_task)
            .await
            .expect("zeroization discovery deadline")
            .expect("zeroization task")
            .expect_err("test live endpoint deliberately rejects cleanup");
        assert!(
            error.to_string().contains("startup-window-test"),
            "late live endpoint was not reached: {error}"
        );
        server.await.expect("server task").expect("server response");
        drop(identity);
        drop(store);
        drop(mission);
        fs::remove_dir_all(root).expect("cleanup root");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn hardlinked_store_alias_fails_before_zeroization_or_node_bind() {
        let root = root("zeroization-hardlinked-store-alias");
        let first_state = root.join("first-state");
        let aliased_state = root.join("aliased-state");
        let first_mission_path = root.join("first.bundle");
        let aliased_mission_path = root.join("aliased.bundle");
        fs::create_dir_all(&first_state).expect("first state");
        fs::create_dir_all(&aliased_state).expect("aliased state");

        let access = ProvisioningAccess::member(
            Scope::new("test/zeroization-hardlink").expect("scope"),
            vec![1],
            vec![Topic::new("zeroization-hardlink").expect("topic")],
        )
        .expect("access");
        let mut provisioner = ReferenceProvisioner::from_seed([0xb7; 32]).expect("provisioner");
        let first_bytes = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .expect("first bundle")
            .to_bytes()
            .expect("encode first bundle");
        let aliased_bytes = provisioner
            .issue_node(2, std::slice::from_ref(&access))
            .expect("aliased bundle")
            .to_bytes()
            .expect("encode aliased bundle");
        let first_mission = UnprotectedReferenceMission::persist(&first_mission_path, first_bytes)
            .expect("persist first mission");
        let mission_authority = first_mission.mission_authority_id();
        drop(first_mission);
        drop(
            UnprotectedReferenceMission::persist(&aliased_mission_path, aliased_bytes)
                .expect("persist aliased mission"),
        );
        drop(NodeIdentity::load_or_create(&first_state).expect("first identity"));
        let aliased_identity =
            NodeIdentity::load_or_create(&aliased_state).expect("aliased identity");
        let aliased_identity_path = aliased_identity.path().to_path_buf();
        drop(aliased_identity);

        let first_store_path = first_state.join(STORE_FILE);
        drop(Store::open_for_mission(&first_store_path, mission_authority).expect("first store"));
        let aliased_store_path = aliased_state.join(STORE_FILE);
        fs::hard_link(&first_store_path, &aliased_store_path).expect("hardlink exact store");
        let store_before = fs::read(&first_store_path).expect("store before rejection");
        let mission_before = fs::read(&aliased_mission_path).expect("mission before rejection");
        let identity_before = fs::read(&aliased_identity_path).expect("identity before rejection");

        let zeroize_error = zeroize_node(
            &aliased_state,
            &aliased_mission_path,
            Duration::from_secs(1),
        )
        .await
        .expect_err("hardlinked store must reject zeroization");
        assert!(
            zeroize_error.to_string().contains("uniquely linked"),
            "unexpected hardlink rejection: {zeroize_error}"
        );
        assert_eq!(
            Store::inspect_zeroization_state(&first_store_path)
                .expect("inspect shared store")
                .state(),
            StoreZeroizationState::Live
        );
        assert_eq!(
            fs::read(&first_store_path).expect("store retained"),
            store_before
        );
        assert_eq!(
            fs::read(&aliased_mission_path).expect("mission retained"),
            mission_before
        );
        assert_eq!(
            fs::read(&aliased_identity_path).expect("identity retained"),
            identity_before
        );

        let mission =
            UnprotectedReferenceMission::load(&aliased_mission_path).expect("load mission");
        let node_error = run_node(NodeConfig {
            state: aliased_state.clone(),
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            mission,
            peers: Vec::new(),
            sync_interval: Duration::from_millis(10),
            run_for: Some(Duration::from_millis(10)),
            application: NodeApplication::Relay,
        })
        .await
        .expect_err("hardlinked store must reject node bind");
        assert!(
            node_error.to_string().contains("uniquely linked"),
            "unexpected node hardlink rejection: {node_error}"
        );
        assert_eq!(
            fs::read(&first_store_path).expect("store retained"),
            store_before
        );
        assert_eq!(
            fs::read(&aliased_mission_path).expect("mission retained"),
            mission_before
        );
        assert_eq!(
            fs::read(&aliased_identity_path).expect("identity retained"),
            identity_before
        );
        fs::remove_dir_all(root).expect("cleanup root");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_store_replacement_before_marker_preserves_both_artifacts() {
        let root = root("zeroization-live-store-replacement");
        let state = root.join("state");
        let mission_path = root.join("mission.bundle");
        fs::create_dir_all(&state).expect("state");
        persist_zeroization_test_mission(&mission_path, 0xb8);
        let mission = UnprotectedReferenceMission::load(&mission_path).expect("mission");
        let mission_authority = mission.mission_authority_id();
        let identity = NodeIdentity::load_or_create(&state).expect("identity");
        let identity_path = identity.path().to_path_buf();
        let store_path = state.join(STORE_FILE);
        let store =
            Arc::new(Store::open_for_mission(&store_path, mission_authority).expect("live store"));
        store.require_process_exclusive_lock().expect("store lock");
        let expected_store = local_store_identity(&store_path).expect("exact store identity");
        let prepared_mission = mission
            .prepare_software_erasure()
            .expect("prepare mission erasure");
        let prepared_identity = identity
            .prepare_software_erasure()
            .expect("prepare identity erasure");
        let plan = PreparedSoftwareZeroization {
            intent: ZeroizationIntent::new(
                prepared_mission.target().to_bytes(),
                prepared_identity.target().to_bytes(),
            )
            .expect("intent"),
            mission_authority,
            store_identity: Some(expected_store),
            mission: prepared_mission,
            identity: prepared_identity,
        };
        let mission_before = fs::read(&mission_path).expect("mission before replacement");
        let identity_before = fs::read(&identity_path).expect("identity before replacement");

        let displaced_store = state.join("mesh.displaced.redb");
        fs::rename(&store_path, &displaced_store).expect("displace live store pathname");
        drop(
            Store::open_for_mission(&store_path, mission_authority)
                .expect("safe unique replacement store"),
        );
        let error = finish_live_zeroization(store, plan, &state, &mission_path)
            .expect_err("replacement must fail before marker");
        assert!(
            error
                .to_string()
                .contains("changed after exact-state validation"),
            "unexpected replacement rejection: {error}"
        );
        assert_eq!(
            Store::inspect_zeroization_state(&displaced_store)
                .expect("original store status")
                .state(),
            StoreZeroizationState::Live
        );
        assert_eq!(
            Store::inspect_zeroization_state(&store_path)
                .expect("replacement store status")
                .state(),
            StoreZeroizationState::Live
        );
        assert_eq!(
            fs::read(&mission_path).expect("mission retained"),
            mission_before
        );
        assert_eq!(
            fs::read(&identity_path).expect("identity retained"),
            identity_before
        );
        drop(mission);
        drop(identity);
        fs::remove_dir_all(root).expect("cleanup root");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn swapped_cleanup_handle_cannot_hide_behind_restored_store_path() {
        let root = root("zeroization-cleanup-handle-swap-back");
        let state = root.join("state");
        let mission_path = root.join("mission.bundle");
        fs::create_dir_all(&state).expect("state");
        persist_zeroization_test_mission(&mission_path, 0xb9);
        let mission = UnprotectedReferenceMission::load(&mission_path).expect("mission");
        let mission_authority = mission.mission_authority_id();
        drop(mission);
        let identity = NodeIdentity::load_or_create(&state).expect("identity");
        let identity_path = identity.path().to_path_buf();
        drop(identity);
        let mission_before = fs::read(&mission_path).expect("mission before swap");
        let identity_before = fs::read(&identity_path).expect("identity before swap");

        let store_path = state.join(STORE_FILE);
        drop(Store::open_for_mission(&store_path, mission_authority).expect("original store"));
        let expected_store = local_store_identity(&store_path).expect("original identity");
        let displaced_original = state.join("mesh.original.redb");
        fs::rename(&store_path, &displaced_original).expect("displace original store");
        drop(Store::open_for_mission(&store_path, mission_authority).expect("replacement store"));
        let cleanup = Store::open_for_zeroization(&store_path).expect("open replacement cleanup");
        assert_ne!(
            cleanup.backing_identity().unix_device_inode(),
            Some(expected_store)
        );

        let displaced_replacement = state.join("mesh.replacement.redb");
        fs::rename(&store_path, &displaced_replacement).expect("retain replacement store");
        fs::rename(&displaced_original, &store_path).expect("restore original pathname");
        require_local_store_identity(&store_path, expected_store)
            .expect("pathname-only check is intentionally fooled");
        let error = require_store_backing_identity(cleanup.backing_identity(), expected_store)
            .expect_err("opened replacement handle must remain distinguishable");
        assert!(error.to_string().contains("opened store handle differs"));
        drop(cleanup);

        assert_eq!(
            Store::inspect_zeroization_state(&store_path)
                .expect("original status")
                .state(),
            StoreZeroizationState::Live
        );
        assert_eq!(
            Store::inspect_zeroization_state(&displaced_replacement)
                .expect("replacement status")
                .state(),
            StoreZeroizationState::Live
        );
        assert_eq!(
            fs::read(&mission_path).expect("mission retained"),
            mission_before
        );
        assert_eq!(
            fs::read(&identity_path).expect("identity retained"),
            identity_before
        );
        fs::remove_dir_all(root).expect("cleanup root");
    }

    fn persist_zeroization_test_mission(path: &Path, seed: u8) -> NodeId {
        let access = ProvisioningAccess::member(
            Scope::new("test/zeroization").expect("scope"),
            vec![1],
            vec![Topic::new("zeroization").expect("topic")],
        )
        .expect("access");
        let mut provisioner =
            ReferenceProvisioner::from_seed([seed; 32]).expect("zeroization provisioner");
        let bundle = provisioner
            .issue_node(1, &[access])
            .expect("zeroization bundle")
            .to_bytes()
            .expect("encode zeroization bundle");
        let mission =
            UnprotectedReferenceMission::persist(path, bundle).expect("persist test mission");
        let identity = mission.identity();
        drop(mission);
        identity
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_zeroization_closes_selected_event_admission_before_erasure() {
        use crate::application::{ApplicationErrorKind, EventPublishRequest};

        let root = root("zeroize-live-selected-event-actor");
        let state = root.join("state");
        let mission_path = root.join("mission.bundle");
        fs::create_dir_all(&state).expect("state");
        persist_zeroization_test_mission(&mission_path, 0xbd);
        let mission = UnprotectedReferenceMission::load(&mission_path).expect("mission");
        let running = start_node(NodeConfig {
            state: state.clone(),
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            mission,
            peers: Vec::new(),
            sync_interval: Duration::from_millis(10),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .expect("start live node");
        let selected = running.selected_events();
        selected
            .publish(EventPublishRequest {
                operation_key: b"zeroization-live-event".to_vec(),
                predecessor: None,
                topic: Topic::new("zeroization").expect("topic"),
                scope: Scope::new("test/zeroization").expect("scope"),
                priority: Priority::Priority,
                logical_key: b"preserved".to_vec(),
                payload: b"preserved through terminal cleanup".to_vec(),
                tombstone: false,
            })
            .await
            .expect("publish before zeroization");

        let zeroized = zeroize_node(&state, &mission_path, Duration::from_secs(5))
            .await
            .expect("live zeroization");
        assert_eq!(zeroized.state, SoftwareZeroizationState::Complete);
        let receipt = running.wait().await.expect("zeroized actor completion");
        assert_eq!(receipt.events, 1);
        assert_eq!(
            selected
                .status()
                .await
                .expect_err("terminal actor rejects retained application handle")
                .kind(),
            ApplicationErrorKind::StateUnavailable
        );
        assert_eq!(
            Store::inspect_zeroization_state(state.join(STORE_FILE))
                .expect("terminal state")
                .state(),
            StoreZeroizationState::Complete
        );
        fs::remove_dir_all(root).expect("cleanup terminal live actor state");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn queued_live_zeroization_outranks_an_elapsed_run_for_deadline() {
        use crate::application::ApplicationErrorKind;

        struct ReleaseOnDrop(Option<oneshot::Sender<()>>);

        impl ReleaseOnDrop {
            fn release(mut self) {
                if let Some(release) = self.0.take() {
                    let _ = release.send(());
                }
            }
        }

        impl Drop for ReleaseOnDrop {
            fn drop(&mut self) {
                if let Some(release) = self.0.take() {
                    let _ = release.send(());
                }
            }
        }

        let root = root("queued-zeroization-outranks-run-for");
        let state = root.join("state");
        let mission_path = root.join("mission.bundle");
        fs::create_dir_all(&state).expect("state");
        persist_zeroization_test_mission(&mission_path, 0xbe);
        let mission = UnprotectedReferenceMission::load(&mission_path).expect("mission");
        let identity = mission.identity();
        let mission_authority = mission.mission_authority_id();
        let (application_sender, application_receiver) =
            mpsc::channel(APPLICATION_COMMAND_CAPACITY);
        let application_admission = Arc::new(AtomicBool::new(true));
        let selected = SelectedEventHandle::new(
            application_sender.clone(),
            application_admission.clone(),
            identity,
            mission_authority,
        );
        let (shutdown_sender, shutdown_receiver) = mpsc::channel(1);
        let (ready_sender, ready_receiver) = oneshot::channel();
        let (before_loop_ready_sender, before_loop_ready_receiver) = oneshot::channel();
        let (before_loop_release_sender, before_loop_release_receiver) = oneshot::channel();
        let release = ReleaseOnDrop(Some(before_loop_release_sender));
        let (zeroization_queued_sender, zeroization_queued_receiver) = oneshot::channel();
        let run_for = Duration::from_millis(50);
        let actor = tokio::spawn(run_node_actor_inner(
            NodeConfig {
                state: state.clone(),
                bind: SocketAddr::from(([127, 0, 0, 1], 0)),
                mission,
                peers: Vec::new(),
                sync_interval: Duration::from_secs(60),
                run_for: Some(run_for),
                application: NodeApplication::Relay,
            },
            application_receiver,
            application_admission.clone(),
            shutdown_receiver,
            ready_sender,
            Some(RunNodeActorTestControl {
                before_loop_ready: before_loop_ready_sender,
                before_loop_release: before_loop_release_receiver,
                zeroization_queued: zeroization_queued_sender,
            }),
        ));
        timeout(Duration::from_secs(5), ready_receiver)
            .await
            .expect("actor readiness deadline")
            .expect("actor readiness");
        timeout(Duration::from_secs(5), before_loop_ready_receiver)
            .await
            .expect("pre-select gate deadline")
            .expect("pre-select gate readiness");

        let zeroize_state = state.clone();
        let zeroize_mission = mission_path.clone();
        let zeroization = tokio::spawn(async move {
            zeroize_node(&zeroize_state, &zeroize_mission, Duration::from_secs(5)).await
        });
        timeout(Duration::from_secs(5), zeroization_queued_receiver)
            .await
            .expect("zeroization queue deadline")
            .expect("zeroization entered the actor queue");
        sleep(run_for + Duration::from_millis(100)).await;
        release.release();

        let zeroized = timeout(Duration::from_secs(5), zeroization)
            .await
            .expect("live zeroization response deadline")
            .expect("zeroization task")
            .expect("queued live zeroization receives explicit success");
        assert!(zeroized.live_request);
        assert_eq!(zeroized.state, SoftwareZeroizationState::Complete);
        assert!(zeroized.mission_destroyed && zeroized.identity_destroyed);
        assert_eq!(
            zeroized.mission_pathname,
            SoftwareZeroizationPathState::RetainedZeroLength
        );
        assert_eq!(
            zeroized.identity_pathname,
            SoftwareZeroizationPathState::RetainedZeroLength
        );
        let receipt = timeout(Duration::from_secs(5), actor)
            .await
            .expect("zeroized actor completion deadline")
            .expect("actor task")
            .expect("actor takes its zeroized terminal path");
        assert_eq!(receipt.contacts, 0);
        assert_eq!(receipt.contact_errors, 0);
        assert!(!application_admission.load(Ordering::Acquire));
        let closed = selected
            .status()
            .await
            .expect_err("zeroized actor closes retained application admission");
        assert_eq!(closed.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(closed.operation(), "status");
        assert_eq!(
            Store::inspect_zeroization_state(state.join(STORE_FILE))
                .expect("terminal store state")
                .state(),
            StoreZeroizationState::Complete
        );
        assert_eq!(
            fs::metadata(&mission_path)
                .expect("mission tombstone")
                .len(),
            0
        );

        drop(selected);
        drop(application_sender);
        drop(shutdown_sender);
        fs::remove_dir_all(root).expect("cleanup zeroization/deadline race state");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn init_only_state_is_bound_terminally_before_secret_erasure() {
        let state = root("zeroize-init-only");
        fs::create_dir_all(&state).expect("state");
        let identity = NodeIdentity::load_or_create(&state).expect("identity");
        let identity_path = identity.path().to_path_buf();
        drop(identity);
        let mission_path = state.join("mission.bundle");
        persist_zeroization_test_mission(&mission_path, 0xa1);
        assert!(!state.join(STORE_FILE).exists());

        let receipt = zeroize_node(&state, &mission_path, Duration::from_secs(2))
            .await
            .expect("zeroize initialized state");
        assert_eq!(receipt.state, SoftwareZeroizationState::Complete);
        assert!(receipt.mission_destroyed && receipt.identity_destroyed);
        assert_eq!(
            receipt.mission_pathname,
            SoftwareZeroizationPathState::RetainedZeroLength
        );
        assert_eq!(
            receipt.identity_pathname,
            SoftwareZeroizationPathState::RetainedZeroLength
        );
        assert_eq!(
            fs::metadata(&mission_path)
                .expect("mission tombstone")
                .len(),
            0
        );
        assert_eq!(
            fs::metadata(&identity_path)
                .expect("identity tombstone")
                .len(),
            0
        );
        let status = Store::inspect_zeroization_state(state.join(STORE_FILE)).expect("status");
        assert_eq!(status.state(), StoreZeroizationState::Complete);
        assert!(status.mission_authority().is_some());
        fs::remove_dir_all(state).expect("cleanup state");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn wrong_valid_mission_authority_cannot_mark_or_erase_any_artifact() {
        let state = root("zeroize-wrong-authority");
        fs::create_dir_all(&state).expect("state");
        let identity = NodeIdentity::load_or_create(&state).expect("identity");
        let identity_path = identity.path().to_path_buf();
        drop(identity);
        let correct_path = state.join("correct.bundle");
        let wrong_path = state.join("wrong.bundle");
        persist_zeroization_test_mission(&correct_path, 0xa2);
        let wrong_identity = persist_zeroization_test_mission(&wrong_path, 0xb2);
        let correct = UnprotectedReferenceMission::load(&correct_path).expect("correct mission");
        assert_ne!(correct.identity(), wrong_identity);
        let store = Store::open_for_mission(state.join(STORE_FILE), correct.mission_authority_id())
            .expect("bound store");
        drop(store);
        drop(correct);
        let opaque_id = ItemId::new([0xb3; 32]);
        assert!(put_opaque(&state, opaque_id, b"wrong-authority-preserved-row").expect("put row"));
        let store_path = state.join(STORE_FILE);
        let store_before = fs::read(&store_path).expect("store bytes before rejection");
        let store_mtime_before = fs::metadata(&store_path)
            .expect("store metadata before rejection")
            .modified()
            .expect("store mtime before rejection");
        let correct_before = fs::read(&correct_path).expect("correct bytes");
        let wrong_before = fs::read(&wrong_path).expect("wrong bytes");
        let identity_before = fs::read(&identity_path).expect("identity bytes");

        let error = zeroize_node(&state, &wrong_path, Duration::from_secs(2))
            .await
            .expect_err("wrong authority must fail");
        assert!(matches!(
            error,
            NodeError::Store(StoreError::MissionAuthorityMismatch { .. })
        ));
        assert_eq!(
            fs::read(&correct_path).expect("correct retained"),
            correct_before
        );
        assert_eq!(fs::read(&wrong_path).expect("wrong retained"), wrong_before);
        assert_eq!(
            fs::read(&identity_path).expect("identity retained"),
            identity_before
        );
        assert_eq!(
            fs::read(&store_path).expect("store bytes after rejection"),
            store_before
        );
        assert_eq!(
            fs::metadata(&store_path)
                .expect("store metadata after rejection")
                .modified()
                .expect("store mtime after rejection"),
            store_mtime_before
        );
        let status = Store::inspect_zeroization_state(&store_path).expect("status");
        assert_eq!(status.state(), StoreZeroizationState::Live);
        assert!(status.intent().is_none());
        let preserved = inspect_store(&state).expect("preserved logical state");
        assert_eq!(preserved.items, 1);
        assert_eq!(preserved.ids, vec![opaque_id]);
        fs::remove_dir_all(state).expect("cleanup state");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stopped_zeroization_preserves_rows_and_replays_idempotently() {
        let state = root("zeroize-preserves-rows");
        fs::create_dir_all(&state).expect("state");
        let identity = NodeIdentity::load_or_create(&state).expect("identity");
        drop(identity);
        let mission_path = state.join("mission.bundle");
        persist_zeroization_test_mission(&mission_path, 0xa3);
        let opaque_id = ItemId::new([0xd3; 32]);
        assert!(put_opaque(&state, opaque_id, b"preserved-row").expect("put row"));

        let first = zeroize_node(&state, &mission_path, Duration::from_secs(2))
            .await
            .expect("first zeroization");
        assert_eq!(first.preserved.items, 1);
        assert_eq!(first.preserved.acceptance_markers, 1);
        assert_eq!(first.preserved.ids, vec![opaque_id]);
        assert_eq!(
            first.preserved.zeroization,
            SoftwareZeroizationState::Complete
        );

        let replay = zeroize_node(&state, &mission_path, Duration::from_secs(2))
            .await
            .expect("idempotent replay");
        assert_eq!(replay.state, SoftwareZeroizationState::Complete);
        assert_eq!(replay.preserved.items, 1);
        assert_eq!(replay.preserved.ids, vec![opaque_id]);
        fs::remove_dir_all(state).expect("cleanup state");
    }

    fn test_mission() -> UnprotectedReferenceMission {
        let access = ProvisioningAccess::member(
            Scope::new("test/runtime").expect("scope"),
            vec![1],
            vec![Topic::new("opaque").expect("topic")],
        )
        .expect("access");
        let mut provisioner = ReferenceProvisioner::from_seed([0x71; 32]).expect("provisioner");
        let bundle = provisioner
            .issue_node(1, &[access])
            .expect("issue local mission");
        UnprotectedReferenceMission::from_bytes(bundle.to_bytes().expect("encode bundle"))
            .expect("parse local mission")
    }

    fn prefill_status_commands(
        sender: &mpsc::Sender<SelectedEventCommand>,
    ) -> Vec<oneshot::Receiver<Result<SelectedEventStatus, crate::application::ApplicationError>>>
    {
        let mut responses = Vec::with_capacity(APPLICATION_COMMAND_CAPACITY);
        for _ in 0..APPLICATION_COMMAND_CAPACITY {
            let (response, received) = oneshot::channel();
            assert!(
                sender
                    .try_send(SelectedEventCommand::Status { response })
                    .is_ok(),
                "pre-fill bounded application queue"
            );
            responses.push(received);
        }
        assert_eq!(sender.capacity(), 0);
        responses
    }

    async fn assert_explicit_status_responses(
        responses: Vec<
            oneshot::Receiver<Result<SelectedEventStatus, crate::application::ApplicationError>>,
        >,
    ) -> (usize, usize) {
        use crate::application::{ApplicationErrorKind, EventSyncStatus};

        let mut successes = 0usize;
        let mut unavailable = 0usize;
        for response in responses {
            match response
                .await
                .expect("queued caller receives an explicit result")
            {
                Ok(status) => {
                    successes += 1;
                    assert!(matches!(
                        status.sync,
                        EventSyncStatus::Offline
                            | EventSyncStatus::AwaitingAuthenticatedContact
                            | EventSyncStatus::LastContactComplete
                            | EventSyncStatus::WorkRemained
                            | EventSyncStatus::PolicyChangedSinceContact
                    ));
                }
                Err(error) => {
                    unavailable += 1;
                    assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
                    assert_eq!(error.operation(), "status");
                }
            }
        }
        (successes, unavailable)
    }

    fn spawn_saturated_status_callers(
        callers: &mut JoinSet<usize>,
        selected: &SelectedEventHandle,
        authenticated_contact_observed: Arc<AtomicBool>,
    ) {
        use crate::application::ApplicationErrorKind;

        for _ in 0..APPLICATION_COMMAND_CAPACITY * 2 {
            let selected = selected.clone();
            let authenticated_contact_observed = authenticated_contact_observed.clone();
            callers.spawn(async move {
                let mut successes = 0usize;
                loop {
                    match selected.status().await {
                        Ok(status) => {
                            successes = successes.saturating_add(1);
                            if status.authenticated_contacts > 0 {
                                authenticated_contact_observed.store(true, Ordering::Release);
                            }
                        }
                        Err(error) => {
                            assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
                            assert_eq!(error.operation(), "status");
                            return successes;
                        }
                    }
                }
            });
        }
    }

    #[tokio::test]
    async fn oversized_run_for_is_rejected_before_readiness_or_state_mutation() {
        let state = root("oversized-run-for");
        let (application_sender, application_receiver) =
            mpsc::channel(APPLICATION_COMMAND_CAPACITY);
        let application_admission = Arc::new(AtomicBool::new(true));
        let (shutdown_sender, shutdown_receiver) = mpsc::channel(1);
        let (ready_sender, ready_receiver) = oneshot::channel();
        let actor = tokio::spawn(run_node_actor(
            NodeConfig {
                state: state.clone(),
                bind: SocketAddr::from(([127, 0, 0, 1], 0)),
                mission: test_mission(),
                peers: Vec::new(),
                sync_interval: Duration::from_secs(60),
                run_for: Some(Duration::MAX),
                application: NodeApplication::Relay,
            },
            application_receiver,
            application_admission,
            shutdown_receiver,
            ready_sender,
        ));
        let error = timeout(Duration::from_secs(5), actor)
            .await
            .expect("oversized run_for rejection deadline")
            .expect("actor must return an error rather than panic")
            .expect_err("oversized run_for must fail");
        assert!(
            matches!(&error, NodeError::Configuration(message) if message.contains("run_for exceeds the monotonic clock")),
            "unexpected oversized run_for error: {error}"
        );
        assert!(
            ready_receiver.await.is_err(),
            "oversized run_for must fail before readiness"
        );
        assert!(
            !state.exists(),
            "oversized run_for must fail before state mutation"
        );

        drop(application_sender);
        drop(shutdown_sender);
    }

    #[tokio::test]
    async fn run_for_preempts_a_saturated_application_queue_and_closes_every_caller() {
        use crate::application::ApplicationErrorKind;

        let state = root("run-for-saturated-application-queue");
        let mission = test_mission();
        let identity = mission.identity();
        let mission_authority = mission.mission_authority_id();
        let (application_sender, application_receiver) =
            mpsc::channel(APPLICATION_COMMAND_CAPACITY);
        let application_admission = Arc::new(AtomicBool::new(true));
        let selected = SelectedEventHandle::new(
            application_sender.clone(),
            application_admission.clone(),
            identity,
            mission_authority,
        );
        let responses = prefill_status_commands(&application_sender);

        let (shutdown_sender, shutdown_receiver) = mpsc::channel(1);
        let (ready_sender, ready_receiver) = oneshot::channel();
        let actor = tokio::spawn(run_node_actor(
            NodeConfig {
                state: state.clone(),
                bind: SocketAddr::from(([127, 0, 0, 1], 0)),
                mission,
                peers: Vec::new(),
                sync_interval: Duration::from_secs(60),
                run_for: Some(Duration::from_millis(250)),
                application: NodeApplication::Relay,
            },
            application_receiver,
            application_admission.clone(),
            shutdown_receiver,
            ready_sender,
        ));
        let mut callers = JoinSet::new();
        spawn_saturated_status_callers(&mut callers, &selected, Arc::new(AtomicBool::new(false)));
        ready_receiver.await.expect("actor readiness");
        let receipt = timeout(Duration::from_secs(5), actor)
            .await
            .expect("run_for must not be starved by saturated commands")
            .expect("actor task")
            .expect("actor completion");
        assert_eq!(receipt.contacts, 0);
        assert_eq!(receipt.contact_errors, 0);
        assert!(!application_admission.load(Ordering::Acquire));

        let (successes, unavailable) = assert_explicit_status_responses(responses).await;
        assert_eq!(successes + unavailable, APPLICATION_COMMAND_CAPACITY);
        let expected_callers = APPLICATION_COMMAND_CAPACITY * 2;
        let (completed_callers, pressure_successes) = timeout(Duration::from_secs(5), async {
            let mut completed = 0usize;
            let mut successes = 0usize;
            while let Some(result) = callers.join_next().await {
                completed += 1;
                successes = successes.saturating_add(result.expect("status pressure task"));
            }
            (completed, successes)
        })
        .await
        .expect("every saturated status caller closes explicitly");
        assert_eq!(completed_callers, expected_callers);
        assert!(
            successes + pressure_successes > 0,
            "the nonzero run_for interval must admit work before its deadline"
        );
        assert!(
            unavailable + completed_callers > 0,
            "the run_for deadline must close callers with StateUnavailable"
        );
        let closed = selected
            .status()
            .await
            .expect_err("retained handle closes with the actor");
        assert_eq!(closed.kind(), ApplicationErrorKind::StateUnavailable);
        assert_eq!(closed.operation(), "status");

        drop(selected);
        drop(application_sender);
        drop(shutdown_sender);
        fs::remove_dir_all(state).expect("cleanup saturated application state");
    }

    #[tokio::test]
    async fn authenticated_contact_status_progresses_with_saturated_application_queues() {
        let root = root("authenticated-contact-saturated-application-queues");
        let left_state = root.join("left");
        let right_state = root.join("right");
        let mut issued = issue_missions(2);
        let right_mission = issued.pop().expect("right mission");
        let left_mission = issued.pop().expect("left mission");
        let left_mission_id = left_mission.identity;
        let right_mission_id = right_mission.identity;
        let left_mission_authority = left_mission.credentials.mission_authority_id();
        let right_mission_authority = right_mission.credentials.mission_authority_id();
        let left_carrier = {
            let identity =
                NodeIdentity::load_or_create(&left_state).expect("left carrier identity");
            let carrier = identity.id();
            drop(identity);
            carrier
        };
        let right_carrier = {
            let identity =
                NodeIdentity::load_or_create(&right_state).expect("right carrier identity");
            let carrier = identity.id();
            drop(identity);
            carrier
        };
        let (left_sender, left_receiver) = mpsc::channel(APPLICATION_COMMAND_CAPACITY);
        let left_admission = Arc::new(AtomicBool::new(true));
        let left_selected = SelectedEventHandle::new(
            left_sender.clone(),
            left_admission.clone(),
            left_mission_id,
            left_mission_authority,
        );
        let left_prefilled = prefill_status_commands(&left_sender);
        let (left_shutdown, left_shutdown_receiver) = mpsc::channel(1);
        let (left_ready, left_readiness) = oneshot::channel();

        let (right_sender, right_receiver) = mpsc::channel(APPLICATION_COMMAND_CAPACITY);
        let right_admission = Arc::new(AtomicBool::new(true));
        let right_selected = SelectedEventHandle::new(
            right_sender.clone(),
            right_admission.clone(),
            right_mission_id,
            right_mission_authority,
        );
        let right_prefilled = prefill_status_commands(&right_sender);
        let (right_shutdown, right_shutdown_receiver) = mpsc::channel(1);
        let (right_ready, right_readiness) = oneshot::channel();

        let left_contact_observed = Arc::new(AtomicBool::new(false));
        let right_contact_observed = Arc::new(AtomicBool::new(false));
        let mut callers = JoinSet::new();
        spawn_saturated_status_callers(&mut callers, &left_selected, left_contact_observed.clone());
        spawn_saturated_status_callers(
            &mut callers,
            &right_selected,
            right_contact_observed.clone(),
        );
        let placeholder = SocketAddr::from(([127, 0, 0, 1], 9));
        let (left_actor, right_actor) = if left_carrier > right_carrier {
            let left_actor = tokio::spawn(run_node_actor(
                NodeConfig {
                    state: left_state,
                    bind: SocketAddr::from(([127, 0, 0, 1], 0)),
                    mission: left_mission.credentials,
                    peers: vec![MissionExpectedPeer {
                        carrier: ExpectedPeer {
                            id: right_carrier,
                            address: placeholder,
                        },
                        mission: right_mission_id,
                    }],
                    sync_interval: Duration::from_nanos(1),
                    run_for: None,
                    application: NodeApplication::Relay,
                },
                left_receiver,
                left_admission.clone(),
                left_shutdown_receiver,
                left_ready,
            ));
            let left_address = timeout(Duration::from_secs(10), left_readiness)
                .await
                .expect("left responder becomes ready")
                .expect("left responder readiness")
                .into_iter()
                .find(SocketAddr::is_ipv4)
                .expect("left responder IPv4 endpoint");
            let right_actor = tokio::spawn(run_node_actor(
                NodeConfig {
                    state: right_state,
                    bind: SocketAddr::from(([127, 0, 0, 1], 0)),
                    mission: right_mission.credentials,
                    peers: vec![MissionExpectedPeer {
                        carrier: ExpectedPeer {
                            id: left_carrier,
                            address: left_address,
                        },
                        mission: left_mission_id,
                    }],
                    sync_interval: Duration::from_nanos(1),
                    run_for: None,
                    application: NodeApplication::Relay,
                },
                right_receiver,
                right_admission.clone(),
                right_shutdown_receiver,
                right_ready,
            ));
            timeout(Duration::from_secs(10), right_readiness)
                .await
                .expect("right initiator becomes ready")
                .expect("right initiator readiness");
            (left_actor, right_actor)
        } else {
            let right_actor = tokio::spawn(run_node_actor(
                NodeConfig {
                    state: right_state,
                    bind: SocketAddr::from(([127, 0, 0, 1], 0)),
                    mission: right_mission.credentials,
                    peers: vec![MissionExpectedPeer {
                        carrier: ExpectedPeer {
                            id: left_carrier,
                            address: placeholder,
                        },
                        mission: left_mission_id,
                    }],
                    sync_interval: Duration::from_nanos(1),
                    run_for: None,
                    application: NodeApplication::Relay,
                },
                right_receiver,
                right_admission.clone(),
                right_shutdown_receiver,
                right_ready,
            ));
            let right_address = timeout(Duration::from_secs(10), right_readiness)
                .await
                .expect("right responder becomes ready")
                .expect("right responder readiness")
                .into_iter()
                .find(SocketAddr::is_ipv4)
                .expect("right responder IPv4 endpoint");
            let left_actor = tokio::spawn(run_node_actor(
                NodeConfig {
                    state: left_state,
                    bind: SocketAddr::from(([127, 0, 0, 1], 0)),
                    mission: left_mission.credentials,
                    peers: vec![MissionExpectedPeer {
                        carrier: ExpectedPeer {
                            id: right_carrier,
                            address: right_address,
                        },
                        mission: right_mission_id,
                    }],
                    sync_interval: Duration::from_nanos(1),
                    run_for: None,
                    application: NodeApplication::Relay,
                },
                left_receiver,
                left_admission.clone(),
                left_shutdown_receiver,
                left_ready,
            ));
            timeout(Duration::from_secs(10), left_readiness)
                .await
                .expect("left initiator becomes ready")
                .expect("left initiator readiness");
            (left_actor, right_actor)
        };

        timeout(Duration::from_secs(35), async {
            loop {
                if left_contact_observed.load(Ordering::Acquire)
                    && right_contact_observed.load(Ordering::Acquire)
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("authenticated completion and status must outrank saturated commands");

        left_admission.store(false, Ordering::Release);
        right_admission.store(false, Ordering::Release);
        let (left_shutdown_result, right_shutdown_result) =
            tokio::join!(left_shutdown.send(()), right_shutdown.send(()));
        assert!(left_shutdown_result.is_ok());
        assert!(right_shutdown_result.is_ok());
        let (left_receipt, right_receipt) = timeout(Duration::from_secs(10), async {
            let (left, right) = tokio::join!(left_actor, right_actor);
            (
                left.expect("left actor task")
                    .expect("left actor completion"),
                right
                    .expect("right actor task")
                    .expect("right actor completion"),
            )
        })
        .await
        .expect("saturated actors shut down promptly");
        assert!(left_receipt.contacts > 0);
        assert!(right_receipt.contacts > 0);
        let (left_successes, left_unavailable) =
            assert_explicit_status_responses(left_prefilled).await;
        let (right_successes, right_unavailable) =
            assert_explicit_status_responses(right_prefilled).await;
        assert_eq!(
            left_successes + left_unavailable,
            APPLICATION_COMMAND_CAPACITY
        );
        assert_eq!(
            right_successes + right_unavailable,
            APPLICATION_COMMAND_CAPACITY
        );

        let expected_callers = APPLICATION_COMMAND_CAPACITY * 4;
        let (completed_callers, successful_statuses) = timeout(Duration::from_secs(5), async {
            let mut completed = 0usize;
            let mut successes = 0usize;
            while let Some(result) = callers.join_next().await {
                completed += 1;
                successes = successes.saturating_add(result.expect("status pressure task"));
            }
            (completed, successes)
        })
        .await
        .expect("all saturated status callers close explicitly");
        assert_eq!(completed_callers, expected_callers);
        assert!(successful_statuses > 0);

        drop(left_selected);
        drop(right_selected);
        drop(left_sender);
        drop(right_sender);
        drop(left_shutdown);
        drop(right_shutdown);
        fs::remove_dir_all(root).expect("cleanup saturated contact state");
    }

    #[tokio::test]
    async fn live_selected_event_actor_is_peerless_durable_and_closes_admission() {
        use crate::application::{
            ApplicationErrorKind, EventAcknowledgement, EventGapQuery, EventPollRequest,
            EventPublishRequest, EventQuery, EventSubscriptionRequest, EventSyncStatus,
            EventUnsubscribe,
        };

        let state = root("live-selected-event-actor");
        let scope = Scope::new("test/runtime").expect("scope");
        let topic = Topic::new("opaque").expect("topic");
        let running = start_node(NodeConfig {
            state: state.clone(),
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            mission: test_mission(),
            peers: Vec::new(),
            sync_interval: Duration::from_millis(10),
            run_for: None,
            application: NodeApplication::Relay,
        })
        .await
        .expect("start live selected Event actor");
        let selected = running.selected_events();
        assert_eq!(
            selected.status().await.expect("peerless status").sync,
            EventSyncStatus::Offline
        );

        let subscription = selected
            .subscribe(EventSubscriptionRequest {
                operation_key: b"runtime-live-subscription".to_vec(),
                topic: topic.clone(),
                scope: scope.clone(),
                include_descendant_scopes: false,
            })
            .await
            .expect("subscribe while live");
        let published = selected
            .publish(EventPublishRequest {
                operation_key: b"runtime-live-publish".to_vec(),
                predecessor: None,
                topic: topic.clone(),
                scope: scope.clone(),
                priority: Priority::Priority,
                logical_key: b"runtime-live-key".to_vec(),
                payload: b"published while peerless".to_vec(),
                tombstone: false,
            })
            .await
            .expect("publish while live");
        let queried = selected
            .query(EventQuery {
                after_acceptance_marker: 0,
                limit: 8,
                topic: Some(topic.clone()),
                scope: Some(scope.clone()),
                ..EventQuery::default()
            })
            .await
            .expect("query while live");
        assert_eq!(queried.items.len(), 1);
        assert_eq!(queried.items[0].id, published.id);

        let delivered = selected
            .poll(EventPollRequest {
                subscription: subscription.id,
                delivery_limit: 8,
                scan_limit: 8,
            })
            .await
            .expect("poll while live");
        assert_eq!(delivered.deliveries.len(), 1);
        assert_eq!(delivered.deliveries[0].event.id, published.id);
        assert_eq!(delivered.deliveries[0].attempt, 1);
        assert_eq!(
            selected
                .acknowledge(subscription.id, published.id)
                .await
                .expect("acknowledge while live"),
            EventAcknowledgement::Acknowledged
        );
        assert!(
            selected
                .poll(EventPollRequest {
                    subscription: subscription.id,
                    delivery_limit: 8,
                    scan_limit: 8,
                })
                .await
                .expect("poll after acknowledgement")
                .deliveries
                .is_empty()
        );

        let gaps = selected
            .gaps(EventGapQuery {
                publisher: selected.identity(),
                topic: topic.clone(),
                scope: scope.clone(),
                after_sequence: 0,
                scan_limit: 8,
            })
            .await
            .expect("authenticated gap projection");
        assert!(gaps.gaps.is_empty());
        assert_eq!(gaps.scanned_through_sequence, published.event_sequence);
        assert!(!gaps.has_more);
        let beyond_high_water = selected
            .gaps(EventGapQuery {
                publisher: selected.identity(),
                topic,
                scope,
                after_sequence: published.event_sequence + 10,
                scan_limit: 8,
            })
            .await
            .expect("empty gap scan beyond high-water");
        assert!(beyond_high_water.gaps.is_empty());
        assert_eq!(
            beyond_high_water.scanned_through_sequence,
            published.event_sequence + 10
        );
        assert_eq!(
            selected
                .unsubscribe(subscription.id)
                .await
                .expect("unsubscribe while live"),
            EventUnsubscribe::Removed
        );
        assert_eq!(
            selected
                .unsubscribe(subscription.id)
                .await
                .expect("idempotent unsubscribe while live"),
            EventUnsubscribe::AlreadyAbsent
        );

        let retained = selected.clone();
        let receipt = running.shutdown().await.expect("graceful shutdown");
        assert_eq!(receipt.events, 1);
        assert_eq!(
            retained
                .status()
                .await
                .expect_err("closed actor rejects retained handle")
                .kind(),
            ApplicationErrorKind::StateUnavailable
        );
        fs::remove_dir_all(state).expect("cleanup live actor state");
    }

    fn demo_member_mission() -> UnprotectedReferenceMission {
        let access = ProvisioningAccess::member(
            demo_scope().expect("demo scope"),
            vec![1],
            vec![demo_event_topic().expect("demo topic")],
        )
        .expect("demo member access");
        let mut provisioner =
            ReferenceProvisioner::from_seed([0x94; 32]).expect("demo test provisioner");
        let bundle = provisioner
            .issue_node(1, &[access])
            .expect("issue demo member");
        UnprotectedReferenceMission::from_bytes(bundle.to_bytes().expect("encode demo bundle"))
            .expect("parse demo member")
    }

    struct ControlTestServices {
        authority: UnprotectedReferenceMission,
        member: UnprotectedReferenceMission,
        other: UnprotectedReferenceMission,
        excluded: UnprotectedReferenceMission,
        registry: Vec<u8>,
        registry_next: Vec<u8>,
        scope: Scope,
        topic: Topic,
    }

    fn control_test_services(seed: [u8; 32]) -> ControlTestServices {
        let scope = Scope::new("test/selected-control").expect("control scope");
        let topic = Topic::new("control-event").expect("control topic");
        let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])
            .expect("control access");
        let mut provisioner = ReferenceProvisioner::from_seed(seed).expect("control provisioner");
        let authority_bytes = provisioner
            .issue_control_authority(1, std::slice::from_ref(&access))
            .expect("issue authority")
            .to_bytes()
            .expect("encode authority");
        let authority = UnprotectedReferenceMission::from_bytes(authority_bytes)
            .expect("parse authority mission");
        let member_bytes = provisioner
            .issue_node(2, std::slice::from_ref(&access))
            .expect("issue member")
            .to_bytes()
            .expect("encode member");
        let member =
            UnprotectedReferenceMission::from_bytes(member_bytes).expect("parse member mission");
        let other_bytes = provisioner
            .issue_node(3, std::slice::from_ref(&access))
            .expect("issue other")
            .to_bytes()
            .expect("encode other");
        let other =
            UnprotectedReferenceMission::from_bytes(other_bytes).expect("parse other mission");
        let registry = provisioner
            .export_rekey_registry()
            .expect("signed registry");
        let excluded_bytes = provisioner
            .issue_node(4, std::slice::from_ref(&access))
            .expect("issue excluded registry member")
            .to_bytes()
            .expect("encode excluded");
        let excluded = UnprotectedReferenceMission::from_bytes(excluded_bytes)
            .expect("parse excluded mission");
        let registry_next = provisioner
            .export_rekey_registry()
            .expect("next signed registry");
        ControlTestServices {
            authority,
            member,
            other,
            excluded,
            registry,
            registry_next,
            scope,
            topic,
        }
    }

    fn open_test_sealer(mission: &UnprotectedReferenceMission) -> ReferenceEnvelopeSealer {
        ReferenceEnvelopeSealer::open(mission.fresh_bundle().expect("fresh test bundle"))
            .expect("open test sealer")
    }

    fn seal_test_revoke_then_rekey(
        services: &ControlTestServices,
        revoked: NodeId,
        recipients: Vec<ScopeRekeyRecipient>,
    ) -> (Vec<u8>, Vec<u8>) {
        let mut authority = open_test_sealer(&services.authority);
        let first = authority
            .seal_chained_revocation_control(revoked, 1, 1, None)
            .expect("seal first revocation");
        let first_id = authority
            .verify_control(&first)
            .expect("verify first revocation")
            .envelope_id();
        let (second, _) = authority
            .seal_chained_scope_rekey_control_from_registry(
                &services.registry,
                0,
                services.scope.clone(),
                2,
                recipients,
                2,
                Some(first_id),
            )
            .expect("seal second rekey");
        (first, second)
    }

    fn publish_test_epoch_two_event(
        store: &Store,
        sealer: &mut ReferenceEnvelopeSealer,
        services: &ControlTestServices,
    ) -> StoredEvent {
        let policy = store
            .control_policy_snapshot()
            .expect("settled epoch policy");
        let reservation = store
            .reserve_event_with_policy(&policy, sealer.identity(), &services.topic, &services.scope)
            .expect("reserve epoch-two Event");
        let payload = b"selected epoch two";
        let header = reservation
            .header(
                Priority::Immediate,
                b"epoch-two".to_vec(),
                None,
                payload.len() as u64,
                false,
                2,
            )
            .expect("epoch-two header");
        let sealed = sealer
            .seal_event(&header, payload)
            .expect("seal epoch-two Event");
        let route = sealer
            .verify_event(&sealed.bytes)
            .expect("verify local epoch-two route");
        let EventContentVerification::ContentVerified { event, .. } = sealer
            .verify_event_content(route, &sealed.bytes)
            .expect("verify local epoch-two content")
        else {
            panic!("authority must retain epoch-two content grant");
        };
        store
            .commit_reserved_event_with_policy(&policy, &reservation, &event, &sealed.bytes)
            .expect("commit epoch-two Event");
        let transfer_id = EventTransferId::new(event.envelope_id());
        match store
            .get_transfer_with_policy(&policy, transfer_id)
            .expect("reload epoch-two Event")
        {
            Some(StoredEventTransfer::Accepted(event)) => event,
            _ => panic!("epoch-two Event is not semantically accepted"),
        }
    }

    fn publish_test_epoch_one_event(
        store: &Store,
        sealer: &mut ReferenceEnvelopeSealer,
        topic: &Topic,
        scope: &Scope,
        logical_key: &[u8],
    ) -> EventTransferId {
        let reservation = store
            .reserve_event(sealer.identity(), topic, scope)
            .expect("reserve epoch-one test Event");
        let payload = logical_key;
        let header = reservation
            .header(
                Priority::Routine,
                logical_key.to_vec(),
                None,
                payload.len() as u64,
                false,
                1,
            )
            .expect("epoch-one test header");
        let sealed = sealer
            .seal_event(&header, payload)
            .expect("seal epoch-one test Event");
        let route = sealer
            .verify_event(&sealed.bytes)
            .expect("verify epoch-one test route");
        let EventContentVerification::ContentVerified { event, .. } = sealer
            .verify_event_content(route, &sealed.bytes)
            .expect("verify epoch-one test content")
        else {
            panic!("test member lost content grant");
        };
        store
            .commit_reserved_event(&reservation, &event, &sealed.bytes)
            .expect("commit epoch-one test Event");
        EventTransferId::new(event.envelope_id())
    }

    async fn contact_test_pair(
        server_store: Arc<Store>,
        server_mission: UnprotectedReferenceMission,
        client_store: &Store,
        client_mission: UnprotectedReferenceMission,
    ) -> (PeerReceipt, PeerReceipt) {
        let server = Endpoint::bind(
            aster_iroh::SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("server address")),
        )
        .await
        .expect("server endpoint");
        let client = Endpoint::bind(
            aster_iroh::SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("client address")),
        )
        .await
        .expect("client endpoint");
        let server_task = tokio::spawn({
            let server = server.clone();
            let store = server_store;
            let credentials = server_mission.clone();
            let allowed = BTreeSet::from([client.id()]);
            let peer = MissionPeerBinding::new(client.id(), client_mission.identity());
            async move {
                let connection = server.accept(&allowed).await.expect("accept carrier");
                serve_connection(
                    store,
                    connection,
                    credentials,
                    peer,
                    Arc::new(RwLock::new(())),
                )
                .await
            }
        });
        let client_receipt = sync_once(
            client_store,
            &client,
            client_mission,
            MissionExpectedPeer {
                carrier: ExpectedPeer {
                    id: server.id(),
                    address: loopback(&server),
                },
                mission: server_mission.identity(),
            },
        )
        .await
        .expect("client contact");
        let server_receipt = server_task
            .await
            .expect("server task")
            .expect("server contact");
        client.close().await;
        server.close().await;
        (client_receipt, server_receipt.receipt)
    }

    fn expected_peer(seed: u64, port: u16) -> MissionExpectedPeer {
        let mut secret = [0u8; 32];
        secret[..8].copy_from_slice(&seed.to_le_bytes());
        let mut mission = [0u8; 32];
        mission[..8].copy_from_slice(&seed.to_be_bytes());
        MissionExpectedPeer {
            carrier: ExpectedPeer {
                id: aster_iroh::SecretKey::from_bytes(&secret).public(),
                address: SocketAddr::from(([127, 0, 0, 1], port)),
            },
            mission,
        }
    }

    #[tokio::test]
    async fn valid_mission_session_rejects_arbitrary_fetch_and_offer_after_reconciliation() {
        let shared = EventTransferId::new([0xe0; 32]);
        reject_hostile_transfer(
            Frame::Fetch {
                direction: EventDirection::ToSessionResponder,
                id: shared,
            },
            "fetch",
        )
        .await;
        reject_hostile_transfer(
            Frame::Offer {
                direction: EventDirection::ToSessionResponder,
                id: shared,
                bytes: b"shared".to_vec(),
            },
            "offer",
        )
        .await;
    }

    #[tokio::test]
    async fn protected_interest_selects_only_beta_and_empty_means_receive_none() {
        let scope = Scope::new("test/interest-filter").expect("interest scope");
        let alpha = Topic::new("alpha").expect("alpha topic");
        let beta = Topic::new("beta").expect("beta topic");
        let access =
            ProvisioningAccess::member(scope.clone(), vec![1], vec![alpha.clone(), beta.clone()])
                .expect("two-topic access");
        let mut provisioner =
            ReferenceProvisioner::from_seed([0x94; 32]).expect("interest provisioner");
        let server_mission = UnprotectedReferenceMission::from_bytes(
            provisioner
                .issue_node(1, std::slice::from_ref(&access))
                .and_then(|bundle| bundle.to_bytes())
                .expect("server bundle"),
        )
        .expect("server mission");
        let beta_mission = UnprotectedReferenceMission::from_bytes(
            provisioner
                .issue_node(2, std::slice::from_ref(&access))
                .and_then(|bundle| bundle.to_bytes())
                .expect("beta receiver bundle"),
        )
        .expect("beta receiver mission");
        let empty_mission = UnprotectedReferenceMission::from_bytes(
            provisioner
                .issue_node(3, &[access])
                .and_then(|bundle| bundle.to_bytes())
                .expect("empty receiver bundle"),
        )
        .expect("empty receiver mission");

        let server_state = root("interest-filter-server");
        let beta_state = root("interest-filter-beta");
        let empty_state = root("interest-filter-empty");
        for state in [&server_state, &beta_state, &empty_state] {
            fs::create_dir_all(state).expect("interest test state");
        }
        let mut server_sealer = open_test_sealer(&server_mission);
        let authority = server_sealer.mission_authority_id();
        let server_store = Arc::new(
            Store::open_for_mission(server_state.join(STORE_FILE), authority)
                .expect("server store"),
        );
        let beta_store = Store::open_for_mission(beta_state.join(STORE_FILE), authority)
            .expect("beta receiver store");
        let empty_store = Store::open_for_mission(empty_state.join(STORE_FILE), authority)
            .expect("empty receiver store");
        seed_test_event_subscription(
            &server_store,
            EventSubscriptionMode::Consume,
            &beta,
            &scope,
            b"server-receive-beta-baseline",
        );
        seed_test_event_subscription(
            &beta_store,
            EventSubscriptionMode::Consume,
            &beta,
            &scope,
            b"receive-beta-only",
        );

        let alpha_id = publish_test_epoch_one_event(
            &server_store,
            &mut server_sealer,
            &alpha,
            &scope,
            b"alpha-event",
        );
        let beta_id = publish_test_epoch_one_event(
            &server_store,
            &mut server_sealer,
            &beta,
            &scope,
            b"beta-event",
        );
        let server_policy = server_store
            .event_replication_policy_snapshot()
            .expect("server replication policy");
        let beta_interest = exact_event_interest(&beta, &scope);
        assert_eq!(
            transfer_inventory_for_receiver(
                &server_store,
                &server_policy,
                &mut server_sealer,
                &beta_interest,
            )
            .expect("beta-filtered inventory"),
            InventorySnapshot::new(vec![beta_id.reconciliation_item_id()]),
        );
        assert!(
            transfer_inventory_for_receiver(
                &server_store,
                &server_policy,
                &mut server_sealer,
                &EventInterest::empty(),
            )
            .expect("empty inventory")
            .is_empty(),
            "empty interest must be receive-none rather than a wildcard"
        );

        let (beta_receipt, beta_server_receipt) = contact_test_pair(
            server_store.clone(),
            server_mission.clone(),
            &beta_store,
            beta_mission,
        )
        .await;
        assert_eq!(beta_receipt.fetched, 1);
        assert_eq!(beta_receipt.inserted, 1);
        assert_eq!(beta_server_receipt.offered, 1);
        assert!(
            beta_store
                .get_event(beta_id)
                .expect("beta lookup")
                .is_some()
        );
        assert!(
            beta_store
                .get_event(alpha_id)
                .expect("alpha exclusion lookup")
                .is_none(),
            "authorized but unsubscribed alpha crossed the beta receive lane"
        );
        assert_eq!(beta_store.event_count().expect("beta Event count"), 1);

        let (empty_receipt, empty_server_receipt) = contact_test_pair(
            server_store.clone(),
            server_mission,
            &empty_store,
            empty_mission,
        )
        .await;
        assert_eq!(empty_receipt.fetched, 0);
        assert_eq!(empty_receipt.inserted, 0);
        assert_eq!(empty_server_receipt.offered, 0);
        assert_eq!(empty_store.event_count().expect("empty Event count"), 0);
        assert_eq!(
            empty_store
                .event_subscription_stats()
                .expect("empty subscription stats")
                .subscriptions,
            0
        );

        drop(server_store);
        drop(beta_store);
        drop(empty_store);
        for state in [server_state, beta_state, empty_state] {
            fs::remove_dir_all(state).expect("cleanup interest test state");
        }
    }

    #[tokio::test]
    async fn content_capable_carry_stays_route_only_until_consume_dominates() {
        let scope = Scope::new("test/effective-receive-mode").expect("mode scope");
        let topic = Topic::new("mode").expect("mode topic");
        let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])
            .expect("content-capable access");
        let mut provisioner =
            ReferenceProvisioner::from_seed([0x9a; 32]).expect("mode provisioner");
        let server_mission = UnprotectedReferenceMission::from_bytes(
            provisioner
                .issue_node(1, std::slice::from_ref(&access))
                .and_then(|bundle| bundle.to_bytes())
                .expect("mode server bundle"),
        )
        .expect("mode server mission");
        let receiver_mission = UnprotectedReferenceMission::from_bytes(
            provisioner
                .issue_node(2, &[access])
                .and_then(|bundle| bundle.to_bytes())
                .expect("mode receiver bundle"),
        )
        .expect("mode receiver mission");

        let server_state = root("effective-mode-server");
        let receiver_state = root("effective-mode-receiver");
        for state in [&server_state, &receiver_state] {
            fs::create_dir_all(state).expect("mode test state");
        }
        let mut server_sealer = open_test_sealer(&server_mission);
        let authority = server_sealer.mission_authority_id();
        let server_store = Arc::new(
            Store::open_for_mission(server_state.join(STORE_FILE), authority)
                .expect("mode server store"),
        );
        let receiver_store = Store::open_for_mission(receiver_state.join(STORE_FILE), authority)
            .expect("mode receiver store");
        seed_test_event_subscription(
            &receiver_store,
            EventSubscriptionMode::Carry,
            &topic,
            &scope,
            b"mode-carry",
        );
        let stale_guard = EventLaneGuard::capture(
            Arc::new(RwLock::new(())).read_owned().await,
            &receiver_store,
            receiver_mission.identity(),
            server_mission.identity(),
            0,
        )
        .expect("capture Carry lane guard");
        let stale_revision = stale_guard.replication_policy().selector_revision();
        assert_eq!(
            stale_guard
                .replication_policy()
                .effective_mode(&topic, &scope),
            Some(EventSubscriptionMode::Carry)
        );

        let carried_id = publish_test_epoch_one_event(
            &server_store,
            &mut server_sealer,
            &topic,
            &scope,
            b"content-capable-carry",
        );
        let (carry_receipt, _) = contact_test_pair(
            server_store.clone(),
            server_mission.clone(),
            &receiver_store,
            receiver_mission.clone(),
        )
        .await;
        assert_eq!(carry_receipt.fetched, 1);
        assert_eq!(carry_receipt.inserted, 1);
        assert_eq!(receiver_store.event_count().expect("Carry Event count"), 0);
        let carry_stats = receiver_store.event_stats().expect("Carry Event stats");
        assert_eq!(carry_stats.events, 0);
        assert_eq!(carry_stats.route_cached, 1);
        let receiver_policy = receiver_store
            .control_policy_snapshot()
            .expect("Carry control policy");
        let carried = match receiver_store
            .get_transfer_with_policy(&receiver_policy, carried_id)
            .expect("Carry exact transfer")
        {
            Some(StoredEventTransfer::RouteCached(event)) => event,
            _ => panic!("content-capable Carry crossed semantic acceptance boundary"),
        };
        let mut receiver_verifier = open_test_sealer(&receiver_mission);
        let carried_route = receiver_verifier
            .verify_event(&carried.sealed)
            .expect("content-capable receiver verifies route");
        assert!(matches!(
            receiver_verifier
                .verify_event_content(carried_route, &carried.sealed)
                .expect("content-capable receiver opens Carry bytes"),
            EventContentVerification::ContentVerified { .. }
        ));
        stale_guard
            .check(&receiver_store)
            .expect("unchanged Carry guard remains current");

        seed_test_event_subscription(
            &receiver_store,
            EventSubscriptionMode::Consume,
            &topic,
            &scope,
            b"mode-overlapping-consume",
        );
        assert!(matches!(
            stale_guard.check(&receiver_store),
            Err(NodeError::Store(StoreError::EventSelectorRevisionChanged))
        ));
        let current_policy = receiver_store
            .event_replication_policy_snapshot()
            .expect("current Consume replication policy");
        assert_eq!(current_policy.selector_revision(), stale_revision + 1);
        assert_eq!(current_policy.selectors().len(), 1);
        assert_eq!(
            current_policy.selectors()[0].mode(),
            EventSubscriptionMode::Consume
        );
        assert_eq!(
            current_policy.effective_mode(&topic, &scope),
            Some(EventSubscriptionMode::Consume)
        );

        let consumed_id = publish_test_epoch_one_event(
            &server_store,
            &mut server_sealer,
            &topic,
            &scope,
            b"overlapping-consume",
        );
        let server_policy = server_store
            .control_policy_snapshot()
            .expect("server policy for stale admission evidence");
        let consumed_bytes = match server_store
            .get_transfer_with_policy(&server_policy, consumed_id)
            .expect("server exact Consume candidate")
        {
            Some(StoredEventTransfer::Accepted(event)) => event.sealed,
            _ => panic!("server lost the semantic Consume candidate"),
        };
        let consumed_route = receiver_verifier
            .verify_event(&consumed_bytes)
            .expect("receiver verifies stale admission candidate route");
        let EventContentVerification::ContentVerified {
            event: consumed_event,
            ..
        } = receiver_verifier
            .verify_event_content(consumed_route, &consumed_bytes)
            .expect("receiver opens stale admission candidate")
        else {
            panic!("content-capable receiver lost its content grant");
        };
        let stale_error = receiver_store
            .apply_verified_event_with_replication_policy(
                stale_guard.replication_policy(),
                &consumed_event,
                &consumed_bytes,
            )
            .expect_err("stale Carry snapshot must not admit after Consume mutation");
        assert!(matches!(
            stale_error,
            StoreError::EventSelectorRevisionChanged
        ));
        assert!(
            receiver_store
                .get_transfer_with_policy(current_policy.control_policy(), consumed_id)
                .expect("stale candidate absence")
                .is_none()
        );
        let (consume_receipt, _) = contact_test_pair(
            server_store.clone(),
            server_mission,
            &receiver_store,
            receiver_mission,
        )
        .await;
        assert_eq!(consume_receipt.fetched, 2);
        assert_eq!(consume_receipt.inserted, 2);
        assert_eq!(
            receiver_store.event_count().expect("Consume Event count"),
            2
        );
        let consume_stats = receiver_store.event_stats().expect("Consume Event stats");
        assert_eq!(consume_stats.events, 2);
        assert_eq!(consume_stats.route_cached, 0);
        assert!(matches!(
            receiver_store
                .get_transfer_with_policy(current_policy.control_policy(), consumed_id)
                .expect("Consume exact transfer"),
            Some(StoredEventTransfer::Accepted(_))
        ));
        assert!(matches!(
            receiver_store
                .get_transfer_with_policy(current_policy.control_policy(), carried_id)
                .expect("promoted Carry exact transfer"),
            Some(StoredEventTransfer::Accepted(_))
        ));

        drop(server_store);
        drop(receiver_store);
        for state in [server_state, receiver_state] {
            fs::remove_dir_all(state).expect("cleanup mode test state");
        }
    }

    #[tokio::test]
    async fn pending_control_never_activates_and_defers_event_application_and_contact() {
        let state = root("pending-control-defers-event");
        fs::create_dir_all(&state).expect("state root");
        let services = control_test_services([0xb1; 32]);
        let mut member = open_test_sealer(&services.member);
        let store = Store::open_for_mission(state.join(STORE_FILE), member.mission_authority_id())
            .expect("member store");
        let recipients = vec![
            ScopeRekeyRecipient::member(
                services.authority.identity(),
                vec![services.topic.clone()],
            )
            .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.member.identity(), vec![services.topic.clone()])
                .expect("member recipient"),
        ];
        let (_missing_first, second) =
            seal_test_revoke_then_rekey(&services, services.other.identity(), recipients);
        let verified_second = member
            .verify_control(&second)
            .expect("verify pending rekey");
        let pending = store
            .ingest_verified_control(&verified_second, &second)
            .expect("retain pending rekey");
        assert!(matches!(pending, ControlOutcome::Pending { .. }));
        assert!(pending.activated().is_empty());
        assert_eq!(
            activate_committed_controls(&store, &mut member, pending.activated(), None)
                .expect("empty activation suffix"),
            0
        );
        assert_eq!(store.control_stats().expect("control stats").pending, 1);

        let policy_lock = Arc::new(RwLock::new(()));
        let lease = policy_lock.read_owned().await;
        let contact_error = match EventLaneGuard::capture(
            lease,
            &store,
            services.member.identity(),
            services.authority.identity(),
            0,
        ) {
            Err(error) => error,
            Ok(_) => panic!("pending gap must block Event contact"),
        };
        assert!(matches!(
            contact_error,
            NodeError::Store(StoreError::ControlPolicyUnsettled { pending: 1 })
        ));

        let mut application = open_test_sealer(&services.member);
        let mut application_head = None;
        assert_eq!(
            refresh_application_policy(
                &store,
                &services.member,
                &mut application,
                &mut application_head,
            )
            .expect("pending application state defers"),
            None
        );
        assert_eq!(store.event_count().expect("Event count"), 0);
        fs::remove_dir_all(state).expect("cleanup");
    }

    #[test]
    fn revoke_then_rekey_suffix_fully_activates_before_local_revocation_closes_runtime() {
        let state = root("local-revoke-rekey-suffix");
        fs::create_dir_all(&state).expect("state root");
        let services = control_test_services([0xb2; 32]);
        let mut member = open_test_sealer(&services.member);
        let store = Store::open_for_mission(state.join(STORE_FILE), member.mission_authority_id())
            .expect("member store");
        let recipients = vec![
            ScopeRekeyRecipient::member(
                services.authority.identity(),
                vec![services.topic.clone()],
            )
            .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.other.identity(), vec![services.topic.clone()])
                .expect("surviving recipient"),
        ];
        let (first, second) =
            seal_test_revoke_then_rekey(&services, services.member.identity(), recipients);
        let verified_second = member
            .verify_control(&second)
            .expect("verify pending second");
        let second_id = ControlTransferId::new(verified_second.envelope_id());
        let pending = store
            .ingest_verified_control(&verified_second, &second)
            .expect("retain second out of order");
        assert!(matches!(pending, ControlOutcome::Pending { .. }));

        let first_id = ControlTransferId::new(
            member
                .verify_control(&first)
                .expect("verify first")
                .envelope_id(),
        );
        let error = accept_received_control(
            &store,
            &mut member,
            services.authority.identity(),
            first_id,
            &first,
        )
        .expect_err("local revocation closes only after the full committed suffix");
        assert!(matches!(
            error,
            NodeError::Revoked(principal) if principal == services.member.identity()
        ));
        let stats = store.control_stats().expect("control stats");
        assert_eq!(stats.applied, 2);
        assert_eq!(stats.pending, 0);
        assert_eq!(
            store.control_head().expect("control head"),
            Some((2, second_id))
        );

        // Restart deterministically replays both exact links before the caller
        // enforces the durable local-revocation startup gate.
        let replayed = open_replayed_verifier(&store, &services.member)
            .expect("complete applied prefix replays");
        let restart_error = ensure_principal_active(&store, replayed.identity())
            .expect_err("revoked local identity cannot reopen selected runtime");
        assert!(matches!(
            restart_error,
            NodeError::Revoked(principal) if principal == services.member.identity()
        ));
        fs::remove_dir_all(state).expect("cleanup");
    }

    #[test]
    fn scope_rekey_publication_retry_requires_exact_canonical_durable_intent() {
        let state = root("rekey-publication-intent");
        let services = control_test_services([0xb3; 32]);
        let recipients = vec![
            ScopeRekeyRecipient::member(
                services.authority.identity(),
                vec![services.topic.clone()],
            )
            .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.member.identity(), vec![services.topic.clone()])
                .expect("member recipient"),
        ];
        let first = publish_scope_rekey_control(
            &state,
            &services.authority,
            &services.registry,
            0,
            services.scope.clone(),
            2,
            recipients.clone(),
        )
        .expect("commit rekey intent");
        assert!(first.emitted);

        // This is the crash-after-commit path: a new Store/provider instance
        // reseals randomly, authenticates the registry again, and reports
        // Existing only after the canonical durable intent matches exactly.
        let exact_retry = publish_scope_rekey_control(
            &state,
            &services.authority,
            &services.registry,
            0,
            services.scope.clone(),
            2,
            recipients.clone(),
        )
        .expect("exact intent retry");
        assert!(!exact_retry.emitted);
        assert_eq!(exact_retry.transfer_id, first.transfer_id);
        assert_eq!(exact_retry.sequence, first.sequence);

        let reordered_retry = publish_scope_rekey_control(
            &state,
            &services.authority,
            &services.registry,
            0,
            services.scope.clone(),
            2,
            recipients.iter().cloned().rev().collect(),
        )
        .expect("recipient ordering is canonical");
        assert!(!reordered_retry.emitted);
        assert_eq!(reordered_retry.transfer_id, first.transfer_id);

        let changed_recipients = vec![
            ScopeRekeyRecipient::member(
                services.authority.identity(),
                vec![services.topic.clone()],
            )
            .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.other.identity(), vec![services.topic.clone()])
                .expect("different member recipient"),
        ];
        let changed_recipient_error = publish_scope_rekey_control(
            &state,
            &services.authority,
            &services.registry,
            0,
            services.scope.clone(),
            2,
            changed_recipients,
        )
        .expect_err("same epoch with another recipient policy must fail closed");
        assert!(matches!(
            changed_recipient_error,
            NodeError::Store(StoreError::ControlPublicationIntentConflict { transfer_id })
                if transfer_id == first.transfer_id
        ));

        let changed_registry_error = publish_scope_rekey_control(
            &state,
            &services.authority,
            &services.registry_next,
            0,
            services.scope.clone(),
            2,
            recipients,
        )
        .expect_err("same epoch with another authenticated registry must fail closed");
        assert!(matches!(
            changed_registry_error,
            NodeError::Store(StoreError::ControlPublicationIntentConflict { transfer_id })
                if transfer_id == first.transfer_id
        ));
        fs::remove_dir_all(state).expect("cleanup");
    }

    #[tokio::test]
    async fn same_contact_rekey_uses_authenticated_peer_identity_for_member_route_and_exclusion() {
        let authority_state = root("same-contact-rekey-authority");
        let member_state = root("same-contact-rekey-member");
        let route_state = root("same-contact-rekey-route");
        let excluded_state = root("same-contact-rekey-excluded");
        for state in [&member_state, &route_state, &excluded_state] {
            fs::create_dir_all(state).expect("contact state root");
        }
        let services = control_test_services([0xb4; 32]);
        let recipients = vec![
            ScopeRekeyRecipient::member(
                services.authority.identity(),
                vec![services.topic.clone()],
            )
            .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.member.identity(), vec![services.topic.clone()])
                .expect("content member recipient"),
            ScopeRekeyRecipient::route_only(services.other.identity()),
        ];
        let publication = publish_scope_rekey_control(
            &authority_state,
            &services.authority,
            &services.registry_next,
            0,
            services.scope.clone(),
            2,
            recipients,
        )
        .expect("publish recipient-filtered rekey");
        assert!(publication.emitted);

        let authority_bootstrap = open_test_sealer(&services.authority);
        let authority_store = Arc::new(
            Store::open_for_mission(
                authority_state.join(STORE_FILE),
                authority_bootstrap.mission_authority_id(),
            )
            .expect("authority store"),
        );
        let mut authority_verifier = open_replayed_verifier(&authority_store, &services.authority)
            .expect("authority replay");
        assert_eq!(
            authority_store
                .control_stats()
                .expect("authority control stats")
                .pending,
            0
        );
        let event =
            publish_test_epoch_two_event(&authority_store, &mut authority_verifier, &services);

        let member_store = Store::open_for_mission(
            member_state.join(STORE_FILE),
            open_test_sealer(&services.member).mission_authority_id(),
        )
        .expect("member store");
        seed_test_event_subscription(
            &member_store,
            EventSubscriptionMode::Consume,
            &services.topic,
            &services.scope,
            b"same-contact-member",
        );
        let (member_receipt, _) = contact_test_pair(
            authority_store.clone(),
            services.authority.clone(),
            &member_store,
            services.member.clone(),
        )
        .await;
        assert_eq!(member_receipt.controls_activated, 1);
        assert_eq!(member_receipt.controls_remaining, 0);
        assert_eq!(member_receipt.fetched, 1);
        assert_eq!(member_receipt.inserted, 1);
        assert_eq!(member_store.event_count().expect("member Events"), 1);
        let member_controls = member_store.control_stats().expect("member controls");
        assert_eq!(member_controls.applied, 1);
        assert_eq!(member_controls.pending, 0);
        let member_policy = member_store
            .control_policy_snapshot()
            .expect("member settled policy");
        let member_stored = match member_store
            .get_transfer_with_policy(&member_policy, event.transfer_id)
            .expect("member exact Event")
        {
            Some(StoredEventTransfer::Accepted(event)) => event,
            _ => panic!("included member did not content-accept epoch-two Event"),
        };
        let mut member_verifier =
            open_replayed_verifier(&member_store, &services.member).expect("member replay");
        let member_route = member_verifier
            .verify_event(&member_stored.sealed)
            .expect("member verifies epoch-two route");
        assert!(matches!(
            member_verifier
                .verify_event_content(member_route, &member_stored.sealed)
                .expect("member opens epoch-two content"),
            EventContentVerification::ContentVerified { .. }
        ));

        let route_store = Store::open_for_mission(
            route_state.join(STORE_FILE),
            open_test_sealer(&services.other).mission_authority_id(),
        )
        .expect("route-only store");
        seed_test_event_subscription(
            &route_store,
            EventSubscriptionMode::Carry,
            &services.topic,
            &services.scope,
            b"same-contact-route",
        );
        let (route_receipt, _) = contact_test_pair(
            authority_store.clone(),
            services.authority.clone(),
            &route_store,
            services.other.clone(),
        )
        .await;
        assert_eq!(route_receipt.controls_activated, 1);
        assert_eq!(route_receipt.controls_remaining, 0);
        assert_eq!(route_receipt.fetched, 1);
        assert_eq!(route_receipt.inserted, 1);
        let route_stats = route_store.event_stats().expect("route-only stats");
        assert_eq!(route_stats.events, 0);
        assert_eq!(route_stats.route_cached, 1);
        let route_policy = route_store
            .control_policy_snapshot()
            .expect("route settled policy");
        let route_cached = match route_store
            .get_transfer_with_policy(&route_policy, event.transfer_id)
            .expect("route exact Event")
        {
            Some(StoredEventTransfer::RouteCached(event)) => event,
            _ => panic!("route-only recipient crossed semantic acceptance boundary"),
        };
        assert_eq!(route_cached.sealed, event.sealed);
        let mut route_verifier =
            open_replayed_verifier(&route_store, &services.other).expect("route replay");
        let route_capability = route_verifier
            .verify_event(&route_cached.sealed)
            .expect("route-only verifies epoch-two route");
        assert!(matches!(
            route_verifier
                .verify_event_content(route_capability, &route_cached.sealed)
                .expect("route-only content decision"),
            EventContentVerification::RouteOnly(_)
        ));

        let excluded_store = Store::open_for_mission(
            excluded_state.join(STORE_FILE),
            open_test_sealer(&services.excluded).mission_authority_id(),
        )
        .expect("excluded store");
        seed_test_event_subscription(
            &excluded_store,
            EventSubscriptionMode::Carry,
            &services.topic,
            &services.scope,
            b"same-contact-excluded",
        );
        let (excluded_receipt, _) = contact_test_pair(
            authority_store.clone(),
            services.authority.clone(),
            &excluded_store,
            services.excluded.clone(),
        )
        .await;
        assert_eq!(excluded_receipt.controls_activated, 1);
        assert_eq!(excluded_receipt.controls_remaining, 0);
        assert_eq!(excluded_receipt.fetched, 0);
        assert_eq!(excluded_receipt.offered, 0);
        let excluded_controls = excluded_store.control_stats().expect("excluded controls");
        assert_eq!(excluded_controls.applied, 1);
        assert_eq!(excluded_controls.pending, 0);
        assert_eq!(excluded_store.event_count().expect("excluded Events"), 0);
        assert_eq!(
            excluded_store
                .event_stats()
                .expect("excluded Event stats")
                .route_cached,
            0
        );
        let excluded_policy = excluded_store
            .control_policy_snapshot()
            .expect("excluded settled policy");
        assert!(
            excluded_store
                .transfer_inventory_with_policy(&excluded_policy)
                .expect("excluded inventory")
                .is_empty()
        );
        let mut excluded_verifier = open_replayed_verifier(&excluded_store, &services.excluded)
            .expect("excluded restart replay");
        assert!(
            excluded_verifier.verify_event(&event.sealed).is_err(),
            "excluded restart recovered an epoch-two route grant"
        );

        // Dynamic epoch authorization is keyed by the independently hybrid-
        // authenticated mission NodeId after exact provider replay. Static
        // baseline commitment input is deliberately empty here.
        let authority_policy = authority_store
            .control_policy_snapshot()
            .expect("authority settled policy");
        let receiver_interest = exact_event_interest(&services.topic, &services.scope);
        assert_eq!(
            transfer_inventory_for_peer(
                &authority_store,
                &authority_policy,
                &mut authority_verifier,
                services.member.identity(),
                &[],
                &receiver_interest,
            )
            .expect("member dynamic inventory")
            .len(),
            1
        );
        assert_eq!(
            transfer_inventory_for_peer(
                &authority_store,
                &authority_policy,
                &mut authority_verifier,
                services.other.identity(),
                &[],
                &receiver_interest,
            )
            .expect("route dynamic inventory")
            .len(),
            1
        );
        assert!(
            transfer_inventory_for_peer(
                &authority_store,
                &authority_policy,
                &mut authority_verifier,
                services.excluded.identity(),
                &[],
                &receiver_interest,
            )
            .expect("excluded dynamic inventory")
            .is_empty()
        );

        drop(authority_store);
        for state in [authority_state, member_state, route_state, excluded_state] {
            fs::remove_dir_all(state).expect("cleanup same-contact state");
        }
    }

    #[test]
    fn valid_relay_cannot_reintroduce_event_from_durably_revoked_source() {
        let authority_state = root("revoked-source-authority");
        let source_state = root("revoked-source-member");
        let relay_state = root("revoked-source-relay");
        for state in [&authority_state, &source_state, &relay_state] {
            fs::create_dir_all(state).expect("revoked-source state");
        }
        let services = control_test_services([0xb5; 32]);
        let mut authority = open_test_sealer(&services.authority);
        let mut source = open_test_sealer(&services.member);
        let mut relay = open_test_sealer(&services.other);
        let authority_store = Store::open_for_mission(
            authority_state.join(STORE_FILE),
            authority.mission_authority_id(),
        )
        .expect("authority store");
        let source_store =
            Store::open_for_mission(source_state.join(STORE_FILE), source.mission_authority_id())
                .expect("source store");
        let relay_store =
            Store::open_for_mission(relay_state.join(STORE_FILE), relay.mission_authority_id())
                .expect("relay store");

        let recipients = vec![
            ScopeRekeyRecipient::member(authority.identity(), vec![services.topic.clone()])
                .expect("authority recipient"),
            ScopeRekeyRecipient::member(source.identity(), vec![services.topic.clone()])
                .expect("source recipient"),
            ScopeRekeyRecipient::route_only(relay.identity()),
        ];
        let (rekey, _) = authority
            .seal_chained_scope_rekey_control_from_registry(
                &services.registry,
                0,
                services.scope.clone(),
                2,
                recipients,
                1,
                None,
            )
            .expect("seal initial rekey");
        let rekey_id = ControlTransferId::new(
            authority
                .verify_control(&rekey)
                .expect("verify rekey")
                .envelope_id(),
        );
        for (store, verifier, peer) in [
            (&authority_store, &mut authority, services.other.identity()),
            (&source_store, &mut source, services.authority.identity()),
            (&relay_store, &mut relay, services.authority.identity()),
        ] {
            let accepted = accept_received_control(store, verifier, peer, rekey_id, &rekey)
                .expect("apply initial rekey");
            assert_eq!(accepted.activated, 1);
            assert_eq!(store.control_stats().expect("settled rekey").pending, 0);
        }
        seed_test_event_subscription(
            &authority_store,
            EventSubscriptionMode::Consume,
            &services.topic,
            &services.scope,
            b"revoked-source-authority-consume",
        );
        seed_test_event_subscription(
            &relay_store,
            EventSubscriptionMode::Carry,
            &services.topic,
            &services.scope,
            b"revoked-source-relay-carry",
        );

        let source_policy = source_store
            .control_policy_snapshot()
            .expect("source policy");
        let reservation = source_store
            .reserve_event_with_policy(
                &source_policy,
                source.identity(),
                &services.topic,
                &services.scope,
            )
            .expect("source reservation");
        let payload = b"pre-revocation source Event";
        let header = reservation
            .header(
                Priority::Immediate,
                b"revoked-source".to_vec(),
                None,
                payload.len() as u64,
                false,
                2,
            )
            .expect("source Event header");
        let sealed = source
            .seal_event(&header, payload)
            .expect("seal source Event");
        let source_route = source
            .verify_event(&sealed.bytes)
            .expect("verify source route");
        let EventContentVerification::ContentVerified {
            event: source_event,
            ..
        } = source
            .verify_event_content(source_route, &sealed.bytes)
            .expect("verify source content")
        else {
            panic!("source lost content grant");
        };
        source_store
            .commit_reserved_event_with_policy(
                &source_policy,
                &reservation,
                &source_event,
                &sealed.bytes,
            )
            .expect("commit source Event");
        let event_id = EventTransferId::new(source_event.envelope_id());
        let receiver_interest = exact_event_interest(&services.topic, &services.scope);
        let authority_replication_policy = authority_store
            .event_replication_policy_snapshot()
            .expect("authority pre-revoke replication policy");
        assert!(
            accept_received_transfer(
                &authority_store,
                &mut authority,
                EventReceiveAuthority {
                    peer: source.identity(),
                    peer_route_commitments: &[],
                    receiver_interest: &receiver_interest,
                    local_replication_policy: &authority_replication_policy,
                },
                event_id,
                &sealed.bytes,
            )
            .expect("authority accepts active source Event")
        );

        let revocation = authority
            .seal_chained_revocation_control(source.identity(), 1, 2, Some(*rekey_id.as_bytes()))
            .expect("seal source revocation");
        let revocation_id = ControlTransferId::new(
            authority
                .verify_control(&revocation)
                .expect("verify source revocation")
                .envelope_id(),
        );
        for (store, verifier, peer) in [
            (&authority_store, &mut authority, services.other.identity()),
            (&relay_store, &mut relay, services.authority.identity()),
        ] {
            let accepted =
                accept_received_control(store, verifier, peer, revocation_id, &revocation)
                    .expect("apply source revocation");
            assert_eq!(accepted.activated, 1);
        }

        let authority_replication_policy = authority_store
            .event_replication_policy_snapshot()
            .expect("authority post-revoke replication policy");
        let authority_policy = authority_replication_policy.control_policy();
        assert!(
            transfer_inventory_for_peer(
                &authority_store,
                authority_policy,
                &mut authority,
                relay.identity(),
                &[],
                &receiver_interest,
            )
            .expect("relay inventory after source revocation")
            .is_empty(),
            "revoked source Event identity leaked through a valid relay path"
        );
        let serve_error =
            load_verified_transfer(&authority_store, authority_policy, &mut authority, event_id)
                .expect_err("revoked source Event cannot be served");
        assert!(matches!(
            serve_error,
            NodeError::Revoked(principal) if principal == source.identity()
        ));
        let reintroduction_error = accept_received_transfer(
            &authority_store,
            &mut authority,
            EventReceiveAuthority {
                peer: relay.identity(),
                peer_route_commitments: &[],
                receiver_interest: &receiver_interest,
                local_replication_policy: &authority_replication_policy,
            },
            event_id,
            &sealed.bytes,
        )
        .expect_err("valid relay cannot reintroduce revoked-source bytes to a member");
        assert!(matches!(
            reintroduction_error,
            NodeError::Revoked(principal) if principal == source.identity()
        ));

        let relay_replication_policy = relay_store
            .event_replication_policy_snapshot()
            .expect("relay post-revoke replication policy");
        let relay_error = accept_received_transfer(
            &relay_store,
            &mut relay,
            EventReceiveAuthority {
                peer: authority.identity(),
                peer_route_commitments: &[],
                receiver_interest: &receiver_interest,
                local_replication_policy: &relay_replication_policy,
            },
            event_id,
            &sealed.bytes,
        )
        .expect_err("valid relay cannot reintroduce revoked-source bytes");
        assert!(matches!(
            relay_error,
            NodeError::Revoked(principal) if principal == source.identity()
        ));
        assert_eq!(relay_store.event_count().expect("relay Event count"), 0);
        assert_eq!(
            relay_store
                .event_stats()
                .expect("relay Event stats")
                .route_cached,
            0
        );

        drop(authority_store);
        drop(source_store);
        drop(relay_store);
        for state in [authority_state, source_state, relay_state] {
            fs::remove_dir_all(state).expect("cleanup revoked-source state");
        }
    }

    #[tokio::test]
    async fn post_authority_revocation_control_ingest_surfaces_exact_durable_principal() {
        let state = root("authority-revocation-attribution");
        let peer_state = root("authority-revocation-event-peer");
        fs::create_dir_all(&state).expect("authority-revocation state");
        fs::create_dir_all(&peer_state).expect("authority-revocation peer state");
        let services = control_test_services([0xb6; 32]);
        let mut authority = open_test_sealer(&services.authority);
        let mut member = open_test_sealer(&services.member);
        let store = Arc::new(
            Store::open_for_mission(state.join(STORE_FILE), member.mission_authority_id())
                .expect("member store"),
        );
        let stable_authority = authority.mission_authority_id();
        let first = authority
            .seal_chained_revocation_control(stable_authority, 1, 1, None)
            .expect("seal authority revocation");
        let first_id = ControlTransferId::new(
            authority
                .verify_control(&first)
                .expect("verify authority revocation")
                .envelope_id(),
        );
        let accepted =
            accept_received_control(&store, &mut member, authority.identity(), first_id, &first)
                .expect("commit authority revocation");
        assert_eq!(accepted.activated, 1);
        assert!(
            store
                .is_control_principal_revoked(stable_authority)
                .expect("authority revocation state")
        );

        let second = authority
            .seal_chained_revocation_control(
                services.other.identity(),
                1,
                2,
                Some(*first_id.as_bytes()),
            )
            .expect("seal post-revocation control");
        let second_id = ControlTransferId::new(
            authority
                .verify_control(&second)
                .expect("verify post-revocation control")
                .envelope_id(),
        );
        let error = accept_received_control(
            &store,
            &mut member,
            authority.identity(),
            second_id,
            &second,
        )
        .expect_err("revoked authority cannot append another control");
        assert!(matches!(
            error,
            NodeError::Revoked(principal) if principal == stable_authority
        ));
        let stats = store.control_stats().expect("control stats");
        assert_eq!(stats.applied, 1);
        assert_eq!(stats.pending, 0);
        assert!(
            store
                .get_control(second_id)
                .expect("second lookup")
                .is_none()
        );

        // Revoking the stable control authority freezes further control
        // append; it does not revoke this non-authority publisher or turn the
        // retained Event plane off. Exercise the runtime's policy-bound local
        // publication and per-peer inventory path under that exact state.
        let policy = store
            .control_policy_snapshot()
            .expect("settled Event policy after authority revocation");
        let reservation = store
            .reserve_event_with_policy(&policy, member.identity(), &services.topic, &services.scope)
            .expect("reserve Event after authority revocation");
        let payload = b"nonrevoked Event continuity";
        let header = reservation
            .header(
                Priority::Immediate,
                b"authority-revoked-event-continuity".to_vec(),
                None,
                payload.len() as u64,
                false,
                1,
            )
            .expect("Event continuity header");
        let sealed = member
            .seal_event(&header, payload)
            .expect("seal Event after authority revocation");
        let route = member
            .verify_event(&sealed.bytes)
            .expect("verify Event continuity route");
        let EventContentVerification::ContentVerified { event, .. } = member
            .verify_event_content(route, &sealed.bytes)
            .expect("verify Event continuity content")
        else {
            panic!("nonrevoked member lost retained content grant");
        };
        store
            .commit_reserved_event_with_policy(&policy, &reservation, &event, &sealed.bytes)
            .expect("commit Event after authority revocation");
        let transfer_id = EventTransferId::new(event.envelope_id());
        let peer_store =
            Store::open_for_mission(peer_state.join(STORE_FILE), member.mission_authority_id())
                .expect("nonrevoked peer store");
        seed_test_event_subscription(
            &peer_store,
            EventSubscriptionMode::Consume,
            &services.topic,
            &services.scope,
            b"post-authority-revocation-peer",
        );
        let (client_receipt, server_receipt) = contact_test_pair(
            store.clone(),
            services.member.clone(),
            &peer_store,
            services.other.clone(),
        )
        .await;
        assert!(
            client_receipt.inserted + server_receipt.inserted >= 1,
            "post-authority-revocation contact transferred no nonrevoked Event"
        );
        assert!(
            peer_store
                .get_event(transfer_id)
                .expect("peer Event lookup")
                .is_some(),
            "authority revocation improperly stopped nonrevoked Event replication"
        );
        drop(peer_store);
        drop(store);
        fs::remove_dir_all(state).expect("cleanup authority-revocation state");
        fs::remove_dir_all(peer_state).expect("cleanup authority-revocation peer state");
    }

    #[tokio::test]
    async fn event_read_lease_serializes_control_commit_and_stale_snapshot_rejects_admission() {
        let state = root("event-policy-race");
        fs::create_dir_all(&state).expect("policy-race state");
        let services = control_test_services([0xb7; 32]);
        let member = open_test_sealer(&services.member);
        let store = Arc::new(
            Store::open_for_mission(state.join(STORE_FILE), member.mission_authority_id())
                .expect("member store"),
        );
        let stale_policy = store.control_policy_snapshot().expect("initial policy");
        let reservation = store
            .reserve_event_with_policy(
                &stale_policy,
                member.identity(),
                &services.topic,
                &services.scope,
            )
            .expect("stale reservation");
        let payload = b"must not cross a raced policy";
        let header = reservation
            .header(
                Priority::Immediate,
                b"policy-race".to_vec(),
                None,
                payload.len() as u64,
                false,
                1,
            )
            .expect("policy-race header");
        let mut publishing_member = open_test_sealer(&services.member);
        let sealed = publishing_member
            .seal_event(&header, payload)
            .expect("seal raced Event");
        let route = publishing_member
            .verify_event(&sealed.bytes)
            .expect("verify raced route");
        let EventContentVerification::ContentVerified { event, .. } = publishing_member
            .verify_event_content(route, &sealed.bytes)
            .expect("verify raced content")
        else {
            panic!("member must open its raced Event");
        };

        let mut authority = open_test_sealer(&services.authority);
        let control = authority
            .seal_chained_revocation_control(services.other.identity(), 1, 1, None)
            .expect("seal racing control");
        let control_id = ControlTransferId::new(
            authority
                .verify_control(&control)
                .expect("verify racing control")
                .envelope_id(),
        );
        let policy_lock = Arc::new(RwLock::new(()));
        let event_lease = policy_lock.clone().read_owned().await;
        let (started_sender, mut started_receiver) = mpsc::channel(1);
        let writer = tokio::spawn({
            let store = store.clone();
            let policy_lock = policy_lock.clone();
            let mission = services.member.clone();
            let peer = services.authority.identity();
            async move {
                started_sender.send(()).await.expect("signal writer");
                let _control_lease = policy_lock.write_owned().await;
                let mut verifier = open_test_sealer(&mission);
                accept_received_control(&store, &mut verifier, peer, control_id, &control)
            }
        });
        started_receiver.recv().await.expect("writer started");
        sleep(Duration::from_millis(25)).await;
        assert_eq!(
            store.control_head().expect("head while Event lease held"),
            None,
            "control commit crossed the Event disclosure lease"
        );
        drop(event_lease);
        writer
            .await
            .expect("writer task")
            .expect("control commit after Event lease");
        assert_eq!(
            store.control_head().expect("head after writer"),
            Some((1, control_id))
        );

        let admission_error = store
            .commit_reserved_event_with_policy(&stale_policy, &reservation, &event, &sealed.bytes)
            .expect_err("stale policy must fail in the Event write transaction");
        assert!(matches!(admission_error, StoreError::ControlPolicyChanged));
        assert_eq!(store.event_count().expect("Event count"), 0);
        drop(store);
        fs::remove_dir_all(state).expect("cleanup policy-race state");
    }

    #[tokio::test]
    async fn durable_local_and_authenticated_peer_revocation_precede_identity_and_inventory() {
        let local_state = root("revoked-local-before-bind");
        let peer_state = root("revoked-peer-before-inventory");
        fs::create_dir_all(&local_state).expect("local state");
        fs::create_dir_all(&peer_state).expect("peer state");
        let services = control_test_services([0xb8; 32]);

        let mut authority = open_test_sealer(&services.authority);
        let local_revocation = authority
            .seal_chained_revocation_control(services.member.identity(), 1, 1, None)
            .expect("seal local revocation");
        let local_revocation_id = ControlTransferId::new(
            authority
                .verify_control(&local_revocation)
                .expect("verify local revocation")
                .envelope_id(),
        );
        {
            let mut local = open_test_sealer(&services.member);
            let store =
                Store::open_for_mission(local_state.join(STORE_FILE), local.mission_authority_id())
                    .expect("local store");
            let error = accept_received_control(
                &store,
                &mut local,
                services.authority.identity(),
                local_revocation_id,
                &local_revocation,
            )
            .expect_err("local revocation closes contact after commit");
            assert!(matches!(
                error,
                NodeError::Revoked(principal) if principal == services.member.identity()
            ));
        }
        let startup_error = run_node(NodeConfig {
            state: local_state.clone(),
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            mission: services.member.clone(),
            peers: Vec::new(),
            sync_interval: Duration::from_millis(10),
            run_for: Some(Duration::from_millis(1)),
            application: NodeApplication::Relay,
        })
        .await
        .expect_err("durably revoked local node cannot restart");
        assert!(matches!(
            startup_error,
            NodeError::Revoked(principal) if principal == services.member.identity()
        ));
        assert!(
            !local_state.join("identity.key").exists(),
            "carrier identity was created before durable revocation replay"
        );

        let mut peer_authority = open_test_sealer(&services.authority);
        let peer_revocation = peer_authority
            .seal_chained_revocation_control(services.member.identity(), 1, 1, None)
            .expect("seal peer revocation");
        let peer_revocation_id = ControlTransferId::new(
            peer_authority
                .verify_control(&peer_revocation)
                .expect("verify peer revocation")
                .envelope_id(),
        );
        let mut local = open_test_sealer(&services.other);
        let peer_store =
            Store::open_for_mission(peer_state.join(STORE_FILE), local.mission_authority_id())
                .expect("peer-gate store");
        accept_received_control(
            &peer_store,
            &mut local,
            services.authority.identity(),
            peer_revocation_id,
            &peer_revocation,
        )
        .expect("commit peer revocation");
        let policy_lock = Arc::new(RwLock::new(()));
        let lease = policy_lock.read_owned().await;
        let peer_error = match EventLaneGuard::capture(
            lease,
            &peer_store,
            services.other.identity(),
            services.member.identity(),
            0,
        ) {
            Err(error) => error,
            Ok(_) => panic!("revoked authenticated peer reached Event inventory"),
        };
        assert!(matches!(
            peer_error,
            NodeError::Revoked(principal) if principal == services.member.identity()
        ));
        assert_eq!(peer_store.event_count().expect("peer-gate Events"), 0);

        fs::remove_dir_all(local_state).expect("cleanup local state");
        fs::remove_dir_all(peer_state).expect("cleanup peer state");
    }

    #[test]
    fn stale_epoch_duplicate_fork_and_rollback_fail_without_policy_regression() {
        let state = root("stale-and-rollback-control");
        fs::create_dir_all(&state).expect("stale state");
        let services = control_test_services([0xb9; 32]);
        let mut authority = open_test_sealer(&services.authority);
        let mut member = open_test_sealer(&services.member);
        let store = Store::open_for_mission(state.join(STORE_FILE), member.mission_authority_id())
            .expect("member store");
        let recipients = vec![
            ScopeRekeyRecipient::member(
                services.authority.identity(),
                vec![services.topic.clone()],
            )
            .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.member.identity(), vec![services.topic.clone()])
                .expect("member recipient"),
        ];
        let (rekey, _) = authority
            .seal_chained_scope_rekey_control_from_registry(
                &services.registry,
                0,
                services.scope.clone(),
                2,
                recipients,
                1,
                None,
            )
            .expect("seal epoch-two rekey");
        let rekey_id = ControlTransferId::new(
            authority
                .verify_control(&rekey)
                .expect("verify rekey")
                .envelope_id(),
        );
        let accepted =
            accept_received_control(&store, &mut member, authority.identity(), rekey_id, &rekey)
                .expect("apply epoch-two rekey");
        assert!(accepted.retained);
        assert_eq!(accepted.activated, 1);

        let duplicate =
            accept_received_control(&store, &mut member, authority.identity(), rekey_id, &rekey)
                .expect("exact control duplicate");
        assert!(!duplicate.retained);
        assert_eq!(duplicate.activated, 0);
        assert_eq!(
            store
                .active_scope_epoch(&services.scope)
                .expect("active epoch")
                .map(|(epoch, _)| epoch),
            Some(2)
        );

        let mut stale_publisher =
            open_replayed_verifier(&store, &services.member).expect("member epoch-two replay");
        let policy = store.control_policy_snapshot().expect("epoch-two policy");
        let stale_reservation = store
            .reserve_event_with_policy(
                &policy,
                stale_publisher.identity(),
                &services.topic,
                &services.scope,
            )
            .expect("stale Event reservation");
        let payload = b"stale epoch one";
        let stale_header = stale_reservation
            .header(
                Priority::Immediate,
                b"stale-epoch".to_vec(),
                None,
                payload.len() as u64,
                false,
                1,
            )
            .expect("stale Event header");
        let stale_sealed = stale_publisher
            .seal_event(&stale_header, payload)
            .expect("seal stale Event");
        let stale_route = stale_publisher
            .verify_event(&stale_sealed.bytes)
            .expect("verify stale route");
        let EventContentVerification::ContentVerified {
            event: stale_event, ..
        } = stale_publisher
            .verify_event_content(stale_route, &stale_sealed.bytes)
            .expect("verify stale content")
        else {
            panic!("member lost epoch-one baseline content");
        };
        let stale_error = store
            .commit_reserved_event_with_policy(
                &policy,
                &stale_reservation,
                &stale_event,
                &stale_sealed.bytes,
            )
            .expect_err("stale epoch Event must fail in write transaction");
        assert!(matches!(
            stale_error,
            StoreError::EventKeyEpochStale {
                current: 2,
                received: 1
            }
        ));

        let mut fork_signer = open_test_sealer(&services.authority);
        let fork = fork_signer
            .seal_chained_revocation_control(services.other.identity(), 9, 1, None)
            .expect("seal fork");
        let fork_verified = member.verify_control(&fork).expect("verify fork");
        let fork_error = store
            .ingest_verified_control(&fork_verified, &fork)
            .expect_err("same-sequence fork must fail");
        assert!(matches!(fork_error, StoreError::ControlFork));

        let second = authority
            .seal_chained_revocation_control(
                services.other.identity(),
                2,
                2,
                Some(*rekey_id.as_bytes()),
            )
            .expect("seal monotonic revocation");
        let second_id = ControlTransferId::new(
            authority
                .verify_control(&second)
                .expect("verify monotonic revocation")
                .envelope_id(),
        );
        accept_received_control(
            &store,
            &mut member,
            authority.identity(),
            second_id,
            &second,
        )
        .expect("apply monotonic revocation");
        let mut rollback_signer = open_test_sealer(&services.authority);
        let rollback = rollback_signer
            .seal_chained_revocation_control(
                services.other.identity(),
                1,
                3,
                Some(*second_id.as_bytes()),
            )
            .expect("seal rollback candidate");
        let rollback_verified = member
            .verify_control(&rollback)
            .expect("verify rollback candidate");
        let rollback_error = store
            .ingest_verified_control(&rollback_verified, &rollback)
            .expect_err("revocation generation rollback must fail");
        assert!(matches!(rollback_error, StoreError::ControlRollback));
        assert_eq!(
            store.control_head().expect("final head"),
            Some((2, second_id))
        );
        assert_eq!(store.event_count().expect("Event count"), 0);
        fs::remove_dir_all(state).expect("cleanup stale state");
    }

    #[tokio::test]
    async fn authenticated_peer_without_scope_grant_learns_no_event_id_and_cannot_fetch() {
        let allowed_scope = Scope::new("test/route-acl/allowed").expect("allowed scope");
        let unrelated_scope = Scope::new("test/route-acl/unrelated").expect("unrelated scope");
        let topic = Topic::new("classified-event").expect("topic");
        let server_access =
            ProvisioningAccess::member(allowed_scope.clone(), vec![1], vec![topic.clone()])
                .expect("server access");
        let client_access =
            ProvisioningAccess::member(unrelated_scope, vec![1], vec![topic.clone()])
                .expect("client access");
        let mut provisioner =
            ReferenceProvisioner::from_seed([0x93; 32]).expect("route ACL provisioner");
        let server_mission = UnprotectedReferenceMission::from_bytes(
            provisioner
                .issue_node(1, &[server_access])
                .and_then(|bundle| bundle.to_bytes())
                .expect("server bundle"),
        )
        .expect("server mission");
        let client_mission = UnprotectedReferenceMission::from_bytes(
            provisioner
                .issue_node(2, &[client_access])
                .and_then(|bundle| bundle.to_bytes())
                .expect("client bundle"),
        )
        .expect("client mission");

        let server = Endpoint::bind(
            aster_iroh::SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("server address")),
        )
        .await
        .expect("server endpoint");
        let client = Endpoint::bind(
            aster_iroh::SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("client address")),
        )
        .await
        .expect("client endpoint");
        let server_root = root("route-acl-server");
        fs::create_dir_all(&server_root).expect("server root");
        let mut server_sealer = ReferenceEnvelopeSealer::open(
            server_mission.fresh_bundle().expect("fresh server bundle"),
        )
        .expect("server sealer");
        let server_store = Arc::new(
            Store::open_for_mission(
                server_root.join(STORE_FILE),
                server_sealer.mission_authority_id(),
            )
            .expect("server store"),
        );
        let reservation = server_store
            .reserve_event(server_sealer.identity(), &topic, &allowed_scope)
            .expect("reserve hidden Event");
        let payload = b"hidden";
        let header = reservation
            .header(
                Priority::Routine,
                b"hidden".to_vec(),
                None,
                payload.len() as u64,
                false,
                1,
            )
            .expect("hidden header");
        let sealed = server_sealer
            .seal_event(&header, payload)
            .expect("seal hidden Event");
        let route = server_sealer
            .verify_event(&sealed.bytes)
            .expect("verify hidden route");
        let EventContentVerification::ContentVerified { event, .. } = server_sealer
            .verify_event_content(route, &sealed.bytes)
            .expect("verify hidden content")
        else {
            panic!("server member must open its hidden Event");
        };
        server_store
            .commit_reserved_event(&reservation, &event, &sealed.bytes)
            .expect("commit hidden Event");
        let hidden_id = EventTransferId::new(event.envelope_id());
        let matching_interest = exact_event_interest(&topic, &allowed_scope);

        let server_task = tokio::spawn({
            let server = server.clone();
            let store = server_store.clone();
            let credentials = server_mission.clone();
            let allowed = BTreeSet::from([client.id()]);
            let peer = MissionPeerBinding::new(client.id(), client_mission.identity());
            async move {
                let connection = server.accept(&allowed).await.expect("accept carrier");
                serve_connection(
                    store,
                    connection,
                    credentials,
                    peer,
                    Arc::new(RwLock::new(())),
                )
                .await
            }
        });

        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address: loopback(&server),
            })
            .await
            .expect("connect carrier");
        let mut mission = initiate_over_iroh(
            &connection,
            client_mission.fresh_bundle().expect("fresh client bundle"),
            MissionPeerBinding::new(server.id(), server_mission.identity()),
        )
        .await
        .expect("valid mission handshake");
        let mut receipt = finish_equal_difference(
            &connection,
            &mut mission,
            InventorySnapshot::default(),
            matching_interest.clone(),
        )
        .await;
        assert_eq!(
            request_mission_frame(
                &connection,
                &mut mission,
                Frame::Finish {
                    direction: EventDirection::ToSessionResponder,
                },
                &mut receipt,
            )
            .await
            .expect("finish empty responder receive lane"),
            Frame::Finished {
                direction: EventDirection::ToSessionResponder,
            }
        );
        reconcile_equal_event_lane(
            &connection,
            &mut mission,
            InventorySnapshot::default(),
            EventDirection::ToSessionInitiator,
            &mut receipt,
        )
        .await;
        let client_error = request_mission_frame(
            &connection,
            &mut mission,
            Frame::Fetch {
                direction: EventDirection::ToSessionInitiator,
                id: hidden_id,
            },
            &mut receipt,
        )
        .await
        .expect_err("out-of-scope hidden Event must not be fetchable");
        assert!(matches!(
            client_error,
            NodeError::Carrier(_) | NodeError::Mission(_)
        ));
        let server_error = server_task
            .await
            .expect("server task")
            .expect_err("server must reject hidden fetch");
        assert!(
            server_error
                .to_string()
                .contains("outside this authenticated contact's negotiated difference")
        );
        assert_eq!(server_store.event_count().expect("server Event count"), 1);
        client.close().await;
        server.close().await;
        seed_test_event_subscription(
            &server_store,
            EventSubscriptionMode::Consume,
            &topic,
            &allowed_scope,
            b"local-receiver-baseline",
        );
        let server_policy = server_store
            .event_replication_policy_snapshot()
            .expect("server replication policy");
        assert_eq!(
            transfer_inventory_for_receiver(
                &server_store,
                &server_policy,
                &mut server_sealer,
                &matching_interest,
            )
            .expect("local receiver baseline"),
            InventorySnapshot::new(vec![hidden_id.reconciliation_item_id()]),
            "receiver baseline must use the local current route grant, not the unrelated peer grant"
        );
        fs::remove_dir_all(server_root).expect("cleanup");
    }

    #[tokio::test]
    async fn right_carrier_with_wrong_expected_mission_fails_before_inventory() {
        let mut issued = issue_missions(3);
        let client_mission = issued.remove(0);
        let server_mission = issued.remove(0);
        let wrong_expected_client = issued.remove(0);
        let server = Endpoint::bind(
            aster_iroh::SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("server address")),
        )
        .await
        .expect("server endpoint");
        let client = Endpoint::bind(
            aster_iroh::SecretKey::generate(),
            EndpointConfig::direct("127.0.0.1:0".parse().expect("client address")),
        )
        .await
        .expect("client endpoint");
        let server_root = root("wrong-mission-server");
        let client_root = root("wrong-mission-client");
        fs::create_dir_all(&server_root).expect("server root");
        fs::create_dir_all(&client_root).expect("client root");
        let server_authority = ReferenceEnvelopeSealer::open(
            server_mission
                .credentials
                .fresh_bundle()
                .expect("server bundle"),
        )
        .expect("server sealer")
        .mission_authority_id();
        let client_authority = ReferenceEnvelopeSealer::open(
            client_mission
                .credentials
                .fresh_bundle()
                .expect("client bundle"),
        )
        .expect("client sealer")
        .mission_authority_id();
        let server_store = Arc::new(
            Store::open_for_mission(server_root.join(STORE_FILE), server_authority)
                .expect("server store"),
        );
        let client_store = Store::open_for_mission(client_root.join(STORE_FILE), client_authority)
            .expect("client store");
        let server_task = tokio::spawn({
            let server = server.clone();
            let server_store = server_store.clone();
            let credentials = server_mission.credentials.clone();
            let allowed = BTreeSet::from([client.id()]);
            let wrong_binding =
                MissionPeerBinding::new(client.id(), wrong_expected_client.identity);
            async move {
                let connection = server.accept(&allowed).await.expect("accept carrier");
                serve_connection(
                    server_store,
                    connection,
                    credentials,
                    wrong_binding,
                    Arc::new(RwLock::new(())),
                )
                .await
            }
        });
        let client_error = sync_once(
            &client_store,
            &client,
            client_mission.credentials,
            MissionExpectedPeer {
                carrier: ExpectedPeer {
                    id: server.id(),
                    address: loopback(&server),
                },
                mission: server_mission.identity,
            },
        )
        .await
        .expect_err("wrong expected mission must fail");
        assert!(
            matches!(client_error, NodeError::Carrier(_) | NodeError::Mission(_)),
            "unexpected client rejection: {client_error}"
        );
        let server_error = server_task
            .await
            .expect("server task")
            .expect_err("server must reject wrong mission identity");
        assert!(
            matches!(
                server_error,
                NodeError::Mission(MissionSessionError::MissionIdentityMismatch { .. })
            ),
            "unexpected server rejection: {server_error}"
        );
        assert_eq!(server_store.stats().expect("server stats").items, 0);
        assert_eq!(client_store.stats().expect("client stats").items, 0);
        client.close().await;
        server.close().await;
        fs::remove_dir_all(server_root).expect("server cleanup");
        fs::remove_dir_all(client_root).expect("client cleanup");
    }

    async fn assert_config_rejected_without_state(
        name: &str,
        peers: Vec<MissionExpectedPeer>,
        sync_interval: Duration,
        expected_message: &str,
    ) {
        let state = root(name);
        let error = run_node(NodeConfig {
            state: state.clone(),
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            mission: test_mission(),
            peers,
            sync_interval,
            run_for: Some(Duration::from_millis(1)),
            application: NodeApplication::Relay,
        })
        .await
        .expect_err("invalid configuration must fail");
        assert!(
            error.to_string().contains(expected_message),
            "unexpected error: {error}"
        );
        assert!(
            !state.exists(),
            "invalid configuration created state at {}",
            state.display()
        );
    }

    #[test]
    fn inspection_of_absent_state_does_not_create_it() {
        let state = root("inspect-absent");
        assert!(inspect_store(&state).is_err());
        assert!(!state.exists());
    }

    #[tokio::test]
    async fn pure_peer_configuration_is_rejected_before_any_state_is_created() {
        assert_config_rejected_without_state(
            "invalid-zero-interval",
            Vec::new(),
            Duration::ZERO,
            "sync interval must be nonzero",
        )
        .await;

        let too_many = (0..=MAX_CONFIGURED_PEERS)
            .map(|index| expected_peer(index as u64 + 1, 20_000 + index as u16))
            .collect();
        assert_config_rejected_without_state(
            "invalid-too-many-peers",
            too_many,
            Duration::from_millis(1),
            "peer count",
        )
        .await;

        let duplicate_id = expected_peer(300, 21_000);
        assert_config_rejected_without_state(
            "invalid-duplicate-id",
            vec![
                duplicate_id,
                MissionExpectedPeer {
                    carrier: ExpectedPeer {
                        address: SocketAddr::from(([127, 0, 0, 1], 21_001)),
                        ..duplicate_id.carrier
                    },
                    mission: [0x81; 32],
                },
            ],
            Duration::from_millis(1),
            "endpoint identities must be unique",
        )
        .await;

        let first = expected_peer(301, 21_002);
        let second = expected_peer(302, 21_003);
        assert_config_rejected_without_state(
            "invalid-duplicate-address",
            vec![
                first,
                MissionExpectedPeer {
                    carrier: ExpectedPeer {
                        address: first.carrier.address,
                        ..second.carrier
                    },
                    mission: second.mission,
                },
            ],
            Duration::from_millis(1),
            "socket addresses must be unique",
        )
        .await;
    }

    #[tokio::test]
    async fn wrong_mission_authority_fails_before_carrier_identity_or_socket() {
        let state = root("wrong-store-authority");
        fs::create_dir_all(&state).expect("state root");
        let bound_mission = test_mission();
        let bound_authority =
            ReferenceEnvelopeSealer::open(bound_mission.fresh_bundle().expect("bound bundle"))
                .expect("bound sealer")
                .mission_authority_id();
        drop(
            Store::open_for_mission(state.join(STORE_FILE), bound_authority)
                .expect("bind semantic store"),
        );

        let access = ProvisioningAccess::member(
            Scope::new("test/runtime").expect("scope"),
            vec![1],
            vec![Topic::new("opaque").expect("topic")],
        )
        .expect("access");
        let mut other_authority =
            ReferenceProvisioner::from_seed([0x74; 32]).expect("other provisioner");
        let other_mission = UnprotectedReferenceMission::from_bytes(
            other_authority
                .issue_node(1, &[access])
                .and_then(|bundle| bundle.to_bytes())
                .expect("other bundle"),
        )
        .expect("other mission");
        let error = run_node(NodeConfig {
            state: state.clone(),
            bind: "127.0.0.1:0".parse().expect("bind address"),
            mission: other_mission,
            peers: Vec::new(),
            sync_interval: Duration::from_millis(1),
            run_for: Some(Duration::from_millis(1)),
            application: NodeApplication::Relay,
        })
        .await
        .expect_err("another mission authority must fail before startup");
        assert!(matches!(
            error,
            NodeError::Store(StoreError::MissionAuthorityMismatch { .. })
        ));
        assert!(
            !state.join("identity.key").exists(),
            "mismatched mission created a carrier identity"
        );
        fs::remove_dir_all(state).expect("cleanup");
    }

    #[test]
    fn caller_supplied_id_survives_restart_and_duplicate_apply() {
        let root = root("opaque");
        let id = ItemId::new([0x55; 32]);
        assert!(put_opaque(&root, id, b"opaque").expect("first"));
        assert!(!put_opaque(&root, id, b"opaque").expect("duplicate"));
        let receipt = inspect_store(&root).expect("inspect");
        assert_eq!(receipt.ids, vec![id]);
        assert_eq!(receipt.items, 1);
        assert_eq!(receipt.acceptance_markers, 1);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn existing_application_operation_is_freshly_verified_against_requested_contract() {
        let state = root("existing-application-contract");
        fs::create_dir_all(&state).expect("state root");
        let mission = demo_member_mission();
        let mut sealer =
            ReferenceEnvelopeSealer::open(mission.fresh_bundle().expect("fresh mission bundle"))
                .expect("application sealer");
        let store = Store::open_for_mission(state.join(STORE_FILE), sealer.mission_authority_id())
            .expect("mission-bound store");
        let operation = ping_operation_key().expect("Ping operation key");
        let policy = store.control_policy_snapshot().expect("settled policy");

        let (inserted, first) = {
            let (event, inserted) = publish_event_once(
                &store,
                &policy,
                &mut sealer,
                &operation,
                None,
                DEMO_PING_LOGICAL_KEY.to_vec(),
                DEMO_PING_PAYLOAD,
            )
            .expect("publish Ping");
            (inserted, event)
        };
        assert!(inserted);
        let (replayed, replay_inserted) = publish_event_once(
            &store,
            &policy,
            &mut sealer,
            &operation,
            None,
            DEMO_PING_LOGICAL_KEY.to_vec(),
            DEMO_PING_PAYLOAD,
        )
        .expect("authenticate durable operation replay");
        assert!(!replay_inserted);
        assert_eq!(replayed, first);

        let error = publish_event_once(
            &store,
            &policy,
            &mut sealer,
            &operation,
            None,
            DEMO_PING_LOGICAL_KEY.to_vec(),
            b"ASTER_SAMPLE_PING_TAMPERED",
        )
        .expect_err("durable operation with another payload must fail closed");
        assert!(
            matches!(error, NodeError::Protocol(message) if message.contains(
                "differs from the requested application Event"
            ))
        );
        assert_eq!(store.event_count().expect("Event count"), 1);
        fs::remove_dir_all(state).expect("cleanup");
    }

    #[test]
    fn existing_application_operation_remains_exact_retry_across_authorized_rekey() {
        let state = root("existing-application-rekey");
        fs::create_dir_all(&state).expect("state root");
        let services = control_test_services([0xc4; 32]);
        let mut member = open_test_sealer(&services.member);
        let store = Store::open_for_mission(state.join(STORE_FILE), member.mission_authority_id())
            .expect("member store");
        let operation =
            EventOperationKey::new(b"application/rekey/retry".to_vec()).expect("operation key");
        let policy = store.control_policy_snapshot().expect("epoch-one policy");
        let request = || SelectedEventPublish {
            operation: &operation,
            predecessor: None,
            topic: &services.topic,
            scope: &services.scope,
            priority: Priority::Priority,
            logical_key: b"asset",
            payload: b"ready",
            tombstone: false,
        };
        let (first, inserted) =
            publish_selected_event_once(&store, &policy, &mut member, request())
                .expect("publish epoch-one Event");
        assert!(inserted);
        assert_eq!(first.header.key_epoch, 1);

        let recipients = vec![
            ScopeRekeyRecipient::member(
                services.authority.identity(),
                vec![services.topic.clone()],
            )
            .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.member.identity(), vec![services.topic.clone()])
                .expect("member recipient"),
        ];
        let mut authority = open_test_sealer(&services.authority);
        let (sealed_rekey, _) = authority
            .seal_chained_scope_rekey_control_from_registry(
                &services.registry,
                0,
                services.scope.clone(),
                2,
                recipients,
                1,
                None,
            )
            .expect("seal epoch-two rekey");
        let verified_rekey = member
            .verify_control(&sealed_rekey)
            .expect("verify epoch-two rekey");
        let outcome = store
            .ingest_verified_control(&verified_rekey, &sealed_rekey)
            .expect("commit epoch-two rekey");
        assert_eq!(outcome.activated().len(), 1);
        activate_committed_controls(&store, &mut member, outcome.activated(), None)
            .expect("activate epoch-two rekey");
        assert_eq!(
            store
                .active_scope_epoch(&services.scope)
                .expect("active epoch")
                .map(|(epoch, _)| epoch),
            Some(2)
        );

        let policy = store.control_policy_snapshot().expect("epoch-two policy");
        let (retried, inserted) =
            publish_selected_event_once(&store, &policy, &mut member, request())
                .expect("retry original operation after rekey");
        assert!(!inserted);
        assert_eq!(retried, first);
        assert_eq!(store.event_count().expect("Event count"), 1);
        fs::remove_dir_all(state).expect("cleanup");
    }

    #[test]
    fn line_topology_has_no_unregistered_end_to_end_edge() {
        assert_eq!(neighbors(0, 4), vec![1]);
        assert_eq!(neighbors(1, 4), vec![0, 2]);
        assert_eq!(neighbors(3, 4), vec![2]);
    }

    #[test]
    fn demo_watchdog_scales_with_line_diameter() {
        assert_eq!(demo_run_seconds(1), 3);
        assert_eq!(demo_run_seconds(3), 5);
        assert_eq!(demo_run_seconds(8), 10);
        assert_eq!(demo_run_seconds(32), 34);
    }

    #[test]
    fn retained_opaque_namespace_rejects_equal_identifier_with_different_bytes() {
        let state = root("opaque-collision");
        let id = ItemId::new([0x66; 32]);
        assert!(put_opaque(&state, id, b"left").expect("first insert"));
        let error = put_opaque(&state, id, b"right").expect_err("identity conflict");
        assert!(matches!(
            error,
            NodeError::Store(StoreError::IdentityConflict { id: rejected }) if rejected == id
        ));
        fs::remove_dir_all(state).expect("cleanup");
    }
}
