//! High-level, offline-first composition host for Aster Mesh.
//!
//! [`MeshService`] owns the durable node, encrypted Blob carrier store,
//! mutually authenticated runtime adjacency, and configured carriers. Normal
//! application operations never accept cryptographic values, wire messages,
//! fragments, or a carrier choice. Carrier registration is a deployment-time
//! integration operation; contact selection is automatic and never per item.
//!
//! The current bounded profile deliberately supports one active authenticated
//! adjacency per service. Any number of peers and carriers may be configured,
//! but contacts are serviced sequentially. Pausing a contact destroys its
//! session keys while retaining peer-neutral durable object ranges, so a later
//! contact can resume over a different carrier or peer.

#![forbid(unsafe_code)]

use aster_mesh::blob::{BlobStoreConfig, BlobTransferStore};
use aster_mesh::engine::{NodeConfig, ResolveRequest};
use aster_mesh::inventory::SparseInventory;
use aster_mesh::link::Link;
use aster_mesh::runtime::{
    BlobRuntimeError, ReferenceSemanticRuntimeBackend, RuntimeBackend, RuntimeCommit,
    RuntimeDriver, RuntimeError, RuntimeTransferProgress, StartRequest,
};
use aster_mesh::store::StoreConfig;
use aster_mesh::sync::{InterestFilter, InventoryPurpose, SyncState};
use aster_mesh::wire::{Data, ObjectId, Receipt, WantItem};
use aster_mesh::{
    ApplicationMergePolicy, ApplicationNodeOptions, ApplicationNodeRef, BatchPublishRequest,
    BatchPublishResult, BlobError, BlobId, BridgeAuthorizationId, BridgeAuthorizationPolicy,
    BridgeAuthorizationResult, BridgeAuthorizationStatus, BridgeEdge, BridgeEnrollment,
    BridgeFilter, BridgeNarrowingPolicy, BridgeRouteHandle, BridgeRouteResult, BridgeRouteStatus,
    ConflictAnnotation, DataClass, Delivery, EmissionPolicy, EngineError, EventGap, FinishedBlob,
    FinishedBlobBatchRequest, Item, ItemId, NodeId, PeerSnapshot, PeerStatus, Priority,
    ProvisioningBundle, PublishRequest, PublishResult, Query, QuotaUsage, ReferenceBlobReader,
    ReferenceBlobService, RekeyRecipient, Scope, ScopeRekeyResult, SubscriptionId, SyncStatus,
    Topic, open_reference_node,
};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use zeroize::{Zeroize, Zeroizing};

const MAX_FILTER_NAMES: usize = 256;
const MAX_CONFIGURED_CARRIERS: usize = 256;
const MAX_CARRIERS_PER_PEER: usize = 16;

type DurableBackend = ReferenceSemanticRuntimeBackend;
type ContactDriver = RuntimeDriver<PeerBoundBackend>;

/// Fixed, bounded interest used for each authenticated contact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyncProfile {
    topics: Vec<Topic>,
    scopes: Vec<Scope>,
    minimum_priority: Priority,
}

impl SyncProfile {
    /// Creates a canonical contact interest.
    pub fn new(
        mut topics: Vec<Topic>,
        mut scopes: Vec<Scope>,
        minimum_priority: Priority,
    ) -> Result<Self, ServiceError> {
        topics.sort();
        topics.dedup();
        scopes.sort();
        scopes.dedup();
        if topics.is_empty() || scopes.is_empty() {
            return Err(ServiceError::Invalid(
                "sync profile requires at least one topic and scope".into(),
            ));
        }
        if topics.len() > MAX_FILTER_NAMES || scopes.len() > MAX_FILTER_NAMES {
            return Err(ServiceError::Invalid(
                "sync profile exceeds the 256-name bound".into(),
            ));
        }
        Ok(Self {
            topics,
            scopes,
            minimum_priority,
        })
    }

    pub fn topics(&self) -> &[Topic] {
        &self.topics
    }

    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    pub fn minimum_priority(&self) -> Priority {
        self.minimum_priority
    }

    fn start_request(&self, exchange_id: u64) -> StartRequest {
        StartRequest {
            exchange_id,
            topics: self
                .topics
                .iter()
                .map(|topic| topic.as_str().to_owned())
                .collect(),
            scopes: self
                .scopes
                .iter()
                .map(|scope| scope.as_str().to_owned())
                .collect(),
            min_priority: self.minimum_priority as u8,
        }
    }
}

/// Durable storage, emission, and contact policy for [`MeshService`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceOptions {
    pub node: ApplicationNodeOptions,
    pub blobs: BlobStoreConfig,
    pub sync: SyncProfile,
}

/// One nonblocking service-drive result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PumpReport {
    pub peer: NodeId,
    pub authenticated: bool,
    pub pending_objects: usize,
    pub status: SyncStatus,
}

/// Active contact state without carrier, handshake, or wire details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContactStatus {
    pub peer: NodeId,
    pub authenticated: bool,
    pub pending_objects: usize,
    pub status: SyncStatus,
}

/// Stable high-level reason that an authenticated contact could not proceed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContactFailure {
    /// Mutual authentication or the configured peer binding was rejected.
    Authentication,
    /// The selected nonblocking carrier failed.
    Carrier,
    /// Durable local state could not service the contact.
    LocalState,
    /// The authenticated reconciliation could not continue safely.
    Synchronization,
}

/// Failure from high-level service composition or an application operation.
#[derive(Debug)]
pub enum ServiceError {
    Engine(EngineError),
    Blob(BlobError),
    Contact(ContactFailure),
    /// The named operation is durably committed, but the live contact could
    /// not refresh its authenticated inventory view. Callers must not retry as
    /// though the local commit had rolled back.
    CommittedContactRefresh {
        operation: &'static str,
        reason: ContactFailure,
    },
    Io(io::Error),
    Credential(String),
    Invalid(String),
    Unavailable(String),
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Engine(error) => write!(formatter, "node operation failed: {error}"),
            Self::Blob(error) => write!(formatter, "Blob operation failed: {error}"),
            Self::Contact(reason) => write!(formatter, "contact failed: {reason:?}"),
            Self::CommittedContactRefresh { operation, reason } => write!(
                formatter,
                "{operation} committed locally, but active contact refresh failed: {reason:?}"
            ),
            Self::Io(error) => write!(formatter, "carrier operation failed: {error}"),
            Self::Credential(error) => write!(formatter, "credential rejected: {error}"),
            Self::Invalid(error) => formatter.write_str(error),
            Self::Unavailable(error) => write!(formatter, "service unavailable: {error}"),
        }
    }
}

impl Error for ServiceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Engine(error) => Some(error),
            Self::Blob(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Contact(_)
            | Self::CommittedContactRefresh { .. }
            | Self::Credential(_)
            | Self::Invalid(_)
            | Self::Unavailable(_) => None,
        }
    }
}

impl From<EngineError> for ServiceError {
    fn from(error: EngineError) -> Self {
        Self::Engine(error)
    }
}

impl From<BlobError> for ServiceError {
    fn from(error: BlobError) -> Self {
        Self::Blob(error)
    }
}

impl From<BlobRuntimeError> for ServiceError {
    fn from(error: BlobRuntimeError) -> Self {
        match error {
            BlobRuntimeError::Engine(error) => Self::Engine(error),
            BlobRuntimeError::Blob(error) => Self::Blob(error),
            BlobRuntimeError::Invalid(message) => Self::Invalid(message.into()),
        }
    }
}

impl From<RuntimeError> for ServiceError {
    fn from(error: RuntimeError) -> Self {
        Self::Contact(contact_failure(&error))
    }
}

impl From<io::Error> for ServiceError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

struct ConfiguredCarrier {
    peer: NodeId,
    link: Box<dyn Link>,
}

enum ServiceState {
    Offline(Box<DurableBackend>),
    Active {
        peer: NodeId,
        carrier: usize,
        driver: Box<ContactDriver>,
    },
    Unavailable,
}

#[derive(Debug)]
enum PeerBoundError {
    Inner(BlobRuntimeError),
    UnexpectedPeer,
}

impl fmt::Display for PeerBoundError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inner(error) => error.fmt(formatter),
            Self::UnexpectedPeer => {
                formatter.write_str("authenticated identity does not match configured peer")
            }
        }
    }
}

struct PeerBoundBackend {
    expected_peer: NodeId,
    inner: DurableBackend,
}

impl PeerBoundBackend {
    fn into_inner(self) -> DurableBackend {
        self.inner
    }
}

impl RuntimeBackend for PeerBoundBackend {
    type Error = PeerBoundError;

    fn authorize_adjacency(&mut self, authenticated_peer: NodeId) -> Result<(), Self::Error> {
        if authenticated_peer != self.expected_peer {
            return Err(PeerBoundError::UnexpectedPeer);
        }
        self.inner
            .authorize_adjacency(authenticated_peer)
            .map_err(PeerBoundError::Inner)
    }

    fn durable_progress(
        &mut self,
        limit: usize,
    ) -> Result<Vec<RuntimeTransferProgress>, Self::Error> {
        self.inner
            .durable_progress(limit)
            .map_err(PeerBoundError::Inner)
    }

    fn durable_progress_for_semantic_version(
        &mut self,
        limit: usize,
        semantic_version: u16,
    ) -> Result<Vec<RuntimeTransferProgress>, Self::Error> {
        self.inner
            .durable_progress_for_semantic_version(limit, semantic_version)
            .map_err(PeerBoundError::Inner)
    }

    fn durable_dependencies(&mut self, limit: usize) -> Result<Vec<ObjectId>, Self::Error> {
        self.inner
            .durable_dependencies(limit)
            .map_err(PeerBoundError::Inner)
    }

    fn durable_dependencies_for_semantic_version(
        &mut self,
        limit: usize,
        semantic_version: u16,
    ) -> Result<Vec<ObjectId>, Self::Error> {
        self.inner
            .durable_dependencies_for_semantic_version(limit, semantic_version)
            .map_err(PeerBoundError::Inner)
    }

    fn durably_disposed_object_len(
        &mut self,
        object_id: ObjectId,
        semantic_version: u16,
    ) -> Result<Option<u64>, Self::Error> {
        self.inner
            .durably_disposed_object_len(object_id, semantic_version)
            .map_err(PeerBoundError::Inner)
    }

    fn select_authorized_inventory(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &InterestFilter,
        purpose: InventoryPurpose,
    ) -> Result<SparseInventory, Self::Error> {
        self.inner
            .select_authorized_inventory(
                authenticated_peer,
                peer_route_commitments,
                filter,
                purpose,
            )
            .map_err(PeerBoundError::Inner)
    }

    fn select_authorized_inventory_for_semantic_version(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &InterestFilter,
        purpose: InventoryPurpose,
        semantic_version: u16,
    ) -> Result<SparseInventory, Self::Error> {
        self.inner
            .select_authorized_inventory_for_semantic_version(
                authenticated_peer,
                peer_route_commitments,
                filter,
                purpose,
                semantic_version,
            )
            .map_err(PeerBoundError::Inner)
    }

    fn store_object_chunk(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        self.inner
            .store_object_chunk(object_id, total_len, offset, bytes)
            .map_err(PeerBoundError::Inner)
    }

    fn store_object_chunk_for_semantic_version(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
        semantic_version: u16,
    ) -> Result<(), Self::Error> {
        self.inner
            .store_object_chunk_for_semantic_version(
                object_id,
                total_len,
                offset,
                bytes,
                semantic_version,
            )
            .map_err(PeerBoundError::Inner)
    }

    fn complete_object_bytes(
        &mut self,
        object_id: ObjectId,
        total_len: u64,
    ) -> Result<Vec<u8>, Self::Error> {
        self.inner
            .complete_object_bytes(object_id, total_len)
            .map_err(PeerBoundError::Inner)
    }

    fn abort_object(&mut self, object_id: ObjectId) -> Result<(), Self::Error> {
        self.inner
            .abort_object(object_id)
            .map_err(PeerBoundError::Inner)
    }

    fn commit_authenticated_object(
        &mut self,
        authenticated_peer: NodeId,
        exchange_id: u64,
        object_id: ObjectId,
        bytes: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<Option<ItemId>, Self::Error> {
        self.inner
            .commit_authenticated_object(
                authenticated_peer,
                exchange_id,
                object_id,
                bytes,
                forwarding,
            )
            .map_err(PeerBoundError::Inner)
    }

    fn commit_authenticated_object_with_dependencies(
        &mut self,
        authenticated_peer: NodeId,
        exchange_id: u64,
        semantic_version: u16,
        object_id: ObjectId,
        bytes: Vec<u8>,
        forwarding: Vec<u8>,
    ) -> Result<RuntimeCommit, Self::Error> {
        self.inner
            .commit_authenticated_object_with_dependencies(
                authenticated_peer,
                exchange_id,
                semantic_version,
                object_id,
                bytes,
                forwarding,
            )
            .map_err(PeerBoundError::Inner)
    }

    fn is_terminal_commit_error(&self, error: &Self::Error) -> bool {
        match error {
            PeerBoundError::Inner(error) => self.inner.is_terminal_commit_error(error),
            PeerBoundError::UnexpectedPeer => true,
        }
    }

    fn object_priority(&mut self, object_id: ObjectId) -> Result<Priority, Self::Error> {
        self.inner
            .object_priority(object_id)
            .map_err(PeerBoundError::Inner)
    }

    fn data_for_want(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        exchange_id: u64,
        want: &WantItem,
    ) -> Result<Vec<Data>, Self::Error> {
        self.inner
            .data_for_want(
                authenticated_peer,
                peer_route_commitments,
                exchange_id,
                want,
            )
            .map_err(PeerBoundError::Inner)
    }

    fn data_for_want_for_semantic_version(
        &mut self,
        authenticated_peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        exchange_id: u64,
        semantic_version: u16,
        want: &WantItem,
    ) -> Result<Vec<Data>, Self::Error> {
        self.inner
            .data_for_want_for_semantic_version(
                authenticated_peer,
                peer_route_commitments,
                exchange_id,
                semantic_version,
                want,
            )
            .map_err(PeerBoundError::Inner)
    }

    fn acknowledge_receipt(
        &mut self,
        authenticated_peer: NodeId,
        semantic_version: u16,
        receipt: &Receipt,
    ) -> Result<(), Self::Error> {
        self.inner
            .acknowledge_receipt(authenticated_peer, semantic_version, receipt)
            .map_err(PeerBoundError::Inner)
    }
}

/// Offline-first application node plus an event-driven authenticated contact host.
///
/// `MeshService` never starts a thread and never polls in a loop. Call
/// [`Self::pump`] after adapter readiness, an application command, or the
/// optional [`Self::next_wakeup`] deadline. One call drains only work currently
/// available from the selected nonblocking carrier.
pub struct MeshService {
    database_path: PathBuf,
    blob_path: PathBuf,
    credentials: Zeroizing<Vec<u8>>,
    options: ServiceOptions,
    identity: NodeId,
    state: ServiceState,
    carriers: Vec<ConfiguredCarrier>,
    next_carrier: BTreeMap<NodeId, usize>,
    next_exchange_id: u64,
    zeroized: bool,
}

impl MeshService {
    /// Opens durable local state. No carrier is required, so offline publication
    /// is available immediately.
    pub fn open(
        database_path: impl AsRef<Path>,
        blob_path: impl AsRef<Path>,
        provisioning_bundle: &[u8],
        options: ServiceOptions,
    ) -> Result<Self, ServiceError> {
        let database_path = database_path.as_ref().to_path_buf();
        let blob_path = blob_path.as_ref().to_path_buf();
        let config = node_config(&options.node)?;
        let credentials = Zeroizing::new(provisioning_bundle.to_vec());
        let bundle = parse_bundle(&credentials)?;
        let node = open_reference_node(&database_path, bundle, config)?;
        let identity = node.identity();
        let blobs = BlobTransferStore::open_with_config(&blob_path, options.blobs)?;
        Ok(Self {
            database_path,
            blob_path,
            credentials,
            options,
            identity,
            state: ServiceState::Offline(Box::new(ReferenceSemanticRuntimeBackend::new(
                node, blobs,
            )?)),
            carriers: Vec::new(),
            next_carrier: BTreeMap::new(),
            next_exchange_id: 1,
            zeroized: false,
        })
    }

    pub fn identity(&self) -> NodeId {
        self.identity
    }

    /// Registers one deployment-configured carrier for an authenticated peer.
    ///
    /// This is host integration, not an application routing operation: items
    /// never name or select a carrier. At most 16 carriers may be registered per
    /// peer and 256 per service. Registration is allowed only while offline.
    pub fn configure_peer_carrier<L>(&mut self, peer: NodeId, link: L) -> Result<(), ServiceError>
    where
        L: Link + 'static,
    {
        self.ensure_not_zeroized()?;
        if !matches!(self.state, ServiceState::Offline(_)) {
            return Err(ServiceError::Invalid(
                "carriers can be configured only without an active contact".into(),
            ));
        }
        if peer == self.identity {
            return Err(ServiceError::Invalid(
                "a carrier peer must differ from the local identity".into(),
            ));
        }
        if self.carriers.len() >= MAX_CONFIGURED_CARRIERS {
            return Err(ServiceError::Invalid(
                "configured carrier capacity reached".into(),
            ));
        }
        if self
            .carriers
            .iter()
            .filter(|carrier| carrier.peer == peer)
            .count()
            >= MAX_CARRIERS_PER_PEER
        {
            return Err(ServiceError::Invalid(
                "configured per-peer carrier capacity reached".into(),
            ));
        }
        if link.name().is_empty() {
            return Err(ServiceError::Invalid(
                "configured carrier name cannot be empty".into(),
            ));
        }
        if usize::from(link.characteristics().mtu) <= aster_mesh::fragment::HEADER_LEN {
            return Err(ServiceError::Invalid(
                "configured carrier MTU cannot hold one fragment header".into(),
            ));
        }
        link.set_discovery(self.application()?.may_advertise())?;
        self.carriers.push(ConfiguredCarrier {
            peer,
            link: Box::new(link),
        });
        Ok(())
    }

    pub fn configured_carrier_count(&self) -> usize {
        self.carriers.len()
    }

    /// Starts one authenticated, bidirectional contact. Handshake role and
    /// carrier choice are deterministic service concerns, not caller choices.
    pub fn begin_sync(&mut self, peer: NodeId) -> Result<ContactStatus, ServiceError> {
        self.ensure_not_zeroized()?;
        if !matches!(self.state, ServiceState::Offline(_)) {
            return Err(ServiceError::Invalid(
                "only one contact may be active; pause it before starting another".into(),
            ));
        }
        let carrier = self.select_carrier(peer)?;
        let bundle = parse_bundle(&self.credentials)?;
        let sync = SyncState::new(Default::default(), SparseInventory::new())
            .map_err(|error| ServiceError::Invalid(error.to_string()))?;
        let exchange_id = self.next_exchange_id;
        self.next_exchange_id = self
            .next_exchange_id
            .checked_add(1)
            .ok_or_else(|| ServiceError::Unavailable("exchange identifiers exhausted".into()))?;
        let start = self.options.sync.start_request(exchange_id);

        let state = std::mem::replace(&mut self.state, ServiceState::Unavailable);
        let ServiceState::Offline(mut backend) = state else {
            self.state = state;
            return Err(ServiceError::Unavailable(
                "service state changed while starting contact".into(),
            ));
        };
        // A local Blob writer is intentionally a separate bounded streaming
        // service. Refresh the transfer view at contact start so manifests,
        // chunks, and quota usage committed while offline are authoritative.
        let refreshed_blobs =
            match BlobTransferStore::open_with_config(&self.blob_path, self.options.blobs) {
                Ok(blobs) => blobs,
                Err(error) => {
                    self.state = ServiceState::Offline(backend);
                    return Err(ServiceError::Blob(error));
                }
            };
        *backend.blobs_mut() = refreshed_blobs;
        if let Err(error) = backend.node_mut().update_peer_status(
            peer,
            PeerStatus::Authenticating,
            SyncStatus::Reconciling,
            None,
        ) {
            self.state = ServiceState::Offline(backend);
            return Err(ServiceError::Engine(error));
        }
        let bound = PeerBoundBackend {
            expected_peer: peer,
            inner: *backend,
        };
        let driver = if self.identity < peer {
            RuntimeDriver::initiator(bundle, sync, bound, start, Some(peer))
        } else {
            RuntimeDriver::responder_with_start(bundle, sync, bound, start, Some(peer))
        };
        match driver {
            Ok(driver) => {
                self.state = ServiceState::Active {
                    peer,
                    carrier,
                    driver: Box::new(driver),
                };
                Ok(ContactStatus {
                    peer,
                    authenticated: false,
                    pending_objects: 0,
                    status: SyncStatus::Reconciling,
                })
            }
            Err(error) => {
                self.state =
                    ServiceState::Offline(Box::new(self.reopen_backend().map_err(|_| {
                        ServiceError::Unavailable(
                            "contact initialization failed and durable state could not be reopened"
                                .into(),
                        )
                    })?));
                Err(ServiceError::Contact(contact_failure(&error)))
            }
        }
    }

    /// Performs one nonblocking drive pass on the automatically selected carrier.
    pub fn pump(&mut self) -> Result<PumpReport, ServiceError> {
        let (state, carriers) = (&mut self.state, &self.carriers);
        let ServiceState::Active {
            peer,
            carrier,
            driver,
        } = state
        else {
            return Err(ServiceError::Invalid("no active contact".into()));
        };
        match driver.pump(carriers[*carrier].link.as_ref()) {
            Ok(_) => {}
            Err(error) => {
                let rejected = matches!(
                    error,
                    RuntimeError::Session(_) | RuntimeError::TransportPeerChanged
                ) || matches!(
                    &error,
                    RuntimeError::Backend(message)
                        if message == "authenticated identity does not match configured peer"
                );
                let _ = driver.backend_mut().inner.node_mut().update_peer_status(
                    *peer,
                    if rejected {
                        PeerStatus::Rejected
                    } else {
                        PeerStatus::Offline
                    },
                    SyncStatus::Suspended,
                    Some(contact_failure_detail(contact_failure(&error)).into()),
                );
                return Err(ServiceError::Contact(contact_failure(&error)));
            }
        }
        let authenticated = driver.is_authenticated();
        let pending_objects = driver.sync().wants().len();
        let status = if authenticated && pending_objects > 0 {
            SyncStatus::Transferring
        } else {
            // The v1 reducer has no authenticated terminal-root acknowledgement;
            // do not claim convergence merely because one nonblocking pass was quiet.
            SyncStatus::Reconciling
        };
        driver.backend_mut().inner.node_mut().update_peer_status(
            *peer,
            if authenticated {
                PeerStatus::Ready
            } else {
                PeerStatus::Authenticating
            },
            status,
            None,
        )?;
        Ok(PumpReport {
            peer: *peer,
            authenticated,
            pending_objects,
            status,
        })
    }

    /// Ends the current adjacency, erases its traffic keys, and retains all
    /// durable peer-neutral transfer ranges for a later carrier or peer.
    pub fn pause_sync(&mut self) -> Result<Option<ContactStatus>, ServiceError> {
        let state = std::mem::replace(&mut self.state, ServiceState::Unavailable);
        match state {
            ServiceState::Offline(backend) => {
                self.state = ServiceState::Offline(backend);
                Ok(None)
            }
            ServiceState::Active {
                peer,
                driver,
                carrier: _,
            } => {
                let pending_objects = driver.sync().wants().len();
                let authenticated = driver.is_authenticated();
                let mut backend = (*driver).into_backend().into_inner();
                let update = backend.node_mut().update_peer_status(
                    peer,
                    PeerStatus::Offline,
                    SyncStatus::Suspended,
                    None,
                );
                self.state = ServiceState::Offline(Box::new(backend));
                update?;
                Ok(Some(ContactStatus {
                    peer,
                    authenticated,
                    pending_objects,
                    status: SyncStatus::Suspended,
                }))
            }
            ServiceState::Unavailable => {
                self.state = ServiceState::Unavailable;
                Err(ServiceError::Unavailable(
                    "durable backend is unavailable".into(),
                ))
            }
        }
    }

    /// Earliest active-carrier maintenance deadline. `None` means callers wait
    /// for adapter readiness or an application command; no polling is needed.
    pub fn next_wakeup(&self) -> Option<Instant> {
        match &self.state {
            ServiceState::Active {
                carrier, driver, ..
            } => driver.next_wakeup(self.carriers[*carrier].link.as_ref()),
            ServiceState::Offline(_) | ServiceState::Unavailable => None,
        }
    }

    pub fn active_contact(&self) -> Option<ContactStatus> {
        let ServiceState::Active { peer, driver, .. } = &self.state else {
            return None;
        };
        let authenticated = driver.is_authenticated();
        let pending_objects = driver.sync().wants().len();
        Some(ContactStatus {
            peer: *peer,
            authenticated,
            pending_objects,
            status: if authenticated && pending_objects > 0 {
                SyncStatus::Transferring
            } else {
                SyncStatus::Reconciling
            },
        })
    }

    pub fn publish(&mut self, request: PublishRequest) -> Result<PublishResult, ServiceError> {
        let result = self.application()?.publish(request)?;
        self.notify_local_inventory_changed_after_commit("publish")?;
        Ok(result)
    }

    pub fn publish_batch(
        &mut self,
        request: BatchPublishRequest,
    ) -> Result<BatchPublishResult, ServiceError> {
        let result = self.application()?.publish_batch(request)?;
        self.notify_local_inventory_changed_after_commit("batch publication")?;
        Ok(result)
    }

    pub fn open_blob_service(
        &mut self,
        scope: &Scope,
        topic: &Topic,
    ) -> Result<ReferenceBlobService, ServiceError> {
        let path = self.blob_path.clone();
        let config = self.options.blobs;
        Ok(self
            .application()?
            .open_blob_service(scope, topic, path, config)?)
    }

    pub fn publish_finished_blob(
        &mut self,
        topic: Topic,
        scope: Scope,
        priority: Priority,
        ttl_ms: Option<u64>,
        finished: FinishedBlob,
    ) -> Result<PublishResult, ServiceError> {
        let result = self
            .application()?
            .publish_finished_blob(topic, scope, priority, ttl_ms, finished)?;
        self.notify_local_inventory_changed_after_commit("finished Blob publication")?;
        Ok(result)
    }

    pub fn publish_finished_blob_batch(
        &mut self,
        request: FinishedBlobBatchRequest,
    ) -> Result<BatchPublishResult, ServiceError> {
        let result = self.application()?.publish_finished_blob_batch(request)?;
        self.notify_local_inventory_changed_after_commit("finished Blob batch publication")?;
        Ok(result)
    }

    pub fn open_blob_reader(
        &mut self,
        scope: &Scope,
        topic: &Topic,
        id: BlobId,
    ) -> Result<ReferenceBlobReader, ServiceError> {
        let path = self.blob_path.clone();
        let config = self.options.blobs;
        Ok(self
            .application()?
            .open_blob_reader(scope, topic, path, config, id)?)
    }

    pub fn query(&mut self, query: Query) -> Result<Vec<Item>, ServiceError> {
        Ok(self.application()?.query(query)?)
    }

    pub fn subscribe(
        &mut self,
        topic: Topic,
        scope: Scope,
        class: Option<DataClass>,
        include_descendant_scopes: bool,
    ) -> Result<SubscriptionId, ServiceError> {
        Ok(self
            .application()?
            .subscribe(topic, scope, class, include_descendant_scopes)?)
    }

    pub fn poll(
        &mut self,
        subscription: SubscriptionId,
        limit: usize,
    ) -> Result<Vec<Delivery>, ServiceError> {
        Ok(self.application()?.poll(subscription, limit)?)
    }

    pub fn acknowledge(
        &mut self,
        subscription: SubscriptionId,
        item: ItemId,
    ) -> Result<(), ServiceError> {
        Ok(self.application()?.acknowledge(subscription, item)?)
    }

    pub fn conflicts(&mut self, query: Query) -> Result<Vec<ConflictAnnotation>, ServiceError> {
        Ok(self.application()?.conflicts(query)?)
    }

    pub fn resolve(&mut self, request: ResolveRequest) -> Result<PublishResult, ServiceError> {
        let result = self.application()?.resolve(request)?;
        self.notify_local_inventory_changed_after_commit("conflict resolution")?;
        Ok(result)
    }

    pub fn event_gaps(&mut self, query: Query) -> Result<Vec<EventGap>, ServiceError> {
        Ok(self.application()?.event_gaps(query)?)
    }

    /// Registers a process-local policy ID for Record conflict annotations.
    ///
    /// The service retains no executable policy object and never invokes it
    /// during replicated ingestion. Callers own explicit merge and resolution.
    pub fn register_merge_policy(
        &mut self,
        topic: Topic,
        policy: Arc<dyn ApplicationMergePolicy>,
    ) -> Result<(), ServiceError> {
        self.application()?.register_merge_policy(topic, policy);
        Ok(())
    }

    /// Authority-only fresh scope rekey. The registry remains opaque and the
    /// independently retained minimum generation is enforced before any
    /// durable control is published.
    pub fn rekey_scope(
        &mut self,
        signed_public_registry: &[u8],
        minimum_registry_generation: u64,
        scope: Scope,
        new_epoch: u64,
        recipients: Vec<RekeyRecipient>,
    ) -> Result<ScopeRekeyResult, ServiceError> {
        self.ensure_offline_semantic_mutation("scope rekey")?;
        let result = self.application()?.rekey_scope(
            signed_public_registry,
            minimum_registry_generation,
            scope,
            new_epoch,
            recipients,
        )?;
        self.rebuild_offline_backend_after_commit("scope rekey")?;
        Ok(result)
    }

    /// Creates an opaque bridge-node enrollment. No contact or carrier is
    /// selected; callers pass the move-only result to the authority service.
    pub fn create_bridge_enrollment(
        &mut self,
        source_scope: Scope,
        source_route_epoch: u64,
        target_scope: Scope,
        target_route_epoch: u64,
    ) -> Result<BridgeEnrollment, ServiceError> {
        Ok(self.application()?.create_bridge_enrollment(
            source_scope,
            source_route_epoch,
            target_scope,
            target_route_epoch,
        )?)
    }

    /// Authenticates and durably enables one signed bridge enrollment.
    pub fn enable_bridge(
        &mut self,
        enrollment: BridgeEnrollment,
        policy: BridgeAuthorizationPolicy,
    ) -> Result<BridgeAuthorizationResult, ServiceError> {
        self.ensure_offline_semantic_mutation("bridge authorization enable")?;
        let result = self.application()?.enable_bridge(enrollment, policy)?;
        self.rebuild_offline_backend_after_commit("bridge authorization enable")?;
        Ok(result)
    }

    pub fn disable_bridge(
        &mut self,
        edge: BridgeEdge,
    ) -> Result<BridgeAuthorizationResult, ServiceError> {
        self.ensure_offline_semantic_mutation("bridge authorization disable")?;
        let result = self.application()?.disable_bridge(edge)?;
        self.rebuild_offline_backend_after_commit("bridge authorization disable")?;
        Ok(result)
    }

    /// Creates a first bridge hop by application ItemID, with no sealed bytes,
    /// transport, fragmentation, or provider handles in the request.
    pub fn bridge_item(
        &mut self,
        source_item: ItemId,
        authorization: BridgeAuthorizationId,
        narrowing: BridgeNarrowingPolicy,
    ) -> Result<BridgeRouteResult, ServiceError> {
        self.ensure_offline_semantic_mutation("bridge route creation")?;
        let result = self
            .application()?
            .bridge_item(source_item, authorization, narrowing)?;
        self.rebuild_offline_backend_after_commit("bridge route creation")?;
        Ok(result)
    }

    pub fn extend_bridge_route(
        &mut self,
        route: BridgeRouteHandle,
        authorization: BridgeAuthorizationId,
        narrowing: BridgeNarrowingPolicy,
    ) -> Result<BridgeRouteResult, ServiceError> {
        self.ensure_offline_semantic_mutation("bridge route extension")?;
        let result = self
            .application()?
            .extend_bridge_route(route, authorization, narrowing)?;
        self.rebuild_offline_backend_after_commit("bridge route extension")?;
        Ok(result)
    }

    pub fn bridge_authorization_status(
        &mut self,
        id: BridgeAuthorizationId,
    ) -> Result<Option<BridgeAuthorizationStatus>, ServiceError> {
        Ok(self.application()?.bridge_authorization_status(id)?)
    }

    pub fn bridge_authorizations(
        &mut self,
        after: Option<BridgeAuthorizationId>,
        limit: usize,
    ) -> Result<Vec<BridgeAuthorizationStatus>, ServiceError> {
        Ok(self.application()?.bridge_authorizations(after, limit)?)
    }

    pub fn bridge_route_status(
        &mut self,
        handle: BridgeRouteHandle,
    ) -> Result<Option<BridgeRouteStatus>, ServiceError> {
        Ok(self.application()?.bridge_route_status(handle)?)
    }

    pub fn bridge_routes(
        &mut self,
        after: Option<BridgeRouteHandle>,
        limit: usize,
    ) -> Result<Vec<BridgeRouteStatus>, ServiceError> {
        Ok(self.application()?.bridge_routes(after, limit)?)
    }

    pub fn set_emission_policy(&mut self, policy: EmissionPolicy) -> Result<(), ServiceError> {
        self.ensure_not_zeroized()?;
        for carrier in &self.carriers {
            carrier.link.set_discovery(policy.allows_discovery())?;
        }
        self.application()?.set_emission_policy(policy);
        self.refresh_bridge_state_after_commit("emission policy change")?;
        Ok(())
    }

    pub fn emission_policy(&mut self) -> Result<EmissionPolicy, ServiceError> {
        Ok(self.application()?.emission_policy())
    }

    pub fn peer_status(&mut self, peer: NodeId) -> Result<Option<PeerSnapshot>, ServiceError> {
        Ok(self.application()?.peer_status(peer)?)
    }

    pub fn peers(&mut self) -> Result<Vec<PeerSnapshot>, ServiceError> {
        Ok(self.application()?.peers()?)
    }

    pub fn set_bridge_filters(&mut self, filters: &[BridgeFilter]) -> Result<(), ServiceError> {
        self.application()?.set_bridge_filters(filters)?;
        self.refresh_bridge_state_after_commit("bridge filter change")?;
        Ok(())
    }

    pub fn quota_usage(&mut self, scope: Option<&Scope>) -> Result<QuotaUsage, ServiceError> {
        Ok(self.application()?.quota_usage(scope)?)
    }

    pub fn collect_garbage(&mut self) -> Result<Vec<ItemId>, ServiceError> {
        let removed = self.application()?.collect_garbage()?;
        self.refresh_bridge_state_after_commit("garbage collection")?;
        Ok(removed)
    }

    /// Erases active session keys, node key material, and the retained
    /// provisioning bytes. Discovery is disabled on every configured carrier.
    pub fn zeroize(&mut self) -> Result<(), ServiceError> {
        if self.zeroized {
            return Ok(());
        }
        let state = std::mem::replace(&mut self.state, ServiceState::Unavailable);
        let backend = match state {
            ServiceState::Offline(backend) => Some(backend),
            ServiceState::Active { driver, .. } => {
                Some(Box::new((*driver).into_backend().into_inner()))
            }
            ServiceState::Unavailable => None,
        };
        if let Some(backend) = backend {
            self.state = ServiceState::Offline(backend);
        }
        let node_result = match &mut self.state {
            ServiceState::Offline(backend) => backend.node_mut().zeroize(),
            ServiceState::Active { .. } | ServiceState::Unavailable => Ok(()),
        };
        self.credentials.zeroize();
        self.zeroized = true;
        let mut discovery_error = None;
        for carrier in &self.carriers {
            if let Err(error) = carrier.link.set_discovery(false) {
                discovery_error.get_or_insert(error);
            }
        }
        node_result?;
        if let Some(error) = discovery_error {
            return Err(ServiceError::Io(error));
        }
        Ok(())
    }

    fn application(&mut self) -> Result<ApplicationNodeRef<'_>, ServiceError> {
        self.ensure_not_zeroized()?;
        let node = match &mut self.state {
            ServiceState::Offline(backend) => backend.node_mut(),
            ServiceState::Active { driver, .. } => driver.backend_mut().inner.node_mut(),
            ServiceState::Unavailable => {
                return Err(ServiceError::Unavailable(
                    "durable backend is unavailable".into(),
                ));
            }
        };
        Ok(ApplicationNodeRef::new(node))
    }

    fn ensure_not_zeroized(&self) -> Result<(), ServiceError> {
        if self.zeroized {
            Err(ServiceError::Unavailable("node is zeroized".into()))
        } else {
            Ok(())
        }
    }

    /// Epoch and bridge mutations can clear store process-liveness while
    /// invalidating semantic authorization caches. Apply them only while no
    /// contact owns the backend, then reconstruct the complete backend.
    fn ensure_offline_semantic_mutation(
        &self,
        operation: &'static str,
    ) -> Result<(), ServiceError> {
        self.ensure_not_zeroized()?;
        if matches!(self.state, ServiceState::Offline(_)) {
            Ok(())
        } else {
            Err(ServiceError::Invalid(format!(
                "{operation} is allowed only without an active contact; pause it first"
            )))
        }
    }

    fn rebuild_offline_backend_after_commit(
        &mut self,
        operation: &'static str,
    ) -> Result<(), ServiceError> {
        let state = std::mem::replace(&mut self.state, ServiceState::Unavailable);
        let ServiceState::Offline(backend) = state else {
            self.state = state;
            return Err(ServiceError::CommittedContactRefresh {
                operation,
                reason: ContactFailure::Synchronization,
            });
        };
        let (node, blobs) = (*backend).into_parts();
        match ReferenceSemanticRuntimeBackend::new(node, blobs) {
            Ok(backend) => {
                self.state = ServiceState::Offline(Box::new(backend));
                Ok(())
            }
            Err(error) => {
                let refresh_reason = match ServiceError::from(error) {
                    ServiceError::Blob(_) | ServiceError::Engine(_) => ContactFailure::LocalState,
                    _ => ContactFailure::Synchronization,
                };
                match self.reopen_backend() {
                    Ok(backend) => {
                        self.state = ServiceState::Offline(Box::new(backend));
                        Err(ServiceError::CommittedContactRefresh {
                            operation,
                            reason: refresh_reason,
                        })
                    }
                    Err(_) => Err(ServiceError::Unavailable(format!(
                        "{operation} committed locally, but the semantic backend could not be rebuilt or reopened"
                    ))),
                }
            }
        }
    }

    fn notify_local_inventory_changed_after_commit(
        &mut self,
        operation: &'static str,
    ) -> Result<(), ServiceError> {
        match &mut self.state {
            ServiceState::Offline(_) => Ok(()),
            ServiceState::Active { driver, .. } => {
                driver.local_inventory_changed().map_err(|error| {
                    ServiceError::CommittedContactRefresh {
                        operation,
                        reason: contact_failure(&error),
                    }
                })
            }
            ServiceState::Unavailable => Err(ServiceError::CommittedContactRefresh {
                operation,
                reason: ContactFailure::Synchronization,
            }),
        }
    }

    fn refresh_bridge_state_after_commit(
        &mut self,
        operation: &'static str,
    ) -> Result<(), ServiceError> {
        let refresh = match &mut self.state {
            ServiceState::Offline(backend) => backend.refresh_local_bridge_state(),
            ServiceState::Active { driver, .. } => {
                driver.backend_mut().inner.refresh_local_bridge_state()
            }
            ServiceState::Unavailable => {
                return Err(ServiceError::CommittedContactRefresh {
                    operation,
                    reason: ContactFailure::Synchronization,
                });
            }
        };
        refresh.map_err(|error| {
            let reason = match ServiceError::from(error) {
                ServiceError::Blob(_) | ServiceError::Engine(_) => ContactFailure::LocalState,
                _ => ContactFailure::Synchronization,
            };
            ServiceError::CommittedContactRefresh { operation, reason }
        })?;
        self.notify_local_inventory_changed_after_commit(operation)
    }

    fn select_carrier(&mut self, peer: NodeId) -> Result<usize, ServiceError> {
        let eligible = self
            .carriers
            .iter()
            .enumerate()
            .filter_map(|(index, carrier)| (carrier.peer == peer).then_some(index))
            .collect::<Vec<_>>();
        if eligible.is_empty() {
            return Err(ServiceError::Invalid(
                "no carrier is configured for the requested peer".into(),
            ));
        }
        let cursor = self.next_carrier.entry(peer).or_default();
        let selected = eligible[*cursor % eligible.len()];
        *cursor = cursor.wrapping_add(1);
        Ok(selected)
    }

    fn reopen_backend(&self) -> Result<DurableBackend, ServiceError> {
        let bundle = parse_bundle(&self.credentials)?;
        let node = open_reference_node(
            &self.database_path,
            bundle,
            node_config(&self.options.node)?,
        )?;
        let blobs = BlobTransferStore::open_with_config(&self.blob_path, self.options.blobs)?;
        Ok(ReferenceSemanticRuntimeBackend::new(node, blobs)?)
    }

    /// Returns durable encrypted Blob transfer-store usage as a
    /// (bytes, chunks) pair. This is observational and exposes neither content
    /// keys nor plaintext.
    pub fn blob_transfer_usage(&mut self) -> Result<(u64, u64), ServiceError> {
        match &mut self.state {
            ServiceState::Offline(backend) => Ok(backend.blobs().quota_usage()),
            ServiceState::Active { driver, .. } => {
                Ok(driver.backend_mut().inner.blobs().quota_usage())
            }
            ServiceState::Unavailable => Err(ServiceError::Unavailable(
                "Blob transfer usage is unavailable while service state moves".into(),
            )),
        }
    }

    #[cfg(test)]
    fn durable_progress(&mut self) -> Vec<RuntimeTransferProgress> {
        match &mut self.state {
            ServiceState::Offline(backend) => backend.durable_progress(128).unwrap(),
            ServiceState::Active { driver, .. } => {
                driver.backend_mut().durable_progress(128).unwrap()
            }
            ServiceState::Unavailable => Vec::new(),
        }
    }
}

fn parse_bundle(bytes: &[u8]) -> Result<ProvisioningBundle, ServiceError> {
    ProvisioningBundle::from_bytes(bytes)
        .map_err(|error| ServiceError::Credential(error.to_string()))
}

fn contact_failure(error: &RuntimeError) -> ContactFailure {
    match error {
        RuntimeError::Io(_) => ContactFailure::Carrier,
        RuntimeError::Session(_) | RuntimeError::TransportPeerChanged => {
            ContactFailure::Authentication
        }
        RuntimeError::Backend(message)
            if message == "authenticated identity does not match configured peer" =>
        {
            ContactFailure::Authentication
        }
        RuntimeError::Backend(_) => ContactFailure::LocalState,
        RuntimeError::Fragment(_)
        | RuntimeError::Wire(_)
        | RuntimeError::Sync(_)
        | RuntimeError::BackendContract(_)
        | RuntimeError::EnvelopeLengthMismatch
        | RuntimeError::EnvelopeHashMismatch
        | RuntimeError::TransferIdReuse
        | RuntimeError::Backpressure
        | RuntimeError::TransferIdExhausted
        | RuntimeError::FailedState => ContactFailure::Synchronization,
    }
}

fn contact_failure_detail(failure: ContactFailure) -> &'static str {
    match failure {
        ContactFailure::Authentication => "contact authentication rejected",
        ContactFailure::Carrier => "carrier unavailable",
        ContactFailure::LocalState => "local sync state unavailable",
        ContactFailure::Synchronization => "contact synchronization failed",
    }
}

fn node_config(options: &ApplicationNodeOptions) -> Result<NodeConfig, ServiceError> {
    if options.max_items == 0
        || options.max_bytes == 0
        || options.tombstone_retention_ms == 0
        || options.superseded_retention_ms == 0
    {
        return Err(ServiceError::Invalid(
            "node storage and retention limits must be nonzero".into(),
        ));
    }
    Ok(NodeConfig {
        store: StoreConfig {
            max_items: options.max_items,
            max_bytes: options.max_bytes,
            tombstone_retention_ms: options.tombstone_retention_ms,
            superseded_retention_ms: options.superseded_retention_ms,
        },
        emission: options.emission,
        priority_cap: options.priority_cap,
        ..NodeConfig::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_mesh::fragment::Fragment;
    use aster_mesh::link::{LinkCharacteristics, ReceivedFrame};
    use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};
    use std::collections::{BTreeSet, VecDeque};
    use std::fs;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[derive(Clone)]
    struct AutomaticMergeMustNotRun {
        calls: Arc<AtomicU64>,
    }

    impl ApplicationMergePolicy for AutomaticMergeMustNotRun {
        fn id(&self) -> &str {
            "test.manual-resolution-only/v1"
        }

        fn merge(&self, _versions: &[aster_mesh::MergeVersion]) -> Result<Vec<u8>, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err("registered policy must not execute during replicated ingestion".into())
        }
    }

    #[derive(Clone)]
    struct MemoryEndpoint {
        name: &'static str,
        mtu: u16,
        local_peer: NodeId,
        inbound: Arc<Mutex<VecDeque<ReceivedFrame>>>,
        outbound: Arc<Mutex<VecDeque<ReceivedFrame>>>,
    }

    impl MemoryEndpoint {
        fn pair(name: &'static str, mtu: u16, left: NodeId, right: NodeId) -> (Self, Self) {
            let left_inbound = Arc::new(Mutex::new(VecDeque::new()));
            let right_inbound = Arc::new(Mutex::new(VecDeque::new()));
            (
                Self {
                    name,
                    mtu,
                    local_peer: left,
                    inbound: left_inbound.clone(),
                    outbound: right_inbound.clone(),
                },
                Self {
                    name,
                    mtu,
                    local_peer: right,
                    inbound: right_inbound,
                    outbound: left_inbound,
                },
            )
        }

        fn send(&self, frame: &[u8]) -> io::Result<()> {
            self.outbound
                .lock()
                .map_err(|_| io::Error::other("memory carrier poisoned"))?
                .push_back(ReceivedFrame {
                    peer: Some(self.local_peer),
                    bytes: frame.to_vec(),
                });
            Ok(())
        }

        fn receive(&self) -> io::Result<Option<ReceivedFrame>> {
            Ok(self
                .inbound
                .lock()
                .map_err(|_| io::Error::other("memory carrier poisoned"))?
                .pop_front())
        }

        fn characteristics(&self) -> LinkCharacteristics {
            LinkCharacteristics {
                mtu: self.mtu,
                bits_per_second: Some(4_000),
                cost: 1,
                emission: 1,
                broadcast: false,
            }
        }
    }

    #[derive(Clone)]
    struct GatedCarrier {
        endpoint: MemoryEndpoint,
        allowed_transfer: Arc<Mutex<Option<u64>>>,
    }

    impl GatedCarrier {
        fn pair(mtu: u16, left: NodeId, right: NodeId) -> (Self, Self) {
            let (left_endpoint, right_endpoint) =
                MemoryEndpoint::pair("gated-small", mtu, left, right);
            (
                Self {
                    endpoint: left_endpoint,
                    allowed_transfer: Arc::new(Mutex::new(None)),
                },
                Self {
                    endpoint: right_endpoint,
                    allowed_transfer: Arc::new(Mutex::new(None)),
                },
            )
        }

        fn allow_next_logical(&self) {
            let next = self
                .endpoint
                .inbound
                .lock()
                .unwrap()
                .front()
                .and_then(|frame| Fragment::decode(&frame.bytes).ok())
                .map(|fragment| fragment.transfer_id);
            *self.allowed_transfer.lock().unwrap() = next;
        }
    }

    impl Link for GatedCarrier {
        fn name(&self) -> &str {
            self.endpoint.name
        }

        fn characteristics(&self) -> LinkCharacteristics {
            self.endpoint.characteristics()
        }

        fn send(&self, _peer: Option<NodeId>, frame: &[u8]) -> io::Result<()> {
            self.endpoint.send(frame)
        }

        fn try_receive(&self) -> io::Result<Option<ReceivedFrame>> {
            let allowed = *self
                .allowed_transfer
                .lock()
                .map_err(|_| io::Error::other("memory gate poisoned"))?;
            let Some(allowed) = allowed else {
                return Ok(None);
            };
            let mut inbound = self
                .endpoint
                .inbound
                .lock()
                .map_err(|_| io::Error::other("memory carrier poisoned"))?;
            let Some(front) = inbound.front() else {
                return Ok(None);
            };
            if Fragment::decode(&front.bytes)
                .map_err(io::Error::other)?
                .transfer_id
                != allowed
            {
                return Ok(None);
            }
            Ok(inbound.pop_front())
        }

        fn set_discovery(&self, _enabled: bool) -> io::Result<()> {
            Ok(())
        }

        fn retry_floor(&self) -> Duration {
            Duration::from_millis(1)
        }
    }

    fn drive_pair_until(
        left: &mut MeshService,
        right: &mut MeshService,
        timeout: Duration,
        mut complete: impl FnMut(&mut MeshService) -> bool,
    ) {
        let deadline = Instant::now() + timeout;
        loop {
            left.pump().unwrap();
            right.pump().unwrap();
            if complete(right) {
                return;
            }

            let now = Instant::now();
            if now >= deadline {
                panic!("pair did not reach the expected state within {timeout:?}");
            }
            let Some(wakeup) = [left.next_wakeup(), right.next_wakeup()]
                .into_iter()
                .flatten()
                .min()
            else {
                panic!("pair became quiescent before reaching the expected state");
            };
            std::thread::sleep(
                wakeup
                    .saturating_duration_since(now)
                    .min(deadline.saturating_duration_since(now)),
            );
        }
    }

    #[derive(Clone)]
    struct OpenCarrier(MemoryEndpoint);

    impl OpenCarrier {
        fn pair(mtu: u16, left: NodeId, right: NodeId) -> (Self, Self) {
            let (left, right) = MemoryEndpoint::pair("open-wide", mtu, left, right);
            (Self(left), Self(right))
        }
    }

    impl Link for OpenCarrier {
        fn name(&self) -> &str {
            self.0.name
        }

        fn characteristics(&self) -> LinkCharacteristics {
            self.0.characteristics()
        }

        fn send(&self, _peer: Option<NodeId>, frame: &[u8]) -> io::Result<()> {
            self.0.send(frame)
        }

        fn try_receive(&self) -> io::Result<Option<ReceivedFrame>> {
            self.0.receive()
        }

        fn set_discovery(&self, _enabled: bool) -> io::Result<()> {
            Ok(())
        }

        fn next_wakeup(&self) -> Option<Instant> {
            self.0
                .inbound
                .lock()
                .ok()
                .and_then(|inbound| (!inbound.is_empty()).then(Instant::now))
        }

        fn retry_floor(&self) -> Duration {
            Duration::from_millis(1)
        }
    }

    fn test_directory() -> PathBuf {
        static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(1);
        let ordinal = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-host-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            ordinal,
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn registered_merge_policy_does_not_publish_during_sync_or_recontact() {
        let root = test_directory();
        let topic = Topic::new("record.plan").unwrap();
        let scope = Scope::new("mission/team").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x7a; 32]).unwrap();
        let left_bundle = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let right_bundle = provisioner
            .issue_node(2, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();
        let options = ServiceOptions {
            node: ApplicationNodeOptions::default(),
            blobs: BlobStoreConfig::default(),
            sync: SyncProfile::new(vec![topic.clone()], vec![scope.clone()], Priority::Routine)
                .unwrap(),
        };
        let mut left = MeshService::open(
            root.join("left-record.sqlite"),
            root.join("left-record-blobs"),
            &left_bundle,
            options.clone(),
        )
        .unwrap();
        let mut right = MeshService::open(
            root.join("right-record.sqlite"),
            root.join("right-record-blobs"),
            &right_bundle,
            options,
        )
        .unwrap();
        let calls = Arc::new(AtomicU64::new(0));
        let policy = AutomaticMergeMustNotRun {
            calls: calls.clone(),
        };
        left.register_merge_policy(topic.clone(), Arc::new(policy.clone()))
            .unwrap();
        right
            .register_merge_policy(topic.clone(), Arc::new(policy))
            .unwrap();

        let record = |payload: &[u8]| PublishRequest {
            class: DataClass::Record,
            topic: topic.clone(),
            scope: scope.clone(),
            priority: Priority::Priority,
            ttl_ms: None,
            logical_key: b"plan-red".to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
        };
        let left_revision = left.publish(record(b"left revision")).unwrap();
        let right_revision = right.publish(record(b"right revision")).unwrap();
        assert_eq!(left.quota_usage(Some(&scope)).unwrap().items, 1);
        assert_eq!(right.quota_usage(Some(&scope)).unwrap().items, 1);
        let mut expected_siblings = vec![left_revision.id, right_revision.id];
        expected_siblings.sort_unstable();

        let left_id = left.identity();
        let right_id = right.identity();
        for _ in 0..2 {
            let (left_link, right_link) = OpenCarrier::pair(768, left_id, right_id);
            left.configure_peer_carrier(right_id, left_link).unwrap();
            right.configure_peer_carrier(left_id, right_link).unwrap();
        }
        left.begin_sync(right_id).unwrap();
        right.begin_sync(left_id).unwrap();

        let conflict_query = || Query {
            topic: Some(topic.clone()),
            scope: Some(scope.clone()),
            class: Some(DataClass::Record),
            logical_key: Some(b"plan-red".to_vec()),
            ..Query::default()
        };
        let expected_for_right = expected_siblings.clone();
        drive_pair_until(&mut left, &mut right, Duration::from_secs(5), |right| {
            right.conflicts(conflict_query()).is_ok_and(|conflicts| {
                conflicts.len() == 1 && conflicts[0].siblings == expected_for_right
            })
        });
        let expected_for_left = expected_siblings.clone();
        drive_pair_until(&mut right, &mut left, Duration::from_secs(5), |left| {
            left.conflicts(conflict_query()).is_ok_and(|conflicts| {
                conflicts.len() == 1 && conflicts[0].siblings == expected_for_left
            })
        });

        for service in [&mut left, &mut right] {
            let conflicts = service.conflicts(conflict_query()).unwrap();
            assert_eq!(conflicts.len(), 1);
            assert_eq!(conflicts[0].siblings, expected_siblings);
            assert_eq!(
                conflicts[0].merge_policy.as_deref(),
                Some("test.manual-resolution-only/v1")
            );
            assert_eq!(service.quota_usage(Some(&scope)).unwrap().items, 2);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        left.pause_sync().unwrap();
        right.pause_sync().unwrap();
        let left_recontact_revision = left.publish(record(b"left recontact revision")).unwrap();
        let right_recontact_revision = right.publish(record(b"right recontact revision")).unwrap();
        let mut expected_recontact_siblings =
            vec![left_recontact_revision.id, right_recontact_revision.id];
        expected_recontact_siblings.sort_unstable();

        left.begin_sync(right_id).unwrap();
        right.begin_sync(left_id).unwrap();
        let expected_for_right = expected_recontact_siblings.clone();
        drive_pair_until(&mut left, &mut right, Duration::from_secs(5), |right| {
            right.conflicts(conflict_query()).is_ok_and(|conflicts| {
                conflicts.len() == 1 && conflicts[0].siblings == expected_for_right
            })
        });
        let expected_for_left = expected_recontact_siblings.clone();
        drive_pair_until(&mut right, &mut left, Duration::from_secs(5), |left| {
            left.conflicts(conflict_query()).is_ok_and(|conflicts| {
                conflicts.len() == 1 && conflicts[0].siblings == expected_for_left
            })
        });
        for service in [&mut left, &mut right] {
            let conflicts = service.conflicts(conflict_query()).unwrap();
            assert_eq!(conflicts.len(), 1);
            assert_eq!(conflicts[0].siblings, expected_recontact_siblings);
            assert_eq!(
                conflicts[0].merge_policy.as_deref(),
                Some("test.manual-resolution-only/v1")
            );
            assert_eq!(service.quota_usage(Some(&scope)).unwrap().items, 4);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        left.pause_sync().unwrap();
        right.pause_sync().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    fn activate_service_epoch(service: &mut MeshService, scope: &Scope, epoch: u64) {
        let ServiceState::Offline(backend) = &mut service.state else {
            panic!("test epoch activation requires an offline service");
        };
        backend
            .node_mut()
            .publish_scope_epoch(scope, epoch)
            .unwrap();
    }

    #[test]
    fn offline_batch_publication_is_queryable_and_restart_durable() {
        let root = test_directory();
        let database = root.join("batch.sqlite");
        let blobs = root.join("batch-blobs");
        let topic = Topic::new("batch.host").unwrap();
        let scope = Scope::new("mission/host-batch").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x79; 32]).unwrap();
        let bundle = provisioner
            .issue_node(1, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();
        let options = ServiceOptions {
            node: ApplicationNodeOptions::default(),
            blobs: BlobStoreConfig::default(),
            sync: SyncProfile::new(vec![topic.clone()], vec![scope.clone()], Priority::Routine)
                .unwrap(),
        };
        let item = |key: &[u8], payload: &[u8]| PublishRequest {
            class: DataClass::State,
            topic: topic.clone(),
            scope: scope.clone(),
            priority: Priority::Routine,
            ttl_ms: None,
            logical_key: key.to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
        };
        let mut service = MeshService::open(&database, &blobs, &bundle, options.clone()).unwrap();
        let result = service
            .publish_batch(BatchPublishRequest::batch_only(vec![
                item(b"alpha", b"ready"),
                item(b"bravo", b"moving"),
            ]))
            .unwrap();
        assert_eq!(result.items.len(), 2);
        assert_eq!(result.items[0].publisher_counter, 1);
        assert_eq!(result.items[1].publisher_counter, 2);
        assert_eq!(
            service
                .query(Query {
                    topic: Some(topic.clone()),
                    scope: Some(scope.clone()),
                    class: Some(DataClass::State),
                    ..Query::default()
                })
                .unwrap()
                .len(),
            2
        );
        drop(service);

        let mut restarted = MeshService::open(&database, &blobs, &bundle, options).unwrap();
        let queried = restarted
            .query(Query {
                topic: Some(topic),
                scope: Some(scope),
                class: Some(DataClass::State),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(queried.len(), 2);
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retained_batch_inventory_selects_exact_representation_by_semantic_version() {
        use aster_mesh::inventory::NibblePrefix;
        use aster_mesh::wire::ObjectKind;

        let root = test_directory();
        let topic = Topic::new("batch.inventory").unwrap();
        let scope = Scope::new("mission/batch-inventory").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x7a; 32]).unwrap();
        let bundle = provisioner
            .issue_node(1, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();
        let options = ServiceOptions {
            node: ApplicationNodeOptions::default(),
            blobs: BlobStoreConfig::default(),
            sync: SyncProfile::new(vec![topic.clone()], vec![scope.clone()], Priority::Routine)
                .unwrap(),
        };
        let item = |key: &[u8]| PublishRequest {
            class: DataClass::State,
            topic: topic.clone(),
            scope: scope.clone(),
            priority: Priority::Routine,
            ttl_ms: None,
            logical_key: key.to_vec(),
            payload: key.to_vec(),
            tombstone: false,
        };
        let mut service = MeshService::open(
            root.join("inventory.sqlite"),
            root.join("inventory-blobs"),
            &bundle,
            options,
        )
        .unwrap();
        service
            .publish_batch(BatchPublishRequest::new(vec![item(b"one"), item(b"two")]))
            .unwrap();
        service
            .publish_batch(BatchPublishRequest::batch_only(vec![
                item(b"three"),
                item(b"four"),
            ]))
            .unwrap();
        let ServiceState::Offline(backend) = &mut service.state else {
            panic!("inventory test requires an offline service");
        };
        let filter = InterestFilter {
            topics: vec![topic.as_str().to_owned()],
            scopes: vec![scope.as_str().to_owned()],
            min_priority: Priority::Routine as u8,
        };
        let peer = [0xa5; 32];
        let v1 = backend
            .select_authorized_inventory_for_semantic_version(
                peer,
                &[],
                &filter,
                InventoryPurpose::ReceiveBaseline,
                1,
            )
            .unwrap()
            .ids_under(&NibblePrefix::root(), 16);
        assert_eq!(
            v1.iter()
                .filter(|id| id.kind() == ObjectKind::SourceEnvelope)
                .count(),
            2
        );
        assert!(
            v1.iter()
                .all(|id| id.kind() != ObjectKind::SourceBatchProof)
        );

        let v2 = backend
            .select_authorized_inventory_for_semantic_version(
                peer,
                &[],
                &filter,
                InventoryPurpose::ReceiveBaseline,
                2,
            )
            .unwrap()
            .ids_under(&NibblePrefix::root(), 16);
        assert_eq!(
            v2.iter()
                .filter(|id| id.kind() == ObjectKind::SourceEnvelope)
                .count(),
            4
        );
        assert_eq!(
            v2.iter()
                .filter(|id| id.kind() == ObjectKind::SourceBatchProof)
                .count(),
            2
        );
        assert!(v1.iter().all(|id| !v2.contains(id)));

        drop(service);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn batch_only_publication_replicates_and_reauthenticates_after_receiver_restart() {
        let root = test_directory();
        let topic = Topic::new("batch.peer").unwrap();
        let scope = Scope::new("mission/batch-peer").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x7b; 32]).unwrap();
        let left_bundle = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let right_bundle = provisioner
            .issue_node(2, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();
        let options = ServiceOptions {
            node: ApplicationNodeOptions::default(),
            blobs: BlobStoreConfig::default(),
            sync: SyncProfile::new(vec![topic.clone()], vec![scope.clone()], Priority::Routine)
                .unwrap(),
        };
        let right_database = root.join("right-batch.sqlite");
        let right_blobs = root.join("right-batch-blobs");
        let mut left = MeshService::open(
            root.join("left-batch.sqlite"),
            root.join("left-batch-blobs"),
            &left_bundle,
            options.clone(),
        )
        .unwrap();
        let mut right = MeshService::open(
            &right_database,
            &right_blobs,
            &right_bundle,
            options.clone(),
        )
        .unwrap();
        let item = |key: &[u8], payload: &[u8]| PublishRequest {
            class: DataClass::State,
            topic: topic.clone(),
            scope: scope.clone(),
            priority: Priority::Priority,
            ttl_ms: None,
            logical_key: key.to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
        };
        let published = left
            .publish_batch(BatchPublishRequest::batch_only(vec![
                item(b"alpha", b"ready"),
                item(b"bravo", b"moving"),
            ]))
            .unwrap();
        let left_id = left.identity();
        let right_id = right.identity();
        let (left_link, right_link) = OpenCarrier::pair(768, left_id, right_id);
        left.configure_peer_carrier(right_id, left_link).unwrap();
        right.configure_peer_carrier(left_id, right_link).unwrap();
        left.begin_sync(right_id).unwrap();
        right.begin_sync(left_id).unwrap();
        drive_pair_until(&mut left, &mut right, Duration::from_secs(5), |right| {
            right
                .query(Query {
                    topic: Some(topic.clone()),
                    scope: Some(scope.clone()),
                    class: Some(DataClass::State),
                    ..Query::default()
                })
                .unwrap()
                .len()
                == 2
        });
        let received = right
            .query(Query {
                topic: Some(topic.clone()),
                scope: Some(scope.clone()),
                class: Some(DataClass::State),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(received.len(), 2);
        assert_eq!(
            received.iter().map(|item| item.id).collect::<BTreeSet<_>>(),
            published
                .items
                .iter()
                .map(|item| item.id)
                .collect::<BTreeSet<_>>()
        );
        left.pause_sync().unwrap();
        right.pause_sync().unwrap();
        drop(right);

        let mut restarted =
            MeshService::open(&right_database, &right_blobs, &right_bundle, options).unwrap();
        let reopened = restarted
            .query(Query {
                topic: Some(topic),
                scope: Some(scope),
                class: Some(DataClass::State),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(reopened.len(), 2);
        drop(restarted);
        drop(left);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn finalized_batch_blob_carriers_follow_proof_and_compact_receipts() {
        use aster_mesh::FinishedBlobBatchItem;
        use aster_mesh::blob::{BlobMetadata, MIN_BLOB_CHUNK_SIZE};

        let root = test_directory();
        let topic = Topic::new("batch.peer-blobs").unwrap();
        let scope = Scope::new("mission/batch-peer-blobs").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x7c; 32]).unwrap();
        let left_bundle = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let right_bundle = provisioner
            .issue_node(2, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();
        let options = ServiceOptions {
            node: ApplicationNodeOptions::default(),
            blobs: BlobStoreConfig::default(),
            sync: SyncProfile::new(vec![topic.clone()], vec![scope.clone()], Priority::Routine)
                .unwrap(),
        };
        let mut left = MeshService::open(
            root.join("left-blob-batch.sqlite"),
            root.join("left-blob-batch-store"),
            &left_bundle,
            options.clone(),
        )
        .unwrap();
        let mut right = MeshService::open(
            root.join("right-blob-batch.sqlite"),
            root.join("right-blob-batch-store"),
            &right_bundle,
            options,
        )
        .unwrap();
        let first_plaintext = vec![0x31; MIN_BLOB_CHUNK_SIZE as usize + 137];
        let second_plaintext = vec![0x52; MIN_BLOB_CHUNK_SIZE as usize * 2 + 19];
        let mut blob_service = left.open_blob_service(&scope, &topic).unwrap();
        let mut finish = |plaintext: &[u8], schema: &[u8]| {
            let mut source = io::Cursor::new(plaintext.to_vec());
            let mut scratch = io::Cursor::new(Vec::new());
            let manifest = blob_service
                .prepare(
                    &mut source,
                    &mut scratch,
                    MIN_BLOB_CHUNK_SIZE,
                    BlobMetadata::new(Some("application/octet-stream".into()), schema.to_vec())
                        .unwrap(),
                )
                .unwrap();
            assert!(
                blob_service
                    .encrypt_some(&mut source, &manifest, u64::MAX)
                    .unwrap()
                    .complete
            );
            blob_service.finish(manifest.id()).unwrap()
        };
        let first = finish(&first_plaintext, b"first");
        let second = finish(&second_plaintext, b"second");
        drop(blob_service);
        left.publish_finished_blob_batch(FinishedBlobBatchRequest::batch_only(vec![
            FinishedBlobBatchItem {
                topic: topic.clone(),
                scope: scope.clone(),
                priority: Priority::Priority,
                ttl_ms: None,
                finished: first.clone(),
            },
            FinishedBlobBatchItem {
                topic: topic.clone(),
                scope: scope.clone(),
                priority: Priority::Routine,
                ttl_ms: None,
                finished: second.clone(),
            },
        ]))
        .unwrap();

        let left_id = left.identity();
        let right_id = right.identity();
        let (left_link, right_link) = OpenCarrier::pair(1024, left_id, right_id);
        left.configure_peer_carrier(right_id, left_link).unwrap();
        right.configure_peer_carrier(left_id, right_link).unwrap();
        left.begin_sync(right_id).unwrap();
        right.begin_sync(left_id).unwrap();
        drive_pair_until(&mut left, &mut right, Duration::from_secs(30), |right| {
            right.open_blob_reader(&scope, &topic, first.id()).is_ok()
                && right.open_blob_reader(&scope, &topic, second.id()).is_ok()
        });
        let mut first_reader = right.open_blob_reader(&scope, &topic, first.id()).unwrap();
        let mut first_output = Vec::new();
        first_reader.stream_into(&mut first_output).unwrap();
        assert_eq!(first_output, first_plaintext);
        let mut second_reader = right.open_blob_reader(&scope, &topic, second.id()).unwrap();
        let mut second_output = Vec::new();
        second_reader.stream_into(&mut second_output).unwrap();
        assert_eq!(second_output, second_plaintext);

        left.pause_sync().unwrap();
        right.pause_sync().unwrap();
        drop(left);
        drop(right);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn offline_publish_partially_syncs_then_resumes_over_a_different_carrier() {
        let root = test_directory();
        let topic = Topic::new("alpha").unwrap();
        let scope = Scope::new("mission/team").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x73; 32]).unwrap();
        let left_bundle = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let right_bundle = provisioner
            .issue_node(2, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();
        let options = ServiceOptions {
            node: ApplicationNodeOptions::default(),
            blobs: BlobStoreConfig::default(),
            sync: SyncProfile::new(vec![topic.clone()], vec![scope.clone()], Priority::Routine)
                .unwrap(),
        };
        let mut left = MeshService::open(
            root.join("left.sqlite"),
            root.join("left-blobs"),
            &left_bundle,
            options.clone(),
        )
        .unwrap();
        let mut right = MeshService::open(
            root.join("right.sqlite"),
            root.join("right-blobs"),
            &right_bundle,
            options,
        )
        .unwrap();
        let left_id = left.identity();
        let right_id = right.identity();
        let (left_small, right_small) = GatedCarrier::pair(96, left_id, right_id);
        let (left_wide, right_wide) = OpenCarrier::pair(768, left_id, right_id);
        left.configure_peer_carrier(right_id, left_small.clone())
            .unwrap();
        right
            .configure_peer_carrier(left_id, right_small.clone())
            .unwrap();
        left.configure_peer_carrier(right_id, left_wide).unwrap();
        right.configure_peer_carrier(left_id, right_wide).unwrap();
        assert_eq!(left.configured_carrier_count(), 2);
        assert_eq!(right.configured_carrier_count(), 2);
        assert_eq!(left.next_wakeup(), None);

        let subscription = right
            .subscribe(topic.clone(), scope.clone(), Some(DataClass::Event), false)
            .unwrap();
        let payload = (0..180_000)
            .map(|index| ((index * 17 + 11) % 251) as u8)
            .collect::<Vec<_>>();
        let published = left
            .publish(PublishRequest {
                class: DataClass::Event,
                topic: topic.clone(),
                scope: scope.clone(),
                priority: Priority::Priority,
                ttl_ms: None,
                logical_key: b"offline-large-event".to_vec(),
                payload: payload.clone(),
                tombstone: false,
            })
            .unwrap();
        assert!(right.query(Query::default()).unwrap().is_empty());

        left.begin_sync(right_id).unwrap();
        right.begin_sync(left_id).unwrap();
        assert!(left.next_wakeup().is_some() || right.next_wakeup().is_some());
        let mut observed_partial = false;
        for _ in 0..2_000 {
            left_small.allow_next_logical();
            left.pump().unwrap();
            right_small.allow_next_logical();
            right.pump().unwrap();
            observed_partial = right.durable_progress().iter().any(|progress| {
                let received = progress
                    .received
                    .iter()
                    .map(|range| range.end - range.start)
                    .sum::<u64>();
                received > 0 && received < progress.total_len
            });
            if observed_partial {
                break;
            }
        }
        assert!(
            observed_partial,
            "small carrier did not durably stage a partial object"
        );
        assert!(right.query(Query::default()).unwrap().is_empty());
        left.pause_sync().unwrap();
        right.pause_sync().unwrap();
        assert_eq!(left.next_wakeup(), None);
        assert_eq!(right.next_wakeup(), None);

        // Round-robin contact selection moves both services to the second,
        // separately implemented carrier. A fresh authenticated session hydrates
        // the peer-neutral range written by the first contact.
        left.begin_sync(right_id).unwrap();
        right.begin_sync(left_id).unwrap();
        for _ in 0..1_000 {
            left.pump().unwrap();
            right.pump().unwrap();
            if right
                .query(Query {
                    topic: Some(topic.clone()),
                    scope: Some(scope.clone()),
                    class: Some(DataClass::Event),
                    ..Query::default()
                })
                .unwrap()
                .iter()
                .any(|item| item.id == published.id)
            {
                break;
            }
        }
        let deliveries = right.poll(subscription, 8).unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].item.id, published.id);
        assert_eq!(deliveries[0].item.payload, payload);
        right
            .acknowledge(subscription, deliveries[0].item.id)
            .unwrap();
        assert!(right.poll(subscription, 8).unwrap().is_empty());

        left.pause_sync().unwrap();
        right.pause_sync().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publish_during_authenticated_contact_reselects_inventory_without_reconnect() {
        let root = test_directory();
        let topic = Topic::new("alpha").unwrap();
        let scope = Scope::new("mission/team").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x74; 32]).unwrap();
        let left_bundle = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let right_bundle = provisioner
            .issue_node(2, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();
        let options = ServiceOptions {
            node: ApplicationNodeOptions::default(),
            blobs: BlobStoreConfig::default(),
            sync: SyncProfile::new(vec![topic.clone()], vec![scope.clone()], Priority::Routine)
                .unwrap(),
        };
        let mut left = MeshService::open(
            root.join("left-live.sqlite"),
            root.join("left-live-blobs"),
            &left_bundle,
            options.clone(),
        )
        .unwrap();
        let mut right = MeshService::open(
            root.join("right-live.sqlite"),
            root.join("right-live-blobs"),
            &right_bundle,
            options,
        )
        .unwrap();
        let left_id = left.identity();
        let right_id = right.identity();
        let (left_link, right_link) = OpenCarrier::pair(768, left_id, right_id);
        left.configure_peer_carrier(right_id, left_link).unwrap();
        right.configure_peer_carrier(left_id, right_link).unwrap();
        left.begin_sync(right_id).unwrap();
        right.begin_sync(left_id).unwrap();
        for _ in 0..128 {
            left.pump().unwrap();
            right.pump().unwrap();
            if left
                .active_contact()
                .is_some_and(|status| status.authenticated)
                && right
                    .active_contact()
                    .is_some_and(|status| status.authenticated)
            {
                for _ in 0..16 {
                    left.pump().unwrap();
                    right.pump().unwrap();
                }
                break;
            }
        }
        assert!(
            left.active_contact()
                .is_some_and(|status| status.authenticated)
        );
        assert!(
            right
                .active_contact()
                .is_some_and(|status| status.authenticated)
        );
        assert!(right.query(Query::default()).unwrap().is_empty());

        let published = left
            .publish(PublishRequest {
                class: DataClass::Event,
                topic: topic.clone(),
                scope: scope.clone(),
                priority: Priority::Priority,
                ttl_ms: None,
                logical_key: b"live-event".to_vec(),
                payload: b"committed during contact".to_vec(),
                tombstone: false,
            })
            .unwrap();
        for _ in 0..512 {
            left.pump().unwrap();
            right.pump().unwrap();
            if right
                .query(Query {
                    topic: Some(topic.clone()),
                    scope: Some(scope.clone()),
                    class: Some(DataClass::Event),
                    ..Query::default()
                })
                .unwrap()
                .iter()
                .any(|item| item.id == published.id)
            {
                break;
            }
        }
        assert!(
            right
                .query(Query {
                    topic: Some(topic),
                    scope: Some(scope),
                    class: Some(DataClass::Event),
                    ..Query::default()
                })
                .unwrap()
                .iter()
                .any(|item| item.id == published.id)
        );

        left.pause_sync().unwrap();
        right.pause_sync().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bridge_status_handles_and_projection_survive_host_restart() {
        let root = test_directory();
        let source_scope = Scope::new("mission/source").unwrap();
        let target_scope = Scope::new("mission/target").unwrap();
        let topic = Topic::new("ops").unwrap();
        let accesses = [
            ProvisioningAccess::member(source_scope.clone(), vec![1], vec![topic.clone()]).unwrap(),
            ProvisioningAccess::member(target_scope.clone(), vec![2], vec![topic.clone()]).unwrap(),
        ];
        let mut provisioner = ReferenceProvisioner::from_seed([0x75; 32]).unwrap();
        let bundle = provisioner
            .issue_control_authority(1, &accesses)
            .unwrap()
            .to_bytes()
            .unwrap();
        let options = ServiceOptions {
            node: ApplicationNodeOptions::default(),
            blobs: BlobStoreConfig::default(),
            sync: SyncProfile::new(
                vec![topic.clone()],
                vec![source_scope.clone(), target_scope.clone()],
                Priority::Routine,
            )
            .unwrap(),
        };
        let database = root.join("bridge-restart.sqlite");
        let blobs = root.join("bridge-restart-blobs");
        let mut service = MeshService::open(&database, &blobs, &bundle, options.clone()).unwrap();
        activate_service_epoch(&mut service, &source_scope, 1);
        activate_service_epoch(&mut service, &target_scope, 2);
        service
            .set_bridge_filters(&[BridgeFilter {
                from_scope: source_scope.clone(),
                to_scope: target_scope.clone(),
                topics: std::collections::BTreeSet::from([topic.clone()]),
                minimum_priority: Priority::Routine,
            }])
            .unwrap();
        let enrollment = service
            .create_bridge_enrollment(source_scope.clone(), 1, target_scope.clone(), 2)
            .unwrap();
        let authorization = service
            .enable_bridge(
                enrollment,
                BridgeAuthorizationPolicy::new(vec![topic.clone()], vec![Priority::Immediate], 1)
                    .unwrap(),
            )
            .unwrap();
        let source = service
            .publish(PublishRequest {
                class: DataClass::State,
                topic: topic.clone(),
                scope: source_scope.clone(),
                priority: Priority::Immediate,
                ttl_ms: None,
                logical_key: b"host-bridge-restart".to_vec(),
                payload: b"restart-safe".to_vec(),
                tombstone: false,
            })
            .unwrap();
        let route = service
            .bridge_item(
                source.id,
                authorization.id,
                BridgeNarrowingPolicy::new(vec![topic.clone()], vec![Priority::Immediate]).unwrap(),
            )
            .unwrap();
        assert!(
            service
                .bridge_authorization_status(authorization.id)
                .unwrap()
                .unwrap()
                .usable
        );
        assert!(
            service
                .bridge_route_status(route.handle)
                .unwrap()
                .unwrap()
                .live
        );
        assert_eq!(service.bridge_authorizations(None, 8).unwrap().len(), 1);
        assert_eq!(service.bridge_routes(None, 8).unwrap().len(), 1);
        drop(service);

        let mut restarted = MeshService::open(&database, &blobs, &bundle, options).unwrap();
        assert_eq!(
            BridgeAuthorizationId::from_slice(authorization.id.as_bytes()).unwrap(),
            authorization.id
        );
        assert_eq!(
            BridgeRouteHandle::from_slice(route.handle.as_bytes()).unwrap(),
            route.handle
        );
        assert!(
            restarted
                .bridge_authorization_status(authorization.id)
                .unwrap()
                .unwrap()
                .usable
        );
        assert!(
            restarted
                .bridge_route_status(route.handle)
                .unwrap()
                .unwrap()
                .live
        );
        let projected = restarted
            .query(Query {
                topic: Some(topic),
                scope: Some(target_scope),
                class: Some(DataClass::State),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(projected.len(), 1);
        assert_eq!(projected[0].id, source.id);
        assert_eq!(projected[0].payload, b"restart-safe");
        drop(restarted);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bridge_first_sync_materializes_one_authorized_origin_view() {
        let root = test_directory();
        let source_scope = Scope::new("mission/source").unwrap();
        let target_scope = Scope::new("mission/target").unwrap();
        let topic = Topic::new("ops").unwrap();
        let accesses = [
            ProvisioningAccess::member(source_scope.clone(), vec![1], vec![topic.clone()]).unwrap(),
            ProvisioningAccess::member(target_scope.clone(), vec![2], vec![topic.clone()]).unwrap(),
        ];
        let mut provisioner = ReferenceProvisioner::from_seed([0x76; 32]).unwrap();
        let sender_bundle = provisioner
            .issue_control_authority(1, &accesses)
            .unwrap()
            .to_bytes()
            .unwrap();
        let receiver_bundle = provisioner
            .issue_node(2, &accesses)
            .unwrap()
            .to_bytes()
            .unwrap();
        let sender_options = ServiceOptions {
            node: ApplicationNodeOptions::default(),
            blobs: BlobStoreConfig::default(),
            sync: SyncProfile::new(
                vec![topic.clone()],
                vec![source_scope.clone(), target_scope.clone()],
                Priority::Routine,
            )
            .unwrap(),
        };
        // The receiver asks only for the target projection. Its origin view
        // can therefore arise only from provider-authorized bridge-source
        // materialization, not ordinary source-scope inventory selection.
        let receiver_options = ServiceOptions {
            node: ApplicationNodeOptions::default(),
            blobs: BlobStoreConfig::default(),
            sync: SyncProfile::new(
                vec![topic.clone()],
                vec![target_scope.clone()],
                Priority::Routine,
            )
            .unwrap(),
        };
        let mut sender = MeshService::open(
            root.join("bridge-first-sender.sqlite"),
            root.join("bridge-first-sender-blobs"),
            &sender_bundle,
            sender_options,
        )
        .unwrap();
        let mut receiver = MeshService::open(
            root.join("bridge-first-receiver.sqlite"),
            root.join("bridge-first-receiver-blobs"),
            &receiver_bundle,
            receiver_options,
        )
        .unwrap();
        activate_service_epoch(&mut sender, &source_scope, 1);
        activate_service_epoch(&mut sender, &target_scope, 2);
        let filter = BridgeFilter {
            from_scope: source_scope.clone(),
            to_scope: target_scope.clone(),
            topics: std::collections::BTreeSet::from([topic.clone()]),
            minimum_priority: Priority::Routine,
        };
        sender
            .set_bridge_filters(std::slice::from_ref(&filter))
            .unwrap();
        receiver.set_bridge_filters(&[filter]).unwrap();
        let enrollment = sender
            .create_bridge_enrollment(source_scope.clone(), 1, target_scope.clone(), 2)
            .unwrap();
        let authorization = sender
            .enable_bridge(
                enrollment,
                BridgeAuthorizationPolicy::new(vec![topic.clone()], vec![Priority::Immediate], 1)
                    .unwrap(),
            )
            .unwrap();
        let source = sender
            .publish(PublishRequest {
                class: DataClass::State,
                topic: topic.clone(),
                scope: source_scope.clone(),
                priority: Priority::Immediate,
                ttl_ms: None,
                logical_key: b"bridge-first".to_vec(),
                payload: b"one semantic item".to_vec(),
                tombstone: false,
            })
            .unwrap();
        sender
            .bridge_item(
                source.id,
                authorization.id,
                BridgeNarrowingPolicy::new(vec![topic.clone()], vec![Priority::Immediate]).unwrap(),
            )
            .unwrap();

        let sender_id = sender.identity();
        let receiver_id = receiver.identity();
        let (sender_link, receiver_link) = OpenCarrier::pair(1_400, sender_id, receiver_id);
        sender
            .configure_peer_carrier(receiver_id, sender_link)
            .unwrap();
        receiver
            .configure_peer_carrier(sender_id, receiver_link)
            .unwrap();
        sender.begin_sync(receiver_id).unwrap();
        receiver.begin_sync(sender_id).unwrap();
        drive_pair_until(
            &mut sender,
            &mut receiver,
            Duration::from_secs(5),
            |receiver| {
                receiver
                    .query(Query {
                        topic: Some(topic.clone()),
                        scope: Some(target_scope.clone()),
                        class: Some(DataClass::State),
                        ..Query::default()
                    })
                    .unwrap()
                    .iter()
                    .any(|item| item.id == source.id)
            },
        );
        let target = receiver
            .query(Query {
                topic: Some(topic.clone()),
                scope: Some(target_scope),
                class: Some(DataClass::State),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(target.len(), 1);
        assert_eq!(target[0].id, source.id);
        let origin = receiver
            .query(Query {
                topic: Some(topic.clone()),
                scope: Some(source_scope),
                class: Some(DataClass::State),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(origin.len(), 1);
        assert_eq!(origin[0].id, source.id);
        assert_eq!(origin[0].payload, b"one semantic item");
        assert_eq!(
            receiver
                .query(Query {
                    topic: Some(topic),
                    class: Some(DataClass::State),
                    ..Query::default()
                })
                .unwrap()
                .iter()
                .filter(|item| item.id == source.id)
                .count(),
            1
        );

        sender.pause_sync().unwrap();
        receiver.pause_sync().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn high_level_rekey_excludes_an_omitted_captured_node() {
        let root = test_directory();
        let topic = Topic::new("ops").unwrap();
        let scope = Scope::new("mission/team").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x91; 32]).unwrap();
        let included_bundle = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let captured_bundle = provisioner
            .issue_node(2, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let authority_bundle = provisioner
            .issue_control_authority(3, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();
        let registry = provisioner.export_rekey_registry().unwrap();
        assert_eq!(provisioner.rekey_registry_generation(), 3);
        let options = ServiceOptions {
            node: ApplicationNodeOptions::default(),
            blobs: BlobStoreConfig::default(),
            sync: SyncProfile::new(vec![topic.clone()], vec![scope.clone()], Priority::Routine)
                .unwrap(),
        };
        let mut authority = MeshService::open(
            root.join("authority.sqlite"),
            root.join("authority-blobs"),
            &authority_bundle,
            options.clone(),
        )
        .unwrap();
        let mut included = MeshService::open(
            root.join("included.sqlite"),
            root.join("included-blobs"),
            &included_bundle,
            options.clone(),
        )
        .unwrap();
        let mut captured = MeshService::open(
            root.join("captured.sqlite"),
            root.join("captured-blobs"),
            &captured_bundle,
            options.clone(),
        )
        .unwrap();
        let authority_id = authority.identity();
        let included_id = included.identity();
        let captured_id = captured.identity();
        let (authority_to_included, included_to_authority) =
            OpenCarrier::pair(1_400, authority_id, included_id);
        let (authority_to_captured, captured_to_authority) =
            OpenCarrier::pair(1_400, authority_id, captured_id);
        authority
            .configure_peer_carrier(included_id, authority_to_included)
            .unwrap();
        included
            .configure_peer_carrier(authority_id, included_to_authority)
            .unwrap();
        authority
            .configure_peer_carrier(captured_id, authority_to_captured)
            .unwrap();
        captured
            .configure_peer_carrier(authority_id, captured_to_authority)
            .unwrap();
        let included_subscription = included
            .subscribe(topic.clone(), scope.clone(), Some(DataClass::Event), false)
            .unwrap();
        let captured_subscription = captured
            .subscribe(topic.clone(), scope.clone(), Some(DataClass::Event), false)
            .unwrap();

        let rekey = authority
            .rekey_scope(
                &registry,
                3,
                scope.clone(),
                1,
                vec![
                    RekeyRecipient::read_topics(authority_id, vec![topic.clone()]).unwrap(),
                    RekeyRecipient::read_topics(included_id, vec![topic.clone()]).unwrap(),
                ],
            )
            .unwrap();
        assert_eq!(rekey.registry_generation, 3);
        assert_eq!(rekey.recipient_count, 2);

        // Propagate and durably activate the authority control before creating
        // data under its new epoch. Both the included and omitted old-epoch
        // members can authenticate this control contact.
        authority.begin_sync(included_id).unwrap();
        included.begin_sync(authority_id).unwrap();
        for _ in 0..500 {
            authority.pump().unwrap();
            included.pump().unwrap();
        }
        authority.pause_sync().unwrap();
        included.pause_sync().unwrap();

        authority.begin_sync(captured_id).unwrap();
        captured.begin_sync(authority_id).unwrap();
        for _ in 0..500 {
            authority.pump().unwrap();
            captured.pump().unwrap();
        }
        authority.pause_sync().unwrap();
        captured.pause_sync().unwrap();

        // Reopen every durable node before any fresh data is created. The
        // included node must replay its forwarded control into the provider;
        // the omitted node must replay the same public control without gaining
        // a recipient package.
        drop(authority);
        drop(included);
        drop(captured);
        let mut authority = MeshService::open(
            root.join("authority.sqlite"),
            root.join("authority-blobs"),
            &authority_bundle,
            options.clone(),
        )
        .unwrap();
        let mut included = MeshService::open(
            root.join("included.sqlite"),
            root.join("included-blobs"),
            &included_bundle,
            options.clone(),
        )
        .unwrap();
        let mut captured = MeshService::open(
            root.join("captured.sqlite"),
            root.join("captured-blobs"),
            &captured_bundle,
            options,
        )
        .unwrap();
        assert_eq!(authority.identity(), authority_id);
        assert_eq!(included.identity(), included_id);
        assert_eq!(captured.identity(), captured_id);
        let (authority_to_included, included_to_authority) =
            OpenCarrier::pair(1_400, authority_id, included_id);
        let (authority_to_captured, captured_to_authority) =
            OpenCarrier::pair(1_400, authority_id, captured_id);
        authority
            .configure_peer_carrier(included_id, authority_to_included)
            .unwrap();
        included
            .configure_peer_carrier(authority_id, included_to_authority)
            .unwrap();
        authority
            .configure_peer_carrier(captured_id, authority_to_captured)
            .unwrap();
        captured
            .configure_peer_carrier(authority_id, captured_to_authority)
            .unwrap();

        let fresh_payload = b"fresh epoch excludes captured credential".to_vec();
        let published = authority
            .publish(PublishRequest {
                class: DataClass::Event,
                topic: topic.clone(),
                scope: scope.clone(),
                priority: Priority::Immediate,
                ttl_ms: None,
                logical_key: b"fresh-after-capture".to_vec(),
                payload: fresh_payload.clone(),
                tombstone: false,
            })
            .unwrap();

        // A fresh contact delivers the new-epoch item to the included member.
        authority.begin_sync(included_id).unwrap();
        included.begin_sync(authority_id).unwrap();
        for _ in 0..2_000 {
            authority.pump().unwrap();
            included.pump().unwrap();
            if included
                .query(Query {
                    topic: Some(topic.clone()),
                    scope: Some(scope.clone()),
                    class: Some(DataClass::Event),
                    ..Query::default()
                })
                .unwrap()
                .iter()
                .any(|item| item.id == published.id)
            {
                break;
            }
        }
        let delivered = included.poll(included_subscription, 8).unwrap();
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].item.id, published.id);
        assert_eq!(delivered[0].item.payload, fresh_payload);
        authority.pause_sync().unwrap();
        included.pause_sync().unwrap();

        // The omitted node is absent from both the authority's fresh route
        // authorization and recipient packages, so another valid authenticated
        // contact cannot reveal or deliver the new-epoch item.
        authority.begin_sync(captured_id).unwrap();
        captured.begin_sync(authority_id).unwrap();
        for _ in 0..500 {
            authority.pump().unwrap();
            captured.pump().unwrap();
        }
        assert!(captured.poll(captured_subscription, 8).unwrap().is_empty());
        assert!(
            captured
                .query(Query {
                    topic: Some(topic),
                    scope: Some(scope),
                    class: Some(DataClass::Event),
                    ..Query::default()
                })
                .unwrap()
                .is_empty()
        );
        authority.pause_sync().unwrap();
        captured.pause_sync().unwrap();

        drop(authority);
        drop(included);
        drop(captured);
        fs::remove_dir_all(root).unwrap();
    }
}
