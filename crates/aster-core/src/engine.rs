//! Synchronous, event-driven, offline-first node facade.
//!
//! Applications publish into one local atomic commit and may immediately go
//! offline. Network code exchanges only opaque `Emission::sealed` bytes; source
//! sealing, authenticated metadata inspection, payload opening, and control-plane
//! verification are isolated behind [`EnvelopeSealer`]. Wall time is used only to
//! improve TTL behavior and never to order versions or resolve conflicts.

use crate::blob::{BlobId, BlobRouteCommitment};
use crate::model::{
    CausalStamp, ConflictAnnotation, DataClass, ItemId, NodeId, PeerStatus, Priority, Scope,
    SyncStatus, Topic, VersionVector,
};
use crate::store::{
    AppDelivery, ApplyOutcome, BatchStoragePolicy, BridgeFilter, BridgeProjectionCursor,
    BridgeProjectionQuery, ChunkRange, ControlKind, ControlOutcome, CustodySample, EnvelopeId,
    EventGap, LocalBatchCommit, LocalBatchItemCommit, PeerSnapshot, ProviderOpenedBridgeProjection,
    QuotaUsage, RecordStore, Revocation, ScopeEpoch, ScopeQuota, SqliteStore, StoreConfig,
    StoreError, StoreQuery, StoredBridgeProjection, StoredItem, SubscriptionCursor, SubscriptionId,
    SubscriptionSpec, TransferProgress, VerifiedStoredControl, VersionStatus,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// Authenticated routing and causality metadata protected inside an envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeHeader {
    pub class: DataClass,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub stamp: CausalStamp,
    pub event_sequence: Option<u64>,
    pub logical_key: Vec<u8>,
    pub blob_route: Option<BlobRouteCommitment>,
    pub ttl_ms: Option<u64>,
    pub content_len: u64,
    pub tombstone: bool,
    pub key_epoch: u64,
}

/// Input to source sealing. Routing fields must be protected by the provider's
/// mesh-membership layer and payload bytes by the scope end-to-end layer.
pub struct SealRequest<'a> {
    pub header: &'a EnvelopeHeader,
    pub payload: &'a [u8],
}

/// Provider output ready for durable storage and opaque transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedEnvelope {
    pub id: ItemId,
    pub bytes: Vec<u8>,
}

/// An envelope whose source authentication, membership metadata, algorithms,
/// downgrade protection, and freshness syntax have been checked by the provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedEnvelope {
    pub id: ItemId,
    pub header: EnvelopeHeader,
}

/// Authenticated mesh control object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedControl {
    Revocation(Revocation),
    ScopeEpoch(ScopeEpoch),
}

/// Authenticated result of inspecting either stable envelope kind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedObject {
    Data(VerifiedEnvelope),
    Control(VerifiedControl),
}

/// Cryptographic integration error without exposing primitives in the node API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeError(pub String);

impl Display for EnvelopeError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for EnvelopeError {}

/// Narrow integration boundary implemented by the selected vetted crypto stack.
pub trait EnvelopeSealer {
    fn seal(&mut self, request: SealRequest<'_>) -> Result<SealedEnvelope, EnvelopeError>;
    fn inspect(&mut self, sealed: &[u8]) -> Result<VerifiedEnvelope, EnvelopeError>;
    fn open_payload(
        &mut self,
        envelope: &VerifiedEnvelope,
        sealed: &[u8],
    ) -> Result<Vec<u8>, EnvelopeError>;
    /// Reauthenticates one exact compact batch representation through its exact
    /// proof and opens its payload. Providers without semantic-v2 batch support
    /// fail closed through the default implementation.
    fn open_compact_batch_payload_with_proof(
        &mut self,
        _compact: &[u8],
        _proof: &[u8],
    ) -> Result<(VerifiedEnvelope, Vec<u8>), EnvelopeError> {
        Err(EnvelopeError(
            "compact batch authentication is unsupported by this provider".into(),
        ))
    }
    /// Opens content when this node is authorized. `None` is reserved for a valid,
    /// source-authenticated route whose topic content key is not granted locally.
    fn open_payload_if_authorized(
        &mut self,
        envelope: &VerifiedEnvelope,
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>, EnvelopeError> {
        self.open_payload(envelope, sealed).map(Some)
    }
    fn inspect_control(&mut self, sealed: &[u8]) -> Result<VerifiedControl, EnvelopeError>;
    /// Applies provider-owned key state only after the corresponding control is durably active.
    fn activate_control(
        &mut self,
        _sealed: &[u8],
        _local_revoked: bool,
    ) -> Result<(), EnvelopeError> {
        Ok(())
    }
    /// Inspects either a data or control envelope without exposing format tags to callers.
    fn inspect_object(&mut self, sealed: &[u8]) -> Result<VerifiedObject, EnvelopeError> {
        match self.inspect(sealed) {
            Ok(data) => Ok(VerifiedObject::Data(data)),
            Err(data_error) => self
                .inspect_control(sealed)
                .map(VerifiedObject::Control)
                .map_err(|_| data_error),
        }
    }
    /// Creates recipient- and exchange-bound protected custody metadata.
    fn seal_forwarding(
        &mut self,
        _recipient: NodeId,
        _exchange_id: u64,
        _envelope_id: EnvelopeId,
        _custody_age_ms: u64,
    ) -> Result<Vec<u8>, EnvelopeError> {
        Err(EnvelopeError(
            "forwarding metadata is unsupported by this provider".into(),
        ))
    }
    /// Authenticates protected custody metadata against the live adjacency.
    fn inspect_forwarding(
        &mut self,
        _authenticated_sender: NodeId,
        _recipient: NodeId,
        _exchange_id: u64,
        _envelope_id: EnvelopeId,
        _forwarding: &[u8],
    ) -> Result<u64, EnvelopeError> {
        Err(EnvelopeError(
            "forwarding metadata is unsupported by this provider".into(),
        ))
    }
    /// Tests an authority-signed opaque route-grant commitment from a peer credential.
    fn peer_can_route(
        &self,
        _peer: NodeId,
        _peer_route_commitments: &[[u8; 32]],
        _scope: &Scope,
        _epoch: u64,
    ) -> bool {
        false
    }
    /// Identity of the mission control authority, only for an authority-capable provider.
    fn control_authority(&self) -> Option<NodeId> {
        None
    }
    fn seal_revocation_control(
        &mut self,
        _subject: NodeId,
        _generation: u64,
        _sequence: u64,
        _previous: Option<EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        Err(EnvelopeError(
            "control publication is unsupported by this provider".into(),
        ))
    }
    fn seal_scope_epoch_control(
        &mut self,
        _scope: &Scope,
        _epoch: u64,
        _sequence: u64,
        _previous: Option<EnvelopeId>,
    ) -> Result<Vec<u8>, EnvelopeError> {
        Err(EnvelopeError(
            "control publication is unsupported by this provider".into(),
        ))
    }
    /// Rapidly and irreversibly erases provider-owned local key material.
    fn zeroize(&mut self) -> Result<(), EnvelopeError>;
}

/// Optional time source. `None` retains finite-TTL data but makes it
/// non-forwardable until trustworthy time becomes available.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> Option<u64>;
    /// Elapsed-time observation with a continuity identifier. A changed token or
    /// regressing tick means elapsed custody cannot safely be reconstructed.
    fn custody_sample(&self) -> Option<CustodySample>;
}

/// Default advisory local time source. It never participates in causality.
#[derive(Clone, Debug)]
pub struct SystemClock {
    started: Instant,
    clock_id: [u8; 16],
}

impl Default for SystemClock {
    fn default() -> Self {
        static NEXT_CLOCK: AtomicU64 = AtomicU64::new(1);
        let nonce = NEXT_CLOCK.fetch_add(1, Ordering::Relaxed);
        let mut material = Vec::new();
        material.extend_from_slice(&std::process::id().to_be_bytes());
        material.extend_from_slice(&nonce.to_be_bytes());
        if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
            material.extend_from_slice(&duration.as_nanos().to_be_bytes());
        }
        let digest = Sha256::digest(&material);
        let mut clock_id = [0u8; 16];
        clock_id.copy_from_slice(&digest[..16]);
        Self {
            started: Instant::now(),
            clock_id,
        }
    }
}

impl Clock for SystemClock {
    fn now_ms(&self) -> Option<u64> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
    }

    fn custody_sample(&self) -> Option<CustodySample> {
        Some(CustodySample {
            clock_id: self.clock_id,
            tick_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

/// Clock for deployments that cannot make even advisory elapsed-time judgments.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableClock;

impl Clock for UnavailableClock {
    fn now_ms(&self) -> Option<u64> {
        None
    }

    fn custody_sample(&self) -> Option<CustodySample> {
        None
    }
}

/// Outbound RF/emission policy. `None` is receive-only/radio-silent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmissionPolicy {
    pub minimum_priority: Option<Priority>,
}

impl Default for EmissionPolicy {
    fn default() -> Self {
        Self {
            minimum_priority: Some(Priority::Routine),
        }
    }
}

impl EmissionPolicy {
    pub const fn receive_only() -> Self {
        Self {
            minimum_priority: None,
        }
    }

    pub fn allows(self, priority: Priority) -> bool {
        self.minimum_priority
            .is_some_and(|minimum| priority >= minimum)
    }

    /// Discovery is suppressed for both constrained and silent operation.
    pub fn allows_discovery(self) -> bool {
        self.minimum_priority == Some(Priority::Routine)
    }
}

/// Node configuration independent from transport and crypto internals.
#[derive(Clone)]
pub struct NodeConfig {
    pub store: StoreConfig,
    pub emission: EmissionPolicy,
    /// Integrator policy may cap publisher-assigned precedence.
    pub priority_cap: Priority,
    pub publish_retry_limit: usize,
    pub clock: Arc<dyn Clock>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            store: StoreConfig::default(),
            emission: EmissionPolicy::default(),
            priority_cap: Priority::Flash,
            publish_retry_limit: 4,
            clock: Arc::new(SystemClock::default()),
        }
    }
}

/// Offline publish operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishRequest {
    pub class: DataClass,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub ttl_ms: Option<u64>,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
}

/// Successful local commit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishReceipt {
    pub id: ItemId,
    pub stamp: CausalStamp,
    pub event_sequence: Option<u64>,
    pub effective_priority: Priority,
    pub evicted: Vec<ItemId>,
}

/// One high-level item prepared for the concrete batch publisher. Blob route
/// commitments are carried internally and never exposed by the batch facade.
pub(crate) struct BatchPublishItem {
    pub(crate) request: PublishRequest,
    pub(crate) blob_route: Option<BlobRouteCommitment>,
}

/// Successful atomic batch commit. Eviction is reported once for the entire
/// transaction rather than attributed to an arbitrary item.
pub(crate) struct BatchPublishReceipt {
    pub(crate) items: Vec<PublishReceipt>,
    pub(crate) evicted: Vec<ItemId>,
}

/// Application-visible decrypted item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationItem {
    pub id: ItemId,
    pub class: DataClass,
    pub topic: Topic,
    /// Compatibility/current projection scope. For an ordinary item this is
    /// identical to `origin_scope`; for a bridged item it is the authorized
    /// target scope.
    pub scope: Scope,
    /// Immutable source-authenticated scope.
    pub origin_scope: Scope,
    /// Scope through which this application projection was selected.
    pub current_scope: Scope,
    pub priority: Priority,
    pub publisher: NodeId,
    pub stamp: CausalStamp,
    pub event_sequence: Option<u64>,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
}

/// Durable at-least-once delivery with decrypted application data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivery {
    pub subscription: SubscriptionId,
    pub attempt: u64,
    pub item: ApplicationItem,
}

/// Opaque authenticated object selected for a peer under emission policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Emission {
    pub id: ItemId,
    pub priority: Priority,
    pub sealed: Vec<u8>,
}

/// Result of authenticated inbound application.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IngestReceipt {
    pub outcome: ApplyOutcome,
    /// Deterministic automatic record merge, when a registered policy applied.
    pub merged: Option<ItemId>,
}

/// Result of applying a stable object received through authenticated sync.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ForwardedIngest {
    Data(IngestReceipt),
    Control(ControlOutcome),
}

/// One locally published, durably chained control object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlPublishReceipt {
    pub envelope_id: crate::wire::EnvelopeId,
    pub sequence: u64,
    pub outcome: ControlOutcome,
}

/// Stable transfer metadata returned without exposing source-sealed contents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopeDescriptor {
    pub envelope_id: crate::wire::EnvelopeId,
    pub total_len: u64,
    pub priority: Priority,
    pub control: bool,
}

/// Explicit record conflict resolution guarded by the observed sibling set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolveRequest {
    pub topic: Topic,
    pub scope: Scope,
    pub logical_key: Vec<u8>,
    pub expected_siblings: Vec<ItemId>,
    pub payload: Vec<u8>,
    pub priority: Priority,
    pub ttl_ms: Option<u64>,
}

/// Version input to an application-provided deterministic record merge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordVersion {
    pub id: ItemId,
    pub publisher: NodeId,
    pub stamp: CausalStamp,
    pub payload: Vec<u8>,
    pub tombstone: bool,
}

/// Integrator merge policy. Implementations must produce identical bytes for the
/// canonical, item-ID-sorted input on every conformant node.
pub trait RecordMergePolicy: Send + Sync {
    fn id(&self) -> &str;
    fn merge(&self, versions: &[RecordVersion]) -> Result<Vec<u8>, String>;
}

/// High-level node failure.
#[derive(Debug)]
pub enum EngineError {
    Store(StoreError),
    Envelope(EnvelopeError),
    Invalid(String),
    StaleConflict,
    Revoked(NodeId),
    StaleKeyEpoch { current: u64, received: u64 },
    Expired,
    Unauthorized(NodeId),
    Merge(String),
}

impl Display for EngineError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => Display::fmt(error, formatter),
            Self::Envelope(error) => Display::fmt(error, formatter),
            Self::Invalid(message) => write!(formatter, "invalid engine input: {message}"),
            Self::StaleConflict => formatter.write_str("record conflict changed before resolution"),
            Self::Revoked(_) => formatter.write_str("publisher is revoked"),
            Self::StaleKeyEpoch { current, received } => write!(
                formatter,
                "envelope key epoch {received} is older than current epoch {current}"
            ),
            Self::Expired => formatter.write_str("envelope custody age exceeds its TTL"),
            Self::Unauthorized(_) => formatter.write_str("peer is not authorized for envelope"),
            Self::Merge(message) => write!(formatter, "record merge failed: {message}"),
        }
    }
}

impl Error for EngineError {}

impl From<StoreError> for EngineError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<EnvelopeError> for EngineError {
    fn from(value: EnvelopeError) -> Self {
        Self::Envelope(value)
    }
}

/// Offline-first node. Synchronous methods are deliberate for simple C FFI and
/// embedding; callers drive it from their own event loop without busy polling.
pub struct Node<S, E> {
    identity: NodeId,
    store: S,
    envelopes: E,
    emission: EmissionPolicy,
    priority_cap: Priority,
    publish_retry_limit: usize,
    clock: Arc<dyn Clock>,
    merge_policies: BTreeMap<String, Arc<dyn RecordMergePolicy>>,
}

impl<E: EnvelopeSealer> Node<SqliteStore, E> {
    pub fn open(
        path: impl AsRef<Path>,
        identity: NodeId,
        envelopes: E,
        config: NodeConfig,
    ) -> Result<Self, EngineError> {
        let store = SqliteStore::open(path, config.store.clone())?;
        let mut node = Self::with_store(identity, store, envelopes, config);
        node.replay_active_controls()?;
        Ok(node)
    }
}

impl<S: RecordStore, E: EnvelopeSealer> Node<S, E> {
    pub fn with_store(identity: NodeId, store: S, envelopes: E, config: NodeConfig) -> Self {
        Self {
            identity,
            store,
            envelopes,
            emission: config.emission,
            priority_cap: config.priority_cap,
            publish_retry_limit: config.publish_retry_limit.max(1),
            clock: config.clock,
            merge_policies: BTreeMap::new(),
        }
    }

    pub fn identity(&self) -> NodeId {
        self.identity
    }

    pub(crate) fn store(&self) -> &S {
        &self.store
    }

    pub(crate) fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    pub(crate) fn envelopes(&self) -> &E {
        &self.envelopes
    }

    pub(crate) fn envelopes_mut(&mut self) -> &mut E {
        &mut self.envelopes
    }

    pub(crate) fn now_ms(&self) -> Option<u64> {
        self.clock.now_ms()
    }

    pub(crate) fn custody_sample(&self) -> Option<CustodySample> {
        self.clock.custody_sample()
    }

    pub(crate) fn authorize_peer(&mut self, peer: NodeId) -> Result<(), EngineError> {
        if self.store.is_zeroized()? {
            return Err(StoreError::Zeroized.into());
        }
        if self.store.is_revoked(&peer)? {
            return Err(EngineError::Revoked(peer));
        }
        Ok(())
    }

    pub fn register_merge_policy(&mut self, topic: Topic, policy: Arc<dyn RecordMergePolicy>) {
        self.merge_policies
            .insert(topic.as_str().to_owned(), policy);
    }

    pub fn publish(&mut self, request: PublishRequest) -> Result<PublishReceipt, EngineError> {
        self.publish_with_context(request, None, None)
    }

    /// Publishes a finalized Blob manifest with its source-authenticated protected route
    /// commitment. The application-facing Blob service supplies this after finalization.
    pub fn publish_blob_manifest(
        &mut self,
        request: PublishRequest,
        route: BlobRouteCommitment,
    ) -> Result<PublishReceipt, EngineError> {
        if request.class != DataClass::Blob {
            return Err(EngineError::Invalid(
                "Blob route commitment requires Blob data class".into(),
            ));
        }
        self.publish_with_context(request, None, Some(route))
    }

    /// Finds an already published Blob manifest only when its source-authenticated
    /// route commitment and plaintext manifest both exactly match finalization.
    /// This is the idempotency/read gate shared by high-level bindings.
    pub fn find_authenticated_blob_manifest(
        &mut self,
        topic: &Topic,
        scope: &Scope,
        id: BlobId,
        manifest_bytes: &[u8],
        route: BlobRouteCommitment,
    ) -> Result<Option<PublishReceipt>, EngineError> {
        if route.blob_id() != id {
            return Err(EngineError::Invalid(
                "Blob route commitment identifier mismatch".into(),
            ));
        }
        let existing = self.store.query(&StoreQuery {
            topic: Some(topic.clone()),
            scope: Some(scope.clone()),
            include_descendant_scopes: false,
            class: Some(DataClass::Blob),
            logical_key: Some(id.as_bytes().to_vec()),
            include_recoverable_versions: true,
            include_tombstones: false,
            now_ms: self.clock.now_ms(),
            custody_sample: self.clock.custody_sample(),
            limit: Some(2),
        })?;
        if existing.is_empty() {
            return Ok(None);
        }
        if existing.len() != 1 {
            return Err(EngineError::Invalid(
                "Blob identifier names multiple manifest items".into(),
            ));
        }
        let item = &existing[0];
        let (verified, payload) = self.open_authenticated_stored_item(item)?;
        if verified.header.blob_route != Some(route) {
            return Err(EngineError::Invalid(
                "Blob manifest route commitment mismatch".into(),
            ));
        }
        if payload != manifest_bytes {
            return Err(EngineError::Invalid(
                "Blob identifier conflicts with authenticated manifest bytes".into(),
            ));
        }
        Ok(Some(PublishReceipt {
            id: item.id,
            stamp: item.stamp.clone(),
            event_sequence: item.event_sequence,
            effective_priority: item.priority,
            evicted: Vec::new(),
        }))
    }

    fn publish_with_context(
        &mut self,
        request: PublishRequest,
        additional_context: Option<&VersionVector>,
        blob_route: Option<BlobRouteCommitment>,
    ) -> Result<PublishReceipt, EngineError> {
        if self.store.is_zeroized()? {
            return Err(StoreError::Zeroized.into());
        }
        if request.tombstone && request.class == DataClass::Blob {
            return Err(EngineError::Invalid(
                "immutable Blob cannot be a tombstone".into(),
            ));
        }
        if request.tombstone && !request.payload.is_empty() {
            return Err(EngineError::Invalid(
                "tombstone payload must be empty".into(),
            ));
        }
        let effective_priority = request.priority.min(self.priority_cap);
        for _ in 0..self.publish_retry_limit {
            let reservation = self.store.reserve_publish(
                self.identity,
                request.class,
                &request.topic,
                &request.scope,
            )?;
            let mut context = reservation.context.clone();
            if let Some(additional) = additional_context {
                context.join(additional);
            }
            let epoch = self.store.scope_epoch(&request.scope)?;
            let header = EnvelopeHeader {
                class: request.class,
                topic: request.topic.clone(),
                scope: request.scope.clone(),
                priority: effective_priority,
                stamp: CausalStamp {
                    dot: crate::model::Dot {
                        publisher: self.identity,
                        counter: reservation.counter,
                    },
                    context,
                },
                event_sequence: reservation.event_sequence,
                logical_key: request.logical_key.clone(),
                blob_route,
                ttl_ms: request.ttl_ms,
                content_len: request.payload.len() as u64,
                tombstone: request.tombstone,
                key_epoch: epoch,
            };
            let sealed = self.envelopes.seal(SealRequest {
                header: &header,
                payload: &request.payload,
            })?;
            if sealed.bytes.is_empty() {
                return Err(EngineError::Invalid(
                    "sealer returned an empty envelope".into(),
                ));
            }
            let item = stored_from_verified(
                VerifiedEnvelope {
                    id: sealed.id,
                    header: header.clone(),
                },
                sealed.bytes,
                self.clock.now_ms(),
                0,
                self.clock.custody_sample(),
            );
            match self.store.commit_publish(&reservation, item) {
                Ok(ApplyOutcome::Inserted { evicted, .. }) => {
                    return Ok(PublishReceipt {
                        id: sealed.id,
                        stamp: header.stamp,
                        event_sequence: header.event_sequence,
                        effective_priority,
                        evicted,
                    });
                }
                Ok(ApplyOutcome::Duplicate { .. }) => {
                    return Err(EngineError::Invalid(
                        "new publisher reservation produced a duplicate item id".into(),
                    ));
                }
                Err(StoreError::CounterChanged) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(StoreError::CounterChanged.into())
    }

    pub fn ingest(&mut self, sealed: &[u8]) -> Result<IngestReceipt, EngineError> {
        if self.store.is_zeroized()? {
            return Err(StoreError::Zeroized.into());
        }
        let verified = self.envelopes.inspect(sealed)?;
        if self
            .store
            .is_revoked(&verified.header.stamp.dot.publisher)?
        {
            return Err(EngineError::Revoked(verified.header.stamp.dot.publisher));
        }
        let current_epoch = self.store.scope_epoch(&verified.header.scope)?;
        if verified.header.key_epoch < current_epoch {
            return Err(EngineError::StaleKeyEpoch {
                current: current_epoch,
                received: verified.header.key_epoch,
            });
        }
        let topic = verified.header.topic.clone();
        let scope = verified.header.scope.clone();
        let priority = verified.header.priority;
        let ttl_ms = verified.header.ttl_ms;
        let logical_key = verified.header.logical_key.clone();
        let item = stored_from_verified(
            verified,
            sealed.to_vec(),
            self.clock.now_ms(),
            0,
            self.clock.custody_sample(),
        );
        let outcome = self.store.ingest(item)?;
        let conflict = match &outcome {
            ApplyOutcome::Inserted { conflict, .. } => conflict.clone(),
            ApplyOutcome::Duplicate { .. } => None,
        };
        let merged = if let Some(conflict) = conflict {
            self.auto_merge(&topic, &scope, priority, ttl_ms, &logical_key, &conflict)?
        } else {
            None
        };
        Ok(IngestReceipt { outcome, merged })
    }

    pub fn ingest_control(&mut self, sealed: &[u8]) -> Result<ControlOutcome, EngineError> {
        if self.store.is_zeroized()? {
            return Err(StoreError::Zeroized.into());
        }
        let verified = self.envelopes.inspect_control(sealed)?;
        let stored = verified_stored_control(verified, sealed, self.clock.now_ms())?;
        let outcome = self.store.ingest_control(&stored)?;
        self.activate_control_outcome(&outcome)?;
        Ok(outcome)
    }

    /// Publishes a revocation as the next crash-atomic authority-chain link.
    pub fn publish_revocation(
        &mut self,
        subject: NodeId,
        generation: u64,
    ) -> Result<ControlPublishReceipt, EngineError> {
        let authority = self
            .envelopes
            .control_authority()
            .ok_or_else(|| EngineError::Invalid("node is not a control authority".into()))?;
        for _ in 0..self.publish_retry_limit {
            let reservation = self.store.reserve_control(authority)?;
            let sealed = self.envelopes.seal_revocation_control(
                subject,
                generation,
                reservation.sequence,
                reservation.previous_control,
            )?;
            let verified = self.envelopes.inspect_control(&sealed)?;
            let stored = verified_stored_control(verified, &sealed, self.clock.now_ms())?;
            match self.store.commit_local_control(&reservation, &stored) {
                Ok(outcome) => {
                    self.activate_control_outcome(&outcome)?;
                    return Ok(ControlPublishReceipt {
                        envelope_id: stored.envelope_id.into(),
                        sequence: stored.sequence,
                        outcome,
                    });
                }
                Err(StoreError::CounterChanged) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(StoreError::CounterChanged.into())
    }

    /// Publishes a scope-epoch activation as the next authority-chain link.
    pub fn publish_scope_epoch(
        &mut self,
        scope: &Scope,
        epoch: u64,
    ) -> Result<ControlPublishReceipt, EngineError> {
        let authority = self
            .envelopes
            .control_authority()
            .ok_or_else(|| EngineError::Invalid("node is not a control authority".into()))?;
        for _ in 0..self.publish_retry_limit {
            let reservation = self.store.reserve_control(authority)?;
            let sealed = self.envelopes.seal_scope_epoch_control(
                scope,
                epoch,
                reservation.sequence,
                reservation.previous_control,
            )?;
            let verified = self.envelopes.inspect_control(&sealed)?;
            let stored = verified_stored_control(verified, &sealed, self.clock.now_ms())?;
            match self.store.commit_local_control(&reservation, &stored) {
                Ok(outcome) => {
                    self.activate_control_outcome(&outcome)?;
                    return Ok(ControlPublishReceipt {
                        envelope_id: stored.envelope_id.into(),
                        sequence: stored.sequence,
                        outcome,
                    });
                }
                Err(StoreError::CounterChanged) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(StoreError::CounterChanged.into())
    }

    pub fn query(&mut self, mut query: StoreQuery) -> Result<Vec<ApplicationItem>, EngineError> {
        query.now_ms = self.clock.now_ms();
        query.custody_sample = self.clock.custody_sample();
        let items = self.store.query(&query)?;
        items
            .into_iter()
            .map(|item| self.open_application_item(item))
            .collect()
    }

    pub fn subscribe(&mut self, spec: SubscriptionSpec) -> Result<SubscriptionId, EngineError> {
        Ok(self.store.create_subscription(&spec)?)
    }

    pub fn poll(
        &mut self,
        subscription: SubscriptionId,
        limit: usize,
    ) -> Result<Vec<Delivery>, EngineError> {
        let now = self.clock.now_ms();
        let custody = self.clock.custody_sample();
        self.store.collect_garbage(now, custody)?;
        let deliveries = self
            .store
            .poll_subscription(subscription, limit, now, custody)?;
        deliveries
            .into_iter()
            .map(|delivery| self.open_delivery(delivery))
            .collect()
    }

    pub fn acknowledge(
        &mut self,
        subscription: SubscriptionId,
        item: ItemId,
    ) -> Result<(), EngineError> {
        Ok(self
            .store
            .acknowledge_delivery(subscription, &item, self.clock.now_ms())?)
    }

    pub fn conflicts(&mut self, query: StoreQuery) -> Result<Vec<ConflictAnnotation>, EngineError> {
        Ok(self.store.conflicts(&query)?)
    }

    pub fn resolve(&mut self, mut request: ResolveRequest) -> Result<PublishReceipt, EngineError> {
        request.expected_siblings.sort();
        request.expected_siblings.dedup();
        let query = StoreQuery {
            topic: Some(request.topic.clone()),
            scope: Some(request.scope.clone()),
            class: Some(DataClass::Record),
            logical_key: Some(request.logical_key.clone()),
            ..StoreQuery::default()
        };
        let conflicts = self.store.conflicts(&query)?;
        let Some(conflict) = conflicts.into_iter().next() else {
            return Err(EngineError::StaleConflict);
        };
        if conflict.siblings != request.expected_siblings {
            return Err(EngineError::StaleConflict);
        }
        let context = self.context_for_siblings(&conflict.siblings)?;
        self.publish_with_context(
            PublishRequest {
                class: DataClass::Record,
                topic: request.topic,
                scope: request.scope,
                priority: request.priority,
                ttl_ms: request.ttl_ms,
                logical_key: request.logical_key,
                payload: request.payload,
                tombstone: false,
            },
            Some(&context),
            None,
        )
    }

    fn context_for_siblings(&mut self, siblings: &[ItemId]) -> Result<VersionVector, EngineError> {
        let mut context = VersionVector::default();
        for id in siblings {
            let item = self.store.get(id)?.ok_or(EngineError::StaleConflict)?;
            context.join(&item.stamp.clock());
        }
        Ok(context)
    }

    fn auto_merge(
        &mut self,
        topic: &Topic,
        scope: &Scope,
        priority: Priority,
        ttl_ms: Option<u64>,
        logical_key: &[u8],
        conflict: &ConflictAnnotation,
    ) -> Result<Option<ItemId>, EngineError> {
        let Some(policy) = self.merge_policies.get(topic.as_str()).cloned() else {
            return Ok(None);
        };
        let mut versions = Vec::new();
        for id in &conflict.siblings {
            let item = self.store.get(id)?.ok_or(EngineError::StaleConflict)?;
            let application = self.open_application_item(item)?;
            versions.push(RecordVersion {
                id: application.id,
                publisher: application.publisher,
                stamp: application.stamp,
                payload: application.payload,
                tombstone: application.tombstone,
            });
        }
        versions.sort_by_key(|version| version.id);
        let merged = policy.merge(&versions).map_err(EngineError::Merge)?;
        // Detect an immediately nondeterministic policy before committing a value
        // that could make peers diverge. Cross-implementation determinism remains
        // an integrator/conformance obligation.
        let repeated = policy.merge(&versions).map_err(EngineError::Merge)?;
        if merged != repeated {
            return Err(EngineError::Merge(format!(
                "policy {} returned different bytes for identical input",
                policy.id()
            )));
        }
        let receipt = self.resolve(ResolveRequest {
            topic: topic.clone(),
            scope: scope.clone(),
            logical_key: logical_key.to_vec(),
            expected_siblings: conflict.siblings.clone(),
            payload: merged,
            priority,
            ttl_ms,
        })?;
        Ok(Some(receipt.id))
    }

    fn open_delivery(&mut self, delivery: AppDelivery) -> Result<Delivery, EngineError> {
        Ok(Delivery {
            subscription: delivery.subscription,
            attempt: delivery.delivery_attempt,
            item: self.open_application_item(delivery.item)?,
        })
    }

    /// Opens either a canonical singleton or a canonical compact batch item.
    /// Compact reads authenticate the exact durable proof and compact bytes on
    /// every call; durable indexes and a previously verified process flag are
    /// never treated as payload authority.
    fn open_authenticated_stored_item(
        &mut self,
        item: &StoredItem,
    ) -> Result<(VerifiedEnvelope, Vec<u8>), EngineError> {
        let opened = match self.envelopes.inspect(&item.sealed) {
            Ok(verified) => {
                let payload = if item.tombstone {
                    Vec::new()
                } else {
                    self.envelopes.open_payload(&verified, &item.sealed)?
                };
                (verified, payload)
            }
            Err(singleton_error) => {
                let Some(material) = self.store.stored_batch_material(&item.id)? else {
                    return Err(singleton_error.into());
                };
                let proof_envelope_id: EnvelopeId =
                    Sha256::digest(&material.proof.exact_bytes).into();
                if material.item_id != item.id
                    || material.compact_envelope_id != item.envelope_id
                    || material.compact_bytes != item.sealed
                    || material.proof.proof_envelope_id != proof_envelope_id
                {
                    return Err(EngineError::Invalid(
                        "compact batch provenance does not match durable authenticated index"
                            .into(),
                    ));
                }
                self.envelopes.open_compact_batch_payload_with_proof(
                    &material.compact_bytes,
                    &material.proof.exact_bytes,
                )?
            }
        };
        if opened.0.id != item.id || !header_matches_item(&opened.0.header, item) {
            return Err(EngineError::Invalid(
                "sealed item does not match durable authenticated index".into(),
            ));
        }
        if item.tombstone && !opened.1.is_empty() {
            return Err(EngineError::Invalid(
                "authenticated tombstone unexpectedly contains payload bytes".into(),
            ));
        }
        Ok(opened)
    }

    fn open_application_item(&mut self, item: StoredItem) -> Result<ApplicationItem, EngineError> {
        let (_, payload) = self.open_authenticated_stored_item(&item)?;
        let publisher = item.publisher();
        Ok(ApplicationItem {
            id: item.id,
            class: item.class,
            topic: item.topic,
            scope: item.scope.clone(),
            origin_scope: item.scope.clone(),
            current_scope: item.scope,
            priority: item.priority,
            publisher,
            stamp: item.stamp,
            event_sequence: item.event_sequence,
            logical_key: item.logical_key,
            payload,
            tombstone: item.tombstone,
        })
    }

    pub fn event_gaps(&mut self, mut query: StoreQuery) -> Result<Vec<EventGap>, EngineError> {
        query.now_ms = self.clock.now_ms();
        query.custody_sample = self.clock.custody_sample();
        Ok(self.store.event_gaps(&query)?)
    }

    pub fn set_emission_policy(&mut self, policy: EmissionPolicy) {
        self.emission = policy;
    }

    pub fn emission_policy(&self) -> EmissionPolicy {
        self.emission
    }

    pub fn may_advertise(&self) -> bool {
        self.emission.allows_discovery()
    }

    pub fn next_emissions(
        &mut self,
        peer: NodeId,
        limit: usize,
        byte_budget: u64,
    ) -> Result<Vec<Emission>, EngineError> {
        let Some(minimum) = self.emission.minimum_priority else {
            return Ok(Vec::new());
        };
        let now = self.clock.now_ms();
        let custody = self.clock.custody_sample();
        self.store.collect_garbage(now, custody)?;
        Ok(self
            .store
            .next_outbound(peer, minimum, limit, byte_budget, now, custody)?
            .into_iter()
            .filter(|item| self.emission.allows(item.priority))
            .map(|item| Emission {
                id: item.id,
                priority: item.priority,
                sealed: item.sealed,
            })
            .collect())
    }

    pub fn acknowledge_peer(&mut self, peer: NodeId, ids: &[ItemId]) -> Result<(), EngineError> {
        Ok(self
            .store
            .acknowledge_peer(peer, ids, self.clock.now_ms())?)
    }

    pub fn update_peer_status(
        &mut self,
        node: NodeId,
        peer: PeerStatus,
        sync: SyncStatus,
        detail: Option<String>,
    ) -> Result<(), EngineError> {
        if self.store.is_revoked(&node)? && peer != PeerStatus::Revoked {
            return Err(EngineError::Revoked(node));
        }
        Ok(self.store.update_peer(&PeerSnapshot {
            node,
            peer,
            sync,
            last_change_ms: self.clock.now_ms(),
            detail,
        })?)
    }

    pub fn peer_status(&mut self, node: NodeId) -> Result<Option<PeerSnapshot>, EngineError> {
        Ok(self.store.peer(&node)?)
    }

    pub fn peers(&mut self) -> Result<Vec<PeerSnapshot>, EngineError> {
        Ok(self.store.peers()?)
    }

    pub fn set_bridge_filters(&mut self, filters: &[BridgeFilter]) -> Result<(), EngineError> {
        Ok(self.store.replace_bridge_filters(filters)?)
    }

    pub fn bridge_allows(
        &mut self,
        from: &Scope,
        to: &Scope,
        topic: &Topic,
        priority: Priority,
    ) -> Result<bool, EngineError> {
        Ok(self.store.bridge_allows(from, to, topic, priority)?)
    }

    pub fn set_scope_quota(&mut self, quota: ScopeQuota) -> Result<(), EngineError> {
        Ok(self.store.set_scope_quota(quota)?)
    }

    pub fn quota_usage(&mut self, scope: Option<&Scope>) -> Result<QuotaUsage, EngineError> {
        Ok(self.store.quota_usage(scope)?)
    }

    pub fn collect_garbage(&mut self) -> Result<Vec<ItemId>, EngineError> {
        Ok(self
            .store
            .collect_garbage(self.clock.now_ms(), self.clock.custody_sample())?)
    }

    pub fn begin_object(
        &mut self,
        object: ItemId,
        total_len: u64,
        priority: Priority,
    ) -> Result<(), EngineError> {
        Ok(self
            .store
            .begin_want(object, total_len, priority, self.clock.now_ms())?)
    }

    pub fn missing_object_ranges(
        &mut self,
        object: ItemId,
        limit: usize,
    ) -> Result<Vec<ChunkRange>, EngineError> {
        Ok(self.store.missing_ranges(&object, limit)?)
    }

    pub fn accept_object_chunk(
        &mut self,
        object: ItemId,
        total_len: u64,
        offset: u64,
        sealed: &[u8],
    ) -> Result<bool, EngineError> {
        Ok(self
            .store
            .put_sealed_chunk(object, total_len, offset, sealed, self.clock.now_ms())?)
    }

    pub fn read_object_range(
        &mut self,
        object: ItemId,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<Vec<u8>, EngineError> {
        Ok(self.store.read_sealed_range(&object, range, max_bytes)?)
    }

    /// Builds an exact filtered inventory. Scope strings only select candidates;
    /// serving additionally requires a matching authority-signed peer grant.
    pub fn authorized_envelopes(
        &mut self,
        peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        filter: &crate::sync::InterestFilter,
        purpose: crate::sync::InventoryPurpose,
    ) -> Result<Vec<EnvelopeDescriptor>, EngineError> {
        if self.store.is_zeroized()? || self.store.is_revoked(&peer)? {
            return Ok(Vec::new());
        }
        if purpose == crate::sync::InventoryPurpose::ServePeer
            && self.emission.minimum_priority.is_none()
        {
            return Ok(Vec::new());
        }
        let minimum = Priority::from_wire(filter.min_priority)
            .ok_or_else(|| EngineError::Invalid("interest priority is unknown".into()))?;
        let topics = filter
            .topics
            .iter()
            .map(|value| {
                Topic::new(value.clone()).map_err(|error| EngineError::Invalid(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let scopes = filter
            .scopes
            .iter()
            .map(|value| {
                Scope::new(value.clone()).map_err(|error| EngineError::Invalid(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let custody = self.clock.custody_sample();
        let mut selected = BTreeMap::new();
        for topic in &topics {
            for scope in &scopes {
                let items = self.store.query(&StoreQuery {
                    topic: Some(topic.clone()),
                    scope: Some(scope.clone()),
                    include_descendant_scopes: false,
                    include_recoverable_versions: true,
                    include_tombstones: true,
                    custody_sample: custody,
                    ..StoreQuery::default()
                })?;
                for item in items {
                    if item.priority < minimum
                        || !item.is_forwardable_at(custody)
                        || (purpose == crate::sync::InventoryPurpose::ServePeer
                            && !self.emission.allows(item.priority))
                    {
                        continue;
                    }
                    if purpose == crate::sync::InventoryPurpose::ServePeer
                        && !self.envelopes.peer_can_route(
                            peer,
                            peer_route_commitments,
                            &item.scope,
                            item.key_epoch,
                        )
                    {
                        continue;
                    }
                    let envelope_id = crate::wire::EnvelopeId::from(item.envelope_id);
                    selected.entry(envelope_id).or_insert(EnvelopeDescriptor {
                        envelope_id,
                        total_len: item.sealed.len() as u64,
                        priority: item.priority,
                        control: false,
                    });
                }
            }
        }
        // Controls are mission-wide and do not carry topic/scope routing metadata.
        // A revoked peer was rejected above; every remaining peer proved mission membership.
        for control in self.store.applied_controls()? {
            if purpose == crate::sync::InventoryPurpose::ServePeer
                && !self.emission.allows(Priority::Flash)
            {
                continue;
            }
            let envelope_id = crate::wire::EnvelopeId::from(control.envelope_id);
            selected.entry(envelope_id).or_insert(EnvelopeDescriptor {
                envelope_id,
                total_len: control.sealed.len() as u64,
                priority: Priority::Flash,
                control: true,
            });
        }
        Ok(selected.into_values().collect())
    }

    /// Re-authenticates one durably stored data envelope and returns its exact
    /// sealed bytes. This is the narrow source-binding seam used by Blob chunk
    /// routing; control objects and absent envelopes return `None`.
    pub(crate) fn inspect_stored_data_envelope(
        &mut self,
        envelope_id: crate::wire::EnvelopeId,
    ) -> Result<Option<(VerifiedEnvelope, Vec<u8>)>, EngineError> {
        let raw = envelope_id.into_bytes();
        let Some(item) = self.store.get_by_envelope(&raw)? else {
            return Ok(None);
        };
        if crate::wire::EnvelopeId::from_sealed_bytes(&item.sealed) != envelope_id {
            return Err(EngineError::Invalid(
                "stored source envelope identity mismatch".into(),
            ));
        }
        let verified = self.envelopes.inspect(&item.sealed)?;
        if verified.id != item.id || !header_matches_item(&verified.header, &item) {
            return Err(EngineError::Invalid(
                "stored source envelope index mismatch".into(),
            ));
        }
        Ok(Some((verified, item.sealed)))
    }

    /// Opens content only when the provider confirms a valid current or
    /// retained content grant. Route-only membership yields `None`; malformed
    /// or unauthenticated content remains an error.
    pub(crate) fn open_verified_payload_if_authorized(
        &mut self,
        verified: &VerifiedEnvelope,
        sealed: &[u8],
    ) -> Result<Option<Vec<u8>>, EngineError> {
        Ok(self
            .envelopes
            .open_payload_if_authorized(verified, sealed)?)
    }

    /// Reads one source-sealed range after repeating peer authorization at serve time.
    pub fn read_authorized_envelope_range(
        &mut self,
        peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        envelope_id: crate::wire::EnvelopeId,
        range: ChunkRange,
        max_bytes: usize,
    ) -> Result<(u64, Priority, Vec<u8>), EngineError> {
        if self.store.is_revoked(&peer)? {
            return Err(EngineError::Revoked(peer));
        }
        let raw = envelope_id.into_bytes();
        if let Some(item) = self.store.get_by_envelope(&raw)? {
            if !self.envelopes.peer_can_route(
                peer,
                peer_route_commitments,
                &item.scope,
                item.key_epoch,
            ) || !self.emission.allows(item.priority)
                || !item.is_forwardable_at(self.clock.custody_sample())
            {
                return Err(EngineError::Unauthorized(peer));
            }
            let total_len = item.sealed.len() as u64;
            let bytes = self
                .store
                .read_item_envelope_range(&raw, range, max_bytes)?;
            return Ok((total_len, item.priority, bytes));
        }
        let control = self
            .store
            .applied_controls()?
            .into_iter()
            .find(|control| control.envelope_id == raw)
            .ok_or(StoreError::NotFound("envelope"))?;
        if !self.emission.allows(Priority::Flash) {
            return Err(EngineError::Unauthorized(peer));
        }
        let total_len = control.sealed.len() as u64;
        let bytes = self
            .store
            .read_control_envelope_range(&raw, range, max_bytes)?;
        Ok((total_len, Priority::Flash, bytes))
    }

    /// Creates fresh authenticated forwarding metadata for an authorized object.
    pub fn forwarding_for_envelope(
        &mut self,
        peer: NodeId,
        peer_route_commitments: &[[u8; 32]],
        exchange_id: u64,
        envelope_id: crate::wire::EnvelopeId,
    ) -> Result<Vec<u8>, EngineError> {
        if self.store.is_revoked(&peer)? {
            return Err(EngineError::Revoked(peer));
        }
        let raw = envelope_id.into_bytes();
        let age = if let Some(item) = self.store.get_by_envelope(&raw)? {
            if !self.envelopes.peer_can_route(
                peer,
                peer_route_commitments,
                &item.scope,
                item.key_epoch,
            ) || !item.is_forwardable_at(self.clock.custody_sample())
            {
                return Err(EngineError::Unauthorized(peer));
            }
            effective_custody_age(&item, self.clock.custody_sample()).ok_or(EngineError::Expired)?
        } else if self
            .store
            .applied_controls()?
            .iter()
            .any(|control| control.envelope_id == raw)
        {
            if !self.emission.allows(Priority::Flash) {
                return Err(EngineError::Unauthorized(peer));
            }
            0
        } else {
            return Err(StoreError::NotFound("envelope").into());
        };
        Ok(self
            .envelopes
            .seal_forwarding(peer, exchange_id, raw, age)?)
    }

    pub fn store_envelope_chunk(
        &mut self,
        envelope_id: crate::wire::EnvelopeId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), EngineError> {
        self.store_transfer_chunk(
            crate::wire::ObjectId::for_envelope(envelope_id),
            total_len,
            offset,
            bytes,
        )
    }

    pub fn store_transfer_chunk(
        &mut self,
        object_id: crate::wire::ObjectId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), EngineError> {
        let raw = crate::store::transfer_storage_key(object_id);
        self.store
            .begin_transfer(object_id, total_len, Priority::Routine, self.clock.now_ms())?;
        self.store
            .put_sealed_chunk(raw, total_len, offset, bytes, self.clock.now_ms())?;
        Ok(())
    }

    /// Stages one authenticated-session chunk while durably binding the first
    /// negotiated semantic version to the typed transfer identity. Reopening
    /// the same transfer under a different version fails before bytes change.
    pub fn store_transfer_chunk_for_semantic_version(
        &mut self,
        object_id: crate::wire::ObjectId,
        total_len: u64,
        offset: u64,
        bytes: &[u8],
        semantic_version: u16,
    ) -> Result<(), EngineError> {
        let raw = crate::store::transfer_storage_key(object_id);
        self.store.begin_transfer_for_semantic_version(
            object_id,
            total_len,
            Priority::Routine,
            self.clock.now_ms(),
            semantic_version,
        )?;
        self.store
            .put_sealed_chunk(raw, total_len, offset, bytes, self.clock.now_ms())?;
        Ok(())
    }

    pub fn complete_envelope(
        &mut self,
        envelope_id: crate::wire::EnvelopeId,
        total_len: u64,
    ) -> Result<Vec<u8>, EngineError> {
        let object_id = crate::wire::ObjectId::for_envelope(envelope_id);
        let bytes = self.complete_transfer_object(object_id, total_len)?;
        if crate::wire::EnvelopeId::from_sealed_bytes(&bytes) != envelope_id {
            return Err(EngineError::Invalid(
                "completed envelope bytes do not match transfer identity".into(),
            ));
        }
        Ok(bytes)
    }

    pub fn complete_transfer_object(
        &mut self,
        object_id: crate::wire::ObjectId,
        total_len: u64,
    ) -> Result<Vec<u8>, EngineError> {
        let key = crate::store::transfer_storage_key(object_id);
        let bytes = self.store.read_sealed_range(
            &key,
            ChunkRange::new(0, total_len)?,
            usize::try_from(total_len)
                .map_err(|_| EngineError::Invalid("transfer object is too large".into()))?,
        )?;
        if bytes.len() as u64 != total_len {
            return Err(EngineError::Invalid(
                "completed object length does not match transfer identity".into(),
            ));
        }
        Ok(bytes)
    }

    pub fn durable_transfer_progress(
        &mut self,
        limit: usize,
    ) -> Result<Vec<TransferProgress>, EngineError> {
        Ok(self.store.transfer_progress(limit)?)
    }

    pub(crate) fn finish_transfer(
        &mut self,
        object_id: crate::wire::ObjectId,
    ) -> Result<(), EngineError> {
        Ok(self.store.finish_transfer(object_id)?)
    }

    /// Atomically removes only the named typed staging object after terminal
    /// identity or authentication failure. Committed records are untouched.
    pub(crate) fn abort_transfer(
        &mut self,
        object_id: crate::wire::ObjectId,
    ) -> Result<(), EngineError> {
        Ok(self.store.abort_transfer(object_id)?)
    }

    /// Authenticates hop metadata and applies either stable object kind.
    pub fn ingest_forwarded(
        &mut self,
        authenticated_sender: NodeId,
        exchange_id: u64,
        envelope_id: crate::wire::EnvelopeId,
        sealed: &[u8],
        forwarding: &[u8],
    ) -> Result<ForwardedIngest, EngineError> {
        if self.store.is_zeroized()? {
            return Err(StoreError::Zeroized.into());
        }
        if self.store.is_revoked(&authenticated_sender)? {
            return Err(EngineError::Revoked(authenticated_sender));
        }
        if crate::wire::EnvelopeId::from_sealed_bytes(sealed) != envelope_id {
            return Err(EngineError::Invalid(
                "forwarded envelope hash mismatch".into(),
            ));
        }
        let raw = envelope_id.into_bytes();
        let custody_age_ms = self.envelopes.inspect_forwarding(
            authenticated_sender,
            self.identity,
            exchange_id,
            raw,
            forwarding,
        )?;
        match self.envelopes.inspect_object(sealed)? {
            VerifiedObject::Control(verified) => {
                let stored = verified_stored_control(verified, sealed, self.clock.now_ms())?;
                let outcome = self.store.ingest_control(&stored)?;
                self.activate_control_outcome(&outcome)?;
                Ok(ForwardedIngest::Control(outcome))
            }
            VerifiedObject::Data(verified) => {
                if self
                    .store
                    .is_revoked(&verified.header.stamp.dot.publisher)?
                {
                    return Err(EngineError::Revoked(verified.header.stamp.dot.publisher));
                }
                let current_epoch = self.store.scope_epoch(&verified.header.scope)?;
                if verified.header.key_epoch < current_epoch {
                    return Err(EngineError::StaleKeyEpoch {
                        current: current_epoch,
                        received: verified.header.key_epoch,
                    });
                }
                if !verified.header.tombstone
                    && verified
                        .header
                        .ttl_ms
                        .is_some_and(|ttl| custody_age_ms >= ttl)
                {
                    return Err(EngineError::Expired);
                }
                let topic = verified.header.topic.clone();
                let scope = verified.header.scope.clone();
                let priority = verified.header.priority;
                let ttl_ms = verified.header.ttl_ms;
                let logical_key = verified.header.logical_key.clone();
                let item = stored_from_verified(
                    verified,
                    sealed.to_vec(),
                    self.clock.now_ms(),
                    custody_age_ms,
                    self.clock.custody_sample(),
                );
                let outcome = self.store.ingest(item)?;
                let conflict = match &outcome {
                    ApplyOutcome::Inserted { conflict, .. } => conflict.clone(),
                    ApplyOutcome::Duplicate { .. } => None,
                };
                let merged = if let Some(conflict) = conflict {
                    self.auto_merge(&topic, &scope, priority, ttl_ms, &logical_key, &conflict)?
                } else {
                    None
                };
                Ok(ForwardedIngest::Data(IngestReceipt { outcome, merged }))
            }
        }
    }

    fn activate_control_outcome(&mut self, outcome: &ControlOutcome) -> Result<(), EngineError> {
        let ControlOutcome::Applied { activated, .. } = outcome else {
            return Ok(());
        };
        let local_revoked = self.store.is_revoked(&self.identity)?;
        for control in activated {
            self.envelopes
                .activate_control(&control.sealed, local_revoked)?;
        }
        Ok(())
    }

    fn replay_active_controls(&mut self) -> Result<(), EngineError> {
        for persisted in self.store.applied_controls()? {
            let verified = self.envelopes.inspect_control(&persisted.sealed)?;
            let replay = verified_stored_control(verified, &persisted.sealed, None)?;
            if replay.envelope_id != persisted.envelope_id
                || replay.authority != persisted.authority
                || replay.sequence != persisted.sequence
                || replay.previous_control != persisted.previous_control
                || replay.kind != persisted.kind
            {
                return Err(EngineError::Invalid(
                    "persisted control does not match authenticated envelope".into(),
                ));
            }
            let _ = self.store.ingest_control(&replay)?;
            let local_revoked = self.store.is_revoked(&self.identity)?;
            self.envelopes
                .activate_control(&persisted.sealed, local_revoked)?;
        }
        Ok(())
    }

    pub fn zeroize(&mut self) -> Result<(), EngineError> {
        // Erase actual secrets first. Even if durable marking subsequently fails,
        // key material has already been destroyed.
        self.envelopes.zeroize()?;
        self.store.mark_zeroized()?;
        Ok(())
    }

    pub fn into_parts(self) -> (S, E) {
        (self.store, self.envelopes)
    }
}

impl<S: RecordStore> Node<S, crate::crypto::ReferenceEnvelopeSealer> {
    /// Verifies an opaque signed public recipient registry, constructs fresh
    /// recipient-filtered grants internally, and durably publishes the next
    /// chained scope control. No key material enters or leaves this method.
    pub fn publish_scope_rekey_from_registry(
        &mut self,
        signed_public_registry: &[u8],
        minimum_registry_generation: u64,
        scope: Scope,
        epoch: u64,
        recipients: Vec<crate::crypto::ScopeRekeyRecipient>,
    ) -> Result<(ControlPublishReceipt, u64), EngineError> {
        let (plan, registry_generation) = self.envelopes.plan_scope_rekey_from_registry(
            signed_public_registry,
            minimum_registry_generation,
            scope,
            epoch,
            recipients,
        )?;
        let receipt = self.publish_scope_rekey(&plan)?;
        Ok((receipt, registry_generation))
    }

    /// Publishes a fresh recipient-filtered scope epoch as the next durable authority link.
    pub fn publish_scope_rekey(
        &mut self,
        plan: &crate::crypto::ScopeRekeyPlan,
    ) -> Result<ControlPublishReceipt, EngineError> {
        let authority = self
            .envelopes
            .control_authority()
            .ok_or_else(|| EngineError::Invalid("node is not a control authority".into()))?;
        if plan.epoch() <= self.store.scope_epoch(plan.scope())? {
            return Err(EngineError::Invalid(
                "fresh scope rekey epoch must strictly increase".into(),
            ));
        }
        for recipient in plan.recipients() {
            if self.store.is_revoked(&recipient.node())? {
                return Err(EngineError::Revoked(recipient.node()));
            }
        }
        for _ in 0..self.publish_retry_limit {
            let reservation = self.store.reserve_control(authority)?;
            let sealed = self.envelopes.seal_scope_rekey_chained(
                plan,
                reservation.sequence,
                reservation.previous_control,
            )?;
            let verified = self.envelopes.inspect_control(&sealed)?;
            let stored = verified_stored_control(verified, &sealed, self.clock.now_ms())?;
            match self.store.commit_local_control(&reservation, &stored) {
                Ok(outcome) => {
                    self.activate_control_outcome(&outcome)?;
                    return Ok(ControlPublishReceipt {
                        envelope_id: stored.envelope_id.into(),
                        sequence: stored.sequence,
                        outcome,
                    });
                }
                Err(StoreError::CounterChanged) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(StoreError::CounterChanged.into())
    }

    /// Opens the service at the durably active scope epoch so callers cannot
    /// accidentally select a stale or not-yet-activated content grant.
    pub fn current_blob_service(
        &mut self,
        scope: &Scope,
        topic: &Topic,
        store_path: impl AsRef<Path>,
        config: crate::blob::BlobStoreConfig,
    ) -> Result<crate::blob::ReferenceBlobService, EngineError> {
        let epoch = self.store.scope_epoch(scope)?;
        self.blob_service(scope, topic, epoch, store_path, config)
    }

    /// Opens an owned Blob service through this node's authorized content grant.
    /// The generic envelope provider and grant seed are never exposed.
    pub fn blob_service(
        &self,
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
        store_path: impl AsRef<Path>,
        config: crate::blob::BlobStoreConfig,
    ) -> Result<crate::blob::ReferenceBlobService, EngineError> {
        Ok(self
            .envelopes
            .blob_service(scope, topic, epoch, store_path, config)?)
    }

    pub fn blob_service_with_defaults(
        &self,
        scope: &Scope,
        topic: &Topic,
        epoch: u64,
        store_path: impl AsRef<Path>,
    ) -> Result<crate::blob::ReferenceBlobService, EngineError> {
        Ok(self
            .envelopes
            .blob_service_with_defaults(scope, topic, epoch, store_path)?)
    }
}

struct ApplicationProjectionCandidate {
    item: ApplicationItem,
    inserted_order: u64,
    representation_order: u8,
}

enum SubscriptionRepresentation {
    Ordinary(Box<StoredItem>),
    Bridged(Box<StoredBridgeProjection>),
}

struct OpenedSubscriptionCandidate {
    item: ApplicationItem,
    inserted_order: u64,
    representation_order: u8,
    representation: SubscriptionRepresentation,
}

fn subscription_candidate_order(
    left: &OpenedSubscriptionCandidate,
    right: &OpenedSubscriptionCandidate,
) -> std::cmp::Ordering {
    right
        .item
        .priority
        .cmp(&left.item.priority)
        .then_with(|| left.inserted_order.cmp(&right.inserted_order))
        .then_with(|| left.representation_order.cmp(&right.representation_order))
        .then_with(|| left.item.id.cmp(&right.item.id))
}

fn projection_candidate_order(
    left: &ApplicationProjectionCandidate,
    right: &ApplicationProjectionCandidate,
) -> std::cmp::Ordering {
    right
        .item
        .priority
        .cmp(&left.item.priority)
        .then_with(|| left.inserted_order.cmp(&right.inserted_order))
        .then_with(|| left.representation_order.cmp(&right.representation_order))
        .then_with(|| left.item.id.cmp(&right.item.id))
}

fn projection_dominates(
    successor: &ApplicationProjectionCandidate,
    predecessor: &ApplicationProjectionCandidate,
) -> bool {
    application_item_dominates(&successor.item, &predecessor.item)
}

fn application_item_dominates(successor: &ApplicationItem, predecessor: &ApplicationItem) -> bool {
    successor
        .stamp
        .context
        .counter(&predecessor.stamp.dot.publisher)
        >= predecessor.stamp.dot.counter
}

fn reduce_application_projection(
    candidates: Vec<ApplicationProjectionCandidate>,
    include_recoverable_versions: bool,
) -> Vec<ApplicationProjectionCandidate> {
    if include_recoverable_versions {
        return candidates;
    }
    let mut groups =
        BTreeMap::<(Topic, Scope, DataClass, Vec<u8>), Vec<ApplicationProjectionCandidate>>::new();
    for candidate in candidates {
        groups
            .entry((
                candidate.item.topic.clone(),
                candidate.item.current_scope.clone(),
                candidate.item.class,
                candidate.item.logical_key.clone(),
            ))
            .or_default()
            .push(candidate);
    }
    let mut reduced = Vec::new();
    for (_, group) in groups {
        let keep = (0..group.len())
            .map(|index| {
                !(0..group.len()).any(|other| {
                    other != index && projection_dominates(&group[other], &group[index])
                })
            })
            .collect::<Vec<_>>();
        let mut maximal = group
            .into_iter()
            .enumerate()
            .filter_map(|(index, candidate)| keep[index].then_some(candidate))
            .collect::<Vec<_>>();
        if maximal
            .first()
            .is_some_and(|candidate| candidate.item.class == DataClass::State)
        {
            if let Some(winner) = maximal
                .into_iter()
                .max_by_key(|candidate| candidate.item.id)
            {
                reduced.push(winner);
            }
        } else {
            reduced.append(&mut maximal);
        }
    }
    reduced
}

fn reduce_subscription_projection(
    candidates: Vec<OpenedSubscriptionCandidate>,
) -> Vec<OpenedSubscriptionCandidate> {
    let mut groups =
        BTreeMap::<(Topic, Scope, DataClass, Vec<u8>), Vec<OpenedSubscriptionCandidate>>::new();
    for candidate in candidates {
        groups
            .entry((
                candidate.item.topic.clone(),
                candidate.item.current_scope.clone(),
                candidate.item.class,
                candidate.item.logical_key.clone(),
            ))
            .or_default()
            .push(candidate);
    }
    let mut reduced = Vec::new();
    for (_, group) in groups {
        let keep = (0..group.len())
            .map(|index| {
                !(0..group.len()).any(|other| {
                    other != index
                        && application_item_dominates(&group[other].item, &group[index].item)
                })
            })
            .collect::<Vec<_>>();
        let mut maximal = group
            .into_iter()
            .enumerate()
            .filter_map(|(index, candidate)| keep[index].then_some(candidate))
            .collect::<Vec<_>>();
        if maximal
            .first()
            .is_some_and(|candidate| candidate.item.class == DataClass::State)
        {
            if let Some(winner) = maximal
                .into_iter()
                .max_by_key(|candidate| candidate.item.id)
            {
                reduced.push(winner);
            }
        } else {
            reduced.append(&mut maximal);
        }
    }
    reduced
}

impl Node<SqliteStore, crate::crypto::ReferenceEnvelopeSealer> {
    /// Rebuilds process-local batch proof authority and reauthenticates every
    /// accepted compact representation after the durable store is reopened.
    /// Pending proof/item promotion remains a semantic-runtime responsibility
    /// because Blob promotion also owns the authenticated carrier store.
    pub(crate) fn reauthenticate_application_batch_state(&mut self) -> Result<(), EngineError> {
        use crate::crypto::BatchCryptoProvider;

        const RESTART_PAGE: usize = 1_024;

        if self.store.is_zeroized()? {
            return Err(StoreError::Zeroized.into());
        }
        let mut proof_after = None;
        loop {
            let proofs = self
                .store
                .stored_batch_proofs_after(proof_after, RESTART_PAGE)?;
            if proofs.is_empty() {
                return Ok(());
            }
            for stored_proof in &proofs {
                let proof = self.envelopes.open_batch_proof(
                    &stored_proof.exact_bytes,
                    crate::crypto::SEMANTIC_PROTOCOL_V2,
                )?;
                if proof.proof_envelope_id() != stored_proof.proof_envelope_id
                    || proof.batch_id() != stored_proof.batch_id
                {
                    return Err(EngineError::Invalid(
                        "reauthenticated batch proof differs from durable provenance".into(),
                    ));
                }
                self.store
                    .mark_verified_batch_proof(&proof, &stored_proof.exact_bytes)?;

                let mut item_after = None;
                loop {
                    let materials = self.store.stored_batch_materials_for_proof(
                        &stored_proof.proof_envelope_id,
                        item_after,
                        RESTART_PAGE,
                    )?;
                    if materials.is_empty() {
                        break;
                    }
                    for material in &materials {
                        if material.proof != *stored_proof {
                            return Err(EngineError::Invalid(
                                "batch item names inconsistent durable proof provenance".into(),
                            ));
                        }
                        let pending = self.envelopes.open_compact_batch_item(
                            &material.compact_bytes,
                            crate::crypto::SEMANTIC_PROTOCOL_V2,
                        )?;
                        if self.envelopes.pending_batch_proof_id(&pending)
                            != stored_proof.proof_envelope_id
                        {
                            return Err(EngineError::Invalid(
                                "compact batch item names the wrong proof".into(),
                            ));
                        }
                        let verified = self.envelopes.verify_compact_batch_item(
                            &pending,
                            Some(&proof),
                            &material.compact_bytes,
                        )?;
                        let envelope = verified.verified_envelope();
                        let durable = self.store.get(&material.item_id)?.ok_or_else(|| {
                            EngineError::Invalid(
                                "accepted compact batch item is missing its durable index".into(),
                            )
                        })?;
                        if verified.envelope_id() != material.compact_envelope_id
                            || verified.proof_envelope_id() != stored_proof.proof_envelope_id
                            || verified.batch_id() != stored_proof.batch_id
                            || envelope.id != durable.id
                            || !header_matches_item(&envelope.header, &durable)
                        {
                            return Err(EngineError::Invalid(
                                "reauthenticated compact item differs from durable provenance"
                                    .into(),
                            ));
                        }
                    }
                    item_after = materials.last().map(|material| material.inserted_order);
                    if materials.len() < RESTART_PAGE {
                        break;
                    }
                }
            }
            proof_after = proofs.last().map(|proof| proof.inserted_order);
            if proofs.len() < RESTART_PAGE {
                return Ok(());
            }
        }
    }

    /// Explicitly seals and commits one complete semantic-v2 source batch.
    /// Reservation is read-only until the proof, every compact item, and every
    /// policy-required singleton are ready for one store transaction.
    pub(crate) fn publish_reference_batch(
        &mut self,
        items: Vec<BatchPublishItem>,
        storage_policy: BatchStoragePolicy,
    ) -> Result<BatchPublishReceipt, EngineError> {
        use crate::crypto::BatchCryptoProvider;

        if self.store.is_zeroized()? {
            return Err(StoreError::Zeroized.into());
        }
        let item_count = u16::try_from(items.len())
            .map_err(|_| EngineError::Invalid("batch item count exceeds 64".into()))?;
        if !(crate::batch::MIN_BATCH_ITEMS..=crate::batch::MAX_BATCH_ITEMS).contains(&item_count) {
            return Err(EngineError::Invalid(
                "batch publication requires between 2 and 64 items".into(),
            ));
        }
        let first = &items[0].request;
        let class = first.class;
        let topic = first.topic.clone();
        let scope = first.scope.clone();
        for item in &items {
            let request = &item.request;
            if request.class != class || request.topic != topic || request.scope != scope {
                return Err(EngineError::Invalid(
                    "batch items must share data class, topic, and scope".into(),
                ));
            }
            if request.tombstone && request.class == DataClass::Blob {
                return Err(EngineError::Invalid(
                    "immutable Blob cannot be a tombstone".into(),
                ));
            }
            if request.tombstone && !request.payload.is_empty() {
                return Err(EngineError::Invalid(
                    "tombstone payload must be empty".into(),
                ));
            }
            match (request.class, item.blob_route) {
                (DataClass::Blob, Some(route))
                    if request.logical_key.as_slice() == route.blob_id().as_bytes() => {}
                (DataClass::Blob, _) => {
                    return Err(EngineError::Invalid(
                        "batch Blob requires its exact finalized route commitment".into(),
                    ));
                }
                (_, None) => {}
                (_, Some(_)) => {
                    return Err(EngineError::Invalid(
                        "non-Blob batch item cannot carry a Blob route commitment".into(),
                    ));
                }
            }
        }

        for _ in 0..self.publish_retry_limit {
            let reservation = self.store.reserve_batch_publish(
                self.identity,
                class,
                &topic,
                &scope,
                item_count,
            )?;
            let epoch = self.store.scope_epoch(&scope)?;
            let mut context = reservation.context.clone();
            let mut headers = Vec::with_capacity(items.len());
            for (index, item) in items.iter().enumerate() {
                let index = u64::try_from(index)
                    .map_err(|_| EngineError::Invalid("batch index overflow".into()))?;
                let counter = reservation
                    .first_counter
                    .checked_add(index)
                    .ok_or_else(|| EngineError::Invalid("batch causal range exhausted".into()))?;
                let event_sequence = reservation
                    .first_event_sequence
                    .map(|first| {
                        first.checked_add(index).ok_or_else(|| {
                            EngineError::Invalid("batch event range exhausted".into())
                        })
                    })
                    .transpose()?;
                let dot = crate::model::Dot {
                    publisher: self.identity,
                    counter,
                };
                headers.push(EnvelopeHeader {
                    class,
                    topic: topic.clone(),
                    scope: scope.clone(),
                    priority: item.request.priority.min(self.priority_cap),
                    stamp: CausalStamp {
                        dot,
                        context: context.clone(),
                    },
                    event_sequence,
                    logical_key: item.request.logical_key.clone(),
                    blob_route: item.blob_route,
                    ttl_ms: item.request.ttl_ms,
                    content_len: u64::try_from(item.request.payload.len()).map_err(|_| {
                        EngineError::Invalid("batch payload length exceeds u64".into())
                    })?,
                    tombstone: item.request.tombstone,
                    key_epoch: epoch,
                });
                context.observe(dot);
            }
            let sealing_requests = headers
                .iter()
                .zip(&items)
                .map(|(header, item)| SealRequest {
                    header,
                    payload: &item.request.payload,
                })
                .collect::<Vec<_>>();
            let sealed = self.envelopes.seal_source_batch(&sealing_requests)?;
            if sealed.items.len() != items.len() {
                return Err(EngineError::Invalid(
                    "batch provider returned the wrong compact item count".into(),
                ));
            }
            let observed_at_ms = self.clock.now_ms();
            let custody_sample = self.clock.custody_sample();
            let mut item_ids = Vec::with_capacity(items.len());
            let mut committed_items = Vec::with_capacity(items.len());
            for ((header, compact), seal_request) in
                headers.iter().zip(sealed.items).zip(&sealing_requests)
            {
                let compact_envelope_id: EnvelopeId = Sha256::digest(&compact.bytes).into();
                if compact_envelope_id != compact.envelope_id {
                    return Err(EngineError::Invalid(
                        "batch provider returned a mismatched compact identity".into(),
                    ));
                }
                let compact_item = stored_from_verified(
                    VerifiedEnvelope {
                        id: compact.item_id,
                        header: header.clone(),
                    },
                    compact.bytes,
                    observed_at_ms,
                    0,
                    custody_sample,
                );
                let singleton = if storage_policy == BatchStoragePolicy::RetainedDual {
                    let singleton = self.envelopes.seal(SealRequest {
                        header,
                        payload: seal_request.payload,
                    })?;
                    if singleton.id != compact_item.id {
                        return Err(EngineError::Invalid(
                            "batch compact and singleton semantic identities differ".into(),
                        ));
                    }
                    Some(stored_from_verified(
                        VerifiedEnvelope {
                            id: singleton.id,
                            header: header.clone(),
                        },
                        singleton.bytes,
                        observed_at_ms,
                        0,
                        custody_sample,
                    ))
                } else {
                    None
                };
                item_ids.push(compact_item.id);
                committed_items.push(LocalBatchItemCommit {
                    compact: compact_item,
                    singleton,
                });
            }
            let commit = LocalBatchCommit {
                proof_envelope_id: sealed.proof_envelope_id,
                batch_id: sealed.batch_id,
                proof_bytes: sealed.proof_bytes,
                items: committed_items,
                storage_policy,
            };
            match self.store.commit_local_batch(&reservation, commit) {
                Ok(outcome) => {
                    let receipts = headers
                        .into_iter()
                        .zip(item_ids)
                        .map(|(header, id)| PublishReceipt {
                            id,
                            stamp: header.stamp,
                            event_sequence: header.event_sequence,
                            effective_priority: header.priority,
                            evicted: Vec::new(),
                        })
                        .collect();
                    return Ok(BatchPublishReceipt {
                        items: receipts,
                        evicted: outcome.evicted,
                    });
                }
                Err(StoreError::CounterChanged) => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(StoreError::CounterChanged.into())
    }

    /// Restores only provider-verified bridge controls and routes to the
    /// process-live application projection after a standalone node restart.
    pub(crate) fn reauthenticate_application_bridge_state(&mut self) -> Result<(), EngineError> {
        let sample = self.clock.custody_sample();
        let mut service = crate::bridge_service::ReferenceBridgeService::new(
            &mut self.envelopes,
            &mut self.store,
            self.emission,
        );
        service
            .reauthenticate_durable_application_state(sample)
            .map_err(bridge_service_error)
    }

    /// Concrete application query that merges ordinary items with the active,
    /// provider-revalidated bridge target projection. Ordinary ItemIDs win
    /// exact de-duplication, and a bridged item is omitted unless this provider
    /// can open the immutable origin-scope content grant.
    pub(crate) fn query_application_projection(
        &mut self,
        mut query: StoreQuery,
    ) -> Result<Vec<ApplicationItem>, EngineError> {
        query.now_ms = self.clock.now_ms();
        query.custody_sample = self.clock.custody_sample();
        let limit = query.limit.unwrap_or(usize::MAX);
        let include_recoverable_versions = query.include_recoverable_versions;
        let mut candidates = self.application_projection_candidates(&query)?;
        candidates = reduce_application_projection(candidates, include_recoverable_versions);
        candidates.sort_by(projection_candidate_order);
        candidates.truncate(limit);
        Ok(candidates
            .into_iter()
            .map(|candidate| candidate.item)
            .collect())
    }

    pub(crate) fn poll_application_projection(
        &mut self,
        subscription: SubscriptionId,
        limit: usize,
    ) -> Result<Vec<Delivery>, EngineError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let now = self.clock.now_ms();
        let custody = self.clock.custody_sample();
        self.store.collect_garbage(now, custody)?;

        let mut ordinary = Vec::new();
        let mut ordinary_cursor: Option<SubscriptionCursor> = None;
        loop {
            let page = self
                .store
                .peek_subscription_page(subscription, ordinary_cursor, custody)?;
            ordinary.extend(page.entries);
            let Some(next) = page.next_cursor else { break };
            if Some(next) == ordinary_cursor {
                return Err(EngineError::Invalid(
                    "ordinary subscription cursor did not advance".into(),
                ));
            }
            ordinary_cursor = Some(next);
        }
        let ordinary_ids = ordinary.iter().map(|item| item.id).collect::<BTreeSet<_>>();
        let mut opened = Vec::new();
        for stored in ordinary {
            let retained = stored.clone();
            let inserted_order = stored.inserted_order;
            opened.push(OpenedSubscriptionCandidate {
                item: self.open_application_item(stored)?,
                inserted_order,
                representation_order: 0,
                representation: SubscriptionRepresentation::Ordinary(Box::new(retained)),
            });
        }

        let mut bridge_cursor: Option<BridgeProjectionCursor> = None;
        let mut bridge_seen = BTreeSet::new();
        loop {
            let page = self.store.peek_bridge_projection_subscription_page(
                subscription,
                bridge_cursor,
                custody,
            )?;
            for projection in page.entries {
                let id = projection.source.metadata.source_item_id;
                if ordinary_ids.contains(&id) || bridge_seen.contains(&id) {
                    continue;
                }
                let retained = projection.clone();
                let inserted_order = projection.route.inserted_order;
                if let Some(item) = self.open_bridge_application_item(projection)? {
                    bridge_seen.insert(id);
                    opened.push(OpenedSubscriptionCandidate {
                        item,
                        inserted_order,
                        representation_order: 1,
                        representation: SubscriptionRepresentation::Bridged(Box::new(retained)),
                    });
                }
            }
            let Some(next) = page.next_cursor else { break };
            if Some(next) == bridge_cursor {
                return Err(EngineError::Invalid(
                    "bridge subscription cursor did not advance".into(),
                ));
            }
            bridge_cursor = Some(next);
        }
        opened = reduce_subscription_projection(opened);
        opened.sort_by(subscription_candidate_order);
        let mut seen = BTreeSet::new();
        opened.retain(|candidate| seen.insert(candidate.item.id));
        opened.truncate(limit);

        let ordinary_to_record = opened
            .iter()
            .filter_map(|candidate| match &candidate.representation {
                SubscriptionRepresentation::Ordinary(item) => Some((**item).clone()),
                SubscriptionRepresentation::Bridged(_) => None,
            })
            .collect::<Vec<_>>();
        let bridge_to_record = opened
            .iter()
            .filter_map(|candidate| match &candidate.representation {
                SubscriptionRepresentation::Ordinary(_) => None,
                SubscriptionRepresentation::Bridged(projection) => Some(
                    ProviderOpenedBridgeProjection::from_provider((**projection).clone()),
                ),
            })
            .collect::<Vec<_>>();
        let mut attempts = BTreeMap::new();
        if !ordinary_to_record.is_empty() {
            for delivery in self.store.record_subscription_deliveries(
                subscription,
                &ordinary_to_record,
                now,
                custody,
            )? {
                attempts.insert(delivery.item.id, delivery.delivery_attempt);
            }
        }
        if !bridge_to_record.is_empty() {
            for delivery in self.store.record_bridge_projection_deliveries(
                subscription,
                &bridge_to_record,
                now,
                custody,
            )? {
                attempts.insert(
                    delivery.projection.source.metadata.source_item_id,
                    delivery.delivery_attempt,
                );
            }
        }
        Ok(opened
            .into_iter()
            .filter_map(|candidate| {
                attempts.remove(&candidate.item.id).map(|attempt| Delivery {
                    subscription,
                    attempt,
                    item: candidate.item,
                })
            })
            .collect())
    }

    pub(crate) fn acknowledge_application_projection(
        &mut self,
        subscription: SubscriptionId,
        item: ItemId,
    ) -> Result<(), EngineError> {
        self.store
            .acknowledge_delivery(subscription, &item, self.clock.now_ms())?;
        Ok(())
    }

    fn application_projection_candidates(
        &mut self,
        query: &StoreQuery,
    ) -> Result<Vec<ApplicationProjectionCandidate>, EngineError> {
        let mut ordinary_query = query.clone();
        ordinary_query.include_recoverable_versions = true;
        ordinary_query.limit = None;
        let ordinary = self.store.query(&ordinary_query)?;
        let ordinary_ids = ordinary.iter().map(|item| item.id).collect::<BTreeSet<_>>();
        let mut candidates = Vec::new();
        for stored in ordinary {
            let inserted_order = stored.inserted_order;
            candidates.push(ApplicationProjectionCandidate {
                item: self.open_application_item(stored)?,
                inserted_order,
                representation_order: 0,
            });
        }

        let projection_query = BridgeProjectionQuery {
            target_scope: query.scope.clone(),
            target_route_epoch: None,
            topic: query.topic.clone(),
            class: query.class,
            logical_key: query.logical_key.clone(),
            // Representation-local status cannot decide dominance across an
            // ordinary target item and a bridged source. Fetch every retained
            // version and reduce the authenticated causal stamps together.
            version_status: None,
            include_tombstones: query.include_tombstones,
            custody_sample: query.custody_sample,
            limit: None,
        };
        let mut cursor: Option<BridgeProjectionCursor> = None;
        let mut seen = BTreeSet::new();
        loop {
            let page = self
                .store
                .query_active_bridge_projection_page(&projection_query, cursor)?;
            for projection in page.entries {
                let id = projection.source.metadata.source_item_id;
                if ordinary_ids.contains(&id) || !seen.insert(id) {
                    continue;
                }
                let inserted_order = projection.route.inserted_order;
                if let Some(item) = self.open_bridge_application_item(projection)? {
                    candidates.push(ApplicationProjectionCandidate {
                        item,
                        inserted_order,
                        representation_order: 1,
                    });
                }
            }
            let Some(next) = page.next_cursor else { break };
            if Some(next) == cursor {
                return Err(EngineError::Invalid(
                    "bridge projection cursor did not advance".into(),
                ));
            }
            cursor = Some(next);
        }
        candidates.sort_by(projection_candidate_order);
        let mut exact_seen = BTreeSet::new();
        candidates.retain(|candidate| exact_seen.insert(candidate.item.id));
        Ok(candidates)
    }

    pub(crate) fn conflicts_application_projection(
        &mut self,
        mut query: StoreQuery,
    ) -> Result<Vec<ConflictAnnotation>, EngineError> {
        query.now_ms = self.clock.now_ms();
        query.custody_sample = self.clock.custody_sample();
        query.include_recoverable_versions = true;
        query.limit = None;
        let candidates = self.application_projection_candidates(&query)?;
        let mut groups =
            BTreeMap::<(Topic, Scope, Vec<u8>), Vec<ApplicationProjectionCandidate>>::new();
        for candidate in candidates
            .into_iter()
            .filter(|candidate| candidate.item.class == DataClass::Record)
        {
            groups
                .entry((
                    candidate.item.topic.clone(),
                    candidate.item.current_scope.clone(),
                    candidate.item.logical_key.clone(),
                ))
                .or_default()
                .push(candidate);
        }
        let mut conflicts = Vec::new();
        for ((topic, _, logical_key), group) in groups {
            let mut siblings = (0..group.len())
                .filter(|index| {
                    !(0..group.len()).any(|other| {
                        other != *index && projection_dominates(&group[other], &group[*index])
                    })
                })
                .map(|index| group[index].item.id)
                .collect::<Vec<_>>();
            siblings.sort_unstable();
            siblings.dedup();
            if siblings.len() > 1 {
                conflicts.push(ConflictAnnotation {
                    logical_key,
                    siblings,
                    merge_policy: self
                        .merge_policies
                        .get(topic.as_str())
                        .map(|policy| policy.id().to_owned()),
                });
            }
        }
        Ok(conflicts)
    }

    pub(crate) fn event_gaps_application_projection(
        &mut self,
        mut query: StoreQuery,
    ) -> Result<Vec<EventGap>, EngineError> {
        query.now_ms = self.clock.now_ms();
        query.custody_sample = self.clock.custody_sample();
        query.class = Some(DataClass::Event);
        query.include_recoverable_versions = true;
        query.include_tombstones = true;
        query.limit = None;
        let candidates = self.application_projection_candidates(&query)?;
        let mut streams = BTreeMap::<(NodeId, Topic, Scope), BTreeSet<u64>>::new();
        for candidate in candidates {
            if let Some(sequence) = candidate.item.event_sequence {
                streams
                    .entry((
                        candidate.item.publisher,
                        candidate.item.topic,
                        candidate.item.current_scope,
                    ))
                    .or_default()
                    .insert(sequence);
            }
        }
        let mut gaps = Vec::new();
        for ((publisher, topic, scope), sequences) in streams {
            let mut expected = 1u64;
            for sequence in sequences {
                if sequence > expected {
                    gaps.push(EventGap {
                        publisher,
                        topic: topic.clone(),
                        scope: scope.clone(),
                        start_sequence: expected,
                        end_sequence: sequence,
                    });
                }
                expected = expected.max(sequence.saturating_add(1));
            }
        }
        Ok(gaps)
    }

    pub(crate) fn resolve_application_projection(
        &mut self,
        mut request: ResolveRequest,
    ) -> Result<PublishReceipt, EngineError> {
        request.expected_siblings.sort_unstable();
        request.expected_siblings.dedup();
        let query = StoreQuery {
            topic: Some(request.topic.clone()),
            scope: Some(request.scope.clone()),
            include_descendant_scopes: false,
            class: Some(DataClass::Record),
            logical_key: Some(request.logical_key.clone()),
            include_recoverable_versions: true,
            include_tombstones: true,
            now_ms: self.clock.now_ms(),
            custody_sample: self.clock.custody_sample(),
            limit: None,
        };
        let candidates = self.application_projection_candidates(&query)?;
        let mut maximal = (0..candidates.len())
            .filter(|index| {
                !(0..candidates.len()).any(|other| {
                    other != *index && projection_dominates(&candidates[other], &candidates[*index])
                })
            })
            .collect::<Vec<_>>();
        maximal.sort_by_key(|index| candidates[*index].item.id);
        let sibling_ids = maximal
            .iter()
            .map(|index| candidates[*index].item.id)
            .collect::<Vec<_>>();
        if sibling_ids.len() < 2 || sibling_ids != request.expected_siblings {
            return Err(EngineError::StaleConflict);
        }
        let mut context = VersionVector::default();
        for index in maximal {
            context.join(&candidates[index].item.stamp.clock());
        }
        self.publish_with_context(
            PublishRequest {
                class: DataClass::Record,
                topic: request.topic,
                scope: request.scope,
                priority: request.priority,
                ttl_ms: request.ttl_ms,
                logical_key: request.logical_key,
                payload: request.payload,
                tombstone: false,
            },
            Some(&context),
            None,
        )
    }

    fn open_bridge_application_item(
        &self,
        projection: StoredBridgeProjection,
    ) -> Result<Option<ApplicationItem>, EngineError> {
        use crate::crypto::BridgeCryptoProvider;

        let route = projection.route;
        let source = projection.source;
        let wrapper = self
            .envelopes
            .open_bridge_wrapper_for_any_local_route(&route.exact_wrapper_bytes)?;
        let authenticated_route = wrapper.route();
        if wrapper.wrapper_envelope_id() != route.wrapper_envelope_id
            || authenticated_route.bridge_route_id != route.bridge_route_id
            || authenticated_route.origin_envelope_id != route.origin_envelope_id
            || authenticated_route.source_item_id != route.source_item_id
            || authenticated_route.origin_scope != route.origin_scope
            || authenticated_route.origin_route_epoch != route.origin_route_epoch
            || authenticated_route.current_scope != route.current_scope
            || authenticated_route.current_route_epoch != route.current_route_epoch
            || authenticated_route.hops.len() != usize::from(route.hop_count)
            || route.exact_source_bytes != source.exact_bytes
            || source.origin_envelope_id != route.origin_envelope_id
        {
            return Err(EngineError::Invalid(
                "active bridge projection differs from its provider-authenticated route".into(),
            ));
        }
        let verified_source = self
            .envelopes
            .verify_bridge_wrapper_source(&wrapper, &source.exact_bytes)?;
        let header = verified_source.header();
        let metadata = &source.metadata;
        if verified_source.origin_envelope_id() != source.origin_envelope_id
            || verified_source.source_item_id() != metadata.source_item_id
            || header.class != metadata.class
            || header.topic != metadata.topic
            || header.scope != metadata.origin_scope
            || header.priority != metadata.priority
            || header.stamp != metadata.stamp
            || header.event_sequence != metadata.event_sequence
            || header.logical_key != metadata.logical_key
            || header.ttl_ms != metadata.ttl_ms
            || header.content_len != metadata.content_len
            || header.tombstone != metadata.tombstone
            || header.key_epoch != metadata.origin_route_epoch
        {
            return Err(EngineError::Invalid(
                "active bridge source differs from provider-authenticated metadata".into(),
            ));
        }
        if !self.envelopes.has_content_grant(
            &metadata.origin_scope,
            &metadata.topic,
            metadata.origin_route_epoch,
        ) {
            return Ok(None);
        }
        let payload = self
            .envelopes
            .open_bridged_payload(&verified_source, &source.exact_bytes)
            .map_err(EngineError::Envelope)?;
        Ok(Some(ApplicationItem {
            id: metadata.source_item_id,
            class: metadata.class,
            topic: metadata.topic.clone(),
            scope: route.current_scope.clone(),
            origin_scope: metadata.origin_scope.clone(),
            current_scope: route.current_scope,
            priority: metadata.priority,
            publisher: metadata.stamp.dot.publisher,
            stamp: metadata.stamp.clone(),
            event_sequence: metadata.event_sequence,
            logical_key: metadata.logical_key.clone(),
            payload,
            tombstone: metadata.tombstone,
        }))
    }

    /// Creates a bridge-node-signed enrollment for one exact directed edge.
    /// The opaque artifact can be moved to the authority API, but its provider
    /// bytes, credentials, route commitments, and keys are never exposed.
    pub(crate) fn create_bridge_edge_enrollment(
        &self,
        source_scope: &Scope,
        source_route_epoch: u64,
        target_scope: &Scope,
        target_route_epoch: u64,
    ) -> Result<crate::crypto::BridgeEdgeEnrollment, EngineError> {
        use crate::crypto::BridgeCryptoProvider;

        self.envelopes
            .create_bridge_edge_enrollment(
                source_scope,
                source_route_epoch,
                target_scope,
                target_route_epoch,
            )
            .map_err(EngineError::Envelope)
    }

    /// Authority-only activation of a signed opaque bridge enrollment.
    pub(crate) fn enable_bridge_edge(
        &mut self,
        request: crate::bridge_service::EnableBridgeAuthorizationRequest,
    ) -> Result<crate::bridge_service::IssuedBridgeAuthorization, EngineError> {
        let mut service = crate::bridge_service::ReferenceBridgeService::new(
            &mut self.envelopes,
            &mut self.store,
            self.emission,
        );
        service
            .issue_enabled_authorization(request)
            .map_err(bridge_service_error)
    }

    /// Authority-only higher-generation disable for one exact directed edge.
    pub(crate) fn disable_bridge_edge(
        &mut self,
        request: crate::bridge_service::DisableBridgeAuthorizationRequest,
    ) -> Result<crate::bridge_service::IssuedBridgeAuthorization, EngineError> {
        let mut service = crate::bridge_service::ReferenceBridgeService::new(
            &mut self.envelopes,
            &mut self.store,
            self.emission,
        );
        service
            .issue_disabled_authorization(request)
            .map_err(bridge_service_error)
    }

    /// Creates the first wrapper around an already-durable ordinary item.
    pub(crate) fn bridge_item(
        &mut self,
        source_item_id: ItemId,
        authorization_envelope_id: EnvelopeId,
        local_narrowing: crate::bridge_service::LocalBridgeNarrowing,
    ) -> Result<crate::bridge_service::CreatedBridgeRoute, EngineError> {
        let source_envelope_id = self
            .store
            .get(&source_item_id)?
            .ok_or_else(|| EngineError::Invalid("bridge source item is not durable".into()))?
            .envelope_id;
        let custody_sample = self.clock.custody_sample();
        let mut service = crate::bridge_service::ReferenceBridgeService::new(
            &mut self.envelopes,
            &mut self.store,
            self.emission,
        );
        service
            .create_first_hop(crate::bridge_service::FirstBridgeHopRequest {
                source_envelope_id,
                authorization_envelope_id,
                local_narrowing,
                custody_sample,
            })
            .map_err(bridge_service_error)
    }

    /// Extends one active durable bridge route by exactly one authorized hop.
    pub(crate) fn extend_bridge_route(
        &mut self,
        current_wrapper_envelope_id: EnvelopeId,
        authorization_envelope_id: EnvelopeId,
        local_narrowing: crate::bridge_service::LocalBridgeNarrowing,
    ) -> Result<crate::bridge_service::CreatedBridgeRoute, EngineError> {
        let custody_sample = self.clock.custody_sample();
        let mut service = crate::bridge_service::ReferenceBridgeService::new(
            &mut self.envelopes,
            &mut self.store,
            self.emission,
        );
        service
            .create_nested_hop(crate::bridge_service::NestedBridgeHopRequest {
                current_wrapper_envelope_id,
                authorization_envelope_id,
                local_narrowing,
                custody_sample,
            })
            .map_err(bridge_service_error)
    }
}

fn bridge_service_error(error: crate::bridge_service::BridgeServiceError) -> EngineError {
    match error {
        crate::bridge_service::BridgeServiceError::Provider(error) => EngineError::Envelope(error),
        crate::bridge_service::BridgeServiceError::Store(error) => EngineError::Store(error),
        crate::bridge_service::BridgeServiceError::Invalid(message) => {
            EngineError::Invalid(message.into())
        }
        crate::bridge_service::BridgeServiceError::Codec(error) => {
            EngineError::Invalid(error.to_string())
        }
    }
}

pub(crate) fn stored_from_verified(
    envelope: VerifiedEnvelope,
    sealed: Vec<u8>,
    observed_at_ms: Option<u64>,
    custody_age_ms: u64,
    custody_sample: Option<CustodySample>,
) -> StoredItem {
    let envelope_id: EnvelopeId = Sha256::digest(&sealed).into();
    StoredItem {
        id: envelope.id,
        envelope_id,
        class: envelope.header.class,
        topic: envelope.header.topic,
        scope: envelope.header.scope,
        priority: envelope.header.priority,
        stamp: envelope.header.stamp,
        event_sequence: envelope.header.event_sequence,
        logical_key: envelope.header.logical_key,
        ttl_ms: envelope.header.ttl_ms,
        observed_at_ms,
        sealed,
        content_len: envelope.header.content_len,
        tombstone: envelope.header.tombstone,
        key_epoch: envelope.header.key_epoch,
        custody_age_ms,
        custody_clock_id: custody_sample.map(|sample| sample.clock_id),
        custody_tick_ms: custody_sample.map(|sample| sample.tick_ms),
        custody_elapsed_available: custody_sample.is_some(),
        status: VersionStatus::Current,
        inserted_order: 0,
    }
}

fn verified_stored_control(
    control: VerifiedControl,
    sealed: &[u8],
    observed_at_ms: Option<u64>,
) -> Result<VerifiedStoredControl, EngineError> {
    if sealed.is_empty() {
        return Err(EngineError::Invalid("control envelope is empty".into()));
    }
    let envelope_id: EnvelopeId = Sha256::digest(sealed).into();
    let stored = match control {
        VerifiedControl::Revocation(mut revocation) => {
            revocation.observed_at_ms = observed_at_ms;
            VerifiedStoredControl {
                envelope_id,
                authority: revocation.authority,
                sequence: revocation.control_sequence,
                previous_control: revocation.previous_control,
                kind: ControlKind::Revocation,
                revocation: Some(revocation),
                scope_epoch: None,
                sealed: sealed.to_vec(),
            }
        }
        VerifiedControl::ScopeEpoch(epoch) => VerifiedStoredControl {
            envelope_id,
            authority: epoch.authority,
            sequence: epoch.control_sequence,
            previous_control: epoch.previous_control,
            kind: ControlKind::ScopeEpoch,
            revocation: None,
            scope_epoch: Some(epoch),
            sealed: sealed.to_vec(),
        },
    };
    Ok(stored)
}

fn effective_custody_age(item: &StoredItem, sample: Option<CustodySample>) -> Option<u64> {
    if item.ttl_ms.is_none() {
        if item.custody_elapsed_available
            && let (Some(clock_id), Some(tick), Some(sample)) =
                (item.custody_clock_id, item.custody_tick_ms, sample)
            && clock_id == sample.clock_id
            && sample.tick_ms >= tick
        {
            return Some(
                item.custody_age_ms
                    .saturating_add(sample.tick_ms.saturating_sub(tick)),
            );
        }
        return Some(item.custody_age_ms);
    }
    if !item.custody_elapsed_available {
        return None;
    }
    let (Some(clock_id), Some(tick), Some(sample)) =
        (item.custody_clock_id, item.custody_tick_ms, sample)
    else {
        return None;
    };
    if clock_id != sample.clock_id || sample.tick_ms < tick {
        return None;
    }
    Some(
        item.custody_age_ms
            .saturating_add(sample.tick_ms.saturating_sub(tick)),
    )
}

fn header_matches_item(header: &EnvelopeHeader, item: &StoredItem) -> bool {
    header.class == item.class
        && header.topic == item.topic
        && header.scope == item.scope
        && header.priority == item.priority
        && header.stamp == item.stamp
        && header.event_sequence == item.event_sequence
        && header.logical_key == item.logical_key
        && header.ttl_ms == item.ttl_ms
        && header.content_len == item.content_len
        && header.tombstone == item.tombstone
        && header.key_epoch == item.key_epoch
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryStore;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    type Registry = BTreeMap<Vec<u8>, (VerifiedEnvelope, Vec<u8>)>;

    #[derive(Clone, Default)]
    struct TestSealer {
        records: Arc<Mutex<Registry>>,
        nonce: Arc<AtomicU64>,
        zeroized: Arc<AtomicBool>,
    }

    impl TestSealer {
        fn test_id(bytes: &[u8], header: &EnvelopeHeader) -> ItemId {
            let mut id = header.stamp.dot.publisher;
            for (index, byte) in header
                .stamp
                .dot
                .counter
                .to_be_bytes()
                .iter()
                .chain(bytes)
                .enumerate()
            {
                let slot = index % 32;
                id[slot] = id[slot]
                    .wrapping_mul(33)
                    .wrapping_add(*byte)
                    .rotate_left((slot % 7) as u32);
            }
            id
        }
    }

    impl EnvelopeSealer for TestSealer {
        fn seal(&mut self, request: SealRequest<'_>) -> Result<SealedEnvelope, EnvelopeError> {
            if self.zeroized.load(Ordering::SeqCst) {
                return Err(EnvelopeError("zeroized".into()));
            }
            let nonce = self.nonce.fetch_add(1, Ordering::SeqCst);
            let mut bytes = nonce.to_be_bytes().to_vec();
            bytes.extend_from_slice(request.payload);
            let id = Self::test_id(&bytes, request.header);
            self.records.lock().unwrap().insert(
                bytes.clone(),
                (
                    VerifiedEnvelope {
                        id,
                        header: request.header.clone(),
                    },
                    request.payload.to_vec(),
                ),
            );
            Ok(SealedEnvelope { id, bytes })
        }

        fn inspect(&mut self, sealed: &[u8]) -> Result<VerifiedEnvelope, EnvelopeError> {
            self.records
                .lock()
                .unwrap()
                .get(sealed)
                .map(|(envelope, _)| envelope.clone())
                .ok_or_else(|| EnvelopeError("unknown test envelope".into()))
        }

        fn open_payload(
            &mut self,
            envelope: &VerifiedEnvelope,
            sealed: &[u8],
        ) -> Result<Vec<u8>, EnvelopeError> {
            self.records
                .lock()
                .unwrap()
                .get(sealed)
                .filter(|(stored, _)| stored == envelope)
                .map(|(_, payload)| payload.clone())
                .ok_or_else(|| EnvelopeError("test envelope mismatch".into()))
        }

        fn inspect_control(&mut self, _sealed: &[u8]) -> Result<VerifiedControl, EnvelopeError> {
            Err(EnvelopeError("no test control object".into()))
        }

        fn zeroize(&mut self) -> Result<(), EnvelopeError> {
            self.zeroized.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct ControlTrackingSealer {
        controls: Arc<Mutex<BTreeMap<Vec<u8>, VerifiedControl>>>,
        activated: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl ControlTrackingSealer {
        fn register_scope_epoch(
            &self,
            sealed: Vec<u8>,
            authority: NodeId,
            epoch: u64,
        ) -> crate::wire::EnvelopeId {
            let envelope_id = crate::wire::EnvelopeId::from_sealed_bytes(&sealed);
            self.controls.lock().unwrap().insert(
                sealed.clone(),
                VerifiedControl::ScopeEpoch(ScopeEpoch {
                    authority,
                    scope: scope(),
                    epoch,
                    control_sequence: 1,
                    previous_control: None,
                    sealed_notice: sealed,
                }),
            );
            envelope_id
        }

        fn activated(&self) -> Vec<Vec<u8>> {
            self.activated.lock().unwrap().clone()
        }
    }

    impl EnvelopeSealer for ControlTrackingSealer {
        fn seal(&mut self, _request: SealRequest<'_>) -> Result<SealedEnvelope, EnvelopeError> {
            Err(EnvelopeError(
                "data sealing is not used by this test".into(),
            ))
        }

        fn inspect(&mut self, _sealed: &[u8]) -> Result<VerifiedEnvelope, EnvelopeError> {
            Err(EnvelopeError("not a test data envelope".into()))
        }

        fn open_payload(
            &mut self,
            _envelope: &VerifiedEnvelope,
            _sealed: &[u8],
        ) -> Result<Vec<u8>, EnvelopeError> {
            Err(EnvelopeError(
                "data opening is not used by this test".into(),
            ))
        }

        fn inspect_control(&mut self, sealed: &[u8]) -> Result<VerifiedControl, EnvelopeError> {
            self.controls
                .lock()
                .unwrap()
                .get(sealed)
                .cloned()
                .ok_or_else(|| EnvelopeError("unknown test control".into()))
        }

        fn activate_control(
            &mut self,
            sealed: &[u8],
            _local_revoked: bool,
        ) -> Result<(), EnvelopeError> {
            self.activated.lock().unwrap().push(sealed.to_vec());
            Ok(())
        }

        fn inspect_forwarding(
            &mut self,
            _authenticated_sender: NodeId,
            _recipient: NodeId,
            _exchange_id: u64,
            _envelope_id: EnvelopeId,
            forwarding: &[u8],
        ) -> Result<u64, EnvelopeError> {
            if forwarding == b"authenticated-hop" {
                Ok(0)
            } else {
                Err(EnvelopeError("invalid test forwarding metadata".into()))
            }
        }

        fn zeroize(&mut self) -> Result<(), EnvelopeError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct ManualClock(AtomicU64);

    impl ManualClock {
        fn set(&self, value: u64) {
            self.0.store(value, Ordering::SeqCst);
        }
    }

    impl Clock for ManualClock {
        fn now_ms(&self) -> Option<u64> {
            Some(self.0.load(Ordering::SeqCst))
        }

        fn custody_sample(&self) -> Option<CustodySample> {
            Some(CustodySample {
                clock_id: [0x5a; 16],
                tick_ms: self.0.load(Ordering::SeqCst),
            })
        }
    }

    fn topic() -> Topic {
        Topic::new("mission.items").unwrap()
    }

    fn scope() -> Scope {
        Scope::new("mission/team/alpha").unwrap()
    }

    fn request(class: DataClass, key: &[u8], payload: &[u8]) -> PublishRequest {
        PublishRequest {
            class,
            topic: topic(),
            scope: scope(),
            priority: Priority::Routine,
            ttl_ms: None,
            logical_key: key.to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
        }
    }

    fn memory_node(
        identity_byte: u8,
        sealer: TestSealer,
        config: NodeConfig,
    ) -> Node<InMemoryStore, TestSealer> {
        let store = InMemoryStore::new(config.store.clone()).unwrap();
        Node::with_store([identity_byte; 32], store, sealer, config)
    }

    #[test]
    fn forwarded_control_activates_only_after_durable_chain_acceptance() {
        let sealer = ControlTrackingSealer::default();
        let authority = [0x51; 32];
        let accepted = b"accepted scope control".to_vec();
        let accepted_id = sealer.register_scope_epoch(accepted.clone(), authority, 1);
        let forked = b"forked scope control".to_vec();
        let forked_id = sealer.register_scope_epoch(forked, authority, 2);
        let store = InMemoryStore::new(StoreConfig::default()).unwrap();
        let mut node = Node::with_store([0x52; 32], store, sealer.clone(), NodeConfig::default());

        assert!(
            node.ingest_forwarded(authority, 7, accepted_id, &accepted, b"unauthenticated-hop")
                .is_err()
        );
        assert!(sealer.activated().is_empty());
        assert_eq!(node.store.scope_epoch(&scope()).unwrap(), 0);

        let accepted_outcome = node
            .ingest_forwarded(authority, 7, accepted_id, &accepted, b"authenticated-hop")
            .unwrap();
        assert!(matches!(
            accepted_outcome,
            ForwardedIngest::Control(ControlOutcome::Applied { .. })
        ));
        assert_eq!(node.store.scope_epoch(&scope()).unwrap(), 1);
        assert_eq!(sealer.activated(), vec![accepted.clone()]);

        let duplicate = node
            .ingest_forwarded(authority, 8, accepted_id, &accepted, b"authenticated-hop")
            .unwrap();
        assert!(matches!(
            duplicate,
            ForwardedIngest::Control(ControlOutcome::Duplicate { .. })
        ));
        assert_eq!(sealer.activated(), vec![accepted.clone()]);

        let fork_error = node
            .ingest_forwarded(
                authority,
                9,
                forked_id,
                b"forked scope control",
                b"authenticated-hop",
            )
            .unwrap_err();
        assert!(matches!(
            fork_error,
            EngineError::Store(StoreError::ControlFork)
        ));
        assert_eq!(node.store.scope_epoch(&scope()).unwrap(), 1);
        assert_eq!(sealer.activated(), vec![accepted]);
    }

    #[test]
    fn blob_idempotency_requires_the_exact_authenticated_route_commitment() {
        let mut node = memory_node(1, TestSealer::default(), NodeConfig::default());
        let id = BlobId::from_bytes([0x41; 32]);
        let stored_route = BlobRouteCommitment::from_authenticated_header(id, 2, [0x51; 32]);
        let finalized_route = BlobRouteCommitment::from_authenticated_header(id, 3, [0x61; 32]);
        let manifest = b"canonical manifest";
        node.publish_blob_manifest(
            request(DataClass::Blob, id.as_bytes(), manifest),
            stored_route,
        )
        .unwrap();

        assert!(
            node.find_authenticated_blob_manifest(&topic(), &scope(), id, manifest, stored_route,)
                .unwrap()
                .is_some()
        );
        assert!(
            node.find_authenticated_blob_manifest(
                &topic(),
                &scope(),
                id,
                manifest,
                finalized_route,
            )
            .is_err()
        );
        assert!(
            node.find_authenticated_blob_manifest(
                &topic(),
                &scope(),
                id,
                b"different manifest",
                stored_route,
            )
            .is_err()
        );
    }

    #[test]
    fn duplicate_ingest_is_idempotent_and_records_remain_siblings() {
        let sealer = TestSealer::default();
        let mut left = memory_node(1, sealer.clone(), NodeConfig::default());
        let mut right = memory_node(2, sealer.clone(), NodeConfig::default());
        let mut receiver = memory_node(3, sealer, NodeConfig::default());
        left.publish(request(DataClass::Record, b"plan", b"left"))
            .unwrap();
        right
            .publish(request(DataClass::Record, b"plan", b"right"))
            .unwrap();
        let left_wire = left.next_emissions([3; 32], 8, u64::MAX).unwrap();
        let right_wire = right.next_emissions([3; 32], 8, u64::MAX).unwrap();
        receiver.ingest(&left_wire[0].sealed).unwrap();
        let second = receiver.ingest(&right_wire[0].sealed).unwrap();
        assert!(matches!(
            second.outcome,
            ApplyOutcome::Inserted {
                conflict: Some(_),
                ..
            }
        ));
        let replay = receiver.ingest(&left_wire[0].sealed).unwrap();
        assert!(matches!(replay.outcome, ApplyOutcome::Duplicate { .. }));

        let conflicts = receiver
            .conflicts(StoreQuery {
                topic: Some(topic()),
                scope: Some(scope()),
                class: Some(DataClass::Record),
                logical_key: Some(b"plan".to_vec()),
                ..StoreQuery::default()
            })
            .unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].siblings.len(), 2);
        let receipt = receiver
            .resolve(ResolveRequest {
                topic: topic(),
                scope: scope(),
                logical_key: b"plan".to_vec(),
                expected_siblings: conflicts[0].siblings.clone(),
                payload: b"resolved".to_vec(),
                priority: Priority::Priority,
                ttl_ms: None,
            })
            .unwrap();
        assert_ne!(receipt.id, [0; 32]);
        assert!(
            receiver
                .conflicts(StoreQuery {
                    topic: Some(topic()),
                    scope: Some(scope()),
                    class: Some(DataClass::Record),
                    logical_key: Some(b"plan".to_vec()),
                    ..StoreQuery::default()
                })
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn event_gap_is_detected_per_publisher_stream() {
        let sealer = TestSealer::default();
        let mut sender = memory_node(7, sealer.clone(), NodeConfig::default());
        let mut receiver = memory_node(8, sealer, NodeConfig::default());
        for payload in [b"one".as_slice(), b"two", b"three"] {
            sender
                .publish(request(DataClass::Event, b"", payload))
                .unwrap();
        }
        let emissions = sender.next_emissions([8; 32], 8, u64::MAX).unwrap();
        receiver.ingest(&emissions[0].sealed).unwrap();
        receiver.ingest(&emissions[2].sealed).unwrap();
        let gaps = receiver
            .event_gaps(StoreQuery {
                topic: Some(topic()),
                scope: Some(scope()),
                ..StoreQuery::default()
            })
            .unwrap();
        assert_eq!(gaps.len(), 1);
        assert_eq!((gaps[0].start_sequence, gaps[0].end_sequence), (2, 3));
    }

    #[test]
    fn quota_evicts_lowest_priority_before_newer_critical_items() {
        let config = NodeConfig {
            store: StoreConfig {
                max_items: 2,
                max_bytes: 1_000_000,
                ..StoreConfig::default()
            },
            ..NodeConfig::default()
        };
        let mut node = memory_node(4, TestSealer::default(), config);
        let routine = node
            .publish(request(DataClass::State, b"routine", b"r"))
            .unwrap();
        let mut flash = request(DataClass::State, b"flash", b"f");
        flash.priority = Priority::Flash;
        node.publish(flash).unwrap();
        let mut immediate = request(DataClass::State, b"immediate", b"i");
        immediate.priority = Priority::Immediate;
        let third = node.publish(immediate).unwrap();
        assert_eq!(third.evicted, vec![routine.id]);
        let remaining = node
            .query(StoreQuery {
                include_recoverable_versions: true,
                ..StoreQuery::default()
            })
            .unwrap();
        assert_eq!(remaining.len(), 2);
        assert!(remaining.iter().all(|item| item.id != routine.id));
    }

    #[test]
    fn thirty_day_virtual_disconnect_keeps_durable_data_and_expires_perishable_data() {
        let clock = Arc::new(ManualClock::default());
        clock.set(1_000);
        let config = NodeConfig {
            clock: clock.clone(),
            ..NodeConfig::default()
        };
        let mut node = memory_node(5, TestSealer::default(), config);
        node.publish(request(DataClass::State, b"durable", b"keep"))
            .unwrap();
        let mut perishable = request(DataClass::State, b"perishable", b"drop");
        perishable.ttl_ms = Some(29 * 24 * 60 * 60 * 1_000);
        node.publish(perishable).unwrap();
        clock.set(1_000 + 30 * 24 * 60 * 60 * 1_000);
        assert_eq!(node.collect_garbage().unwrap().len(), 1);
        let items = node.query(StoreQuery::default()).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].payload, b"keep");
    }

    #[test]
    fn sqlite_publish_survives_drop_and_reopen_with_outbox() {
        let unique = format!(
            "aster-store-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        let sealer = TestSealer::default();
        let item_id;
        {
            let mut node =
                Node::open(&path, [9; 32], sealer.clone(), NodeConfig::default()).unwrap();
            item_id = node
                .publish(request(DataClass::State, b"status", b"offline"))
                .unwrap()
                .id;
        }
        {
            let mut reopened = Node::open(&path, [9; 32], sealer, NodeConfig::default()).unwrap();
            let items = reopened.query(StoreQuery::default()).unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].id, item_id);
            let emissions = reopened.next_emissions([10; 32], 2, u64::MAX).unwrap();
            assert_eq!(emissions.len(), 1);
            assert_eq!(emissions[0].id, item_id);
        }
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    #[test]
    fn global_chunk_ranges_resume_across_contacts() {
        let mut node = memory_node(11, TestSealer::default(), NodeConfig::default());
        let object: ItemId = Sha256::digest(b"abcdefghij").into();
        node.begin_object(object, 10, Priority::Priority).unwrap();
        assert!(!node.accept_object_chunk(object, 10, 4, b"efg").unwrap());
        assert_eq!(
            node.missing_object_ranges(object, 8).unwrap(),
            vec![
                ChunkRange { start: 0, end: 4 },
                ChunkRange { start: 7, end: 10 }
            ]
        );
        assert!(!node.accept_object_chunk(object, 10, 0, b"abcd").unwrap());
        assert!(node.accept_object_chunk(object, 10, 7, b"hij").unwrap());
        assert!(node.missing_object_ranges(object, 8).unwrap().is_empty());
        assert_eq!(
            node.read_object_range(object, ChunkRange { start: 0, end: 10 }, 10)
                .unwrap(),
            b"abcdefghij"
        );
    }

    #[test]
    fn application_ack_does_not_require_wall_time() {
        let config = NodeConfig {
            clock: Arc::new(UnavailableClock),
            ..NodeConfig::default()
        };
        let mut node = memory_node(12, TestSealer::default(), config);
        let published = node
            .publish(request(DataClass::State, b"status", b"ready"))
            .unwrap();
        let subscription = node
            .subscribe(SubscriptionSpec {
                topic: topic(),
                scope: scope(),
                include_descendant_scopes: false,
                class: Some(DataClass::State),
            })
            .unwrap();
        let first = node.poll(subscription, 4).unwrap();
        assert_eq!(first.len(), 1);
        node.acknowledge(subscription, published.id).unwrap();
        assert!(node.poll(subscription, 4).unwrap().is_empty());
    }

    #[test]
    fn unavailable_time_withholds_finite_ttl_but_not_durable_data() {
        let config = NodeConfig {
            clock: Arc::new(UnavailableClock),
            ..NodeConfig::default()
        };
        let mut node = memory_node(16, TestSealer::default(), config);
        let durable = node
            .publish(request(DataClass::Event, b"stream", b"durable"))
            .unwrap();
        let mut perishable = request(DataClass::State, b"position", b"recent");
        perishable.ttl_ms = Some(60_000);
        let perishable = node.publish(perishable).unwrap();

        let emissions = node.next_emissions([17; 32], 4, u64::MAX).unwrap();
        assert_eq!(emissions.len(), 1);
        assert_eq!(emissions[0].id, durable.id);
        assert_ne!(emissions[0].id, perishable.id);
        assert_eq!(node.query(StoreQuery::default()).unwrap().len(), 2);
    }

    #[test]
    fn receive_only_suppresses_emission_but_not_ingest() {
        let sealer = TestSealer::default();
        let mut sender = memory_node(13, sealer.clone(), NodeConfig::default());
        sender
            .publish(request(DataClass::State, b"position", b"north"))
            .unwrap();
        sender.set_emission_policy(EmissionPolicy::receive_only());
        assert!(!sender.may_advertise());
        assert!(
            sender
                .next_emissions([14; 32], 4, u64::MAX)
                .unwrap()
                .is_empty()
        );
        sender.set_emission_policy(EmissionPolicy::default());
        let wire = sender.next_emissions([14; 32], 4, u64::MAX).unwrap();

        let mut receiver = memory_node(
            14,
            sealer,
            NodeConfig {
                emission: EmissionPolicy::receive_only(),
                ..NodeConfig::default()
            },
        );
        receiver.ingest(&wire[0].sealed).unwrap();
        assert_eq!(receiver.query(StoreQuery::default()).unwrap().len(), 1);
        assert!(
            receiver
                .next_emissions([15; 32], 4, u64::MAX)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn tombstone_retention_outlives_item_ttl_and_prevents_resurrection() {
        let clock = Arc::new(ManualClock::default());
        let config = NodeConfig {
            store: StoreConfig {
                tombstone_retention_ms: 100,
                superseded_retention_ms: 1_000,
                ..StoreConfig::default()
            },
            clock: clock.clone(),
            ..NodeConfig::default()
        };
        let mut node = memory_node(15, TestSealer::default(), config);
        node.publish(request(DataClass::State, b"track", b"present"))
            .unwrap();
        let mut deletion = request(DataClass::State, b"track", b"");
        deletion.tombstone = true;
        deletion.ttl_ms = Some(1);
        node.publish(deletion).unwrap();
        clock.set(99);
        assert!(node.collect_garbage().unwrap().is_empty());
        assert!(node.query(StoreQuery::default()).unwrap().is_empty());
        clock.set(100);
        assert_eq!(node.collect_garbage().unwrap().len(), 2);
        assert!(
            node.query(StoreQuery {
                include_recoverable_versions: true,
                include_tombstones: true,
                ..StoreQuery::default()
            })
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn completed_object_must_match_content_address() {
        let mut node = memory_node(16, TestSealer::default(), NodeConfig::default());
        let false_address = [99; 32];
        node.begin_object(false_address, 3, Priority::Routine)
            .unwrap();
        assert!(
            node.accept_object_chunk(false_address, 3, 0, b"bad")
                .is_err()
        );
        assert_eq!(
            node.missing_object_ranges(false_address, 4).unwrap(),
            vec![ChunkRange { start: 0, end: 3 }]
        );
    }
}
