//! High-level application API.
//!
//! This facade owns the reference engine and deliberately omits sealed-object
//! ingest/emission, handshake, inventory, range, fragmentation, link, and
//! cryptographic-provider operations. Transport adapters use the separately
//! versioned `adapter-sdk` feature instead.

use crate::blob::{
    BlobId, BlobStoreConfig, FileBlobStore, FinishedBlob, ReferenceBlobReader, ReferenceBlobService,
};
use crate::bridge_service::{
    BridgeCommitDisposition as InternalBridgeCommitDisposition, CreatedBridgeRoute,
    DisableBridgeAuthorizationRequest, EnableBridgeAuthorizationRequest, IssuedBridgeAuthorization,
    LocalBridgeNarrowing,
};
use crate::crypto::{
    BridgeCryptoProvider, BridgeEdgeEnrollment, ProvisioningBundle, ReferenceNode,
    ScopeRekeyRecipient as CryptoScopeRekeyRecipient, open_reference_node,
};
use crate::engine::{
    ApplicationItem as EngineApplicationItem, BatchPublishItem as EngineBatchPublishItem,
    BatchPublishReceipt as EngineBatchPublishReceipt, Delivery as EngineDelivery, EmissionPolicy,
    EngineError, NodeConfig, PublishReceipt as EnginePublishReceipt, PublishRequest,
    RecordMergePolicy, RecordVersion, ResolveRequest,
};
use crate::model::{ConflictAnnotation, DataClass, ItemId, NodeId, Priority, Scope, Topic};
use crate::provisioning::ProvisioningUnprotector;
use crate::store::{
    BatchStoragePolicy, BridgeAuthorizationCursor, BridgeFilter, EventGap, PeerSnapshot,
    QuotaUsage, RecordStore, StoreConfig, StoreQuery, StoredBridgeAuthorization, StoredBridgeRoute,
    SubscriptionId, SubscriptionSpec,
};
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

const MAX_APPLICATION_PAGE: usize = 4_096;

/// Successful local publication without exposing the internal causal clock.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishResult {
    pub id: ItemId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub event_sequence: Option<u64>,
    pub effective_priority: Priority,
    pub evicted: Vec<ItemId>,
}

impl From<EnginePublishReceipt> for PublishResult {
    fn from(value: EnginePublishReceipt) -> Self {
        Self {
            id: value.id,
            publisher: value.stamp.dot.publisher,
            publisher_counter: value.stamp.dot.counter,
            event_sequence: value.event_sequence,
            effective_priority: value.effective_priority,
            evicted: value.evicted,
        }
    }
}

impl From<EngineBatchPublishReceipt> for BatchPublishResult {
    fn from(value: EngineBatchPublishReceipt) -> Self {
        Self {
            items: value.items.into_iter().map(Into::into).collect(),
            evicted: value.evicted,
        }
    }
}

/// Source-retention policy for one explicit atomic batch publication.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BatchPublicationPolicy {
    /// Retain a semantic-v1 singleton alongside every compact item so an
    /// intermittent future version-1 peer remains reachable. This is the safe
    /// offline-first default.
    #[default]
    RetainedDual,
    /// Retain only the semantic-v2 proof and compact representations.
    BatchOnly,
}

/// One explicit, bounded batch commit. Items must share class, topic, scope,
/// and the active epoch; the publisher is always the local node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchPublishRequest {
    pub items: Vec<PublishRequest>,
    pub policy: BatchPublicationPolicy,
}

impl BatchPublishRequest {
    /// Creates the default retained-dual publication request.
    pub fn new(items: Vec<PublishRequest>) -> Self {
        Self {
            items,
            policy: BatchPublicationPolicy::RetainedDual,
        }
    }

    /// Explicitly opts out of future semantic-v1 delivery for this batch.
    pub fn batch_only(items: Vec<PublishRequest>) -> Self {
        Self {
            items,
            policy: BatchPublicationPolicy::BatchOnly,
        }
    }
}

/// Successful atomic batch commit without proof, signature, or wire details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchPublishResult {
    pub items: Vec<PublishResult>,
    /// Aggregate victims from the one atomic post-insert quota pass.
    pub evicted: Vec<ItemId>,
}

/// One finalized Blob manifest in an explicit atomic batch. The authenticated
/// route commitment remains encapsulated by [`FinishedBlob`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinishedBlobBatchItem {
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub ttl_ms: Option<u64>,
    pub finished: FinishedBlob,
}

/// Explicit atomic batch of finalized Blob manifests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FinishedBlobBatchRequest {
    pub items: Vec<FinishedBlobBatchItem>,
    pub policy: BatchPublicationPolicy,
}

impl FinishedBlobBatchRequest {
    /// Creates the default retained-dual Blob batch.
    pub fn new(items: Vec<FinishedBlobBatchItem>) -> Self {
        Self {
            items,
            policy: BatchPublicationPolicy::RetainedDual,
        }
    }

    /// Explicitly opts this Blob batch out of future semantic-v1 delivery.
    pub fn batch_only(items: Vec<FinishedBlobBatchItem>) -> Self {
        Self {
            items,
            policy: BatchPublicationPolicy::BatchOnly,
        }
    }
}

fn internal_batch_policy(policy: BatchPublicationPolicy) -> BatchStoragePolicy {
    match policy {
        BatchPublicationPolicy::RetainedDual => BatchStoragePolicy::RetainedDual,
        BatchPublicationPolicy::BatchOnly => BatchStoragePolicy::BatchOnly,
    }
}

fn publish_application_batch(
    node: &mut ReferenceNode,
    request: BatchPublishRequest,
) -> Result<BatchPublishResult, EngineError> {
    if request
        .items
        .iter()
        .any(|item| item.class == DataClass::Blob)
    {
        return Err(EngineError::Invalid(
            "Blob batch publication requires finalized Blob inputs".into(),
        ));
    }
    let policy = internal_batch_policy(request.policy);
    let items = request
        .items
        .into_iter()
        .map(|request| EngineBatchPublishItem {
            request,
            blob_route: None,
        })
        .collect();
    node.publish_reference_batch(items, policy).map(Into::into)
}

fn publish_finished_blob_application_batch(
    node: &mut ReferenceNode,
    request: FinishedBlobBatchRequest,
) -> Result<BatchPublishResult, EngineError> {
    let policy = internal_batch_policy(request.policy);
    let items = request
        .items
        .into_iter()
        .map(|item| {
            let logical_key = item.finished.id().as_bytes().to_vec();
            let payload = item.finished.manifest_bytes().to_vec();
            let blob_route = item.finished.route_commitment();
            EngineBatchPublishItem {
                request: PublishRequest {
                    class: DataClass::Blob,
                    topic: item.topic,
                    scope: item.scope,
                    priority: item.priority,
                    ttl_ms: item.ttl_ms,
                    logical_key,
                    payload,
                    tombstone: false,
                },
                blob_route: Some(blob_route),
            }
        })
        .collect();
    node.publish_reference_batch(items, policy).map(Into::into)
}

/// High-level read access assigned to one fresh scope epoch recipient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RekeyRecipientAccess {
    /// May route protected metadata and opaque payloads but receives no content key.
    RouteOnly,
    /// May route and read only the listed topics.
    ReadTopics(Vec<Topic>),
}

/// One authority-selected recipient without public keys or key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RekeyRecipient {
    node: NodeId,
    access: RekeyRecipientAccess,
}

impl RekeyRecipient {
    /// Selects an explicit routing-only recipient.
    pub fn route_only(node: NodeId) -> Self {
        Self {
            node,
            access: RekeyRecipientAccess::RouteOnly,
        }
    }

    /// Selects a recipient that may read exactly the supplied topics.
    pub fn read_topics(node: NodeId, topics: Vec<Topic>) -> Result<Self, EngineError> {
        CryptoScopeRekeyRecipient::member(node, topics.clone()).map_err(EngineError::Envelope)?;
        Ok(Self {
            node,
            access: RekeyRecipientAccess::ReadTopics(topics),
        })
    }

    pub fn node(&self) -> NodeId {
        self.node
    }

    pub fn access(&self) -> &RekeyRecipientAccess {
        &self.access
    }

    fn into_crypto(self) -> Result<CryptoScopeRekeyRecipient, EngineError> {
        match self.access {
            RekeyRecipientAccess::RouteOnly => Ok(CryptoScopeRekeyRecipient::route_only(self.node)),
            RekeyRecipientAccess::ReadTopics(topics) => {
                CryptoScopeRekeyRecipient::member(self.node, topics).map_err(EngineError::Envelope)
            }
        }
    }
}

/// High-level receipt for one durably chained fresh scope epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeRekeyResult {
    pub scope: Scope,
    pub epoch: u64,
    pub registry_generation: u64,
    pub recipient_count: usize,
    pub control_sequence: u64,
}

/// Move-only, bridge-node-signed enrollment for one exact directed edge.
///
/// The application may hand this value to an authority node, but cannot read
/// or serialize its provider-owned credential, signatures, or route-grant
/// commitments. Creating it never grants authority by itself.
pub struct BridgeEnrollment {
    inner: BridgeEdgeEnrollment,
    bridge_node: NodeId,
    source_scope: Scope,
    source_route_epoch: u64,
    target_scope: Scope,
    target_route_epoch: u64,
}

impl fmt::Debug for BridgeEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BridgeEnrollment")
            .field("bridge_node", &self.bridge_node)
            .field("source_scope", &self.source_scope)
            .field("source_route_epoch", &self.source_route_epoch)
            .field("target_scope", &self.target_scope)
            .field("target_route_epoch", &self.target_route_epoch)
            .field("authenticated_artifact", &"[PROVIDER-OWNED]")
            .field("key_material", &"[NONE]")
            .finish()
    }
}

impl BridgeEnrollment {
    pub fn bridge_node(&self) -> NodeId {
        self.bridge_node
    }

    pub fn source_scope(&self) -> &Scope {
        &self.source_scope
    }

    pub fn source_route_epoch(&self) -> u64 {
        self.source_route_epoch
    }

    pub fn target_scope(&self) -> &Scope {
        &self.target_scope
    }

    pub fn target_route_epoch(&self) -> u64 {
        self.target_route_epoch
    }
}

/// Authority policy attached to one verified bridge enrollment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeAuthorizationPolicy {
    topics: Vec<Topic>,
    allowed_priorities: Vec<Priority>,
    max_total_hops: u8,
}

impl BridgeAuthorizationPolicy {
    /// Creates canonical, bounded authority policy. Duplicate values are
    /// collapsed and the path bound must be between one and eight hops.
    pub fn new(
        topics: Vec<Topic>,
        allowed_priorities: Vec<Priority>,
        max_total_hops: u8,
    ) -> Result<Self, EngineError> {
        let topics = topics.into_iter().collect::<BTreeSet<_>>();
        let allowed_priorities = allowed_priorities.into_iter().collect::<BTreeSet<_>>();
        if topics.is_empty()
            || topics.len() > crate::bridge::MAX_TOPICS
            || allowed_priorities.is_empty()
            || max_total_hops == 0
            || usize::from(max_total_hops) > crate::bridge::MAX_HOPS
        {
            return Err(EngineError::Invalid(
                "bridge authorization policy is empty or exceeds protocol bounds".into(),
            ));
        }
        Ok(Self {
            topics: topics.into_iter().collect(),
            allowed_priorities: allowed_priorities.into_iter().collect(),
            max_total_hops,
        })
    }

    pub fn topics(&self) -> &[Topic] {
        &self.topics
    }

    pub fn allowed_priorities(&self) -> &[Priority] {
        &self.allowed_priorities
    }

    pub fn max_total_hops(&self) -> u8 {
        self.max_total_hops
    }
}

/// Local policy intersection applied only to the newly-created hop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeNarrowingPolicy {
    topics: Vec<Topic>,
    allowed_priorities: Vec<Priority>,
}

impl BridgeNarrowingPolicy {
    /// An empty topic list means every topic still allowed by the signed
    /// authority object. Priorities are always explicit and nonempty.
    pub fn new(topics: Vec<Topic>, allowed_priorities: Vec<Priority>) -> Result<Self, EngineError> {
        let topics = topics.into_iter().collect::<BTreeSet<_>>();
        let allowed_priorities = allowed_priorities.into_iter().collect::<BTreeSet<_>>();
        let value = Self {
            topics: topics.into_iter().collect(),
            allowed_priorities: allowed_priorities.into_iter().collect(),
        };
        value.clone().into_internal()?;
        Ok(value)
    }

    pub fn topics(&self) -> &[Topic] {
        &self.topics
    }

    pub fn allowed_priorities(&self) -> &[Priority] {
        &self.allowed_priorities
    }

    fn into_internal(self) -> Result<LocalBridgeNarrowing, EngineError> {
        LocalBridgeNarrowing::new(self.topics, self.allowed_priorities)
            .map_err(|error| EngineError::Invalid(error.to_string()))
    }
}

/// Exact directed edge selected for an authority disable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeEdge {
    bridge_node: NodeId,
    source_scope: Scope,
    target_scope: Scope,
}

impl BridgeEdge {
    pub fn new(
        bridge_node: NodeId,
        source_scope: Scope,
        target_scope: Scope,
    ) -> Result<Self, EngineError> {
        DisableBridgeAuthorizationRequest::new(
            bridge_node,
            source_scope.clone(),
            target_scope.clone(),
        )
        .map_err(|error| EngineError::Invalid(error.to_string()))?;
        Ok(Self {
            bridge_node,
            source_scope,
            target_scope,
        })
    }

    pub fn bridge_node(&self) -> NodeId {
        self.bridge_node
    }

    pub fn source_scope(&self) -> &Scope {
        &self.source_scope
    }

    pub fn target_scope(&self) -> &Scope {
        &self.target_scope
    }
}

/// Opaque durable identifier for one signed bridge authorization control.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BridgeAuthorizationId([u8; 32]);

impl BridgeAuthorizationId {
    pub const BYTE_LEN: usize = 32;

    pub const fn from_bytes(bytes: [u8; Self::BYTE_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, EngineError> {
        let bytes = <[u8; Self::BYTE_LEN]>::try_from(bytes).map_err(|_| {
            EngineError::Invalid("bridge authorization identifier must be exactly 32 bytes".into())
        })?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; Self::BYTE_LEN] {
        self.0
    }
}

impl TryFrom<&[u8]> for BridgeAuthorizationId {
    type Error = EngineError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

/// High-level authority receipt without the sealed control or provider tokens.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeAuthorizationResult {
    pub id: BridgeAuthorizationId,
    pub generation: u64,
    pub control_sequence: u64,
    pub enabled: bool,
}

impl From<IssuedBridgeAuthorization> for BridgeAuthorizationResult {
    fn from(value: IssuedBridgeAuthorization) -> Self {
        Self {
            id: BridgeAuthorizationId(value.envelope_id),
            generation: value.generation,
            control_sequence: value.control_sequence,
            enabled: value.enabled,
        }
    }
}

/// Opaque handle to one durable bridge wrapper. It is sufficient to request
/// the next hop but reveals no wrapper bytes or route descriptor.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BridgeRouteHandle([u8; 32]);

impl BridgeRouteHandle {
    pub const BYTE_LEN: usize = 32;

    pub const fn from_bytes(bytes: [u8; Self::BYTE_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, EngineError> {
        let bytes = <[u8; Self::BYTE_LEN]>::try_from(bytes).map_err(|_| {
            EngineError::Invalid("bridge route handle must be exactly 32 bytes".into())
        })?;
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; Self::BYTE_LEN] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; Self::BYTE_LEN] {
        self.0
    }
}

impl TryFrom<&[u8]> for BridgeRouteHandle {
    type Error = EngineError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(value)
    }
}

/// Provider-authenticated durable bridge-control status. No sealed bytes,
/// credentials, route commitments, or key handles are exposed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeAuthorizationStatus {
    pub id: BridgeAuthorizationId,
    pub authority: NodeId,
    pub bridge_node: NodeId,
    pub source_scope: Scope,
    pub target_scope: Scope,
    pub generation: u64,
    pub control_sequence: u64,
    pub applied: bool,
    pub current: bool,
    pub enabled: bool,
    pub usable: bool,
    pub source_route_epoch: Option<u64>,
    pub target_route_epoch: Option<u64>,
    pub topics: Vec<Topic>,
    pub allowed_priorities: Vec<Priority>,
    pub max_total_hops: Option<u8>,
}

/// Provider-authenticated durable bridge route status without wrapper/source
/// carrier bytes or provider capabilities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeRouteStatus {
    pub handle: BridgeRouteHandle,
    pub source_item: ItemId,
    pub origin_scope: Scope,
    pub origin_route_epoch: u64,
    pub current_scope: Scope,
    pub current_route_epoch: u64,
    pub topic: Topic,
    pub priority: Priority,
    pub hop_count: u8,
    pub active: bool,
    pub live: bool,
}

/// Durable selection result after atomic wrapper/source promotion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeCommitStatus {
    Active,
    RetainedAlternate,
    DuplicateActive,
    DuplicateInactive,
}

/// High-level result of creating one bridge hop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeRouteResult {
    pub handle: BridgeRouteHandle,
    pub source_item: ItemId,
    pub current_scope: Scope,
    pub current_route_epoch: u64,
    pub hop_count: u8,
    pub status: BridgeCommitStatus,
}

impl From<CreatedBridgeRoute> for BridgeRouteResult {
    fn from(value: CreatedBridgeRoute) -> Self {
        Self {
            handle: BridgeRouteHandle(value.wrapper_envelope_id),
            source_item: value.source_item_id,
            current_scope: value.current_scope,
            current_route_epoch: value.current_route_epoch,
            hop_count: value.hop_count,
            status: match value.disposition {
                InternalBridgeCommitDisposition::Active => BridgeCommitStatus::Active,
                InternalBridgeCommitDisposition::RetainedAlternate => {
                    BridgeCommitStatus::RetainedAlternate
                }
                InternalBridgeCommitDisposition::DuplicateActive => {
                    BridgeCommitStatus::DuplicateActive
                }
                InternalBridgeCommitDisposition::DuplicateInactive => {
                    BridgeCommitStatus::DuplicateInactive
                }
            },
        }
    }
}

fn validate_bridge_page_limit(limit: usize) -> Result<(), EngineError> {
    if limit == 0 || limit > MAX_APPLICATION_PAGE {
        return Err(EngineError::Invalid(
            "bridge administration page limit must be between 1 and 4096".into(),
        ));
    }
    Ok(())
}

fn authenticated_bridge_authorization_status(
    node: &mut ReferenceNode,
    stored: StoredBridgeAuthorization,
) -> Result<BridgeAuthorizationStatus, EngineError> {
    let verified = node
        .envelopes()
        .open_bridge_authorization(&stored.exact_bytes)?;
    let envelope = verified.envelope().clone();
    if envelope.envelope_id != stored.envelope_id || envelope.authorization != stored.authorization
    {
        return Err(EngineError::Invalid(
            "durable bridge authorization differs from provider verification".into(),
        ));
    }
    let authorization = envelope.authorization;
    let current = node
        .store()
        .active_bridge_authorization(&authorization.authorization_key)?
        .is_some_and(|active| active.envelope_id == stored.envelope_id && active.applied);
    let authority_revoked = node.store_mut().is_revoked(&authorization.authority_id)?;
    let bridge_node_revoked = node.store_mut().is_revoked(&authorization.bridge_node_id)?;
    let source_epoch = node.store_mut().scope_epoch(&authorization.source_scope)?;
    let target_epoch = node.store_mut().scope_epoch(&authorization.target_scope)?;
    let enabled = authorization.enabled.as_ref();
    let usable = stored.applied
        && current
        && !authority_revoked
        && !bridge_node_revoked
        && enabled.is_some_and(|policy| {
            policy.source_route_epoch == source_epoch && policy.target_route_epoch == target_epoch
        });
    let allowed_priorities = enabled
        .map(|policy| {
            [
                Priority::Routine,
                Priority::Priority,
                Priority::Immediate,
                Priority::Flash,
            ]
            .into_iter()
            .filter(|priority| {
                crate::bridge::priority_allowed(policy.allowed_priority_mask, *priority)
            })
            .collect()
        })
        .unwrap_or_default();
    Ok(BridgeAuthorizationStatus {
        id: BridgeAuthorizationId(stored.envelope_id),
        authority: authorization.authority_id,
        bridge_node: authorization.bridge_node_id,
        source_scope: authorization.source_scope,
        target_scope: authorization.target_scope,
        generation: authorization.generation,
        control_sequence: authorization.control_sequence,
        applied: stored.applied,
        current,
        enabled: enabled.is_some(),
        usable,
        source_route_epoch: enabled.map(|policy| policy.source_route_epoch),
        target_route_epoch: enabled.map(|policy| policy.target_route_epoch),
        topics: enabled
            .map(|policy| policy.topics.clone())
            .unwrap_or_default(),
        allowed_priorities,
        max_total_hops: enabled.map(|policy| policy.max_total_hops),
    })
}

fn authenticated_bridge_route_status(
    node: &mut ReferenceNode,
    stored: StoredBridgeRoute,
) -> Result<BridgeRouteStatus, EngineError> {
    let wrapper = node
        .envelopes()
        .open_bridge_wrapper_for_any_local_route(&stored.exact_wrapper_bytes)?;
    let source = node
        .envelopes()
        .verify_bridge_wrapper_source(&wrapper, &stored.exact_source_bytes)?;
    let route = wrapper.route();
    let header = source.header();
    if wrapper.wrapper_envelope_id() != stored.wrapper_envelope_id
        || route.bridge_route_id != stored.bridge_route_id
        || route.origin_envelope_id != stored.origin_envelope_id
        || route.source_item_id != stored.source_item_id
        || route.origin_scope != stored.origin_scope
        || route.origin_route_epoch != stored.origin_route_epoch
        || route.current_scope != stored.current_scope
        || route.current_route_epoch != stored.current_route_epoch
        || route.hops.len() != usize::from(stored.hop_count)
        || source.origin_envelope_id() != stored.origin_envelope_id
        || source.source_item_id() != stored.source_item_id
        || header.scope != stored.origin_scope
        || header.key_epoch != stored.origin_route_epoch
        || header.topic != stored.topic
        || header.priority != stored.priority
    {
        return Err(EngineError::Invalid(
            "durable bridge route differs from provider verification".into(),
        ));
    }
    let sample = node.custody_sample();
    let live = node
        .store()
        .bridge_route_is_live_at(&stored.wrapper_envelope_id, sample)?;
    Ok(BridgeRouteStatus {
        handle: BridgeRouteHandle(stored.wrapper_envelope_id),
        source_item: stored.source_item_id,
        origin_scope: stored.origin_scope,
        origin_route_epoch: stored.origin_route_epoch,
        current_scope: stored.current_scope,
        current_route_epoch: stored.current_route_epoch,
        topic: stored.topic,
        priority: stored.priority,
        hop_count: stored.hop_count,
        active: stored.active,
        live,
    })
}

fn bridge_authorization_status_for_node(
    node: &mut ReferenceNode,
    id: BridgeAuthorizationId,
) -> Result<Option<BridgeAuthorizationStatus>, EngineError> {
    let Some(stored) = node.store().stored_bridge_authorization(&id.0)? else {
        return Ok(None);
    };
    authenticated_bridge_authorization_status(node, stored).map(Some)
}

fn bridge_authorizations_for_node(
    node: &mut ReferenceNode,
    after: Option<BridgeAuthorizationId>,
    limit: usize,
) -> Result<Vec<BridgeAuthorizationStatus>, EngineError> {
    validate_bridge_page_limit(limit)?;
    let mut cursor = after
        .map(|id| {
            node.store()
                .stored_bridge_authorization(&id.0)?
                .map(|stored| BridgeAuthorizationCursor {
                    authority_id: stored.authorization.authority_id,
                    sequence: stored.authorization.control_sequence,
                })
                .ok_or_else(|| {
                    EngineError::Invalid("bridge authorization page cursor was not found".into())
                })
        })
        .transpose()?;
    let mut statuses = Vec::with_capacity(limit);
    while statuses.len() < limit {
        let page = node
            .store()
            .stored_bridge_authorizations_after(cursor, limit - statuses.len())?;
        if page.is_empty() {
            break;
        }
        cursor = page.last().map(|stored| BridgeAuthorizationCursor {
            authority_id: stored.authorization.authority_id,
            sequence: stored.authorization.control_sequence,
        });
        for stored in page {
            statuses.push(authenticated_bridge_authorization_status(node, stored)?);
        }
    }
    Ok(statuses)
}

fn bridge_route_status_for_node(
    node: &mut ReferenceNode,
    handle: BridgeRouteHandle,
) -> Result<Option<BridgeRouteStatus>, EngineError> {
    let Some(stored) = node.store().stored_bridge_route(&handle.0)? else {
        return Ok(None);
    };
    authenticated_bridge_route_status(node, stored).map(Some)
}

fn bridge_routes_for_node(
    node: &mut ReferenceNode,
    after: Option<BridgeRouteHandle>,
    limit: usize,
) -> Result<Vec<BridgeRouteStatus>, EngineError> {
    validate_bridge_page_limit(limit)?;
    let mut cursor = after
        .map(|handle| {
            node.store()
                .stored_bridge_route(&handle.0)?
                .map(|stored| stored.inserted_order)
                .ok_or_else(|| {
                    EngineError::Invalid("bridge route page cursor was not found".into())
                })
        })
        .transpose()?;
    let mut statuses = Vec::with_capacity(limit);
    while statuses.len() < limit {
        let page = node
            .store()
            .stored_bridge_routes_after(cursor, limit - statuses.len())?;
        if page.is_empty() {
            break;
        }
        cursor = page.last().map(|stored| stored.inserted_order);
        for stored in page {
            statuses.push(authenticated_bridge_route_status(node, stored)?);
        }
    }
    Ok(statuses)
}

/// Decrypted application item with only the publisher counter needed by UI and audit code.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Item {
    pub id: ItemId,
    pub class: DataClass,
    pub topic: Topic,
    pub scope: Scope,
    pub origin_scope: Scope,
    pub current_scope: Scope,
    pub priority: Priority,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub event_sequence: Option<u64>,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
}

impl From<EngineApplicationItem> for Item {
    fn from(value: EngineApplicationItem) -> Self {
        Self {
            id: value.id,
            class: value.class,
            topic: value.topic,
            scope: value.scope,
            origin_scope: value.origin_scope,
            current_scope: value.current_scope,
            priority: value.priority,
            publisher: value.publisher,
            publisher_counter: value.stamp.dot.counter,
            event_sequence: value.event_sequence,
            logical_key: value.logical_key,
            payload: value.payload,
            tombstone: value.tombstone,
        }
    }
}

/// At-least-once application delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Delivery {
    pub subscription: SubscriptionId,
    pub attempt: u64,
    pub item: Item,
}

impl From<EngineDelivery> for Delivery {
    fn from(value: EngineDelivery) -> Self {
        Self {
            subscription: value.subscription,
            attempt: value.attempt,
            item: value.item.into(),
        }
    }
}

/// Input to an explicit application merge helper.
///
/// Callers MUST supply versions in ascending full-ItemID order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MergeVersion {
    pub id: ItemId,
    pub publisher: NodeId,
    pub payload: Vec<u8>,
    pub tombstone: bool,
}

/// Process-local Record policy descriptor and explicit-resolution helper.
///
/// Registration lets high-level conflict results report [`Self::id`]; it is not
/// durable, and the node retains only that identifier rather than this
/// executable object. Replicated ingestion never invokes [`Self::merge`].
/// Applications may retain and invoke their helper over inspected siblings
/// before submitting [`ResolveRequest`].
///
/// For identical canonical inputs, [`Self::merge`] MUST return identical bytes
/// across every supported implementation and version. Aster does not verify
/// that application-level conformance obligation.
pub trait ApplicationMergePolicy: Send + Sync {
    fn id(&self) -> &str;
    fn merge(&self, versions: &[MergeVersion]) -> Result<Vec<u8>, String>;
}

struct MergePolicyAdapter(Arc<dyn ApplicationMergePolicy>);

impl RecordMergePolicy for MergePolicyAdapter {
    fn id(&self) -> &str {
        self.0.id()
    }

    fn merge(&self, versions: &[RecordVersion]) -> Result<Vec<u8>, String> {
        let values = versions
            .iter()
            .map(|value| MergeVersion {
                id: value.id,
                publisher: value.publisher,
                payload: value.payload.clone(),
                tombstone: value.tombstone,
            })
            .collect::<Vec<_>>();
        self.0.merge(&values)
    }
}

/// Bounded storage and publication policy for an application node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicationNodeOptions {
    pub max_items: u64,
    pub max_bytes: u64,
    pub tombstone_retention_ms: u64,
    pub superseded_retention_ms: u64,
    pub priority_cap: Priority,
    pub emission: EmissionPolicy,
}

impl Default for ApplicationNodeOptions {
    fn default() -> Self {
        let store = StoreConfig::default();
        Self {
            max_items: store.max_items,
            max_bytes: store.max_bytes,
            tombstone_retention_ms: store.tombstone_retention_ms,
            superseded_retention_ms: store.superseded_retention_ms,
            priority_cap: Priority::Flash,
            emission: EmissionPolicy::default(),
        }
    }
}

impl ApplicationNodeOptions {
    fn into_engine(self) -> Result<NodeConfig, EngineError> {
        if self.max_items == 0
            || self.max_bytes == 0
            || self.tombstone_retention_ms == 0
            || self.superseded_retention_ms == 0
        {
            return Err(EngineError::Invalid(
                "node storage and retention limits must be nonzero".into(),
            ));
        }
        Ok(NodeConfig {
            store: StoreConfig {
                max_items: self.max_items,
                max_bytes: self.max_bytes,
                tombstone_retention_ms: self.tombstone_retention_ms,
                superseded_retention_ms: self.superseded_retention_ms,
            },
            emission: self.emission,
            priority_cap: self.priority_cap,
            ..NodeConfig::default()
        })
    }
}

/// Application query with a mandatory bounded page size.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Query {
    pub topic: Option<Topic>,
    pub scope: Option<Scope>,
    pub include_descendant_scopes: bool,
    pub class: Option<DataClass>,
    pub logical_key: Option<Vec<u8>>,
    pub include_recoverable_versions: bool,
    pub include_tombstones: bool,
    pub limit: usize,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            topic: None,
            scope: None,
            include_descendant_scopes: false,
            class: None,
            logical_key: None,
            include_recoverable_versions: false,
            include_tombstones: false,
            limit: 100,
        }
    }
}

impl Query {
    fn into_store(self) -> Result<StoreQuery, EngineError> {
        if self.limit == 0 || self.limit > MAX_APPLICATION_PAGE {
            return Err(EngineError::Invalid(
                "query limit must be between 1 and 4096".into(),
            ));
        }
        Ok(StoreQuery {
            topic: self.topic,
            scope: self.scope,
            include_descendant_scopes: self.include_descendant_scopes,
            class: self.class,
            logical_key: self.logical_key,
            include_recoverable_versions: self.include_recoverable_versions,
            include_tombstones: self.include_tombstones,
            limit: Some(self.limit),
            ..StoreQuery::default()
        })
    }
}

/// Offline-first reference node with application operations only.
pub struct ApplicationNode {
    inner: ReferenceNode,
}

impl ApplicationNode {
    /// Opens and authenticates a canonical unprotected inner bundle.
    ///
    /// This raw-byte entry point exists for compatibility, tests, and controlled migration. It
    /// does not protect provisioning material at rest. Operational Rust callers should use
    /// [`Self::open_protected`] with an admitted provider.
    pub fn open(
        path: impl AsRef<Path>,
        provisioning_bundle: &[u8],
        options: ApplicationNodeOptions,
    ) -> Result<Self, EngineError> {
        let config = options.into_engine()?;
        let bundle = ProvisioningBundle::from_bytes(provisioning_bundle)?;
        Self::open_bundle(path, bundle, config)
    }

    /// Authenticates and opens a provider-protected provisioning artifact.
    ///
    /// Local options are validated first. A nonempty bounded outer artifact invokes the
    /// unprotector exactly once; empty, oversized, or raw-inner input invokes it zero times.
    /// Failure is returned before the node store is opened, and the method never retries by
    /// treating the artifact as plaintext.
    pub fn open_protected<P>(
        path: impl AsRef<Path>,
        protected_bundle: &[u8],
        unprotector: &mut P,
        options: ApplicationNodeOptions,
    ) -> Result<Self, EngineError>
    where
        P: ProvisioningUnprotector + ?Sized,
    {
        let config = options.into_engine()?;
        let bundle = ProvisioningBundle::from_protected_bytes(protected_bundle, unprotector)?;
        Self::open_bundle(path, bundle, config)
    }

    fn open_bundle(
        path: impl AsRef<Path>,
        bundle: ProvisioningBundle,
        config: NodeConfig,
    ) -> Result<Self, EngineError> {
        let mut inner = open_reference_node(path, bundle, config)?;
        inner.reauthenticate_application_bridge_state()?;
        Ok(Self { inner })
    }

    pub fn identity(&self) -> NodeId {
        self.inner.identity()
    }

    /// Commits a non-Blob item locally before returning.
    pub fn publish(&mut self, request: PublishRequest) -> Result<PublishResult, EngineError> {
        if request.class == DataClass::Blob {
            return Err(EngineError::Invalid(
                "Blob publication requires the streaming Blob service".into(),
            ));
        }
        self.inner.publish(request).map(Into::into)
    }

    /// Atomically commits 2 through 64 non-Blob items as one explicit source
    /// batch. Ordinary [`Self::publish`] calls are never buffered into batches.
    pub fn publish_batch(
        &mut self,
        request: BatchPublishRequest,
    ) -> Result<BatchPublishResult, EngineError> {
        publish_application_batch(&mut self.inner, request)
    }

    /// Opens a staging service at the durably active content epoch.
    pub fn open_blob_service(
        &mut self,
        scope: &Scope,
        topic: &Topic,
        store_path: impl AsRef<Path>,
        config: BlobStoreConfig,
    ) -> Result<ReferenceBlobService, EngineError> {
        self.inner
            .current_blob_service(scope, topic, store_path, config)
    }

    /// Idempotently publishes a finalized bounded Blob manifest.
    ///
    /// Encrypted chunks remain in the quota-bound Blob store. Recovery calls
    /// this method again: an exact existing BlobId/manifest is returned rather
    /// than publishing a second semantic item.
    pub fn publish_finished_blob(
        &mut self,
        topic: Topic,
        scope: Scope,
        priority: Priority,
        ttl_ms: Option<u64>,
        finished: FinishedBlob,
    ) -> Result<PublishResult, EngineError> {
        let logical_key = finished.id().as_bytes().to_vec();
        let manifest = finished.manifest_bytes().to_vec();
        let route = finished.route_commitment();
        if let Some(receipt) = self.inner.find_authenticated_blob_manifest(
            &topic,
            &scope,
            finished.id(),
            &manifest,
            route,
        )? {
            return Ok(receipt.into());
        }
        self.inner
            .publish_blob_manifest(
                PublishRequest {
                    class: DataClass::Blob,
                    topic,
                    scope,
                    priority,
                    ttl_ms,
                    logical_key,
                    payload: manifest,
                    tombstone: false,
                },
                route,
            )
            .map(Into::into)
    }

    /// Atomically commits 2 through 64 finalized Blob manifests while keeping
    /// each source-authenticated route commitment inside the Blob boundary.
    pub fn publish_finished_blob_batch(
        &mut self,
        request: FinishedBlobBatchRequest,
    ) -> Result<BatchPublishResult, EngineError> {
        publish_finished_blob_application_batch(&mut self.inner, request)
    }

    /// Opens a local Blob reader using the manifest's retained historical epoch.
    pub fn open_blob_reader(
        &mut self,
        scope: &Scope,
        topic: &Topic,
        store_path: impl AsRef<Path>,
        config: BlobStoreConfig,
        id: BlobId,
    ) -> Result<ReferenceBlobReader, EngineError> {
        let path = store_path.as_ref();
        let manifest = FileBlobStore::open_with_config(path, config)
            .and_then(|store| store.load_manifest(id))
            .map_err(|error| EngineError::Invalid(error.to_string()))?
            .ok_or_else(|| EngineError::Invalid("Blob manifest is not stored".into()))?;
        let mut service =
            self.inner
                .blob_service(scope, topic, manifest.content_epoch(), path, config)?;
        service
            .reader_for_local(id)
            .map_err(|error| EngineError::Invalid(error.to_string()))
    }

    pub fn query(&mut self, query: Query) -> Result<Vec<Item>, EngineError> {
        self.inner
            .query_application_projection(query.into_store()?)
            .map(|items| items.into_iter().map(Into::into).collect())
    }

    pub fn subscribe(
        &mut self,
        topic: Topic,
        scope: Scope,
        class: Option<DataClass>,
        include_descendant_scopes: bool,
    ) -> Result<SubscriptionId, EngineError> {
        self.inner.subscribe(SubscriptionSpec {
            topic,
            scope,
            include_descendant_scopes,
            class,
        })
    }

    pub fn poll(
        &mut self,
        subscription: SubscriptionId,
        limit: usize,
    ) -> Result<Vec<Delivery>, EngineError> {
        if limit == 0 || limit > MAX_APPLICATION_PAGE {
            return Err(EngineError::Invalid(
                "delivery limit must be between 1 and 4096".into(),
            ));
        }
        self.inner
            .poll_application_projection(subscription, limit)
            .map(|items| items.into_iter().map(Into::into).collect())
    }

    pub fn acknowledge(
        &mut self,
        subscription: SubscriptionId,
        item: ItemId,
    ) -> Result<(), EngineError> {
        self.inner
            .acknowledge_application_projection(subscription, item)
    }

    pub fn conflicts(&mut self, query: Query) -> Result<Vec<ConflictAnnotation>, EngineError> {
        self.inner
            .conflicts_application_projection(query.into_store()?)
    }

    pub fn resolve(&mut self, request: ResolveRequest) -> Result<PublishResult, EngineError> {
        self.inner
            .resolve_application_projection(request)
            .map(Into::into)
    }

    pub fn event_gaps(&mut self, query: Query) -> Result<Vec<EventGap>, EngineError> {
        self.inner
            .event_gaps_application_projection(query.into_store()?)
    }

    /// Registers process-local policy metadata for Record conflict annotations.
    ///
    /// Only [`ApplicationMergePolicy::id`] is retained. Replicated ingestion
    /// never invokes the executable policy object; callers must retain any
    /// helper they intend to use before submitting an explicit resolution.
    pub fn register_merge_policy(&mut self, topic: Topic, policy: Arc<dyn ApplicationMergePolicy>) {
        self.inner
            .register_merge_policy(topic, Arc::new(MergePolicyAdapter(policy)));
    }

    /// Authority-only in-field rekey using an opaque signed public registry.
    ///
    /// `minimum_registry_generation` is the caller's independently retained
    /// rollback high-water mark. Fresh route/content keys and recipient wraps
    /// are generated internally and never enter this API.
    pub fn rekey_scope(
        &mut self,
        signed_public_registry: &[u8],
        minimum_registry_generation: u64,
        scope: Scope,
        new_epoch: u64,
        recipients: Vec<RekeyRecipient>,
    ) -> Result<ScopeRekeyResult, EngineError> {
        let recipient_count = recipients.len();
        let crypto_recipients = recipients
            .into_iter()
            .map(RekeyRecipient::into_crypto)
            .collect::<Result<Vec<_>, _>>()?;
        let result_scope = scope.clone();
        let (receipt, registry_generation) = self.inner.publish_scope_rekey_from_registry(
            signed_public_registry,
            minimum_registry_generation,
            scope,
            new_epoch,
            crypto_recipients,
        )?;
        Ok(ScopeRekeyResult {
            scope: result_scope,
            epoch: new_epoch,
            registry_generation,
            recipient_count,
            control_sequence: receipt.sequence,
        })
    }

    /// Bridge-node operation: creates a move-only, signed enrollment for one
    /// exact directed pair of currently provisioned route epochs.
    pub fn create_bridge_enrollment(
        &self,
        source_scope: Scope,
        source_route_epoch: u64,
        target_scope: Scope,
        target_route_epoch: u64,
    ) -> Result<BridgeEnrollment, EngineError> {
        let inner = self.inner.create_bridge_edge_enrollment(
            &source_scope,
            source_route_epoch,
            &target_scope,
            target_route_epoch,
        )?;
        Ok(BridgeEnrollment {
            inner,
            bridge_node: self.identity(),
            source_scope,
            source_route_epoch,
            target_scope,
            target_route_epoch,
        })
    }

    /// Authority operation: authenticates an enrollment, applies policy, and
    /// durably activates the resulting signed authorization control.
    pub fn enable_bridge(
        &mut self,
        enrollment: BridgeEnrollment,
        policy: BridgeAuthorizationPolicy,
    ) -> Result<BridgeAuthorizationResult, EngineError> {
        let request = EnableBridgeAuthorizationRequest::new(
            enrollment.inner,
            policy.topics,
            policy.allowed_priorities,
            policy.max_total_hops,
        )
        .map_err(|error| EngineError::Invalid(error.to_string()))?;
        self.inner.enable_bridge_edge(request).map(Into::into)
    }

    /// Authority operation: issues a higher-generation disable for an active
    /// exact edge. Existing wrappers are retained for recovery but cease to be active.
    pub fn disable_bridge(
        &mut self,
        edge: BridgeEdge,
    ) -> Result<BridgeAuthorizationResult, EngineError> {
        let request = DisableBridgeAuthorizationRequest::new(
            edge.bridge_node,
            edge.source_scope,
            edge.target_scope,
        )
        .map_err(|error| EngineError::Invalid(error.to_string()))?;
        self.inner.disable_bridge_edge(request).map(Into::into)
    }

    /// Bridge-node operation: atomically creates the first authorized wrapper
    /// around one ordinary durable item selected by its application ItemID.
    pub fn bridge_item(
        &mut self,
        source_item: ItemId,
        authorization: BridgeAuthorizationId,
        narrowing: BridgeNarrowingPolicy,
    ) -> Result<BridgeRouteResult, EngineError> {
        self.inner
            .bridge_item(source_item, authorization.0, narrowing.into_internal()?)
            .map(Into::into)
    }

    /// Bridge-node operation: appends exactly one authorized hop to an active
    /// durable route. The opaque handle selects no carrier or transport.
    pub fn extend_bridge_route(
        &mut self,
        route: BridgeRouteHandle,
        authorization: BridgeAuthorizationId,
        narrowing: BridgeNarrowingPolicy,
    ) -> Result<BridgeRouteResult, EngineError> {
        self.inner
            .extend_bridge_route(route.0, authorization.0, narrowing.into_internal()?)
            .map(Into::into)
    }

    pub fn bridge_authorization_status(
        &mut self,
        id: BridgeAuthorizationId,
    ) -> Result<Option<BridgeAuthorizationStatus>, EngineError> {
        bridge_authorization_status_for_node(&mut self.inner, id)
    }

    /// Lists a bounded page in stable authority/sequence order. `after` is
    /// exclusive and may be retained across process restarts.
    pub fn bridge_authorizations(
        &mut self,
        after: Option<BridgeAuthorizationId>,
        limit: usize,
    ) -> Result<Vec<BridgeAuthorizationStatus>, EngineError> {
        bridge_authorizations_for_node(&mut self.inner, after, limit)
    }

    pub fn bridge_route_status(
        &mut self,
        handle: BridgeRouteHandle,
    ) -> Result<Option<BridgeRouteStatus>, EngineError> {
        bridge_route_status_for_node(&mut self.inner, handle)
    }

    /// Lists a bounded page in stable durable insertion order. `after` is
    /// exclusive and may be retained across process restarts.
    pub fn bridge_routes(
        &mut self,
        after: Option<BridgeRouteHandle>,
        limit: usize,
    ) -> Result<Vec<BridgeRouteStatus>, EngineError> {
        bridge_routes_for_node(&mut self.inner, after, limit)
    }

    pub fn set_emission_policy(&mut self, policy: EmissionPolicy) {
        self.inner.set_emission_policy(policy);
    }

    pub fn emission_policy(&self) -> EmissionPolicy {
        self.inner.emission_policy()
    }

    pub fn may_advertise(&self) -> bool {
        self.inner.may_advertise()
    }

    pub fn peer_status(&mut self, peer: NodeId) -> Result<Option<PeerSnapshot>, EngineError> {
        self.inner.peer_status(peer)
    }

    pub fn peers(&mut self) -> Result<Vec<PeerSnapshot>, EngineError> {
        self.inner.peers()
    }

    pub fn set_bridge_filters(&mut self, filters: &[BridgeFilter]) -> Result<(), EngineError> {
        self.inner.set_bridge_filters(filters)
    }

    pub fn quota_usage(&mut self, scope: Option<&Scope>) -> Result<QuotaUsage, EngineError> {
        self.inner.quota_usage(scope)
    }

    pub fn collect_garbage(&mut self) -> Result<Vec<ItemId>, EngineError> {
        self.inner.collect_garbage()
    }

    pub fn zeroize(&mut self) -> Result<(), EngineError> {
        self.inner.zeroize()
    }
}

/// Borrowed application-only view of a reference node owned by a trusted host.
///
/// This type is available only with `adapter-sdk`. It lets a composition host
/// retain ownership of the durable runtime backend while presenting exactly the
/// same publish, subscription, query, conflict, peer, and Blob operations as
/// [`ApplicationNode`]. It never exposes sealed envelopes, cryptographic
/// providers, fragmentation, wire messages, or transport selection.
#[cfg(feature = "adapter-sdk")]
pub struct ApplicationNodeRef<'a> {
    inner: &'a mut ReferenceNode,
}

#[cfg(feature = "adapter-sdk")]
impl<'a> ApplicationNodeRef<'a> {
    /// Creates an application-only view over a host-owned reference node.
    pub fn new(inner: &'a mut ReferenceNode) -> Self {
        Self { inner }
    }

    pub fn identity(&self) -> NodeId {
        self.inner.identity()
    }

    /// Reauthenticates durable application bridge state after an adapter-owned
    /// reference node is reopened. No cryptographic capability is exposed.
    pub fn reauthenticate_bridge_state(&mut self) -> Result<(), EngineError> {
        self.inner.reauthenticate_application_bridge_state()
    }

    /// Commits a non-Blob item locally before returning.
    pub fn publish(&mut self, request: PublishRequest) -> Result<PublishResult, EngineError> {
        if request.class == DataClass::Blob {
            return Err(EngineError::Invalid(
                "Blob publication requires the streaming Blob service".into(),
            ));
        }
        self.inner.publish(request).map(Into::into)
    }

    /// Atomically commits 2 through 64 non-Blob items as one explicit source
    /// batch. Ordinary [`Self::publish`] calls are never buffered into batches.
    pub fn publish_batch(
        &mut self,
        request: BatchPublishRequest,
    ) -> Result<BatchPublishResult, EngineError> {
        publish_application_batch(self.inner, request)
    }

    /// Opens a staging service at the durably active content epoch.
    pub fn open_blob_service(
        &mut self,
        scope: &Scope,
        topic: &Topic,
        store_path: impl AsRef<Path>,
        config: BlobStoreConfig,
    ) -> Result<ReferenceBlobService, EngineError> {
        self.inner
            .current_blob_service(scope, topic, store_path, config)
    }

    /// Idempotently publishes a finalized bounded Blob manifest.
    pub fn publish_finished_blob(
        &mut self,
        topic: Topic,
        scope: Scope,
        priority: Priority,
        ttl_ms: Option<u64>,
        finished: FinishedBlob,
    ) -> Result<PublishResult, EngineError> {
        let logical_key = finished.id().as_bytes().to_vec();
        let manifest = finished.manifest_bytes().to_vec();
        let route = finished.route_commitment();
        if let Some(receipt) = self.inner.find_authenticated_blob_manifest(
            &topic,
            &scope,
            finished.id(),
            &manifest,
            route,
        )? {
            return Ok(receipt.into());
        }
        self.inner
            .publish_blob_manifest(
                PublishRequest {
                    class: DataClass::Blob,
                    topic,
                    scope,
                    priority,
                    ttl_ms,
                    logical_key,
                    payload: manifest,
                    tombstone: false,
                },
                route,
            )
            .map(Into::into)
    }

    /// Atomically commits 2 through 64 finalized Blob manifests while keeping
    /// each source-authenticated route commitment inside the Blob boundary.
    pub fn publish_finished_blob_batch(
        &mut self,
        request: FinishedBlobBatchRequest,
    ) -> Result<BatchPublishResult, EngineError> {
        publish_finished_blob_application_batch(self.inner, request)
    }

    /// Opens a local Blob reader using the manifest's retained historical epoch.
    pub fn open_blob_reader(
        &mut self,
        scope: &Scope,
        topic: &Topic,
        store_path: impl AsRef<Path>,
        config: BlobStoreConfig,
        id: BlobId,
    ) -> Result<ReferenceBlobReader, EngineError> {
        let path = store_path.as_ref();
        let manifest = FileBlobStore::open_with_config(path, config)
            .and_then(|store| store.load_manifest(id))
            .map_err(|error| EngineError::Invalid(error.to_string()))?
            .ok_or_else(|| EngineError::Invalid("Blob manifest is not stored".into()))?;
        let mut service =
            self.inner
                .blob_service(scope, topic, manifest.content_epoch(), path, config)?;
        service
            .reader_for_local(id)
            .map_err(|error| EngineError::Invalid(error.to_string()))
    }

    pub fn query(&mut self, query: Query) -> Result<Vec<Item>, EngineError> {
        self.inner
            .query_application_projection(query.into_store()?)
            .map(|items| items.into_iter().map(Into::into).collect())
    }

    pub fn subscribe(
        &mut self,
        topic: Topic,
        scope: Scope,
        class: Option<DataClass>,
        include_descendant_scopes: bool,
    ) -> Result<SubscriptionId, EngineError> {
        self.inner.subscribe(SubscriptionSpec {
            topic,
            scope,
            include_descendant_scopes,
            class,
        })
    }

    pub fn poll(
        &mut self,
        subscription: SubscriptionId,
        limit: usize,
    ) -> Result<Vec<Delivery>, EngineError> {
        if limit == 0 || limit > MAX_APPLICATION_PAGE {
            return Err(EngineError::Invalid(
                "delivery limit must be between 1 and 4096".into(),
            ));
        }
        self.inner
            .poll_application_projection(subscription, limit)
            .map(|items| items.into_iter().map(Into::into).collect())
    }

    pub fn acknowledge(
        &mut self,
        subscription: SubscriptionId,
        item: ItemId,
    ) -> Result<(), EngineError> {
        self.inner
            .acknowledge_application_projection(subscription, item)
    }

    pub fn conflicts(&mut self, query: Query) -> Result<Vec<ConflictAnnotation>, EngineError> {
        self.inner
            .conflicts_application_projection(query.into_store()?)
    }

    pub fn resolve(&mut self, request: ResolveRequest) -> Result<PublishResult, EngineError> {
        self.inner
            .resolve_application_projection(request)
            .map(Into::into)
    }

    pub fn event_gaps(&mut self, query: Query) -> Result<Vec<EventGap>, EngineError> {
        self.inner
            .event_gaps_application_projection(query.into_store()?)
    }

    /// Registers process-local policy metadata for Record conflict annotations.
    ///
    /// Only [`ApplicationMergePolicy::id`] is retained. Replicated ingestion
    /// never invokes the executable policy object; callers must retain any
    /// helper they intend to use before submitting an explicit resolution.
    pub fn register_merge_policy(&mut self, topic: Topic, policy: Arc<dyn ApplicationMergePolicy>) {
        self.inner
            .register_merge_policy(topic, Arc::new(MergePolicyAdapter(policy)));
    }

    /// Authority-only in-field rekey using an opaque signed public registry.
    pub fn rekey_scope(
        &mut self,
        signed_public_registry: &[u8],
        minimum_registry_generation: u64,
        scope: Scope,
        new_epoch: u64,
        recipients: Vec<RekeyRecipient>,
    ) -> Result<ScopeRekeyResult, EngineError> {
        let recipient_count = recipients.len();
        let crypto_recipients = recipients
            .into_iter()
            .map(RekeyRecipient::into_crypto)
            .collect::<Result<Vec<_>, _>>()?;
        let result_scope = scope.clone();
        let (receipt, registry_generation) = self.inner.publish_scope_rekey_from_registry(
            signed_public_registry,
            minimum_registry_generation,
            scope,
            new_epoch,
            crypto_recipients,
        )?;
        Ok(ScopeRekeyResult {
            scope: result_scope,
            epoch: new_epoch,
            registry_generation,
            recipient_count,
            control_sequence: receipt.sequence,
        })
    }

    /// Bridge-node operation: creates a move-only, signed enrollment for one
    /// exact directed pair of currently provisioned route epochs.
    pub fn create_bridge_enrollment(
        &self,
        source_scope: Scope,
        source_route_epoch: u64,
        target_scope: Scope,
        target_route_epoch: u64,
    ) -> Result<BridgeEnrollment, EngineError> {
        let inner = self.inner.create_bridge_edge_enrollment(
            &source_scope,
            source_route_epoch,
            &target_scope,
            target_route_epoch,
        )?;
        Ok(BridgeEnrollment {
            inner,
            bridge_node: self.identity(),
            source_scope,
            source_route_epoch,
            target_scope,
            target_route_epoch,
        })
    }

    pub fn enable_bridge(
        &mut self,
        enrollment: BridgeEnrollment,
        policy: BridgeAuthorizationPolicy,
    ) -> Result<BridgeAuthorizationResult, EngineError> {
        let request = EnableBridgeAuthorizationRequest::new(
            enrollment.inner,
            policy.topics,
            policy.allowed_priorities,
            policy.max_total_hops,
        )
        .map_err(|error| EngineError::Invalid(error.to_string()))?;
        self.inner.enable_bridge_edge(request).map(Into::into)
    }

    pub fn disable_bridge(
        &mut self,
        edge: BridgeEdge,
    ) -> Result<BridgeAuthorizationResult, EngineError> {
        let request = DisableBridgeAuthorizationRequest::new(
            edge.bridge_node,
            edge.source_scope,
            edge.target_scope,
        )
        .map_err(|error| EngineError::Invalid(error.to_string()))?;
        self.inner.disable_bridge_edge(request).map(Into::into)
    }

    pub fn bridge_item(
        &mut self,
        source_item: ItemId,
        authorization: BridgeAuthorizationId,
        narrowing: BridgeNarrowingPolicy,
    ) -> Result<BridgeRouteResult, EngineError> {
        self.inner
            .bridge_item(source_item, authorization.0, narrowing.into_internal()?)
            .map(Into::into)
    }

    pub fn extend_bridge_route(
        &mut self,
        route: BridgeRouteHandle,
        authorization: BridgeAuthorizationId,
        narrowing: BridgeNarrowingPolicy,
    ) -> Result<BridgeRouteResult, EngineError> {
        self.inner
            .extend_bridge_route(route.0, authorization.0, narrowing.into_internal()?)
            .map(Into::into)
    }

    pub fn bridge_authorization_status(
        &mut self,
        id: BridgeAuthorizationId,
    ) -> Result<Option<BridgeAuthorizationStatus>, EngineError> {
        bridge_authorization_status_for_node(self.inner, id)
    }

    pub fn bridge_authorizations(
        &mut self,
        after: Option<BridgeAuthorizationId>,
        limit: usize,
    ) -> Result<Vec<BridgeAuthorizationStatus>, EngineError> {
        bridge_authorizations_for_node(self.inner, after, limit)
    }

    pub fn bridge_route_status(
        &mut self,
        handle: BridgeRouteHandle,
    ) -> Result<Option<BridgeRouteStatus>, EngineError> {
        bridge_route_status_for_node(self.inner, handle)
    }

    pub fn bridge_routes(
        &mut self,
        after: Option<BridgeRouteHandle>,
        limit: usize,
    ) -> Result<Vec<BridgeRouteStatus>, EngineError> {
        bridge_routes_for_node(self.inner, after, limit)
    }

    pub fn set_emission_policy(&mut self, policy: EmissionPolicy) {
        self.inner.set_emission_policy(policy);
    }

    pub fn emission_policy(&self) -> EmissionPolicy {
        self.inner.emission_policy()
    }

    pub fn may_advertise(&self) -> bool {
        self.inner.may_advertise()
    }

    pub fn peer_status(&mut self, peer: NodeId) -> Result<Option<PeerSnapshot>, EngineError> {
        self.inner.peer_status(peer)
    }

    pub fn peers(&mut self) -> Result<Vec<PeerSnapshot>, EngineError> {
        self.inner.peers()
    }

    pub fn set_bridge_filters(&mut self, filters: &[BridgeFilter]) -> Result<(), EngineError> {
        self.inner.set_bridge_filters(filters)
    }

    pub fn quota_usage(&mut self, scope: Option<&Scope>) -> Result<QuotaUsage, EngineError> {
        self.inner.quota_usage(scope)
    }

    pub fn collect_garbage(&mut self) -> Result<Vec<ItemId>, EngineError> {
        self.inner.collect_garbage()
    }

    pub fn zeroize(&mut self) -> Result<(), EngineError> {
        self.inner.zeroize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::{BlobMetadata, MIN_BLOB_CHUNK_SIZE};
    use crate::crypto::{BridgeCryptoProvider, ProvisioningAccess, ReferenceProvisioner};
    use crate::engine::EnvelopeSealer;
    use crate::provisioning::{
        ProtectedProvisioningError, ProvisioningProtectionError, UnprotectedProvisioning,
    };
    use crate::store::{
        RecordStore, ScopeEpoch, VerifiedBridgeAuthorization as StoreVerifiedBridgeAuthorization,
    };
    use std::fs;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestProtectedSource {
        plaintext: Option<Vec<u8>>,
        calls: usize,
        failure: Option<ProvisioningProtectionError>,
    }

    impl ProvisioningUnprotector for TestProtectedSource {
        fn unprotect(
            &mut self,
            _protected: &[u8],
            max_plaintext_len: usize,
        ) -> Result<UnprotectedProvisioning, ProvisioningProtectionError> {
            self.calls += 1;
            if let Some(error) = self.failure {
                return Err(error);
            }
            let plaintext = self
                .plaintext
                .take()
                .ok_or(ProvisioningProtectionError::Unavailable)?;
            if plaintext.len() > max_plaintext_len {
                return Err(ProvisioningProtectionError::TooLarge);
            }
            UnprotectedProvisioning::new(plaintext)
        }
    }

    fn api_test_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aster-api-{label}-{}-{}.sqlite3",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn remove_store(path: &Path) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(path.with_extension("sqlite3-wal"));
        let _ = fs::remove_file(path.with_extension("sqlite3-shm"));
    }

    fn configure_epoch(node: &mut ApplicationNode, authority: NodeId, scope: Scope, epoch: u64) {
        node.inner
            .store_mut()
            .set_scope_epoch(&ScopeEpoch {
                authority,
                signer: authority,
                scope,
                epoch,
                control_sequence: epoch,
                previous_control: None,
                sealed_notice: epoch.to_be_bytes().to_vec(),
            })
            .unwrap_or_else(|error| panic!("scope epoch setup failed: {error}"));
    }

    fn copy_bridge_authorization(
        source: &mut ApplicationNode,
        target: &mut ApplicationNode,
        id: BridgeAuthorizationId,
    ) {
        let exact_bytes = source
            .inner
            .store_mut()
            .stored_bridge_authorization(&id.0)
            .unwrap_or_else(|error| panic!("authorization read failed: {error}"))
            .unwrap_or_else(|| panic!("authorization receipt was not durable"))
            .exact_bytes;
        let (envelope_id, authorization, control_signer) = {
            let verified = target
                .inner
                .envelopes()
                .open_bridge_authorization(&exact_bytes)
                .unwrap_or_else(|error| panic!("authorization verify failed: {error}"));
            (
                verified.envelope().envelope_id,
                verified.envelope().authorization.clone(),
                verified.control_signer(),
            )
        };
        let verified = StoreVerifiedBridgeAuthorization::from_provider(
            envelope_id,
            authorization,
            control_signer,
            exact_bytes,
        )
        .unwrap_or_else(|error| panic!("authorization token failed: {error}"));
        target
            .inner
            .store_mut()
            .ingest_bridge_authorization(&verified)
            .unwrap_or_else(|error| panic!("authorization ingest failed: {error}"));
    }

    fn copy_ordinary_item(source: &mut ApplicationNode, target: &mut ApplicationNode, id: ItemId) {
        let sealed = source
            .inner
            .store_mut()
            .get(&id)
            .unwrap_or_else(|error| panic!("ordinary item read failed: {error}"))
            .unwrap_or_else(|| panic!("ordinary item was not durable"))
            .sealed;
        target
            .inner
            .ingest(&sealed)
            .unwrap_or_else(|error| panic!("ordinary item ingest failed: {error}"));
    }

    fn batch_publish_request(
        class: DataClass,
        topic: &Topic,
        scope: &Scope,
        key: &[u8],
        payload: &[u8],
    ) -> PublishRequest {
        PublishRequest {
            class,
            topic: topic.clone(),
            scope: scope.clone(),
            priority: Priority::Routine,
            ttl_ms: None,
            logical_key: key.to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
        }
    }

    fn batch_test_node(
        label: &str,
        seed: u8,
        topic: &Topic,
        scope: &Scope,
        options: ApplicationNodeOptions,
    ) -> (PathBuf, Vec<u8>, ApplicationNode) {
        let path = api_test_path(label);
        let access = ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()])
            .unwrap_or_else(|error| panic!("batch access setup failed: {error}"));
        let mut provisioner = ReferenceProvisioner::from_seed([seed; 32])
            .unwrap_or_else(|error| panic!("batch provisioner setup failed: {error}"));
        let bundle = provisioner
            .issue_node(1, &[access])
            .unwrap_or_else(|error| panic!("batch bundle setup failed: {error}"))
            .to_bytes()
            .unwrap_or_else(|error| panic!("batch bundle encoding failed: {error}"));
        let node = ApplicationNode::open(&path, &bundle, options)
            .unwrap_or_else(|error| panic!("batch node open failed: {error}"));
        (path, bundle, node)
    }

    #[test]
    fn application_queries_are_always_bounded() {
        assert!(Query::default().into_store().is_ok());
        assert!(
            Query {
                limit: 0,
                ..Query::default()
            }
            .into_store()
            .is_err()
        );
        assert!(
            Query {
                limit: MAX_APPLICATION_PAGE + 1,
                ..Query::default()
            }
            .into_store()
            .is_err()
        );
    }

    #[test]
    fn protected_application_open_is_one_shot_and_fails_before_store_creation() {
        let scope = Scope::new("mission/protected-api").unwrap();
        let topic = Topic::new("protected.api").unwrap();
        let access = ProvisioningAccess::member(scope, vec![0], vec![topic]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x93; 32]).unwrap();
        let raw = provisioner
            .issue_node(1, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();

        let success_path = api_test_path("protected-open-success");
        let mut success = TestProtectedSource {
            plaintext: Some(raw.clone()),
            calls: 0,
            failure: None,
        };
        let node = ApplicationNode::open_protected(
            &success_path,
            b"provider-owned-artifact",
            &mut success,
            ApplicationNodeOptions::default(),
        )
        .unwrap();
        assert_eq!(success.calls, 1);
        drop(node);
        remove_store(&success_path);

        let failure_path = api_test_path("protected-open-failure");
        let mut failure = TestProtectedSource {
            plaintext: None,
            calls: 0,
            failure: Some(ProvisioningProtectionError::Unavailable),
        };
        let error = ApplicationNode::open_protected(
            &failure_path,
            b"provider-owned-rejected-artifact",
            &mut failure,
            ApplicationNodeOptions::default(),
        )
        .err()
        .unwrap_or_else(|| panic!("provider failure must not fall back to valid plaintext"));
        assert!(matches!(
            error,
            EngineError::Provisioning(ProtectedProvisioningError::Protection(
                ProvisioningProtectionError::Unavailable
            ))
        ));
        assert_eq!(failure.calls, 1);
        assert!(!failure_path.exists());

        let invalid_options_path = api_test_path("protected-open-invalid-options");
        let mut invalid_options = TestProtectedSource {
            plaintext: Some(raw.clone()),
            calls: 0,
            failure: None,
        };
        assert!(
            ApplicationNode::open_protected(
                &invalid_options_path,
                b"provider-owned-artifact",
                &mut invalid_options,
                ApplicationNodeOptions {
                    max_items: 0,
                    ..ApplicationNodeOptions::default()
                },
            )
            .is_err()
        );
        assert_eq!(invalid_options.calls, 0);
        assert!(!invalid_options_path.exists());

        let malformed_path = api_test_path("protected-open-malformed-inner");
        let mut malformed = TestProtectedSource {
            plaintext: Some(b"not-a-provisioning-bundle".to_vec()),
            calls: 0,
            failure: None,
        };
        let error = ApplicationNode::open_protected(
            &malformed_path,
            b"provider-owned-artifact",
            &mut malformed,
            ApplicationNodeOptions::default(),
        )
        .err()
        .unwrap_or_else(|| panic!("malformed recovered plaintext must fail closed"));
        assert!(matches!(
            error,
            EngineError::Provisioning(ProtectedProvisioningError::InvalidBundle)
        ));
        assert_eq!(malformed.calls, 1);
        assert!(!malformed_path.exists());
    }

    #[test]
    fn invalid_zero_capacity_is_rejected() {
        assert!(
            ApplicationNodeOptions {
                max_items: 0,
                ..ApplicationNodeOptions::default()
            }
            .into_engine()
            .is_err()
        );
    }

    #[test]
    fn explicit_event_batch_is_contiguous_queryable_and_restart_durable() {
        let topic = Topic::new("batch.events").unwrap();
        let scope = Scope::new("mission/batch").unwrap();
        let (path, bundle, mut node) = batch_test_node(
            "retained-batch",
            0x91,
            &topic,
            &scope,
            ApplicationNodeOptions::default(),
        );
        let subscription = node
            .subscribe(topic.clone(), scope.clone(), Some(DataClass::Event), false)
            .unwrap();
        let result = node
            .publish_batch(BatchPublishRequest::new(vec![
                batch_publish_request(DataClass::Event, &topic, &scope, b"one", b"first"),
                batch_publish_request(DataClass::Event, &topic, &scope, b"two", b"second"),
            ]))
            .unwrap();
        assert_eq!(result.items.len(), 2);
        assert_eq!(result.items[0].publisher_counter, 1);
        assert_eq!(result.items[1].publisher_counter, 2);
        assert_eq!(result.items[0].event_sequence, Some(1));
        assert_eq!(result.items[1].event_sequence, Some(2));
        assert!(result.evicted.is_empty());

        let deliveries = node.poll(subscription, 8).unwrap();
        assert_eq!(deliveries.len(), 2);
        assert_eq!(deliveries[0].item.payload, b"first");
        assert_eq!(deliveries[1].item.payload, b"second");
        for delivery in deliveries {
            node.acknowledge(subscription, delivery.item.id).unwrap();
        }
        assert!(node.poll(subscription, 8).unwrap().is_empty());
        drop(node);

        let mut restarted =
            ApplicationNode::open(&path, &bundle, ApplicationNodeOptions::default()).unwrap();
        let queried = restarted
            .query(Query {
                topic: Some(topic.clone()),
                scope: Some(scope.clone()),
                class: Some(DataClass::Event),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(queried.len(), 2);
        assert_eq!(queried[0].event_sequence, Some(1));
        assert_eq!(queried[1].event_sequence, Some(2));
        let singleton = restarted
            .publish(batch_publish_request(
                DataClass::Event,
                &topic,
                &scope,
                b"three",
                b"third",
            ))
            .unwrap();
        assert_eq!(singleton.publisher_counter, 3);
        assert_eq!(singleton.event_sequence, Some(3));

        drop(restarted);
        remove_store(&path);
    }

    #[test]
    fn same_key_events_remain_queryable_and_deliverable() {
        let topic = Topic::new("events.stream").unwrap();
        let scope = Scope::new("mission/events").unwrap();
        let (path, _bundle, mut node) = batch_test_node(
            "same-key-events",
            0x95,
            &topic,
            &scope,
            ApplicationNodeOptions::default(),
        );
        let subscription = node
            .subscribe(topic.clone(), scope.clone(), Some(DataClass::Event), false)
            .unwrap();
        let mut published = Vec::new();
        for payload in [b"first".as_slice(), b"second", b"third"] {
            published.push(
                node.publish(batch_publish_request(
                    DataClass::Event,
                    &topic,
                    &scope,
                    b"operations-chat",
                    payload,
                ))
                .unwrap()
                .id,
            );
        }

        let queried = node
            .query(Query {
                topic: Some(topic),
                scope: Some(scope),
                class: Some(DataClass::Event),
                logical_key: Some(b"operations-chat".to_vec()),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(
            queried
                .iter()
                .map(|item| item.payload.as_slice())
                .collect::<Vec<_>>(),
            [b"first".as_slice(), b"second", b"third"]
        );

        let deliveries = node.poll(subscription, 8).unwrap();
        assert_eq!(
            deliveries
                .iter()
                .map(|delivery| delivery.item.payload.as_slice())
                .collect::<Vec<_>>(),
            [b"first".as_slice(), b"second", b"third"]
        );
        assert_eq!(
            deliveries
                .iter()
                .map(|delivery| delivery.item.id)
                .collect::<Vec<_>>(),
            published
        );

        drop(node);
        remove_store(&path);
    }

    #[test]
    fn acknowledging_current_state_and_record_does_not_reveal_ancestors() {
        let topic = Topic::new("projection.ack").unwrap();
        let scope = Scope::new("mission/projection").unwrap();
        let (path, _bundle, mut node) = batch_test_node(
            "projection-ack",
            0x96,
            &topic,
            &scope,
            ApplicationNodeOptions::default(),
        );
        let subscription = node
            .subscribe(topic.clone(), scope.clone(), None, false)
            .unwrap();
        for (class, key) in [
            (DataClass::State, b"state-key".as_slice()),
            (DataClass::Record, b"record-key".as_slice()),
        ] {
            node.publish(batch_publish_request(class, &topic, &scope, key, b"old"))
                .unwrap();
            node.publish(batch_publish_request(class, &topic, &scope, key, b"new"))
                .unwrap();
        }

        let deliveries = node.poll(subscription, 8).unwrap();
        assert_eq!(deliveries.len(), 2);
        assert_eq!(
            deliveries
                .iter()
                .map(|delivery| delivery.item.class)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([DataClass::State, DataClass::Record])
        );
        assert!(
            deliveries
                .iter()
                .all(|delivery| delivery.item.payload == b"new")
        );
        for delivery in deliveries {
            node.acknowledge(subscription, delivery.item.id).unwrap();
        }
        assert!(node.poll(subscription, 8).unwrap().is_empty());

        let recoverable = node
            .query(Query {
                topic: Some(topic),
                scope: Some(scope),
                include_recoverable_versions: true,
                ..Query::default()
            })
            .unwrap();
        assert_eq!(recoverable.len(), 4);
        assert_eq!(
            recoverable
                .iter()
                .map(|item| item.payload.as_slice())
                .collect::<Vec<_>>()
                .iter()
                .filter(|payload| **payload == b"old")
                .count(),
            2
        );

        drop(node);
        remove_store(&path);
    }

    #[test]
    fn acknowledged_causal_intermediates_preserve_subscription_projection() {
        let scope = Scope::new("mission/projection-chain").unwrap();
        let state_topic = Topic::new("projection.chain.state").unwrap();
        let record_topic = Topic::new("projection.chain.record").unwrap();
        let concurrent_topic = Topic::new("projection.concurrent.record").unwrap();
        let access = ProvisioningAccess::member(
            scope.clone(),
            vec![0],
            vec![
                state_topic.clone(),
                record_topic.clone(),
                concurrent_topic.clone(),
            ],
        )
        .unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x97; 32]).unwrap();
        let first_bytes = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let second_bytes = provisioner
            .issue_node(2, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let third_bytes = provisioner
            .issue_node(3, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let receiver_bytes = provisioner
            .issue_node(4, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();
        let first_path = api_test_path("projection-chain-first");
        let second_path = api_test_path("projection-chain-second");
        let third_path = api_test_path("projection-chain-third");
        let receiver_path = api_test_path("projection-chain-receiver");
        let mut first =
            ApplicationNode::open(&first_path, &first_bytes, ApplicationNodeOptions::default())
                .unwrap();
        let mut second = ApplicationNode::open(
            &second_path,
            &second_bytes,
            ApplicationNodeOptions::default(),
        )
        .unwrap();
        let mut third =
            ApplicationNode::open(&third_path, &third_bytes, ApplicationNodeOptions::default())
                .unwrap();
        let mut receiver = ApplicationNode::open(
            &receiver_path,
            &receiver_bytes,
            ApplicationNodeOptions::default(),
        )
        .unwrap();

        for (class, topic) in [
            (DataClass::State, state_topic),
            (DataClass::Record, record_topic),
        ] {
            let subscription = receiver
                .subscribe(topic.clone(), scope.clone(), Some(class), false)
                .unwrap();
            let a = first
                .publish(batch_publish_request(class, &topic, &scope, b"chain", b"a"))
                .unwrap();
            copy_ordinary_item(&mut first, &mut second, a.id);
            copy_ordinary_item(&mut first, &mut receiver, a.id);
            let b = second
                .publish(batch_publish_request(class, &topic, &scope, b"chain", b"b"))
                .unwrap();
            copy_ordinary_item(&mut second, &mut receiver, b.id);
            let delivered_b = receiver.poll(subscription, 8).unwrap();
            assert_eq!(delivered_b.len(), 1);
            assert_eq!(delivered_b[0].item.id, b.id);
            receiver.acknowledge(subscription, b.id).unwrap();

            // Third observes B directly but never receives A. Its context names
            // B only, so acknowledged B is required as a transitive projection
            // witness after C supersedes it.
            copy_ordinary_item(&mut second, &mut third, b.id);
            let c = third
                .publish(batch_publish_request(class, &topic, &scope, b"chain", b"c"))
                .unwrap();
            copy_ordinary_item(&mut third, &mut receiver, c.id);
            let delivered_c = receiver.poll(subscription, 8).unwrap();
            assert_eq!(delivered_c.len(), 1);
            assert_eq!(delivered_c[0].item.id, c.id);
            assert_eq!(delivered_c[0].item.payload, b"c");
            receiver.acknowledge(subscription, c.id).unwrap();
            assert!(receiver.poll(subscription, 8).unwrap().is_empty());
        }

        let concurrent_subscription = receiver
            .subscribe(
                concurrent_topic.clone(),
                scope.clone(),
                Some(DataClass::Record),
                false,
            )
            .unwrap();
        let left = first
            .publish(batch_publish_request(
                DataClass::Record,
                &concurrent_topic,
                &scope,
                b"siblings",
                b"left",
            ))
            .unwrap();
        let right = second
            .publish(batch_publish_request(
                DataClass::Record,
                &concurrent_topic,
                &scope,
                b"siblings",
                b"right",
            ))
            .unwrap();
        copy_ordinary_item(&mut first, &mut receiver, left.id);
        copy_ordinary_item(&mut second, &mut receiver, right.id);
        let siblings = receiver.poll(concurrent_subscription, 8).unwrap();
        assert_eq!(siblings.len(), 2);
        receiver
            .acknowledge(concurrent_subscription, left.id)
            .unwrap();
        let remaining = receiver.poll(concurrent_subscription, 8).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].item.id, right.id);
        receiver
            .acknowledge(concurrent_subscription, right.id)
            .unwrap();
        assert!(
            receiver
                .poll(concurrent_subscription, 8)
                .unwrap()
                .is_empty()
        );

        drop(first);
        drop(second);
        drop(third);
        drop(receiver);
        for path in [first_path, second_path, third_path, receiver_path] {
            remove_store(&path);
        }
    }

    #[test]
    fn batch_only_items_reauthenticate_for_reads_and_restart() {
        let topic = Topic::new("batch.state").unwrap();
        let scope = Scope::new("mission/batch-only").unwrap();
        let (path, bundle, mut node) = batch_test_node(
            "batch-only",
            0x92,
            &topic,
            &scope,
            ApplicationNodeOptions::default(),
        );
        let subscription = node
            .subscribe(topic.clone(), scope.clone(), Some(DataClass::State), false)
            .unwrap();
        node.publish_batch(BatchPublishRequest::batch_only(vec![
            batch_publish_request(DataClass::State, &topic, &scope, b"alpha", b"ready"),
            batch_publish_request(DataClass::State, &topic, &scope, b"bravo", b"moving"),
        ]))
        .unwrap();
        let deliveries = node.poll(subscription, 8).unwrap();
        assert_eq!(deliveries.len(), 2);
        assert_eq!(
            deliveries
                .iter()
                .map(|delivery| delivery.item.payload.as_slice())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([b"moving".as_slice(), b"ready".as_slice()])
        );
        drop(node);

        let mut restarted =
            ApplicationNode::open(&path, &bundle, ApplicationNodeOptions::default()).unwrap();
        let queried = restarted
            .query(Query {
                topic: Some(topic),
                scope: Some(scope),
                class: Some(DataClass::State),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(queried.len(), 2);
        assert_eq!(
            queried
                .iter()
                .map(|item| item.payload.as_slice())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([b"moving".as_slice(), b"ready".as_slice()])
        );

        drop(restarted);
        remove_store(&path);
    }

    #[test]
    fn rejected_or_uncommittable_batch_consumes_no_counter_or_event_range() {
        let topic = Topic::new("batch.atomic").unwrap();
        let scope = Scope::new("mission/batch-atomic").unwrap();
        let options = ApplicationNodeOptions {
            max_items: 1,
            ..ApplicationNodeOptions::default()
        };
        let (path, _bundle, mut node) =
            batch_test_node("batch-atomic", 0x93, &topic, &scope, options);
        assert!(
            node.publish_batch(BatchPublishRequest::new(vec![
                batch_publish_request(DataClass::Event, &topic, &scope, b"one", b"first"),
                batch_publish_request(DataClass::Event, &topic, &scope, b"two", b"second"),
            ]))
            .is_err()
        );
        assert!(
            node.query(Query {
                topic: Some(topic.clone()),
                scope: Some(scope.clone()),
                class: Some(DataClass::Event),
                ..Query::default()
            })
            .unwrap()
            .is_empty()
        );
        let singleton = node
            .publish(batch_publish_request(
                DataClass::Event,
                &topic,
                &scope,
                b"fallback",
                b"only",
            ))
            .unwrap();
        assert_eq!(singleton.publisher_counter, 1);
        assert_eq!(singleton.event_sequence, Some(1));

        let blob = batch_publish_request(DataClass::Blob, &topic, &scope, &[0x44; 32], b"blob");
        assert!(
            node.publish_batch(BatchPublishRequest::new(vec![blob.clone(), blob]))
                .is_err()
        );
        let after_rejection = node
            .publish(batch_publish_request(
                DataClass::Event,
                &topic,
                &scope,
                b"after-blob-rejection",
                b"still-contiguous",
            ))
            .unwrap();
        assert_eq!(after_rejection.publisher_counter, 2);
        assert_eq!(after_rejection.event_sequence, Some(2));
        drop(node);
        remove_store(&path);
    }

    #[test]
    fn finalized_blob_batch_keeps_routes_private_and_batch_only_idempotent() {
        let topic = Topic::new("batch.blobs").unwrap();
        let scope = Scope::new("mission/batch-blobs").unwrap();
        let (path, bundle, mut node) = batch_test_node(
            "blob-batch",
            0x94,
            &topic,
            &scope,
            ApplicationNodeOptions::default(),
        );
        let blob_path = api_test_path("blob-batch-files").with_extension("blobs");
        let mut service = node
            .open_blob_service(&scope, &topic, &blob_path, BlobStoreConfig::default())
            .unwrap();
        let mut finish = |bytes: &[u8], schema: &[u8]| {
            let mut source = Cursor::new(bytes.to_vec());
            let mut scratch = Cursor::new(Vec::new());
            let manifest = service
                .prepare(
                    &mut source,
                    &mut scratch,
                    MIN_BLOB_CHUNK_SIZE,
                    BlobMetadata::new(Some("application/octet-stream".into()), schema.to_vec())
                        .unwrap(),
                )
                .unwrap();
            assert!(
                service
                    .encrypt_some(&mut source, &manifest, u64::MAX)
                    .unwrap()
                    .complete
            );
            service.finish(manifest.id()).unwrap()
        };
        let first = finish(b"first batch Blob", b"schema:first");
        let second = finish(b"second batch Blob", b"schema:second");
        drop(service);

        let committed = node
            .publish_finished_blob_batch(FinishedBlobBatchRequest::batch_only(vec![
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
        assert_eq!(committed.items.len(), 2);
        let idempotent = node
            .publish_finished_blob(
                topic.clone(),
                scope.clone(),
                Priority::Priority,
                None,
                first.clone(),
            )
            .unwrap();
        assert_eq!(idempotent.id, committed.items[0].id);
        assert_eq!(idempotent.publisher_counter, 1);
        drop(node);

        let mut restarted =
            ApplicationNode::open(&path, &bundle, ApplicationNodeOptions::default()).unwrap();
        let queried = restarted
            .query(Query {
                topic: Some(topic),
                scope: Some(scope),
                class: Some(DataClass::Blob),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(queried.len(), 2);
        assert_eq!(
            queried
                .iter()
                .map(|item| item.logical_key.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                first.id().as_bytes().to_vec(),
                second.id().as_bytes().to_vec(),
            ])
        );

        drop(restarted);
        remove_store(&path);
        fs::remove_dir_all(blob_path).unwrap();
    }

    #[test]
    fn authority_rekey_is_high_water_checked_and_restart_durable() {
        let scope = Scope::new("mission/team").unwrap();
        let topic = Topic::new("ops").unwrap();
        let member_access =
            ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()]).unwrap();
        let relay_access = ProvisioningAccess::relay(scope.clone(), vec![0]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x81; 32]).unwrap();
        let member_bytes = provisioner
            .issue_node(1, std::slice::from_ref(&member_access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let authority_bytes = provisioner
            .issue_control_authority(2, &[member_access])
            .unwrap()
            .to_bytes()
            .unwrap();
        let older_registry = provisioner.export_rekey_registry().unwrap();
        assert_eq!(provisioner.rekey_registry_generation(), 2);
        let relay_bytes = provisioner
            .issue_node(3, &[relay_access])
            .unwrap()
            .to_bytes()
            .unwrap();
        let registry = provisioner.export_rekey_registry().unwrap();
        assert_eq!(provisioner.rekey_registry_generation(), 3);

        let member_path = api_test_path("rekey-member");
        let relay_path = api_test_path("rekey-relay");
        let authority_path = api_test_path("rekey-authority");
        let mut member = ApplicationNode::open(
            &member_path,
            &member_bytes,
            ApplicationNodeOptions::default(),
        )
        .unwrap();
        let member_id = member.identity();
        let relay =
            ApplicationNode::open(&relay_path, &relay_bytes, ApplicationNodeOptions::default())
                .unwrap();
        let relay_id = relay.identity();
        let mut authority = ApplicationNode::open(
            &authority_path,
            &authority_bytes,
            ApplicationNodeOptions::default(),
        )
        .unwrap();
        let authority_id = authority.identity();
        let recipients = || {
            vec![
                RekeyRecipient::read_topics(authority_id, vec![topic.clone()]).unwrap(),
                RekeyRecipient::read_topics(member_id, vec![topic.clone()]).unwrap(),
                RekeyRecipient::route_only(relay_id),
            ]
        };

        // A caller-retained generation of three rejects the authentic older
        // two-entry artifact before it can create a control.
        assert!(
            authority
                .rekey_scope(&older_registry, 3, scope.clone(), 1, recipients())
                .is_err()
        );
        assert!(
            member
                .rekey_scope(
                    &registry,
                    3,
                    scope.clone(),
                    1,
                    vec![RekeyRecipient::read_topics(member_id, vec![topic.clone()]).unwrap(),]
                )
                .is_err(),
            "ordinary member unexpectedly performed authority rekey"
        );

        let mut other = ReferenceProvisioner::from_seed([0x82; 32]).unwrap();
        other
            .issue_node(
                1,
                &[ProvisioningAccess::relay(scope.clone(), vec![0]).unwrap()],
            )
            .unwrap();
        let wrong_authority_registry = other.export_rekey_registry().unwrap();
        assert!(
            authority
                .rekey_scope(&wrong_authority_registry, 1, scope.clone(), 1, recipients(),)
                .is_err()
        );

        let first = authority
            .rekey_scope(&registry, 3, scope.clone(), 1, recipients())
            .unwrap();
        assert_eq!(first.scope, scope);
        assert_eq!(first.epoch, 1);
        assert_eq!(first.registry_generation, 3);
        assert_eq!(first.recipient_count, 3);
        assert_eq!(first.control_sequence, 1);
        drop(authority);

        let mut restarted = ApplicationNode::open(
            &authority_path,
            &authority_bytes,
            ApplicationNodeOptions::default(),
        )
        .unwrap();
        assert!(
            restarted
                .rekey_scope(&older_registry, 3, scope.clone(), 2, recipients())
                .is_err()
        );
        let second = restarted
            .rekey_scope(&registry, 3, scope.clone(), 2, recipients())
            .unwrap();
        assert_eq!(second.epoch, 2);
        assert_eq!(second.registry_generation, 3);
        assert_eq!(second.control_sequence, 2);

        drop(member);
        drop(relay);
        drop(restarted);
        remove_store(&member_path);
        remove_store(&relay_path);
        remove_store(&authority_path);
    }

    #[test]
    fn opaque_bridge_api_enables_and_creates_two_hops_then_rejects_stale_epoch() {
        let alpha = Scope::new("mission/alpha").unwrap();
        let bravo = Scope::new("mission/bravo").unwrap();
        let charlie = Scope::new("mission/charlie").unwrap();
        let ops = Topic::new("ops").unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x83; 32]).unwrap();
        let route_accesses = [
            ProvisioningAccess::relay(alpha.clone(), vec![7]).unwrap(),
            ProvisioningAccess::relay(bravo.clone(), vec![9]).unwrap(),
            ProvisioningAccess::member(charlie.clone(), vec![11], vec![ops.clone()]).unwrap(),
        ];
        let authority_bytes = provisioner
            .issue_control_authority(1, &route_accesses)
            .unwrap()
            .to_bytes()
            .unwrap();
        let bridge_bytes = provisioner
            .issue_node(
                2,
                &[
                    ProvisioningAccess::member(alpha.clone(), vec![7], vec![ops.clone()]).unwrap(),
                    ProvisioningAccess::relay(bravo.clone(), vec![9]).unwrap(),
                    ProvisioningAccess::member(charlie.clone(), vec![11], vec![ops.clone()])
                        .unwrap(),
                ],
            )
            .unwrap()
            .to_bytes()
            .unwrap();
        let authority_path = api_test_path("bridge-authority");
        let bridge_path = api_test_path("bridge-node");
        let mut authority = ApplicationNode::open(
            &authority_path,
            &authority_bytes,
            ApplicationNodeOptions::default(),
        )
        .unwrap();
        let mut bridge = ApplicationNode::open(
            &bridge_path,
            &bridge_bytes,
            ApplicationNodeOptions::default(),
        )
        .unwrap();
        let authority_id = authority
            .inner
            .envelopes()
            .control_authority()
            .unwrap_or_else(|| panic!("authority capability missing"));
        for node in [&mut authority, &mut bridge] {
            configure_epoch(node, authority_id, alpha.clone(), 7);
            configure_epoch(node, authority_id, bravo.clone(), 9);
            configure_epoch(node, authority_id, charlie.clone(), 11);
        }
        bridge
            .set_bridge_filters(&[
                BridgeFilter {
                    from_scope: alpha.clone(),
                    to_scope: bravo.clone(),
                    topics: BTreeSet::from([ops.clone()]),
                    minimum_priority: Priority::Routine,
                },
                BridgeFilter {
                    from_scope: bravo.clone(),
                    to_scope: charlie.clone(),
                    topics: BTreeSet::from([ops.clone()]),
                    minimum_priority: Priority::Routine,
                },
            ])
            .unwrap();
        let policy = BridgeAuthorizationPolicy::new(
            vec![ops.clone()],
            vec![Priority::Immediate, Priority::Flash],
            8,
        )
        .unwrap();
        let first_enrollment = bridge
            .create_bridge_enrollment(alpha.clone(), 7, bravo.clone(), 9)
            .unwrap();
        assert_eq!(first_enrollment.bridge_node(), bridge.identity());
        assert!(!format!("{first_enrollment:?}").contains("credential"));
        let first_authorization = authority
            .enable_bridge(first_enrollment, policy.clone())
            .unwrap();
        let second_enrollment = bridge
            .create_bridge_enrollment(bravo.clone(), 9, charlie.clone(), 11)
            .unwrap();
        let second_authorization = authority
            .enable_bridge(second_enrollment, policy.clone())
            .unwrap();
        assert_eq!(first_authorization.control_sequence, 1);
        assert_eq!(second_authorization.control_sequence, 2);
        copy_bridge_authorization(&mut authority, &mut bridge, first_authorization.id);
        copy_bridge_authorization(&mut authority, &mut bridge, second_authorization.id);

        let source = bridge
            .publish(PublishRequest {
                class: DataClass::State,
                topic: ops.clone(),
                scope: alpha.clone(),
                priority: Priority::Immediate,
                ttl_ms: None,
                logical_key: b"opaque-bridge-api".to_vec(),
                payload: b"never returned by bridge administration".to_vec(),
                tombstone: false,
            })
            .unwrap();
        let narrowing =
            BridgeNarrowingPolicy::new(vec![ops.clone()], vec![Priority::Immediate]).unwrap();
        let first = bridge
            .bridge_item(source.id, first_authorization.id, narrowing.clone())
            .unwrap();
        assert_eq!(first.source_item, source.id);
        assert_eq!(first.current_scope, bravo);
        assert_eq!(first.hop_count, 1);
        assert_eq!(first.status, BridgeCommitStatus::Active);
        let nested = bridge
            .extend_bridge_route(first.handle, second_authorization.id, narrowing.clone())
            .unwrap();
        assert_eq!(nested.source_item, source.id);
        assert_eq!(nested.current_scope, charlie);
        assert_eq!(nested.hop_count, 2);
        assert_eq!(nested.status, BridgeCommitStatus::Active);

        let target_projection = bridge
            .query(Query {
                topic: Some(ops.clone()),
                scope: Some(nested.current_scope.clone()),
                class: Some(DataClass::State),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(target_projection.len(), 1);
        assert_eq!(target_projection[0].id, source.id);
        assert_eq!(target_projection[0].origin_scope, alpha);
        assert_eq!(target_projection[0].current_scope, nested.current_scope);
        assert_eq!(
            target_projection[0].payload,
            b"never returned by bridge administration"
        );
        let deduplicated = bridge
            .query(Query {
                topic: Some(ops.clone()),
                class: Some(DataClass::State),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(
            deduplicated
                .iter()
                .filter(|item| item.id == source.id)
                .count(),
            1,
            "ordinary ItemID must win the wildcard projection"
        );

        assert_eq!(
            BridgeAuthorizationId::from_slice(first_authorization.id.as_bytes()).unwrap(),
            first_authorization.id
        );
        assert!(BridgeAuthorizationId::from_slice(&[0u8; 31]).is_err());
        assert_eq!(
            BridgeRouteHandle::from_slice(nested.handle.as_bytes()).unwrap(),
            nested.handle
        );
        assert!(BridgeRouteHandle::from_slice(&[0u8; 33]).is_err());
        let authorization_status = bridge
            .bridge_authorization_status(first_authorization.id)
            .unwrap()
            .unwrap();
        assert!(authorization_status.current);
        assert!(authorization_status.enabled);
        assert!(authorization_status.usable);
        assert_eq!(bridge.bridge_authorizations(None, 8).unwrap().len(), 2);
        let route_status = bridge.bridge_route_status(nested.handle).unwrap().unwrap();
        assert!(route_status.active);
        assert!(route_status.live);
        assert_eq!(route_status.current_scope, charlie);
        assert_eq!(bridge.bridge_routes(None, 8).unwrap().len(), 2);

        let projected_subscription = bridge
            .subscribe(ops.clone(), charlie.clone(), Some(DataClass::State), false)
            .unwrap();
        let deliveries = bridge.poll(projected_subscription, 8).unwrap();
        assert_eq!(deliveries.len(), 1);
        assert_eq!(deliveries[0].item.id, source.id);
        assert_eq!(deliveries[0].item.current_scope, charlie);
        bridge
            .acknowledge(projected_subscription, deliveries[0].item.id)
            .unwrap();
        assert!(bridge.poll(projected_subscription, 8).unwrap().is_empty());

        let mut source_events = Vec::new();
        for payload in [b"one".as_slice(), b"two", b"three"] {
            source_events.push(
                bridge
                    .publish(PublishRequest {
                        class: DataClass::Event,
                        topic: ops.clone(),
                        scope: alpha.clone(),
                        priority: Priority::Immediate,
                        ttl_ms: None,
                        logical_key: Vec::new(),
                        payload: payload.to_vec(),
                        tombstone: false,
                    })
                    .unwrap(),
            );
        }
        for event in [&source_events[0], &source_events[2]] {
            let first_event_route = bridge
                .bridge_item(event.id, first_authorization.id, narrowing.clone())
                .unwrap();
            bridge
                .extend_bridge_route(
                    first_event_route.handle,
                    second_authorization.id,
                    narrowing.clone(),
                )
                .unwrap();
        }
        let gaps = bridge
            .event_gaps(Query {
                topic: Some(ops.clone()),
                scope: Some(charlie.clone()),
                class: Some(DataClass::Event),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(gaps.len(), 1);
        assert_eq!((gaps[0].start_sequence, gaps[0].end_sequence), (2, 3));

        let bridged_record = bridge
            .publish(PublishRequest {
                class: DataClass::Record,
                topic: ops.clone(),
                scope: alpha.clone(),
                priority: Priority::Immediate,
                ttl_ms: None,
                logical_key: b"projection-conflict".to_vec(),
                payload: b"bridged-version".to_vec(),
                tombstone: false,
            })
            .unwrap();
        let first_record_route = bridge
            .bridge_item(bridged_record.id, first_authorization.id, narrowing.clone())
            .unwrap();
        bridge
            .extend_bridge_route(
                first_record_route.handle,
                second_authorization.id,
                narrowing.clone(),
            )
            .unwrap();
        let ordinary_record = authority
            .publish(PublishRequest {
                class: DataClass::Record,
                topic: ops.clone(),
                scope: charlie.clone(),
                priority: Priority::Immediate,
                ttl_ms: None,
                logical_key: b"projection-conflict".to_vec(),
                payload: b"ordinary-version".to_vec(),
                tombstone: false,
            })
            .unwrap();
        copy_ordinary_item(&mut authority, &mut bridge, ordinary_record.id);
        let conflict_query = Query {
            topic: Some(ops.clone()),
            scope: Some(charlie.clone()),
            class: Some(DataClass::Record),
            logical_key: Some(b"projection-conflict".to_vec()),
            ..Query::default()
        };
        let conflicts = bridge.conflicts(conflict_query.clone()).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].siblings.len(), 2);
        assert!(conflicts[0].siblings.contains(&bridged_record.id));
        assert!(conflicts[0].siblings.contains(&ordinary_record.id));
        let conflict_subscription = bridge
            .subscribe(ops.clone(), charlie.clone(), Some(DataClass::Record), false)
            .unwrap();
        let conflict_deliveries = bridge.poll(conflict_subscription, 8).unwrap();
        let delivered_siblings = conflict_deliveries
            .iter()
            .map(|delivery| delivery.item.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            delivered_siblings,
            conflicts[0].siblings.iter().copied().collect()
        );
        for delivery in conflict_deliveries {
            bridge
                .acknowledge(conflict_subscription, delivery.item.id)
                .unwrap();
        }
        let resolved = bridge
            .resolve(ResolveRequest {
                topic: ops.clone(),
                scope: charlie.clone(),
                logical_key: b"projection-conflict".to_vec(),
                expected_siblings: conflicts[0].siblings.clone(),
                payload: b"resolved-version".to_vec(),
                priority: Priority::Immediate,
                ttl_ms: None,
            })
            .unwrap();
        let resolution_delivery = bridge.poll(conflict_subscription, 8).unwrap();
        assert_eq!(resolution_delivery.len(), 1);
        assert_eq!(resolution_delivery[0].item.id, resolved.id);
        assert!(bridge.conflicts(conflict_query.clone()).unwrap().is_empty());
        let resolved_projection = bridge.query(conflict_query).unwrap();
        assert_eq!(resolved_projection.len(), 1);
        assert_eq!(resolved_projection[0].id, resolved.id);
        assert_eq!(resolved_projection[0].payload, b"resolved-version");

        // Handles remain sufficient after a standalone restart. Opening the
        // application node reauthenticates durable controls/routes before any
        // status or target-projection query is admitted.
        drop(bridge);
        let mut bridge = ApplicationNode::open(
            &bridge_path,
            &bridge_bytes,
            ApplicationNodeOptions::default(),
        )
        .unwrap();
        assert!(
            bridge
                .bridge_authorization_status(first_authorization.id)
                .unwrap()
                .unwrap()
                .usable
        );
        assert!(
            bridge
                .bridge_route_status(nested.handle)
                .unwrap()
                .unwrap()
                .live
        );
        assert_eq!(bridge.bridge_authorizations(None, 8).unwrap().len(), 2);
        assert_eq!(bridge.bridge_routes(None, 8).unwrap().len(), 8);
        assert!(bridge.poll(projected_subscription, 8).unwrap().is_empty());
        let restarted_projection = bridge
            .query(Query {
                topic: Some(ops.clone()),
                scope: Some(charlie.clone()),
                class: Some(DataClass::State),
                ..Query::default()
            })
            .unwrap();
        assert_eq!(restarted_projection.len(), 1);
        assert_eq!(restarted_projection[0].id, source.id);

        let stale = bridge
            .create_bridge_enrollment(alpha.clone(), 7, bravo, 9)
            .unwrap();
        configure_epoch(&mut authority, authority_id, alpha, 8);
        assert!(authority.enable_bridge(stale, policy).is_err());

        drop(authority);
        drop(bridge);
        remove_store(&authority_path);
        remove_store(&bridge_path);
    }
}
