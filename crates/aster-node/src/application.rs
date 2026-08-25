//! High-level selected Event application surface.
//!
//! This module deliberately exposes no source-envelope, cryptographic-provider,
//! carrier, inventory, reconciliation, or sealed-byte operations. It composes
//! the same mission-bound redb authority used by the selected runtime and
//! freshly verifies every application result before returning plaintext.

use std::{fmt, fs, path::Path};

use aster_mesh::{EventContentVerification, ReferenceEnvelopeSealer};
pub use aster_mesh::{NodeId, Priority, Scope, Topic};
use aster_redb_store::{
    ControlPolicySnapshot, ControlTransferId, EventDeliveryAck as StoreEventDeliveryAck,
    EventOperationKey, EventQueryFilter, EventSemanticId,
    EventSubscriptionId as StoreEventSubscriptionId, EventSubscriptionKey, EventSubscriptionMode,
    EventSubscriptionPollSelection, EventSubscriptionSpec, MAX_EVENT_PAGE,
    MAX_EVENT_POLL_DELIVERIES, MAX_EVENT_SUBSCRIPTION_SCAN, Store, StoreError, StoredEvent,
};

use crate::{
    NodeError,
    mission::UnprotectedReferenceMission,
    runtime::{
        EVENT_OPERATION_CONFLICT, STORE_FILE, SelectedEventPublish, ensure_principal_active,
        ensure_state_accepts_normal_operation, event_is_inactive, open_replayed_verifier,
        publish_selected_event_once, refresh_application_policy, verify_content_stored_claim,
        verify_stored_claim,
    },
};

/// Maximum number of accepted Event rows one query call may scan.
pub const MAX_SELECTED_EVENT_PAGE: usize = MAX_EVENT_PAGE;

/// Maximum number of at-least-once deliveries returned by one poll.
pub const MAX_SELECTED_EVENT_DELIVERIES: usize = MAX_EVENT_POLL_DELIVERIES;

/// Maximum accepted or pending rows freshly verified by one poll.
pub const MAX_SELECTED_EVENT_SUBSCRIPTION_SCAN: usize = MAX_EVENT_SUBSCRIPTION_SCAN;

/// Stable, high-level failure category for selected Event operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApplicationErrorKind {
    InvalidRequest,
    RequestRejected,
    UnauthorizedOrRevoked,
    PolicyUnsettled,
    Conflict,
    ResourceLimit,
    StateUnavailable,
    Integrity,
    Provisioning,
}

/// Sanitized selected Event application failure.
///
/// The underlying store, source-envelope, carrier, and provider errors remain
/// private so an application cannot couple itself to privileged mechanics or
/// learn exact transfer/schema details through an error path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ApplicationError {
    kind: ApplicationErrorKind,
    operation: &'static str,
}

impl ApplicationError {
    /// Stable category suitable for application control flow.
    pub const fn kind(&self) -> ApplicationErrorKind {
        self.kind
    }

    /// High-level operation that failed.
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    const fn new(kind: ApplicationErrorKind, operation: &'static str) -> Self {
        Self { kind, operation }
    }
}

impl fmt::Display for ApplicationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let disposition = match self.kind {
            ApplicationErrorKind::InvalidRequest => "invalid application request",
            ApplicationErrorKind::RequestRejected => "request rejected by selected Event policy",
            ApplicationErrorKind::UnauthorizedOrRevoked => {
                "application identity or Event is not currently authorized"
            }
            ApplicationErrorKind::PolicyUnsettled => "mission policy is not settled",
            ApplicationErrorKind::Conflict => "idempotency or causal conflict",
            ApplicationErrorKind::ResourceLimit => "selected Event resource limit reached",
            ApplicationErrorKind::StateUnavailable => "selected Event state is unavailable",
            ApplicationErrorKind::Integrity => "selected Event integrity check failed",
            ApplicationErrorKind::Provisioning => "mission provisioning is unavailable",
        };
        write!(
            formatter,
            "selected Event {} failed: {disposition}",
            self.operation
        )
    }
}

impl std::error::Error for ApplicationError {}

/// Source-authenticated semantic identity returned to applications.
///
/// This deliberately omits the randomized exact transfer representation used
/// by reconciliation. Application deduplication uses this semantic identity
/// instead.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventId([u8; 32]);

impl EventId {
    /// Constructs an application Event identity from complete semantic identity bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete semantic identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_store(id: EventSemanticId) -> Self {
        Self(*id.as_bytes())
    }

    fn into_store(self) -> EventSemanticId {
        EventSemanticId::new(self.0)
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// One durable, idempotent Event publication request.
///
/// The operation key is application-chosen and bounded to 256 bytes. Reusing
/// the same key with the same request returns the original Event; reusing it
/// with different content fails closed. Resolution still requires the caller
/// to remain authorized by current mission policy. Finite TTL is intentionally
/// absent until authenticated cumulative forwarding age is implemented.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPublishRequest {
    pub operation_key: Vec<u8>,
    pub predecessor: Option<EventId>,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
}

/// Successful durable publication without sealed bytes or provider internals.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventPublishResult {
    pub id: EventId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub event_sequence: u64,
    pub priority: Priority,
    pub acceptance_marker: u64,
    pub inserted: bool,
}

/// Bounded application query over content-accepted Event rows.
///
/// `limit` bounds rows scanned, not only rows returned. A selective query may
/// therefore return no items while `has_more` is true; continue from the
/// returned `scanned_through` marker.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventQuery {
    pub publisher: Option<NodeId>,
    pub topic: Option<Topic>,
    pub scope: Option<Scope>,
    pub include_descendant_scopes: bool,
    pub logical_key: Option<Vec<u8>>,
    pub after_acceptance_marker: u64,
    pub limit: usize,
}

impl Default for EventQuery {
    fn default() -> Self {
        Self {
            publisher: None,
            topic: None,
            scope: None,
            include_descendant_scopes: false,
            logical_key: None,
            after_acceptance_marker: 0,
            limit: 128,
        }
    }
}

impl EventQuery {
    fn validate(&self) -> Result<(), ApplicationError> {
        if self.limit == 0 || self.limit > MAX_SELECTED_EVENT_PAGE {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "query",
            ));
        }
        Ok(())
    }

    fn matches_verified(&self, event: &StoredEvent) -> bool {
        self.publisher
            .is_none_or(|publisher| event.header.stamp.dot.publisher == publisher)
            && self
                .topic
                .as_ref()
                .is_none_or(|topic| &event.header.topic == topic)
            && self.scope.as_ref().is_none_or(|scope| {
                if self.include_descendant_scopes {
                    scope.contains(&event.header.scope)
                } else {
                    &event.header.scope == scope
                }
            })
            && self
                .logical_key
                .as_ref()
                .is_none_or(|key| &event.header.logical_key == key)
    }
}

/// One freshly source/content-verified application Event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventItem {
    pub id: EventId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub event_sequence: u64,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
    pub acceptance_marker: u64,
}

/// Marker-ordered bounded query result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventQueryPage {
    pub items: Vec<EventItem>,
    pub scanned_through: u64,
    pub has_more: bool,
}

/// Stable mission-local identity of one durable application subscription.
///
/// This is a local ledger identity, not a content or route capability.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventSubscriptionId([u8; 32]);

impl EventSubscriptionId {
    /// Constructs an identifier from complete durable bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete durable identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_store(id: StoreEventSubscriptionId) -> Self {
        Self(*id.as_bytes())
    }

    fn into_store(self) -> StoreEventSubscriptionId {
        StoreEventSubscriptionId::from_bytes(self.0)
    }
}

impl fmt::Display for EventSubscriptionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Idempotent creation request for one durable Consume subscription.
///
/// The operation key identifies the subscription across process restarts.
/// Topic and scope intent never grant authority: current mission policy must
/// independently permit both route verification and content opening.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventSubscriptionRequest {
    pub operation_key: Vec<u8>,
    pub topic: Topic,
    pub scope: Scope,
    pub include_descendant_scopes: bool,
}

/// Result of creating or replaying one durable subscription request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventSubscription {
    pub id: EventSubscriptionId,
    pub inserted: bool,
}

/// One bounded at-least-once delivery poll.
///
/// `scan_limit` bounds all pending and accepted rows freshly source-verified,
/// not only matching rows returned. An empty page can therefore report
/// `has_more=true`; poll again to continue from the durable internal cursor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventPollRequest {
    pub subscription: EventSubscriptionId,
    pub delivery_limit: usize,
    pub scan_limit: usize,
}

impl EventPollRequest {
    fn validate(self) -> Result<Self, ApplicationError> {
        if self.delivery_limit == 0
            || self.delivery_limit > MAX_SELECTED_EVENT_DELIVERIES
            || self.scan_limit == 0
            || self.scan_limit > MAX_SELECTED_EVENT_SUBSCRIPTION_SCAN
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "poll",
            ));
        }
        Ok(self)
    }
}

/// One Event delivery whose attempt was durably incremented before return.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventDelivery {
    pub event: EventItem,
    pub attempt: u64,
}

/// Bounded at-least-once delivery result.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct EventDeliveryPage {
    pub deliveries: Vec<EventDelivery>,
    pub has_more: bool,
}

/// Idempotent acknowledgement disposition for one semantic Event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventAcknowledgement {
    Acknowledged,
    AlreadyAcknowledged,
}

enum VerifiedSubscriptionCandidate {
    Inactive(EventSemanticId),
    NotSelected,
    Delivery(EventSemanticId, EventItem),
}

/// Exclusive high-level handle over the selected Event composition.
///
/// This stopped-state handle owns the same exact redb writer lock as the mesh
/// runtime, so a second process cannot mutate or query around its policy
/// snapshot. A later stacked slice adds a live actor handle while `run_node`
/// owns this authority.
pub struct SelectedEventNode {
    mission: UnprotectedReferenceMission,
    store: Store,
    verifier: ReferenceEnvelopeSealer,
    verifier_head: Option<(u64, ControlTransferId)>,
}

impl SelectedEventNode {
    /// Opens the current explicitly unprotected reference provisioning path.
    ///
    /// Terminal state is rejected before mission bytes are loaded. The mission
    /// authority is then bound to the exact no-follow redb file, all committed
    /// controls are freshly replayed, and pending control gaps defer use.
    pub fn open_unprotected_reference(
        state: impl AsRef<Path>,
        mission_bundle: impl AsRef<Path>,
    ) -> Result<Self, ApplicationError> {
        let state = state.as_ref();
        ensure_state_accepts_normal_operation(state)
            .map_err(|error| application_error("open", error))?;
        let mission = UnprotectedReferenceMission::load(mission_bundle)
            .map_err(|error| application_error("open", error.into()))?;
        fs::create_dir_all(state).map_err(|error| application_error("open", error.into()))?;
        let store = Store::open_for_mission(state.join(STORE_FILE), mission.mission_authority_id())
            .map_err(|error| application_error("open", error.into()))?;
        store
            .require_process_exclusive_lock()
            .map_err(|error| application_error("open", error.into()))?;
        let verifier = open_replayed_verifier(&store, &mission)
            .map_err(|error| application_error("open", error))?;
        ensure_principal_active(&store, verifier.identity())
            .map_err(|error| application_error("open", error))?;
        let verifier_head = store
            .control_head()
            .map_err(|error| application_error("open", error.into()))?;
        let mut selected = Self {
            mission,
            store,
            verifier,
            verifier_head,
        };
        selected.current_policy("open")?;
        Ok(selected)
    }

    /// Authenticated local publisher identity.
    pub fn identity(&self) -> NodeId {
        self.verifier.identity()
    }

    /// Stable mission authority bound to this store and provisioning artifact.
    pub const fn mission_authority(&self) -> NodeId {
        self.mission.mission_authority_id()
    }

    /// Idempotently creates one durable application-delivery subscription.
    ///
    /// The local selector is intersected with current mission route and
    /// content capabilities. It narrows what the node asks to receive and does
    /// not grant authority to receive, retain, or open an Event.
    pub fn subscribe(
        &mut self,
        request: EventSubscriptionRequest,
    ) -> Result<EventSubscription, ApplicationError> {
        let EventSubscriptionRequest {
            operation_key,
            topic,
            scope,
            include_descendant_scopes,
        } = request;
        let key = EventSubscriptionKey::new(operation_key)
            .map_err(|error| application_error("subscribe", error.into()))?;
        let policy = self.current_policy("subscribe")?;
        let epoch = self
            .store
            .active_scope_epoch(&scope)
            .map_err(|error| application_error("subscribe", error.into()))?
            .map_or(1, |(epoch, _)| epoch);
        if !self.verifier.can_route_event(&scope, epoch)
            || !self.verifier.can_open_event_content(&scope, &topic, epoch)
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                "subscribe",
            ));
        }
        let outcome = self
            .store
            .create_event_subscription_with_policy(
                &policy,
                &key,
                EventSubscriptionSpec {
                    mode: EventSubscriptionMode::Consume,
                    topic,
                    scope,
                    include_descendant_scopes,
                },
            )
            .map_err(|error| application_error("subscribe", error.into()))?;
        Ok(EventSubscription {
            id: EventSubscriptionId::from_store(outcome.id),
            inserted: outcome.inserted,
        })
    }

    /// Polls one durable subscription with at-least-once delivery semantics.
    ///
    /// Every pending and newly accepted row in the bounded plan is freshly
    /// source-verified before the durable discovery cursor advances. Matching
    /// active rows are also content-verified. Attempts are incremented in the
    /// same commit that records delivery, so a crash before return repeats the
    /// Event with a larger attempt number until acknowledged.
    pub fn poll(
        &mut self,
        request: EventPollRequest,
    ) -> Result<EventDeliveryPage, ApplicationError> {
        let request = request.validate()?;
        let policy = self.current_policy("poll")?;
        let plan = self
            .store
            .prepare_event_subscription_poll_with_policy(
                &policy,
                request.subscription.into_store(),
                request.delivery_limit,
                request.scan_limit,
            )
            .map_err(|error| application_error("poll", error.into()))?;
        let spec = plan.spec().clone();
        let mut selection = EventSubscriptionPollSelection::default();
        let mut opened = Vec::new();

        for candidate in plan.pending_candidates() {
            match self.verify_subscription_candidate(&spec, candidate.event.clone())? {
                VerifiedSubscriptionCandidate::Inactive(id) => {
                    selection.inactive_pending.push(id);
                }
                VerifiedSubscriptionCandidate::Delivery(id, event) => {
                    selection.deliveries.push(id);
                    opened.push((id, event));
                }
                VerifiedSubscriptionCandidate::NotSelected => {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "poll",
                    ));
                }
            }
        }
        for candidate in plan.scanned_candidates() {
            match self.verify_subscription_candidate(&spec, candidate.clone())? {
                VerifiedSubscriptionCandidate::Delivery(id, event) => {
                    selection.deliveries.push(id);
                    opened.push((id, event));
                }
                VerifiedSubscriptionCandidate::Inactive(_)
                | VerifiedSubscriptionCandidate::NotSelected => {}
            }
        }

        let committed = self
            .store
            .commit_event_subscription_poll_with_policy(&policy, &plan, &selection)
            .map_err(|error| application_error("poll", error.into()))?;
        if committed.deliveries.len() != opened.len() {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "poll",
            ));
        }
        let mut deliveries = Vec::with_capacity(committed.deliveries.len());
        for (committed, (verified_id, event)) in committed.deliveries.into_iter().zip(opened) {
            if committed.event.semantic_id != verified_id {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "poll",
                ));
            }
            deliveries.push(EventDelivery {
                event,
                attempt: committed.attempt,
            });
        }
        Ok(EventDeliveryPage {
            deliveries,
            has_more: committed.has_more,
        })
    }

    /// Idempotently acknowledges one semantic Event delivery.
    pub fn acknowledge(
        &mut self,
        subscription: EventSubscriptionId,
        event: EventId,
    ) -> Result<EventAcknowledgement, ApplicationError> {
        let policy = self.current_policy("acknowledge")?;
        match self
            .store
            .acknowledge_event_delivery_with_policy(
                &policy,
                subscription.into_store(),
                event.into_store(),
            )
            .map_err(|error| application_error("acknowledge", error.into()))?
        {
            StoreEventDeliveryAck::Acknowledged => Ok(EventAcknowledgement::Acknowledged),
            StoreEventDeliveryAck::AlreadyAcknowledged => {
                Ok(EventAcknowledgement::AlreadyAcknowledged)
            }
        }
    }

    /// Durably publishes one arbitrary selected Event exactly once per operation key.
    pub fn publish(
        &mut self,
        request: EventPublishRequest,
    ) -> Result<EventPublishResult, ApplicationError> {
        let EventPublishRequest {
            operation_key,
            predecessor,
            topic,
            scope,
            priority,
            logical_key,
            payload,
            tombstone,
        } = request;
        let operation = EventOperationKey::new(operation_key)
            .map_err(|error| application_error("publish", error.into()))?;
        let predecessor = predecessor.map(EventId::into_store);
        let policy = self.current_policy("publish")?;
        let (stored, inserted) = publish_selected_event_once(
            &self.store,
            &policy,
            &mut self.verifier,
            SelectedEventPublish {
                operation: &operation,
                predecessor,
                topic: &topic,
                scope: &scope,
                priority,
                logical_key: &logical_key,
                payload: &payload,
                tombstone,
            },
        )
        .map_err(|error| application_error("publish", error))?;
        Ok(EventPublishResult {
            id: EventId::from_store(stored.semantic_id),
            publisher: stored.header.stamp.dot.publisher,
            publisher_counter: stored.header.stamp.dot.counter,
            event_sequence: event_sequence(&stored, "publish")?,
            priority: stored.header.priority,
            acceptance_marker: stored.acceptance_marker,
            inserted,
        })
    }

    /// Returns one bounded marker-ordered page of active, content-verified Events.
    pub fn query(&mut self, query: EventQuery) -> Result<EventQueryPage, ApplicationError> {
        query.validate()?;
        let policy = self.current_policy("query")?;
        let candidates = self
            .store
            .query_event_candidates_with_policy(
                &policy,
                &EventQueryFilter::default(),
                query.after_acceptance_marker,
                query.limit,
            )
            .map_err(|error| application_error("query", error.into()))?;
        let mut items = Vec::with_capacity(candidates.events.len());
        for event in candidates.events {
            if let Some(item) = self.open_application_event(&query, event)? {
                items.push(item);
            }
        }
        Ok(EventQueryPage {
            items,
            scanned_through: candidates.scanned_through,
            has_more: candidates.has_more,
        })
    }

    fn verify_subscription_candidate(
        &mut self,
        spec: &EventSubscriptionSpec,
        stored: StoredEvent,
    ) -> Result<VerifiedSubscriptionCandidate, ApplicationError> {
        let route_verified = self
            .verifier
            .verify_event(&stored.sealed)
            .map_err(|error| application_error("poll", error.into()))?;
        verify_stored_claim(
            &route_verified,
            stored.transfer_id,
            stored.semantic_id,
            &stored.header,
        )
        .map_err(|error| application_error("poll", error))?;
        if event_is_inactive(&self.store, &route_verified)
            .map_err(|error| application_error("poll", error))?
        {
            return Ok(VerifiedSubscriptionCandidate::Inactive(stored.semantic_id));
        }
        let matches = spec.topic == stored.header.topic
            && if spec.include_descendant_scopes {
                spec.scope.contains(&stored.header.scope)
            } else {
                spec.scope == stored.header.scope
            };
        if !matches {
            return Ok(VerifiedSubscriptionCandidate::NotSelected);
        }
        let payload = match self
            .verifier
            .verify_event_content(route_verified, &stored.sealed)
            .map_err(|error| application_error("poll", error.into()))?
        {
            EventContentVerification::ContentVerified { event, payload } => {
                verify_content_stored_claim(&event, &stored)
                    .map_err(|error| application_error("poll", error))?;
                payload
            }
            EventContentVerification::RouteOnly(_) => {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "poll",
                ));
            }
        };
        let id = stored.semantic_id;
        Ok(VerifiedSubscriptionCandidate::Delivery(
            id,
            EventItem {
                id: EventId::from_store(id),
                publisher: stored.header.stamp.dot.publisher,
                publisher_counter: stored.header.stamp.dot.counter,
                event_sequence: event_sequence(&stored, "poll")?,
                topic: stored.header.topic,
                scope: stored.header.scope,
                priority: stored.header.priority,
                logical_key: stored.header.logical_key,
                payload,
                tombstone: stored.header.tombstone,
                acceptance_marker: stored.acceptance_marker,
            },
        ))
    }

    fn current_policy(
        &mut self,
        operation: &'static str,
    ) -> Result<ControlPolicySnapshot, ApplicationError> {
        match refresh_application_policy(
            &self.store,
            &self.mission,
            &mut self.verifier,
            &mut self.verifier_head,
        ) {
            Ok(Some(policy)) => Ok(policy),
            Ok(None) => Err(ApplicationError::new(
                ApplicationErrorKind::PolicyUnsettled,
                operation,
            )),
            Err(error) => Err(application_error(operation, error)),
        }
    }

    fn open_application_event(
        &mut self,
        query: &EventQuery,
        stored: StoredEvent,
    ) -> Result<Option<EventItem>, ApplicationError> {
        let route_verified = self
            .verifier
            .verify_event(&stored.sealed)
            .map_err(|error| application_error("query", error.into()))?;
        verify_stored_claim(
            &route_verified,
            stored.transfer_id,
            stored.semantic_id,
            &stored.header,
        )
        .map_err(|error| application_error("query", error))?;
        if !query.matches_verified(&stored) {
            return Ok(None);
        }
        if event_is_inactive(&self.store, &route_verified)
            .map_err(|error| application_error("query", error))?
        {
            return Ok(None);
        }
        let payload = match self
            .verifier
            .verify_event_content(route_verified, &stored.sealed)
            .map_err(|error| application_error("query", error.into()))?
        {
            EventContentVerification::ContentVerified { event, payload } => {
                verify_content_stored_claim(&event, &stored)
                    .map_err(|error| application_error("query", error))?;
                payload
            }
            EventContentVerification::RouteOnly(_) => {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "query",
                ));
            }
        };
        Ok(Some(EventItem {
            id: EventId::from_store(stored.semantic_id),
            publisher: stored.header.stamp.dot.publisher,
            publisher_counter: stored.header.stamp.dot.counter,
            event_sequence: event_sequence(&stored, "query")?,
            topic: stored.header.topic,
            scope: stored.header.scope,
            priority: stored.header.priority,
            logical_key: stored.header.logical_key,
            payload,
            tombstone: stored.header.tombstone,
            acceptance_marker: stored.acceptance_marker,
        }))
    }
}

fn event_sequence(stored: &StoredEvent, operation: &'static str) -> Result<u64, ApplicationError> {
    stored
        .header
        .event_sequence
        .ok_or_else(|| ApplicationError::new(ApplicationErrorKind::Integrity, operation))
}

fn application_error(operation: &'static str, error: NodeError) -> ApplicationError {
    let kind = match error {
        NodeError::Configuration(_) => ApplicationErrorKind::InvalidRequest,
        NodeError::MissionProvisioning(_) => ApplicationErrorKind::Provisioning,
        NodeError::Revoked(_) => ApplicationErrorKind::UnauthorizedOrRevoked,
        NodeError::SourceEnvelope(_) if operation == "publish" => {
            ApplicationErrorKind::RequestRejected
        }
        NodeError::SourceEnvelope(_) => ApplicationErrorKind::Integrity,
        NodeError::Store(error) => store_error_kind(&error),
        NodeError::Protocol(message) if message == EVENT_OPERATION_CONFLICT => {
            ApplicationErrorKind::Conflict
        }
        NodeError::Protocol(_) => ApplicationErrorKind::Integrity,
        NodeError::Identity(_)
        | NodeError::SoftwareErasure(_)
        | NodeError::Mission(_)
        | NodeError::Reconciliation(_)
        | NodeError::Carrier(_)
        | NodeError::Io(_)
        | NodeError::Demo(_) => ApplicationErrorKind::StateUnavailable,
    };
    ApplicationError::new(kind, operation)
}

fn store_error_kind(error: &StoreError) -> ApplicationErrorKind {
    match error {
        StoreError::InvalidEventOperationKey { .. }
        | StoreError::InvalidEventSubscriptionKey { .. }
        | StoreError::EventPageLimitExceeded { .. }
        | StoreError::EventSubscriptionNotFound
        | StoreError::EventSubscriptionNotConsumable
        | StoreError::EventSubscriptionPollLimitExceeded { .. }
        | StoreError::EventDeliveryNotFound
        | StoreError::EventReplicationNotSelected
        | StoreError::EventReplicationNotConsumable
        | StoreError::InvalidSemanticEvent(_)
        | StoreError::AuthenticatedCustodyAgeRequired => ApplicationErrorKind::InvalidRequest,
        StoreError::EventPublisherRevoked(_)
        | StoreError::EventKeyEpochStale { .. }
        | StoreError::MissionAuthorityMismatch { .. }
        | StoreError::ControlSignerRevoked(_)
        | StoreError::ControlAuthorityRevoked(_) => ApplicationErrorKind::UnauthorizedOrRevoked,
        StoreError::ControlPolicyUnsettled { .. }
        | StoreError::ControlPolicyChanged
        | StoreError::ReservationChanged
        | StoreError::EventSubscriptionPlanChanged
        | StoreError::EventSelectorRevisionChanged => ApplicationErrorKind::PolicyUnsettled,
        StoreError::IdentityConflict { .. }
        | StoreError::SemanticRepresentationConflict { .. }
        | StoreError::CausalEquivocation { .. }
        | StoreError::EventEquivocation { .. }
        | StoreError::MissingReactionPredecessor { .. }
        | StoreError::ReactionContextMissing { .. }
        | StoreError::OperationPredecessorMismatch
        | StoreError::EventSubscriptionConflict => ApplicationErrorKind::Conflict,
        StoreError::ItemLimitExceeded { .. }
        | StoreError::EventSubscriptionLimitExceeded { .. }
        | StoreError::EventPendingDeliveryLimitExceeded { .. }
        | StoreError::EventAcknowledgementReceiptLimitExceeded { .. }
        | StoreError::EventDeliveryAttemptExhausted
        | StoreError::PayloadByteLimitExceeded { .. }
        | StoreError::AcceptanceMarkerExhausted
        | StoreError::ItemCountAccountingOverflow
        | StoreError::PayloadByteAccountingOverflow
        | StoreError::RouteCacheItemLimitExceeded { .. }
        | StoreError::RouteCacheByteLimitExceeded { .. }
        | StoreError::RouteCacheSemanticRepresentationLimit { .. }
        | StoreError::ControlItemLimitExceeded { .. }
        | StoreError::ControlByteLimitExceeded { .. }
        | StoreError::ControlSequenceExhausted => ApplicationErrorKind::ResourceLimit,
        StoreError::Backend(_)
        | StoreError::StorePath(_)
        | StoreError::StoreBackingInvariant(_)
        | StoreError::MissionNotBound
        | StoreError::ProcessExclusiveLockUnavailable
        | StoreError::StoreInUse
        | StoreError::StoreZeroized(_) => ApplicationErrorKind::StateUnavailable,
        StoreError::SemanticVerification(_)
        | StoreError::MissingAcceptanceMarker { .. }
        | StoreError::OrphanedAcceptanceMarker { .. }
        | StoreError::InvalidStoredIdLength { .. }
        | StoreError::AccountingMismatch { .. }
        | StoreError::MissingAccountingMetadata { .. }
        | StoreError::SemanticInvariant(_)
        | StoreError::ControlVerification(_)
        | StoreError::InvalidControl(_)
        | StoreError::ControlFork
        | StoreError::ControlRollback
        | StoreError::ControlReservationChanged
        | StoreError::ControlInvariant(_)
        | StoreError::InvalidControlPublicationIntent
        | StoreError::MissingControlPublicationIntent
        | StoreError::ControlPublicationIntentUnknown { .. }
        | StoreError::ControlPublicationIntentConflict { .. }
        | StoreError::TransferNamespaceCollision { .. }
        | StoreError::ZeroizationInvariant(_)
        | StoreError::InvalidZeroizationDescriptor { .. }
        | StoreError::ZeroizationIntentConflict
        | StoreError::ZeroizationOrderViolation(_) => ApplicationErrorKind::Integrity,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use aster_mesh::{ProvisioningAccess, ReferenceProvisioner};

    use super::*;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-selected-event-{}-{sequence}-{label}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn selected_node(root: &TestRoot) -> SelectedEventNode {
        let scope = Scope::new("mission/apps").expect("scope");
        let alpha = Topic::new("ops.alpha").expect("topic");
        let beta = Topic::new("ops.beta").expect("topic");
        let access =
            ProvisioningAccess::member(scope, vec![1], vec![alpha, beta]).expect("member access");
        let mut provisioner = ReferenceProvisioner::from_seed([0x5a; 32]).expect("provisioner");
        let bytes = provisioner
            .issue_node(1, &[access])
            .expect("issue node")
            .to_bytes()
            .expect("encode mission");
        let mission_path = root.path().join("mission.unprotected-reference.bundle");
        drop(
            UnprotectedReferenceMission::persist(&mission_path, bytes)
                .expect("persist owner-only mission"),
        );
        SelectedEventNode::open_unprotected_reference(root.path(), &mission_path)
            .expect("open selected Event node")
    }

    fn request(operation: &[u8], topic: &str, key: &[u8], payload: &[u8]) -> EventPublishRequest {
        EventPublishRequest {
            operation_key: operation.to_vec(),
            predecessor: None,
            topic: Topic::new(topic).expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            priority: Priority::Priority,
            logical_key: key.to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
        }
    }

    fn subscription_request(operation: &[u8], topic: &str) -> EventSubscriptionRequest {
        EventSubscriptionRequest {
            operation_key: operation.to_vec(),
            topic: Topic::new(topic).expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            include_descendant_scopes: false,
        }
    }

    #[test]
    fn arbitrary_event_publish_query_and_retry_share_one_selected_authority() {
        let root = TestRoot::new("publish-query");
        let mut node = selected_node(&root);
        let first_request = request(b"ops/first", "ops.alpha", b"asset-7", b"ready");
        let first = node.publish(first_request.clone()).expect("publish first");
        assert!(first.inserted);
        assert_eq!(first.publisher_counter, 1);
        assert_eq!(first.event_sequence, 1);
        assert_eq!(first.priority, Priority::Priority);

        let retried = node.publish(first_request).expect("retry first");
        assert!(!retried.inserted);
        assert_eq!(retried.id, first.id);
        assert_eq!(retried.acceptance_marker, first.acceptance_marker);

        let second = node
            .publish(request(b"ops/second", "ops.beta", b"asset-8", b"moving"))
            .expect("publish second");
        assert!(second.inserted);
        assert_eq!(second.publisher_counter, 2);
        assert_eq!(second.event_sequence, 1);

        let first_scan = node
            .query(EventQuery {
                topic: Some(Topic::new("ops.beta").expect("topic")),
                limit: 1,
                ..EventQuery::default()
            })
            .expect("first selective scan");
        assert!(first_scan.items.is_empty());
        assert_eq!(first_scan.scanned_through, first.acceptance_marker);
        assert!(first_scan.has_more);

        let second_scan = node
            .query(EventQuery {
                topic: Some(Topic::new("ops.beta").expect("topic")),
                after_acceptance_marker: first_scan.scanned_through,
                limit: 1,
                ..EventQuery::default()
            })
            .expect("second selective scan");
        assert_eq!(second_scan.items.len(), 1);
        assert_eq!(second_scan.items[0].id, second.id);
        assert_eq!(second_scan.items[0].payload, b"moving");
        assert!(!second_scan.has_more);

        let all = node.query(EventQuery::default()).expect("query all");
        assert_eq!(all.items.len(), 2);
        assert_eq!(all.scanned_through, 2);
        assert!(!all.has_more);
    }

    #[test]
    fn durable_subscription_repeats_until_idempotent_ack_across_restart() {
        let root = TestRoot::new("subscription-retry");
        let (subscription_id, event_id) = {
            let mut node = selected_node(&root);
            let published = node
                .publish(request(
                    b"ops/subscribed",
                    "ops.alpha",
                    b"asset-7",
                    b"ready",
                ))
                .expect("publish");
            let subscription = node
                .subscribe(subscription_request(b"subscriptions/alpha", "ops.alpha"))
                .expect("subscribe");
            assert!(subscription.inserted);
            let replayed = node
                .subscribe(subscription_request(b"subscriptions/alpha", "ops.alpha"))
                .expect("replay subscribe");
            assert!(!replayed.inserted);
            assert_eq!(replayed.id, subscription.id);
            let conflict = node
                .subscribe(subscription_request(b"subscriptions/alpha", "ops.beta"))
                .expect_err("subscription operation mismatch must fail");
            assert_eq!(conflict.kind(), ApplicationErrorKind::Conflict);

            let first = node
                .poll(EventPollRequest {
                    subscription: subscription.id,
                    delivery_limit: 8,
                    scan_limit: 8,
                })
                .expect("first poll");
            assert_eq!(first.deliveries.len(), 1);
            assert_eq!(first.deliveries[0].event.id, published.id);
            assert_eq!(first.deliveries[0].attempt, 1);
            assert!(!first.has_more);
            (subscription.id, published.id)
        };

        let mut reopened = SelectedEventNode::open_unprotected_reference(
            root.path(),
            root.path().join("mission.unprotected-reference.bundle"),
        )
        .expect("reopen selected Event node");
        let repeated = reopened
            .poll(EventPollRequest {
                subscription: subscription_id,
                delivery_limit: 8,
                scan_limit: 8,
            })
            .expect("repeat pending delivery");
        assert_eq!(repeated.deliveries.len(), 1);
        assert_eq!(repeated.deliveries[0].event.id, event_id);
        assert_eq!(repeated.deliveries[0].attempt, 2);

        assert_eq!(
            reopened
                .acknowledge(subscription_id, event_id)
                .expect("acknowledge"),
            EventAcknowledgement::Acknowledged
        );
        assert_eq!(
            reopened
                .acknowledge(subscription_id, event_id)
                .expect("idempotent acknowledge"),
            EventAcknowledgement::AlreadyAcknowledged
        );
        assert!(
            reopened
                .poll(EventPollRequest {
                    subscription: subscription_id,
                    delivery_limit: 8,
                    scan_limit: 8,
                })
                .expect("empty after acknowledgement")
                .deliveries
                .is_empty()
        );
    }

    #[test]
    fn subscription_scan_advances_over_verified_nonmatching_events() {
        let root = TestRoot::new("subscription-selective-scan");
        let mut node = selected_node(&root);
        node.publish(request(
            b"ops/alpha-first",
            "ops.alpha",
            b"asset-7",
            b"alpha",
        ))
        .expect("publish alpha");
        let beta = node
            .publish(request(b"ops/beta-second", "ops.beta", b"asset-8", b"beta"))
            .expect("publish beta");
        let subscription = node
            .subscribe(subscription_request(b"subscriptions/beta", "ops.beta"))
            .expect("subscribe beta");

        let first = node
            .poll(EventPollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 1,
            })
            .expect("scan nonmatching alpha");
        assert!(first.deliveries.is_empty());
        assert!(first.has_more);

        let second = node
            .poll(EventPollRequest {
                subscription: subscription.id,
                delivery_limit: 1,
                scan_limit: 1,
            })
            .expect("deliver matching beta");
        assert_eq!(second.deliveries.len(), 1);
        assert_eq!(second.deliveries[0].event.id, beta.id);
        assert_eq!(second.deliveries[0].event.payload, b"beta");
        assert_eq!(second.deliveries[0].attempt, 1);
        assert!(!second.has_more);
    }

    #[test]
    fn reused_operation_with_different_application_contract_fails_closed() {
        let root = TestRoot::new("operation-conflict");
        let mut node = selected_node(&root);
        node.publish(request(b"ops/stable", "ops.alpha", b"asset", b"first"))
            .expect("publish");
        let error = node
            .publish(request(b"ops/stable", "ops.alpha", b"asset", b"different"))
            .expect_err("operation mismatch must fail");
        assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
        assert_eq!(
            node.query(EventQuery::default())
                .expect("query")
                .items
                .len(),
            1
        );
    }

    #[test]
    fn public_facade_restart_reuses_the_exact_durable_operation() {
        let root = TestRoot::new("restart-operation");
        let request = request(b"ops/restart", "ops.alpha", b"asset", b"ready");
        let first = {
            let mut node = selected_node(&root);
            node.publish(request.clone()).expect("initial publication")
        };
        let mut reopened = SelectedEventNode::open_unprotected_reference(
            root.path(),
            root.path().join("mission.unprotected-reference.bundle"),
        )
        .expect("reopen selected Event node");
        let retried = reopened.publish(request).expect("restart retry");
        assert!(!retried.inserted);
        assert_eq!(retried.id, first.id);
        assert_eq!(retried.publisher_counter, first.publisher_counter);
        assert_eq!(retried.event_sequence, first.event_sequence);
        assert_eq!(retried.acceptance_marker, first.acceptance_marker);
    }

    #[test]
    fn query_limits_and_tombstone_payloads_fail_before_publication() {
        let root = TestRoot::new("bounds");
        let mut node = selected_node(&root);
        assert!(
            node.query(EventQuery {
                limit: 0,
                ..EventQuery::default()
            })
            .is_err()
        );
        let mut tombstone = request(b"ops/tombstone", "ops.alpha", b"asset", b"not-empty");
        tombstone.tombstone = true;
        assert!(node.publish(tombstone).is_err());
        assert!(
            node.query(EventQuery::default())
                .expect("query")
                .items
                .is_empty()
        );
    }

    #[test]
    fn unauthorized_topic_fails_without_consuming_publisher_or_stream_position() {
        let root = TestRoot::new("unauthorized-topic");
        let mut node = selected_node(&root);
        let denied_subscription = node
            .subscribe(subscription_request(
                b"subscriptions/denied",
                "ops.unprovisioned",
            ))
            .expect_err("unprovisioned subscription must fail");
        assert_eq!(
            denied_subscription.kind(),
            ApplicationErrorKind::RequestRejected
        );
        let denied = node
            .publish(request(
                b"ops/denied",
                "ops.unprovisioned",
                b"asset",
                b"denied",
            ))
            .expect_err("unprovisioned topic must fail");
        assert_eq!(denied.kind(), ApplicationErrorKind::RequestRejected);
        assert!(std::error::Error::source(&denied).is_none());
        for rendered in [format!("{denied}"), format!("{denied:?}")] {
            assert!(!rendered.contains("source Event"));
            assert!(!rendered.contains("redb"));
            assert!(!rendered.contains("ops.unprovisioned"));
            assert!(!rendered.contains("transfer"));
        }
        let accepted = node
            .publish(request(b"ops/accepted", "ops.alpha", b"asset", b"accepted"))
            .expect("authorized Event");
        assert_eq!(accepted.publisher_counter, 1);
        assert_eq!(accepted.event_sequence, 1);
        assert_eq!(accepted.acceptance_marker, 1);
        assert_eq!(
            node.query(EventQuery::default())
                .expect("query")
                .items
                .len(),
            1
        );
    }
}
