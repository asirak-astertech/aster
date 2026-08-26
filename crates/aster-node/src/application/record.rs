//! High-level stopped-state surface for source-authenticated Record projections.
//!
//! The application handle is deliberately stopped/exclusive. It shares the
//! exact mission-bound store, control policy, provider, and causal ledger with
//! the selected Event and State surfaces. A separately running node can
//! reconcile its durable Record objects through the class-specific Record lane
//! when the receiver declares an exact source interest. Network ingest never
//! executes application merge code: conflicts remain explicit until an
//! application submits a guarded successor that observes the complete sibling
//! set it inspected.

use std::{fmt, fs, path::Path, sync::Arc};

use aster_mesh::{
    CausalStamp, NodeId, Priority, RecordContentVerification, ReferenceEnvelopeSealer,
    RouteVerifiedRecordEnvelope, Scope, Topic,
};
use aster_redb_store::{
    ControlPolicySnapshot, ControlTransferId, RecordOperationKey, RecordOperationRequest,
    RecordProjectionPlan, RecordPublicationIntent, RecordResolutionRequest as StoreResolution,
    RecordSemanticId, RecordSenderProjection, RecordVersionDisposition as StoreRecordDisposition,
    Store, StoredRecord,
};

use super::{ApplicationError, ApplicationErrorKind, application_error};
use crate::{
    frame::MAX_OBJECT_BYTES,
    mission::UnprotectedReferenceMission,
    runtime::{
        AuthenticatedEventRouteCache, STORE_FILE, StartupEventVerification,
        ensure_principal_active, ensure_state_accepts_normal_operation,
        open_startup_event_verifier_and_cache, refresh_application_policy,
    },
};

/// Source-authenticated semantic identity of one Record version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordId([u8; 32]);

impl RecordId {
    /// Constructs an identity from its complete semantic bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete semantic identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_store(id: RecordSemanticId) -> Self {
        Self(*id.as_bytes())
    }
}

impl fmt::Display for RecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// One durable, operation-key-idempotent Record publication request.
///
/// This creates an ordinary causal Record successor. It is not a conflict
/// resolution request and carries no application merge callback, so it fails
/// when the exact key currently has multiple heads. A tombstone is
/// authenticated and therefore requires an empty payload. Finite TTL is absent
/// until authenticated cumulative forwarding age exists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordPublishRequest {
    pub operation_key: Vec<u8>,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
}

/// Causal disposition of one retained, active Record version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordVersionDisposition {
    /// Deterministic application-visible head.
    Current,
    /// Another causal maximum retained as an explicit conflict sibling.
    Concurrent,
    /// A retained version observed by a later version.
    Superseded,
}

/// Successful durable Record publication or explicit resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordPublishResult {
    pub id: RecordId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub priority: Priority,
    pub acceptance_marker: u64,
    pub inserted: bool,
}

/// Exact logical-key query for one selected Record projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordQuery {
    pub topic: Topic,
    pub scope: Scope,
    pub logical_key: Vec<u8>,
    /// Include active causally dominated versions in `superseded`.
    ///
    /// Every current-lineage candidate is freshly opened; a retained candidate
    /// whose route key was replaced at the same epoch is withheld only after
    /// its exact startup-authenticated cache claim matches the current Store
    /// projection. Concurrent active heads can never be hidden by this option.
    pub include_superseded_versions: bool,
}

/// One freshly source/content-verified retained Record version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordItem {
    pub id: RecordId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
    pub acceptance_marker: u64,
    pub disposition: RecordVersionDisposition,
}

/// Opaque exact sibling/projection guard returned by a verified query.
///
/// The private plan lets a byte-for-byte retry remain idempotent after its
/// successful resolution advances the Record heads. Applications can inspect
/// only the authenticated head identities; sealed representations and store
/// mechanics do not cross this boundary.
#[derive(Clone, Eq, PartialEq)]
pub struct RecordResolutionGuard {
    plan: RecordProjectionPlan,
    siblings: Vec<RecordId>,
}

impl RecordResolutionGuard {
    /// Exact numeric-policy causal heads, sorted by complete semantic identity.
    ///
    /// A head whose same-epoch route lineage was replaced can appear here even
    /// though its plaintext is withheld from the projection. The opaque ID is
    /// still bound to a startup-authenticated exact source and is necessary to
    /// authorize a successor that closes the durable Store conflict.
    pub fn siblings(&self) -> &[RecordId] {
        &self.siblings
    }

    /// Exact selected topic protected by this guard.
    pub const fn topic(&self) -> &Topic {
        self.plan.topic()
    }

    /// Exact selected scope protected by this guard.
    pub const fn scope(&self) -> &Scope {
        self.plan.scope()
    }

    /// Exact selected logical key protected by this guard.
    pub fn logical_key(&self) -> &[u8] {
        self.plan.logical_key()
    }
}

impl fmt::Debug for RecordResolutionGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordResolutionGuard")
            .field("topic", self.topic())
            .field("scope", self.scope())
            .field("logical_key", &self.logical_key())
            .field("siblings", &self.siblings)
            .finish_non_exhaustive()
    }
}

/// Explicit application-visible Record conflict annotation.
///
/// No merge policy is run by Aster. Applications may inspect the authenticated
/// sibling identities, compute a deterministic result from any visible values
/// and their own policy, then submit the embedded guard through
/// [`SelectedRecordNode::resolve`]. A conflict can contain only opaque IDs when
/// every numeric-policy head has a superseded route lineage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordConflict {
    pub siblings: Vec<RecordId>,
    pub resolution_guard: RecordResolutionGuard,
}

/// Deterministic Record projection with explicit conflict and history lanes.
///
/// A current tombstone remains visible; deletion never wins a concurrent tie
/// merely because it is a tombstone. The numeric Store reduction is checked
/// before the stricter route-lineage reduction; inactive and cache-proven
/// superseded-lineage rows are not exposed as [`RecordItem`] plaintext. Their
/// authenticated IDs remain in `conflict` when required to resolve an exact
/// durable multi-head plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordProjection {
    pub current: Option<RecordItem>,
    pub concurrent: Vec<RecordItem>,
    pub superseded: Vec<RecordItem>,
    pub conflict: Option<RecordConflict>,
}

/// Explicit conflict resolution guarded by the exact projection inspected.
///
/// The resulting version is an ordinary Record successor whose causal context
/// must observe every guarded sibling. Reusing the operation key with different
/// intent fails closed; replaying the exact request returns the original row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordResolveRequest {
    pub operation_key: Vec<u8>,
    pub resolution_guard: RecordResolutionGuard,
    pub priority: Priority,
    pub payload: Vec<u8>,
    pub tombstone: bool,
}

struct VerifiedRecordCandidate {
    id: RecordId,
    item: Option<RecordItem>,
    stamp: CausalStamp,
    store_disposition: Option<StoreRecordDisposition>,
    policy_active: bool,
    active: bool,
}

/// Exclusive stopped-state handle over selected Record projections.
///
/// The handle owns the same process-exclusive mission-bound redb writer as the
/// Event facade, State facade, and live runtime. Record reconciliation and
/// automatic merging are deliberately absent from this local slice.
pub struct SelectedRecordNode {
    mission: UnprotectedReferenceMission,
    store: Arc<Store>,
    verifier: ReferenceEnvelopeSealer,
    historical_verifier: ReferenceEnvelopeSealer,
    verifier_head: Option<(u64, ControlTransferId)>,
    source_route_cache: Arc<AuthenticatedEventRouteCache>,
}

impl SelectedRecordNode {
    /// Opens the explicitly unprotected reference provisioning path.
    ///
    /// Terminal state is rejected before mission bytes are loaded. The exact
    /// store is mission-bound and process-locked, every retained exact source
    /// is proved across ordered control replay, then the current verifier and
    /// bounded route-lineage cache become available to Record operations.
    pub fn open_unprotected_reference(
        state: impl AsRef<Path>,
        mission_bundle: impl AsRef<Path>,
    ) -> Result<Self, ApplicationError> {
        let state = state.as_ref();
        ensure_state_accepts_normal_operation(state)
            .map_err(|error| application_error("record open", error))?;
        let mission = UnprotectedReferenceMission::load(mission_bundle)
            .map_err(|error| application_error("record open", error.into()))?;
        fs::create_dir_all(state)
            .map_err(|error| application_error("record open", error.into()))?;
        let store = Store::open_for_mission(state.join(STORE_FILE), mission.mission_authority_id())
            .map_err(|error| application_error("record open", error.into()))?;
        store
            .require_process_exclusive_lock()
            .map_err(|error| application_error("record open", error.into()))?;
        let StartupEventVerification {
            verifier,
            historical_verifier,
            cache: source_route_cache,
            policy: _,
        } = open_startup_event_verifier_and_cache(&store, &mission)
            .map_err(|error| application_error("record open", error))?;
        ensure_principal_active(&store, verifier.identity())
            .map_err(|error| application_error("record open", error))?;
        let verifier_head = store
            .control_head()
            .map_err(|error| application_error("record open", error.into()))?;
        let mut selected = Self {
            mission,
            store: Arc::new(store),
            verifier,
            historical_verifier,
            verifier_head,
            source_route_cache,
        };
        selected.current_policy("record open")?;
        Ok(selected)
    }

    /// Authenticated local Record publisher identity.
    pub fn identity(&self) -> NodeId {
        self.verifier.identity()
    }

    /// Stable mission authority bound to provisioning and the durable store.
    pub const fn mission_authority(&self) -> NodeId {
        self.mission.mission_authority_id()
    }

    /// Durably publishes one ordinary Record version exactly once per operation key.
    pub fn publish(
        &mut self,
        request: RecordPublishRequest,
    ) -> Result<RecordPublishResult, ApplicationError> {
        let RecordPublishRequest {
            operation_key,
            topic,
            scope,
            priority,
            logical_key,
            payload,
            tombstone,
        } = request;
        if payload.len() > MAX_OBJECT_BYTES {
            return Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "record publish",
            ));
        }
        let operation = RecordOperationKey::new(operation_key)
            .map_err(|error| application_error("record publish", error.into()))?;
        let intent = RecordPublicationIntent::new(
            self.identity(),
            topic.clone(),
            scope.clone(),
            priority,
            logical_key.clone(),
            &payload,
            tombstone,
        )
        .map_err(|error| application_error("record publish", error.into()))?;
        let operation_request = RecordOperationRequest::new(&operation, &intent, &payload)
            .map_err(|error| application_error("record publish", error.into()))?;
        let policy = self.current_policy("record publish")?;
        let epoch = self.active_epoch(&scope, "record publish")?;
        self.require_record_grants(&topic, &scope, epoch, "record publish")?;
        let reservation = self
            .store
            .reserve_record_with_policy(&policy, self.identity(), &topic, &scope)
            .map_err(|error| application_error("record publish", error.into()))?;
        let content_len = u64::try_from(payload.len()).map_err(|_| {
            ApplicationError::new(ApplicationErrorKind::ResourceLimit, "record publish")
        })?;
        let header = reservation
            .header(priority, logical_key, content_len, tombstone, epoch)
            .map_err(|error| application_error("record publish", error.into()))?;
        let sealed = self
            .verifier
            .seal_record(&header, &payload)
            .map_err(|error| application_error("record publish", error.into()))?;
        if sealed.bytes.len() > MAX_OBJECT_BYTES {
            return Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "record publish",
            ));
        }
        let verified = self.open_published_record(&sealed.bytes, &payload, "record publish")?;
        let outcome = self
            .store
            .commit_reserved_record_once_with_policy(
                &policy,
                &operation_request,
                &reservation,
                &verified,
                &sealed.bytes,
            )
            .map_err(|error| application_error("record publish", error.into()))?;
        let record = outcome.record();
        self.verify_publication_result(
            &policy,
            &intent,
            &payload,
            record,
            outcome.inserted(),
            "record publish",
        )?;
        Ok(record_result(record, outcome.inserted()))
    }

    /// Returns one exact-key projection after freshly verifying every retained candidate.
    pub fn query(&mut self, query: RecordQuery) -> Result<RecordProjection, ApplicationError> {
        let policy = self.current_policy("record query")?;
        let epoch = self.active_epoch(&query.scope, "record query")?;
        self.require_record_grants(&query.topic, &query.scope, epoch, "record query")?;
        let plan = self
            .store
            .prepare_record_projection_with_policy(
                &policy,
                &query.topic,
                &query.scope,
                &query.logical_key,
            )
            .map_err(|error| application_error("record query", error.into()))?;
        let projection = self.verify_projection(&query, &plan, "record query")?;
        self.store
            .require_record_projection_plan_with_policy(&policy, &plan)
            .map_err(|error| application_error("record query", error.into()))?;
        Ok(projection)
    }

    /// Publishes one ordinary successor guarded by an exact verified conflict plan.
    ///
    /// The guard must contain at least two active heads and remain current at
    /// commit. A stale guard fails atomically without inserting the successor.
    /// An exact retry of an already committed operation remains idempotent even
    /// though that successful successor has advanced the current projection.
    pub fn resolve(
        &mut self,
        request: RecordResolveRequest,
    ) -> Result<RecordPublishResult, ApplicationError> {
        let RecordResolveRequest {
            operation_key,
            resolution_guard,
            priority,
            payload,
            tombstone,
        } = request;
        if resolution_guard.siblings.len() < 2 {
            return Err(ApplicationError::new(
                ApplicationErrorKind::InvalidRequest,
                "record resolve",
            ));
        }
        if payload.len() > MAX_OBJECT_BYTES {
            return Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "record resolve",
            ));
        }
        let RecordResolutionGuard { plan, siblings } = resolution_guard;
        let policy = self.current_policy("record resolve")?;
        let epoch = self.active_epoch(plan.scope(), "record resolve")?;
        self.require_record_grants(plan.topic(), plan.scope(), epoch, "record resolve")?;
        if plan.control_policy() == &policy {
            let inspected = self.verify_projection(
                &RecordQuery {
                    topic: plan.topic().clone(),
                    scope: plan.scope().clone(),
                    logical_key: plan.logical_key().to_vec(),
                    include_superseded_versions: true,
                },
                &plan,
                "record resolve",
            )?;
            let inspected_siblings = inspected
                .conflict
                .as_ref()
                .map(|conflict| conflict.siblings.as_slice())
                .ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Conflict, "record resolve")
                })?;
            if inspected_siblings != siblings {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "record resolve",
                ));
            }
        } else {
            // An opaque guard can outlive a rekey. Freshly authenticate every
            // historical candidate, but leave replay/new-operation
            // discrimination to the store's guard-bound operation digest. A
            // new operation cannot commit against the stale policy; an exact
            // authorized retry may resolve its original durable result.
            self.verify_historical_resolution_guard(&policy, &plan, &siblings)?;
        }

        let operation = RecordOperationKey::new(operation_key)
            .map_err(|error| application_error("record resolve", error.into()))?;
        let intent = RecordPublicationIntent::new(
            self.identity(),
            plan.topic().clone(),
            plan.scope().clone(),
            priority,
            plan.logical_key().to_vec(),
            &payload,
            tombstone,
        )
        .map_err(|error| application_error("record resolve", error.into()))?;
        let publication = RecordOperationRequest::new(&operation, &intent, &payload)
            .map_err(|error| application_error("record resolve", error.into()))?;
        let resolution = StoreResolution::new(&publication, &plan)
            .map_err(|error| application_error("record resolve", error.into()))?;
        let reservation = self
            .store
            .reserve_record_with_policy(&policy, self.identity(), plan.topic(), plan.scope())
            .map_err(|error| application_error("record resolve", error.into()))?;
        let content_len = u64::try_from(payload.len()).map_err(|_| {
            ApplicationError::new(ApplicationErrorKind::ResourceLimit, "record resolve")
        })?;
        let header = reservation
            .header(
                priority,
                plan.logical_key().to_vec(),
                content_len,
                tombstone,
                epoch,
            )
            .map_err(|error| application_error("record resolve", error.into()))?;
        for head in plan.heads() {
            if !header
                .stamp
                .context
                .observes(head.record().header.stamp.dot)
            {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "record resolve",
                ));
            }
        }
        let sealed = self
            .verifier
            .seal_record(&header, &payload)
            .map_err(|error| application_error("record resolve", error.into()))?;
        if sealed.bytes.len() > MAX_OBJECT_BYTES {
            return Err(ApplicationError::new(
                ApplicationErrorKind::ResourceLimit,
                "record resolve",
            ));
        }
        let verified = self.open_published_record(&sealed.bytes, &payload, "record resolve")?;
        let outcome = self
            .store
            .commit_reserved_record_resolution_once_with_policy(
                &policy,
                &resolution,
                &reservation,
                &verified,
                &sealed.bytes,
            )
            .map_err(|error| application_error("record resolve", error.into()))?;
        let record = outcome.record();
        self.verify_publication_result(
            &policy,
            &intent,
            &payload,
            record,
            outcome.inserted(),
            "record resolve",
        )?;
        if !context_observes_all(
            &record.header.stamp.context,
            plan.heads().map(|head| head.record().header.stamp.dot),
        ) {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "record resolve",
            ));
        }
        Ok(record_result(record, outcome.inserted()))
    }

    fn open_published_record(
        &mut self,
        sealed: &[u8],
        payload: &[u8],
        operation: &'static str,
    ) -> Result<aster_mesh::ContentVerifiedRecordEnvelope, ApplicationError> {
        let route = self
            .verifier
            .verify_record(sealed)
            .map_err(|error| application_error(operation, error.into()))?;
        match self
            .verifier
            .verify_record_content(route, sealed)
            .map_err(|error| application_error(operation, error.into()))?
        {
            RecordContentVerification::ContentVerified {
                record,
                payload: opened,
            } if opened == payload => {
                record
                    .verify_exact_payload(payload)
                    .map_err(|error| application_error(operation, error.into()))?;
                Ok(record)
            }
            RecordContentVerification::ContentVerified { .. }
            | RecordContentVerification::RouteOnly(_) => Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            )),
        }
    }

    fn verify_publication_result(
        &mut self,
        policy: &ControlPolicySnapshot,
        intent: &RecordPublicationIntent,
        payload: &[u8],
        stored: &StoredRecord,
        inserted: bool,
        operation: &'static str,
    ) -> Result<(), ApplicationError> {
        let route = match self.verifier.verify_record(&stored.sealed) {
            Ok(route) => route,
            Err(error) if inserted => return Err(application_error(operation, error.into())),
            Err(_) => {
                return self.verify_historical_publication_result(
                    policy, intent, payload, stored, operation,
                );
            }
        };
        Self::verify_publication_route(
            &self.store,
            &mut self.verifier,
            intent,
            payload,
            stored,
            route,
            operation,
        )
    }

    fn verify_historical_publication_result(
        &mut self,
        policy: &ControlPolicySnapshot,
        intent: &RecordPublicationIntent,
        payload: &[u8],
        stored: &StoredRecord,
        operation: &'static str,
    ) -> Result<(), ApplicationError> {
        let projection = self
            .store
            .retained_record_sender_inventory_with_policy(policy)
            .map_err(|error| application_error(operation, error.into()))?
            .into_iter()
            .find(|projection| projection.transfer_id() == stored.transfer_id)
            .ok_or_else(|| ApplicationError::new(ApplicationErrorKind::Integrity, operation))?;
        if projection.semantic_id() != stored.semantic_id
            || projection.publisher() != stored.header.stamp.dot.publisher
            || projection.topic() != &stored.header.topic
            || projection.scope() != &stored.header.scope
            || projection.key_epoch() != stored.header.key_epoch
            || projection.exact_len()
                != u64::try_from(stored.sealed.len()).map_err(|_| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, operation)
                })?
            || projection.acceptance_marker() != stored.acceptance_marker
            || self
                .source_route_cache
                .is_current_record_sender_projection(&self.verifier, &projection)
                .map_err(|error| application_error(operation, error))?
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        let route = self
            .historical_verifier
            .verify_record(&stored.sealed)
            .map_err(|error| application_error(operation, error.into()))?;
        if self.verifier.is_current_source_route_lineage(
            route.scope(),
            route.key_epoch(),
            route.route_lineage(),
        ) {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        Self::verify_publication_route(
            &self.store,
            &mut self.historical_verifier,
            intent,
            payload,
            stored,
            route,
            operation,
        )
    }

    fn verify_publication_route(
        store: &Store,
        verifier: &mut ReferenceEnvelopeSealer,
        intent: &RecordPublicationIntent,
        payload: &[u8],
        stored: &StoredRecord,
        route: RouteVerifiedRecordEnvelope,
        operation: &'static str,
    ) -> Result<(), ApplicationError> {
        if route.envelope_id() != *stored.transfer_id.as_bytes()
            || route.item_id() != *stored.semantic_id.as_bytes()
            || route.header() != &stored.header
            || route.publisher() != intent.publisher()
            || route.topic() != intent.topic()
            || route.scope() != intent.scope()
            || route.priority() != intent.priority()
            || route.logical_key() != intent.logical_key()
            || route.content_len() != intent.content_len()
            || route.tombstone() != intent.tombstone()
            || route.ttl_ms().is_some()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        if store
            .is_control_principal_revoked(route.publisher())
            .map_err(|error| application_error(operation, error.into()))?
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                operation,
            ));
        }
        let current_epoch = store
            .active_scope_epoch(route.scope())
            .map(|epoch| epoch.map_or(1, |(epoch, _)| epoch))
            .map_err(|error| application_error(operation, error.into()))?;
        if route.key_epoch() > current_epoch {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        if !verifier.can_route_record(route.scope(), route.key_epoch())
            || !verifier.can_open_record_content(route.scope(), route.topic(), route.key_epoch())
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        match verifier
            .verify_record_content(route, &stored.sealed)
            .map_err(|error| application_error(operation, error.into()))?
        {
            RecordContentVerification::ContentVerified {
                record,
                payload: opened,
            } if opened == payload => record
                .verify_exact_payload(payload)
                .map_err(|error| application_error(operation, error.into())),
            RecordContentVerification::ContentVerified { .. }
            | RecordContentVerification::RouteOnly(_) => Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            )),
        }
    }

    fn verify_projection(
        &mut self,
        query: &RecordQuery,
        plan: &RecordProjectionPlan,
        operation: &'static str,
    ) -> Result<RecordProjection, ApplicationError> {
        if plan.topic() != &query.topic
            || plan.scope() != &query.scope
            || plan.logical_key() != query.logical_key
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }

        let mut candidates = Vec::with_capacity(plan.candidates().len());
        let retained_projections = self
            .store
            .retained_record_sender_inventory_with_policy(plan.control_policy())
            .map_err(|error| application_error(operation, error.into()))?;
        let mut previous = None;
        for candidate in plan.candidates() {
            let record = candidate.record();
            let id = RecordId::from_store(record.semantic_id);
            if previous.is_some_and(|previous| previous >= id) {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    operation,
                ));
            }
            previous = Some(id);
            let sender_projection = retained_projections
                .iter()
                .find(|projection| projection.transfer_id() == record.transfer_id)
                .ok_or_else(|| ApplicationError::new(ApplicationErrorKind::Integrity, operation))?;
            let (item, policy_active, active) =
                self.open_record_candidate(query, record, sender_projection, operation)?;
            candidates.push(VerifiedRecordCandidate {
                id,
                stamp: record.header.stamp.clone(),
                item,
                store_disposition: candidate.disposition(),
                policy_active,
                active,
            });
        }

        let policy_causal = candidates
            .iter()
            .map(|candidate| (candidate.id, &candidate.stamp, candidate.policy_active))
            .collect::<Vec<_>>();
        let (policy_current_index, policy_dispositions, policy_head_indices) =
            recompute_record_dispositions(&policy_causal);
        let plan_current = plan
            .current()
            .map(|candidate| RecordId::from_store(candidate.record().semantic_id));
        let verified_policy_current = policy_current_index.map(|index| candidates[index].id);
        if plan_current != verified_policy_current {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        let plan_heads = plan
            .heads()
            .map(|candidate| RecordId::from_store(candidate.record().semantic_id))
            .collect::<Vec<_>>();
        let verified_policy_heads = policy_head_indices
            .iter()
            .map(|index| candidates[*index].id)
            .collect::<Vec<_>>();
        if plan_heads != verified_policy_heads {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }

        for (candidate, disposition) in candidates.iter().zip(policy_dispositions) {
            if candidate.store_disposition != disposition.map(RecordVersionDisposition::into_store)
            {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    operation,
                ));
            }
        }

        let current_causal = candidates
            .iter()
            .map(|candidate| (candidate.id, &candidate.stamp, candidate.active))
            .collect::<Vec<_>>();
        let (current_index, dispositions, head_indices) =
            recompute_record_dispositions(&current_causal);
        for (candidate, disposition) in candidates.iter_mut().zip(dispositions) {
            if let Some(disposition) = disposition {
                candidate
                    .item
                    .as_mut()
                    .ok_or_else(|| {
                        ApplicationError::new(ApplicationErrorKind::Integrity, operation)
                    })?
                    .disposition = disposition;
            }
        }

        let current = current_index
            .map(|index| {
                candidates[index].item.clone().ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, operation)
                })
            })
            .transpose()?;
        let concurrent = head_indices
            .iter()
            .copied()
            .filter(|index| Some(*index) != current_index)
            .map(|index| {
                candidates[index].item.clone().ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, operation)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let superseded = if query.include_superseded_versions {
            candidates
                .iter()
                .filter(|candidate| {
                    candidate.active
                        && candidate.item.as_ref().is_some_and(|item| {
                            item.disposition == RecordVersionDisposition::Superseded
                        })
                })
                .filter_map(|candidate| candidate.item.clone())
                .collect()
        } else {
            Vec::new()
        };
        let conflict = (verified_policy_heads.len() > 1).then(|| {
            let resolution_guard = RecordResolutionGuard {
                plan: plan.clone(),
                siblings: verified_policy_heads.clone(),
            };
            RecordConflict {
                siblings: verified_policy_heads,
                resolution_guard,
            }
        });
        Ok(RecordProjection {
            current,
            concurrent,
            superseded,
            conflict,
        })
    }

    fn verify_historical_resolution_guard(
        &mut self,
        policy: &ControlPolicySnapshot,
        plan: &RecordProjectionPlan,
        expected_siblings: &[RecordId],
    ) -> Result<(), ApplicationError> {
        let query = RecordQuery {
            topic: plan.topic().clone(),
            scope: plan.scope().clone(),
            logical_key: plan.logical_key().to_vec(),
            include_superseded_versions: true,
        };
        let retained_projections = self
            .store
            .retained_record_sender_inventory_with_policy(policy)
            .map_err(|error| application_error("record resolve", error.into()))?;
        let mut previous = None;
        for candidate in plan.candidates() {
            let record = candidate.record();
            let id = RecordId::from_store(record.semantic_id);
            if previous.is_some_and(|previous| previous >= id) {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "record resolve",
                ));
            }
            previous = Some(id);
            let sender_projection = retained_projections
                .iter()
                .find(|projection| projection.transfer_id() == record.transfer_id)
                .ok_or_else(|| {
                    ApplicationError::new(ApplicationErrorKind::Integrity, "record resolve")
                })?;
            let _ =
                self.open_record_candidate(&query, record, sender_projection, "record resolve")?;
        }
        let plan_siblings = plan
            .heads()
            .map(|candidate| RecordId::from_store(candidate.record().semantic_id))
            .collect::<Vec<_>>();
        if plan_siblings.len() < 2 || plan_siblings != expected_siblings {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "record resolve",
            ));
        }
        Ok(())
    }

    fn open_record_candidate(
        &mut self,
        query: &RecordQuery,
        stored: &StoredRecord,
        projection: &RecordSenderProjection,
        operation: &'static str,
    ) -> Result<(Option<RecordItem>, bool, bool), ApplicationError> {
        let route = match self.verifier.verify_record(&stored.sealed) {
            Ok(route) => route,
            Err(_) => {
                if stored.header.topic != query.topic
                    || stored.header.scope != query.scope
                    || stored.header.logical_key != query.logical_key
                    || stored.header.ttl_ms.is_some()
                {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        operation,
                    ));
                }
                if projection.semantic_id() != stored.semantic_id
                    || projection.publisher() != stored.header.stamp.dot.publisher
                    || projection.topic() != &stored.header.topic
                    || projection.scope() != &stored.header.scope
                    || projection.key_epoch() != stored.header.key_epoch
                    || projection.exact_len()
                        != u64::try_from(stored.sealed.len()).map_err(|_| {
                            ApplicationError::new(ApplicationErrorKind::Integrity, operation)
                        })?
                    || projection.acceptance_marker() != stored.acceptance_marker
                {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        operation,
                    ));
                }
                let revoked = self
                    .store
                    .is_control_principal_revoked(projection.publisher())
                    .map_err(|error| application_error(operation, error.into()))?;
                let current_epoch = self.active_epoch(projection.scope(), operation)?;
                if projection.key_epoch() > current_epoch {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        operation,
                    ));
                }
                let policy_active = !revoked && projection.key_epoch() == current_epoch;
                let current = self
                    .source_route_cache
                    .is_current_record_sender_projection(&self.verifier, projection)
                    .map_err(|error| application_error(operation, error))?;
                if current {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        operation,
                    ));
                }
                return Ok((None, policy_active, false));
            }
        };
        if route.envelope_id() != *stored.transfer_id.as_bytes()
            || route.item_id() != *stored.semantic_id.as_bytes()
            || route.header() != &stored.header
            || route.topic() != &query.topic
            || route.scope() != &query.scope
            || route.logical_key() != query.logical_key
            || route.ttl_ms().is_some()
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        let revoked = self
            .store
            .is_control_principal_revoked(route.publisher())
            .map_err(|error| application_error(operation, error.into()))?;
        let current_epoch = self.active_epoch(route.scope(), operation)?;
        if route.key_epoch() > current_epoch {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        let policy_active = !revoked && route.key_epoch() == current_epoch;
        let active = policy_active
            && self.verifier.is_current_source_route_lineage(
                route.scope(),
                route.key_epoch(),
                route.route_lineage(),
            );
        if !self
            .verifier
            .can_route_record(route.scope(), route.key_epoch())
            || !self.verifier.can_open_record_content(
                route.scope(),
                route.topic(),
                route.key_epoch(),
            )
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                operation,
            ));
        }
        let payload = match self
            .verifier
            .verify_record_content(route, &stored.sealed)
            .map_err(|error| application_error(operation, error.into()))?
        {
            RecordContentVerification::ContentVerified { record, payload } => {
                record
                    .verify_exact_payload(&payload)
                    .map_err(|error| application_error(operation, error.into()))?;
                payload
            }
            RecordContentVerification::RouteOnly(_) => {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    operation,
                ));
            }
        };
        Ok((
            Some(RecordItem {
                id: RecordId::from_store(stored.semantic_id),
                publisher: stored.header.stamp.dot.publisher,
                publisher_counter: stored.header.stamp.dot.counter,
                topic: stored.header.topic.clone(),
                scope: stored.header.scope.clone(),
                priority: stored.header.priority,
                logical_key: stored.header.logical_key.clone(),
                payload,
                tombstone: stored.header.tombstone,
                acceptance_marker: stored.acceptance_marker,
                disposition: RecordVersionDisposition::Superseded,
            }),
            policy_active,
            active,
        ))
    }

    fn active_epoch(
        &self,
        scope: &Scope,
        operation: &'static str,
    ) -> Result<u64, ApplicationError> {
        self.store
            .active_scope_epoch(scope)
            .map(|epoch| epoch.map_or(1, |(epoch, _)| epoch))
            .map_err(|error| application_error(operation, error.into()))
    }

    fn require_record_grants(
        &self,
        topic: &Topic,
        scope: &Scope,
        epoch: u64,
        operation: &'static str,
    ) -> Result<(), ApplicationError> {
        if self.verifier.can_route_record(scope, epoch)
            && self.verifier.can_open_record_content(scope, topic, epoch)
        {
            Ok(())
        } else {
            Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                operation,
            ))
        }
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
}

fn record_result(record: &StoredRecord, inserted: bool) -> RecordPublishResult {
    RecordPublishResult {
        id: RecordId::from_store(record.semantic_id),
        publisher: record.header.stamp.dot.publisher,
        publisher_counter: record.header.stamp.dot.counter,
        priority: record.header.priority,
        acceptance_marker: record.acceptance_marker,
        inserted,
    }
}

fn context_observes_all(
    context: &aster_mesh::VersionVector,
    dots: impl IntoIterator<Item = aster_mesh::Dot>,
) -> bool {
    dots.into_iter().all(|dot| context.observes(dot))
}

impl RecordVersionDisposition {
    const fn into_store(self) -> StoreRecordDisposition {
        match self {
            Self::Current => StoreRecordDisposition::Current,
            Self::Concurrent => StoreRecordDisposition::Concurrent,
            Self::Superseded => StoreRecordDisposition::Superseded,
        }
    }
}

fn recompute_record_dispositions(
    candidates: &[(RecordId, &CausalStamp, bool)],
) -> (
    Option<usize>,
    Vec<Option<RecordVersionDisposition>>,
    Vec<usize>,
) {
    let mut maximal = candidates
        .iter()
        .map(|(_, _, active)| *active)
        .collect::<Vec<_>>();
    for index in 0..candidates.len() {
        if !candidates[index].2 {
            continue;
        }
        for other in 0..candidates.len() {
            if index != other
                && candidates[other].2
                && candidates[other]
                    .1
                    .context
                    .observes(candidates[index].1.dot)
            {
                maximal[index] = false;
                break;
            }
        }
    }
    let heads = maximal
        .iter()
        .enumerate()
        .filter_map(|(index, maximal)| maximal.then_some(index))
        .collect::<Vec<_>>();
    let current = heads
        .iter()
        .copied()
        .max_by_key(|index| candidates[*index].0);
    let dispositions = candidates
        .iter()
        .enumerate()
        .map(|(index, (_, _, active))| {
            if !active {
                None
            } else if Some(index) == current {
                Some(RecordVersionDisposition::Current)
            } else if maximal[index] {
                Some(RecordVersionDisposition::Concurrent)
            } else {
                Some(RecordVersionDisposition::Superseded)
            }
        })
        .collect();
    (current, dispositions, heads)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use aster_mesh::{
        ContentVerifiedRecordEnvelope, Dot, ProvisioningAccess, ReferenceProvisioner,
        ScopeRekeyRecipient, VersionVector,
    };
    use aster_redb_store::RecordReservation;
    use redb::ReadableTable as _;

    use super::*;
    use crate::application::{SelectedStateNode, StateQuery};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-selected-record-{}-{sequence}-{label}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn mission_path(&self) -> PathBuf {
            self.path().join("mission.unprotected-reference.bundle")
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn record_topic() -> Topic {
        Topic::new("ops.record").expect("topic")
    }

    fn record_scope() -> Scope {
        Scope::new("mission/apps").expect("scope")
    }

    fn persist_mission(root: &TestRoot) {
        let access = ProvisioningAccess::member(
            record_scope(),
            vec![1],
            vec![
                record_topic(),
                Topic::new("ops.state").expect("State topic"),
            ],
        )
        .expect("member access");
        let mut provisioner = ReferenceProvisioner::from_seed([0x82; 32]).expect("provisioner");
        let bytes = provisioner
            .issue_node(1, &[access])
            .expect("issue node")
            .to_bytes()
            .expect("encode mission");
        drop(
            UnprotectedReferenceMission::persist(root.mission_path(), bytes)
                .expect("persist mission"),
        );
    }

    struct RecordRekeyServices {
        control_authority: ReferenceEnvelopeSealer,
        registry: Vec<u8>,
        authority: NodeId,
        selected_identity: NodeId,
    }

    fn persist_rekeyable_mission(root: &TestRoot) -> RecordRekeyServices {
        let access = ProvisioningAccess::member(
            record_scope(),
            vec![1],
            vec![
                record_topic(),
                Topic::new("ops.state").expect("State topic"),
            ],
        )
        .expect("member access");
        let mut provisioner =
            ReferenceProvisioner::from_seed([0x83; 32]).expect("rekey provisioner");
        let control_authority = provisioner
            .issue_control_authority(60, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("control authority");
        let selected_bytes = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .expect("issue selected node")
            .to_bytes()
            .expect("encode selected mission");
        let selected_mission = UnprotectedReferenceMission::from_bytes(selected_bytes.clone())
            .expect("parse selected mission");
        let selected_identity = ReferenceEnvelopeSealer::open(
            selected_mission
                .fresh_bundle()
                .expect("fresh selected bundle"),
        )
        .expect("inspect selected identity")
        .identity();
        let registry = provisioner.export_rekey_registry().expect("rekey registry");
        drop(
            UnprotectedReferenceMission::persist(root.mission_path(), selected_bytes)
                .expect("persist rekeyable mission"),
        );
        RecordRekeyServices {
            authority: control_authority.mission_authority_id(),
            control_authority,
            registry,
            selected_identity,
        }
    }

    fn apply_same_epoch_rekey(root: &TestRoot, services: &mut RecordRekeyServices) {
        let recipients = vec![
            ScopeRekeyRecipient::member(
                services.control_authority.identity(),
                vec![record_topic()],
            )
            .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.selected_identity, vec![record_topic()])
                .expect("selected recipient"),
        ];
        let (sealed, _) = services
            .control_authority
            .seal_chained_scope_rekey_control_from_registry(
                &services.registry,
                0,
                record_scope(),
                1,
                recipients,
                1,
                None,
            )
            .expect("seal same-epoch rekey");
        let verified = services
            .control_authority
            .verify_control(&sealed)
            .expect("verify same-epoch rekey");
        let store = Store::open_for_mission(root.path().join(STORE_FILE), services.authority)
            .expect("open store for rekey");
        let outcome = store
            .ingest_verified_control(&verified, &sealed)
            .expect("commit same-epoch rekey");
        assert_eq!(outcome.activated().len(), 1);
        assert_eq!(
            store
                .active_scope_epoch(&record_scope())
                .expect("active epoch")
                .map(|(epoch, _)| epoch),
            Some(1)
        );
    }

    fn selected_node(root: &TestRoot) -> SelectedRecordNode {
        if !root.mission_path().exists() {
            persist_mission(root);
        }
        SelectedRecordNode::open_unprotected_reference(root.path(), root.mission_path())
            .expect("open selected Record node")
    }

    fn request(operation: &[u8], payload: &[u8]) -> RecordPublishRequest {
        RecordPublishRequest {
            operation_key: operation.to_vec(),
            topic: record_topic(),
            scope: record_scope(),
            priority: Priority::Priority,
            logical_key: b"asset-7".to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
        }
    }

    fn query(include_superseded_versions: bool) -> RecordQuery {
        RecordQuery {
            topic: record_topic(),
            scope: record_scope(),
            logical_key: b"asset-7".to_vec(),
            include_superseded_versions,
        }
    }

    fn payload_for_exact_sealed_size(
        node: &mut SelectedRecordNode,
        topic: &Topic,
        scope: &Scope,
        logical_key: &[u8],
        priority: Priority,
        target: usize,
    ) -> Vec<u8> {
        let policy = node.current_policy("record size probe").expect("policy");
        let epoch = node
            .active_epoch(scope, "record size probe")
            .expect("active epoch");
        let reservation = node
            .store
            .reserve_record_with_policy(&policy, node.identity(), topic, scope)
            .expect("Record size-probe reservation");
        let probe_header = reservation
            .header(priority, logical_key.to_vec(), 0, false, epoch)
            .expect("Record size-probe header");
        let probe = node
            .verifier
            .seal_record(&probe_header, b"")
            .expect("seal Record size probe");
        let payload_len = target
            .checked_sub(probe.bytes.len())
            .expect("target exceeds Record envelope overhead");
        let payload = vec![0xa5; payload_len];
        let header = reservation
            .header(
                priority,
                logical_key.to_vec(),
                u64::try_from(payload.len()).expect("payload length"),
                false,
                epoch,
            )
            .expect("Record boundary header");
        let sealed = node
            .verifier
            .seal_record(&header, &payload)
            .expect("seal Record boundary payload");
        assert_eq!(sealed.bytes.len(), target);
        payload
    }

    fn stamp(publisher: u8, counter: u64, observed: &[Dot]) -> CausalStamp {
        let mut context = VersionVector::default();
        for dot in observed {
            context.observe(*dot);
        }
        CausalStamp {
            dot: Dot {
                publisher: [publisher; 32],
                counter,
            },
            context,
        }
    }

    struct DirectRecordServices {
        late: ReferenceEnvelopeSealer,
        reader: ReferenceEnvelopeSealer,
        authority: NodeId,
        control_authority: ReferenceEnvelopeSealer,
        registry: Vec<u8>,
        selected_identity: NodeId,
        pre_conflict_reservation: Option<RecordReservation>,
    }

    struct PendingDirectRecord {
        reservation: RecordReservation,
        verified: ContentVerifiedRecordEnvelope,
        sealed: Vec<u8>,
    }

    fn open_direct_record(
        reader: &mut ReferenceEnvelopeSealer,
        sealed: &[u8],
    ) -> ContentVerifiedRecordEnvelope {
        let route = reader.verify_record(sealed).expect("verify Record route");
        match reader
            .verify_record_content(route, sealed)
            .expect("verify Record content")
        {
            RecordContentVerification::ContentVerified { record, payload: _ } => record,
            RecordContentVerification::RouteOnly(_) => panic!("reader has a content grant"),
        }
    }

    fn persist_concurrent_records(root: &TestRoot, head_count: usize) -> DirectRecordServices {
        assert!(head_count >= 2);
        let access = ProvisioningAccess::member(
            record_scope(),
            vec![1],
            vec![
                record_topic(),
                Topic::new("ops.state").expect("State topic"),
            ],
        )
        .expect("member access");
        let mut provisioner = ReferenceProvisioner::from_seed([0x91; 32]).expect("provisioner");
        let control_authority = provisioner
            .issue_control_authority(60, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("control authority");
        let mut publishers = (1..=head_count)
            .map(|index| {
                provisioner
                    .issue_node(
                        u64::try_from(index).expect("publisher index"),
                        std::slice::from_ref(&access),
                    )
                    .and_then(ReferenceEnvelopeSealer::open)
                    .expect("concurrent publisher")
            })
            .collect::<Vec<_>>();
        let late = provisioner
            .issue_node(50, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("late publisher");
        let mut reader = provisioner
            .issue_node(51, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("fixture reader");
        let selected_bundle = provisioner
            .issue_node(52, std::slice::from_ref(&access))
            .expect("selected node bundle");
        let selected_bytes = selected_bundle
            .to_bytes()
            .expect("encode selected node bundle");
        let selected_mission = UnprotectedReferenceMission::from_bytes(selected_bytes.clone())
            .expect("parse selected mission");
        let selected_identity = ReferenceEnvelopeSealer::open(
            selected_mission
                .fresh_bundle()
                .expect("fresh selected bundle"),
        )
        .expect("inspect selected identity")
        .identity();
        let registry = provisioner.export_rekey_registry().expect("rekey registry");
        drop(
            UnprotectedReferenceMission::persist(root.mission_path(), selected_bytes)
                .expect("persist selected mission"),
        );

        let authority = late.mission_authority_id();
        let store = Store::open_for_mission(root.path().join(STORE_FILE), authority)
            .expect("open direct fixture store");
        let policy = store.control_policy_snapshot().expect("settled policy");
        let reservations = publishers
            .iter()
            .map(|publisher| {
                store
                    .reserve_record_with_policy(
                        &policy,
                        publisher.identity(),
                        &record_topic(),
                        &record_scope(),
                    )
                    .expect("reserve concurrent Record")
            })
            .collect::<Vec<_>>();
        let pre_conflict_reservation = store
            .reserve_record_with_policy(&policy, late.identity(), &record_topic(), &record_scope())
            .expect("reserve additional concurrent Record");
        for (index, (publisher, reservation)) in
            publishers.iter_mut().zip(&reservations).enumerate()
        {
            let payload = format!("sibling-{index}").into_bytes();
            let header = reservation
                .header(
                    Priority::Priority,
                    b"asset-7".to_vec(),
                    u64::try_from(payload.len()).expect("payload length"),
                    false,
                    1,
                )
                .expect("Record header");
            let sealed = publisher
                .seal_record(&header, &payload)
                .expect("seal concurrent Record");
            let verified = open_direct_record(&mut reader, &sealed.bytes);
            store
                .commit_reserved_record_with_policy(&policy, reservation, &verified, &sealed.bytes)
                .expect("commit concurrent Record");
        }
        drop(store);
        DirectRecordServices {
            late,
            reader,
            authority,
            control_authority,
            registry,
            selected_identity,
            pre_conflict_reservation: Some(pre_conflict_reservation),
        }
    }

    fn apply_epoch_two_rekey(root: &TestRoot, services: &mut DirectRecordServices) {
        let recipients = vec![
            ScopeRekeyRecipient::member(
                services.control_authority.identity(),
                vec![record_topic()],
            )
            .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.reader.identity(), vec![record_topic()])
                .expect("reader recipient"),
            ScopeRekeyRecipient::member(services.selected_identity, vec![record_topic()])
                .expect("selected recipient"),
        ];
        let (sealed, _) = services
            .control_authority
            .seal_chained_scope_rekey_control_from_registry(
                &services.registry,
                0,
                record_scope(),
                2,
                recipients,
                1,
                None,
            )
            .expect("seal epoch-two rekey");
        let verified = services
            .reader
            .verify_control(&sealed)
            .expect("verify epoch-two rekey");
        let store = Store::open_for_mission(root.path().join(STORE_FILE), services.authority)
            .expect("open store for rekey");
        let outcome = store
            .ingest_verified_control(&verified, &sealed)
            .expect("commit epoch-two rekey");
        assert_eq!(outcome.activated().len(), 1);
        assert_eq!(
            store
                .active_scope_epoch(&record_scope())
                .expect("active epoch")
                .map(|(epoch, _)| epoch),
            Some(2)
        );
    }

    fn apply_direct_same_epoch_rekey(
        root: &TestRoot,
        services: &mut DirectRecordServices,
    ) -> [u8; 32] {
        let recipients = vec![
            ScopeRekeyRecipient::member(
                services.control_authority.identity(),
                vec![record_topic()],
            )
            .expect("authority recipient"),
            ScopeRekeyRecipient::member(services.reader.identity(), vec![record_topic()])
                .expect("reader recipient"),
            ScopeRekeyRecipient::member(services.selected_identity, vec![record_topic()])
                .expect("selected recipient"),
        ];
        let (rekey, _) = services
            .control_authority
            .seal_chained_scope_rekey_control_from_registry(
                &services.registry,
                0,
                record_scope(),
                1,
                recipients,
                1,
                None,
            )
            .expect("seal same-epoch rekey");
        let verified_rekey = services
            .reader
            .verify_control(&rekey)
            .expect("verify same-epoch rekey");
        let rekey_id = verified_rekey.envelope_id();
        let store = Store::open_for_mission(root.path().join(STORE_FILE), services.authority)
            .expect("open store for same-epoch rekey");
        assert_eq!(
            store
                .ingest_verified_control(&verified_rekey, &rekey)
                .expect("commit same-epoch rekey")
                .activated()
                .len(),
            1
        );
        assert_eq!(
            store
                .active_scope_epoch(&record_scope())
                .expect("active epoch")
                .map(|(epoch, _)| epoch),
            Some(1)
        );
        rekey_id
    }

    fn apply_same_epoch_rekey_and_revoke_one(root: &TestRoot, services: &mut DirectRecordServices) {
        let subject = {
            let store = Store::open_for_mission(root.path().join(STORE_FILE), services.authority)
                .expect("open store for revocation subject");
            let policy = store.control_policy_snapshot().expect("settled policy");
            store
                .retained_record_sender_inventory_with_policy(&policy)
                .expect("retained Record senders")
                .first()
                .expect("remote Record publisher")
                .publisher()
        };
        assert_ne!(subject, services.selected_identity);
        let rekey_id = apply_direct_same_epoch_rekey(root, services);
        let store = Store::open_for_mission(root.path().join(STORE_FILE), services.authority)
            .expect("open store for mixed controls");
        let revocation = services
            .control_authority
            .seal_chained_revocation_control(subject, 1, 2, Some(rekey_id))
            .expect("seal publisher revocation");
        let verified_revocation = services
            .reader
            .verify_control(&revocation)
            .expect("verify publisher revocation");
        assert_eq!(
            store
                .ingest_verified_control(&verified_revocation, &revocation)
                .expect("commit publisher revocation")
                .activated()
                .len(),
            1
        );
        assert!(
            store
                .is_control_principal_revoked(subject)
                .expect("publisher revocation state")
        );
    }

    fn prepare_pre_conflict_successor(
        services: &mut DirectRecordServices,
        payload: &[u8],
    ) -> PendingDirectRecord {
        let reservation = services
            .pre_conflict_reservation
            .take()
            .expect("unused pre-conflict reservation");
        let header = reservation
            .header(
                Priority::Priority,
                b"asset-7".to_vec(),
                u64::try_from(payload.len()).expect("payload length"),
                false,
                1,
            )
            .expect("additional concurrent header");
        let sealed = services
            .late
            .seal_record(&header, payload)
            .expect("seal additional concurrent Record");
        let verified = open_direct_record(&mut services.reader, &sealed.bytes);
        PendingDirectRecord {
            reservation,
            verified,
            sealed: sealed.bytes,
        }
    }

    fn prepare_direct_successor(
        root: &TestRoot,
        services: &mut DirectRecordServices,
        payload: &[u8],
    ) -> PendingDirectRecord {
        let store = Store::open_for_mission(root.path().join(STORE_FILE), services.authority)
            .expect("reopen direct fixture store");
        let policy = store.control_policy_snapshot().expect("settled policy");
        let reservation = store
            .reserve_record_with_policy(
                &policy,
                services.late.identity(),
                &record_topic(),
                &record_scope(),
            )
            .expect("reserve direct successor");
        let header = reservation
            .header(
                Priority::Priority,
                b"asset-7".to_vec(),
                u64::try_from(payload.len()).expect("payload length"),
                false,
                1,
            )
            .expect("successor header");
        let sealed = services
            .late
            .seal_record(&header, payload)
            .expect("seal direct successor");
        let verified = open_direct_record(&mut services.reader, &sealed.bytes);
        PendingDirectRecord {
            reservation,
            verified,
            sealed: sealed.bytes,
        }
    }

    fn commit_direct_successor(
        root: &TestRoot,
        services: &DirectRecordServices,
        pending: PendingDirectRecord,
    ) -> RecordId {
        let store = Store::open_for_mission(root.path().join(STORE_FILE), services.authority)
            .expect("reopen direct fixture store");
        let policy = store.control_policy_snapshot().expect("settled policy");
        store
            .commit_reserved_record_with_policy(
                &policy,
                &pending.reservation,
                &pending.verified,
                &pending.sealed,
            )
            .expect("commit direct successor");
        RecordId::from_store(RecordSemanticId::new(pending.verified.item_id()))
    }

    fn tamper_persisted_record_priority(
        root: &TestRoot,
        transfer_id: &[u8; 32],
        expected_sealed: &[u8],
    ) {
        let database = redb::Database::open(root.path().join(STORE_FILE))
            .expect("open raw Record test database");
        let write = database.begin_write().expect("begin metadata tamper");
        let records = redb::TableDefinition::<&[u8], &[u8]>::new("aster.semantic-records.v1");
        let record_bytes =
            redb::TableDefinition::<&[u8], &[u8]>::new("aster.semantic-record-bytes.v1");
        {
            let mut table = write.open_table(records).expect("Record metadata table");
            let mut encoded = table
                .get(transfer_id.as_slice())
                .expect("read Record metadata")
                .expect("Record metadata row")
                .value()
                .to_vec();
            // version + transfer ID + semantic ID = byte offset 65. Keep the
            // encoding structurally valid while making durable metadata differ
            // from the untouched source-sealed header.
            assert_eq!(encoded[65], Priority::Priority as u8);
            encoded[65] = Priority::Flash as u8;
            table
                .insert(transfer_id.as_slice(), encoded.as_slice())
                .expect("tamper only Record metadata");
        }
        {
            let table = write
                .open_table(record_bytes)
                .expect("Record sealed-bytes table");
            assert_eq!(
                table
                    .get(transfer_id.as_slice())
                    .expect("read sealed Record")
                    .expect("sealed Record row")
                    .value(),
                expected_sealed
            );
        }
        write.commit().expect("commit Record metadata tamper");
    }

    #[test]
    fn record_reducer_handles_both_id_orders_n_way_heads_and_inactive_rows() {
        let left = stamp(0x11, 1, &[]);
        let middle = stamp(0x22, 1, &[]);
        let right = stamp(0x33, 1, &[]);
        let low = RecordId::from_bytes([0x10; 32]);
        let mid = RecordId::from_bytes([0x20; 32]);
        let high = RecordId::from_bytes([0x30; 32]);

        let mut incomplete = VersionVector::default();
        incomplete.observe(left.dot);
        assert!(!context_observes_all(&incomplete, [left.dot, middle.dot]));
        incomplete.observe(middle.dot);
        assert!(context_observes_all(&incomplete, [left.dot, middle.dot]));

        let (current, dispositions, heads) = recompute_record_dispositions(&[
            (low, &left, true),
            (mid, &middle, true),
            (high, &right, true),
        ]);
        assert_eq!(current, Some(2));
        assert_eq!(heads, vec![0, 1, 2]);
        assert_eq!(
            dispositions,
            vec![
                Some(RecordVersionDisposition::Concurrent),
                Some(RecordVersionDisposition::Concurrent),
                Some(RecordVersionDisposition::Current),
            ]
        );

        // Candidate position and tombstone state are intentionally absent from
        // the winner rule: only the complete semantic ID breaks a head tie.
        let (current, dispositions, heads) = recompute_record_dispositions(&[
            (high, &right, true),
            (low, &left, true),
            (mid, &middle, false),
        ]);
        assert_eq!(current, Some(0));
        assert_eq!(heads, vec![0, 1]);
        assert_eq!(
            dispositions,
            vec![
                Some(RecordVersionDisposition::Current),
                Some(RecordVersionDisposition::Concurrent),
                None,
            ]
        );

        let successor = stamp(0x44, 1, &[left.dot, middle.dot, right.dot]);
        let joined = RecordId::from_bytes([0x01; 32]);
        let (current, dispositions, heads) = recompute_record_dispositions(&[
            (low, &left, true),
            (mid, &middle, true),
            (high, &right, true),
            (joined, &successor, true),
        ]);
        assert_eq!(current, Some(3));
        assert_eq!(heads, vec![3]);
        assert_eq!(
            dispositions,
            vec![
                Some(RecordVersionDisposition::Superseded),
                Some(RecordVersionDisposition::Superseded),
                Some(RecordVersionDisposition::Superseded),
                Some(RecordVersionDisposition::Current),
            ]
        );
    }

    #[test]
    fn record_publish_query_retry_conflict_and_restart_are_stable() {
        let root = TestRoot::new("publish-query");
        let first_request = request(b"record/first", b"ready");
        let (first, second) = {
            let mut node = selected_node(&root);
            let first = node.publish(first_request.clone()).expect("first Record");
            assert!(first.inserted);
            assert_eq!(first.publisher_counter, 1);

            let replay = node.publish(first_request.clone()).expect("exact retry");
            assert!(!replay.inserted);
            assert_eq!(replay.id, first.id);
            assert_eq!(replay.acceptance_marker, first.acceptance_marker);

            let second = node
                .publish(request(b"record/second", b"moving"))
                .expect("second Record");
            assert!(second.inserted);
            assert_eq!(second.publisher_counter, 2);
            let projection = node.query(query(true)).expect("Record projection");
            assert_eq!(
                projection.current.as_ref().map(|item| item.id),
                Some(second.id)
            );
            assert!(projection.concurrent.is_empty());
            assert!(projection.conflict.is_none());
            assert_eq!(projection.superseded.len(), 1);
            assert_eq!(projection.superseded[0].id, first.id);

            let mut changed = first_request.clone();
            changed.payload = b"changed".to_vec();
            let error = node.publish(changed).expect_err("operation conflict");
            assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
            assert_eq!(
                error.to_string(),
                "selected application record publish failed: idempotency or causal conflict"
            );
            (first, second)
        };

        let mut reopened = selected_node(&root);
        let replay = reopened
            .publish(first_request)
            .expect("restart-stable exact retry");
        assert!(!replay.inserted);
        assert_eq!(replay.id, first.id);
        let projection = reopened.query(query(false)).expect("reopened projection");
        assert_eq!(projection.current.map(|item| item.id), Some(second.id));
        assert!(projection.superseded.is_empty());
    }

    #[test]
    fn same_epoch_rekey_withholds_old_record_and_replacement_is_restart_stable() {
        let root = TestRoot::new("same-epoch-lineage");
        let mut services = persist_rekeyable_mission(&root);
        let old_request = request(b"record/pre-rekey", b"old route");
        let old = {
            let mut node = selected_node(&root);
            node.publish(old_request.clone())
                .expect("publish pre-rekey Record")
        };

        apply_same_epoch_rekey(&root, &mut services);
        let replacement = {
            let mut reopened = selected_node(&root);
            let hidden = reopened
                .query(query(true))
                .expect("cache-proven old Record is safely withheld");
            assert!(hidden.current.is_none());
            assert!(hidden.concurrent.is_empty());
            assert!(hidden.superseded.is_empty());
            assert!(hidden.conflict.is_none());

            let replay = reopened
                .publish(old_request)
                .expect("exact Record retry survives same-epoch rekey");
            assert!(!replay.inserted);
            assert_eq!(replay.id, old.id);
            assert_eq!(replay.publisher_counter, old.publisher_counter);
            assert_eq!(replay.acceptance_marker, old.acceptance_marker);

            let replacement = reopened
                .publish(request(b"record/post-rekey", b"current route"))
                .expect("publish post-rekey Record");
            assert_ne!(replacement.id, old.id);
            let projection = reopened.query(query(true)).expect("current projection");
            assert_eq!(
                projection.current.as_ref().map(|item| item.id),
                Some(replacement.id)
            );
            assert_eq!(
                projection
                    .current
                    .as_ref()
                    .map(|item| item.payload.as_slice()),
                Some(b"current route".as_slice())
            );
            assert!(projection.concurrent.is_empty());
            assert!(projection.superseded.is_empty());
            assert!(projection.conflict.is_none());
            replacement
        };

        let mut restarted = selected_node(&root);
        let projection = restarted
            .query(query(true))
            .expect("restart-stable lineage filtering");
        assert_eq!(
            projection.current.as_ref().map(|item| item.id),
            Some(replacement.id)
        );
        assert!(projection.concurrent.is_empty());
        assert!(projection.superseded.is_empty());
        assert!(projection.conflict.is_none());
    }

    #[test]
    fn same_epoch_hidden_record_heads_expose_opaque_guard_and_resolve_across_restart() {
        let root = TestRoot::new("same-epoch-hidden-conflict");
        let mut services = persist_concurrent_records(&root, 2);
        let _ = apply_direct_same_epoch_rekey(&root, &mut services);

        let resolved = {
            let mut node = selected_node(&root);
            let projection = node
                .query(query(true))
                .expect("source-proven hidden conflict projection");
            assert!(projection.current.is_none());
            assert!(projection.concurrent.is_empty());
            assert!(projection.superseded.is_empty());
            let conflict = projection
                .conflict
                .expect("numeric heads retain an opaque resolution guard");
            assert_eq!(conflict.siblings.len(), 2);
            assert!(conflict.siblings.windows(2).all(|pair| pair[0] < pair[1]));
            assert_eq!(
                conflict.resolution_guard.siblings(),
                conflict.siblings.as_slice()
            );

            let resolved = node
                .resolve(RecordResolveRequest {
                    operation_key: b"record/resolve/hidden-lineage".to_vec(),
                    resolution_guard: conflict.resolution_guard,
                    priority: Priority::Immediate,
                    payload: b"current-lineage resolution".to_vec(),
                    tombstone: false,
                })
                .expect("resolve source-proven hidden heads");
            assert!(resolved.inserted);
            let projection = node.query(query(true)).expect("resolved projection");
            assert_eq!(
                projection.current.as_ref().map(|item| item.id),
                Some(resolved.id)
            );
            assert_eq!(
                projection
                    .current
                    .as_ref()
                    .map(|item| item.payload.as_slice()),
                Some(b"current-lineage resolution".as_slice())
            );
            assert!(projection.concurrent.is_empty());
            assert!(projection.superseded.is_empty());
            assert!(projection.conflict.is_none());
            resolved
        };

        let mut restarted = selected_node(&root);
        let projection = restarted
            .query(query(true))
            .expect("reopened resolved hidden-head projection");
        assert_eq!(
            projection.current.as_ref().map(|item| item.id),
            Some(resolved.id)
        );
        assert_eq!(
            projection
                .current
                .as_ref()
                .map(|item| item.payload.as_slice()),
            Some(b"current-lineage resolution".as_slice())
        );
        assert!(projection.concurrent.is_empty());
        assert!(projection.superseded.is_empty());
        assert!(projection.conflict.is_none());
    }

    #[test]
    fn exact_resolution_retry_survives_same_epoch_route_replacement() {
        let root = TestRoot::new("resolution-same-epoch-retry");
        let mut services = persist_concurrent_records(&root, 2);
        let (request, resolved) = {
            let mut node = selected_node(&root);
            let conflict = node
                .query(query(true))
                .expect("pre-rekey conflict")
                .conflict
                .expect("explicit conflict");
            let request = RecordResolveRequest {
                operation_key: b"record/resolve/same-epoch-retry".to_vec(),
                resolution_guard: conflict.resolution_guard,
                priority: Priority::Immediate,
                payload: b"pre-rekey resolution".to_vec(),
                tombstone: false,
            };
            let resolved = node.resolve(request.clone()).expect("pre-rekey resolution");
            assert!(resolved.inserted);
            (request, resolved)
        };

        let _ = apply_direct_same_epoch_rekey(&root, &mut services);
        let mut reopened = selected_node(&root);
        let hidden = reopened
            .query(query(true))
            .expect("historical resolution remains withheld");
        assert!(hidden.current.is_none());
        assert!(hidden.concurrent.is_empty());
        assert!(hidden.superseded.is_empty());
        assert!(hidden.conflict.is_none());

        let replay = reopened
            .resolve(request)
            .expect("exact resolution retry survives same-epoch rekey");
        assert!(!replay.inserted);
        assert_eq!(replay.id, resolved.id);
        assert_eq!(replay.publisher_counter, resolved.publisher_counter);
        assert_eq!(replay.acceptance_marker, resolved.acceptance_marker);
    }

    #[test]
    fn same_epoch_rekey_plus_revocation_preserves_record_plan_and_withholds_history() {
        let root = TestRoot::new("same-epoch-revocation");
        let mut services = persist_concurrent_records(&root, 2);
        apply_same_epoch_rekey_and_revoke_one(&root, &mut services);

        for pass in 0..2 {
            let mut node = selected_node(&root);
            let projection = node
                .query(query(true))
                .expect("mixed inactive and stale-lineage Record plan remains valid");
            assert!(projection.current.is_none(), "pass {pass}");
            assert!(projection.concurrent.is_empty(), "pass {pass}");
            assert!(projection.superseded.is_empty(), "pass {pass}");
            assert!(projection.conflict.is_none(), "pass {pass}");
        }
    }

    #[test]
    fn record_publish_sealed_wire_boundary_is_inclusive_and_restart_atomic() {
        let root = TestRoot::new("publish-wire-boundary");
        let exact;
        let exact_payload;
        {
            let mut node = selected_node(&root);
            let payload_over_wire = vec![0x42; MAX_OBJECT_BYTES + 1];
            let error = node
                .publish(request(
                    b"record/payload-over-wire-limit",
                    &payload_over_wire,
                ))
                .expect_err("payload larger than the wire object bound");
            assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);

            exact_payload = payload_for_exact_sealed_size(
                &mut node,
                &record_topic(),
                &record_scope(),
                b"asset-7",
                Priority::Priority,
                MAX_OBJECT_BYTES,
            );
            exact = node
                .publish(request(b"record/exact-wire-limit", &exact_payload))
                .expect("exact-bound Record");
            assert!(exact.inserted);
            assert_eq!(exact.publisher_counter, 1);

            let oversized = payload_for_exact_sealed_size(
                &mut node,
                &record_topic(),
                &record_scope(),
                b"asset-7",
                Priority::Priority,
                MAX_OBJECT_BYTES + 1,
            );
            let error = node
                .publish(request(b"record/oversized-wire-limit", &oversized))
                .expect_err("oversized sealed Record");
            assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
            assert_eq!(error.operation(), "record publish");
            assert_eq!(
                error.to_string(),
                "selected application record publish failed: selected data resource limit reached"
            );

            let projection = node.query(query(true)).expect("unchanged projection");
            assert_eq!(
                projection.current.as_ref().map(|item| item.id),
                Some(exact.id)
            );
            assert_eq!(
                projection
                    .current
                    .as_ref()
                    .map(|item| item.payload.as_slice()),
                Some(exact_payload.as_slice())
            );
            assert!(projection.concurrent.is_empty());
            assert!(projection.superseded.is_empty());
            assert!(projection.conflict.is_none());
        }

        let mut reopened = selected_node(&root);
        let projection = reopened.query(query(true)).expect("reopened projection");
        assert_eq!(
            projection.current.as_ref().map(|item| item.id),
            Some(exact.id)
        );
        assert_eq!(
            projection
                .current
                .as_ref()
                .map(|item| item.payload.as_slice()),
            Some(exact_payload.as_slice())
        );
        assert!(projection.concurrent.is_empty());
        assert!(projection.superseded.is_empty());
        assert!(projection.conflict.is_none());

        let replacement = reopened
            .publish(request(
                b"record/oversized-wire-limit",
                b"small replacement",
            ))
            .expect("rejected operation key remains unbound");
        assert!(replacement.inserted);
        assert_eq!(replacement.publisher_counter, 2);
        let preflight_replacement = reopened
            .publish(request(
                b"record/payload-over-wire-limit",
                b"small preflight replacement",
            ))
            .expect("preflight-rejected operation key remains unbound");
        assert!(preflight_replacement.inserted);
        assert_eq!(preflight_replacement.publisher_counter, 3);
    }

    #[test]
    fn record_resolution_accepts_exact_sealed_wire_boundary_across_restart() {
        let root = TestRoot::new("resolve-exact-wire-boundary");
        let _services = persist_concurrent_records(&root, 2);
        let resolved;
        let exact_payload;
        {
            let mut node = selected_node(&root);
            let conflict = node
                .query(query(true))
                .expect("conflict projection")
                .conflict
                .expect("explicit conflict");
            let guard = conflict.resolution_guard;
            exact_payload = payload_for_exact_sealed_size(
                &mut node,
                guard.topic(),
                guard.scope(),
                guard.logical_key(),
                Priority::Immediate,
                MAX_OBJECT_BYTES,
            );
            resolved = node
                .resolve(RecordResolveRequest {
                    operation_key: b"record/resolve/exact-wire-limit".to_vec(),
                    resolution_guard: guard,
                    priority: Priority::Immediate,
                    payload: exact_payload.clone(),
                    tombstone: false,
                })
                .expect("exact-bound Record resolution");
            assert!(resolved.inserted);
            let projection = node.query(query(true)).expect("resolved projection");
            assert_eq!(
                projection.current.as_ref().map(|item| item.id),
                Some(resolved.id)
            );
            assert_eq!(
                projection
                    .current
                    .as_ref()
                    .map(|item| item.payload.as_slice()),
                Some(exact_payload.as_slice())
            );
            assert!(projection.concurrent.is_empty());
            assert!(projection.conflict.is_none());
            assert_eq!(projection.superseded.len(), 2);
        }

        let mut reopened = selected_node(&root);
        let projection = reopened.query(query(true)).expect("reopened resolution");
        assert_eq!(
            projection.current.as_ref().map(|item| item.id),
            Some(resolved.id)
        );
        assert_eq!(
            projection
                .current
                .as_ref()
                .map(|item| item.payload.as_slice()),
            Some(exact_payload.as_slice())
        );
        assert!(projection.concurrent.is_empty());
        assert!(projection.conflict.is_none());
        assert_eq!(projection.superseded.len(), 2);
    }

    #[test]
    fn oversized_record_resolution_is_atomic_and_operation_key_survives_restart() {
        let root = TestRoot::new("resolve-oversized-wire-boundary");
        let _services = persist_concurrent_records(&root, 2);
        let siblings;
        {
            let mut node = selected_node(&root);
            let conflict = node
                .query(query(true))
                .expect("conflict projection")
                .conflict
                .expect("explicit conflict");
            let guard = conflict.resolution_guard;
            siblings = guard.siblings().to_vec();
            let preflight_error = node
                .resolve(RecordResolveRequest {
                    operation_key: b"record/resolve/oversized-wire-limit".to_vec(),
                    resolution_guard: guard.clone(),
                    priority: Priority::Immediate,
                    payload: vec![0x43; MAX_OBJECT_BYTES + 1],
                    tombstone: false,
                })
                .expect_err("resolution payload larger than the wire object bound");
            assert_eq!(preflight_error.kind(), ApplicationErrorKind::ResourceLimit);

            let oversized = payload_for_exact_sealed_size(
                &mut node,
                guard.topic(),
                guard.scope(),
                guard.logical_key(),
                Priority::Immediate,
                MAX_OBJECT_BYTES + 1,
            );
            let error = node
                .resolve(RecordResolveRequest {
                    operation_key: b"record/resolve/oversized-wire-limit".to_vec(),
                    resolution_guard: guard,
                    priority: Priority::Immediate,
                    payload: oversized,
                    tombstone: false,
                })
                .expect_err("oversized sealed Record resolution");
            assert_eq!(error.kind(), ApplicationErrorKind::ResourceLimit);
            assert_eq!(error.operation(), "record resolve");
            assert_eq!(
                error.to_string(),
                "selected application record resolve failed: selected data resource limit reached"
            );
            let unchanged = node.query(query(true)).expect("unchanged conflict");
            assert_eq!(
                unchanged.conflict.expect("conflict remains").siblings,
                siblings
            );
            assert!(unchanged.superseded.is_empty());
        }

        let mut reopened = selected_node(&root);
        let conflict = reopened
            .query(query(true))
            .expect("reopened conflict")
            .conflict
            .expect("conflict remains after restart");
        assert_eq!(conflict.siblings, siblings);
        let resolved = reopened
            .resolve(RecordResolveRequest {
                operation_key: b"record/resolve/oversized-wire-limit".to_vec(),
                resolution_guard: conflict.resolution_guard,
                priority: Priority::Immediate,
                payload: b"small replacement".to_vec(),
                tombstone: false,
            })
            .expect("rejected resolution operation key remains unbound");
        assert!(resolved.inserted);
        let projection = reopened.query(query(true)).expect("resolved projection");
        assert_eq!(
            projection.current.as_ref().map(|item| item.id),
            Some(resolved.id)
        );
        assert!(projection.concurrent.is_empty());
        assert!(projection.conflict.is_none());
        assert_eq!(projection.superseded.len(), 2);
    }

    #[test]
    fn n_way_conflict_requires_explicit_guarded_resolution_and_retry_is_stable() {
        let root = TestRoot::new("n-way-resolution");
        let mut services = persist_concurrent_records(&root, 3);
        // Reserve before the application resolution, then commit afterward.
        // Both successors observe the original siblings but not each other,
        // producing a later conflict with a different exact guard.
        let pending_later = prepare_direct_successor(&root, &mut services, b"later-concurrent");
        let resolve_request;
        let resolved = {
            let mut node = selected_node(&root);
            let projection = node.query(query(true)).expect("conflict projection");
            assert_eq!(projection.concurrent.len(), 2);
            assert!(projection.superseded.is_empty());
            let conflict = projection.conflict.expect("explicit conflict");
            assert_eq!(conflict.siblings.len(), 3);
            assert!(conflict.siblings.windows(2).all(|pair| pair[0] < pair[1]));
            assert_eq!(
                conflict.resolution_guard.siblings(),
                conflict.siblings.as_slice()
            );

            let bypass = node
                .publish(request(b"record/ordinary-cannot-resolve", b"unguarded"))
                .expect_err("ordinary publish cannot collapse a conflict");
            assert_eq!(bypass.kind(), ApplicationErrorKind::Conflict);
            let unchanged = node.query(query(true)).expect("unchanged conflict");
            let unchanged_conflict = unchanged.conflict.expect("conflict remains explicit");
            assert_eq!(unchanged_conflict.siblings, conflict.siblings);
            assert_eq!(unchanged.concurrent.len(), 2);
            assert!(
                unchanged
                    .current
                    .iter()
                    .chain(&unchanged.concurrent)
                    .all(|item| item.payload != b"unguarded")
            );
            resolve_request = RecordResolveRequest {
                operation_key: b"record/resolve/n-way".to_vec(),
                resolution_guard: unchanged_conflict.resolution_guard,
                priority: Priority::Immediate,
                payload: b"joined".to_vec(),
                tombstone: false,
            };
            let resolved = node
                .resolve(resolve_request.clone())
                .expect("explicit resolution");
            assert!(resolved.inserted);
            let joined = node.query(query(true)).expect("resolved projection");
            assert_eq!(
                joined.current.as_ref().map(|item| item.id),
                Some(resolved.id)
            );
            assert_eq!(
                joined.current.as_ref().map(|item| item.payload.as_slice()),
                Some(b"joined".as_slice())
            );
            assert!(joined.concurrent.is_empty());
            assert!(joined.conflict.is_none());
            assert_eq!(joined.superseded.len(), 3);
            resolved
        };

        let later = commit_direct_successor(&root, &services, pending_later);

        let mut reopened = selected_node(&root);
        let replay = reopened
            .resolve(resolve_request.clone())
            .expect("restart-stable resolution retry");
        assert!(!replay.inserted);
        assert_eq!(replay.id, resolved.id);
        assert_eq!(replay.acceptance_marker, resolved.acceptance_marker);

        let changed = reopened.query(query(true)).expect("later conflict");
        assert_eq!(changed.concurrent.len(), 1);
        let changed_conflict = changed.conflict.expect("changed exact sibling guard");
        assert_eq!(changed_conflict.siblings.len(), 2);
        assert!(changed_conflict.siblings.contains(&resolved.id));
        assert!(changed_conflict.siblings.contains(&later));
        assert_ne!(
            changed_conflict.resolution_guard,
            resolve_request.resolution_guard
        );
        let changed_siblings = changed_conflict.siblings.clone();
        let changed_guard_same_operation = RecordResolveRequest {
            operation_key: resolve_request.operation_key,
            resolution_guard: changed_conflict.resolution_guard,
            priority: resolve_request.priority,
            payload: resolve_request.payload,
            tombstone: resolve_request.tombstone,
        };
        let error = reopened
            .resolve(changed_guard_same_operation)
            .expect_err("same operation cannot resolve a different guard");
        assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
        let still_conflicted = reopened.query(query(true)).expect("conflict unchanged");
        assert_eq!(
            still_conflicted
                .conflict
                .expect("two heads remain")
                .siblings,
            changed_siblings
        );
    }

    #[test]
    fn stale_resolution_plan_fails_without_inserting_application_bytes() {
        let root = TestRoot::new("stale-resolution");
        let mut services = persist_concurrent_records(&root, 2);
        let stale_request = {
            let mut node = selected_node(&root);
            let projection = node.query(query(true)).expect("conflict projection");
            let conflict = projection.conflict.expect("explicit conflict");
            RecordResolveRequest {
                operation_key: b"record/resolve/stale".to_vec(),
                resolution_guard: conflict.resolution_guard,
                priority: Priority::Priority,
                payload: b"must-not-commit".to_vec(),
                tombstone: false,
            }
        };
        let pending = prepare_pre_conflict_successor(&mut services, b"additional-head");
        let additional = commit_direct_successor(&root, &services, pending);

        let mut reopened = selected_node(&root);
        let error = reopened
            .resolve(stale_request)
            .expect_err("stale resolution must fail");
        assert_eq!(error.kind(), ApplicationErrorKind::Conflict);
        assert_eq!(
            error.to_string(),
            "selected application record resolve failed: idempotency or causal conflict"
        );
        let projection = reopened.query(query(true)).expect("advanced projection");
        let conflict = projection.conflict.expect("three-head conflict remains");
        assert_eq!(conflict.siblings.len(), 3);
        assert!(conflict.siblings.contains(&additional));
        assert_eq!(projection.concurrent.len(), 2);
        assert!(projection.superseded.is_empty());
        assert!(
            projection
                .current
                .iter()
                .chain(&projection.concurrent)
                .all(|item| item.payload != b"must-not-commit")
        );
    }

    #[test]
    fn exact_resolution_retry_survives_authorized_rekey_but_new_old_guard_operation_fails() {
        let root = TestRoot::new("resolution-rekey-retry");
        let mut services = persist_concurrent_records(&root, 2);
        let request = {
            let mut node = selected_node(&root);
            let conflict = node
                .query(query(true))
                .expect("epoch-one conflict")
                .conflict
                .expect("explicit conflict");
            RecordResolveRequest {
                operation_key: b"record/resolve/rekey".to_vec(),
                resolution_guard: conflict.resolution_guard,
                priority: Priority::Priority,
                payload: b"epoch-one-resolution".to_vec(),
                tombstone: false,
            }
        };
        let first = {
            let mut node = selected_node(&root);
            node.resolve(request.clone()).expect("epoch-one resolution")
        };
        assert!(first.inserted);

        apply_epoch_two_rekey(&root, &mut services);
        let mut reopened = selected_node(&root);
        let hidden = reopened
            .query(query(true))
            .expect("post-rekey query freshly verifies retained epoch-one rows");
        assert!(hidden.current.is_none());
        assert!(hidden.concurrent.is_empty());
        assert!(hidden.superseded.is_empty());
        assert!(hidden.conflict.is_none());
        let replay = reopened
            .resolve(request.clone())
            .expect("authorized exact retry after rekey");
        assert!(!replay.inserted);
        assert_eq!(replay.id, first.id);
        assert_eq!(replay.acceptance_marker, first.acceptance_marker);

        let mut stale_new_operation = request;
        stale_new_operation.operation_key = b"record/resolve/rekey/new".to_vec();
        let error = reopened
            .resolve(stale_new_operation)
            .expect_err("new operation cannot use an old-policy guard");
        assert!(matches!(
            error.kind(),
            ApplicationErrorKind::Conflict | ApplicationErrorKind::PolicyUnsettled
        ));
    }

    #[test]
    fn authenticated_record_tombstone_stays_visible_and_invalid_requests_are_sanitized() {
        let root = TestRoot::new("tombstone");
        let mut node = selected_node(&root);
        let live = node
            .publish(request(b"record/live", b"ready"))
            .expect("live Record");
        let mut deletion = request(b"record/delete", b"");
        deletion.tombstone = true;
        let tombstone = node.publish(deletion).expect("Record tombstone");
        let projection = node.query(query(true)).expect("tombstone projection");
        let current = projection.current.expect("visible current tombstone");
        assert_eq!(current.id, tombstone.id);
        assert!(current.tombstone);
        assert!(current.payload.is_empty());
        assert_eq!(projection.superseded.len(), 1);
        assert_eq!(projection.superseded[0].id, live.id);

        let mut invalid = request(b"record/invalid-delete", b"not-empty");
        invalid.tombstone = true;
        let error = node.publish(invalid).expect_err("nonempty tombstone");
        assert_eq!(error.kind(), ApplicationErrorKind::InvalidRequest);
        assert_eq!(
            error.to_string(),
            "selected application record publish failed: invalid application request"
        );
        assert!(!error.to_string().contains("tombstone"));
        assert!(!error.to_string().contains("payload"));
    }

    #[test]
    fn persisted_metadata_tamper_is_integrity_not_withholding_or_exposure() {
        let root = TestRoot::new("metadata-tamper");
        let (transfer_id, sealed) = {
            let mut node = selected_node(&root);
            let published = node
                .publish(request(b"record/tamper", b"authenticated"))
                .expect("publish Record before tamper");
            let stored = node
                .store
                .record_by_semantic_id(RecordSemanticId::new(*published.id.as_bytes()))
                .expect("read stored Record")
                .expect("stored Record exists");
            (*stored.transfer_id.as_bytes(), stored.sealed)
        };
        tamper_persisted_record_priority(&root, &transfer_id, &sealed);

        let error = match SelectedRecordNode::open_unprotected_reference(
            root.path(),
            root.mission_path(),
        ) {
            Ok(_) => panic!("tampered metadata cannot cross startup source verification"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ApplicationErrorKind::Integrity);
        assert_eq!(error.operation(), "record open");
        assert_eq!(
            error.to_string(),
            "selected application record open failed: selected data integrity check failed"
        );
        for private_detail in ["priority", "semantic-records", "sealed", "transfer"] {
            assert!(!error.to_string().contains(private_detail));
        }
    }

    #[test]
    fn record_and_state_facades_share_exact_writer_exclusion() {
        let root = TestRoot::new("writer-exclusion");
        persist_mission(&root);
        let records = selected_node(&root);
        let error =
            match SelectedStateNode::open_unprotected_reference(root.path(), root.mission_path()) {
                Ok(_) => panic!("second writer must fail"),
                Err(error) => error,
            };
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        drop(records);

        let mut states =
            SelectedStateNode::open_unprotected_reference(root.path(), root.mission_path())
                .expect("State owns writer after Record drop");
        let projection = states
            .query(StateQuery {
                topic: Topic::new("ops.state").expect("topic"),
                scope: record_scope(),
                logical_key: b"asset-7".to_vec(),
                include_recoverable_versions: true,
            })
            .expect("empty State query");
        assert!(projection.current.is_none());
    }
}
