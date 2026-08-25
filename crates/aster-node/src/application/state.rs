//! High-level stopped-state surface for source-authenticated State projections.
//!
//! The application handle is intentionally stopped/exclusive. It shares the
//! mission-bound store, control policy, source-envelope provider, and causal
//! ledger with the selected Event surface. A separately running node can
//! reconcile its durable State objects through the class-specific State lane
//! when the receiver declares an exact source interest.

use std::{fmt, fs, path::Path, sync::Arc};

use aster_mesh::{
    CausalStamp, NodeId, Priority, ReferenceEnvelopeSealer, Scope, StateContentVerification, Topic,
};
use aster_redb_store::{
    ControlPolicySnapshot, ControlTransferId, StateOperationKey, StateOperationRequest,
    StateProjectionPlan, StatePublicationIntent, StateSemanticId,
    StateVersionDisposition as StoreStateDisposition, Store, StoredState,
};

use super::{ApplicationError, ApplicationErrorKind, application_error};
use crate::{
    mission::UnprotectedReferenceMission,
    runtime::{
        STORE_FILE, ensure_principal_active, ensure_state_accepts_normal_operation,
        open_replayed_verifier, refresh_application_policy,
    },
};

/// Source-authenticated semantic identity of one State version.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct StateId([u8; 32]);

impl StateId {
    /// Constructs an identity from its complete semantic bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete semantic identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_store(id: StateSemanticId) -> Self {
        Self(*id.as_bytes())
    }
}

impl fmt::Display for StateId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// One durable, operation-key-idempotent State publication request.
///
/// A tombstone is an authenticated State version and therefore requires an
/// empty payload. Finite TTL is absent until the selected forwarding path
/// carries authenticated cumulative age.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatePublishRequest {
    pub operation_key: Vec<u8>,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
}

/// Causal disposition computed for one retained State version.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateVersionDisposition {
    /// Deterministic application-visible causal maximum.
    Current,
    /// Another causal maximum retained for recovery.
    Concurrent,
    /// A retained version observed by a later version.
    Superseded,
}

/// Successful durable State publication without sealed-byte/provider details.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StatePublishResult {
    pub id: StateId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub priority: Priority,
    pub acceptance_marker: u64,
    pub inserted: bool,
}

/// Exact logical-key query for one selected State projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateQuery {
    pub topic: Topic,
    pub scope: Scope,
    pub logical_key: Vec<u8>,
    /// Include all currently active retained concurrent and superseded versions.
    ///
    /// Versions made inactive by revocation or a later scope epoch remain
    /// durable and are freshly verified, but are not exposed as application
    /// results.
    pub include_recoverable_versions: bool,
}

/// One freshly source/content-verified retained State version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateItem {
    pub id: StateId,
    pub publisher: NodeId,
    pub publisher_counter: u64,
    pub topic: Topic,
    pub scope: Scope,
    pub priority: Priority,
    pub logical_key: Vec<u8>,
    pub payload: Vec<u8>,
    pub tombstone: bool,
    pub acceptance_marker: u64,
    pub disposition: StateVersionDisposition,
}

/// Deterministic latest-value State projection plus optional recovery history.
///
/// A current tombstone remains visible as `Some(StateItem { tombstone: true,
/// .. })`; deletion is never collapsed into an unauthenticated absence.
/// Revoked and stale-epoch versions are excluded only after fresh source and
/// content verification agrees with the current policy-bound plan.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StateProjection {
    pub current: Option<StateItem>,
    pub recoverable: Vec<StateItem>,
}

struct VerifiedStateCandidate {
    item: StateItem,
    stamp: CausalStamp,
    store_disposition: Option<StoreStateDisposition>,
    active: bool,
}

/// Exclusive stopped-state handle over the selected State projection.
///
/// The handle takes the same process-exclusive mission-bound redb writer as
/// the Event facade and live runtime. It therefore cannot observe or mutate
/// around their policy snapshots. Stop this handle before running the network
/// actor; the actor can then reconcile these durable State objects without
/// exposing a live State application handle.
pub struct SelectedStateNode {
    mission: UnprotectedReferenceMission,
    store: Arc<Store>,
    verifier: ReferenceEnvelopeSealer,
    verifier_head: Option<(u64, ControlTransferId)>,
}

impl SelectedStateNode {
    /// Opens the explicitly unprotected reference provisioning path.
    ///
    /// Terminal state is rejected before mission bytes are loaded. The exact
    /// store is mission-bound and process-locked, then every committed control
    /// is replayed before State operations become available.
    pub fn open_unprotected_reference(
        state: impl AsRef<Path>,
        mission_bundle: impl AsRef<Path>,
    ) -> Result<Self, ApplicationError> {
        let state = state.as_ref();
        ensure_state_accepts_normal_operation(state)
            .map_err(|error| application_error("state open", error))?;
        let mission = UnprotectedReferenceMission::load(mission_bundle)
            .map_err(|error| application_error("state open", error.into()))?;
        fs::create_dir_all(state).map_err(|error| application_error("state open", error.into()))?;
        let store = Store::open_for_mission(state.join(STORE_FILE), mission.mission_authority_id())
            .map_err(|error| application_error("state open", error.into()))?;
        store
            .require_process_exclusive_lock()
            .map_err(|error| application_error("state open", error.into()))?;
        let verifier = open_replayed_verifier(&store, &mission)
            .map_err(|error| application_error("state open", error))?;
        ensure_principal_active(&store, verifier.identity())
            .map_err(|error| application_error("state open", error))?;
        let verifier_head = store
            .control_head()
            .map_err(|error| application_error("state open", error.into()))?;
        let mut selected = Self {
            mission,
            store: Arc::new(store),
            verifier,
            verifier_head,
        };
        selected.current_policy("state open")?;
        Ok(selected)
    }

    /// Authenticated local State publisher identity.
    pub fn identity(&self) -> NodeId {
        self.verifier.identity()
    }

    /// Stable mission authority bound to provisioning and the durable store.
    pub const fn mission_authority(&self) -> NodeId {
        self.mission.mission_authority_id()
    }

    /// Durably publishes one State version exactly once per operation key.
    pub fn publish(
        &mut self,
        request: StatePublishRequest,
    ) -> Result<StatePublishResult, ApplicationError> {
        let StatePublishRequest {
            operation_key,
            topic,
            scope,
            priority,
            logical_key,
            payload,
            tombstone,
        } = request;
        let operation = StateOperationKey::new(operation_key)
            .map_err(|error| application_error("state publish", error.into()))?;
        let intent = StatePublicationIntent::new(
            self.identity(),
            topic.clone(),
            scope.clone(),
            priority,
            logical_key.clone(),
            &payload,
            tombstone,
        )
        .map_err(|error| application_error("state publish", error.into()))?;
        let operation_request = StateOperationRequest::new(&operation, &intent, &payload)
            .map_err(|error| application_error("state publish", error.into()))?;
        let policy = self.current_policy("state publish")?;
        let epoch = self
            .store
            .active_scope_epoch(&scope)
            .map_err(|error| application_error("state publish", error.into()))?
            .map_or(1, |(epoch, _)| epoch);
        if !self.verifier.can_route_state(&scope, epoch)
            || !self.verifier.can_open_state_content(&scope, &topic, epoch)
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                "state publish",
            ));
        }
        let reservation = self
            .store
            .reserve_state_with_policy(&policy, self.identity(), &topic, &scope)
            .map_err(|error| application_error("state publish", error.into()))?;
        let content_len = u64::try_from(payload.len()).map_err(|_| {
            ApplicationError::new(ApplicationErrorKind::ResourceLimit, "state publish")
        })?;
        let header = reservation
            .header(priority, logical_key, content_len, tombstone, epoch)
            .map_err(|error| application_error("state publish", error.into()))?;
        let sealed = self
            .verifier
            .seal_state(&header, &payload)
            .map_err(|error| application_error("state publish", error.into()))?;
        let route = self
            .verifier
            .verify_state(&sealed.bytes)
            .map_err(|error| application_error("state publish", error.into()))?;
        let verified = match self
            .verifier
            .verify_state_content(route, &sealed.bytes)
            .map_err(|error| application_error("state publish", error.into()))?
        {
            StateContentVerification::ContentVerified {
                state,
                payload: opened,
            } => {
                if opened != payload {
                    return Err(ApplicationError::new(
                        ApplicationErrorKind::Integrity,
                        "state publish",
                    ));
                }
                state
            }
            StateContentVerification::RouteOnly(_) => {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::RequestRejected,
                    "state publish",
                ));
            }
        };
        verified
            .ensure_live_for_local_publication()
            .map_err(|error| application_error("state publish", error.into()))?;
        let outcome = self
            .store
            .commit_reserved_state_once_with_policy(
                &policy,
                &operation_request,
                &reservation,
                &verified,
                &sealed.bytes,
            )
            .map_err(|error| application_error("state publish", error.into()))?;
        let state = outcome.state();
        self.verify_publication_result(&intent, &payload, state)?;
        Ok(StatePublishResult {
            id: StateId::from_store(state.semantic_id),
            publisher: state.header.stamp.dot.publisher,
            publisher_counter: state.header.stamp.dot.counter,
            priority: state.header.priority,
            acceptance_marker: state.acceptance_marker,
            inserted: outcome.inserted(),
        })
    }

    fn verify_publication_result(
        &mut self,
        intent: &StatePublicationIntent,
        payload: &[u8],
        stored: &StoredState,
    ) -> Result<(), ApplicationError> {
        let route = self
            .verifier
            .verify_state(&stored.sealed)
            .map_err(|error| application_error("state publish", error.into()))?;
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
                "state publish",
            ));
        }
        if self
            .store
            .is_control_principal_revoked(route.publisher())
            .map_err(|error| application_error("state publish", error.into()))?
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::UnauthorizedOrRevoked,
                "state publish",
            ));
        }
        let current_epoch = self
            .store
            .active_scope_epoch(route.scope())
            .map_err(|error| application_error("state publish", error.into()))?
            .map_or(1, |(epoch, _)| epoch);
        if route.key_epoch() > current_epoch {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state publish",
            ));
        }
        if !self
            .verifier
            .can_route_state(route.scope(), route.key_epoch())
            || !self.verifier.can_open_state_content(
                route.scope(),
                route.topic(),
                route.key_epoch(),
            )
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state publish",
            ));
        }
        match self
            .verifier
            .verify_state_content(route, &stored.sealed)
            .map_err(|error| application_error("state publish", error.into()))?
        {
            StateContentVerification::ContentVerified {
                state,
                payload: opened,
            } if opened == payload => state
                .verify_exact_payload(payload)
                .map_err(|error| application_error("state publish", error.into())),
            StateContentVerification::ContentVerified { .. }
            | StateContentVerification::RouteOnly(_) => Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state publish",
            )),
        }
    }

    /// Returns the deterministic, freshly verified projection for one exact key.
    pub fn query(&mut self, query: StateQuery) -> Result<StateProjection, ApplicationError> {
        let policy = self.current_policy("state query")?;
        let epoch = self
            .store
            .active_scope_epoch(&query.scope)
            .map_err(|error| application_error("state query", error.into()))?
            .map_or(1, |(epoch, _)| epoch);
        if !self.verifier.can_route_state(&query.scope, epoch)
            || !self
                .verifier
                .can_open_state_content(&query.scope, &query.topic, epoch)
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::RequestRejected,
                "state query",
            ));
        }
        let plan = self
            .store
            .prepare_state_projection_with_policy(
                &policy,
                &query.topic,
                &query.scope,
                &query.logical_key,
            )
            .map_err(|error| application_error("state query", error.into()))?;
        let projection = self.verify_projection(&query, &plan)?;
        self.store
            .require_state_projection_plan_with_policy(&policy, &plan)
            .map_err(|error| application_error("state query", error.into()))?;
        Ok(projection)
    }

    fn verify_projection(
        &mut self,
        query: &StateQuery,
        plan: &StateProjectionPlan,
    ) -> Result<StateProjection, ApplicationError> {
        if plan.topic() != &query.topic
            || plan.scope() != &query.scope
            || plan.logical_key() != query.logical_key
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state query",
            ));
        }

        let mut candidates = Vec::with_capacity(plan.candidates().len());
        let mut previous = None;
        for candidate in plan.candidates() {
            let state = candidate.state();
            let id = StateId::from_store(state.semantic_id);
            if previous.is_some_and(|previous| previous >= id) {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "state query",
                ));
            }
            previous = Some(id);
            let (item, active) = self.open_state_candidate(query, state)?;
            candidates.push(VerifiedStateCandidate {
                stamp: state.header.stamp.clone(),
                item,
                store_disposition: candidate.disposition(),
                active,
            });
        }

        let causal_candidates = candidates
            .iter()
            .map(|candidate| (candidate.item.id, &candidate.stamp, candidate.active))
            .collect::<Vec<_>>();
        let (current_index, dispositions) = recompute_state_dispositions(&causal_candidates);
        let plan_current = plan
            .current()
            .map(|candidate| StateId::from_store(candidate.state().semantic_id));
        let verified_current = current_index.map(|index| candidates[index].item.id);
        if plan_current != verified_current {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state query",
            ));
        }

        for (candidate, disposition) in candidates.iter_mut().zip(dispositions) {
            if candidate.store_disposition != disposition.map(StateVersionDisposition::into_store) {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "state query",
                ));
            }
            if let Some(disposition) = disposition {
                candidate.item.disposition = disposition;
            }
        }

        let current = current_index.map(|index| candidates[index].item.clone());
        let recoverable = if query.include_recoverable_versions {
            candidates
                .into_iter()
                .enumerate()
                .filter_map(|(index, candidate)| {
                    (candidate.active && Some(index) != current_index).then_some(candidate.item)
                })
                .collect()
        } else {
            Vec::new()
        };
        Ok(StateProjection {
            current,
            recoverable,
        })
    }

    fn open_state_candidate(
        &mut self,
        query: &StateQuery,
        stored: &StoredState,
    ) -> Result<(StateItem, bool), ApplicationError> {
        let route = self
            .verifier
            .verify_state(&stored.sealed)
            .map_err(|error| application_error("state query", error.into()))?;
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
                "state query",
            ));
        }
        let revoked = self
            .store
            .is_control_principal_revoked(route.publisher())
            .map_err(|error| application_error("state query", error.into()))?;
        let current_epoch = self
            .store
            .active_scope_epoch(route.scope())
            .map_err(|error| application_error("state query", error.into()))?
            .map_or(1, |(epoch, _)| epoch);
        if route.key_epoch() > current_epoch {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state query",
            ));
        }
        let active = !revoked && route.key_epoch() == current_epoch;
        if !self
            .verifier
            .can_route_state(route.scope(), route.key_epoch())
            || !self.verifier.can_open_state_content(
                route.scope(),
                route.topic(),
                route.key_epoch(),
            )
        {
            return Err(ApplicationError::new(
                ApplicationErrorKind::Integrity,
                "state query",
            ));
        }
        let payload = match self
            .verifier
            .verify_state_content(route, &stored.sealed)
            .map_err(|error| application_error("state query", error.into()))?
        {
            StateContentVerification::ContentVerified { state, payload } => {
                state
                    .verify_exact_payload(&payload)
                    .map_err(|error| application_error("state query", error.into()))?;
                payload
            }
            StateContentVerification::RouteOnly(_) => {
                return Err(ApplicationError::new(
                    ApplicationErrorKind::Integrity,
                    "state query",
                ));
            }
        };
        Ok((
            StateItem {
                id: StateId::from_store(stored.semantic_id),
                publisher: stored.header.stamp.dot.publisher,
                publisher_counter: stored.header.stamp.dot.counter,
                topic: stored.header.topic.clone(),
                scope: stored.header.scope.clone(),
                priority: stored.header.priority,
                logical_key: stored.header.logical_key.clone(),
                payload,
                tombstone: stored.header.tombstone,
                acceptance_marker: stored.acceptance_marker,
                disposition: StateVersionDisposition::Superseded,
            },
            active,
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
}

impl StateVersionDisposition {
    const fn into_store(self) -> StoreStateDisposition {
        match self {
            Self::Current => StoreStateDisposition::Current,
            Self::Concurrent => StoreStateDisposition::Concurrent,
            Self::Superseded => StoreStateDisposition::Superseded,
        }
    }
}

fn recompute_state_dispositions(
    candidates: &[(StateId, &CausalStamp, bool)],
) -> (Option<usize>, Vec<Option<StateVersionDisposition>>) {
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
    let current = maximal
        .iter()
        .enumerate()
        .filter(|(_, maximal)| **maximal)
        .max_by_key(|(index, _)| candidates[*index].0)
        .map(|(index, _)| index);
    let dispositions = candidates
        .iter()
        .enumerate()
        .map(|(index, (_, _, active))| {
            if !active {
                None
            } else if Some(index) == current {
                Some(StateVersionDisposition::Current)
            } else if maximal[index] {
                Some(StateVersionDisposition::Concurrent)
            } else {
                Some(StateVersionDisposition::Superseded)
            }
        })
        .collect();
    (current, dispositions)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    use aster_mesh::{Dot, ProvisioningAccess, ReferenceProvisioner, VersionVector};

    use super::*;
    use crate::application::{EventPublishRequest, EventQuery, SelectedEventNode};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-selected-state-{}-{sequence}-{label}",
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

    fn persist_mission(root: &TestRoot) {
        let scope = Scope::new("mission/apps").expect("scope");
        let state = Topic::new("ops.state").expect("topic");
        let events = Topic::new("ops.events").expect("topic");
        let access =
            ProvisioningAccess::member(scope, vec![1], vec![state, events]).expect("member access");
        let mut provisioner = ReferenceProvisioner::from_seed([0x73; 32]).expect("provisioner");
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

    fn selected_node(root: &TestRoot) -> SelectedStateNode {
        if !root.mission_path().exists() {
            persist_mission(root);
        }
        SelectedStateNode::open_unprotected_reference(root.path(), root.mission_path())
            .expect("open selected State node")
    }

    fn request(operation: &[u8], payload: &[u8]) -> StatePublishRequest {
        StatePublishRequest {
            operation_key: operation.to_vec(),
            topic: Topic::new("ops.state").expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            priority: Priority::Priority,
            logical_key: b"asset-7".to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
        }
    }

    fn query(recoverable: bool) -> StateQuery {
        StateQuery {
            topic: Topic::new("ops.state").expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            logical_key: b"asset-7".to_vec(),
            include_recoverable_versions: recoverable,
        }
    }

    #[test]
    fn state_reducer_uses_explicit_observation_and_id_tie_without_delete_wins() {
        let first_dot = Dot {
            publisher: [0x11; 32],
            counter: 1,
        };
        let concurrent_dot = Dot {
            publisher: [0x22; 32],
            counter: 1,
        };
        let first = CausalStamp {
            dot: first_dot,
            context: VersionVector::default(),
        };
        let concurrent = CausalStamp {
            dot: concurrent_dot,
            context: VersionVector::default(),
        };
        let low = StateId::from_bytes([0x10; 32]);
        let high = StateId::from_bytes([0x20; 32]);

        // Tombstone is intentionally not an input to this reducer: concurrent
        // edit/delete heads use the same complete semantic-ID tie break.
        let (current, dispositions) =
            recompute_state_dispositions(&[(low, &first, true), (high, &concurrent, true)]);
        assert_eq!(current, Some(1));
        assert_eq!(
            dispositions,
            vec![
                Some(StateVersionDisposition::Concurrent),
                Some(StateVersionDisposition::Current),
            ]
        );
        let (current, dispositions) =
            recompute_state_dispositions(&[(high, &concurrent, true), (low, &first, true)]);
        assert_eq!(current, Some(0));
        assert_eq!(
            dispositions,
            vec![
                Some(StateVersionDisposition::Current),
                Some(StateVersionDisposition::Concurrent),
            ]
        );

        let mut successor_context = VersionVector::default();
        successor_context.observe(first_dot);
        let successor = CausalStamp {
            dot: Dot {
                publisher: first_dot.publisher,
                counter: 2,
            },
            context: successor_context,
        };
        let (current, dispositions) =
            recompute_state_dispositions(&[(high, &first, true), (low, &successor, true)]);
        assert_eq!(current, Some(1));
        assert_eq!(
            dispositions,
            vec![
                Some(StateVersionDisposition::Superseded),
                Some(StateVersionDisposition::Current),
            ]
        );

        let (current, dispositions) =
            recompute_state_dispositions(&[(high, &concurrent, false), (low, &first, true)]);
        assert_eq!(current, Some(1));
        assert_eq!(
            dispositions,
            vec![None, Some(StateVersionDisposition::Current)]
        );
    }

    #[test]
    fn state_projection_is_causal_idempotent_and_restart_stable() {
        let root = TestRoot::new("projection");
        let (first, second) = {
            let mut node = selected_node(&root);
            let first_request = request(b"state/first", b"ready");
            let first = node.publish(first_request.clone()).expect("first State");
            assert!(first.inserted);
            assert_eq!(first.publisher_counter, 1);
            let first_projection = node.query(query(true)).expect("first projection");
            assert_eq!(
                first_projection.current.as_ref().map(|item| item.id),
                Some(first.id)
            );
            assert!(first_projection.recoverable.is_empty());

            let second = node
                .publish(request(b"state/second", b"moving"))
                .expect("second State");
            assert!(second.inserted);
            assert_eq!(second.publisher_counter, 2);
            let projection = node.query(query(true)).expect("causal projection");
            assert_eq!(
                projection.current.as_ref().map(|item| item.id),
                Some(second.id)
            );
            assert_eq!(
                projection
                    .current
                    .as_ref()
                    .map(|item| item.payload.as_slice()),
                Some(b"moving".as_slice())
            );
            assert_eq!(projection.recoverable.len(), 1);
            assert_eq!(projection.recoverable[0].id, first.id);
            assert_eq!(
                projection.recoverable[0].disposition,
                StateVersionDisposition::Superseded
            );

            let replay = node.publish(first_request).expect("idempotent replay");
            assert!(!replay.inserted);
            assert_eq!(replay.id, first.id);
            assert_eq!(replay.publisher_counter, first.publisher_counter);
            assert_eq!(replay.acceptance_marker, first.acceptance_marker);
            let conflict = node
                .publish(request(b"state/first", b"different"))
                .expect_err("changed operation intent");
            assert_eq!(conflict.kind(), ApplicationErrorKind::Conflict);
            (first, second)
        };

        let mut reopened = selected_node(&root);
        let projection = reopened.query(query(true)).expect("reopen projection");
        assert_eq!(
            projection.current.as_ref().map(|item| item.id),
            Some(second.id)
        );
        assert_eq!(projection.recoverable.len(), 1);
        assert_eq!(projection.recoverable[0].id, first.id);
    }

    #[test]
    fn authenticated_tombstone_remains_visible_as_the_current_state() {
        let root = TestRoot::new("tombstone");
        let mut node = selected_node(&root);
        let live = node
            .publish(request(b"state/live", b"ready"))
            .expect("live State");
        let mut deletion = request(b"state/delete", b"");
        deletion.tombstone = true;
        let tombstone = node.publish(deletion).expect("State tombstone");
        let projection = node.query(query(true)).expect("tombstone projection");
        let current = projection.current.expect("visible current tombstone");
        assert_eq!(current.id, tombstone.id);
        assert!(current.tombstone);
        assert!(current.payload.is_empty());
        assert_eq!(projection.recoverable.len(), 1);
        assert_eq!(projection.recoverable[0].id, live.id);

        let mut invalid = request(b"state/invalid-delete", b"not-empty");
        invalid.tombstone = true;
        let error = node.publish(invalid).expect_err("nonempty tombstone");
        assert_eq!(error.kind(), ApplicationErrorKind::InvalidRequest);
    }

    #[test]
    fn event_and_state_share_publisher_counters_but_not_event_positions() {
        let root = TestRoot::new("shared-ledger");
        persist_mission(&root);
        let event_request = |operation: &[u8], payload: &[u8]| EventPublishRequest {
            operation_key: operation.to_vec(),
            predecessor: None,
            topic: Topic::new("ops.events").expect("topic"),
            scope: Scope::new("mission/apps").expect("scope"),
            priority: Priority::Routine,
            logical_key: b"asset-7".to_vec(),
            payload: payload.to_vec(),
            tombstone: false,
        };

        let first_event = {
            let mut events =
                SelectedEventNode::open_unprotected_reference(root.path(), root.mission_path())
                    .expect("open Event node");
            events
                .publish(event_request(b"event/first", b"first"))
                .expect("first Event")
        };
        assert_eq!(first_event.publisher_counter, 1);
        assert_eq!(first_event.event_sequence, 1);

        let state = {
            let mut state = selected_node(&root);
            state
                .publish(request(b"state/interleaved", b"state"))
                .expect("interleaved State")
        };
        assert_eq!(state.publisher_counter, 2);

        let mut events =
            SelectedEventNode::open_unprotected_reference(root.path(), root.mission_path())
                .expect("reopen Event node");
        let second_event = events
            .publish(event_request(b"event/second", b"second"))
            .expect("second Event");
        assert_eq!(second_event.publisher_counter, 3);
        assert_eq!(second_event.event_sequence, 2);
        let page = events.query(EventQuery::default()).expect("Event page");
        assert_eq!(page.items.len(), 2);
        assert_eq!(page.scanned_through, 2);
    }

    #[test]
    fn state_and_event_facades_share_the_exact_writer_exclusion() {
        let root = TestRoot::new("writer-exclusion");
        persist_mission(&root);
        let events =
            SelectedEventNode::open_unprotected_reference(root.path(), root.mission_path())
                .expect("open Event owner");
        let error =
            match SelectedStateNode::open_unprotected_reference(root.path(), root.mission_path()) {
                Ok(_) => panic!("second writer must fail"),
                Err(error) => error,
            };
        assert_eq!(error.kind(), ApplicationErrorKind::StateUnavailable);
        drop(events);
        drop(selected_node(&root));
    }
}
