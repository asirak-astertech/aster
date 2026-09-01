//! Durable, payload-blind Event bridge candidates and process-local promotion.
//!
//! Bridge authorization and route bytes remain opaque to this crate. Only the
//! strong capabilities minted by `aster-core` after fresh cryptographic
//! verification can enter the mutation methods below. Durable reload methods
//! deliberately return candidates, never verification capabilities.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use aster_mesh::{
    NodeId, Priority, Scope, Topic, VerifiedSelectedBridgeAuthorization,
    VerifiedSelectedBridgeEventRoute,
};
use redb::{ReadableDatabase, ReadableTable, TableDefinition, TableHandle};
use sha2::{Digest, Sha256};

use super::{
    METADATA, Store, StoreError, StoreLimits, enforce_live_write, require_aggregate_capacity,
    require_ordinary_aggregate_capacity,
};

const BRIDGE_AUTHORIZATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.selected-bridge-authorizations.v1");
const BRIDGE_AUTHORIZATION_BYTES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.selected-bridge-authorization-bytes.v1");
const BRIDGE_AUTHORIZATION_SEQUENCE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("aster.selected-bridge-authorization-sequence.v1");
const BRIDGE_AUTHORIZATION_HEAD: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.selected-bridge-authorization-head.v1");
const BRIDGE_AUTHORIZATION_HIGH_WATER: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.selected-bridge-authorization-high-water.v1");
const BRIDGE_EVENT_SOURCES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.selected-bridge-event-sources.v1");
const BRIDGE_EVENT_ROUTES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.selected-bridge-event-routes.v1");
const BRIDGE_EVENT_WRAPPER_BYTES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.selected-bridge-event-wrapper-bytes.v1");
const BRIDGE_EVENT_ROUTE_IDS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.selected-bridge-event-route-ids.v1");
const BRIDGE_EVENT_ACTIVE_ROUTES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.selected-bridge-event-active-routes.v1");

pub(crate) const BRIDGE_AUTHORIZATION_ITEM_COUNT: &str = "selected_bridge_authorization_item_count";
pub(crate) const BRIDGE_AUTHORIZATION_TOTAL_BYTES: &str =
    "selected_bridge_authorization_total_bytes";
pub(crate) const BRIDGE_EVENT_SOURCE_ITEM_COUNT: &str = "selected_bridge_event_source_item_count";
pub(crate) const BRIDGE_EVENT_SOURCE_TOTAL_BYTES: &str = "selected_bridge_event_source_total_bytes";
pub(crate) const BRIDGE_EVENT_ROUTE_ITEM_COUNT: &str = "selected_bridge_event_route_item_count";
pub(crate) const BRIDGE_EVENT_ROUTE_TOTAL_BYTES: &str = "selected_bridge_event_route_total_bytes";

const AUTHORIZATION_RECORD_MAGIC: &[u8; 8] = b"ASTRBAR1";
const ROUTE_RECORD_MAGIC: &[u8; 8] = b"ASTRBER1";
const RECORD_FORMAT: u16 = 1;
const AUTHORIZATION_HEAD_KEY: &[u8] = b"head";
const MAX_AUTHORIZATION_BYTES: usize = 65_536;
const MAX_WRAPPER_BYTES: usize = 524_322;
const MAX_HOPS: usize = 8;
const MAX_CANDIDATE_PAGE: usize = 1_024;

/// A bridge persistence failure which is distinct from ordinary Event state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BridgeStoreError {
    /// A fresh core capability carried inconsistent bounded metadata.
    Invalid(&'static str),
    /// Durable bridge tables or indexes disagree.
    Invariant(&'static str),
    /// A control did not extend the exact current bridge-control head.
    AuthorizationSequence { expected: u64, received: u64 },
    /// Two bridge controls claim one sequence or predecessor position.
    AuthorizationFork,
    /// An authorization key generation did not strictly advance.
    AuthorizationGenerationRollback { high_water: u64, received: u64 },
    /// A route's exact source, wrapper, or route identity conflicts with a durable row.
    RouteIdentityConflict,
    /// A route references an authorization which is absent, disabled, or superseded.
    RouteAuthorizationNotCurrent,
    /// A bounded candidate scan requested too many rows.
    CandidatePageLimit { requested: usize, maximum: usize },
}

impl fmt::Display for BridgeStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => {
                write!(formatter, "invalid verified Event bridge input: {reason}")
            }
            Self::Invariant(reason) => {
                write!(formatter, "durable Event bridge invariant failed: {reason}")
            }
            Self::AuthorizationSequence { expected, received } => write!(
                formatter,
                "Event bridge authorization sequence {received} does not extend expected sequence {expected}"
            ),
            Self::AuthorizationFork => {
                formatter.write_str("Event bridge authorization-chain fork detected")
            }
            Self::AuthorizationGenerationRollback {
                high_water,
                received,
            } => write!(
                formatter,
                "Event bridge authorization generation {received} does not advance high-water {high_water}"
            ),
            Self::RouteIdentityConflict => formatter
                .write_str("Event bridge route identity maps to different exact bytes or metadata"),
            Self::RouteAuthorizationNotCurrent => formatter.write_str(
                "Event bridge route does not reference the current enabled authorization set",
            ),
            Self::CandidatePageLimit { requested, maximum } => write!(
                formatter,
                "Event bridge candidate page {requested} exceeds maximum {maximum}"
            ),
        }
    }
}

impl std::error::Error for BridgeStoreError {}

/// Aggregate bounded usage of the selected redb Event bridge namespace.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BridgeStoreStats {
    pub authorizations: u64,
    pub authorization_bytes: u64,
    pub event_sources: u64,
    pub event_source_bytes: u64,
    pub event_routes: u64,
    pub event_route_bytes: u64,
    /// Process-live route projections. Normal reopen audits and clears these.
    pub active_routes: u64,
    pub authorization_head_sequence: u64,
}

impl BridgeStoreStats {
    pub(crate) fn aggregate_items(self) -> Result<u64, StoreError> {
        self.authorizations
            .checked_add(self.event_sources)
            .and_then(|value| value.checked_add(self.event_routes))
            .ok_or(StoreError::ItemCountAccountingOverflow)
    }
}

/// Opaque durable authorization returned after reopen.
///
/// This is only a verification candidate. It cannot authorize route promotion;
/// pass `exact_bytes()` back through `aster-core` to obtain a fresh strong
/// capability first.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSelectedBridgeAuthorizationCandidate {
    envelope_id: [u8; 32],
    authority_id: NodeId,
    control_signer: NodeId,
    control_sequence: u64,
    previous_control_id: Option<[u8; 32]>,
    authorization_key: [u8; 32],
    generation: u64,
    enabled: bool,
    exact_bytes: Vec<u8>,
}

impl StoredSelectedBridgeAuthorizationCandidate {
    pub const fn envelope_id(&self) -> [u8; 32] {
        self.envelope_id
    }
    pub const fn authority_id(&self) -> NodeId {
        self.authority_id
    }
    pub const fn control_signer(&self) -> NodeId {
        self.control_signer
    }
    pub const fn control_sequence(&self) -> u64 {
        self.control_sequence
    }
    pub const fn previous_control_id(&self) -> Option<[u8; 32]> {
        self.previous_control_id
    }
    pub const fn authorization_key(&self) -> [u8; 32] {
        self.authorization_key
    }
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
    pub fn exact_bytes(&self) -> &[u8] {
        &self.exact_bytes
    }
}

/// Opaque durable Event route/source pair returned after reopen.
///
/// Exact source bytes are deduplicated in redb and joined into this candidate.
/// Loading this value never makes it active or trusted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredSelectedBridgeEventRouteCandidate {
    wrapper_envelope_id: [u8; 32],
    bridge_route_id: [u8; 32],
    origin_envelope_id: [u8; 32],
    source_item_id: [u8; 32],
    publisher: NodeId,
    origin_scope: Scope,
    origin_route_epoch: u64,
    current_scope: Scope,
    current_route_epoch: u64,
    topic: Topic,
    priority: Priority,
    event_sequence: u64,
    ttl_ms: Option<u64>,
    hop_count: u8,
    authorization_envelope_ids: Vec<[u8; 32]>,
    exact_wrapper_bytes: Arc<[u8]>,
    exact_source_bytes: Arc<[u8]>,
}

impl StoredSelectedBridgeEventRouteCandidate {
    pub const fn wrapper_envelope_id(&self) -> [u8; 32] {
        self.wrapper_envelope_id
    }
    pub const fn bridge_route_id(&self) -> [u8; 32] {
        self.bridge_route_id
    }
    pub const fn origin_envelope_id(&self) -> [u8; 32] {
        self.origin_envelope_id
    }
    pub const fn source_item_id(&self) -> [u8; 32] {
        self.source_item_id
    }
    pub const fn publisher(&self) -> NodeId {
        self.publisher
    }
    pub const fn origin_scope(&self) -> &Scope {
        &self.origin_scope
    }
    pub const fn origin_route_epoch(&self) -> u64 {
        self.origin_route_epoch
    }
    pub const fn current_scope(&self) -> &Scope {
        &self.current_scope
    }
    pub const fn current_route_epoch(&self) -> u64 {
        self.current_route_epoch
    }
    pub const fn topic(&self) -> &Topic {
        &self.topic
    }
    pub const fn priority(&self) -> Priority {
        self.priority
    }
    pub const fn event_sequence(&self) -> u64 {
        self.event_sequence
    }
    pub const fn ttl_ms(&self) -> Option<u64> {
        self.ttl_ms
    }
    pub const fn hop_count(&self) -> u8 {
        self.hop_count
    }
    pub fn authorization_envelope_ids(&self) -> &[[u8; 32]] {
        &self.authorization_envelope_ids
    }
    pub fn exact_wrapper_bytes(&self) -> &[u8] {
        &self.exact_wrapper_bytes
    }
    pub fn exact_source_bytes(&self) -> &[u8] {
        &self.exact_source_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedBridgeAuthorizationCommitOutcome {
    Applied {
        envelope_id: [u8; 32],
        sequence: u64,
    },
    Duplicate {
        envelope_id: [u8; 32],
        sequence: u64,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectedBridgeEventRouteCommitOutcome {
    Active {
        wrapper_envelope_id: [u8; 32],
        replaced: Option<[u8; 32]>,
    },
    RetainedAlternate {
        wrapper_envelope_id: [u8; 32],
        active_wrapper_envelope_id: [u8; 32],
    },
    Duplicate {
        wrapper_envelope_id: [u8; 32],
        active: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthorizationRecord {
    envelope_id: [u8; 32],
    authority_id: NodeId,
    control_signer: NodeId,
    control_sequence: u64,
    previous_control_id: Option<[u8; 32]>,
    authorization_key: [u8; 32],
    generation: u64,
    enabled: bool,
    exact_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EventRouteRecord {
    wrapper_envelope_id: [u8; 32],
    bridge_route_id: [u8; 32],
    origin_envelope_id: [u8; 32],
    source_item_id: [u8; 32],
    publisher: NodeId,
    origin_scope: Scope,
    origin_route_epoch: u64,
    current_scope: Scope,
    current_route_epoch: u64,
    topic: Topic,
    priority: Priority,
    event_sequence: u64,
    ttl_ms: Option<u64>,
    hop_count: u8,
    authorization_envelope_ids: Vec<[u8; 32]>,
    exact_wrapper_bytes: Arc<[u8]>,
    exact_source_bytes: Arc<[u8]>,
}

impl AuthorizationRecord {
    fn from_verified(value: &VerifiedSelectedBridgeAuthorization) -> Result<Self, StoreError> {
        let record = Self {
            envelope_id: value.envelope_id(),
            authority_id: value.authority_id(),
            control_signer: value.control_signer(),
            control_sequence: value.control_sequence(),
            previous_control_id: value.previous_control_id(),
            authorization_key: value.authorization_key(),
            generation: value.generation(),
            enabled: value.is_enabled(),
            exact_bytes: value.exact_bytes().to_vec(),
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.control_sequence == 0
            || self.generation == 0
            || (self.control_sequence == 1) != self.previous_control_id.is_none()
            || self.exact_bytes.is_empty()
            || self.exact_bytes.len() > MAX_AUTHORIZATION_BYTES
            || digest(&self.exact_bytes) != self.envelope_id
        {
            return Err(BridgeStoreError::Invalid(
                "authorization identity, chain, generation, or exact bytes",
            )
            .into());
        }
        Ok(())
    }

    fn candidate(self) -> StoredSelectedBridgeAuthorizationCandidate {
        StoredSelectedBridgeAuthorizationCandidate {
            envelope_id: self.envelope_id,
            authority_id: self.authority_id,
            control_signer: self.control_signer,
            control_sequence: self.control_sequence,
            previous_control_id: self.previous_control_id,
            authorization_key: self.authorization_key,
            generation: self.generation,
            enabled: self.enabled,
            exact_bytes: self.exact_bytes,
        }
    }
}

impl EventRouteRecord {
    fn from_verified(value: &VerifiedSelectedBridgeEventRoute) -> Result<Self, StoreError> {
        let record = Self {
            wrapper_envelope_id: value.wrapper_envelope_id(),
            bridge_route_id: value.bridge_route_id(),
            origin_envelope_id: value.origin_envelope_id(),
            source_item_id: value.source_item_id(),
            publisher: value.publisher(),
            origin_scope: value.origin_scope().clone(),
            origin_route_epoch: value.origin_route_epoch(),
            current_scope: value.current_scope().clone(),
            current_route_epoch: value.current_route_epoch(),
            topic: value.topic().clone(),
            priority: value.priority(),
            event_sequence: value.event_sequence(),
            ttl_ms: value.ttl_ms(),
            hop_count: value.hop_count(),
            authorization_envelope_ids: value.authorization_envelope_ids().to_vec(),
            exact_wrapper_bytes: Arc::from(value.exact_wrapper_bytes()),
            exact_source_bytes: Arc::from(value.exact_source_bytes()),
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), StoreError> {
        let hop_count = usize::from(self.hop_count);
        if hop_count == 0
            || hop_count > MAX_HOPS
            || self.authorization_envelope_ids.len() != hop_count
            || self
                .authorization_envelope_ids
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != hop_count
            || self.origin_route_epoch == 0
            || self.current_route_epoch == 0
            || self.event_sequence == 0
            || self.origin_scope == self.current_scope
            || self.exact_source_bytes.is_empty()
            || self.exact_wrapper_bytes.is_empty()
            || self.exact_wrapper_bytes.len() > MAX_WRAPPER_BYTES
            || digest(&self.exact_source_bytes) != self.origin_envelope_id
            || digest(&self.exact_wrapper_bytes) != self.wrapper_envelope_id
        {
            return Err(BridgeStoreError::Invalid(
                "Event route metadata, dependencies, or exact bytes",
            )
            .into());
        }
        Ok(())
    }

    fn candidate(self) -> StoredSelectedBridgeEventRouteCandidate {
        StoredSelectedBridgeEventRouteCandidate {
            wrapper_envelope_id: self.wrapper_envelope_id,
            bridge_route_id: self.bridge_route_id,
            origin_envelope_id: self.origin_envelope_id,
            source_item_id: self.source_item_id,
            publisher: self.publisher,
            origin_scope: self.origin_scope,
            origin_route_epoch: self.origin_route_epoch,
            current_scope: self.current_scope,
            current_route_epoch: self.current_route_epoch,
            topic: self.topic,
            priority: self.priority,
            event_sequence: self.event_sequence,
            ttl_ms: self.ttl_ms,
            hop_count: self.hop_count,
            authorization_envelope_ids: self.authorization_envelope_ids,
            exact_wrapper_bytes: self.exact_wrapper_bytes,
            exact_source_bytes: self.exact_source_bytes,
        }
    }
}

impl Store {
    /// Atomically commits one freshly verified bridge authorization.
    ///
    /// The bridge-control chain is independent from mission controls and must
    /// extend its exact contiguous head. Every accepted update strictly advances
    /// the named edge generation, including disable updates. A successful new
    /// update clears process-live route projections in the same transaction.
    pub fn commit_verified_selected_bridge_authorization(
        &self,
        verified: &VerifiedSelectedBridgeAuthorization,
    ) -> Result<SelectedBridgeAuthorizationCommitOutcome, StoreError> {
        self.require_live()?;
        let record = AuthorizationRecord::from_verified(verified)?;
        self.commit_bridge_authorization_record(&record)
    }

    /// Atomically stores and promotes one freshly verified opaque Event route.
    ///
    /// Exact source bytes are deduplicated by origin-envelope identity. Promotion
    /// rechecks every referenced authorization high-water in the same transaction
    /// and selects the shortest hop count, then lexicographically smallest route ID.
    pub fn commit_verified_selected_bridge_event_route(
        &self,
        verified: &VerifiedSelectedBridgeEventRoute,
    ) -> Result<SelectedBridgeEventRouteCommitOutcome, StoreError> {
        self.require_live()?;
        let record = EventRouteRecord::from_verified(verified)?;
        self.commit_bridge_event_route_record(&record)
    }

    /// Returns a bounded sequence-ordered set of opaque authorization candidates.
    pub fn selected_bridge_authorization_candidates(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredSelectedBridgeAuthorizationCandidate>, StoreError> {
        self.selected_bridge_authorization_candidates_after(None, limit)
    }

    /// Returns a bounded sequence-ordered candidate page strictly after `after_sequence`.
    pub fn selected_bridge_authorization_candidates_after(
        &self,
        after_sequence: Option<u64>,
        limit: usize,
    ) -> Result<Vec<StoredSelectedBridgeAuthorizationCandidate>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        check_page_limit(limit)?;
        let read = self.database.begin_read()?;
        let sequence = read.open_table(BRIDGE_AUTHORIZATION_SEQUENCE)?;
        let lower = after_sequence.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let mut candidates = Vec::new();
        for row in sequence
            .range((lower, std::ops::Bound::Unbounded))?
            .take(limit)
        {
            let (_, id) = row?;
            candidates.push(
                load_authorization_read(&read, parse_id(id.value())?)?
                    .ok_or(BridgeStoreError::Invariant(
                        "authorization sequence points to a missing row",
                    ))?
                    .candidate(),
            );
        }
        Ok(candidates)
    }

    /// Returns bounded opaque route/source candidates in wrapper-ID order.
    pub fn selected_bridge_event_route_candidates(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredSelectedBridgeEventRouteCandidate>, StoreError> {
        self.selected_bridge_event_route_candidates_after(None, limit)
    }

    /// Returns a bounded wrapper-ID-ordered candidate page strictly after `after_wrapper`.
    pub fn selected_bridge_event_route_candidates_after(
        &self,
        after_wrapper: Option<[u8; 32]>,
        limit: usize,
    ) -> Result<Vec<StoredSelectedBridgeEventRouteCandidate>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        check_page_limit(limit)?;
        let read = self.database.begin_read()?;
        let routes = read.open_table(BRIDGE_EVENT_ROUTES)?;
        let lower = after_wrapper
            .as_ref()
            .map_or(std::ops::Bound::Unbounded, |id| {
                std::ops::Bound::Excluded(id.as_slice())
            });
        let mut candidates = Vec::new();
        let mut exact_sources = BTreeMap::new();
        for row in routes
            .range::<&[u8]>((lower, std::ops::Bound::Unbounded))?
            .take(limit)
        {
            let (id, _) = row?;
            candidates.push(
                load_route_read_cached(&read, parse_id(id.value())?, &mut exact_sources)?
                    .ok_or(BridgeStoreError::Invariant("route scan row disappeared"))?
                    .candidate(),
            );
        }
        Ok(candidates)
    }

    /// Returns the current process-live route projection as an opaque candidate.
    ///
    /// Normal reopen audits and clears this projection. Therefore a restarted
    /// caller must freshly verify and recommit a candidate before this returns it.
    pub fn active_selected_bridge_event_route_candidate(
        &self,
        origin_envelope_id: [u8; 32],
        current_scope: &Scope,
        current_route_epoch: u64,
    ) -> Result<Option<StoredSelectedBridgeEventRouteCandidate>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        if current_route_epoch == 0 {
            return Err(BridgeStoreError::Invalid("active route epoch is zero").into());
        }
        let key = active_route_key(origin_envelope_id, current_scope, current_route_epoch)?;
        let read = self.database.begin_read()?;
        let wrapper = read
            .open_table(BRIDGE_EVENT_ACTIVE_ROUTES)?
            .get(key.as_slice())?
            .map(|value| parse_id(value.value()))
            .transpose()?;
        wrapper
            .map(|id| {
                load_route_read(&read, id)?
                    .map(EventRouteRecord::candidate)
                    .ok_or_else(|| {
                        BridgeStoreError::Invariant("active route points to a missing wrapper")
                            .into()
                    })
            })
            .transpose()
    }

    /// Reads audited bridge namespace usage for this live handle.
    pub fn selected_bridge_stats(&self) -> Result<BridgeStoreStats, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        inspect_bridge_tables_read_transaction(&read, self.mission_authority)
    }

    fn commit_bridge_authorization_record(
        &self,
        record: &AuthorizationRecord,
    ) -> Result<SelectedBridgeAuthorizationCommitOutcome, StoreError> {
        let authority = self.require_bound_mission()?;
        if record.authority_id != authority {
            return Err(StoreError::MissionAuthorityMismatch {
                bound: authority,
                received: record.authority_id,
            });
        }
        let encoded = encode_authorization(record)?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        super::check_expected_mission_binding(&write, authority)?;

        if let Some(existing) = load_authorization_write(&write, record.envelope_id)? {
            if existing != *record {
                return Err(BridgeStoreError::AuthorizationFork.into());
            }
            return Ok(SelectedBridgeAuthorizationCommitOutcome::Duplicate {
                envelope_id: record.envelope_id,
                sequence: record.control_sequence,
            });
        }

        let head = authorization_head_write(&write)?;
        let expected_sequence = match head {
            Some((sequence, _)) => sequence
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?,
            None => 1,
        };
        if record.control_sequence != expected_sequence {
            return Err(BridgeStoreError::AuthorizationSequence {
                expected: expected_sequence,
                received: record.control_sequence,
            }
            .into());
        }
        if record.previous_control_id != head.map(|(_, id)| id) {
            return Err(BridgeStoreError::AuthorizationFork.into());
        }
        if write
            .open_table(BRIDGE_AUTHORIZATION_SEQUENCE)?
            .get(record.control_sequence)?
            .is_some()
        {
            return Err(BridgeStoreError::AuthorizationFork.into());
        }
        if let Some((generation, _, _)) =
            authorization_high_water_write(&write, record.authorization_key)?
            && record.generation <= generation
        {
            return Err(BridgeStoreError::AuthorizationGenerationRollback {
                high_water: generation,
                received: record.generation,
            }
            .into());
        }

        let incoming = usize_to_u64(encoded.len())?
            .checked_add(usize_to_u64(record.exact_bytes.len())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        {
            let mut metadata = write.open_table(METADATA)?;
            require_ordinary_aggregate_capacity(&write, &metadata, self.limits, 1, incoming)?;
            increment_counter(&mut metadata, BRIDGE_AUTHORIZATION_ITEM_COUNT, 1)?;
            increment_counter(&mut metadata, BRIDGE_AUTHORIZATION_TOTAL_BYTES, incoming)?;
        }
        write
            .open_table(BRIDGE_AUTHORIZATIONS)?
            .insert(record.envelope_id.as_slice(), encoded.as_slice())?;
        write
            .open_table(BRIDGE_AUTHORIZATION_BYTES)?
            .insert(record.envelope_id.as_slice(), record.exact_bytes.as_slice())?;
        write
            .open_table(BRIDGE_AUTHORIZATION_SEQUENCE)?
            .insert(record.control_sequence, record.envelope_id.as_slice())?;
        write.open_table(BRIDGE_AUTHORIZATION_HEAD)?.insert(
            AUTHORIZATION_HEAD_KEY,
            encode_head(record.control_sequence, record.envelope_id).as_slice(),
        )?;
        write.open_table(BRIDGE_AUTHORIZATION_HIGH_WATER)?.insert(
            record.authorization_key.as_slice(),
            encode_high_water(record.generation, record.enabled, record.envelope_id).as_slice(),
        )?;
        clear_active_routes_write(&write)?;
        write.commit()?;
        Ok(SelectedBridgeAuthorizationCommitOutcome::Applied {
            envelope_id: record.envelope_id,
            sequence: record.control_sequence,
        })
    }

    fn commit_bridge_event_route_record(
        &self,
        record: &EventRouteRecord,
    ) -> Result<SelectedBridgeEventRouteCommitOutcome, StoreError> {
        let authority = self.require_bound_mission()?;
        let encoded = encode_route(record)?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        super::check_expected_mission_binding(&write, authority)?;
        require_route_authorizations_current_write(&write, &record.authorization_envelope_ids)?;

        let existing_route = load_route_write(&write, record.wrapper_envelope_id)?;
        if let Some(existing) = &existing_route {
            if existing != record {
                return Err(BridgeStoreError::RouteIdentityConflict.into());
            }
        } else {
            if let Some(occupied) = write
                .open_table(BRIDGE_EVENT_ROUTE_IDS)?
                .get(record.bridge_route_id.as_slice())?
                .map(|value| parse_id(value.value()))
                .transpose()?
                && occupied != record.wrapper_envelope_id
            {
                return Err(BridgeStoreError::RouteIdentityConflict.into());
            }
            let source = write
                .open_table(BRIDGE_EVENT_SOURCES)?
                .get(record.origin_envelope_id.as_slice())?
                .map(|value| value.value().to_vec());
            if source
                .as_deref()
                .is_some_and(|bytes| bytes != record.exact_source_bytes.as_ref())
            {
                return Err(BridgeStoreError::RouteIdentityConflict.into());
            }
            let source_is_new = source.is_none();
            let source_incoming = if source_is_new {
                usize_to_u64(record.exact_source_bytes.len())?
            } else {
                0
            };
            let route_incoming = usize_to_u64(encoded.len())?
                .checked_add(usize_to_u64(record.exact_wrapper_bytes.len())?)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            let incoming_items = 1u64
                .checked_add(u64::from(source_is_new))
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            let incoming_bytes = source_incoming
                .checked_add(route_incoming)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            {
                let mut metadata = write.open_table(METADATA)?;
                require_ordinary_aggregate_capacity(
                    &write,
                    &metadata,
                    self.limits,
                    incoming_items,
                    incoming_bytes,
                )?;
                increment_counter(&mut metadata, BRIDGE_EVENT_ROUTE_ITEM_COUNT, 1)?;
                increment_counter(
                    &mut metadata,
                    BRIDGE_EVENT_ROUTE_TOTAL_BYTES,
                    route_incoming,
                )?;
                if source_is_new {
                    increment_counter(&mut metadata, BRIDGE_EVENT_SOURCE_ITEM_COUNT, 1)?;
                    increment_counter(
                        &mut metadata,
                        BRIDGE_EVENT_SOURCE_TOTAL_BYTES,
                        source_incoming,
                    )?;
                }
            }
            if source_is_new {
                write.open_table(BRIDGE_EVENT_SOURCES)?.insert(
                    record.origin_envelope_id.as_slice(),
                    record.exact_source_bytes.as_ref(),
                )?;
            }
            write
                .open_table(BRIDGE_EVENT_ROUTES)?
                .insert(record.wrapper_envelope_id.as_slice(), encoded.as_slice())?;
            write.open_table(BRIDGE_EVENT_WRAPPER_BYTES)?.insert(
                record.wrapper_envelope_id.as_slice(),
                record.exact_wrapper_bytes.as_ref(),
            )?;
            write.open_table(BRIDGE_EVENT_ROUTE_IDS)?.insert(
                record.bridge_route_id.as_slice(),
                record.wrapper_envelope_id.as_slice(),
            )?;
        }

        let active_key = active_route_key(
            record.origin_envelope_id,
            &record.current_scope,
            record.current_route_epoch,
        )?;
        let active_wrapper = write
            .open_table(BRIDGE_EVENT_ACTIVE_ROUTES)?
            .get(active_key.as_slice())?
            .map(|value| parse_id(value.value()))
            .transpose()?;
        let candidate_rank = (record.hop_count, record.bridge_route_id);
        let active_rank = match active_wrapper {
            Some(id) => Some(
                load_route_write(&write, id)?
                    .ok_or(BridgeStoreError::Invariant(
                        "active route points to a missing wrapper",
                    ))
                    .map(|active| (active.hop_count, active.bridge_route_id))?,
            ),
            None => None,
        };
        let candidate_wins = active_rank.is_none_or(|rank| candidate_rank < rank);
        let was_active = active_wrapper == Some(record.wrapper_envelope_id);
        let outcome = if candidate_wins {
            write
                .open_table(BRIDGE_EVENT_ACTIVE_ROUTES)?
                .insert(active_key.as_slice(), record.wrapper_envelope_id.as_slice())?;
            if existing_route.is_some() && was_active {
                SelectedBridgeEventRouteCommitOutcome::Duplicate {
                    wrapper_envelope_id: record.wrapper_envelope_id,
                    active: true,
                }
            } else {
                SelectedBridgeEventRouteCommitOutcome::Active {
                    wrapper_envelope_id: record.wrapper_envelope_id,
                    replaced: active_wrapper.filter(|id| id != &record.wrapper_envelope_id),
                }
            }
        } else if existing_route.is_some() {
            SelectedBridgeEventRouteCommitOutcome::Duplicate {
                wrapper_envelope_id: record.wrapper_envelope_id,
                active: false,
            }
        } else {
            SelectedBridgeEventRouteCommitOutcome::RetainedAlternate {
                wrapper_envelope_id: record.wrapper_envelope_id,
                active_wrapper_envelope_id: active_wrapper.ok_or(BridgeStoreError::Invariant(
                    "ranked route has no active predecessor",
                ))?,
            }
        };
        write.commit()?;
        Ok(outcome)
    }
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn check_page_limit(limit: usize) -> Result<(), StoreError> {
    if limit > MAX_CANDIDATE_PAGE {
        return Err(BridgeStoreError::CandidatePageLimit {
            requested: limit,
            maximum: MAX_CANDIDATE_PAGE,
        }
        .into());
    }
    Ok(())
}

fn usize_to_u64(value: usize) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_| StoreError::PayloadByteAccountingOverflow)
}

fn increment_counter(
    metadata: &mut redb::Table<'_, &str, u64>,
    field: &'static str,
    increment: u64,
) -> Result<(), StoreError> {
    let next = metadata
        .get(field)?
        .map_or(0, |value| value.value())
        .checked_add(increment)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    metadata.insert(field, next)?;
    Ok(())
}

fn parse_id(bytes: &[u8]) -> Result<[u8; 32], StoreError> {
    bytes
        .try_into()
        .map_err(|_| BridgeStoreError::Invariant("identifier has invalid length").into())
}

fn encode_head(sequence: u64, id: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(40);
    bytes.extend_from_slice(&sequence.to_be_bytes());
    bytes.extend_from_slice(&id);
    bytes
}

fn decode_head(bytes: &[u8]) -> Result<(u64, [u8; 32]), StoreError> {
    if bytes.len() != 40 {
        return Err(BridgeStoreError::Invariant("authorization head has invalid length").into());
    }
    let sequence = u64::from_be_bytes(bytes[..8].try_into().expect("head length checked"));
    if sequence == 0 {
        return Err(BridgeStoreError::Invariant("authorization head sequence is zero").into());
    }
    Ok((
        sequence,
        bytes[8..].try_into().expect("head length checked"),
    ))
}

fn encode_high_water(generation: u64, enabled: bool, id: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(41);
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.push(u8::from(enabled));
    bytes.extend_from_slice(&id);
    bytes
}

fn decode_high_water(bytes: &[u8]) -> Result<(u64, bool, [u8; 32]), StoreError> {
    if bytes.len() != 41 || !matches!(bytes[8], 0 | 1) {
        return Err(
            BridgeStoreError::Invariant("authorization high-water has invalid encoding").into(),
        );
    }
    let generation = u64::from_be_bytes(bytes[..8].try_into().expect("high-water length checked"));
    if generation == 0 {
        return Err(
            BridgeStoreError::Invariant("authorization high-water generation is zero").into(),
        );
    }
    Ok((
        generation,
        bytes[8] == 1,
        bytes[9..].try_into().expect("high-water length checked"),
    ))
}

fn authorization_head_write(
    write: &redb::WriteTransaction,
) -> Result<Option<(u64, [u8; 32])>, StoreError> {
    write
        .open_table(BRIDGE_AUTHORIZATION_HEAD)?
        .get(AUTHORIZATION_HEAD_KEY)?
        .map(|value| decode_head(value.value()))
        .transpose()
}

fn authorization_high_water_write(
    write: &redb::WriteTransaction,
    key: [u8; 32],
) -> Result<Option<(u64, bool, [u8; 32])>, StoreError> {
    write
        .open_table(BRIDGE_AUTHORIZATION_HIGH_WATER)?
        .get(key.as_slice())?
        .map(|value| decode_high_water(value.value()))
        .transpose()
}

fn require_route_authorizations_current_write(
    write: &redb::WriteTransaction,
    ids: &[[u8; 32]],
) -> Result<(), StoreError> {
    for id in ids {
        let record = load_authorization_write(write, *id)?
            .ok_or(BridgeStoreError::RouteAuthorizationNotCurrent)?;
        let Some((generation, enabled, high_water_id)) =
            authorization_high_water_write(write, record.authorization_key)?
        else {
            return Err(BridgeStoreError::RouteAuthorizationNotCurrent.into());
        };
        if !enabled || high_water_id != *id || generation != record.generation {
            return Err(BridgeStoreError::RouteAuthorizationNotCurrent.into());
        }
    }
    Ok(())
}

fn active_route_key(origin: [u8; 32], scope: &Scope, epoch: u64) -> Result<Vec<u8>, StoreError> {
    if epoch == 0 {
        return Err(BridgeStoreError::Invalid("route epoch is zero").into());
    }
    let scope_len = u16::try_from(scope.as_str().len())
        .map_err(|_| BridgeStoreError::Invalid("scope length exceeds active-key encoding"))?;
    let mut key = Vec::with_capacity(42 + usize::from(scope_len));
    key.extend_from_slice(&origin);
    key.extend_from_slice(&scope_len.to_be_bytes());
    key.extend_from_slice(scope.as_str().as_bytes());
    key.extend_from_slice(&epoch.to_be_bytes());
    Ok(key)
}

fn decode_active_route_key(bytes: &[u8]) -> Result<([u8; 32], Scope, u64), StoreError> {
    if bytes.len() < 42 {
        return Err(BridgeStoreError::Invariant("active route key is truncated").into());
    }
    let origin = bytes[..32]
        .try_into()
        .expect("active route key length checked");
    let scope_len = usize::from(u16::from_be_bytes(
        bytes[32..34]
            .try_into()
            .expect("active route key length checked"),
    ));
    let expected = 42usize
        .checked_add(scope_len)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if bytes.len() != expected {
        return Err(BridgeStoreError::Invariant("active route key length is inconsistent").into());
    }
    let scope = std::str::from_utf8(&bytes[34..34 + scope_len])
        .map_err(|_| BridgeStoreError::Invariant("active route scope is not UTF-8"))?;
    let scope = Scope::new(scope.to_owned())
        .map_err(|_| BridgeStoreError::Invariant("active route scope is noncanonical"))?;
    let epoch = u64::from_be_bytes(
        bytes[34 + scope_len..]
            .try_into()
            .expect("active route key length checked"),
    );
    if epoch == 0 {
        return Err(BridgeStoreError::Invariant("active route epoch is zero").into());
    }
    Ok((origin, scope, epoch))
}

fn encode_authorization(record: &AuthorizationRecord) -> Result<Vec<u8>, StoreError> {
    record.validate()?;
    let mut bytes = Vec::with_capacity(188);
    bytes.extend_from_slice(AUTHORIZATION_RECORD_MAGIC);
    bytes.extend_from_slice(&RECORD_FORMAT.to_be_bytes());
    bytes.extend_from_slice(&record.authority_id);
    bytes.extend_from_slice(&record.control_signer);
    bytes.extend_from_slice(&record.control_sequence.to_be_bytes());
    match record.previous_control_id {
        Some(previous) => {
            bytes.push(1);
            bytes.extend_from_slice(&previous);
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&[0; 32]);
        }
    }
    bytes.extend_from_slice(&record.authorization_key);
    bytes.extend_from_slice(&record.generation.to_be_bytes());
    bytes.push(u8::from(record.enabled));
    Ok(bytes)
}

fn decode_authorization(
    envelope_id: [u8; 32],
    encoded: &[u8],
    exact_bytes: Vec<u8>,
) -> Result<AuthorizationRecord, StoreError> {
    let mut reader = Reader::new(encoded);
    if reader.take(8)? != AUTHORIZATION_RECORD_MAGIC || reader.u16()? != RECORD_FORMAT {
        return Err(BridgeStoreError::Invariant("authorization record format is invalid").into());
    }
    let authority_id = reader.id()?;
    let control_signer = reader.id()?;
    let control_sequence = reader.u64()?;
    let previous_present = reader.u8()?;
    let previous = reader.id()?;
    let previous_control_id = match previous_present {
        0 if previous == [0; 32] => None,
        1 => Some(previous),
        _ => {
            return Err(BridgeStoreError::Invariant(
                "authorization predecessor encoding is invalid",
            )
            .into());
        }
    };
    let authorization_key = reader.id()?;
    let generation = reader.u64()?;
    let enabled = match reader.u8()? {
        0 => false,
        1 => true,
        _ => {
            return Err(
                BridgeStoreError::Invariant("authorization enabled flag is invalid").into(),
            );
        }
    };
    reader.finish()?;
    let record = AuthorizationRecord {
        envelope_id,
        authority_id,
        control_signer,
        control_sequence,
        previous_control_id,
        authorization_key,
        generation,
        enabled,
        exact_bytes,
    };
    record.validate().map_err(|_| {
        StoreError::Bridge(BridgeStoreError::Invariant(
            "authorization row failed structural validation",
        ))
    })?;
    Ok(record)
}

fn encode_route(record: &EventRouteRecord) -> Result<Vec<u8>, StoreError> {
    record.validate()?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ROUTE_RECORD_MAGIC);
    bytes.extend_from_slice(&RECORD_FORMAT.to_be_bytes());
    bytes.extend_from_slice(&record.bridge_route_id);
    bytes.extend_from_slice(&record.origin_envelope_id);
    bytes.extend_from_slice(&record.source_item_id);
    bytes.extend_from_slice(&record.publisher);
    push_text(&mut bytes, record.origin_scope.as_str())?;
    bytes.extend_from_slice(&record.origin_route_epoch.to_be_bytes());
    push_text(&mut bytes, record.current_scope.as_str())?;
    bytes.extend_from_slice(&record.current_route_epoch.to_be_bytes());
    push_text(&mut bytes, record.topic.as_str())?;
    bytes.push(record.priority as u8);
    bytes.extend_from_slice(&record.event_sequence.to_be_bytes());
    match record.ttl_ms {
        Some(ttl) => {
            bytes.push(1);
            bytes.extend_from_slice(&ttl.to_be_bytes());
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&0u64.to_be_bytes());
        }
    }
    bytes.push(record.hop_count);
    for id in &record.authorization_envelope_ids {
        bytes.extend_from_slice(id);
    }
    Ok(bytes)
}

fn decode_route(
    wrapper_envelope_id: [u8; 32],
    encoded: &[u8],
    exact_wrapper_bytes: Arc<[u8]>,
    exact_source_bytes: Arc<[u8]>,
) -> Result<EventRouteRecord, StoreError> {
    let mut reader = Reader::new(encoded);
    if reader.take(8)? != ROUTE_RECORD_MAGIC || reader.u16()? != RECORD_FORMAT {
        return Err(BridgeStoreError::Invariant("Event route record format is invalid").into());
    }
    let bridge_route_id = reader.id()?;
    let origin_envelope_id = reader.id()?;
    let source_item_id = reader.id()?;
    let publisher = reader.id()?;
    let origin_scope = Scope::new(reader.text()?.to_owned())
        .map_err(|_| BridgeStoreError::Invariant("origin scope is noncanonical"))?;
    let origin_route_epoch = reader.u64()?;
    let current_scope = Scope::new(reader.text()?.to_owned())
        .map_err(|_| BridgeStoreError::Invariant("current scope is noncanonical"))?;
    let current_route_epoch = reader.u64()?;
    let topic = Topic::new(reader.text()?.to_owned())
        .map_err(|_| BridgeStoreError::Invariant("route topic is noncanonical"))?;
    let priority = Priority::from_wire(reader.u8()?)
        .ok_or(BridgeStoreError::Invariant("route priority is invalid"))?;
    let event_sequence = reader.u64()?;
    let ttl_present = reader.u8()?;
    let ttl_value = reader.u64()?;
    let ttl_ms = match (ttl_present, ttl_value) {
        (0, 0) => None,
        (1, value) => Some(value),
        _ => return Err(BridgeStoreError::Invariant("route TTL encoding is invalid").into()),
    };
    let hop_count = reader.u8()?;
    let mut authorization_envelope_ids = Vec::with_capacity(usize::from(hop_count));
    for _ in 0..hop_count {
        authorization_envelope_ids.push(reader.id()?);
    }
    reader.finish()?;
    let record = EventRouteRecord {
        wrapper_envelope_id,
        bridge_route_id,
        origin_envelope_id,
        source_item_id,
        publisher,
        origin_scope,
        origin_route_epoch,
        current_scope,
        current_route_epoch,
        topic,
        priority,
        event_sequence,
        ttl_ms,
        hop_count,
        authorization_envelope_ids,
        exact_wrapper_bytes,
        exact_source_bytes,
    };
    record.validate().map_err(|_| {
        StoreError::Bridge(BridgeStoreError::Invariant(
            "Event route row failed structural validation",
        ))
    })?;
    Ok(record)
}

fn push_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), StoreError> {
    let length =
        u16::try_from(value.len()).map_err(|_| BridgeStoreError::Invalid("name is too long"))?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, length: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BridgeStoreError::Invariant("bridge record is truncated"))?;
        self.offset = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, StoreError> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().expect("reader length"),
        ))
    }
    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().expect("reader length"),
        ))
    }
    fn id(&mut self) -> Result<[u8; 32], StoreError> {
        Ok(self.take(32)?.try_into().expect("reader length"))
    }
    fn text(&mut self) -> Result<&'a str, StoreError> {
        let length = usize::from(self.u16()?);
        std::str::from_utf8(self.take(length)?)
            .map_err(|_| BridgeStoreError::Invariant("bridge record name is not UTF-8").into())
    }
    fn finish(self) -> Result<(), StoreError> {
        if self.offset != self.bytes.len() {
            return Err(BridgeStoreError::Invariant("bridge record has trailing bytes").into());
        }
        Ok(())
    }
}

fn load_authorization_read(
    read: &redb::ReadTransaction,
    id: [u8; 32],
) -> Result<Option<AuthorizationRecord>, StoreError> {
    let encoded = read
        .open_table(BRIDGE_AUTHORIZATIONS)?
        .get(id.as_slice())?
        .map(|v| v.value().to_vec());
    let exact = read
        .open_table(BRIDGE_AUTHORIZATION_BYTES)?
        .get(id.as_slice())?
        .map(|v| v.value().to_vec());
    match (encoded, exact) {
        (None, None) => Ok(None),
        (Some(encoded), Some(exact)) => decode_authorization(id, &encoded, exact).map(Some),
        _ => Err(
            BridgeStoreError::Invariant("authorization metadata and exact bytes are partial")
                .into(),
        ),
    }
}

fn load_authorization_write(
    write: &redb::WriteTransaction,
    id: [u8; 32],
) -> Result<Option<AuthorizationRecord>, StoreError> {
    let encoded = write
        .open_table(BRIDGE_AUTHORIZATIONS)?
        .get(id.as_slice())?
        .map(|v| v.value().to_vec());
    let exact = write
        .open_table(BRIDGE_AUTHORIZATION_BYTES)?
        .get(id.as_slice())?
        .map(|v| v.value().to_vec());
    match (encoded, exact) {
        (None, None) => Ok(None),
        (Some(encoded), Some(exact)) => decode_authorization(id, &encoded, exact).map(Some),
        _ => Err(
            BridgeStoreError::Invariant("authorization metadata and exact bytes are partial")
                .into(),
        ),
    }
}

fn load_route_read(
    read: &redb::ReadTransaction,
    id: [u8; 32],
) -> Result<Option<EventRouteRecord>, StoreError> {
    load_route_read_cached(read, id, &mut BTreeMap::new())
}

fn load_route_read_cached(
    read: &redb::ReadTransaction,
    id: [u8; 32],
    exact_sources: &mut BTreeMap<[u8; 32], Arc<[u8]>>,
) -> Result<Option<EventRouteRecord>, StoreError> {
    let encoded = read
        .open_table(BRIDGE_EVENT_ROUTES)?
        .get(id.as_slice())?
        .map(|v| v.value().to_vec());
    let wrapper = read
        .open_table(BRIDGE_EVENT_WRAPPER_BYTES)?
        .get(id.as_slice())?
        .map(|v| Arc::<[u8]>::from(v.value()));
    match (encoded, wrapper) {
        (None, None) => Ok(None),
        (Some(encoded), Some(wrapper)) => {
            let mut reader = Reader::new(&encoded);
            if reader.take(8)? != ROUTE_RECORD_MAGIC || reader.u16()? != RECORD_FORMAT {
                return Err(
                    BridgeStoreError::Invariant("Event route record format is invalid").into(),
                );
            }
            let _ = reader.id()?;
            let origin = reader.id()?;
            let source = match exact_sources.get(&origin) {
                Some(source) => Arc::clone(source),
                None => {
                    let source = read
                        .open_table(BRIDGE_EVENT_SOURCES)?
                        .get(origin.as_slice())?
                        .map(|v| Arc::<[u8]>::from(v.value()))
                        .ok_or(BridgeStoreError::Invariant("route source is missing"))?;
                    exact_sources.insert(origin, Arc::clone(&source));
                    source
                }
            };
            decode_route(id, &encoded, wrapper, source).map(Some)
        }
        _ => Err(
            BridgeStoreError::Invariant("route metadata and exact wrapper bytes are partial")
                .into(),
        ),
    }
}

fn load_route_write(
    write: &redb::WriteTransaction,
    id: [u8; 32],
) -> Result<Option<EventRouteRecord>, StoreError> {
    let encoded = write
        .open_table(BRIDGE_EVENT_ROUTES)?
        .get(id.as_slice())?
        .map(|v| v.value().to_vec());
    let wrapper = write
        .open_table(BRIDGE_EVENT_WRAPPER_BYTES)?
        .get(id.as_slice())?
        .map(|v| Arc::<[u8]>::from(v.value()));
    match (encoded, wrapper) {
        (None, None) => Ok(None),
        (Some(encoded), Some(wrapper)) => {
            let mut reader = Reader::new(&encoded);
            if reader.take(8)? != ROUTE_RECORD_MAGIC || reader.u16()? != RECORD_FORMAT {
                return Err(
                    BridgeStoreError::Invariant("Event route record format is invalid").into(),
                );
            }
            let _ = reader.id()?;
            let origin = reader.id()?;
            let source = write
                .open_table(BRIDGE_EVENT_SOURCES)?
                .get(origin.as_slice())?
                .map(|v| Arc::<[u8]>::from(v.value()))
                .ok_or(BridgeStoreError::Invariant("route source is missing"))?;
            decode_route(id, &encoded, wrapper, source).map(Some)
        }
        _ => Err(
            BridgeStoreError::Invariant("route metadata and exact wrapper bytes are partial")
                .into(),
        ),
    }
}

#[derive(Default)]
struct BridgeAuditSnapshot {
    authorizations: BTreeMap<Vec<u8>, Vec<u8>>,
    authorization_bytes: BTreeMap<Vec<u8>, Vec<u8>>,
    sequence: BTreeMap<u64, Vec<u8>>,
    head: BTreeMap<Vec<u8>, Vec<u8>>,
    high_water: BTreeMap<Vec<u8>, Vec<u8>>,
    sources: BTreeMap<Vec<u8>, Arc<[u8]>>,
    routes: BTreeMap<Vec<u8>, Vec<u8>>,
    wrappers: BTreeMap<Vec<u8>, Arc<[u8]>>,
    route_ids: BTreeMap<Vec<u8>, Vec<u8>>,
    active: BTreeMap<Vec<u8>, Vec<u8>>,
}

fn collect_bytes_table<T>(table: &T) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, StoreError>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let mut rows = BTreeMap::new();
    for row in table.iter()? {
        let (key, value) = row?;
        rows.insert(key.value().to_vec(), value.value().to_vec());
    }
    Ok(rows)
}

fn collect_sequence_table<T>(table: &T) -> Result<BTreeMap<u64, Vec<u8>>, StoreError>
where
    T: ReadableTable<u64, &'static [u8]>,
{
    let mut rows = BTreeMap::new();
    for row in table.iter()? {
        let (key, value) = row?;
        rows.insert(key.value(), value.value().to_vec());
    }
    Ok(rows)
}

fn collect_shared_bytes_table<T>(table: &T) -> Result<BTreeMap<Vec<u8>, Arc<[u8]>>, StoreError>
where
    T: ReadableTable<&'static [u8], &'static [u8]>,
{
    let mut rows = BTreeMap::new();
    for row in table.iter()? {
        let (key, value) = row?;
        rows.insert(key.value().to_vec(), Arc::from(value.value()));
    }
    Ok(rows)
}

fn collect_bridge_snapshot_read(
    read: &redb::ReadTransaction,
) -> Result<BridgeAuditSnapshot, StoreError> {
    Ok(BridgeAuditSnapshot {
        authorizations: collect_bytes_table(&read.open_table(BRIDGE_AUTHORIZATIONS)?)?,
        authorization_bytes: collect_bytes_table(&read.open_table(BRIDGE_AUTHORIZATION_BYTES)?)?,
        sequence: collect_sequence_table(&read.open_table(BRIDGE_AUTHORIZATION_SEQUENCE)?)?,
        head: collect_bytes_table(&read.open_table(BRIDGE_AUTHORIZATION_HEAD)?)?,
        high_water: collect_bytes_table(&read.open_table(BRIDGE_AUTHORIZATION_HIGH_WATER)?)?,
        sources: collect_shared_bytes_table(&read.open_table(BRIDGE_EVENT_SOURCES)?)?,
        routes: collect_bytes_table(&read.open_table(BRIDGE_EVENT_ROUTES)?)?,
        wrappers: collect_shared_bytes_table(&read.open_table(BRIDGE_EVENT_WRAPPER_BYTES)?)?,
        route_ids: collect_bytes_table(&read.open_table(BRIDGE_EVENT_ROUTE_IDS)?)?,
        active: collect_bytes_table(&read.open_table(BRIDGE_EVENT_ACTIVE_ROUTES)?)?,
    })
}

fn collect_bridge_snapshot_write(
    write: &redb::WriteTransaction,
) -> Result<BridgeAuditSnapshot, StoreError> {
    Ok(BridgeAuditSnapshot {
        authorizations: collect_bytes_table(&write.open_table(BRIDGE_AUTHORIZATIONS)?)?,
        authorization_bytes: collect_bytes_table(&write.open_table(BRIDGE_AUTHORIZATION_BYTES)?)?,
        sequence: collect_sequence_table(&write.open_table(BRIDGE_AUTHORIZATION_SEQUENCE)?)?,
        head: collect_bytes_table(&write.open_table(BRIDGE_AUTHORIZATION_HEAD)?)?,
        high_water: collect_bytes_table(&write.open_table(BRIDGE_AUTHORIZATION_HIGH_WATER)?)?,
        sources: collect_shared_bytes_table(&write.open_table(BRIDGE_EVENT_SOURCES)?)?,
        routes: collect_bytes_table(&write.open_table(BRIDGE_EVENT_ROUTES)?)?,
        wrappers: collect_shared_bytes_table(&write.open_table(BRIDGE_EVENT_WRAPPER_BYTES)?)?,
        route_ids: collect_bytes_table(&write.open_table(BRIDGE_EVENT_ROUTE_IDS)?)?,
        active: collect_bytes_table(&write.open_table(BRIDGE_EVENT_ACTIVE_ROUTES)?)?,
    })
}

fn validate_bridge_snapshot(
    snapshot: &BridgeAuditSnapshot,
    mission_authority: Option<NodeId>,
) -> Result<BridgeStoreStats, StoreError> {
    if snapshot.authorizations.len() != snapshot.authorization_bytes.len()
        || snapshot.authorizations.len() != snapshot.sequence.len()
    {
        return Err(BridgeStoreError::Invariant("authorization table cardinalities differ").into());
    }
    let mut decoded_authorizations = BTreeMap::new();
    let mut expected_high_water = BTreeMap::<Vec<u8>, (u64, bool, [u8; 32])>::new();
    let mut previous = None;
    let mut expected_sequence = 1u64;
    let mut authorization_bytes = 0u64;
    for (sequence, id_bytes) in &snapshot.sequence {
        if *sequence != expected_sequence {
            return Err(BridgeStoreError::Invariant(
                "authorization chain is not contiguous from one",
            )
            .into());
        }
        let id = parse_id(id_bytes)?;
        let encoded = snapshot
            .authorizations
            .get(id_bytes)
            .ok_or(BridgeStoreError::Invariant(
                "authorization sequence row has no record",
            ))?;
        let exact =
            snapshot
                .authorization_bytes
                .get(id_bytes)
                .ok_or(BridgeStoreError::Invariant(
                    "authorization record has no exact bytes",
                ))?;
        let record = decode_authorization(id, encoded, exact.clone())?;
        let authority = mission_authority.ok_or(BridgeStoreError::Invariant(
            "unbound store contains bridge state",
        ))?;
        if record.authority_id != authority {
            return Err(StoreError::MissionAuthorityMismatch {
                bound: authority,
                received: record.authority_id,
            });
        }
        if record.control_sequence != *sequence || record.previous_control_id != previous {
            return Err(BridgeStoreError::Invariant(
                "authorization predecessor chain differs from sequence index",
            )
            .into());
        }
        if let Some((generation, _, _)) =
            expected_high_water.get(record.authorization_key.as_slice())
            && record.generation <= *generation
        {
            return Err(BridgeStoreError::Invariant(
                "authorization generation high-water is not strictly increasing",
            )
            .into());
        }
        expected_high_water.insert(
            record.authorization_key.to_vec(),
            (record.generation, record.enabled, record.envelope_id),
        );
        authorization_bytes = authorization_bytes
            .checked_add(usize_to_u64(encoded.len())?)
            .and_then(|value| value.checked_add(usize_to_u64(exact.len()).ok()?))
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        previous = Some(id);
        decoded_authorizations.insert(id, record);
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
    }
    let expected_head = previous.map(|id| (expected_sequence - 1, id));
    match (expected_head, snapshot.head.get(AUTHORIZATION_HEAD_KEY)) {
        (None, None) => {}
        (Some(expected), Some(value)) if decode_head(value)? == expected => {}
        _ => {
            return Err(BridgeStoreError::Invariant(
                "authorization head differs from contiguous chain",
            )
            .into());
        }
    }
    if snapshot.head.len() > usize::from(expected_head.is_some()) {
        return Err(
            BridgeStoreError::Invariant("authorization head contains an unknown key").into(),
        );
    }
    if snapshot.high_water.len() != expected_high_water.len() {
        return Err(
            BridgeStoreError::Invariant("authorization high-water cardinality differs").into(),
        );
    }
    for (key, expected) in expected_high_water {
        if snapshot
            .high_water
            .get(&key)
            .map(|bytes| decode_high_water(bytes))
            .transpose()?
            != Some(expected)
        {
            return Err(BridgeStoreError::Invariant(
                "authorization high-water differs from chain history",
            )
            .into());
        }
    }

    let mut source_bytes = 0u64;
    for (id, bytes) in &snapshot.sources {
        if parse_id(id)? != digest(bytes) || bytes.is_empty() {
            return Err(
                BridgeStoreError::Invariant("bridge source exact identity is invalid").into(),
            );
        }
        source_bytes = source_bytes
            .checked_add(usize_to_u64(bytes.len())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    }
    if snapshot.routes.len() != snapshot.wrappers.len()
        || snapshot.routes.len() != snapshot.route_ids.len()
    {
        return Err(BridgeStoreError::Invariant("route table cardinalities differ").into());
    }
    let mut decoded_routes = BTreeMap::new();
    let mut route_bytes = 0u64;
    for (wrapper_key, encoded) in &snapshot.routes {
        let wrapper_id = parse_id(wrapper_key)?;
        let wrapper = snapshot
            .wrappers
            .get(wrapper_key)
            .ok_or(BridgeStoreError::Invariant(
                "route record has no exact wrapper bytes",
            ))?;
        let mut prefix = Reader::new(encoded);
        if prefix.take(8)? != ROUTE_RECORD_MAGIC || prefix.u16()? != RECORD_FORMAT {
            return Err(BridgeStoreError::Invariant("route record format is invalid").into());
        }
        let route_id = prefix.id()?;
        let origin_id = prefix.id()?;
        let source =
            snapshot
                .sources
                .get(origin_id.as_slice())
                .ok_or(BridgeStoreError::Invariant(
                    "route record has no exact source bytes",
                ))?;
        let record = decode_route(wrapper_id, encoded, wrapper.clone(), source.clone())?;
        if snapshot
            .route_ids
            .get(route_id.as_slice())
            .map(Vec::as_slice)
            != Some(wrapper_key.as_slice())
        {
            return Err(BridgeStoreError::Invariant(
                "route-ID inverse index differs from route record",
            )
            .into());
        }
        for authorization in &record.authorization_envelope_ids {
            if !decoded_authorizations.contains_key(authorization) {
                return Err(BridgeStoreError::Invariant(
                    "route references a missing authorization",
                )
                .into());
            }
        }
        route_bytes = route_bytes
            .checked_add(usize_to_u64(encoded.len())?)
            .and_then(|value| value.checked_add(usize_to_u64(wrapper.len()).ok()?))
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        decoded_routes.insert(wrapper_id, record);
    }
    for (route_id, wrapper_id) in &snapshot.route_ids {
        parse_id(route_id)?;
        if !snapshot.routes.contains_key(wrapper_id) {
            return Err(
                BridgeStoreError::Invariant("route-ID index points to a missing route").into(),
            );
        }
    }
    for source_id in snapshot.sources.keys() {
        let source_id = parse_id(source_id)?;
        if !decoded_routes
            .values()
            .any(|route| route.origin_envelope_id == source_id)
        {
            return Err(
                BridgeStoreError::Invariant("bridge source has no referencing route").into(),
            );
        }
    }
    for (active_key, wrapper_id) in &snapshot.active {
        let (origin, scope, epoch) = decode_active_route_key(active_key)?;
        let wrapper = parse_id(wrapper_id)?;
        let route = decoded_routes
            .get(&wrapper)
            .ok_or(BridgeStoreError::Invariant(
                "active route points to a missing wrapper",
            ))?;
        if route.origin_envelope_id != origin
            || route.current_scope != scope
            || route.current_route_epoch != epoch
        {
            return Err(BridgeStoreError::Invariant(
                "active route key differs from route metadata",
            )
            .into());
        }
        for id in &route.authorization_envelope_ids {
            let authorization =
                decoded_authorizations
                    .get(id)
                    .ok_or(BridgeStoreError::Invariant(
                        "active route authorization is missing",
                    ))?;
            let high_water = snapshot
                .high_water
                .get(authorization.authorization_key.as_slice())
                .ok_or(BridgeStoreError::Invariant(
                    "active route authorization high-water is missing",
                ))?;
            let (generation, enabled, high_water_id) = decode_high_water(high_water)?;
            if !enabled || high_water_id != *id || generation != authorization.generation {
                return Err(BridgeStoreError::Invariant(
                    "active route references a disabled or superseded authorization",
                )
                .into());
            }
        }
    }
    Ok(BridgeStoreStats {
        authorizations: u64::try_from(snapshot.authorizations.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        authorization_bytes,
        event_sources: u64::try_from(snapshot.sources.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        event_source_bytes: source_bytes,
        event_routes: u64::try_from(snapshot.routes.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        event_route_bytes: route_bytes,
        active_routes: u64::try_from(snapshot.active.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        authorization_head_sequence: expected_head.map_or(0, |(sequence, _)| sequence),
    })
}

fn bridge_table_names() -> [&'static str; 10] {
    [
        BRIDGE_AUTHORIZATIONS.name(),
        BRIDGE_AUTHORIZATION_BYTES.name(),
        BRIDGE_AUTHORIZATION_SEQUENCE.name(),
        BRIDGE_AUTHORIZATION_HEAD.name(),
        BRIDGE_AUTHORIZATION_HIGH_WATER.name(),
        BRIDGE_EVENT_SOURCES.name(),
        BRIDGE_EVENT_ROUTES.name(),
        BRIDGE_EVENT_WRAPPER_BYTES.name(),
        BRIDGE_EVENT_ROUTE_IDS.name(),
        BRIDGE_EVENT_ACTIVE_ROUTES.name(),
    ]
}

pub(crate) fn inspect_bridge_tables_read_transaction(
    read: &redb::ReadTransaction,
    mission_authority: Option<NodeId>,
) -> Result<BridgeStoreStats, StoreError> {
    let names = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let present = bridge_table_names()
        .into_iter()
        .filter(|name| names.contains(*name))
        .count();
    if present == 0 {
        let metadata = read.open_table(METADATA)?;
        for field in bridge_counter_fields() {
            if metadata.get(field)?.is_some_and(|value| value.value() != 0) {
                return Err(BridgeStoreError::Invariant(
                    "bridge accounting exists without its schema group",
                )
                .into());
            }
        }
        return Ok(BridgeStoreStats::default());
    }
    if present != bridge_table_names().len() {
        return Err(BridgeStoreError::Invariant("bridge schema group is partial").into());
    }
    let stats = validate_bridge_snapshot(&collect_bridge_snapshot_read(read)?, mission_authority)?;
    let metadata = read.open_table(METADATA)?;
    for (field, reconstructed) in bridge_counter_values(stats) {
        let durable = metadata
            .get(field)?
            .ok_or(StoreError::MissingAccountingMetadata { field })?
            .value();
        if durable != reconstructed {
            return Err(StoreError::AccountingMismatch {
                field,
                durable,
                reconstructed,
            });
        }
    }
    Ok(stats)
}

pub(crate) fn audit_bridge_tables_write(
    write: &redb::WriteTransaction,
    mission_authority: Option<NodeId>,
    limits: StoreLimits,
    clear_process_liveness: bool,
) -> Result<BridgeStoreStats, StoreError> {
    let snapshot = collect_bridge_snapshot_write(write)?;
    let mut stats = validate_bridge_snapshot(&snapshot, mission_authority)?;
    {
        let mut metadata = write.open_table(METADATA)?;
        for (field, reconstructed) in bridge_counter_values(stats) {
            super::audit_or_initialize_counter(&mut metadata, field, reconstructed)?;
        }
        require_aggregate_capacity(&metadata, limits, 0, 0)?;
    }
    if clear_process_liveness {
        clear_active_routes_write(write)?;
        stats.active_routes = 0;
    }
    Ok(stats)
}

fn bridge_counter_fields() -> [&'static str; 6] {
    [
        BRIDGE_AUTHORIZATION_ITEM_COUNT,
        BRIDGE_AUTHORIZATION_TOTAL_BYTES,
        BRIDGE_EVENT_SOURCE_ITEM_COUNT,
        BRIDGE_EVENT_SOURCE_TOTAL_BYTES,
        BRIDGE_EVENT_ROUTE_ITEM_COUNT,
        BRIDGE_EVENT_ROUTE_TOTAL_BYTES,
    ]
}

fn bridge_counter_values(stats: BridgeStoreStats) -> [(&'static str, u64); 6] {
    [
        (BRIDGE_AUTHORIZATION_ITEM_COUNT, stats.authorizations),
        (BRIDGE_AUTHORIZATION_TOTAL_BYTES, stats.authorization_bytes),
        (BRIDGE_EVENT_SOURCE_ITEM_COUNT, stats.event_sources),
        (BRIDGE_EVENT_SOURCE_TOTAL_BYTES, stats.event_source_bytes),
        (BRIDGE_EVENT_ROUTE_ITEM_COUNT, stats.event_routes),
        (BRIDGE_EVENT_ROUTE_TOTAL_BYTES, stats.event_route_bytes),
    ]
}

fn clear_active_routes_write(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let keys = {
        let table = write.open_table(BRIDGE_EVENT_ACTIVE_ROUTES)?;
        table
            .iter()?
            .map(|row| row.map(|(key, _)| key.value().to_vec()))
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut table = write.open_table(BRIDGE_EVENT_ACTIVE_ROUTES)?;
    for key in keys {
        table.remove(key.as_slice())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use aster_mesh::engine::EnvelopeHeader;
    use aster_mesh::{
        BridgeAuthorizationLink, CausalStamp, DataClass, Dot, ProvisioningAccess,
        ReferenceEnvelopeSealer, ReferenceProvisioner, SelectedBridgeAuthorizationPolicy,
        SelectedBridgeNarrowingPolicy, SelectedEventBridgeAdapter, VersionVector,
    };

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestFile(PathBuf);
    impl TestFile {
        fn new(name: &str) -> Self {
            let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "aster-redb-bridge-{name}-{}-{sequence}.redb",
                std::process::id()
            )))
        }
    }
    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn auth(
        authority: NodeId,
        sequence: u64,
        previous: Option<[u8; 32]>,
        key: [u8; 32],
        generation: u64,
        enabled: bool,
        byte: u8,
    ) -> AuthorizationRecord {
        let exact_bytes = vec![byte; 64];
        AuthorizationRecord {
            envelope_id: digest(&exact_bytes),
            authority_id: authority,
            control_signer: [0x55; 32],
            control_sequence: sequence,
            previous_control_id: previous,
            authorization_key: key,
            generation,
            enabled,
            exact_bytes,
        }
    }

    fn route(
        authorization: [u8; 32],
        source_byte: u8,
        wrapper_byte: u8,
        route_byte: u8,
        hops: u8,
    ) -> EventRouteRecord {
        let exact_source_bytes = vec![source_byte; 96];
        let exact_wrapper_bytes = vec![wrapper_byte; 112];
        EventRouteRecord {
            wrapper_envelope_id: digest(&exact_wrapper_bytes),
            bridge_route_id: [route_byte; 32],
            origin_envelope_id: digest(&exact_source_bytes),
            source_item_id: [0x33; 32],
            publisher: [0x44; 32],
            origin_scope: Scope::new("demo/alpha").expect("scope"),
            origin_route_epoch: 1,
            current_scope: Scope::new("demo/root").expect("scope"),
            current_route_epoch: 2,
            topic: Topic::new("events").expect("topic"),
            priority: Priority::Priority,
            event_sequence: 7,
            ttl_ms: Some(60_000),
            hop_count: hops,
            authorization_envelope_ids: vec![authorization; usize::from(hops)],
            exact_wrapper_bytes: Arc::from(exact_wrapper_bytes),
            exact_source_bytes: Arc::from(exact_source_bytes),
        }
    }

    #[test]
    fn contiguous_authorization_high_water_and_disable_are_atomic() {
        let file = TestFile::new("authorization");
        let authority = [0x11; 32];
        let store = Store::open_for_mission(&file.0, authority).expect("open");
        let first = auth(authority, 1, None, [0x77; 32], 1, true, 1);
        assert!(matches!(
            store.commit_bridge_authorization_record(&first),
            Ok(SelectedBridgeAuthorizationCommitOutcome::Applied { sequence: 1, .. })
        ));
        assert!(matches!(
            store.commit_bridge_authorization_record(&first),
            Ok(SelectedBridgeAuthorizationCommitOutcome::Duplicate { sequence: 1, .. })
        ));
        let active_route = route(first.envelope_id, 51, 52, 53, 1);
        store
            .commit_bridge_event_route_record(&active_route)
            .expect("active route");

        let rollback = auth(
            authority,
            2,
            Some(first.envelope_id),
            [0x77; 32],
            1,
            false,
            2,
        );
        assert!(matches!(
            store.commit_bridge_authorization_record(&rollback),
            Err(StoreError::Bridge(
                BridgeStoreError::AuthorizationGenerationRollback { .. }
            ))
        ));
        assert_eq!(
            store
                .selected_bridge_stats()
                .expect("stats")
                .authorization_head_sequence,
            1
        );
        assert!(
            store
                .active_selected_bridge_event_route_candidate(
                    active_route.origin_envelope_id,
                    &active_route.current_scope,
                    active_route.current_route_epoch,
                )
                .expect("rollback keeps active route")
                .is_some()
        );

        let disable = auth(
            authority,
            2,
            Some(first.envelope_id),
            [0x77; 32],
            2,
            false,
            3,
        );
        store
            .commit_bridge_authorization_record(&disable)
            .expect("disable");
        let candidates = store
            .selected_bridge_authorization_candidates(8)
            .expect("candidates");
        assert_eq!(candidates.len(), 2);
        assert!(!candidates[1].is_enabled());
        assert_eq!(candidates[1].exact_bytes(), disable.exact_bytes);
        assert!(
            store
                .active_selected_bridge_event_route_candidate(
                    active_route.origin_envelope_id,
                    &active_route.current_scope,
                    active_route.current_route_epoch,
                )
                .expect("disable clears active route")
                .is_none()
        );
    }

    #[test]
    fn route_commit_deduplicates_source_and_selects_deterministic_rank() {
        let file = TestFile::new("routes");
        let authority = [0x12; 32];
        let store = Store::open_for_mission(&file.0, authority).expect("open");
        let control = auth(authority, 1, None, [0x70; 32], 1, true, 4);
        store
            .commit_bridge_authorization_record(&control)
            .expect("control");

        let longer = route(control.envelope_id, 8, 9, 9, 2);
        // Unit fixtures repeat one authorization solely to exercise rank length;
        // the production capability requires one exact authorization per hop.
        let mut longer = longer;
        longer.authorization_envelope_ids = vec![control.envelope_id, control.envelope_id];
        // Internal validation rejects duplicate hop authorization IDs, so use a
        // second independent authorization chain link/key for the second hop.
        let second = auth(
            authority,
            2,
            Some(control.envelope_id),
            [0x71; 32],
            1,
            true,
            5,
        );
        store
            .commit_bridge_authorization_record(&second)
            .expect("second control");
        longer.authorization_envelope_ids[1] = second.envelope_id;
        store
            .commit_bridge_event_route_record(&longer)
            .expect("long route");

        let shorter = route(control.envelope_id, 8, 10, 8, 1);
        assert!(matches!(
            store.commit_bridge_event_route_record(&shorter),
            Ok(SelectedBridgeEventRouteCommitOutcome::Active {
                replaced: Some(_),
                ..
            })
        ));
        let stats = store.selected_bridge_stats().expect("stats");
        assert_eq!(stats.event_sources, 1);
        assert_eq!(stats.event_routes, 2);
        let active = store
            .active_selected_bridge_event_route_candidate(
                shorter.origin_envelope_id,
                &shorter.current_scope,
                shorter.current_route_epoch,
            )
            .expect("active")
            .expect("route");
        assert_eq!(active.wrapper_envelope_id(), shorter.wrapper_envelope_id);
        assert_eq!(
            active.exact_source_bytes(),
            shorter.exact_source_bytes.as_ref()
        );
    }

    #[test]
    fn reopen_keeps_candidates_but_requires_fresh_promotion_for_active_route() {
        let file = TestFile::new("reopen");
        let authority = [0x13; 32];
        let control = auth(authority, 1, None, [0x72; 32], 1, true, 6);
        let candidate = route(control.envelope_id, 11, 12, 7, 1);
        {
            let store = Store::open_for_mission(&file.0, authority).expect("open");
            store
                .commit_bridge_authorization_record(&control)
                .expect("control");
            store
                .commit_bridge_event_route_record(&candidate)
                .expect("route");
            assert!(
                store
                    .active_selected_bridge_event_route_candidate(
                        candidate.origin_envelope_id,
                        &candidate.current_scope,
                        candidate.current_route_epoch
                    )
                    .expect("active")
                    .is_some()
            );
        }
        let store = Store::open_for_mission(&file.0, authority).expect("reopen");
        assert!(
            store
                .active_selected_bridge_event_route_candidate(
                    candidate.origin_envelope_id,
                    &candidate.current_scope,
                    candidate.current_route_epoch
                )
                .expect("inactive after restart")
                .is_none()
        );
        assert_eq!(
            store
                .selected_bridge_event_route_candidates(8)
                .expect("candidates")
                .len(),
            1
        );
        assert!(matches!(
            store.commit_bridge_event_route_record(&candidate),
            Ok(SelectedBridgeEventRouteCommitOutcome::Active { replaced: None, .. })
        ));
    }

    #[test]
    fn ordinary_reserve_rejection_rolls_back_and_remains_reopenable() {
        let file = TestFile::new("quota");
        let authority = [0x14; 32];
        let limits = StoreLimits::new(
            crate::MAX_CONTROL_ITEMS + crate::custody::CUSTODY_EMERGENCY_ITEM_RESERVE + 1,
            crate::MAX_CONTROL_BYTES + crate::custody::CUSTODY_EMERGENCY_BYTE_RESERVE + 1_024,
        )
        .expect("limits");
        let store = Store::open_with_limits_for_mission(&file.0, limits, authority).expect("open");
        let control = auth(authority, 1, None, [0x73; 32], 1, true, 7);
        store
            .commit_bridge_authorization_record(&control)
            .expect("control");
        let candidate = route(control.envelope_id, 13, 14, 6, 1);
        assert!(matches!(
            store.commit_bridge_event_route_record(&candidate),
            Err(StoreError::ItemLimitExceeded { .. })
        ));
        let stats = store.selected_bridge_stats().expect("stats");
        assert_eq!(stats.authorizations, 1);
        assert_eq!(stats.event_sources, 0);
        assert_eq!(stats.event_routes, 0);
        drop(store);
        let reopened = Store::open_with_limits_for_mission(&file.0, limits, authority)
            .expect("reserve-aware state reopens");
        assert_eq!(
            reopened
                .selected_bridge_stats()
                .expect("reopened stats")
                .authorizations,
            1
        );
    }

    #[test]
    fn open_audit_rejects_exact_source_corruption() {
        let file = TestFile::new("audit");
        let authority = [0x15; 32];
        let control = auth(authority, 1, None, [0x74; 32], 1, true, 8);
        let candidate = route(control.envelope_id, 15, 16, 5, 1);
        {
            let store = Store::open_for_mission(&file.0, authority).expect("open");
            store
                .commit_bridge_authorization_record(&control)
                .expect("control");
            store
                .commit_bridge_event_route_record(&candidate)
                .expect("route");
            let write = store.database.begin_write().expect("write");
            write
                .open_table(BRIDGE_EVENT_SOURCES)
                .expect("sources")
                .insert(
                    candidate.origin_envelope_id.as_slice(),
                    b"corrupt".as_slice(),
                )
                .expect("corrupt");
            write.commit().expect("commit corruption");
        }
        assert!(matches!(
            Store::open_for_mission(&file.0, authority),
            Err(StoreError::Bridge(BridgeStoreError::Invariant(_)))
        ));
    }

    #[test]
    fn candidate_pages_reach_every_authorization_and_route() {
        let file = TestFile::new("candidate-pages");
        let authority = [0x16; 32];
        let store = Store::open_for_mission(&file.0, authority).expect("open");
        let first = auth(authority, 1, None, [0x81; 32], 1, true, 21);
        let second = auth(
            authority,
            2,
            Some(first.envelope_id),
            [0x82; 32],
            1,
            true,
            22,
        );
        let third = auth(
            authority,
            3,
            Some(second.envelope_id),
            [0x83; 32],
            1,
            true,
            23,
        );
        for control in [&first, &second, &third] {
            store
                .commit_bridge_authorization_record(control)
                .expect("control");
        }
        let first_page = store
            .selected_bridge_authorization_candidates_after(None, 2)
            .expect("first authorization page");
        let second_page = store
            .selected_bridge_authorization_candidates_after(
                Some(first_page[1].control_sequence()),
                2,
            )
            .expect("second authorization page");
        assert_eq!(
            first_page
                .iter()
                .chain(&second_page)
                .map(StoredSelectedBridgeAuthorizationCandidate::control_sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );

        let routes = [
            route(first.envelope_id, 31, 32, 41, 1),
            route(first.envelope_id, 31, 33, 42, 1),
            route(first.envelope_id, 31, 34, 43, 1),
        ];
        for candidate in &routes {
            store
                .commit_bridge_event_route_record(candidate)
                .expect("route");
        }
        let first_page = store
            .selected_bridge_event_route_candidates_after(None, 2)
            .expect("first route page");
        let second_page = store
            .selected_bridge_event_route_candidates_after(
                Some(first_page[1].wrapper_envelope_id()),
                2,
            )
            .expect("second route page");
        let mut expected = routes
            .iter()
            .map(|route| route.wrapper_envelope_id)
            .collect::<Vec<_>>();
        expected.sort_unstable();
        assert_eq!(
            first_page
                .iter()
                .chain(&second_page)
                .map(StoredSelectedBridgeEventRouteCandidate::wrapper_envelope_id)
                .collect::<Vec<_>>(),
            expected
        );
        assert!(std::sync::Arc::ptr_eq(
            &first_page[0].exact_source_bytes,
            &first_page[1].exact_source_bytes,
        ));
    }

    #[test]
    fn core_verified_capabilities_gate_commit_and_reopen_promotion() {
        let file = TestFile::new("core-capability");
        let alpha = Scope::new("demo/alpha").expect("alpha scope");
        let parent = Scope::new("demo/parent").expect("parent scope");
        let topic = Topic::new("ops").expect("topic");
        let alpha_relay = ProvisioningAccess::relay(alpha.clone(), vec![1]).expect("alpha relay");
        let parent_relay =
            ProvisioningAccess::relay(parent.clone(), vec![2]).expect("parent relay");
        let mut provisioner = ReferenceProvisioner::from_seed([0xc8; 32]).expect("provisioner");
        let mut authority = provisioner
            .issue_control_authority(1, &[alpha_relay.clone(), parent_relay.clone()])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("authority");
        let mut bridge = provisioner
            .issue_node(2, &[alpha_relay, parent_relay])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("bridge");
        let mut publisher = provisioner
            .issue_node(
                3,
                &[
                    ProvisioningAccess::member(alpha.clone(), vec![1], vec![topic.clone()])
                        .expect("publisher access"),
                ],
            )
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("publisher");

        let enrollment =
            SelectedEventBridgeAdapter::create_enrollment(&bridge, &alpha, 1, &parent, 2)
                .expect("enrollment");
        let enrollment = SelectedEventBridgeAdapter::verify_enrollment(&authority, &enrollment)
            .expect("verified enrollment");
        let policy = SelectedBridgeAuthorizationPolicy::new(
            vec![topic.clone()],
            vec![Priority::Immediate],
            1,
        )
        .expect("policy");
        let authorization = SelectedEventBridgeAdapter::issue_authorization(
            &mut authority,
            &enrollment,
            BridgeAuthorizationLink::new(1, None, 1).expect("link"),
            &policy,
        )
        .expect("authorization");
        let authority_id = authorization.authority_id();
        let store = Store::open_for_mission(&file.0, authority_id).expect("store");
        store
            .commit_verified_selected_bridge_authorization(&authorization)
            .expect("commit authorization capability");

        let payload = b"opaque outside the source and target providers";
        let header = EnvelopeHeader {
            class: DataClass::Event,
            topic: topic.clone(),
            scope: alpha,
            priority: Priority::Immediate,
            stamp: CausalStamp {
                dot: Dot {
                    publisher: publisher.identity(),
                    counter: 1,
                },
                context: VersionVector::default(),
            },
            event_sequence: Some(1),
            logical_key: b"bridge-event".to_vec(),
            blob_route: None,
            ttl_ms: None,
            content_len: payload.len() as u64,
            tombstone: false,
            key_epoch: 1,
        };
        let source = publisher.seal_event(&header, payload).expect("source seal");
        let narrowing = SelectedBridgeNarrowingPolicy::new(vec![topic], vec![Priority::Immediate])
            .expect("narrowing");
        let route = SelectedEventBridgeAdapter::create_first_hop(
            &mut bridge,
            &source.bytes,
            authorization.envelope_id(),
            &[&authorization],
            &narrowing,
            0,
            false,
        )
        .expect("verified route");
        store
            .commit_verified_selected_bridge_event_route(&route)
            .expect("commit route capability");
        let origin = route.origin_envelope_id();
        let current_scope = route.current_scope().clone();
        let current_epoch = route.current_route_epoch();
        drop(store);

        let reopened = Store::open_for_mission(&file.0, authority_id).expect("reopen");
        assert!(
            reopened
                .active_selected_bridge_event_route_candidate(origin, &current_scope, current_epoch)
                .expect("inactive projection")
                .is_none()
        );
        let authorization_candidate = reopened
            .selected_bridge_authorization_candidates(1)
            .expect("authorization candidate")
            .pop()
            .expect("one authorization");
        let route_candidate = reopened
            .selected_bridge_event_route_candidates(1)
            .expect("route candidate")
            .pop()
            .expect("one route");
        let fresh_authorization = SelectedEventBridgeAdapter::verify_authorization(
            &authority,
            authorization_candidate.exact_bytes(),
        )
        .expect("fresh authorization verification");
        let fresh_route = SelectedEventBridgeAdapter::verify_event_route(
            &bridge,
            route_candidate.exact_wrapper_bytes(),
            route_candidate.exact_source_bytes(),
            &[&fresh_authorization],
        )
        .expect("fresh route verification");
        reopened
            .commit_verified_selected_bridge_event_route(&fresh_route)
            .expect("fresh promotion");
        assert!(
            reopened
                .active_selected_bridge_event_route_candidate(origin, &current_scope, current_epoch)
                .expect("active projection")
                .is_some()
        );
    }
}
