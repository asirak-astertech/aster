//! Durable immutable-publication Blob application subscriptions.
//!
//! The store owns only selector, retry, acknowledgement, and monotonic tenure
//! structure. Poll plans carry compact source projections, never sealed source
//! bytes or provider internals. `aster-node` rebinds every candidate to its
//! startup-authenticated projection and current policy, then exact-loads and
//! rechecks each deliverable source envelope and completed depot before
//! supplying the exhaustive deliverable/inactive partition committed here.

use std::collections::{BTreeMap, BTreeSet};

use aster_mesh::{NodeId, Scope, Topic};
use redb::{
    MultimapTableHandle, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    TableHandle,
};
use sha2::{Digest, Sha256};

use super::{BLOB_ACCEPTANCE_MARKERS, BLOB_PUBLICATIONS, LAST_BLOB_ACCEPTANCE_MARKER};
use super::{
    BlobSemanticId, BlobSourceProjection, BlobSubscriptionIdentity, BlobTransferId,
    ControlPolicySnapshot, METADATA, MetadataCursor, Store, StoreError,
    blob_subscription_exact_source_matches_write, blob_subscription_identity_read,
    blob_subscription_identity_write, blob_subscription_projection_matches_write,
    blob_subscription_projection_read, enforce_live_write, read_mission_binding,
    read_mission_binding_read, require_control_policy_read, require_control_policy_write,
};

/// Audited inverse of Blob forward acceptance markers used only for bounded scans.
pub(crate) const BLOB_ACCEPTANCE_ORDER: TableDefinition<u64, &[u8]> =
    TableDefinition::new("aster.semantic-blob-acceptance-order.v1");

pub(crate) const BLOB_SUBSCRIPTIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-subscriptions.v1");
pub(crate) const BLOB_SUBSCRIPTION_PENDING: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-delivery-pending.v1");
pub(crate) const BLOB_DELIVERY_ACKNOWLEDGEMENTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-delivery-acknowledgements.v1");
pub(crate) const BLOB_DELIVERY_CURSORS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-delivery-cursors.v1");

pub(crate) const BLOB_SUBSCRIPTION_COUNT: &str = "semantic_blob_subscription_count";
pub(crate) const BLOB_PENDING_DELIVERY_COUNT: &str = "semantic_blob_pending_delivery_count";
pub(crate) const BLOB_ACKNOWLEDGEMENT_COUNT: &str = "semantic_blob_acknowledgement_count";
pub(crate) const BLOB_DELIVERY_CURSOR_COUNT: &str = "semantic_blob_delivery_cursor_count";
pub(crate) const BLOB_SELECTOR_GENERATION: &str = "semantic_blob_selector_generation";

const BLOB_SUBSCRIPTION_VERSION: u8 = 1;
const BLOB_PENDING_DELIVERY_VERSION: u8 = 1;
const BLOB_ACKNOWLEDGEMENT_VERSION: u8 = 1;
const BLOB_DELIVERY_CURSOR_VERSION: u8 = 1;
const BLOB_DELIVERY_TOKEN_VERSION: u8 = 1;
const BLOB_SUBSCRIPTION_ID_DOMAIN: &[u8] = b"aster/blob-subscription-id/v1";
const BLOB_DELIVERY_TOKEN_DOMAIN: &[u8] = b"aster/blob-delivery-token/v1";
const BLOB_DELIVERY_TOKEN_COUNTER_BYTES: usize = 1 + (3 * 8);

/// Maximum byte length of one durable Blob subscription operation key.
pub const MAX_BLOB_SUBSCRIPTION_KEY_BYTES: usize = 256;
/// Maximum durable Blob application subscriptions in one mission-bound store.
pub const MAX_BLOB_SUBSCRIPTIONS: u64 = 256;
/// Maximum immutable Blob publication attempts returned by one poll.
pub const MAX_BLOB_POLL_DELIVERIES: usize = 128;
/// Maximum matching retained Blob versions freshly verified by one poll.
pub const MAX_BLOB_SUBSCRIPTION_SCAN: usize = 4_096;
/// Dedicated hard cap for unacknowledged Blob delivery attempts.
pub const MAX_BLOB_PENDING_DELIVERIES: u64 = 262_144;
/// Hard cap for durable idempotent Blob acknowledgement receipts.
pub const MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS: u64 = 262_144;
/// Hard cap for durable monotonic per-Blob delivery cursors.
pub const MAX_BLOB_DELIVERY_CURSORS: u64 = 262_144;
/// Canonical byte length of one opaque Blob delivery acknowledgement token.
pub const BLOB_DELIVERY_TOKEN_BYTES: usize = BLOB_DELIVERY_TOKEN_COUNTER_BYTES + 32;

/// Stable mission-local identity of one durable Blob application subscription.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobSubscriptionId([u8; 32]);

impl BlobSubscriptionId {
    /// Constructs an identifier from complete durable bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the complete durable identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Bounded application idempotency key for one Blob subscription.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobSubscriptionKey(Vec<u8>);

impl BlobSubscriptionKey {
    /// Validates one nonempty durable subscription key.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, StoreError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_BLOB_SUBSCRIPTION_KEY_BYTES {
            return Err(StoreError::InvalidBlobSubscriptionKey {
                length: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Returns the exact durable operation-key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// One durable Blob application-delivery selector.
///
/// This is local intent, never route or content authority.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobSubscriptionSpec {
    /// Exact selected topic.
    pub topic: Topic,
    /// Exact selected scope or ancestor scope when descendants are enabled.
    pub scope: Scope,
    /// Whether descendant scopes are included in addition to the exact scope.
    pub include_descendant_scopes: bool,
}

impl BlobSubscriptionSpec {
    pub(crate) fn matches(&self, projection: &BlobSourceProjection) -> bool {
        self.matches_topic_scope(&projection.topic, &projection.scope)
    }

    fn matches_topic_scope(&self, topic: &Topic, scope: &Scope) -> bool {
        &self.topic == topic
            && if self.include_descendant_scopes {
                self.scope.contains(scope)
            } else {
                &self.scope == scope
            }
    }

    fn matches_identity(&self, identity: &BlobSubscriptionIdentity) -> bool {
        self.matches_topic_scope(&identity.topic, &identity.scope)
    }
}

/// Result of idempotently creating one durable Blob subscription.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobSubscriptionCreateOutcome {
    /// Stable mission-local subscription identity.
    pub id: BlobSubscriptionId,
    /// True only when this call inserted the durable row.
    pub inserted: bool,
}

/// Result of idempotently removing one Blob selector and its ledgers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobSubscriptionRemoveOutcome {
    /// Stable identity supplied by the caller.
    pub id: BlobSubscriptionId,
    /// True only when this call removed durable blob.
    pub removed: bool,
}

/// One complete-snapshot Blob candidate requiring fresh verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobSubscriptionCandidate {
    projection: BlobSourceProjection,
    acceptance_marker: u64,
    pending_attempt: Option<u64>,
    acknowledged_attempt: Option<u64>,
    delivery_cursor: Option<BlobDeliveryCursorRecord>,
}

impl BlobSubscriptionCandidate {
    /// Compact authenticated-source claim requiring exact privileged verification.
    pub const fn projection(&self) -> &BlobSourceProjection {
        &self.projection
    }

    /// Stable marker ordering this immutable publication.
    pub const fn acceptance_marker(&self) -> u64 {
        self.acceptance_marker
    }

    /// Previously committed unacknowledged attempt, when any.
    pub const fn pending_attempt(&self) -> Option<u64> {
        self.pending_attempt
    }

    /// Durable acknowledgement attempt, when this exact version was acknowledged.
    pub const fn acknowledged_attempt(&self) -> Option<u64> {
        self.acknowledged_attempt
    }

    /// Highest attempt committed in this publication's most recent visibility tenure.
    pub const fn last_delivery_attempt(&self) -> Option<u64> {
        match self.delivery_cursor {
            Some(cursor) => Some(cursor.last_attempt),
            None => None,
        }
    }

    /// Monotonic active-delivery tenure last allocated to this publication.
    pub const fn delivery_tenure(&self) -> Option<u64> {
        match self.delivery_cursor {
            Some(cursor) => Some(cursor.tenure),
            None => None,
        }
    }
}

/// Complete bounded matching-Blob snapshot prepared for privileged verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobSubscriptionPollPlan {
    policy: ControlPolicySnapshot,
    subscription: BlobSubscriptionId,
    spec: BlobSubscriptionSpec,
    incarnation: u64,
    selector_generation: u64,
    candidates: Vec<BlobSubscriptionCandidate>,
    delivery_limit: usize,
    scan_limit: usize,
}

impl BlobSubscriptionPollPlan {
    /// Stable identity of the planned subscription.
    pub const fn subscription(&self) -> BlobSubscriptionId {
        self.subscription
    }

    /// Exact durable selector observed by the plan transaction.
    pub const fn spec(&self) -> &BlobSubscriptionSpec {
        &self.spec
    }

    /// Durable selector mutation generation observed by the plan.
    pub const fn selector_generation(&self) -> u64 {
        self.selector_generation
    }

    /// Monotonic tenure of this stable subscription identity.
    pub const fn incarnation(&self) -> u64 {
        self.incarnation
    }

    /// Acceptance-marker ordered complete matching snapshot.
    pub fn candidates(&self) -> &[BlobSubscriptionCandidate] {
        &self.candidates
    }
}

/// Privileged freshly verified partition of one complete Blob poll snapshot.
///
/// Every candidate semantic ID must appear exactly once. The store rechecks
/// exact durable structure; `aster-node` owns source/content, settled-policy,
/// and completed-depot verification before constructing this value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlobSubscriptionPollSelection {
    /// Freshly verified publications that are active and depot-complete.
    pub deliverable: Vec<BlobSemanticId>,
    /// Freshly verified revoked, stale-epoch, incomplete, or otherwise inactive publications.
    pub inactive: Vec<BlobSemanticId>,
}

/// One at-least-once immutable-publication delivery committed before application return.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobSubscriptionDelivery {
    /// Exact source-authenticated publication identity.
    pub semantic_id: BlobSemanticId,
    /// Stable acceptance marker for deterministic application ordering.
    pub acceptance_marker: u64,
    /// Nonzero durable delivery-attempt number.
    pub attempt: u64,
    /// Opaque durable acknowledgement token for this exact delivery tenure and attempt.
    pub token: BlobDeliveryToken,
}

/// Opaque activation-safe acknowledgement identity for one committed Blob delivery.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobDeliveryToken([u8; BLOB_DELIVERY_TOKEN_BYTES]);

impl BlobDeliveryToken {
    /// Reconstructs one canonical opaque token transported by the application boundary.
    ///
    /// Its subscription and Blob binding is revalidated by acknowledgement.
    pub fn from_bytes(bytes: [u8; BLOB_DELIVERY_TOKEN_BYTES]) -> Result<Self, StoreError> {
        let token = Self(bytes);
        if token.0[0] != BLOB_DELIVERY_TOKEN_VERSION
            || token.incarnation() == 0
            || token.tenure() == 0
            || token.attempt() == 0
        {
            return Err(StoreError::InvalidBlobDeliveryToken);
        }
        Ok(token)
    }

    /// Returns the complete canonical opaque token bytes.
    pub const fn as_bytes(&self) -> &[u8; BLOB_DELIVERY_TOKEN_BYTES] {
        &self.0
    }

    pub(crate) fn incarnation(self) -> u64 {
        u64::from_be_bytes(
            self.0[1..9]
                .try_into()
                .expect("fixed Blob delivery-token incarnation"),
        )
    }

    pub(crate) fn tenure(self) -> u64 {
        u64::from_be_bytes(
            self.0[9..17]
                .try_into()
                .expect("fixed Blob delivery-token tenure"),
        )
    }

    pub(crate) fn attempt(self) -> u64 {
        u64::from_be_bytes(
            self.0[17..25]
                .try_into()
                .expect("fixed Blob delivery-token attempt"),
        )
    }
}

/// Result of one complete-snapshot Blob subscription poll commit.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BlobSubscriptionDeliveryPage {
    /// Pending-first, marker-ordered attempts committed before return.
    pub deliveries: Vec<BlobSubscriptionDelivery>,
    /// True when additional unacknowledged deliverable publications remain.
    pub has_more: bool,
}

/// Idempotent acknowledgement result for one semantic Blob delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobDeliveryAck {
    /// This call atomically replaced a pending attempt with a receipt.
    Acknowledged,
    /// An exact durable acknowledgement receipt already exists.
    AlreadyAcknowledged,
}

/// Consistent durable counts for Blob selectors and deliveries.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlobSubscriptionStats {
    /// Durable Blob application selectors.
    pub subscriptions: u64,
    /// Unacknowledged attempted Blob publication deliveries.
    pub pending_deliveries: u64,
    /// Durable receipts for publications still active in their committed classification.
    pub acknowledged_deliveries: u64,
    /// Durable monotonic per-Blob delivery cursors, including retired tenures.
    pub delivery_cursors: u64,
    /// Mutation generation advanced by each actual insert or removal.
    pub selector_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BlobSubscriptionRecord {
    operation_key: BlobSubscriptionKey,
    spec: BlobSubscriptionSpec,
    incarnation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobPendingDeliveryRecord {
    semantic_id: BlobSemanticId,
    tenure: u64,
    attempts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobAcknowledgementRecord {
    acceptance_marker: u64,
    tenure: u64,
    attempts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobDeliveryCursorRecord {
    acceptance_marker: u64,
    tenure: u64,
    last_attempt: u64,
    last_acknowledged_tenure: u64,
    last_acknowledged_attempt: u64,
}

impl Store {
    /// Returns structurally audited Blob subscription counts.
    pub fn blob_subscription_stats(&self) -> Result<BlobSubscriptionStats, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        inspect_blob_subscription_tables(&read)
    }

    /// Idempotently creates one durable Blob application selector.
    pub fn create_blob_subscription_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        key: &BlobSubscriptionKey,
        spec: BlobSubscriptionSpec,
    ) -> Result<BlobSubscriptionCreateOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let id = blob_subscription_id(authority, key);
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let existing = write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(id.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?;
        if let Some(existing) = existing {
            if existing.operation_key != *key || existing.spec != spec {
                return Err(StoreError::BlobSubscriptionConflict);
            }
            return Ok(BlobSubscriptionCreateOutcome {
                id,
                inserted: false,
            });
        }

        let current_count = write.open_table(BLOB_SUBSCRIPTIONS)?.len()?;
        if current_count >= MAX_BLOB_SUBSCRIPTIONS {
            return Err(StoreError::BlobSubscriptionLimitExceeded {
                current: current_count,
                limit: MAX_BLOB_SUBSCRIPTIONS,
            });
        }
        let (durable_count, generation) = {
            let metadata = write.open_table(METADATA)?;
            let count = metadata
                .get(BLOB_SUBSCRIPTION_COUNT)?
                .ok_or(StoreError::MissingAccountingMetadata {
                    field: BLOB_SUBSCRIPTION_COUNT,
                })?
                .value();
            let generation = metadata
                .get(BLOB_SELECTOR_GENERATION)?
                .ok_or(StoreError::MissingAccountingMetadata {
                    field: BLOB_SELECTOR_GENERATION,
                })?
                .value();
            (count, generation)
        };
        if durable_count != current_count {
            return Err(StoreError::AccountingMismatch {
                field: BLOB_SUBSCRIPTION_COUNT,
                durable: durable_count,
                reconstructed: current_count,
            });
        }
        validate_blob_selector_generation(generation, current_count)?;
        let incarnation = generation
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let record = BlobSubscriptionRecord {
            operation_key: key.clone(),
            spec,
            incarnation,
        };
        let encoded = encode_blob_subscription_record(&record)?;
        write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .insert(id.as_bytes().as_slice(), encoded.as_slice())?;
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(
                BLOB_SUBSCRIPTION_COUNT,
                current_count
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
            metadata.insert(BLOB_SELECTOR_GENERATION, incarnation)?;
        }
        write.commit()?;
        Ok(BlobSubscriptionCreateOutcome { id, inserted: true })
    }

    /// Idempotently removes one Blob selector and all delivery evidence.
    pub fn remove_blob_subscription_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        id: BlobSubscriptionId,
    ) -> Result<BlobSubscriptionRemoveOutcome, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let record = write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(id.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?;
        let Some(record) = record else {
            return Ok(BlobSubscriptionRemoveOutcome { id, removed: false });
        };
        if blob_subscription_id(authority, &record.operation_key) != id {
            return Err(StoreError::BlobInvariant(
                "Blob subscription identifier differs from its operation key",
            ));
        }

        let subscription_count = write.open_table(BLOB_SUBSCRIPTIONS)?.len()?;
        let pending_count = write.open_table(BLOB_SUBSCRIPTION_PENDING)?.len()?;
        let acknowledgement_count = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
        let cursor_count = write.open_table(BLOB_DELIVERY_CURSORS)?.len()?;
        let generation = require_blob_subscription_accounting(
            &write,
            subscription_count,
            pending_count,
            acknowledgement_count,
            cursor_count,
        )?;

        let mut pending_removals = Vec::new();
        for row in write.open_table(BLOB_SUBSCRIPTION_PENDING)?.iter()? {
            let (key, value) = row?;
            let (row_subscription, _) = parse_blob_pending_delivery_key(key.value())?;
            if row_subscription == id {
                decode_blob_pending_delivery_record(value.value())?;
                pending_removals.push(key.value().to_vec());
            }
        }
        let mut acknowledgement_removals = Vec::new();
        for row in write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
            let (key, value) = row?;
            let (row_subscription, _) = parse_blob_acknowledgement_key(key.value())?;
            if row_subscription == id {
                decode_blob_acknowledgement_record(value.value())?;
                acknowledgement_removals.push(key.value().to_vec());
            }
        }
        let mut cursor_removals = Vec::new();
        for row in write.open_table(BLOB_DELIVERY_CURSORS)?.iter()? {
            let (key, value) = row?;
            let (row_subscription, _) = parse_blob_delivery_cursor_key(key.value())?;
            if row_subscription == id {
                decode_blob_delivery_cursor_record(value.value())?;
                cursor_removals.push(key.value().to_vec());
            }
        }
        {
            let mut pending = write.open_table(BLOB_SUBSCRIPTION_PENDING)?;
            for key in &pending_removals {
                pending.remove(key.as_slice())?;
            }
        }
        {
            let mut acknowledgements = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?;
            for key in &acknowledgement_removals {
                acknowledgements.remove(key.as_slice())?;
            }
        }
        {
            let mut cursors = write.open_table(BLOB_DELIVERY_CURSORS)?;
            for key in &cursor_removals {
                cursors.remove(key.as_slice())?;
            }
        }
        if write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .remove(id.as_bytes().as_slice())?
            .is_none()
        {
            return Err(StoreError::BlobInvariant(
                "Blob subscription disappeared during its write transaction",
            ));
        }
        let removed_pending = u64::try_from(pending_removals.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        let removed_acknowledgements = u64::try_from(acknowledgement_removals.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        let removed_cursors = u64::try_from(cursor_removals.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(
                BLOB_SUBSCRIPTION_COUNT,
                subscription_count
                    .checked_sub(1)
                    .ok_or(StoreError::BlobInvariant(
                        "Blob subscription counter underflow",
                    ))?,
            )?;
            metadata.insert(
                BLOB_PENDING_DELIVERY_COUNT,
                pending_count
                    .checked_sub(removed_pending)
                    .ok_or(StoreError::BlobInvariant(
                        "Blob pending-delivery counter underflow",
                    ))?,
            )?;
            metadata.insert(
                BLOB_ACKNOWLEDGEMENT_COUNT,
                acknowledgement_count
                    .checked_sub(removed_acknowledgements)
                    .ok_or(StoreError::BlobInvariant(
                        "Blob acknowledgement counter underflow",
                    ))?,
            )?;
            metadata.insert(
                BLOB_DELIVERY_CURSOR_COUNT,
                cursor_count
                    .checked_sub(removed_cursors)
                    .ok_or(StoreError::BlobInvariant(
                        "Blob delivery-cursor counter underflow",
                    ))?,
            )?;
            metadata.insert(
                BLOB_SELECTOR_GENERATION,
                generation
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
        }
        write.commit()?;
        Ok(BlobSubscriptionRemoveOutcome { id, removed: true })
    }

    /// Prepares a complete bounded matching-Blob snapshot for fresh verification.
    pub fn prepare_blob_subscription_poll_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        subscription: BlobSubscriptionId,
        delivery_limit: usize,
        scan_limit: usize,
    ) -> Result<BlobSubscriptionPollPlan, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        validate_blob_poll_limits(delivery_limit, scan_limit)?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let record = read
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(subscription.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::BlobSubscriptionNotFound)?;
        let selector_generation = read
            .open_table(METADATA)?
            .get(BLOB_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: BLOB_SELECTOR_GENERATION,
            })?
            .value();
        let subscription_count = read.open_table(BLOB_SUBSCRIPTIONS)?.len()?;
        validate_blob_selector_generation(selector_generation, subscription_count)?;
        let candidates =
            blob_subscription_candidates_read(&read, subscription, &record.spec, scan_limit)?;
        Ok(BlobSubscriptionPollPlan {
            policy: *policy,
            subscription,
            spec: record.spec,
            incarnation: record.incarnation,
            selector_generation,
            candidates,
            delivery_limit,
            scan_limit,
        })
    }

    /// Commits one exact freshly verified deliverable/inactive partition.
    pub fn commit_blob_subscription_poll_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        plan: &BlobSubscriptionPollPlan,
        selection: &BlobSubscriptionPollSelection,
    ) -> Result<BlobSubscriptionDeliveryPage, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        validate_blob_poll_limits(plan.delivery_limit, plan.scan_limit)?;
        if policy != &plan.policy || plan.candidates.len() > plan.scan_limit {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        let partition = validate_blob_selection(plan, selection)?;

        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let record = write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(plan.subscription.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::BlobSubscriptionNotFound)?;
        let generation = write
            .open_table(METADATA)?
            .get(BLOB_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: BLOB_SELECTOR_GENERATION,
            })?
            .value();
        if record.spec != plan.spec
            || record.incarnation != plan.incarnation
            || generation != plan.selector_generation
        {
            return Err(StoreError::BlobSelectorGenerationChanged);
        }
        let durable_candidates = blob_subscription_candidates_write(
            &write,
            plan.subscription,
            &record.spec,
            plan.scan_limit,
            &plan.candidates,
        )?;
        if durable_candidates != plan.candidates {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }

        let subscription_count = write.open_table(BLOB_SUBSCRIPTIONS)?.len()?;
        let pending_count = write.open_table(BLOB_SUBSCRIPTION_PENDING)?.len()?;
        let acknowledgement_count = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
        let cursor_count = write.open_table(BLOB_DELIVERY_CURSORS)?.len()?;
        require_blob_subscription_accounting(
            &write,
            subscription_count,
            pending_count,
            acknowledgement_count,
            cursor_count,
        )?;

        let mut retire_pending = Vec::new();
        let mut retire_acknowledgements = Vec::new();
        let mut pending_deliverable = Vec::new();
        let mut new_deliverable = Vec::new();
        for candidate in &durable_candidates {
            let id = candidate.projection.semantic_id;
            if !partition.deliverable.contains(&id) {
                if candidate.pending_attempt.is_some() {
                    retire_pending.push(candidate);
                }
                if candidate.acknowledged_attempt.is_some() {
                    retire_acknowledgements.push(candidate);
                }
                continue;
            }
            if candidate.acknowledged_attempt.is_some() {
                continue;
            }
            if candidate.pending_attempt.is_some() {
                pending_deliverable.push(candidate);
            } else {
                new_deliverable.push(candidate);
            }
        }
        pending_deliverable.sort_by_key(|candidate| candidate.acceptance_marker);
        new_deliverable.sort_by_key(|candidate| candidate.acceptance_marker);
        let eligible_count = pending_deliverable
            .len()
            .checked_add(new_deliverable.len())
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let chosen = pending_deliverable
            .into_iter()
            .chain(new_deliverable)
            .take(plan.delivery_limit)
            .collect::<Vec<_>>();
        for candidate in &chosen {
            if !blob_subscription_exact_source_matches_write(
                &write,
                candidate.projection.transfer_id,
            )? {
                return Err(StoreError::BlobSubscriptionPlanChanged);
            }
        }
        let new_delivery_count = chosen
            .iter()
            .filter(|candidate| candidate.pending_attempt.is_none())
            .count();
        let new_cursor_count = chosen
            .iter()
            .filter(|candidate| candidate.delivery_cursor.is_none())
            .count();
        let final_pending_count = pending_count
            .checked_sub(
                u64::try_from(retire_pending.len())
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            )
            .ok_or(StoreError::BlobInvariant(
                "Blob pending retirement underflows accounting",
            ))?
            .checked_add(
                u64::try_from(new_delivery_count)
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            )
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let final_acknowledgement_count = acknowledgement_count
            .checked_sub(
                u64::try_from(retire_acknowledgements.len())
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            )
            .ok_or(StoreError::BlobInvariant(
                "Blob acknowledgement retirement underflows accounting",
            ))?;
        let final_cursor_count = cursor_count
            .checked_add(
                u64::try_from(new_cursor_count)
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            )
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if final_pending_count > MAX_BLOB_PENDING_DELIVERIES {
            return Err(StoreError::BlobPendingDeliveryLimitExceeded {
                current: final_pending_count,
                limit: MAX_BLOB_PENDING_DELIVERIES,
            });
        }
        let combined = final_pending_count
            .checked_add(final_acknowledgement_count)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if combined > MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS {
            return Err(StoreError::BlobDeliveryLedgerLimitExceeded {
                current: combined,
                limit: MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS,
            });
        }
        if final_cursor_count > MAX_BLOB_DELIVERY_CURSORS {
            return Err(StoreError::BlobDeliveryLedgerLimitExceeded {
                current: final_cursor_count,
                limit: MAX_BLOB_DELIVERY_CURSORS,
            });
        }

        let mut tenures = Vec::with_capacity(chosen.len());
        let mut attempts = Vec::with_capacity(chosen.len());
        for candidate in &chosen {
            if candidate.pending_attempt.is_some() {
                let cursor = candidate.delivery_cursor.ok_or(StoreError::BlobInvariant(
                    "pending Blob delivery is missing its monotonic cursor",
                ))?;
                tenures.push(cursor.tenure);
                attempts.push(
                    cursor
                        .last_attempt
                        .checked_add(1)
                        .ok_or(StoreError::BlobDeliveryAttemptExhausted)?,
                );
            } else {
                tenures.push(match candidate.delivery_cursor {
                    Some(cursor) => cursor
                        .tenure
                        .checked_add(1)
                        .ok_or(StoreError::BlobDeliveryTenureExhausted)?,
                    None => 1,
                });
                attempts.push(1);
            }
        }
        {
            let mut pending = write.open_table(BLOB_SUBSCRIPTION_PENDING)?;
            for candidate in &retire_pending {
                let key = blob_pending_delivery_key(plan.subscription, candidate.acceptance_marker);
                if pending.remove(key.as_slice())?.is_none() {
                    return Err(StoreError::BlobSubscriptionPlanChanged);
                }
            }
            for ((candidate, tenure), attempt) in chosen.iter().zip(&tenures).zip(&attempts) {
                let key = blob_pending_delivery_key(plan.subscription, candidate.acceptance_marker);
                let encoded = encode_blob_pending_delivery_record(BlobPendingDeliveryRecord {
                    semantic_id: candidate.projection.semantic_id,
                    tenure: *tenure,
                    attempts: *attempt,
                });
                pending.insert(key.as_slice(), encoded.as_slice())?;
            }
        }
        {
            let mut acknowledgements = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?;
            for candidate in &retire_acknowledgements {
                let key =
                    blob_acknowledgement_key(plan.subscription, candidate.projection.semantic_id);
                if acknowledgements.remove(key.as_slice())?.is_none() {
                    return Err(StoreError::BlobSubscriptionPlanChanged);
                }
            }
        }
        {
            let mut cursors = write.open_table(BLOB_DELIVERY_CURSORS)?;
            for ((candidate, tenure), attempt) in chosen.iter().zip(&tenures).zip(&attempts) {
                let key =
                    blob_delivery_cursor_key(plan.subscription, candidate.projection.semantic_id);
                let encoded = encode_blob_delivery_cursor_record(BlobDeliveryCursorRecord {
                    acceptance_marker: candidate.acceptance_marker,
                    tenure: *tenure,
                    last_attempt: *attempt,
                    last_acknowledged_tenure: candidate
                        .delivery_cursor
                        .map_or(0, |cursor| cursor.last_acknowledged_tenure),
                    last_acknowledged_attempt: candidate
                        .delivery_cursor
                        .map_or(0, |cursor| cursor.last_acknowledged_attempt),
                });
                cursors.insert(key.as_slice(), encoded.as_slice())?;
            }
        }
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(BLOB_PENDING_DELIVERY_COUNT, final_pending_count)?;
            metadata.insert(BLOB_ACKNOWLEDGEMENT_COUNT, final_acknowledgement_count)?;
            metadata.insert(BLOB_DELIVERY_CURSOR_COUNT, final_cursor_count)?;
        }
        write.commit()?;

        Ok(BlobSubscriptionDeliveryPage {
            deliveries: chosen
                .into_iter()
                .zip(tenures)
                .zip(attempts)
                .map(|((candidate, tenure), attempt)| BlobSubscriptionDelivery {
                    semantic_id: candidate.projection.semantic_id,
                    acceptance_marker: candidate.acceptance_marker,
                    attempt,
                    token: blob_delivery_token(
                        plan.subscription,
                        candidate.projection.semantic_id,
                        plan.incarnation,
                        tenure,
                        attempt,
                    ),
                })
                .collect(),
            has_more: eligible_count > plan.delivery_limit,
        })
    }

    /// Idempotently acknowledges one exact semantic Blob delivery.
    pub fn acknowledge_blob_delivery_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        subscription: BlobSubscriptionId,
        semantic_id: BlobSemanticId,
        token: BlobDeliveryToken,
    ) -> Result<BlobDeliveryAck, StoreError> {
        let token = validate_blob_delivery_token_binding(subscription, semantic_id, token)?;
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let record = write
            .open_table(BLOB_SUBSCRIPTIONS)?
            .get(subscription.as_bytes().as_slice())?
            .map(|value| decode_blob_subscription_record(value.value()))
            .transpose()?
            .ok_or(StoreError::BlobSubscriptionNotFound)?;
        if token.incarnation != record.incarnation {
            return Err(StoreError::BlobSubscriptionIncarnationChanged {
                current: record.incarnation,
                received: token.incarnation,
            });
        }
        let blob = blob_subscription_identity_write(&write, semantic_id)?
            .ok_or(StoreError::BlobDeliveryNotFound)?;
        if !record.spec.matches_topic_scope(&blob.topic, &blob.scope) {
            return Err(StoreError::BlobDeliveryNotFound);
        }
        let cursor_key = blob_delivery_cursor_key(subscription, semantic_id);
        let mut cursor = write
            .open_table(BLOB_DELIVERY_CURSORS)?
            .get(cursor_key.as_slice())?
            .map(|value| decode_blob_delivery_cursor_record(value.value()))
            .transpose()?
            .ok_or(StoreError::BlobDeliveryNotFound)?;
        if cursor.acceptance_marker != blob.acceptance_marker {
            return Err(StoreError::BlobInvariant(
                "Blob delivery cursor differs from its accepted Blob",
            ));
        }
        let acknowledgement_key = blob_acknowledgement_key(subscription, semantic_id);
        let receipt = write
            .open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?
            .get(acknowledgement_key.as_slice())?
            .map(|value| decode_blob_acknowledgement_record(value.value()))
            .transpose()?;
        let pending_key = blob_pending_delivery_key(subscription, blob.acceptance_marker);
        let pending = write
            .open_table(BLOB_SUBSCRIPTION_PENDING)?
            .get(pending_key.as_slice())?
            .map(|value| decode_blob_pending_delivery_record(value.value()))
            .transpose()?;
        if receipt.is_some() && pending.is_some() {
            return Err(StoreError::BlobInvariant(
                "Blob delivery is both pending and acknowledged",
            ));
        }
        if let Some(receipt) = receipt {
            if receipt.acceptance_marker != blob.acceptance_marker
                || receipt.tenure != cursor.tenure
                || receipt.tenure != cursor.last_acknowledged_tenure
                || receipt.attempts != cursor.last_acknowledged_attempt
                || receipt.attempts > cursor.last_attempt
            {
                return Err(StoreError::BlobInvariant(
                    "Blob acknowledgement differs from its delivery cursor",
                ));
            }
            if token.tenure != receipt.tenure {
                return Err(StoreError::BlobDeliveryTenureChanged {
                    current: receipt.tenure,
                    received: token.tenure,
                });
            }
            validate_blob_delivery_token_attempt(token.attempt, receipt.attempts)?;
            return Ok(BlobDeliveryAck::AlreadyAcknowledged);
        }
        let Some(pending) = pending else {
            return Err(StoreError::BlobDeliveryNotFound);
        };
        if pending.semantic_id != semantic_id
            || pending.tenure != cursor.tenure
            || pending.attempts != cursor.last_attempt
        {
            return Err(StoreError::BlobInvariant(
                "pending Blob delivery differs from its monotonic cursor",
            ));
        }
        if token.tenure != pending.tenure {
            return Err(StoreError::BlobDeliveryTenureChanged {
                current: pending.tenure,
                received: token.tenure,
            });
        }
        validate_blob_delivery_token_attempt(token.attempt, pending.attempts)?;

        let subscription_count = write.open_table(BLOB_SUBSCRIPTIONS)?.len()?;
        let pending_count = write.open_table(BLOB_SUBSCRIPTION_PENDING)?.len()?;
        let acknowledgement_count = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.len()?;
        let cursor_count = write.open_table(BLOB_DELIVERY_CURSORS)?.len()?;
        require_blob_subscription_accounting(
            &write,
            subscription_count,
            pending_count,
            acknowledgement_count,
            cursor_count,
        )?;
        if acknowledgement_count >= MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS {
            return Err(StoreError::BlobAcknowledgementReceiptLimitExceeded {
                current: acknowledgement_count,
                limit: MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS,
            });
        }
        let encoded = encode_blob_acknowledgement_record(BlobAcknowledgementRecord {
            acceptance_marker: blob.acceptance_marker,
            tenure: pending.tenure,
            attempts: pending.attempts,
        });
        if write
            .open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?
            .insert(acknowledgement_key.as_slice(), encoded.as_slice())?
            .is_some()
        {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        if write
            .open_table(BLOB_SUBSCRIPTION_PENDING)?
            .remove(pending_key.as_slice())?
            .is_none()
        {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        {
            cursor.last_acknowledged_tenure = pending.tenure;
            cursor.last_acknowledged_attempt = pending.attempts;
            let encoded = encode_blob_delivery_cursor_record(cursor);
            write
                .open_table(BLOB_DELIVERY_CURSORS)?
                .insert(cursor_key.as_slice(), encoded.as_slice())?;
        }
        {
            let mut metadata = write.open_table(METADATA)?;
            metadata.insert(
                BLOB_PENDING_DELIVERY_COUNT,
                pending_count
                    .checked_sub(1)
                    .ok_or(StoreError::BlobInvariant(
                        "Blob acknowledgement underflows pending accounting",
                    ))?,
            )?;
            metadata.insert(
                BLOB_ACKNOWLEDGEMENT_COUNT,
                acknowledgement_count
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
        }
        write.commit()?;
        Ok(BlobDeliveryAck::Acknowledged)
    }
}

fn validate_blob_delivery_token_attempt(received: u64, maximum: u64) -> Result<(), StoreError> {
    if received == 0 || received > maximum {
        return Err(StoreError::BlobDeliveryAttemptChanged {
            current: maximum,
            received,
        });
    }
    Ok(())
}

fn validate_blob_poll_limits(delivery_limit: usize, scan_limit: usize) -> Result<(), StoreError> {
    if delivery_limit == 0 || delivery_limit > MAX_BLOB_POLL_DELIVERIES {
        return Err(StoreError::BlobSubscriptionPollLimitExceeded {
            requested: delivery_limit,
            maximum: MAX_BLOB_POLL_DELIVERIES,
        });
    }
    if scan_limit == 0 || scan_limit > MAX_BLOB_SUBSCRIPTION_SCAN {
        return Err(StoreError::BlobSubscriptionPollLimitExceeded {
            requested: scan_limit,
            maximum: MAX_BLOB_SUBSCRIPTION_SCAN,
        });
    }
    Ok(())
}

fn validate_blob_selection(
    plan: &BlobSubscriptionPollPlan,
    selection: &BlobSubscriptionPollSelection,
) -> Result<BlobSelectionPartition, StoreError> {
    let deliverable = selection
        .deliverable
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let inactive = selection.inactive.iter().copied().collect::<BTreeSet<_>>();
    if deliverable.len() != selection.deliverable.len()
        || inactive.len() != selection.inactive.len()
        || !deliverable.is_disjoint(&inactive)
    {
        return Err(StoreError::BlobSubscriptionPlanChanged);
    }
    let expected = plan
        .candidates
        .iter()
        .map(|candidate| candidate.projection.semantic_id)
        .collect::<BTreeSet<_>>();
    let actual = deliverable
        .iter()
        .chain(&inactive)
        .copied()
        .collect::<BTreeSet<_>>();
    if expected != actual {
        return Err(StoreError::BlobSubscriptionPlanChanged);
    }
    Ok(BlobSelectionPartition { deliverable })
}

struct BlobSelectionPartition {
    deliverable: BTreeSet<BlobSemanticId>,
}

fn blob_subscription_candidates_read(
    read: &redb::ReadTransaction,
    subscription: BlobSubscriptionId,
    spec: &BlobSubscriptionSpec,
    scan_limit: usize,
) -> Result<Vec<BlobSubscriptionCandidate>, StoreError> {
    let order = read.open_table(BLOB_ACCEPTANCE_ORDER)?;
    let pending = read.open_table(BLOB_SUBSCRIPTION_PENDING)?;
    let acknowledgements = read.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?;
    let cursors = read.open_table(BLOB_DELIVERY_CURSORS)?;
    let mut candidates = Vec::new();
    let mut expected_marker = 1u64;
    for row in order.iter()? {
        let (marker, transfer) = row?;
        let marker = marker.value();
        if marker != expected_marker {
            return Err(StoreError::BlobInvariant(
                "Blob acceptance-order snapshot is not consecutive",
            ));
        }
        expected_marker = marker
            .checked_add(1)
            .ok_or(StoreError::AcceptanceMarkerExhausted)?;
        let transfer = parse_blob_subscription_transfer_id(transfer.value())?;
        let (projection, acceptance_marker) = blob_subscription_projection_read(read, transfer)?
            .ok_or(StoreError::BlobInvariant(
                "Blob acceptance-order index points to a missing Blob",
            ))?;
        if acceptance_marker != marker || !spec.matches(&projection) {
            if acceptance_marker != marker {
                return Err(StoreError::BlobInvariant(
                    "Blob acceptance-order index differs from its forward marker",
                ));
            }
            continue;
        }
        if candidates.len() == scan_limit {
            return Err(StoreError::BlobSubscriptionPollLimitExceeded {
                requested: scan_limit
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
                maximum: scan_limit,
            });
        }
        let pending_key = blob_pending_delivery_key(subscription, marker);
        let pending_record = pending
            .get(pending_key.as_slice())?
            .map(|value| decode_blob_pending_delivery_record(value.value()))
            .transpose()?;
        let acknowledgement_key = blob_acknowledgement_key(subscription, projection.semantic_id);
        let acknowledgement_record = acknowledgements
            .get(acknowledgement_key.as_slice())?
            .map(|value| decode_blob_acknowledgement_record(value.value()))
            .transpose()?;
        let cursor_key = blob_delivery_cursor_key(subscription, projection.semantic_id);
        let delivery_cursor = cursors
            .get(cursor_key.as_slice())?
            .map(|value| decode_blob_delivery_cursor_record(value.value()))
            .transpose()?;
        validate_blob_candidate_delivery_ledger(
            projection.semantic_id,
            marker,
            pending_record,
            acknowledgement_record,
            delivery_cursor,
        )?;
        candidates.push(BlobSubscriptionCandidate {
            projection,
            acceptance_marker: marker,
            pending_attempt: pending_record.map(|record| record.attempts),
            acknowledged_attempt: acknowledgement_record.map(|record| record.attempts),
            delivery_cursor,
        });
    }
    require_complete_blob_acceptance_snapshot_read(read, expected_marker)?;
    Ok(candidates)
}

fn blob_subscription_candidates_write(
    write: &redb::WriteTransaction,
    subscription: BlobSubscriptionId,
    spec: &BlobSubscriptionSpec,
    scan_limit: usize,
    expected: &[BlobSubscriptionCandidate],
) -> Result<Vec<BlobSubscriptionCandidate>, StoreError> {
    let order = write.open_table(BLOB_ACCEPTANCE_ORDER)?;
    let pending = write.open_table(BLOB_SUBSCRIPTION_PENDING)?;
    let acknowledgements = write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?;
    let cursors = write.open_table(BLOB_DELIVERY_CURSORS)?;
    let mut candidates = Vec::new();
    let expected = expected
        .iter()
        .map(|candidate| (candidate.acceptance_marker, candidate))
        .collect::<BTreeMap<_, _>>();
    let mut expected_marker = 1u64;
    for row in order.iter()? {
        let (marker, transfer) = row?;
        let marker = marker.value();
        if marker != expected_marker {
            return Err(StoreError::BlobInvariant(
                "Blob acceptance-order snapshot is not consecutive",
            ));
        }
        expected_marker = marker
            .checked_add(1)
            .ok_or(StoreError::AcceptanceMarkerExhausted)?;
        let transfer = parse_blob_subscription_transfer_id(transfer.value())?;
        let identity = super::blob_subscription_identity_for_transfer_write(write, transfer)?
            .ok_or(StoreError::BlobInvariant(
                "Blob acceptance-order index points to a missing Blob",
            ))?;
        if identity.acceptance_marker != marker
            || !spec.matches_topic_scope(&identity.topic, &identity.scope)
        {
            if identity.acceptance_marker != marker {
                return Err(StoreError::BlobInvariant(
                    "Blob acceptance-order index differs from its forward marker",
                ));
            }
            continue;
        }
        if candidates.len() == scan_limit {
            return Err(StoreError::BlobSubscriptionPollLimitExceeded {
                requested: scan_limit
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
                maximum: scan_limit,
            });
        }
        let planned = expected
            .get(&marker)
            .copied()
            .ok_or(StoreError::BlobSubscriptionPlanChanged)?;
        if !blob_subscription_projection_matches_write(
            write,
            transfer,
            marker,
            &planned.projection,
        )? {
            return Err(StoreError::BlobSubscriptionPlanChanged);
        }
        let pending_key = blob_pending_delivery_key(subscription, marker);
        let pending_record = pending
            .get(pending_key.as_slice())?
            .map(|value| decode_blob_pending_delivery_record(value.value()))
            .transpose()?;
        let acknowledgement_key = blob_acknowledgement_key(subscription, identity.semantic_id);
        let acknowledgement_record = acknowledgements
            .get(acknowledgement_key.as_slice())?
            .map(|value| decode_blob_acknowledgement_record(value.value()))
            .transpose()?;
        let cursor_key = blob_delivery_cursor_key(subscription, identity.semantic_id);
        let delivery_cursor = cursors
            .get(cursor_key.as_slice())?
            .map(|value| decode_blob_delivery_cursor_record(value.value()))
            .transpose()?;
        validate_blob_candidate_delivery_ledger(
            identity.semantic_id,
            marker,
            pending_record,
            acknowledgement_record,
            delivery_cursor,
        )?;
        candidates.push(BlobSubscriptionCandidate {
            projection: planned.projection.clone(),
            acceptance_marker: marker,
            pending_attempt: pending_record.map(|record| record.attempts),
            acknowledged_attempt: acknowledgement_record.map(|record| record.attempts),
            delivery_cursor,
        });
    }
    require_complete_blob_acceptance_snapshot_write(write, expected_marker)?;
    Ok(candidates)
}

fn validate_blob_candidate_delivery_ledger(
    semantic_id: BlobSemanticId,
    acceptance_marker: u64,
    pending: Option<BlobPendingDeliveryRecord>,
    acknowledgement: Option<BlobAcknowledgementRecord>,
    cursor: Option<BlobDeliveryCursorRecord>,
) -> Result<(), StoreError> {
    if pending.is_some() && acknowledgement.is_some() {
        return Err(StoreError::BlobInvariant(
            "Blob delivery is both pending and acknowledged",
        ));
    }
    let Some(cursor) = cursor else {
        if pending.is_some() || acknowledgement.is_some() {
            return Err(StoreError::BlobInvariant(
                "active Blob delivery is missing its monotonic cursor",
            ));
        }
        return Ok(());
    };
    if cursor.acceptance_marker != acceptance_marker {
        return Err(StoreError::BlobInvariant(
            "Blob delivery cursor differs from its accepted Blob",
        ));
    }
    if let Some(pending) = pending
        && (pending.semantic_id != semantic_id
            || pending.tenure != cursor.tenure
            || pending.attempts != cursor.last_attempt)
    {
        return Err(StoreError::BlobInvariant(
            "pending Blob delivery differs from its monotonic cursor",
        ));
    }
    if let Some(acknowledgement) = acknowledgement
        && (acknowledgement.acceptance_marker != acceptance_marker
            || acknowledgement.tenure != cursor.tenure
            || acknowledgement.tenure != cursor.last_acknowledged_tenure
            || acknowledgement.attempts != cursor.last_acknowledged_attempt
            || acknowledgement.attempts > cursor.last_attempt)
    {
        return Err(StoreError::BlobInvariant(
            "Blob acknowledgement differs from its monotonic cursor",
        ));
    }
    Ok(())
}

fn require_complete_blob_acceptance_snapshot_read(
    read: &redb::ReadTransaction,
    next_marker: u64,
) -> Result<(), StoreError> {
    let high_water = read
        .open_table(METADATA)?
        .get(LAST_BLOB_ACCEPTANCE_MARKER)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: LAST_BLOB_ACCEPTANCE_MARKER,
        })?
        .value();
    if next_marker.checked_sub(1) != Some(high_water) {
        return Err(StoreError::BlobInvariant(
            "Blob acceptance-order snapshot ended before durable acceptance high-water",
        ));
    }
    Ok(())
}

fn require_complete_blob_acceptance_snapshot_write(
    write: &redb::WriteTransaction,
    next_marker: u64,
) -> Result<(), StoreError> {
    let high_water = write
        .open_table(METADATA)?
        .get(LAST_BLOB_ACCEPTANCE_MARKER)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: LAST_BLOB_ACCEPTANCE_MARKER,
        })?
        .value();
    if next_marker.checked_sub(1) != Some(high_water) {
        return Err(StoreError::BlobInvariant(
            "Blob acceptance-order snapshot ended before durable acceptance high-water",
        ));
    }
    Ok(())
}

fn blob_subscription_id(authority: NodeId, key: &BlobSubscriptionKey) -> BlobSubscriptionId {
    let mut digest = Sha256::new();
    digest.update(BLOB_SUBSCRIPTION_ID_DOMAIN);
    digest.update(authority);
    digest.update(
        u16::try_from(key.as_bytes().len())
            .expect("validated Blob subscription key fits u16")
            .to_be_bytes(),
    );
    digest.update(key.as_bytes());
    BlobSubscriptionId(digest.finalize().into())
}

#[derive(Clone, Copy)]
struct BlobDeliveryTokenParts {
    incarnation: u64,
    tenure: u64,
    attempt: u64,
}

fn blob_delivery_token(
    subscription: BlobSubscriptionId,
    semantic_id: BlobSemanticId,
    incarnation: u64,
    tenure: u64,
    attempt: u64,
) -> BlobDeliveryToken {
    debug_assert!(incarnation > 0 && tenure > 0 && attempt > 0);
    let mut bytes = [0u8; BLOB_DELIVERY_TOKEN_BYTES];
    bytes[0] = BLOB_DELIVERY_TOKEN_VERSION;
    bytes[1..9].copy_from_slice(&incarnation.to_be_bytes());
    bytes[9..17].copy_from_slice(&tenure.to_be_bytes());
    bytes[17..25].copy_from_slice(&attempt.to_be_bytes());
    let mut digest = Sha256::new();
    digest.update(BLOB_DELIVERY_TOKEN_DOMAIN);
    digest.update(subscription.as_bytes());
    digest.update(semantic_id.as_bytes());
    digest.update(&bytes[..BLOB_DELIVERY_TOKEN_COUNTER_BYTES]);
    bytes[BLOB_DELIVERY_TOKEN_COUNTER_BYTES..].copy_from_slice(&digest.finalize());
    BlobDeliveryToken(bytes)
}

fn validate_blob_delivery_token_binding(
    subscription: BlobSubscriptionId,
    semantic_id: BlobSemanticId,
    token: BlobDeliveryToken,
) -> Result<BlobDeliveryTokenParts, StoreError> {
    let parts = BlobDeliveryTokenParts {
        incarnation: token.incarnation(),
        tenure: token.tenure(),
        attempt: token.attempt(),
    };
    if token
        != blob_delivery_token(
            subscription,
            semantic_id,
            parts.incarnation,
            parts.tenure,
            parts.attempt,
        )
    {
        return Err(StoreError::BlobDeliveryTokenBindingMismatch);
    }
    Ok(parts)
}

fn encode_blob_subscription_record(record: &BlobSubscriptionRecord) -> Result<Vec<u8>, StoreError> {
    let key_length = u16::try_from(record.operation_key.as_bytes().len()).map_err(|_| {
        StoreError::BlobInvariant("Blob subscription operation key exceeds its bound")
    })?;
    let topic = record.spec.topic.as_str().as_bytes();
    let scope = record.spec.scope.as_str().as_bytes();
    let topic_length = u16::try_from(topic.len())
        .map_err(|_| StoreError::BlobInvariant("Blob subscription topic exceeds its bound"))?;
    let scope_length = u16::try_from(scope.len())
        .map_err(|_| StoreError::BlobInvariant("Blob subscription scope exceeds its bound"))?;
    let mut encoded = Vec::new();
    encoded.push(BLOB_SUBSCRIPTION_VERSION);
    encoded.push(u8::from(record.spec.include_descendant_scopes));
    encoded.extend_from_slice(&record.incarnation.to_be_bytes());
    encoded.extend_from_slice(&key_length.to_be_bytes());
    encoded.extend_from_slice(record.operation_key.as_bytes());
    encoded.extend_from_slice(&topic_length.to_be_bytes());
    encoded.extend_from_slice(topic);
    encoded.extend_from_slice(&scope_length.to_be_bytes());
    encoded.extend_from_slice(scope);
    Ok(encoded)
}

fn decode_blob_subscription_record(bytes: &[u8]) -> Result<BlobSubscriptionRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != BLOB_SUBSCRIPTION_VERSION {
        return Err(StoreError::BlobInvariant(
            "unknown Blob subscription encoding version",
        ));
    }
    let include_descendant_scopes = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => {
            return Err(StoreError::BlobInvariant(
                "invalid Blob subscription descendant flag",
            ));
        }
    };
    let incarnation = cursor.u64()?;
    if incarnation == 0 {
        return Err(StoreError::BlobInvariant(
            "Blob subscription incarnation is zero",
        ));
    }
    let key_length = usize::from(cursor.u16()?);
    let operation_key = BlobSubscriptionKey::new(cursor.take(key_length)?.to_vec())
        .map_err(|_| StoreError::BlobInvariant("invalid Blob subscription operation key"))?;
    let topic = Topic::new(cursor.short_string()?)
        .map_err(|_| StoreError::BlobInvariant("invalid Blob subscription topic"))?;
    let scope = Scope::new(cursor.short_string()?)
        .map_err(|_| StoreError::BlobInvariant("invalid Blob subscription scope"))?;
    cursor.finish()?;
    let record = BlobSubscriptionRecord {
        operation_key,
        spec: BlobSubscriptionSpec {
            topic,
            scope,
            include_descendant_scopes,
        },
        incarnation,
    };
    if encode_blob_subscription_record(&record)?.as_slice() != bytes {
        return Err(StoreError::BlobInvariant(
            "Blob subscription encoding is not canonical",
        ));
    }
    Ok(record)
}

fn blob_pending_delivery_key(subscription: BlobSubscriptionId, marker: u64) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(subscription.as_bytes());
    key[32..].copy_from_slice(&marker.to_be_bytes());
    key
}

fn parse_blob_pending_delivery_key(bytes: &[u8]) -> Result<(BlobSubscriptionId, u64), StoreError> {
    let bytes: [u8; 40] = bytes
        .try_into()
        .map_err(|_| StoreError::BlobInvariant("Blob pending-delivery key has invalid length"))?;
    let subscription = BlobSubscriptionId::from_bytes(
        bytes[..32]
            .try_into()
            .expect("fixed Blob subscription prefix"),
    );
    let marker = u64::from_be_bytes(bytes[32..].try_into().expect("fixed marker suffix"));
    if marker == 0 {
        return Err(StoreError::BlobInvariant(
            "Blob pending-delivery key contains a zero marker",
        ));
    }
    Ok((subscription, marker))
}

fn encode_blob_pending_delivery_record(record: BlobPendingDeliveryRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(49);
    encoded.push(BLOB_PENDING_DELIVERY_VERSION);
    encoded.extend_from_slice(record.semantic_id.as_bytes());
    encoded.extend_from_slice(&record.tenure.to_be_bytes());
    encoded.extend_from_slice(&record.attempts.to_be_bytes());
    encoded
}

fn decode_blob_pending_delivery_record(
    bytes: &[u8],
) -> Result<BlobPendingDeliveryRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != BLOB_PENDING_DELIVERY_VERSION {
        return Err(StoreError::BlobInvariant(
            "unknown Blob pending-delivery encoding version",
        ));
    }
    let semantic_id = BlobSemanticId::new(cursor.array()?);
    let tenure = cursor.u64()?;
    let attempts = cursor.u64()?;
    cursor.finish()?;
    if tenure == 0 || attempts == 0 {
        return Err(StoreError::BlobInvariant(
            "Blob pending-delivery tenure or attempt count is zero",
        ));
    }
    Ok(BlobPendingDeliveryRecord {
        semantic_id,
        tenure,
        attempts,
    })
}

fn blob_acknowledgement_key(
    subscription: BlobSubscriptionId,
    semantic_id: BlobSemanticId,
) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(subscription.as_bytes());
    key[32..].copy_from_slice(semantic_id.as_bytes());
    key
}

fn parse_blob_acknowledgement_key(
    bytes: &[u8],
) -> Result<(BlobSubscriptionId, BlobSemanticId), StoreError> {
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| StoreError::BlobInvariant("Blob acknowledgement key has invalid length"))?;
    Ok((
        BlobSubscriptionId::from_bytes(
            bytes[..32]
                .try_into()
                .expect("fixed Blob subscription prefix"),
        ),
        BlobSemanticId::new(bytes[32..].try_into().expect("fixed semantic suffix")),
    ))
}

fn blob_delivery_cursor_key(
    subscription: BlobSubscriptionId,
    semantic_id: BlobSemanticId,
) -> [u8; 64] {
    blob_acknowledgement_key(subscription, semantic_id)
}

fn parse_blob_delivery_cursor_key(
    bytes: &[u8],
) -> Result<(BlobSubscriptionId, BlobSemanticId), StoreError> {
    parse_blob_acknowledgement_key(bytes)
}

fn encode_blob_acknowledgement_record(record: BlobAcknowledgementRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(25);
    encoded.push(BLOB_ACKNOWLEDGEMENT_VERSION);
    encoded.extend_from_slice(&record.acceptance_marker.to_be_bytes());
    encoded.extend_from_slice(&record.tenure.to_be_bytes());
    encoded.extend_from_slice(&record.attempts.to_be_bytes());
    encoded
}

fn decode_blob_acknowledgement_record(
    bytes: &[u8],
) -> Result<BlobAcknowledgementRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != BLOB_ACKNOWLEDGEMENT_VERSION {
        return Err(StoreError::BlobInvariant(
            "unknown Blob acknowledgement encoding version",
        ));
    }
    let acceptance_marker = cursor.u64()?;
    let tenure = cursor.u64()?;
    let attempts = cursor.u64()?;
    cursor.finish()?;
    if acceptance_marker == 0 || tenure == 0 || attempts == 0 {
        return Err(StoreError::BlobInvariant(
            "Blob acknowledgement contains a zero marker, tenure, or attempt",
        ));
    }
    Ok(BlobAcknowledgementRecord {
        acceptance_marker,
        tenure,
        attempts,
    })
}

fn encode_blob_delivery_cursor_record(record: BlobDeliveryCursorRecord) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(41);
    encoded.push(BLOB_DELIVERY_CURSOR_VERSION);
    encoded.extend_from_slice(&record.acceptance_marker.to_be_bytes());
    encoded.extend_from_slice(&record.tenure.to_be_bytes());
    encoded.extend_from_slice(&record.last_attempt.to_be_bytes());
    encoded.extend_from_slice(&record.last_acknowledged_tenure.to_be_bytes());
    encoded.extend_from_slice(&record.last_acknowledged_attempt.to_be_bytes());
    encoded
}

fn decode_blob_delivery_cursor_record(
    bytes: &[u8],
) -> Result<BlobDeliveryCursorRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != BLOB_DELIVERY_CURSOR_VERSION {
        return Err(StoreError::BlobInvariant(
            "unknown Blob delivery-cursor encoding version",
        ));
    }
    let record = BlobDeliveryCursorRecord {
        acceptance_marker: cursor.u64()?,
        tenure: cursor.u64()?,
        last_attempt: cursor.u64()?,
        last_acknowledged_tenure: cursor.u64()?,
        last_acknowledged_attempt: cursor.u64()?,
    };
    cursor.finish()?;
    if record.acceptance_marker == 0 || record.tenure == 0 || record.last_attempt == 0 {
        return Err(StoreError::BlobInvariant(
            "Blob delivery cursor contains a zero marker, tenure, or attempt",
        ));
    }
    if (record.last_acknowledged_tenure == 0) != (record.last_acknowledged_attempt == 0)
        || record.last_acknowledged_tenure > record.tenure
        || (record.last_acknowledged_tenure == record.tenure
            && record.last_acknowledged_attempt > record.last_attempt)
    {
        return Err(StoreError::BlobInvariant(
            "Blob delivery cursor contains an invalid acknowledgement high-water",
        ));
    }
    Ok(record)
}

fn load_blob_by_semantic_from_read(
    read: &redb::ReadTransaction,
    semantic_id: BlobSemanticId,
) -> Result<Option<BlobSubscriptionIdentity>, StoreError> {
    blob_subscription_identity_read(read, semantic_id)
}

fn load_blob_by_semantic_from_write(
    write: &redb::WriteTransaction,
    semantic_id: BlobSemanticId,
) -> Result<Option<BlobSubscriptionIdentity>, StoreError> {
    blob_subscription_identity_write(write, semantic_id)
}

fn validate_blob_selector_generation(
    generation: u64,
    subscription_count: u64,
) -> Result<(), StoreError> {
    if generation < subscription_count || !(generation - subscription_count).is_multiple_of(2) {
        return Err(StoreError::BlobInvariant(
            "Blob selector mutation generation is inconsistent with the live subscription count",
        ));
    }
    Ok(())
}

fn require_blob_subscription_accounting(
    write: &redb::WriteTransaction,
    subscriptions: u64,
    pending: u64,
    acknowledgements: u64,
    cursors: u64,
) -> Result<u64, StoreError> {
    let metadata = write.open_table(METADATA)?;
    for (field, reconstructed) in [
        (BLOB_SUBSCRIPTION_COUNT, subscriptions),
        (BLOB_PENDING_DELIVERY_COUNT, pending),
        (BLOB_ACKNOWLEDGEMENT_COUNT, acknowledgements),
        (BLOB_DELIVERY_CURSOR_COUNT, cursors),
    ] {
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
    let generation = metadata
        .get(BLOB_SELECTOR_GENERATION)?
        .ok_or(StoreError::MissingAccountingMetadata {
            field: BLOB_SELECTOR_GENERATION,
        })?
        .value();
    validate_blob_selector_generation(generation, subscriptions)?;
    Ok(generation)
}

fn is_blob_subscription_table(name: &str) -> bool {
    name == BLOB_ACCEPTANCE_ORDER.name()
        || name == BLOB_SUBSCRIPTIONS.name()
        || name == BLOB_SUBSCRIPTION_PENDING.name()
        || name == BLOB_DELIVERY_ACKNOWLEDGEMENTS.name()
        || name == BLOB_DELIVERY_CURSORS.name()
}

pub(crate) fn audit_blob_subscription_tables(
    write: &redb::WriteTransaction,
) -> Result<BlobSubscriptionStats, StoreError> {
    if write
        .list_multimap_tables()?
        .any(|table| is_blob_subscription_table(table.name()))
    {
        return Err(StoreError::BlobInvariant(
            "Blob subscription schema has the wrong table kind",
        ));
    }
    let table_names = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let tables_present = [
        BLOB_ACCEPTANCE_ORDER.name(),
        BLOB_SUBSCRIPTIONS.name(),
        BLOB_SUBSCRIPTION_PENDING.name(),
        BLOB_DELIVERY_ACKNOWLEDGEMENTS.name(),
        BLOB_DELIVERY_CURSORS.name(),
    ]
    .into_iter()
    .filter(|name| table_names.contains(*name))
    .count();
    let metadata_presence = {
        let metadata = write.open_table(METADATA)?;
        [
            metadata.get(BLOB_SUBSCRIPTION_COUNT)?.is_some(),
            metadata.get(BLOB_PENDING_DELIVERY_COUNT)?.is_some(),
            metadata.get(BLOB_ACKNOWLEDGEMENT_COUNT)?.is_some(),
            metadata.get(BLOB_DELIVERY_CURSOR_COUNT)?.is_some(),
            metadata.get(BLOB_SELECTOR_GENERATION)?.is_some(),
        ]
    };
    let metadata_present = metadata_presence.iter().filter(|present| **present).count();
    if tables_present == 0 && metadata_present == 0 {
        backfill_blob_acceptance_order(write)?;
        write.open_table(BLOB_SUBSCRIPTIONS)?;
        write.open_table(BLOB_SUBSCRIPTION_PENDING)?;
        write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?;
        write.open_table(BLOB_DELIVERY_CURSORS)?;
        let mut metadata = write.open_table(METADATA)?;
        metadata.insert(BLOB_SUBSCRIPTION_COUNT, 0)?;
        metadata.insert(BLOB_PENDING_DELIVERY_COUNT, 0)?;
        metadata.insert(BLOB_ACKNOWLEDGEMENT_COUNT, 0)?;
        metadata.insert(BLOB_DELIVERY_CURSOR_COUNT, 0)?;
        metadata.insert(BLOB_SELECTOR_GENERATION, 0)?;
        drop(metadata);
        audit_blob_acceptance_order_write(write)?;
        return audit_blob_subscription_rows_write(write);
    }
    if tables_present != 5 || metadata_presence.iter().any(|present| !present) {
        return Err(StoreError::BlobInvariant(
            "Blob subscription schema group is incomplete",
        ));
    }
    audit_blob_acceptance_order_write(write)?;
    audit_blob_subscription_rows_write(write)
}

fn backfill_blob_acceptance_order(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let markers = write.open_table(BLOB_ACCEPTANCE_MARKERS)?;
    let publications = write.open_table(BLOB_PUBLICATIONS)?;
    let mut ordered = BTreeMap::<u64, [u8; 32]>::new();
    for row in markers.iter()? {
        let (transfer, marker) = row?;
        let transfer = parse_blob_subscription_transfer_id(transfer.value())?;
        let marker = marker.value();
        if marker == 0
            || publications.get(transfer.as_bytes().as_slice())?.is_none()
            || ordered.insert(marker, *transfer.as_bytes()).is_some()
        {
            return Err(StoreError::BlobInvariant(
                "legacy Blob acceptance markers cannot be backfilled exactly",
            ));
        }
    }
    if ordered
        .keys()
        .copied()
        .ne(1..=u64::try_from(ordered.len())
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?)
        || publications.len()? != markers.len()?
    {
        return Err(StoreError::BlobInvariant(
            "legacy Blob acceptance markers are not a complete consecutive history",
        ));
    }
    let mut order = write.open_table(BLOB_ACCEPTANCE_ORDER)?;
    for (marker, transfer) in ordered {
        order.insert(marker, transfer.as_slice())?;
    }
    Ok(())
}

fn audit_blob_acceptance_order_write(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let order = write.open_table(BLOB_ACCEPTANCE_ORDER)?;
    let markers = write.open_table(BLOB_ACCEPTANCE_MARKERS)?;
    let publications = write.open_table(BLOB_PUBLICATIONS)?;
    if order.len()? != markers.len()? || order.len()? != publications.len()? {
        return Err(StoreError::BlobInvariant(
            "Blob acceptance-order index has missing or orphan rows",
        ));
    }
    let mut expected = 1u64;
    for row in order.iter()? {
        let (marker, transfer) = row?;
        let marker = marker.value();
        let transfer = parse_blob_subscription_transfer_id(transfer.value())?;
        if marker != expected
            || publications.get(transfer.as_bytes().as_slice())?.is_none()
            || markers
                .get(transfer.as_bytes().as_slice())?
                .map(|value| value.value())
                != Some(marker)
        {
            return Err(StoreError::BlobInvariant(
                "Blob acceptance-order index differs from its forward authority",
            ));
        }
        expected = expected
            .checked_add(1)
            .ok_or(StoreError::AcceptanceMarkerExhausted)?;
    }
    require_complete_blob_acceptance_snapshot_write(write, expected)
}

fn audit_blob_subscription_rows_write(
    write: &redb::WriteTransaction,
) -> Result<BlobSubscriptionStats, StoreError> {
    let authority = read_mission_binding(write)?;
    let mut subscriptions = BTreeMap::new();
    for row in write.open_table(BLOB_SUBSCRIPTIONS)?.iter()? {
        let (key, value) = row?;
        let id = parse_blob_subscription_id(key.value())?;
        let record = decode_blob_subscription_record(value.value())?;
        let authority = authority.ok_or(StoreError::BlobInvariant(
            "unbound store contains Blob subscriptions",
        ))?;
        if blob_subscription_id(authority, &record.operation_key) != id {
            return Err(StoreError::BlobInvariant(
                "Blob subscription identifier differs from its operation key",
            ));
        }
        subscriptions.insert(id, record);
    }
    audit_blob_subscription_ledgers_write(write, &subscriptions)?;
    let stats = BlobSubscriptionStats {
        subscriptions: write.open_table(BLOB_SUBSCRIPTIONS)?.len()?,
        pending_deliveries: write.open_table(BLOB_SUBSCRIPTION_PENDING)?.len()?,
        acknowledged_deliveries: write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.len()?,
        delivery_cursors: write.open_table(BLOB_DELIVERY_CURSORS)?.len()?,
        selector_generation: write
            .open_table(METADATA)?
            .get(BLOB_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: BLOB_SELECTOR_GENERATION,
            })?
            .value(),
    };
    validate_blob_subscription_incarnations(&subscriptions, stats.selector_generation)?;
    validate_blob_subscription_stats(write, stats)?;
    Ok(stats)
}

fn validate_blob_subscription_incarnations(
    subscriptions: &BTreeMap<BlobSubscriptionId, BlobSubscriptionRecord>,
    selector_generation: u64,
) -> Result<(), StoreError> {
    let mut incarnations = BTreeSet::new();
    for record in subscriptions.values() {
        if record.incarnation == 0
            || record.incarnation > selector_generation
            || !incarnations.insert(record.incarnation)
        {
            return Err(StoreError::BlobInvariant(
                "Blob subscription incarnation is invalid or reused",
            ));
        }
    }
    Ok(())
}

fn audit_blob_subscription_ledgers_write(
    write: &redb::WriteTransaction,
    subscriptions: &BTreeMap<BlobSubscriptionId, BlobSubscriptionRecord>,
) -> Result<(), StoreError> {
    let mut pending_records = BTreeMap::new();
    for row in write.open_table(BLOB_SUBSCRIPTION_PENDING)?.iter()? {
        let (key, value) = row?;
        let (subscription, marker) = parse_blob_pending_delivery_key(key.value())?;
        let record = decode_blob_pending_delivery_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::BlobInvariant(
                "pending Blob delivery references a missing subscription",
            ))?
            .spec;
        let blob = load_blob_by_semantic_from_write(write, record.semantic_id)?.ok_or(
            StoreError::BlobInvariant("pending Blob delivery references a missing Blob"),
        )?;
        if blob.acceptance_marker != marker || !spec.matches_identity(&blob) {
            return Err(StoreError::BlobInvariant(
                "pending Blob delivery differs from its subscription ledger",
            ));
        }
        if pending_records
            .insert((subscription, record.semantic_id), record)
            .is_some()
        {
            return Err(StoreError::BlobInvariant(
                "duplicate pending Blob semantic delivery",
            ));
        }
    }
    let mut acknowledgement_records = BTreeMap::new();
    for row in write.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
        let (key, value) = row?;
        let (subscription, semantic_id) = parse_blob_acknowledgement_key(key.value())?;
        let record = decode_blob_acknowledgement_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::BlobInvariant(
                "Blob acknowledgement references a missing subscription",
            ))?
            .spec;
        let blob = load_blob_by_semantic_from_write(write, semantic_id)?.ok_or(
            StoreError::BlobInvariant("Blob acknowledgement references a missing Blob"),
        )?;
        if blob.acceptance_marker != record.acceptance_marker || !spec.matches_identity(&blob) {
            return Err(StoreError::BlobInvariant(
                "Blob acknowledgement differs from its subscription ledger",
            ));
        }
        if pending_records.contains_key(&(subscription, semantic_id)) {
            return Err(StoreError::BlobInvariant(
                "Blob delivery is both pending and acknowledged",
            ));
        }
        acknowledgement_records.insert((subscription, semantic_id), record);
    }
    let mut cursor_ids = BTreeSet::new();
    for row in write.open_table(BLOB_DELIVERY_CURSORS)?.iter()? {
        let (key, value) = row?;
        let (subscription, semantic_id) = parse_blob_delivery_cursor_key(key.value())?;
        let cursor = decode_blob_delivery_cursor_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::BlobInvariant(
                "Blob delivery cursor references a missing subscription",
            ))?
            .spec;
        let blob = load_blob_by_semantic_from_write(write, semantic_id)?.ok_or(
            StoreError::BlobInvariant("Blob delivery cursor references a missing Blob"),
        )?;
        if !spec.matches_identity(&blob) {
            return Err(StoreError::BlobInvariant(
                "Blob delivery cursor differs from its subscription",
            ));
        }
        let id = (subscription, semantic_id);
        validate_blob_candidate_delivery_ledger(
            semantic_id,
            blob.acceptance_marker,
            pending_records.get(&id).copied(),
            acknowledgement_records.get(&id).copied(),
            Some(cursor),
        )?;
        cursor_ids.insert(id);
    }
    if pending_records
        .keys()
        .chain(acknowledgement_records.keys())
        .any(|id| !cursor_ids.contains(id))
    {
        return Err(StoreError::BlobInvariant(
            "active Blob delivery is missing its monotonic cursor",
        ));
    }
    Ok(())
}

fn validate_blob_subscription_stats(
    write: &redb::WriteTransaction,
    stats: BlobSubscriptionStats,
) -> Result<(), StoreError> {
    if stats.subscriptions > MAX_BLOB_SUBSCRIPTIONS
        || stats.pending_deliveries > MAX_BLOB_PENDING_DELIVERIES
        || stats.acknowledged_deliveries > MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS
        || stats
            .pending_deliveries
            .checked_add(stats.acknowledged_deliveries)
            .ok_or(StoreError::ItemCountAccountingOverflow)?
            > MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS
        || stats.delivery_cursors > MAX_BLOB_DELIVERY_CURSORS
    {
        return Err(StoreError::BlobInvariant(
            "Blob subscription tables exceed their bounded cardinality",
        ));
    }
    require_blob_subscription_accounting(
        write,
        stats.subscriptions,
        stats.pending_deliveries,
        stats.acknowledged_deliveries,
        stats.delivery_cursors,
    )?;
    Ok(())
}

pub(crate) fn inspect_blob_subscription_tables(
    read: &redb::ReadTransaction,
) -> Result<BlobSubscriptionStats, StoreError> {
    if read
        .list_multimap_tables()?
        .any(|table| is_blob_subscription_table(table.name()))
    {
        return Err(StoreError::BlobInvariant(
            "Blob subscription schema has the wrong table kind",
        ));
    }
    let table_names = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let tables_present = [
        BLOB_ACCEPTANCE_ORDER.name(),
        BLOB_SUBSCRIPTIONS.name(),
        BLOB_SUBSCRIPTION_PENDING.name(),
        BLOB_DELIVERY_ACKNOWLEDGEMENTS.name(),
        BLOB_DELIVERY_CURSORS.name(),
    ]
    .into_iter()
    .filter(|name| table_names.contains(*name))
    .count();
    let metadata = read.open_table(METADATA)?;
    let metadata_presence = [
        metadata.get(BLOB_SUBSCRIPTION_COUNT)?.is_some(),
        metadata.get(BLOB_PENDING_DELIVERY_COUNT)?.is_some(),
        metadata.get(BLOB_ACKNOWLEDGEMENT_COUNT)?.is_some(),
        metadata.get(BLOB_DELIVERY_CURSOR_COUNT)?.is_some(),
        metadata.get(BLOB_SELECTOR_GENERATION)?.is_some(),
    ];
    if tables_present == 0 && metadata_presence.iter().all(|present| !present) {
        // A predecessor Blob store remains safely inspectable read-only. Its
        // first writable open atomically backfills the inverse marker index and
        // empty ledger group before application delivery becomes available.
        return Ok(BlobSubscriptionStats::default());
    }
    if tables_present != 5 || metadata_presence.iter().any(|present| !present) {
        return Err(StoreError::BlobInvariant(
            "Blob subscription schema group is incomplete",
        ));
    }
    audit_blob_acceptance_order_read(read)?;

    let authority = read_mission_binding_read(read)?;
    let mut subscriptions = BTreeMap::new();
    for row in read.open_table(BLOB_SUBSCRIPTIONS)?.iter()? {
        let (key, value) = row?;
        let id = parse_blob_subscription_id(key.value())?;
        let record = decode_blob_subscription_record(value.value())?;
        let authority = authority.ok_or(StoreError::BlobInvariant(
            "unbound store contains Blob subscriptions",
        ))?;
        if blob_subscription_id(authority, &record.operation_key) != id {
            return Err(StoreError::BlobInvariant(
                "Blob subscription identifier differs from its operation key",
            ));
        }
        subscriptions.insert(id, record);
    }
    let mut pending_records = BTreeMap::new();
    for row in read.open_table(BLOB_SUBSCRIPTION_PENDING)?.iter()? {
        let (key, value) = row?;
        let (subscription, marker) = parse_blob_pending_delivery_key(key.value())?;
        let record = decode_blob_pending_delivery_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::BlobInvariant(
                "pending Blob delivery references a missing subscription",
            ))?
            .spec;
        let blob = load_blob_by_semantic_from_read(read, record.semantic_id)?.ok_or(
            StoreError::BlobInvariant("pending Blob delivery references a missing Blob"),
        )?;
        if blob.acceptance_marker != marker || !spec.matches_identity(&blob) {
            return Err(StoreError::BlobInvariant(
                "pending Blob delivery differs from its subscription ledger",
            ));
        }
        if pending_records
            .insert((subscription, record.semantic_id), record)
            .is_some()
        {
            return Err(StoreError::BlobInvariant(
                "duplicate pending Blob semantic delivery",
            ));
        }
    }
    let mut acknowledgement_records = BTreeMap::new();
    for row in read.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.iter()? {
        let (key, value) = row?;
        let (subscription, semantic_id) = parse_blob_acknowledgement_key(key.value())?;
        let record = decode_blob_acknowledgement_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::BlobInvariant(
                "Blob acknowledgement references a missing subscription",
            ))?
            .spec;
        let blob = load_blob_by_semantic_from_read(read, semantic_id)?.ok_or(
            StoreError::BlobInvariant("Blob acknowledgement references a missing Blob"),
        )?;
        if blob.acceptance_marker != record.acceptance_marker || !spec.matches_identity(&blob) {
            return Err(StoreError::BlobInvariant(
                "Blob acknowledgement differs from its subscription ledger",
            ));
        }
        if pending_records.contains_key(&(subscription, semantic_id)) {
            return Err(StoreError::BlobInvariant(
                "Blob delivery is both pending and acknowledged",
            ));
        }
        acknowledgement_records.insert((subscription, semantic_id), record);
    }
    let mut cursor_ids = BTreeSet::new();
    for row in read.open_table(BLOB_DELIVERY_CURSORS)?.iter()? {
        let (key, value) = row?;
        let (subscription, semantic_id) = parse_blob_delivery_cursor_key(key.value())?;
        let cursor = decode_blob_delivery_cursor_record(value.value())?;
        let spec = &subscriptions
            .get(&subscription)
            .ok_or(StoreError::BlobInvariant(
                "Blob delivery cursor references a missing subscription",
            ))?
            .spec;
        let blob = load_blob_by_semantic_from_read(read, semantic_id)?.ok_or(
            StoreError::BlobInvariant("Blob delivery cursor references a missing Blob"),
        )?;
        if !spec.matches_identity(&blob) {
            return Err(StoreError::BlobInvariant(
                "Blob delivery cursor differs from its subscription",
            ));
        }
        let id = (subscription, semantic_id);
        validate_blob_candidate_delivery_ledger(
            semantic_id,
            blob.acceptance_marker,
            pending_records.get(&id).copied(),
            acknowledgement_records.get(&id).copied(),
            Some(cursor),
        )?;
        cursor_ids.insert(id);
    }
    if pending_records
        .keys()
        .chain(acknowledgement_records.keys())
        .any(|id| !cursor_ids.contains(id))
    {
        return Err(StoreError::BlobInvariant(
            "active Blob delivery is missing its monotonic cursor",
        ));
    }
    let stats = BlobSubscriptionStats {
        subscriptions: read.open_table(BLOB_SUBSCRIPTIONS)?.len()?,
        pending_deliveries: read.open_table(BLOB_SUBSCRIPTION_PENDING)?.len()?,
        acknowledged_deliveries: read.open_table(BLOB_DELIVERY_ACKNOWLEDGEMENTS)?.len()?,
        delivery_cursors: read.open_table(BLOB_DELIVERY_CURSORS)?.len()?,
        selector_generation: metadata
            .get(BLOB_SELECTOR_GENERATION)?
            .ok_or(StoreError::MissingAccountingMetadata {
                field: BLOB_SELECTOR_GENERATION,
            })?
            .value(),
    };
    validate_blob_subscription_incarnations(&subscriptions, stats.selector_generation)?;
    if stats.subscriptions > MAX_BLOB_SUBSCRIPTIONS
        || stats.pending_deliveries > MAX_BLOB_PENDING_DELIVERIES
        || stats.acknowledged_deliveries > MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS
        || stats
            .pending_deliveries
            .checked_add(stats.acknowledged_deliveries)
            .ok_or(StoreError::ItemCountAccountingOverflow)?
            > MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS
        || stats.delivery_cursors > MAX_BLOB_DELIVERY_CURSORS
    {
        return Err(StoreError::BlobInvariant(
            "Blob subscription tables exceed their bounded cardinality",
        ));
    }
    for (field, reconstructed) in [
        (BLOB_SUBSCRIPTION_COUNT, stats.subscriptions),
        (BLOB_PENDING_DELIVERY_COUNT, stats.pending_deliveries),
        (BLOB_ACKNOWLEDGEMENT_COUNT, stats.acknowledged_deliveries),
        (BLOB_DELIVERY_CURSOR_COUNT, stats.delivery_cursors),
    ] {
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
    validate_blob_selector_generation(stats.selector_generation, stats.subscriptions)?;
    Ok(stats)
}

fn audit_blob_acceptance_order_read(read: &redb::ReadTransaction) -> Result<(), StoreError> {
    let order = read.open_table(BLOB_ACCEPTANCE_ORDER)?;
    let markers = read.open_table(BLOB_ACCEPTANCE_MARKERS)?;
    let publications = read.open_table(BLOB_PUBLICATIONS)?;
    if order.len()? != markers.len()? || order.len()? != publications.len()? {
        return Err(StoreError::BlobInvariant(
            "Blob acceptance-order index has missing or orphan rows",
        ));
    }
    let mut expected = 1u64;
    for row in order.iter()? {
        let (marker, transfer) = row?;
        let marker = marker.value();
        let transfer = parse_blob_subscription_transfer_id(transfer.value())?;
        if marker != expected
            || publications.get(transfer.as_bytes().as_slice())?.is_none()
            || markers
                .get(transfer.as_bytes().as_slice())?
                .map(|value| value.value())
                != Some(marker)
        {
            return Err(StoreError::BlobInvariant(
                "Blob acceptance-order index differs from its forward authority",
            ));
        }
        expected = expected
            .checked_add(1)
            .ok_or(StoreError::AcceptanceMarkerExhausted)?;
    }
    require_complete_blob_acceptance_snapshot_read(read, expected)
}

fn parse_blob_subscription_id(bytes: &[u8]) -> Result<BlobSubscriptionId, StoreError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        StoreError::BlobInvariant("Blob subscription identifier has invalid length")
    })?;
    Ok(BlobSubscriptionId::from_bytes(bytes))
}

fn parse_blob_subscription_transfer_id(bytes: &[u8]) -> Result<BlobTransferId, StoreError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        StoreError::BlobInvariant("Blob acceptance-order transfer has invalid length")
    })?;
    Ok(BlobTransferId::new(bytes))
}
