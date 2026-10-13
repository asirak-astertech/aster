use std::collections::{BTreeMap, BTreeSet};

use aster_mesh::{CustodyAge, CustodyContinuity, CustodyError, CustodySample};
use redb::{
    MultimapTableHandle, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};
use sha2::{Digest, Sha256};

use super::{BlobSemanticId, BlobStoreError, BlobStoreStats, BlobTransferId, StoreError, depot};

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_BLOB_LIFECYCLE_MIGRATION_FAULT: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    pub(crate) static TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
    static TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS: std::cell::Cell<u64> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
pub(crate) fn reset_lifecycle_schema_enumerations_for_test() {
    TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS.set(0);
}

#[cfg(test)]
pub(crate) fn take_lifecycle_schema_enumerations_for_test() -> u64 {
    TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS.replace(0)
}

/// Default permanent physical-lineage fence count cap.
pub const DEFAULT_MAX_BLOB_LINEAGE_FENCE_ROWS: u64 = 65_536;
/// Default permanent physical-lineage fence encoded-byte cap (16 MiB).
pub const DEFAULT_MAX_BLOB_LINEAGE_FENCE_BYTES: u64 = 16 * 1024 * 1024;
/// Default permanent accepted-publication replay fence count cap.
pub const DEFAULT_MAX_BLOB_REPLAY_FENCE_ROWS: u64 = 65_536;
/// Default permanent accepted-publication replay fence encoded-byte cap (16 MiB).
pub const DEFAULT_MAX_BLOB_REPLAY_FENCE_BYTES: u64 = 16 * 1024 * 1024;
/// Default combined live and retained Blob-publication lifecycle row cap.
pub const DEFAULT_MAX_BLOB_PUBLICATION_LIFECYCLE_ROWS: u64 = 65_536;
/// Default operation/publication retirement evidence retention (45 days).
pub(crate) const DEFAULT_BLOB_RETIREMENT_RETENTION_MS: u64 = 45 * 24 * 60 * 60 * 1_000;

/// Dedicated non-evictable Blob lifecycle authority limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobLifecycleLimits {
    max_lineage_rows: u64,
    max_lineage_bytes: u64,
    max_replay_rows: u64,
    max_replay_bytes: u64,
    max_publication_rows: u64,
    retain_for_ms: u64,
}

impl BlobLifecycleLimits {
    /// Conservative selected-profile lifecycle authority limits.
    pub const DEFAULT: Self = Self {
        max_lineage_rows: DEFAULT_MAX_BLOB_LINEAGE_FENCE_ROWS,
        max_lineage_bytes: DEFAULT_MAX_BLOB_LINEAGE_FENCE_BYTES,
        max_replay_rows: DEFAULT_MAX_BLOB_REPLAY_FENCE_ROWS,
        max_replay_bytes: DEFAULT_MAX_BLOB_REPLAY_FENCE_BYTES,
        max_publication_rows: DEFAULT_MAX_BLOB_PUBLICATION_LIFECYCLE_ROWS,
        retain_for_ms: DEFAULT_BLOB_RETIREMENT_RETENTION_MS,
    };

    /// Constructs nonzero security-fence and publication-lifecycle limits.
    pub const fn new(
        max_lineage_rows: u64,
        max_lineage_bytes: u64,
        max_replay_rows: u64,
        max_replay_bytes: u64,
        max_publication_rows: u64,
    ) -> Result<Self, BlobStoreError> {
        if max_lineage_rows == 0
            || max_lineage_bytes == 0
            || max_replay_rows == 0
            || max_replay_bytes == 0
            || max_publication_rows == 0
        {
            return Err(BlobStoreError::InvalidLifecycleLimits);
        }
        Ok(Self {
            max_lineage_rows,
            max_lineage_bytes,
            max_replay_rows,
            max_replay_bytes,
            max_publication_rows,
            retain_for_ms: DEFAULT_BLOB_RETIREMENT_RETENTION_MS,
        })
    }

    /// Maximum permanent physical-lineage fence rows.
    pub const fn max_lineage_rows(self) -> u64 {
        self.max_lineage_rows
    }

    /// Maximum encoded bytes across permanent physical-lineage fences.
    pub const fn max_lineage_bytes(self) -> u64 {
        self.max_lineage_bytes
    }

    /// Maximum permanent accepted-publication replay fence rows.
    pub const fn max_replay_rows(self) -> u64 {
        self.max_replay_rows
    }

    /// Maximum encoded bytes across permanent accepted-publication replay fences.
    pub const fn max_replay_bytes(self) -> u64 {
        self.max_replay_bytes
    }

    /// Maximum combined live and retained Blob-publication lifecycle rows.
    pub const fn max_publication_rows(self) -> u64 {
        self.max_publication_rows
    }

    /// Conservative lower-bound age retained for retirement evidence.
    pub(crate) const fn retain_for_ms(self) -> u64 {
        self.retain_for_ms
    }
}

impl Default for BlobLifecycleLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

pub(crate) const BLOB_LIFECYCLE_METADATA: TableDefinition<&str, u64> =
    TableDefinition::new("aster.blob-lifecycle-metadata.v1");
pub(crate) const BLOB_VARIANT_REFERENCES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-variant-references.v1");
pub(crate) const BLOB_LINEAGE_FENCES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-lineage-fences.v1");
pub(crate) const BLOB_REPLAY_FENCES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-replay-fences.v1");
// Expiry removes the bounded publication record but not the causal frontier it
// established.  This fixed-width binding lets startup audit prove which
// remaining frontier row belongs to an expired permanent replay fence without
// retaining topic/scope lookup metadata.
pub(crate) const BLOB_REPLAY_CAUSAL_FENCES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-replay-causal-fences.v1");
pub(crate) const BLOB_MAINTENANCE_CURSORS: TableDefinition<u8, &[u8]> =
    TableDefinition::new("aster.blob-maintenance-cursors.v1");
pub(crate) const BLOB_OPERATION_OWNERS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-operation-owners.v1");
pub(crate) const BLOB_DELIVERY_OWNERS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-delivery-owners.v1");
pub(crate) const BLOB_RETENTION_DEADLINES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-retention-deadlines.v1");
/// Exact point-resolution authority for every retained publication and
/// operation, including records created before a custody clock is available.
pub(crate) const BLOB_RETIREMENT_RESOLVERS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-retirement-resolvers.v1");

const BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD: &str = "schema_version";
const BLOB_LIFECYCLE_SCHEMA_VERSION: u64 = 4;
const BLOB_LINEAGE_ROWS: &str = "lineage_rows";
const BLOB_LINEAGE_BYTES: &str = "lineage_bytes";
const BLOB_REPLAY_ROWS: &str = "replay_rows";
const BLOB_REPLAY_BYTES: &str = "replay_bytes";
const BLOB_PUBLICATION_ROWS: &str = "publication_rows";
const BLOB_REFERENCE_ROWS: &str = "reference_rows";
const BLOB_OPERATION_OWNER_ROWS: &str = "operation_owner_rows";
const BLOB_DELIVERY_OWNER_ROWS: &str = "delivery_owner_rows";
const BLOB_DEADLINE_ROWS: &str = "deadline_rows";
const BLOB_RETIREMENT_RESOLVER_ROWS: &str = "retirement_resolver_rows";
const BLOB_RETIRED_PUBLICATION_ROWS: &str = "retired_publication_rows";
const BLOB_RETIRED_OPERATION_ROWS: &str = "retired_operation_rows";
const BLOB_NEXT_RETIREMENT_GENERATION: &str = "next_retirement_generation";
const BLOB_LIFECYCLE_METADATA_FIELDS: [&str; 14] = [
    BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
    BLOB_LINEAGE_ROWS,
    BLOB_LINEAGE_BYTES,
    BLOB_REPLAY_ROWS,
    BLOB_REPLAY_BYTES,
    BLOB_PUBLICATION_ROWS,
    BLOB_REFERENCE_ROWS,
    BLOB_OPERATION_OWNER_ROWS,
    BLOB_DELIVERY_OWNER_ROWS,
    BLOB_DEADLINE_ROWS,
    BLOB_RETIREMENT_RESOLVER_ROWS,
    BLOB_RETIRED_PUBLICATION_ROWS,
    BLOB_RETIRED_OPERATION_ROWS,
    BLOB_NEXT_RETIREMENT_GENERATION,
];

pub(crate) const PREDECESSOR_PUBLICATION_RECORD_VERSION: u8 = 4;
const CURRENT_PUBLICATION_RECORD_VERSION: u8 = 5;
pub(crate) const LIFECYCLE_V1_PUBLICATION_RECORD_VERSION: u8 = 3;
const CURRENT_OPERATION_RECORD_VERSION: u8 = 2;

const RECORD_VERSION: u8 = 1;
const RECLAIMED_LINEAGE_FENCE_VERSION: u8 = 2;
pub(crate) const PUBLICATION_STATE_LIVE_TAG: u8 = 1;
pub(crate) const PUBLICATION_STATE_RETIRED_TAG: u8 = 2;
const OPERATION_STATE_ACTIVE_TAG: u8 = 1;
const OPERATION_STATE_RETIRED_TAG: u8 = 2;
const VARIANT_REFERENCE_PUBLICATION_TAG: u8 = 1;
const VARIANT_REFERENCE_PENDING_SOURCE_TAG: u8 = 2;
const MAINTENANCE_NEXT_CLASS_KEY: u8 = 0;
const MAINTENANCE_CURSOR_VERSION: u8 = 1;
const MAINTENANCE_CURSOR_UNSET_TAG: u8 = 0;
const MAINTENANCE_CURSOR_POSITION_TAG: u8 = 1;
const MAINTENANCE_PUBLICATION_SOURCE_TAG: u8 = 1;
const MAINTENANCE_PENDING_SOURCE_TAG: u8 = 2;
const MAINTENANCE_INVALID_PENDING_SOURCE_TAG: u8 = 1;
const MAINTENANCE_CARRIER_SOURCE_TAG: u8 = 2;
const MAINTENANCE_DELETION_MANIFEST_TAG: u8 = 1;
const MAINTENANCE_DELETION_CHUNK_TAG: u8 = 2;
const MAINTENANCE_DELETION_CHUNK_RESUME_TAG: u8 = 3;
const MAINTENANCE_DELETION_MANIFEST_RESUME_TAG: u8 = 4;

pub(crate) fn deletion_manifest_cursor_position(variant: super::BlobVariantId) -> [u8; 33] {
    let mut position = [0u8; 33];
    position[0] = MAINTENANCE_DELETION_MANIFEST_TAG;
    position[1..].copy_from_slice(variant.as_bytes());
    position
}

pub(crate) fn deletion_chunk_cursor_position(
    variant: super::BlobVariantId,
    index: u64,
) -> [u8; 41] {
    let mut position = [0u8; 41];
    position[0] = MAINTENANCE_DELETION_CHUNK_TAG;
    position[1..33].copy_from_slice(variant.as_bytes());
    position[33..].copy_from_slice(&index.to_be_bytes());
    position
}

pub(crate) fn deletion_chunk_resume_position(
    variant: super::BlobVariantId,
    index: u64,
) -> [u8; 41] {
    let mut position = deletion_chunk_cursor_position(variant, index);
    position[0] = MAINTENANCE_DELETION_CHUNK_RESUME_TAG;
    position
}

pub(crate) fn deletion_manifest_resume_position(variant: super::BlobVariantId) -> [u8; 33] {
    let mut position = deletion_manifest_cursor_position(variant);
    position[0] = MAINTENANCE_DELETION_MANIFEST_RESUME_TAG;
    position
}

const RETIREMENT_AGE_VERSION: u8 = 1;
const RETIREMENT_AGE_ENCODED_BYTES: usize = 43;
const RETIRED_PUBLICATION_STATE_BYTES: usize = 2 + 8 + RETIREMENT_AGE_ENCODED_BYTES;

/// Stable reason retained after one Blob publication leaves live state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetirementReason {
    Expired,
    Invalidated,
    Evicted,
}

impl RetirementReason {
    pub(crate) const fn encode(self) -> u8 {
        match self {
            Self::Expired => 1,
            Self::Invalidated => 2,
            Self::Evicted => 3,
        }
    }

    pub(crate) const fn decode(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Expired),
            2 => Some(Self::Invalidated),
            3 => Some(Self::Evicted),
            _ => None,
        }
    }
}

/// Durable conservative age of one retained retirement record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetirementAge {
    age: CustodyAge,
    retain_for_ms: u64,
}

impl RetirementAge {
    pub(crate) const fn new(
        cumulative_age_ms: u64,
        checkpoint: CustodySample,
        retain_for_ms: u64,
    ) -> Result<Self, BlobStoreError> {
        if retain_for_ms == 0 {
            return Err(BlobStoreError::InvalidLifecycleLimits);
        }
        Ok(Self {
            age: CustodyAge::new(cumulative_age_ms, checkpoint),
            retain_for_ms,
        })
    }

    pub(crate) const fn unknown(retain_for_ms: u64) -> Result<Self, BlobStoreError> {
        if retain_for_ms == 0 {
            return Err(BlobStoreError::InvalidLifecycleLimits);
        }
        Ok(Self {
            age: CustodyAge::unknown(0),
            retain_for_ms,
        })
    }

    pub(crate) const fn cumulative_age_ms(self) -> u64 {
        self.age.cumulative_age_ms()
    }

    pub(crate) const fn checkpoint_sample(self) -> Option<CustodySample> {
        self.age.checkpoint_sample()
    }

    pub(crate) const fn is_lower_bound(self) -> bool {
        !self.age.is_continuous()
    }

    pub(crate) const fn retain_for_ms(self) -> u64 {
        self.retain_for_ms
    }

    fn encode(self) -> [u8; RETIREMENT_AGE_ENCODED_BYTES] {
        let mut encoded = [0u8; RETIREMENT_AGE_ENCODED_BYTES];
        encoded[0] = RETIREMENT_AGE_VERSION;
        encoded[1..9].copy_from_slice(&self.retain_for_ms.to_be_bytes());
        encoded[9..17].copy_from_slice(&self.age.cumulative_age_ms().to_be_bytes());
        encoded[17] = self.age.continuity().to_wire();
        if let Some(sample) = self.age.checkpoint_sample() {
            encoded[18] = 1;
            encoded[19..35].copy_from_slice(&sample.clock_id);
            encoded[35..43].copy_from_slice(&sample.tick_ms.to_be_bytes());
        }
        encoded
    }

    fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        let bytes: [u8; RETIREMENT_AGE_ENCODED_BYTES] = bytes.try_into().map_err(|_| {
            BlobStoreError::SchemaInvariant("Blob retirement age has an invalid canonical length")
        })?;
        if bytes[0] != RETIREMENT_AGE_VERSION {
            return Err(BlobStoreError::SchemaInvariant(
                "Blob retirement age has an unknown encoding version",
            ));
        }
        let retain_for_ms = u64::from_be_bytes(bytes[1..9].try_into().expect("fixed retention"));
        if retain_for_ms == 0 {
            return Err(BlobStoreError::SchemaInvariant(
                "Blob retirement retention is zero",
            ));
        }
        let continuity = CustodyContinuity::from_wire(bytes[17]).ok_or(
            BlobStoreError::SchemaInvariant("Blob retirement age has unknown continuity"),
        )?;
        let checkpoint = match bytes[18] {
            0 if bytes[19..].iter().all(|byte| *byte == 0) => None,
            1 => Some(CustodySample {
                clock_id: bytes[19..35]
                    .try_into()
                    .expect("fixed retirement clock identifier"),
                tick_ms: u64::from_be_bytes(
                    bytes[35..43]
                        .try_into()
                        .expect("fixed retirement clock tick"),
                ),
            }),
            _ => {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob retirement age has a noncanonical checkpoint",
                ));
            }
        };
        CustodyAge::from_parts(
            u64::from_be_bytes(bytes[9..17].try_into().expect("fixed retirement age")),
            checkpoint,
            continuity,
        )
        .map(|age| Self { age, retain_for_ms })
        .map_err(|_| BlobStoreError::SchemaInvariant("Blob retirement age state is invalid"))
    }

    pub(crate) fn project(
        self,
        current: Option<CustodySample>,
    ) -> Result<RetirementClockProjection, BlobStoreError> {
        let mut age = self.age;
        if age.cumulative_age_ms() < self.retain_for_ms {
            match age.effective_age(current) {
                Ok(_) | Err(CustodyError::ContinuityUnavailable | CustodyError::AgeOverflow) => {}
                Err(CustodyError::InvalidState) => {
                    return Err(BlobStoreError::SchemaInvariant(
                        "Blob retirement age state is invalid",
                    ));
                }
                Err(CustodyError::InvalidClaims | CustodyError::ContextMismatch) => {
                    return Err(BlobStoreError::SchemaInvariant(
                        "Blob retirement clock returned an unrelated custody error",
                    ));
                }
            }
        }
        let age = Self {
            age,
            retain_for_ms: self.retain_for_ms,
        };
        let retention_elapsed = age.cumulative_age_ms() >= self.retain_for_ms;
        let deadline = if retention_elapsed {
            None
        } else {
            age.checkpoint_sample().and_then(|checkpoint| {
                checkpoint
                    .tick_ms
                    .checked_add(self.retain_for_ms - age.cumulative_age_ms())
                    .map(|tick_ms| CustodySample {
                        clock_id: checkpoint.clock_id,
                        tick_ms,
                    })
            })
        };
        Ok(RetirementClockProjection {
            age,
            is_lower_bound: age.is_lower_bound(),
            retention_elapsed,
            deadline,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetirementClockProjection {
    pub(crate) age: RetirementAge,
    pub(crate) is_lower_bound: bool,
    pub(crate) retention_elapsed: bool,
    pub(crate) deadline: Option<CustodySample>,
}

/// Canonical lifecycle state for a publication row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationState {
    Live,
    Retired {
        reason: RetirementReason,
        generation: u64,
        age: RetirementAge,
    },
}

impl PublicationState {
    pub(crate) fn encode(self) -> Vec<u8> {
        match self {
            Self::Live => vec![PUBLICATION_STATE_LIVE_TAG],
            Self::Retired {
                reason,
                generation,
                age,
            } => {
                let mut encoded = Vec::with_capacity(2 + 8 + RETIREMENT_AGE_ENCODED_BYTES);
                encoded.push(PUBLICATION_STATE_RETIRED_TAG);
                encoded.push(reason.encode());
                encoded.extend_from_slice(&generation.to_be_bytes());
                encoded.extend_from_slice(&age.encode());
                encoded
            }
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        match bytes {
            [PUBLICATION_STATE_LIVE_TAG] => Ok(Self::Live),
            [PUBLICATION_STATE_RETIRED_TAG, reason, body @ ..]
                if body.len() == 8 + RETIREMENT_AGE_ENCODED_BYTES =>
            {
                let generation =
                    u64::from_be_bytes(body[..8].try_into().expect("fixed retirement generation"));
                if generation == 0 {
                    return Err(BlobStoreError::SchemaInvariant(
                        "Blob publication retirement generation is zero",
                    ));
                }
                Ok(Self::Retired {
                    reason: RetirementReason::decode(*reason).ok_or(
                        BlobStoreError::SchemaInvariant(
                            "Blob publication retirement reason is unknown",
                        ),
                    )?,
                    generation,
                    age: RetirementAge::decode(&body[8..])?,
                })
            }
            _ => Err(BlobStoreError::SchemaInvariant(
                "Blob publication lifecycle state is not canonical",
            )),
        }
    }
}

/// Canonical lifecycle state for an idempotent Blob operation row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OperationState {
    Active,
    Retired {
        reason: RetirementReason,
        generation: u64,
        operation_key_digest: [u8; 32],
        intent_digest: [u8; 32],
        age: RetirementAge,
    },
}

impl OperationState {
    pub(crate) fn encode(self) -> Vec<u8> {
        match self {
            Self::Active => vec![OPERATION_STATE_ACTIVE_TAG],
            Self::Retired {
                reason,
                generation,
                operation_key_digest,
                intent_digest,
                age,
            } => {
                let mut encoded =
                    Vec::with_capacity(2 + 8 + 32 + 32 + RETIREMENT_AGE_ENCODED_BYTES);
                encoded.push(OPERATION_STATE_RETIRED_TAG);
                encoded.push(reason.encode());
                encoded.extend_from_slice(&generation.to_be_bytes());
                encoded.extend_from_slice(&operation_key_digest);
                encoded.extend_from_slice(&intent_digest);
                encoded.extend_from_slice(&age.encode());
                encoded
            }
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        match bytes {
            [OPERATION_STATE_ACTIVE_TAG] => Ok(Self::Active),
            [OPERATION_STATE_RETIRED_TAG, reason, body @ ..]
                if body.len() == 8 + 32 + 32 + RETIREMENT_AGE_ENCODED_BYTES =>
            {
                let generation =
                    u64::from_be_bytes(body[..8].try_into().expect("fixed retirement generation"));
                if generation == 0 {
                    return Err(BlobStoreError::SchemaInvariant(
                        "Blob operation retirement generation is zero",
                    ));
                }
                Ok(Self::Retired {
                    reason: RetirementReason::decode(*reason).ok_or(
                        BlobStoreError::SchemaInvariant(
                            "Blob operation retirement reason is unknown",
                        ),
                    )?,
                    generation,
                    operation_key_digest: body[8..40]
                        .try_into()
                        .expect("fixed operation-key digest"),
                    intent_digest: body[40..72]
                        .try_into()
                        .expect("fixed operation-intent digest"),
                    age: RetirementAge::decode(&body[72..])?,
                })
            }
            _ => Err(BlobStoreError::SchemaInvariant(
                "Blob operation lifecycle state is not canonical",
            )),
        }
    }
}

/// Exact durable root kind for a variant reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VariantReferenceOwner {
    Publication,
    PendingSource,
}

impl VariantReferenceOwner {
    pub(crate) const fn encode(self) -> [u8; 1] {
        match self {
            Self::Publication => [VARIANT_REFERENCE_PUBLICATION_TAG],
            Self::PendingSource => [VARIANT_REFERENCE_PENDING_SOURCE_TAG],
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        match bytes {
            [VARIANT_REFERENCE_PUBLICATION_TAG] => Ok(Self::Publication),
            [VARIANT_REFERENCE_PENDING_SOURCE_TAG] => Ok(Self::PendingSource),
            _ => Err(BlobStoreError::SchemaInvariant(
                "Blob variant-reference owner is not canonical",
            )),
        }
    }
}

/// Fixed-width permanent evidence for one accepted physical Blob lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LineageFence {
    physical_lineage: [u8; 32],
    owner_binding: [u8; 32],
    bulk_reclamation_observed: bool,
}

impl LineageFence {
    const ENCODED_BYTES: usize = 65;

    pub(crate) const fn new(physical_lineage: [u8; 32], owner_binding: [u8; 32]) -> Self {
        Self {
            physical_lineage,
            owner_binding,
            bulk_reclamation_observed: false,
        }
    }

    const fn with_bulk_reclamation_observed(mut self) -> Self {
        self.bulk_reclamation_observed = true;
        self
    }

    fn same_authority(self, other: Self) -> bool {
        self.physical_lineage == other.physical_lineage && self.owner_binding == other.owner_binding
    }

    pub(crate) const fn bulk_reclamation_observed(self) -> bool {
        self.bulk_reclamation_observed
    }

    pub(crate) const fn encode(self) -> [u8; Self::ENCODED_BYTES] {
        let mut bytes = [0; Self::ENCODED_BYTES];
        bytes[0] = if self.bulk_reclamation_observed {
            RECLAIMED_LINEAGE_FENCE_VERSION
        } else {
            RECORD_VERSION
        };
        let mut index = 0;
        while index < 32 {
            bytes[1 + index] = self.physical_lineage[index];
            bytes[33 + index] = self.owner_binding[index];
            index += 1;
        }
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        let bytes: [u8; Self::ENCODED_BYTES] = bytes.try_into().map_err(|_| {
            BlobStoreError::SchemaInvariant("Blob lineage fence has an invalid canonical length")
        })?;
        let bulk_reclamation_observed = match bytes[0] {
            RECORD_VERSION => false,
            RECLAIMED_LINEAGE_FENCE_VERSION => true,
            _ => {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob lineage fence has an unknown encoding version",
                ));
            }
        };
        Ok(Self {
            physical_lineage: bytes[1..33].try_into().expect("fixed lineage fence slice"),
            owner_binding: bytes[33..].try_into().expect("fixed lineage fence slice"),
            bulk_reclamation_observed,
        })
    }
}

/// Fixed-width permanent evidence for one accepted publisher dot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReplayFence {
    publisher: [u8; 32],
    counter: u64,
    semantic_id: BlobSemanticId,
    transfer_id: BlobTransferId,
    source_len: u64,
    source_digest: [u8; 32],
}

impl ReplayFence {
    const ENCODED_BYTES: usize = 145;

    pub(crate) const fn new(
        publisher: [u8; 32],
        counter: u64,
        semantic_id: BlobSemanticId,
        transfer_id: BlobTransferId,
        source_len: u64,
        source_digest: [u8; 32],
    ) -> Self {
        Self {
            publisher,
            counter,
            semantic_id,
            transfer_id,
            source_len,
            source_digest,
        }
    }

    pub(crate) fn encode(self) -> [u8; Self::ENCODED_BYTES] {
        let mut bytes = [0; Self::ENCODED_BYTES];
        bytes[0] = RECORD_VERSION;
        bytes[1..33].copy_from_slice(&self.publisher);
        bytes[33..41].copy_from_slice(&self.counter.to_be_bytes());
        bytes[41..73].copy_from_slice(self.semantic_id.as_bytes());
        bytes[73..105].copy_from_slice(self.transfer_id.as_bytes());
        bytes[105..113].copy_from_slice(&self.source_len.to_be_bytes());
        bytes[113..].copy_from_slice(&self.source_digest);
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobStoreError> {
        let bytes: [u8; Self::ENCODED_BYTES] = bytes.try_into().map_err(|_| {
            BlobStoreError::SchemaInvariant("Blob replay fence has an invalid canonical length")
        })?;
        if bytes[0] != RECORD_VERSION {
            return Err(BlobStoreError::SchemaInvariant(
                "Blob replay fence has an unknown encoding version",
            ));
        }
        Ok(Self::new(
            bytes[1..33].try_into().expect("fixed replay fence slice"),
            u64::from_be_bytes(
                bytes[33..41]
                    .try_into()
                    .expect("fixed replay fence counter slice"),
            ),
            BlobSemanticId::new(
                bytes[41..73]
                    .try_into()
                    .expect("fixed replay fence semantic ID slice"),
            ),
            BlobTransferId::new(
                bytes[73..105]
                    .try_into()
                    .expect("fixed replay fence transfer ID slice"),
            ),
            u64::from_be_bytes(
                bytes[105..113]
                    .try_into()
                    .expect("fixed replay fence source length slice"),
            ),
            bytes[113..]
                .try_into()
                .expect("fixed replay fence digest slice"),
        ))
    }

    pub(crate) const fn dot(self) -> crate::Dot {
        crate::Dot {
            publisher: self.publisher,
            counter: self.counter,
        }
    }

    pub(crate) const fn semantic_id(self) -> BlobSemanticId {
        self.semantic_id
    }

    pub(crate) const fn transfer_id(self) -> BlobTransferId {
        self.transfer_id
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BlobLifecycleUsage {
    pub(crate) lineage_rows: u64,
    pub(crate) lineage_bytes: u64,
    pub(crate) replay_rows: u64,
    pub(crate) replay_bytes: u64,
    pub(crate) publication_rows: u64,
    pub(crate) reference_rows: u64,
    pub(crate) operation_owner_rows: u64,
    pub(crate) delivery_owner_rows: u64,
    pub(crate) deadline_rows: u64,
    pub(crate) retirement_resolver_rows: u64,
    pub(crate) retired_publication_rows: u64,
    pub(crate) retired_operation_rows: u64,
    pub(crate) next_retirement_generation: u64,
}

impl BlobLifecycleUsage {
    pub(crate) fn apply_to_stats(self, stats: &mut BlobStoreStats) {
        stats.lineage_fences = self.lineage_rows;
        stats.lineage_fence_bytes = self.lineage_bytes;
        stats.replay_fences = self.replay_rows;
        stats.replay_fence_bytes = self.replay_bytes;
        stats.publication_lifecycle_rows = self.publication_rows;
        stats.variant_references = self.reference_rows;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleSchemaState {
    Legacy,
    V1,
    V2,
    V3,
    Current,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PublicationEncodingGeneration {
    RawPredecessor,
    RawCurrent,
    LifecycleV1,
    LifecycleV2OrV3,
    Current,
}

#[derive(Debug)]
struct ExpectedLifecycleImage {
    publications: BTreeMap<Vec<u8>, Vec<u8>>,
    pending_sources: BTreeMap<Vec<u8>, Vec<u8>>,
    live_publications: BTreeSet<Vec<u8>>,
    retired_publications: BTreeSet<Vec<u8>>,
    operations: BTreeMap<Vec<u8>, Vec<u8>>,
    references: BTreeMap<Vec<u8>, Vec<u8>>,
    lineages: BTreeMap<Vec<u8>, Vec<u8>>,
    replays: BTreeMap<Vec<u8>, Vec<u8>>,
    operation_owners: BTreeMap<Vec<u8>, Vec<u8>>,
    delivery_owners: BTreeMap<Vec<u8>, Vec<u8>>,
    deadlines: BTreeMap<Vec<u8>, Vec<u8>>,
    retirement_resolvers: BTreeMap<Vec<u8>, Vec<u8>>,
    operation_bytes: u64,
    usage: BlobLifecycleUsage,
}

/// Fully preflighted predecessor-to-current lifecycle migration.
pub(crate) struct BlobLifecycleMigration {
    image: ExpectedLifecycleImage,
}

fn predecessor_lifecycle_table_names() -> [&'static str; 5] {
    [
        BLOB_LIFECYCLE_METADATA.name(),
        BLOB_VARIANT_REFERENCES.name(),
        BLOB_LINEAGE_FENCES.name(),
        BLOB_REPLAY_FENCES.name(),
        BLOB_MAINTENANCE_CURSORS.name(),
    ]
}

fn lifecycle_v2_table_names() -> [&'static str; 8] {
    [
        BLOB_LIFECYCLE_METADATA.name(),
        BLOB_VARIANT_REFERENCES.name(),
        BLOB_LINEAGE_FENCES.name(),
        BLOB_REPLAY_FENCES.name(),
        BLOB_MAINTENANCE_CURSORS.name(),
        BLOB_OPERATION_OWNERS.name(),
        BLOB_DELIVERY_OWNERS.name(),
        BLOB_RETENTION_DEADLINES.name(),
    ]
}

fn lifecycle_table_names() -> [&'static str; 9] {
    [
        BLOB_LIFECYCLE_METADATA.name(),
        BLOB_VARIANT_REFERENCES.name(),
        BLOB_LINEAGE_FENCES.name(),
        BLOB_REPLAY_FENCES.name(),
        BLOB_MAINTENANCE_CURSORS.name(),
        BLOB_OPERATION_OWNERS.name(),
        BLOB_DELIVERY_OWNERS.name(),
        BLOB_RETENTION_DEADLINES.name(),
        BLOB_RETIREMENT_RESOLVERS.name(),
    ]
}

fn lifecycle_schema_state(
    normal: &BTreeSet<String>,
    multimap: &BTreeSet<String>,
) -> Result<LifecycleSchemaState, StoreError> {
    let names = lifecycle_table_names();
    if multimap.iter().any(|name| names.contains(&name.as_str())) {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema has the wrong table kind",
        )));
    }
    let present = names.iter().filter(|name| normal.contains(**name)).count();
    match present {
        0 => Ok(LifecycleSchemaState::Legacy),
        count
            if count == predecessor_lifecycle_table_names().len()
                && predecessor_lifecycle_table_names()
                    .iter()
                    .all(|name| normal.contains(*name)) =>
        {
            Ok(LifecycleSchemaState::V1)
        }
        count
            if count == lifecycle_v2_table_names().len()
                && lifecycle_v2_table_names()
                    .iter()
                    .all(|name| normal.contains(*name)) =>
        {
            Ok(LifecycleSchemaState::V2)
        }
        count if count == names.len() => Ok(LifecycleSchemaState::Current),
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema group is incomplete",
        ))),
    }
}

fn lifecycle_schema_state_write(
    write: &redb::WriteTransaction,
) -> Result<LifecycleSchemaState, StoreError> {
    #[cfg(test)]
    TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS.set(
        TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS
            .get()
            .saturating_add(1),
    );
    lifecycle_schema_state(
        &write
            .list_tables()?
            .map(|table| table.name().to_owned())
            .collect(),
        &write
            .list_multimap_tables()?
            .map(|table| table.name().to_owned())
            .collect(),
    )
}

fn lifecycle_schema_state_read(
    read: &redb::ReadTransaction,
) -> Result<LifecycleSchemaState, StoreError> {
    #[cfg(test)]
    TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS.set(
        TEST_BLOB_LIFECYCLE_SCHEMA_ENUMERATIONS
            .get()
            .saturating_add(1),
    );
    lifecycle_schema_state(
        &read
            .list_tables()?
            .map(|table| table.name().to_owned())
            .collect(),
        &read
            .list_multimap_tables()?
            .map(|table| table.name().to_owned())
            .collect(),
    )
}

pub(crate) fn require_blob_lifecycle_absent_write(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    if lifecycle_schema_state_write(write)? != LifecycleSchemaState::Legacy
        || write
            .list_tables()?
            .any(|table| table.name() == BLOB_REPLAY_CAUSAL_FENCES.name())
        || write
            .list_multimap_tables()?
            .any(|table| table.name() == BLOB_REPLAY_CAUSAL_FENCES.name())
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle authority exists without its base schema",
        )));
    }
    Ok(())
}

pub(crate) fn require_blob_lifecycle_absent_read(
    read: &redb::ReadTransaction,
) -> Result<(), StoreError> {
    if lifecycle_schema_state_read(read)? != LifecycleSchemaState::Legacy
        || read
            .list_tables()?
            .any(|table| table.name() == BLOB_REPLAY_CAUSAL_FENCES.name())
        || read
            .list_multimap_tables()?
            .any(|table| table.name() == BLOB_REPLAY_CAUSAL_FENCES.name())
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle authority exists without its base schema",
        )));
    }
    Ok(())
}

pub(crate) fn publication_payload(bytes: &[u8]) -> Result<&[u8], BlobStoreError> {
    match bytes.first().copied() {
        Some(1..=3) => Ok(bytes),
        Some(PREDECESSOR_PUBLICATION_RECORD_VERSION | CURRENT_PUBLICATION_RECORD_VERSION) => {
            if bytes.len() < 3 {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob publication lifecycle wrapper is truncated",
                ));
            }
            if PublicationState::decode(&bytes[1..2])? != PublicationState::Live {
                return Err(BlobStoreError::SchemaInvariant(
                    "retired Blob publication has no live metadata payload",
                ));
            }
            if !matches!(bytes[2], 1..=3) {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob publication lifecycle wrapper has a noncanonical payload",
                ));
            }
            Ok(&bytes[2..])
        }
        _ => Err(BlobStoreError::SchemaInvariant(
            "Blob publication lifecycle wrapper has an unknown version",
        )),
    }
}

pub(crate) fn publication_payload_for_encoding(
    bytes: &[u8],
    generation: PublicationEncodingGeneration,
) -> Result<&[u8], BlobStoreError> {
    match generation {
        PublicationEncodingGeneration::RawPredecessor if matches!(bytes.first(), Some(1 | 2)) => {
            Ok(bytes)
        }
        PublicationEncodingGeneration::RawCurrent if bytes.first().copied() == Some(3) => Ok(bytes),
        PublicationEncodingGeneration::LifecycleV1
            if bytes.len() >= 3
                && bytes[0] == LIFECYCLE_V1_PUBLICATION_RECORD_VERSION
                && PublicationState::decode(&bytes[1..2])? == PublicationState::Live
                && matches!(bytes[2], 1 | 2) =>
        {
            Ok(&bytes[2..])
        }
        PublicationEncodingGeneration::LifecycleV2OrV3
            if bytes.first().copied() == Some(PREDECESSOR_PUBLICATION_RECORD_VERSION) =>
        {
            let payload = publication_payload(bytes)?;
            if !matches!(payload.first(), Some(1 | 2)) {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob publication payload contradicts its lifecycle schema",
                ));
            }
            Ok(payload)
        }
        PublicationEncodingGeneration::Current
            if bytes.first().copied() == Some(CURRENT_PUBLICATION_RECORD_VERSION) =>
        {
            let payload = publication_payload(bytes)?;
            if payload.first().copied() != Some(3) {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob publication payload contradicts its lifecycle schema",
                ));
            }
            Ok(payload)
        }
        _ => Err(BlobStoreError::SchemaInvariant(
            "Blob publication encoding contradicts its lifecycle schema",
        )),
    }
}

fn publication_encoding_from_schema(schema: LifecycleSchemaState) -> PublicationEncodingGeneration {
    match schema {
        LifecycleSchemaState::Legacy => PublicationEncodingGeneration::RawPredecessor,
        LifecycleSchemaState::V1 => PublicationEncodingGeneration::LifecycleV1,
        LifecycleSchemaState::V2 | LifecycleSchemaState::V3 => {
            PublicationEncodingGeneration::LifecycleV2OrV3
        }
        LifecycleSchemaState::Current => PublicationEncodingGeneration::Current,
    }
}

pub(crate) fn publication_encoding_write(
    write: &redb::WriteTransaction,
) -> Result<PublicationEncodingGeneration, StoreError> {
    #[cfg(test)]
    if TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return publication_encoding_migration_write(write);
    }
    match write
        .open_table(BLOB_LIFECYCLE_METADATA)?
        .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
    {
        Some(3) => Ok(PublicationEncodingGeneration::LifecycleV2OrV3),
        Some(BLOB_LIFECYCLE_SCHEMA_VERSION) => Ok(PublicationEncodingGeneration::Current),
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema version is unknown",
        ))),
    }
}

pub(crate) fn publication_encoding_migration_read(
    read: &redb::ReadTransaction,
) -> Result<PublicationEncodingGeneration, StoreError> {
    let mut schema = lifecycle_schema_state_read(read)?;
    #[cfg(test)]
    if schema == LifecycleSchemaState::Legacy
        && TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.with(|disabled| disabled.get())
    {
        return Ok(PublicationEncodingGeneration::RawCurrent);
    }
    if schema == LifecycleSchemaState::Current {
        schema = match read
            .open_table(BLOB_LIFECYCLE_METADATA)?
            .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
        {
            Some(3) => LifecycleSchemaState::V3,
            Some(BLOB_LIFECYCLE_SCHEMA_VERSION) => LifecycleSchemaState::Current,
            _ => {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle schema version is unknown",
                )));
            }
        };
    }
    Ok(publication_encoding_from_schema(schema))
}

pub(crate) fn publication_encoding_migration_write(
    write: &redb::WriteTransaction,
) -> Result<PublicationEncodingGeneration, StoreError> {
    let mut schema = lifecycle_schema_state_write(write)?;
    #[cfg(test)]
    if schema == LifecycleSchemaState::Legacy && TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return Ok(PublicationEncodingGeneration::RawCurrent);
    }
    if schema == LifecycleSchemaState::Current {
        schema = match write
            .open_table(BLOB_LIFECYCLE_METADATA)?
            .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
        {
            Some(3) => LifecycleSchemaState::V3,
            Some(BLOB_LIFECYCLE_SCHEMA_VERSION) => LifecycleSchemaState::Current,
            _ => {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle schema version is unknown",
                )));
            }
        };
    }
    Ok(publication_encoding_from_schema(schema))
}

pub(crate) fn publication_encoding_read(
    read: &redb::ReadTransaction,
) -> Result<PublicationEncodingGeneration, StoreError> {
    #[cfg(test)]
    if TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.with(|disabled| disabled.get()) {
        return publication_encoding_migration_read(read);
    }
    match read
        .open_table(BLOB_LIFECYCLE_METADATA)?
        .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
    {
        Some(3) => Ok(PublicationEncodingGeneration::LifecycleV2OrV3),
        Some(BLOB_LIFECYCLE_SCHEMA_VERSION) => Ok(PublicationEncodingGeneration::Current),
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema version is unknown",
        ))),
    }
}

pub(crate) fn publication_record_is_retired(bytes: &[u8]) -> Result<bool, BlobStoreError> {
    if !matches!(
        bytes.first().copied(),
        Some(PREDECESSOR_PUBLICATION_RECORD_VERSION | CURRENT_PUBLICATION_RECORD_VERSION)
    ) {
        return Ok(false);
    }
    match bytes.get(1).copied() {
        Some(PUBLICATION_STATE_LIVE_TAG) => {
            PublicationState::decode(&bytes[1..2])?;
            Ok(false)
        }
        Some(PUBLICATION_STATE_RETIRED_TAG) => {
            publication_retirement(bytes)?;
            Ok(true)
        }
        _ => Err(BlobStoreError::SchemaInvariant(
            "Blob publication lifecycle state is not canonical",
        )),
    }
}

pub(crate) fn publication_record_is_retired_for_encoding(
    bytes: &[u8],
    generation: PublicationEncodingGeneration,
) -> Result<bool, BlobStoreError> {
    match generation {
        PublicationEncodingGeneration::RawPredecessor
        | PublicationEncodingGeneration::RawCurrent
        | PublicationEncodingGeneration::LifecycleV1 => {
            publication_payload_for_encoding(bytes, generation)?;
            Ok(false)
        }
        PublicationEncodingGeneration::LifecycleV2OrV3 | PublicationEncodingGeneration::Current => {
            let expected = match generation {
                PublicationEncodingGeneration::LifecycleV2OrV3 => {
                    PREDECESSOR_PUBLICATION_RECORD_VERSION
                }
                PublicationEncodingGeneration::Current => CURRENT_PUBLICATION_RECORD_VERSION,
                PublicationEncodingGeneration::RawPredecessor
                | PublicationEncodingGeneration::RawCurrent
                | PublicationEncodingGeneration::LifecycleV1 => {
                    unreachable!("predecessor/current branch")
                }
            };
            if bytes.first().copied() != Some(expected) {
                return Err(BlobStoreError::SchemaInvariant(
                    "Blob publication encoding contradicts its lifecycle schema",
                ));
            }
            match bytes.get(1).copied() {
                Some(PUBLICATION_STATE_LIVE_TAG) => {
                    publication_payload_for_encoding(bytes, generation)?;
                    Ok(false)
                }
                Some(PUBLICATION_STATE_RETIRED_TAG) => {
                    publication_retirement(bytes)?;
                    Ok(true)
                }
                _ => Err(BlobStoreError::SchemaInvariant(
                    "Blob publication lifecycle state is unknown",
                )),
            }
        }
    }
}

pub(crate) fn publication_retirement(
    bytes: &[u8],
) -> Result<Option<(RetirementReason, u64, RetirementAge)>, BlobStoreError> {
    if !matches!(
        bytes.first().copied(),
        Some(PREDECESSOR_PUBLICATION_RECORD_VERSION | CURRENT_PUBLICATION_RECORD_VERSION)
    ) {
        return Ok(None);
    }
    match bytes.get(1).copied() {
        Some(PUBLICATION_STATE_LIVE_TAG) => {
            PublicationState::decode(&bytes[1..2])?;
            Ok(None)
        }
        Some(PUBLICATION_STATE_RETIRED_TAG) => {
            if bytes.len() != 1 + RETIRED_PUBLICATION_STATE_BYTES
                && bytes.len() < 1 + RETIRED_PUBLICATION_STATE_BYTES + 8
            {
                return Err(BlobStoreError::SchemaInvariant(
                    "retired Blob publication record is truncated",
                ));
            }
            match PublicationState::decode(&bytes[1..1 + RETIRED_PUBLICATION_STATE_BYTES])? {
                PublicationState::Retired {
                    reason,
                    generation,
                    age,
                } => Ok(Some((reason, generation, age))),
                PublicationState::Live => unreachable!("retired tag decoded as live"),
            }
        }
        _ => Err(BlobStoreError::SchemaInvariant(
            "Blob publication lifecycle state is not canonical",
        )),
    }
}

pub(crate) fn retired_publication_record(
    live: &[u8],
    acceptance_marker: u64,
    reason: RetirementReason,
    generation: u64,
    age: RetirementAge,
) -> Result<Vec<u8>, StoreError> {
    if acceptance_marker == 0 {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "retired Blob publication has a zero acceptance marker",
        )));
    }
    let payload = publication_payload(live).map_err(StoreError::Blob)?;
    let mut encoded = vec![CURRENT_PUBLICATION_RECORD_VERSION];
    encoded.extend_from_slice(
        &PublicationState::Retired {
            reason,
            generation,
            age,
        }
        .encode(),
    );
    encoded.extend_from_slice(&acceptance_marker.to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

pub(crate) fn reanchored_retired_publication_record(
    encoded: &[u8],
    age: RetirementAge,
) -> Result<Vec<u8>, StoreError> {
    let (reason, generation, _) = publication_retirement(encoded)
        .map_err(StoreError::Blob)?
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement reanchor points to a live publication",
        )))?;
    let (marker, payload) = retired_publication_payload(encoded)
        .map_err(StoreError::Blob)?
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "retired Blob publication lacks lookup metadata during reanchor",
        )))?;
    let mut reanchored = vec![CURRENT_PUBLICATION_RECORD_VERSION];
    reanchored.extend_from_slice(
        &PublicationState::Retired {
            reason,
            generation,
            age,
        }
        .encode(),
    );
    reanchored.extend_from_slice(&marker.to_be_bytes());
    reanchored.extend_from_slice(payload);
    Ok(reanchored)
}

pub(crate) fn retired_publication_payload(
    bytes: &[u8],
) -> Result<Option<(u64, &[u8])>, BlobStoreError> {
    if publication_retirement(bytes)?.is_none() {
        return Ok(None);
    }
    let marker_offset = 1 + RETIRED_PUBLICATION_STATE_BYTES;
    if bytes.len() == marker_offset {
        return Ok(None);
    }
    let marker = u64::from_be_bytes(
        bytes[marker_offset..marker_offset + 8]
            .try_into()
            .expect("checked retired marker"),
    );
    if marker == 0 || !matches!(bytes.get(marker_offset + 8), Some(1..=3)) {
        return Err(BlobStoreError::SchemaInvariant(
            "retired Blob publication lookup payload is not canonical",
        ));
    }
    Ok(Some((marker, &bytes[marker_offset + 8..])))
}

fn publication_is_current(bytes: &[u8]) -> bool {
    bytes.first().copied() == Some(CURRENT_PUBLICATION_RECORD_VERSION)
}

fn wrap_publication(bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
    let payload = publication_payload(bytes).map_err(StoreError::Blob)?;
    if publication_is_current(bytes) || !matches!(payload.first(), Some(1..=3)) {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob predecessor publication is not canonical",
        )));
    }
    let payload = super::encode_blob_metadata(super::decode_blob_metadata(payload)?)?;
    let mut wrapped = Vec::with_capacity(payload.len() + 2);
    wrapped.push(CURRENT_PUBLICATION_RECORD_VERSION);
    wrapped.extend_from_slice(&PublicationState::Live.encode());
    wrapped.extend_from_slice(&payload);
    Ok(wrapped)
}

fn wrap_v1_publication(bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
    if bytes.len() < 3
        || bytes[0] != LIFECYCLE_V1_PUBLICATION_RECORD_VERSION
        || PublicationState::decode(&bytes[1..2])? != PublicationState::Live
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v1 publication wrapper is not canonical",
        )));
    }
    let payload = super::encode_blob_metadata(super::decode_blob_metadata(&bytes[2..])?)?;
    let mut wrapped = Vec::with_capacity(payload.len() + 2);
    wrapped.push(CURRENT_PUBLICATION_RECORD_VERSION);
    wrapped.extend_from_slice(&PublicationState::Live.encode());
    wrapped.extend_from_slice(&payload);
    Ok(wrapped)
}

pub(crate) fn replace_live_publication_payload(
    encoded: &[u8],
    payload: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if publication_record_is_retired(encoded)?
        || encoded.first().copied() != Some(CURRENT_PUBLICATION_RECORD_VERSION)
        || !matches!(payload.first(), Some(1..=3))
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob publication lifetime update is not a current live record",
        )));
    }
    let mut wrapped = Vec::with_capacity(payload.len() + 2);
    wrapped.push(CURRENT_PUBLICATION_RECORD_VERSION);
    wrapped.extend_from_slice(&PublicationState::Live.encode());
    wrapped.extend_from_slice(payload);
    Ok(wrapped)
}

fn upgrade_v3_publication(encoded: &[u8]) -> Result<Vec<u8>, StoreError> {
    if encoded.first().copied() != Some(PREDECESSOR_PUBLICATION_RECORD_VERSION) {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v3 publication wrapper is missing",
        )));
    }
    if publication_record_is_retired(encoded)? {
        let state_end = 1 + RETIRED_PUBLICATION_STATE_BYTES;
        let Some((marker, payload)) = retired_publication_payload(encoded)? else {
            let mut upgraded = Vec::with_capacity(state_end);
            upgraded.push(CURRENT_PUBLICATION_RECORD_VERSION);
            upgraded.extend_from_slice(&encoded[1..state_end]);
            return Ok(upgraded);
        };
        let metadata = super::decode_blob_metadata(payload)?;
        let payload = super::encode_blob_metadata(metadata)?;
        let mut upgraded = Vec::with_capacity(state_end + 8 + payload.len());
        upgraded.push(CURRENT_PUBLICATION_RECORD_VERSION);
        upgraded.extend_from_slice(&encoded[1..state_end]);
        upgraded.extend_from_slice(&marker.to_be_bytes());
        upgraded.extend_from_slice(&payload);
        return Ok(upgraded);
    }
    let metadata = super::decode_blob_metadata(encoded)?;
    let payload = super::encode_blob_metadata(metadata)?;
    let mut upgraded = Vec::with_capacity(payload.len() + 2);
    upgraded.push(CURRENT_PUBLICATION_RECORD_VERSION);
    upgraded.extend_from_slice(&PublicationState::Live.encode());
    upgraded.extend_from_slice(&payload);
    Ok(upgraded)
}

fn admission_schema_is_current(write: &redb::WriteTransaction) -> Result<bool, StoreError> {
    #[cfg(test)]
    if TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return Ok(false);
    }
    let metadata = write.open_table(BLOB_LIFECYCLE_METADATA)?;
    if metadata
        .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        == Some(BLOB_LIFECYCLE_SCHEMA_VERSION)
    {
        Ok(true)
    } else {
        Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle authority is absent or unknown on an admission path",
        )))
    }
}

pub(crate) fn require_import_lineage(
    write: &redb::WriteTransaction,
    physical_lineage: Option<[u8; 32]>,
) -> Result<(), StoreError> {
    if admission_schema_is_current(write)? && physical_lineage.is_none() {
        return Err(StoreError::Blob(
            BlobStoreError::PhysicalLineageMigrationRequired,
        ));
    }
    Ok(())
}

fn lifecycle_counter(
    write: &redb::WriteTransaction,
    field: &'static str,
) -> Result<u64, StoreError> {
    let metadata = write.open_table(BLOB_LIFECYCLE_METADATA)?;
    if metadata
        .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        != Some(BLOB_LIFECYCLE_SCHEMA_VERSION)
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema version is missing or unknown",
        )));
    }
    metadata
        .get(field)?
        .map(|value| value.value())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle accounting metadata is incomplete",
        )))
}

fn active_operation_count_from_metadata(
    metadata: &impl ReadableTable<&'static str, u64>,
    total_operations: u64,
) -> Result<u64, StoreError> {
    let schema = metadata
        .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
        .map(|value| value.value())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema version is missing or unknown",
        )))?;
    if schema != BLOB_LIFECYCLE_SCHEMA_VERSION {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema cannot account for retired operations",
        )));
    }
    let retired_operations = metadata
        .get(BLOB_RETIRED_OPERATION_ROWS)?
        .map(|value| value.value())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle retired-operation accounting is missing",
        )))?;
    total_operations
        .checked_sub(retired_operations)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retired-operation accounting exceeds total operations",
        )))
}

pub(crate) fn active_operation_count_write(
    write: &redb::WriteTransaction,
    total_operations: u64,
) -> Result<u64, StoreError> {
    #[cfg(test)]
    if TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return Ok(total_operations);
    }
    active_operation_count_from_metadata(
        &write.open_table(BLOB_LIFECYCLE_METADATA)?,
        total_operations,
    )
}

pub(crate) fn active_operation_count_read(
    read: &redb::ReadTransaction,
    total_operations: u64,
) -> Result<u64, StoreError> {
    #[cfg(test)]
    if TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return Ok(total_operations);
    }
    active_operation_count_from_metadata(
        &read.open_table(BLOB_LIFECYCLE_METADATA)?,
        total_operations,
    )
}

fn set_lifecycle_counter(
    write: &redb::WriteTransaction,
    field: &'static str,
    value: u64,
) -> Result<(), StoreError> {
    write
        .open_table(BLOB_LIFECYCLE_METADATA)?
        .insert(field, value)?;
    Ok(())
}

/// Returns a current live-publication encoding without accepting a predecessor
/// row on an ordinary current-schema write path.
pub(crate) fn live_publication_record(
    write: &redb::WriteTransaction,
    bytes: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if admission_schema_is_current(write)? {
        wrap_publication(bytes)
    } else {
        Ok(bytes.to_vec())
    }
}

/// Point-checks one exact retained physical-lineage fence.
pub(crate) fn require_lineage_fence(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    physical_lineage: [u8; 32],
    owner_binding: [u8; 32],
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    let encoded = write
        .open_table(BLOB_LINEAGE_FENCES)?
        .get(variant.as_bytes().as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "retained Blob variant is missing its lineage fence",
        )))?;
    let fence = LineageFence::decode(&encoded).map_err(StoreError::Blob)?;
    if !fence.same_authority(LineageFence::new(physical_lineage, owner_binding)) {
        return Err(StoreError::Blob(BlobStoreError::PhysicalLineageConflict));
    }
    if lifecycle_counter(write, BLOB_LINEAGE_ROWS)? == 0
        || lifecycle_counter(write, BLOB_LINEAGE_BYTES)?
            < entry_bytes(variant.as_bytes(), &encoded)?
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lineage-fence accounting cannot cover the retained fence",
        )));
    }
    Ok(())
}

/// Point-checks or installs one permanent physical-lineage fence in the
/// caller's transaction. An exact fence is idempotent even at configured
/// capacity; only a new key consumes the separate security resource.
pub(crate) fn ensure_lineage_fence(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
    variant: super::BlobVariantId,
    physical_lineage: [u8; 32],
    owner_binding: [u8; 32],
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    let key = variant.as_bytes().as_slice();
    let expected = LineageFence::new(physical_lineage, owner_binding);
    let existing = {
        let fences = write.open_table(BLOB_LINEAGE_FENCES)?;
        fences.get(key)?.map(|value| value.value().to_vec())
    };
    if let Some(encoded) = existing {
        let existing = LineageFence::decode(&encoded).map_err(StoreError::Blob)?;
        if !existing.same_authority(expected) {
            return Err(StoreError::Blob(BlobStoreError::PhysicalLineageConflict));
        }
        return require_lineage_fence(write, variant, physical_lineage, owner_binding);
    }

    let encoded = expected.encode();
    let current_rows = lifecycle_counter(write, BLOB_LINEAGE_ROWS)?;
    let current_bytes = lifecycle_counter(write, BLOB_LINEAGE_BYTES)?;
    let required_rows = current_rows
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let required_bytes = current_bytes
        .checked_add(entry_bytes(key, &encoded)?)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if required_rows > limits.max_lineage_rows() || required_bytes > limits.max_lineage_bytes() {
        return Err(StoreError::Blob(BlobStoreError::LineageFenceCapacity {
            required_rows,
            required_bytes,
            max_rows: limits.max_lineage_rows(),
            max_bytes: limits.max_lineage_bytes(),
        }));
    }
    if write
        .open_table(BLOB_LINEAGE_FENCES)?
        .insert(key, encoded.as_slice())?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lineage fence changed during one writer transaction",
        )));
    }
    set_lifecycle_counter(write, BLOB_LINEAGE_ROWS, required_rows)?;
    set_lifecycle_counter(write, BLOB_LINEAGE_BYTES, required_bytes)
}

/// Marks the exact retained fence after its protected bulk state reaches the
/// final reclamation transaction. The fixed-width state change preserves the
/// existing row and byte accounting and is idempotent across recovery.
pub(crate) fn mark_lineage_bulk_reclamation_observed(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    expected_evidence: &[u8],
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lineage reclamation requires current lifecycle authority",
        )));
    }
    let expected = LineageFence::decode(expected_evidence).map_err(StoreError::Blob)?;
    let key = variant.as_bytes().as_slice();
    let encoded = write
        .open_table(BLOB_LINEAGE_FENCES)?
        .get(key)?
        .map(|value| value.value().to_vec())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "reclaimed Blob variant is missing its lineage fence",
        )))?;
    let current = LineageFence::decode(&encoded).map_err(StoreError::Blob)?;
    if !current.same_authority(expected) {
        return Err(StoreError::Blob(BlobStoreError::PhysicalLineageConflict));
    }
    if current.bulk_reclamation_observed() {
        return Ok(());
    }
    let reclaimed = current.with_bulk_reclamation_observed().encode();
    write
        .open_table(BLOB_LINEAGE_FENCES)?
        .insert(key, reclaimed.as_slice())?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ReplayFenceStatus {
    Absent,
    Exact,
}

/// Point-classifies one publisher dot against permanent replay authority.
pub(crate) fn check_replay_fence(
    write: &redb::WriteTransaction,
    expected: ReplayFence,
) -> Result<ReplayFenceStatus, StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(ReplayFenceStatus::Absent);
    }
    let key = super::accepted_dot_key(crate::Dot {
        publisher: expected.publisher,
        counter: expected.counter,
    });
    let Some(encoded) = write
        .open_table(BLOB_REPLAY_FENCES)?
        .get(key.as_slice())?
        .map(|value| value.value().to_vec())
    else {
        return Ok(ReplayFenceStatus::Absent);
    };
    let existing = ReplayFence::decode(&encoded).map_err(StoreError::Blob)?;
    if existing.publisher != expected.publisher || existing.counter != expected.counter {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob replay fence key differs from its publisher dot",
        )));
    }
    if existing.semantic_id != expected.semantic_id {
        return Err(StoreError::CausalEquivocation {
            publisher: expected.publisher,
            counter: expected.counter,
        });
    }
    if existing.transfer_id != expected.transfer_id
        || existing.source_len != expected.source_len
        || existing.source_digest != expected.source_digest
    {
        return Err(StoreError::Blob(
            BlobStoreError::SourceRepresentationConflict,
        ));
    }
    if lifecycle_counter(write, BLOB_REPLAY_ROWS)? == 0
        || lifecycle_counter(write, BLOB_REPLAY_BYTES)? < entry_bytes(&key, &encoded)?
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob replay-fence accounting cannot cover the retained fence",
        )));
    }
    Ok(ReplayFenceStatus::Exact)
}

/// Persists the exact causal-frontier commitment that remains after a bounded
/// publication retirement row expires.  The row is keyed by the same
/// permanent publisher dot as the replay fence and contains only a fixed
/// digest of its complete frontier key.
pub(crate) fn record_expired_replay_causal_fence(
    write: &redb::WriteTransaction,
    dot: crate::Dot,
    frontier_key: &[u8],
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "expired Blob replay causal evidence requires current lifecycle authority",
        )));
    }
    let key = super::accepted_dot_key(dot);
    let digest: [u8; 32] = Sha256::digest(frontier_key).into();
    let mut fences = write.open_table(BLOB_REPLAY_CAUSAL_FENCES)?;
    if let Some(existing) = fences.get(key.as_slice())? {
        if existing.value() != digest {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "expired Blob replay causal fence differs from its frontier authority",
            )));
        }
        return Ok(());
    }
    fences.insert(key.as_slice(), digest.as_slice())?;
    Ok(())
}

/// Returns whether an exact replay fence has the durable causal binding that
/// proves its bounded publication record expired normally.  An arbitrary
/// detached replay fence is still corrupt and must not be treated as a
/// duplicate merely because its source bytes happen to match.
pub(crate) fn expired_replay_causal_fence_matches(
    write: &redb::WriteTransaction,
    dot: crate::Dot,
    frontier_key: &[u8],
) -> Result<bool, StoreError> {
    let tables = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if !tables.contains(BLOB_REPLAY_CAUSAL_FENCES.name()) {
        return Ok(false);
    }
    if write
        .list_multimap_tables()?
        .any(|table| table.name() == BLOB_REPLAY_CAUSAL_FENCES.name())
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob replay causal-fence table has the wrong table kind",
        )));
    }
    let key = super::accepted_dot_key(dot);
    let fences = write.open_table(BLOB_REPLAY_CAUSAL_FENCES)?;
    let Some(actual) = fences.get(key.as_slice())? else {
        return Ok(false);
    };
    let expected: [u8; 32] = Sha256::digest(frontier_key).into();
    if actual.value() != expected {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "expired Blob replay causal fence differs from its frontier authority",
        )));
    }
    Ok(true)
}

/// Installs a new replay fence or accepts an exact existing fence without
/// consuming capacity.
pub(crate) fn ensure_replay_fence(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
    expected: ReplayFence,
) -> Result<(), StoreError> {
    match check_replay_fence(write, expected)? {
        ReplayFenceStatus::Exact => return Ok(()),
        ReplayFenceStatus::Absent if !admission_schema_is_current(write)? => return Ok(()),
        ReplayFenceStatus::Absent => {}
    }
    let key = super::accepted_dot_key(crate::Dot {
        publisher: expected.publisher,
        counter: expected.counter,
    });
    let encoded = expected.encode();
    let current_rows = lifecycle_counter(write, BLOB_REPLAY_ROWS)?;
    let current_bytes = lifecycle_counter(write, BLOB_REPLAY_BYTES)?;
    let required_rows = current_rows
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let required_bytes = current_bytes
        .checked_add(entry_bytes(&key, &encoded)?)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if required_rows > limits.max_replay_rows() || required_bytes > limits.max_replay_bytes() {
        return Err(StoreError::Blob(BlobStoreError::ReplayFenceCapacity {
            required_rows,
            required_bytes,
            max_rows: limits.max_replay_rows(),
            max_bytes: limits.max_replay_bytes(),
        }));
    }
    if write
        .open_table(BLOB_REPLAY_FENCES)?
        .insert(key.as_slice(), encoded.as_slice())?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob replay fence changed during one writer transaction",
        )));
    }
    set_lifecycle_counter(write, BLOB_REPLAY_ROWS, required_rows)?;
    set_lifecycle_counter(write, BLOB_REPLAY_BYTES, required_bytes)
}

fn reference_key(
    variant: super::BlobVariantId,
    owner: VariantReferenceOwner,
    transfer: BlobTransferId,
) -> Vec<u8> {
    variant_reference_key(variant, owner, transfer)
}

pub(crate) fn require_variant_reference(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    owner: VariantReferenceOwner,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    super::deletion::require_variant_available_write(write, variant)?;
    let key = reference_key(variant, owner, transfer);
    let value = write
        .open_table(BLOB_VARIANT_REFERENCES)?
        .get(key.as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob root is missing its exact variant reference",
        )))?;
    if !value.is_empty() || lifecycle_counter(write, BLOB_REFERENCE_ROWS)? == 0 {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob variant reference or its accounting is not canonical",
        )));
    }
    Ok(())
}

pub(crate) fn insert_variant_reference(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    owner: VariantReferenceOwner,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    super::deletion::require_variant_available_write(write, variant)?;
    let key = reference_key(variant, owner, transfer);
    if write
        .open_table(BLOB_VARIANT_REFERENCES)?
        .get(key.as_slice())?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "new Blob root already has a variant reference",
        )));
    }
    let current = lifecycle_counter(write, BLOB_REFERENCE_ROWS)?;
    let next = current
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    write
        .open_table(BLOB_VARIANT_REFERENCES)?
        .insert(key.as_slice(), &[][..])?;
    set_lifecycle_counter(write, BLOB_REFERENCE_ROWS, next)
}

pub(crate) fn remove_variant_reference(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    owner: VariantReferenceOwner,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    require_variant_reference(write, variant, owner, transfer)?;
    let current = lifecycle_counter(write, BLOB_REFERENCE_ROWS)?;
    let next = current
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob variant-reference counter underflows",
        )))?;
    let key = reference_key(variant, owner, transfer);
    let removed = write
        .open_table(BLOB_VARIANT_REFERENCES)?
        .remove(key.as_slice())?
        .map(|value| value.value().to_vec());
    if removed.as_deref() != Some(&[][..]) {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob variant reference changed during one writer transaction",
        )));
    }
    set_lifecycle_counter(write, BLOB_REFERENCE_ROWS, next)
}

pub(crate) fn move_variant_reference(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
    transfer: BlobTransferId,
    from: VariantReferenceOwner,
    to: VariantReferenceOwner,
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    super::deletion::require_variant_available_write(write, variant)?;
    require_variant_reference(write, variant, from, transfer)?;
    let from_key = reference_key(variant, from, transfer);
    let to_key = reference_key(variant, to, transfer);
    if write
        .open_table(BLOB_VARIANT_REFERENCES)?
        .get(to_key.as_slice())?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob reference move would create a second owner",
        )));
    }
    let mut references = write.open_table(BLOB_VARIANT_REFERENCES)?;
    references.remove(from_key.as_slice())?;
    references.insert(to_key.as_slice(), &[][..])?;
    Ok(())
}

pub(crate) fn admit_publication_row(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    let current = lifecycle_counter(write, BLOB_PUBLICATION_ROWS)?;
    let required_rows = current
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if required_rows > limits.max_publication_rows() {
        return Err(StoreError::Blob(
            BlobStoreError::PublicationLifecycleCapacity {
                required_rows,
                max_rows: limits.max_publication_rows(),
            },
        ));
    }
    set_lifecycle_counter(write, BLOB_PUBLICATION_ROWS, required_rows)
}

pub(crate) fn require_publication_row(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    if admission_schema_is_current(write)? && lifecycle_counter(write, BLOB_PUBLICATION_ROWS)? == 0
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "live Blob publication is missing lifecycle accounting",
        )));
    }
    Ok(())
}

pub(crate) fn operation_payload(bytes: &[u8]) -> Result<&[u8], BlobStoreError> {
    if bytes.is_empty() {
        return Err(BlobStoreError::SchemaInvariant(
            "Blob operation lifecycle wrapper is truncated",
        ));
    }
    if bytes[0] == super::BLOB_OPERATION_VERSION {
        return Ok(bytes);
    }
    if bytes.len() < 3 || bytes[0] != CURRENT_OPERATION_RECORD_VERSION {
        return Err(BlobStoreError::SchemaInvariant(
            "Blob operation lifecycle wrapper has an unknown version",
        ));
    }
    if OperationState::decode(&bytes[1..2])? != OperationState::Active {
        return Err(BlobStoreError::SchemaInvariant(
            "retired Blob operation has no active operation payload",
        ));
    }
    Ok(&bytes[2..])
}

pub(crate) fn operation_record_is_retired(bytes: &[u8]) -> Result<bool, BlobStoreError> {
    if bytes.first().copied() != Some(CURRENT_OPERATION_RECORD_VERSION) {
        return Ok(false);
    }
    match bytes.get(1).copied() {
        Some(OPERATION_STATE_ACTIVE_TAG) => {
            OperationState::decode(&bytes[1..2])?;
            Ok(false)
        }
        Some(OPERATION_STATE_RETIRED_TAG) => {
            OperationState::decode(&bytes[1..])?;
            Ok(true)
        }
        _ => Err(BlobStoreError::SchemaInvariant(
            "Blob operation lifecycle state is not canonical",
        )),
    }
}

pub(crate) type OperationRetirement = (RetirementReason, u64, [u8; 32], [u8; 32], RetirementAge);

pub(crate) fn operation_retirement(
    bytes: &[u8],
) -> Result<Option<OperationRetirement>, BlobStoreError> {
    if bytes.first().copied() != Some(CURRENT_OPERATION_RECORD_VERSION) {
        return Ok(None);
    }
    match bytes.get(1).copied() {
        Some(OPERATION_STATE_ACTIVE_TAG) => {
            OperationState::decode(&bytes[1..2])?;
            Ok(None)
        }
        Some(OPERATION_STATE_RETIRED_TAG) => match OperationState::decode(&bytes[1..])? {
            OperationState::Retired {
                reason,
                generation,
                operation_key_digest,
                intent_digest,
                age,
            } => Ok(Some((
                reason,
                generation,
                operation_key_digest,
                intent_digest,
                age,
            ))),
            OperationState::Active => unreachable!("retired tag decoded as active"),
        },
        _ => Err(BlobStoreError::SchemaInvariant(
            "Blob operation lifecycle state is not canonical",
        )),
    }
}

pub(crate) fn retired_operation_record(
    reason: RetirementReason,
    generation: u64,
    operation_key_digest: [u8; 32],
    intent_digest: [u8; 32],
    age: RetirementAge,
) -> Vec<u8> {
    let mut encoded = vec![CURRENT_OPERATION_RECORD_VERSION];
    encoded.extend_from_slice(
        &OperationState::Retired {
            reason,
            generation,
            operation_key_digest,
            intent_digest,
            age,
        }
        .encode(),
    );
    encoded
}

pub(crate) fn reanchored_retired_operation_record(
    encoded: &[u8],
    age: RetirementAge,
) -> Result<Vec<u8>, StoreError> {
    let (reason, generation, operation_key_digest, intent_digest, _) =
        operation_retirement(encoded)
            .map_err(StoreError::Blob)?
            .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retirement reanchor points to an active operation",
            )))?;
    Ok(retired_operation_record(
        reason,
        generation,
        operation_key_digest,
        intent_digest,
        age,
    ))
}

fn wrap_operation(bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
    let payload = operation_payload(bytes).map_err(StoreError::Blob)?;
    if payload.first().copied() != Some(super::BLOB_OPERATION_VERSION) {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob predecessor operation is not canonical",
        )));
    }
    let mut wrapped = Vec::with_capacity(payload.len() + 2);
    wrapped.push(CURRENT_OPERATION_RECORD_VERSION);
    wrapped.extend_from_slice(&OperationState::Active.encode());
    wrapped.extend_from_slice(payload);
    Ok(wrapped)
}

pub(crate) fn active_operation_record(
    write: &redb::WriteTransaction,
    bytes: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if admission_schema_is_current(write)? {
        wrap_operation(bytes)
    } else {
        Ok(bytes.to_vec())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetentionDeadlineOwner {
    Publication(BlobTransferId),
    Operation([u8; 32]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetentionDeadlineKind {
    Publication,
    Operation,
}

impl RetentionDeadlineKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Publication => 1,
            Self::Operation => 2,
        }
    }
}

impl RetentionDeadlineOwner {
    const fn kind(self) -> RetentionDeadlineKind {
        match self {
            Self::Publication(_) => RetentionDeadlineKind::Publication,
            Self::Operation(_) => RetentionDeadlineKind::Operation,
        }
    }
}

fn retirement_resolver_key(owner: RetentionDeadlineOwner) -> [u8; 33] {
    let mut key = [0u8; 33];
    match owner {
        RetentionDeadlineOwner::Publication(transfer) => {
            key[0] = 1;
            key[1..].copy_from_slice(transfer.as_bytes());
        }
        RetentionDeadlineOwner::Operation(digest) => {
            key[0] = 2;
            key[1..].copy_from_slice(&digest);
        }
    }
    key
}

fn decode_retirement_resolver_key(key: &[u8]) -> Result<RetentionDeadlineOwner, StoreError> {
    let key: [u8; 33] = key.try_into().map_err(|_| {
        StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver key has an invalid length",
        ))
    })?;
    let identity: [u8; 32] = key[1..].try_into().expect("fixed retirement owner");
    match key[0] {
        1 => Ok(RetentionDeadlineOwner::Publication(BlobTransferId::new(
            identity,
        ))),
        2 => Ok(RetentionDeadlineOwner::Operation(identity)),
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver owner is unknown",
        ))),
    }
}

fn validate_retirement_resolver(
    owner: RetentionDeadlineOwner,
    value: &[u8],
) -> Result<(), StoreError> {
    match owner {
        RetentionDeadlineOwner::Publication(_) if value.is_empty() => Ok(()),
        RetentionDeadlineOwner::Operation(digest)
            if !value.is_empty() && Sha256::digest(value).as_slice() == digest =>
        {
            super::BlobOperationKey::new(value.to_vec())?;
            Ok(())
        }
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver is not canonical",
        ))),
    }
}

pub(crate) fn insert_retirement_resolver(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
    owner: RetentionDeadlineOwner,
    operation_key: Option<&[u8]>,
) -> Result<(), StoreError> {
    let value = match (owner, operation_key) {
        (RetentionDeadlineOwner::Publication(_), None) => &[][..],
        (RetentionDeadlineOwner::Operation(_), Some(key)) => key,
        _ => {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retirement resolver owner and value disagree",
            )));
        }
    };
    validate_retirement_resolver(owner, value)?;
    let rows = lifecycle_counter(write, BLOB_RETIREMENT_RESOLVER_ROWS)?
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let maximum = limits
        .max_publication_rows()
        .checked_add(super::MAX_BLOB_OPERATIONS)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if rows > maximum {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver rows exceed their structural bound",
        )));
    }
    let key = retirement_resolver_key(owner);
    if write
        .open_table(BLOB_RETIREMENT_RESOLVERS)?
        .insert(key.as_slice(), value)?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver already exists",
        )));
    }
    set_lifecycle_counter(write, BLOB_RETIREMENT_RESOLVER_ROWS, rows)
}

pub(crate) fn remove_retirement_resolver(
    write: &redb::WriteTransaction,
    owner: RetentionDeadlineOwner,
) -> Result<Vec<u8>, StoreError> {
    let rows = lifecycle_counter(write, BLOB_RETIREMENT_RESOLVER_ROWS)?
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver counter underflows",
        )))?;
    let key = retirement_resolver_key(owner);
    let value = write
        .open_table(BLOB_RETIREMENT_RESOLVERS)?
        .remove(key.as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver is missing",
        )))?;
    validate_retirement_resolver(owner, &value)?;
    set_lifecycle_counter(write, BLOB_RETIREMENT_RESOLVER_ROWS, rows)?;
    Ok(value)
}

pub(crate) fn retirement_operation_key_write(
    write: &redb::WriteTransaction,
    digest: [u8; 32],
) -> Result<Vec<u8>, StoreError> {
    let owner = RetentionDeadlineOwner::Operation(digest);
    let value = write
        .open_table(BLOB_RETIREMENT_RESOLVERS)?
        .get(retirement_resolver_key(owner).as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob operation retirement resolver is missing",
        )))?;
    validate_retirement_resolver(owner, &value)?;
    Ok(value)
}

pub(crate) fn require_publication_retirement_resolver_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
) -> Result<(), StoreError> {
    let owner = RetentionDeadlineOwner::Publication(transfer);
    let value = write
        .open_table(BLOB_RETIREMENT_RESOLVERS)?
        .get(retirement_resolver_key(owner).as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob publication retirement resolver is missing",
        )))?;
    validate_retirement_resolver(owner, &value)
}

pub(crate) struct RetirementResolver {
    pub(crate) position: Vec<u8>,
    pub(crate) owner: RetentionDeadlineOwner,
    pub(crate) value: Vec<u8>,
}

pub(crate) fn next_retirement_resolver_write(
    write: &redb::WriteTransaction,
    position: Option<&[u8]>,
) -> Result<Option<RetirementResolver>, StoreError> {
    use std::ops::Bound::{Excluded, Unbounded};

    let resolvers = write.open_table(BLOB_RETIREMENT_RESOLVERS)?;
    let next = match position {
        Some(position) => resolvers
            .range::<&[u8]>((Excluded(position), Unbounded))?
            .next()
            .transpose()?,
        None => resolvers.iter()?.next().transpose()?,
    };
    let row = match (next, position) {
        (Some(row), _) => Some(row),
        (None, Some(_)) => resolvers.iter()?.next().transpose()?,
        (None, None) => None,
    };
    let Some((key, value)) = row else {
        return Ok(None);
    };
    let position = key.value().to_vec();
    let owner = decode_retirement_resolver_key(&position)?;
    let value = value.value().to_vec();
    validate_retirement_resolver(owner, &value)?;
    Ok(Some(RetirementResolver {
        position,
        owner,
        value,
    }))
}

fn retention_deadline_key(deadline: CustodySample, owner: RetentionDeadlineOwner) -> [u8; 57] {
    let mut key = [0u8; 57];
    key[..16].copy_from_slice(&deadline.clock_id);
    key[16] = owner.kind().tag();
    key[17..25].copy_from_slice(&deadline.tick_ms.to_be_bytes());
    match owner {
        RetentionDeadlineOwner::Publication(transfer) => {
            key[25..].copy_from_slice(transfer.as_bytes());
        }
        RetentionDeadlineOwner::Operation(digest) => {
            key[25..].copy_from_slice(&digest);
        }
    }
    key
}

fn retention_deadline_key_v2(deadline: CustodySample, owner: RetentionDeadlineOwner) -> [u8; 57] {
    let mut key = [0u8; 57];
    key[..16].copy_from_slice(&deadline.clock_id);
    key[16..24].copy_from_slice(&deadline.tick_ms.to_be_bytes());
    key[24] = owner.kind().tag();
    match owner {
        RetentionDeadlineOwner::Publication(transfer) => {
            key[25..].copy_from_slice(transfer.as_bytes());
        }
        RetentionDeadlineOwner::Operation(digest) => {
            key[25..].copy_from_slice(&digest);
        }
    }
    key
}

fn decode_retention_deadline_key(
    key: &[u8],
) -> Result<(CustodySample, RetentionDeadlineOwner), StoreError> {
    let key: [u8; 57] = key.try_into().map_err(|_| {
        StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline key has an invalid length",
        ))
    })?;
    let sample = CustodySample {
        clock_id: key[..16].try_into().expect("fixed deadline clock ID"),
        tick_ms: u64::from_be_bytes(key[17..25].try_into().expect("fixed deadline tick")),
    };
    let identity: [u8; 32] = key[25..].try_into().expect("fixed deadline owner");
    let owner = match key[16] {
        1 => RetentionDeadlineOwner::Publication(BlobTransferId::new(identity)),
        2 => RetentionDeadlineOwner::Operation(identity),
        _ => {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retention deadline owner is unknown",
            )));
        }
    };
    Ok((sample, owner))
}

fn decode_retention_deadline_key_v2(
    key: &[u8],
) -> Result<(CustodySample, RetentionDeadlineOwner), StoreError> {
    let key: [u8; 57] = key.try_into().map_err(|_| {
        StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline key has an invalid length",
        ))
    })?;
    let sample = CustodySample {
        clock_id: key[..16].try_into().expect("fixed deadline clock ID"),
        tick_ms: u64::from_be_bytes(key[16..24].try_into().expect("fixed deadline tick")),
    };
    let identity: [u8; 32] = key[25..].try_into().expect("fixed deadline owner");
    let owner = match key[24] {
        1 => RetentionDeadlineOwner::Publication(BlobTransferId::new(identity)),
        2 => RetentionDeadlineOwner::Operation(identity),
        _ => {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retention deadline owner is unknown",
            )));
        }
    };
    Ok((sample, owner))
}

fn nearest_retention_deadline_in_table(
    deadlines: &impl ReadableTable<&'static [u8], &'static [u8]>,
    clock_id: [u8; 16],
    kind: RetentionDeadlineKind,
) -> Result<Option<(CustodySample, RetentionDeadlineOwner)>, StoreError> {
    let mut start = [0u8; 57];
    start[..16].copy_from_slice(&clock_id);
    start[16] = kind.tag();
    let Some((key, value)) = deadlines.range(start.as_slice()..)?.next().transpose()? else {
        return Ok(None);
    };
    if key.value()[..16] != clock_id || key.value()[16] != kind.tag() {
        return Ok(None);
    }
    if !value.value().is_empty() {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline value is not empty",
        )));
    }
    decode_retention_deadline_key(key.value()).map(Some)
}

pub(crate) fn nearest_retention_deadline_read(
    read: &redb::ReadTransaction,
    clock_id: [u8; 16],
) -> Result<Option<(CustodySample, RetentionDeadlineOwner)>, StoreError> {
    let deadlines = read.open_table(BLOB_RETENTION_DEADLINES)?;
    let publication = nearest_retention_deadline_in_table(
        &deadlines,
        clock_id,
        RetentionDeadlineKind::Publication,
    )?;
    let operation = nearest_retention_deadline_in_table(
        &deadlines,
        clock_id,
        RetentionDeadlineKind::Operation,
    )?;
    Ok([publication, operation]
        .into_iter()
        .flatten()
        .min_by_key(|(deadline, owner)| (deadline.tick_ms, owner.kind().tag())))
}

pub(crate) fn nearest_retention_deadline_write(
    write: &redb::WriteTransaction,
    clock_id: [u8; 16],
) -> Result<Option<(CustodySample, RetentionDeadlineOwner)>, StoreError> {
    let deadlines = write.open_table(BLOB_RETENTION_DEADLINES)?;
    let publication = nearest_retention_deadline_in_table(
        &deadlines,
        clock_id,
        RetentionDeadlineKind::Publication,
    )?;
    let operation = nearest_retention_deadline_in_table(
        &deadlines,
        clock_id,
        RetentionDeadlineKind::Operation,
    )?;
    Ok([publication, operation]
        .into_iter()
        .flatten()
        .min_by_key(|(deadline, owner)| (deadline.tick_ms, owner.kind().tag())))
}

pub(crate) fn nearest_retention_deadline_for_kind_write(
    write: &redb::WriteTransaction,
    clock_id: [u8; 16],
    kind: RetentionDeadlineKind,
) -> Result<Option<(CustodySample, RetentionDeadlineOwner)>, StoreError> {
    let deadlines = write.open_table(BLOB_RETENTION_DEADLINES)?;
    nearest_retention_deadline_in_table(&deadlines, clock_id, kind)
}

pub(crate) fn next_retention_deadline_write(
    write: &redb::WriteTransaction,
    position: Option<&[u8]>,
) -> Result<Option<(Vec<u8>, CustodySample, RetentionDeadlineOwner)>, StoreError> {
    use std::ops::Bound::{Excluded, Unbounded};

    let deadlines = write.open_table(BLOB_RETENTION_DEADLINES)?;
    let next = match position {
        Some(position) => deadlines
            .range::<&[u8]>((Excluded(position), Unbounded))?
            .next()
            .transpose()?,
        None => deadlines.iter()?.next().transpose()?,
    };
    let row = match (next, position) {
        (Some(row), _) => Some(row),
        (None, Some(_)) => deadlines.iter()?.next().transpose()?,
        (None, None) => None,
    };
    let Some((key, value)) = row else {
        return Ok(None);
    };
    if !value.value().is_empty() {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline value is not empty",
        )));
    }
    let position = key.value().to_vec();
    let (deadline, owner) = decode_retention_deadline_key(&position)?;
    Ok(Some((position, deadline, owner)))
}

pub(crate) fn insert_retention_deadline(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
    deadline: CustodySample,
    owner: RetentionDeadlineOwner,
) -> Result<(), StoreError> {
    let current = lifecycle_counter(write, BLOB_DEADLINE_ROWS)?;
    let rows = current
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let maximum = limits
        .max_publication_rows()
        .checked_add(super::MAX_BLOB_OPERATIONS)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if rows > maximum {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline rows exceed their structural bound",
        )));
    }
    let key = retention_deadline_key(deadline, owner);
    if write
        .open_table(BLOB_RETENTION_DEADLINES)?
        .insert(key.as_slice(), &[][..])?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline already exists",
        )));
    }
    set_lifecycle_counter(write, BLOB_DEADLINE_ROWS, rows)
}

pub(crate) fn insert_reanchored_retention_deadline(
    write: &redb::WriteTransaction,
    deadline: CustodySample,
    owner: RetentionDeadlineOwner,
) -> Result<(), StoreError> {
    let rows = lifecycle_counter(write, BLOB_DEADLINE_ROWS)?
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if rows > lifecycle_counter(write, BLOB_RETIREMENT_RESOLVER_ROWS)? {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline has no retirement resolver",
        )));
    }
    let key = retention_deadline_key(deadline, owner);
    if write
        .open_table(BLOB_RETENTION_DEADLINES)?
        .insert(key.as_slice(), &[][..])?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline already exists",
        )));
    }
    set_lifecycle_counter(write, BLOB_DEADLINE_ROWS, rows)
}

pub(crate) fn remove_retention_deadline(
    write: &redb::WriteTransaction,
    deadline: CustodySample,
    owner: RetentionDeadlineOwner,
) -> Result<(), StoreError> {
    let key = retention_deadline_key(deadline, owner);
    let rows = lifecycle_counter(write, BLOB_DEADLINE_ROWS)?
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline counter underflows",
        )))?;
    if write
        .open_table(BLOB_RETENTION_DEADLINES)?
        .remove(key.as_slice())?
        .is_none()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline is missing",
        )));
    }
    set_lifecycle_counter(write, BLOB_DEADLINE_ROWS, rows)
}

pub(crate) fn replace_retention_deadline(
    write: &redb::WriteTransaction,
    old_deadline: CustodySample,
    new_deadline: CustodySample,
    owner: RetentionDeadlineOwner,
) -> Result<(), StoreError> {
    let old_key = retention_deadline_key(old_deadline, owner);
    let new_key = retention_deadline_key(new_deadline, owner);
    if old_key == new_key {
        let deadlines = write.open_table(BLOB_RETENTION_DEADLINES)?;
        let value = deadlines.get(old_key.as_slice())?.ok_or(StoreError::Blob(
            BlobStoreError::SchemaInvariant("Blob retention deadline is missing"),
        ))?;
        if !value.value().is_empty() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retention deadline value is not empty",
            )));
        }
        return Ok(());
    }
    let mut deadlines = write.open_table(BLOB_RETENTION_DEADLINES)?;
    if deadlines.remove(old_key.as_slice())?.is_none() {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retention deadline is missing",
        )));
    }
    if deadlines.insert(new_key.as_slice(), &[][..])?.is_some() {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "multiple Blob retirements claim one exact deadline key",
        )));
    }
    Ok(())
}

pub(crate) fn allocate_retirement_generation(
    write: &redb::WriteTransaction,
) -> Result<u64, StoreError> {
    let current = lifecycle_counter(write, BLOB_NEXT_RETIREMENT_GENERATION)?;
    let generation = current
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    set_lifecycle_counter(write, BLOB_NEXT_RETIREMENT_GENERATION, generation)?;
    Ok(generation)
}

/// Preflights and charges each distinct lifecycle-accounting row updated by
/// one policy-invalidation retirement. Repeated reads or writes of the same
/// metadata field count once, matching retained-record expiry's unique-row
/// accounting model.
pub(crate) fn policy_retirement_accounting_charge_write(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
    operation_rows: u64,
    has_deadline: bool,
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    fn charged_counter(
        write: &redb::WriteTransaction,
        field: &'static str,
        charge: &mut super::MaintenanceCharge,
    ) -> Result<Option<u64>, StoreError> {
        if !charge.charge(field.as_bytes(), std::mem::size_of::<u64>())? {
            return Ok(None);
        }
        lifecycle_counter(write, field).map(Some)
    }

    let Some(next_generation) = charged_counter(write, BLOB_NEXT_RETIREMENT_GENERATION, charge)?
    else {
        return Ok(false);
    };
    next_generation
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let Some(retired_publications) = charged_counter(write, BLOB_RETIRED_PUBLICATION_ROWS, charge)?
    else {
        return Ok(false);
    };
    retired_publications
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let Some(resolver_rows) = charged_counter(write, BLOB_RETIREMENT_RESOLVER_ROWS, charge)? else {
        return Ok(false);
    };

    let inserted = operation_rows
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    let maximum = limits
        .max_publication_rows()
        .checked_add(super::MAX_BLOB_OPERATIONS)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if resolver_rows
        .checked_add(inserted)
        .ok_or(StoreError::ItemCountAccountingOverflow)?
        > maximum
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement authority exceeds its structural bound",
        )));
    }
    if has_deadline {
        let Some(deadline_rows) = charged_counter(write, BLOB_DEADLINE_ROWS, charge)? else {
            return Ok(false);
        };
        if deadline_rows
            .checked_add(inserted)
            .ok_or(StoreError::ItemCountAccountingOverflow)?
            > maximum
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retirement authority exceeds its structural bound",
            )));
        }
    }
    if operation_rows != 0 {
        let Some(operation_owner_rows) = charged_counter(write, BLOB_OPERATION_OWNER_ROWS, charge)?
        else {
            return Ok(false);
        };
        operation_owner_rows
            .checked_sub(operation_rows)
            .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob operation-owner accounting cannot cover retirement",
            )))?;
        let Some(retired_operations) = charged_counter(write, BLOB_RETIRED_OPERATION_ROWS, charge)?
        else {
            return Ok(false);
        };
        retired_operations
            .checked_add(operation_rows)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
    }
    Ok(true)
}

/// Incrementally preflights and charges one resolver plus its optional
/// deadline before any retirement mutation begins.
pub(crate) fn policy_retirement_authority_charge_write(
    write: &redb::WriteTransaction,
    owner: RetentionDeadlineOwner,
    value: &[u8],
    deadline: Option<aster_mesh::CustodySample>,
    charge: &mut super::MaintenanceCharge,
) -> Result<bool, StoreError> {
    let resolver_key = retirement_resolver_key(owner);
    if !charge.charge(resolver_key.as_slice(), value.len())? {
        return Ok(false);
    }
    if write
        .open_table(BLOB_RETIREMENT_RESOLVERS)?
        .get(resolver_key.as_slice())?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retirement resolver already exists",
        )));
    }
    if let Some(deadline) = deadline {
        let deadline_key = retention_deadline_key(deadline, owner);
        if !charge.charge(deadline_key.as_slice(), 0)? {
            return Ok(false);
        }
        if write
            .open_table(BLOB_RETENTION_DEADLINES)?
            .get(deadline_key.as_slice())?
            .is_some()
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retention deadline already exists",
            )));
        }
    }
    Ok(true)
}

pub(crate) fn record_publication_retirement(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let retired = lifecycle_counter(write, BLOB_RETIRED_PUBLICATION_ROWS)?
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    set_lifecycle_counter(write, BLOB_RETIRED_PUBLICATION_ROWS, retired)
}

pub(crate) fn record_operation_retirement(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let retired = lifecycle_counter(write, BLOB_RETIRED_OPERATION_ROWS)?
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    set_lifecycle_counter(write, BLOB_RETIRED_OPERATION_ROWS, retired)
}

pub(crate) fn remove_publication_retirement(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let publications = lifecycle_counter(write, BLOB_PUBLICATION_ROWS)?
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob publication lifecycle counter underflows on retirement expiry",
        )))?;
    let retired = lifecycle_counter(write, BLOB_RETIRED_PUBLICATION_ROWS)?
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retired-publication counter underflows on retirement expiry",
        )))?;
    set_lifecycle_counter(write, BLOB_PUBLICATION_ROWS, publications)?;
    set_lifecycle_counter(write, BLOB_RETIRED_PUBLICATION_ROWS, retired)
}

pub(crate) fn remove_operation_retirement(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let retired = lifecycle_counter(write, BLOB_RETIRED_OPERATION_ROWS)?
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob retired-operation counter underflows on retirement expiry",
        )))?;
    set_lifecycle_counter(write, BLOB_RETIRED_OPERATION_ROWS, retired)
}

pub(crate) fn inverse_owner_key(owner: BlobTransferId, forward_key: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(owner.as_bytes());
    key.extend_from_slice(&Sha256::digest(forward_key));
    key
}

pub(crate) fn inverse_owner_bounds(owner: BlobTransferId) -> ([u8; 64], [u8; 64]) {
    let mut start = [0u8; 64];
    start[..32].copy_from_slice(owner.as_bytes());
    let mut end = [0xffu8; 64];
    end[..32].copy_from_slice(owner.as_bytes());
    (start, end)
}

fn insert_inverse_owner(
    write: &redb::WriteTransaction,
    table: TableDefinition<&[u8], &[u8]>,
    counter: &'static str,
    owner: BlobTransferId,
    forward_key: &[u8],
    limit: u64,
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    let rows = lifecycle_counter(write, counter)?
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if rows > limit {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob inverse-owner rows exceed their forward authority bound",
        )));
    }
    let key = inverse_owner_key(owner, forward_key);
    if write
        .open_table(table)?
        .insert(key.as_slice(), forward_key)?
        .is_some()
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob inverse owner already exists",
        )));
    }
    set_lifecycle_counter(write, counter, rows)
}

fn remove_inverse_owner(
    write: &redb::WriteTransaction,
    table: TableDefinition<&[u8], &[u8]>,
    counter: &'static str,
    owner: BlobTransferId,
    forward_key: &[u8],
) -> Result<(), StoreError> {
    if !admission_schema_is_current(write)? {
        return Ok(());
    }
    let key = inverse_owner_key(owner, forward_key);
    let rows = lifecycle_counter(write, counter)?
        .checked_sub(1)
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob inverse-owner counter underflows",
        )))?;
    if write.open_table(table)?.remove(key.as_slice())?.is_none() {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob inverse owner is missing",
        )));
    }
    set_lifecycle_counter(write, counter, rows)
}

pub(crate) fn insert_operation_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
    operation_key: &[u8],
) -> Result<(), StoreError> {
    insert_inverse_owner(
        write,
        BLOB_OPERATION_OWNERS,
        BLOB_OPERATION_OWNER_ROWS,
        owner,
        operation_key,
        super::MAX_BLOB_OPERATIONS,
    )
}

pub(crate) fn remove_operation_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
    operation_key: &[u8],
) -> Result<(), StoreError> {
    remove_inverse_owner(
        write,
        BLOB_OPERATION_OWNERS,
        BLOB_OPERATION_OWNER_ROWS,
        owner,
        operation_key,
    )
}

type InverseOwnerEntry = (Vec<u8>, Vec<u8>);

fn inverse_owner_entries(
    write: &redb::WriteTransaction,
    table: TableDefinition<&'static [u8], &'static [u8]>,
    owner: BlobTransferId,
    limit: u64,
) -> Result<Vec<InverseOwnerEntry>, StoreError> {
    let (start, end) = inverse_owner_bounds(owner);
    let rows = write.open_table(table)?;
    let mut keys = Vec::new();
    for row in rows.range::<&[u8]>((
        std::ops::Bound::Included(start.as_slice()),
        std::ops::Bound::Included(end.as_slice()),
    ))? {
        let (key, value) = row?;
        if key.value().len() != 64 || &key.value()[..32] != owner.as_bytes() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob inverse-owner range escaped its exact owner",
            )));
        }
        if u64::try_from(keys.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)? >= limit
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob inverse-owner fan-out exceeds its structural bound",
            )));
        }
        let forward = value.value().to_vec();
        if inverse_owner_key(owner, &forward).as_slice() != key.value() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob inverse-owner key differs from its forward authority",
            )));
        }
        keys.push((key.value().to_vec(), forward));
    }
    Ok(keys)
}

pub(crate) fn operation_owner_entries_for_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
) -> Result<Vec<InverseOwnerEntry>, StoreError> {
    inverse_owner_entries(
        write,
        BLOB_OPERATION_OWNERS,
        owner,
        super::MAX_BLOB_OPERATIONS,
    )
}

pub(crate) fn delivery_owner_entries_for_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
) -> Result<Vec<InverseOwnerEntry>, StoreError> {
    inverse_owner_entries(
        write,
        BLOB_DELIVERY_OWNERS,
        owner,
        crate::blob_subscription::MAX_BLOB_SUBSCRIPTIONS,
    )
}

pub(crate) fn operation_keys_for_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
) -> Result<Vec<Vec<u8>>, StoreError> {
    operation_owner_entries_for_owner(write, owner)
        .map(|entries| entries.into_iter().map(|(_, forward)| forward).collect())
}

pub(crate) fn delivery_keys_for_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
) -> Result<Vec<Vec<u8>>, StoreError> {
    delivery_owner_entries_for_owner(write, owner)
        .map(|entries| entries.into_iter().map(|(_, forward)| forward).collect())
}

pub(crate) fn insert_delivery_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
    delivery_key: &[u8],
) -> Result<(), StoreError> {
    insert_inverse_owner(
        write,
        BLOB_DELIVERY_OWNERS,
        BLOB_DELIVERY_OWNER_ROWS,
        owner,
        delivery_key,
        crate::blob_subscription::MAX_BLOB_PENDING_DELIVERIES,
    )
}

pub(crate) fn remove_delivery_owner(
    write: &redb::WriteTransaction,
    owner: BlobTransferId,
    delivery_key: &[u8],
) -> Result<(), StoreError> {
    remove_inverse_owner(
        write,
        BLOB_DELIVERY_OWNERS,
        BLOB_DELIVERY_OWNER_ROWS,
        owner,
        delivery_key,
    )
}

fn inverse_owner_rows(
    rows: impl IntoIterator<Item = (BlobTransferId, Vec<u8>)>,
    conflict: &'static str,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, StoreError> {
    let mut inverse = BTreeMap::new();
    for (owner, forward_key) in rows {
        insert_unique(
            &mut inverse,
            inverse_owner_key(owner, &forward_key),
            forward_key,
            conflict,
        )?;
    }
    Ok(inverse)
}

fn variant_reference_key(
    variant: super::BlobVariantId,
    owner: VariantReferenceOwner,
    transfer: BlobTransferId,
) -> Vec<u8> {
    let mut key = Vec::with_capacity(65);
    key.extend_from_slice(variant.as_bytes());
    key.extend_from_slice(&owner.encode());
    key.extend_from_slice(transfer.as_bytes());
    key
}

fn entry_bytes(key: &[u8], value: &[u8]) -> Result<u64, StoreError> {
    key.len()
        .checked_add(value.len())
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

fn insert_unique(
    rows: &mut BTreeMap<Vec<u8>, Vec<u8>>,
    key: Vec<u8>,
    value: Vec<u8>,
    conflict: &'static str,
) -> Result<(), StoreError> {
    if rows.insert(key, value).is_some() {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(conflict)));
    }
    Ok(())
}

fn reconstruct_retirement_authority(
    expected: &mut ExpectedLifecycleImage,
    schema: LifecycleSchemaState,
    generation: u64,
    age: RetirementAge,
    owner: RetentionDeadlineOwner,
    operation_key: Option<&[u8]>,
) -> Result<(), StoreError> {
    expected.usage.next_retirement_generation =
        expected.usage.next_retirement_generation.max(generation);
    let projection = age
        .project(age.checkpoint_sample())
        .map_err(StoreError::Blob)?;
    if let Some(deadline) = projection.deadline {
        let key = if schema == LifecycleSchemaState::V2 {
            retention_deadline_key_v2(deadline, owner)
        } else {
            retention_deadline_key(deadline, owner)
        };
        insert_unique(
            &mut expected.deadlines,
            key.to_vec(),
            Vec::new(),
            "multiple Blob retirements claim one exact deadline key",
        )?;
    }
    let resolver_value = match (owner, operation_key) {
        (RetentionDeadlineOwner::Publication(_), None) => Vec::new(),
        (RetentionDeadlineOwner::Operation(_), Some(key)) => key.to_vec(),
        _ => {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retirement resolver reconstruction disagrees with its owner",
            )));
        }
    };
    validate_retirement_resolver(owner, &resolver_value)?;
    insert_unique(
        &mut expected.retirement_resolvers,
        retirement_resolver_key(owner).to_vec(),
        resolver_value,
        "multiple Blob retirements claim one exact resolver",
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)] // One audit seam receives independent durable authorities.
fn reconstruct_expected_image(
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
    source_bytes: &impl ReadableTable<&'static [u8], &'static [u8]>,
    operations: &impl ReadableTable<&'static [u8], &'static [u8]>,
    pending_sources: Vec<(Vec<u8>, Vec<u8>)>,
    delivery_owner_rows: Vec<(BlobTransferId, Vec<u8>)>,
    imports: Vec<depot::AuditedLifecycleImport>,
    owner_binding: [u8; 32],
    schema: LifecycleSchemaState,
) -> Result<ExpectedLifecycleImage, StoreError> {
    let mut expected = ExpectedLifecycleImage {
        publications: BTreeMap::new(),
        pending_sources: BTreeMap::new(),
        live_publications: BTreeSet::new(),
        retired_publications: BTreeSet::new(),
        operations: BTreeMap::new(),
        references: BTreeMap::new(),
        lineages: BTreeMap::new(),
        replays: BTreeMap::new(),
        operation_owners: BTreeMap::new(),
        delivery_owners: inverse_owner_rows(
            delivery_owner_rows,
            "multiple Blob deliveries claim one inverse owner key",
        )?,
        deadlines: BTreeMap::new(),
        retirement_resolvers: BTreeMap::new(),
        operation_bytes: 0,
        usage: BlobLifecycleUsage::default(),
    };
    let mut import_lineages = BTreeMap::new();
    let mut publication_intents = BTreeMap::<BlobTransferId, [u8; 32]>::new();
    for import in imports {
        if import_lineages
            .insert(import.variant_id, import.physical_lineage)
            .is_some()
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "multiple Blob imports claim one exact variant identity",
            )));
        }
        let key = import.variant_id.as_bytes().to_vec();
        let value = LineageFence::new(import.physical_lineage, owner_binding)
            .encode()
            .to_vec();
        expected.usage.lineage_bytes = expected
            .usage
            .lineage_bytes
            .checked_add(entry_bytes(&key, &value)?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        insert_unique(
            &mut expected.lineages,
            key,
            value,
            "multiple lineage fences claim one exact variant",
        )?;
    }
    expected.usage.lineage_rows = u64::try_from(expected.lineages.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;

    for row in publications.iter()? {
        let (key, value) = row?;
        let transfer = super::parse_blob_transfer_id("Blob publication table", key.value())?;
        let encoded = value.value();
        match schema {
            LifecycleSchemaState::Legacy if matches!(encoded.first().copied(), Some(4 | 5)) => {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob predecessor contains a current publication wrapper",
                )));
            }
            LifecycleSchemaState::V1
                if encoded.first().copied() != Some(LIFECYCLE_V1_PUBLICATION_RECORD_VERSION) =>
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle-v1 publication wrapper is missing",
                )));
            }
            LifecycleSchemaState::V2 | LifecycleSchemaState::V3
                if encoded.first().copied() != Some(PREDECESSOR_PUBLICATION_RECORD_VERSION) =>
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "predecessor Blob publication is missing its lifecycle wrapper",
                )));
            }
            LifecycleSchemaState::Current if !publication_is_current(encoded) => {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "current Blob publication is missing its lifecycle wrapper",
                )));
            }
            _ => {}
        }
        if schema == LifecycleSchemaState::V3
            && encoded.first().copied() != Some(PREDECESSOR_PUBLICATION_RECORD_VERSION)
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v3 publication wrapper is missing",
            )));
        }
        if matches!(
            schema,
            LifecycleSchemaState::V2 | LifecycleSchemaState::V3 | LifecycleSchemaState::Current
        ) && encoded.get(1).copied() == Some(PUBLICATION_STATE_RETIRED_TAG)
        {
            if let Some((_, payload)) =
                retired_publication_payload(encoded).map_err(StoreError::Blob)?
            {
                let metadata = super::decode_blob_metadata(payload)?;
                if metadata.header.ttl_ms.is_some() {
                    let intent = super::BlobPublicationIntent::new_with_ttl(
                        metadata.header.stamp.dot.publisher,
                        metadata.header.topic.clone(),
                        metadata.header.scope.clone(),
                        metadata.header.priority,
                        metadata.blob_id,
                        metadata.header.ttl_ms,
                    )?;
                    publication_intents.insert(transfer, intent.digest());
                }
            }
            let Some((_, generation, age)) =
                publication_retirement(encoded).map_err(StoreError::Blob)?
            else {
                unreachable!("retired publication tag decoded as live");
            };
            retired_publication_payload(encoded).map_err(StoreError::Blob)?;
            if source_bytes.get(key.value())?.is_some() {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "retired Blob publication still has source bytes",
                )));
            }
            reconstruct_retirement_authority(
                &mut expected,
                schema,
                generation,
                age,
                RetentionDeadlineOwner::Publication(transfer),
                None,
            )?;
            expected.usage.retired_publication_rows = expected
                .usage
                .retired_publication_rows
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            expected
                .retired_publications
                .insert(transfer.as_bytes().to_vec());
            let retained = if matches!(schema, LifecycleSchemaState::V2 | LifecycleSchemaState::V3)
            {
                upgrade_v3_publication(encoded)?
            } else {
                encoded.to_vec()
            };
            insert_unique(
                &mut expected.publications,
                key.value().to_vec(),
                retained,
                "multiple Blob publication rows claim one transfer identity",
            )?;
            continue;
        }
        let publication_payload = if schema == LifecycleSchemaState::V1 {
            &encoded[2..]
        } else {
            encoded
        };
        let publication = super::decode_blob_metadata(publication_payload)?;
        let intent = super::BlobPublicationIntent::new_with_ttl(
            publication.header.stamp.dot.publisher,
            publication.header.topic.clone(),
            publication.header.scope.clone(),
            publication.header.priority,
            publication.blob_id,
            publication.header.ttl_ms,
        )?;
        if publication.header.ttl_ms.is_some() {
            publication_intents.insert(transfer, intent.digest());
        }
        expected
            .live_publications
            .insert(transfer.as_bytes().to_vec());
        let physical_lineage = publication.physical_lineage.ok_or_else(|| {
            StoreError::Blob(BlobStoreError::SchemaInvariant(
                "accepted Blob publication is missing authenticated physical lineage",
            ))
        })?;
        if import_lineages.get(&publication.variant_id) != Some(&physical_lineage) {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "accepted Blob publication conflicts with its physical lineage",
            )));
        }
        let exact = source_bytes.get(key.value())?.ok_or_else(|| {
            StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob publication is missing exact source bytes during lifecycle audit",
            ))
        })?;
        let source_len = u64::try_from(exact.value().len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
        let dot = publication.header.stamp.dot;
        let replay_key = super::accepted_dot_key(dot).to_vec();
        let replay_value = ReplayFence::new(
            dot.publisher,
            dot.counter,
            publication.semantic_id,
            transfer,
            source_len,
            Sha256::digest(exact.value()).into(),
        )
        .encode()
        .to_vec();
        expected.usage.replay_bytes = expected
            .usage
            .replay_bytes
            .checked_add(entry_bytes(&replay_key, &replay_value)?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        insert_unique(
            &mut expected.replays,
            replay_key,
            replay_value,
            "multiple Blob publications claim one replay-fence publisher dot",
        )?;
        insert_unique(
            &mut expected.references,
            variant_reference_key(
                publication.variant_id,
                VariantReferenceOwner::Publication,
                transfer,
            ),
            Vec::new(),
            "multiple Blob publications claim one variant reference",
        )?;
        let wrapped = match schema {
            LifecycleSchemaState::Legacy => wrap_publication(encoded)?,
            LifecycleSchemaState::V1 => wrap_v1_publication(encoded)?,
            LifecycleSchemaState::V2 | LifecycleSchemaState::V3 => upgrade_v3_publication(encoded)?,
            LifecycleSchemaState::Current => encoded.to_vec(),
        };
        insert_unique(
            &mut expected.publications,
            key.value().to_vec(),
            wrapped,
            "multiple Blob publication rows claim one transfer identity",
        )?;
    }
    expected.usage.replay_rows = u64::try_from(expected.replays.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    expected.usage.publication_rows = u64::try_from(expected.publications.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;

    let mut saw_pending_without_order = false;
    let mut saw_pending_with_order = false;
    let mut next_pending_order = 1u64;
    for (key, value) in pending_sources {
        let transfer = super::parse_blob_transfer_id("pending Blob source table", &key)?;
        let mut pending = super::decode_pending_blob_source_for_encoding(
            &value,
            if schema == LifecycleSchemaState::Current {
                super::PendingBlobEncodingGeneration::Current
            } else {
                super::PendingBlobEncodingGeneration::Predecessor
            },
        )?;
        if pending.pending_acceptance_order == 0 {
            saw_pending_without_order = true;
            pending.pending_acceptance_order = next_pending_order;
            next_pending_order = next_pending_order.checked_add(1).ok_or_else(|| {
                StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "pending Blob acceptance order overflows during migration",
                ))
            })?;
        } else {
            saw_pending_with_order = true;
        }
        if saw_pending_without_order && saw_pending_with_order {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "pending Blob sources mix ordered and unordered predecessor generations",
            )));
        }
        if pending.metadata.transfer_id != transfer
            || import_lineages.get(&pending.metadata.variant_id) != Some(&pending.physical_lineage)
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "pending Blob source conflicts with its physical lineage",
            )));
        }
        insert_unique(
            &mut expected.references,
            variant_reference_key(
                pending.metadata.variant_id,
                VariantReferenceOwner::PendingSource,
                transfer,
            ),
            Vec::new(),
            "multiple pending Blob sources claim one variant reference",
        )?;
        let upgraded = if schema == LifecycleSchemaState::Current {
            value
        } else {
            super::encode_pending_blob_source(&pending)?
        };
        insert_unique(
            &mut expected.pending_sources,
            key,
            upgraded,
            "multiple pending Blob source rows claim one transfer identity",
        )?;
    }
    expected.usage.reference_rows = u64::try_from(expected.references.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;

    for row in operations.iter()? {
        let (key, value) = row?;
        let encoded = value.value();
        super::BlobOperationKey::new(key.value().to_vec())?;
        if matches!(
            schema,
            LifecycleSchemaState::V2 | LifecycleSchemaState::V3 | LifecycleSchemaState::Current
        ) && encoded.get(1).copied() == Some(OPERATION_STATE_RETIRED_TAG)
        {
            if encoded.first().copied() != Some(CURRENT_OPERATION_RECORD_VERSION) {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "current Blob operation is missing its lifecycle wrapper",
                )));
            }
            let OperationState::Retired {
                generation,
                operation_key_digest,
                age,
                ..
            } = OperationState::decode(&encoded[1..]).map_err(StoreError::Blob)?
            else {
                unreachable!("retired operation tag decoded as active");
            };
            if operation_key_digest != Sha256::digest(key.value()).as_slice() {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "retired Blob operation digest differs from its operation key",
                )));
            }
            reconstruct_retirement_authority(
                &mut expected,
                schema,
                generation,
                age,
                RetentionDeadlineOwner::Operation(operation_key_digest),
                Some(key.value()),
            )?;
            expected.usage.retired_operation_rows = expected
                .usage
                .retired_operation_rows
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            expected.operation_bytes = expected
                .operation_bytes
                .checked_add(entry_bytes(key.value(), encoded)?)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            insert_unique(
                &mut expected.operations,
                key.value().to_vec(),
                encoded.to_vec(),
                "multiple Blob operation rows claim one operation key",
            )?;
            continue;
        }
        let operation = super::decode_blob_operation_record(encoded)?;
        if !expected
            .live_publications
            .contains(operation.transfer_id.as_bytes().as_slice())
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "active Blob lifecycle operation points to a missing or retired publication",
            )));
        }
        if publication_intents
            .get(&operation.transfer_id)
            .is_some_and(|digest| digest != &operation.intent_digest)
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob operation intent digest contradicts its publication lifetime",
            )));
        }
        match schema {
            LifecycleSchemaState::Legacy | LifecycleSchemaState::V1
                if encoded.first().copied() != Some(super::BLOB_OPERATION_VERSION) =>
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob predecessor operation is not canonical",
                )));
            }
            LifecycleSchemaState::V2 | LifecycleSchemaState::V3 | LifecycleSchemaState::Current
                if encoded.first().copied() != Some(CURRENT_OPERATION_RECORD_VERSION) =>
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "current Blob operation is missing its lifecycle wrapper",
                )));
            }
            _ => {}
        }
        let wrapped = match schema {
            LifecycleSchemaState::Legacy | LifecycleSchemaState::V1 => wrap_operation(encoded)?,
            LifecycleSchemaState::V2 | LifecycleSchemaState::V3 | LifecycleSchemaState::Current => {
                encoded.to_vec()
            }
        };
        expected.operation_bytes = expected
            .operation_bytes
            .checked_add(entry_bytes(key.value(), &wrapped)?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        insert_unique(
            &mut expected.operations,
            key.value().to_vec(),
            wrapped,
            "multiple Blob operation rows claim one operation key",
        )?;
        insert_unique(
            &mut expected.operation_owners,
            inverse_owner_key(operation.transfer_id, key.value()),
            key.value().to_vec(),
            "multiple Blob operations claim one inverse owner key",
        )?;
    }
    expected.usage.operation_owner_rows = u64::try_from(expected.operation_owners.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    expected.usage.delivery_owner_rows = u64::try_from(expected.delivery_owners.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    expected.usage.deadline_rows = u64::try_from(expected.deadlines.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    expected.usage.retirement_resolver_rows = u64::try_from(expected.retirement_resolvers.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    Ok(expected)
}

fn audit_metadata(
    metadata: &impl ReadableTable<&'static str, u64>,
    mut usage: BlobLifecycleUsage,
    schema_version: u64,
) -> Result<BlobLifecycleUsage, StoreError> {
    if metadata.len()? != BLOB_LIFECYCLE_METADATA_FIELDS.len() as u64 {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle accounting metadata is incomplete",
        )));
    }
    for (field, expected) in [
        (BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD, schema_version),
        (BLOB_LINEAGE_ROWS, usage.lineage_rows),
        (BLOB_LINEAGE_BYTES, usage.lineage_bytes),
        (BLOB_REPLAY_ROWS, usage.replay_rows),
        (BLOB_REPLAY_BYTES, usage.replay_bytes),
        (BLOB_PUBLICATION_ROWS, usage.publication_rows),
        (BLOB_REFERENCE_ROWS, usage.reference_rows),
        (BLOB_OPERATION_OWNER_ROWS, usage.operation_owner_rows),
        (BLOB_DELIVERY_OWNER_ROWS, usage.delivery_owner_rows),
        (BLOB_DEADLINE_ROWS, usage.deadline_rows),
        (
            BLOB_RETIREMENT_RESOLVER_ROWS,
            usage.retirement_resolver_rows,
        ),
        (
            BLOB_RETIRED_PUBLICATION_ROWS,
            usage.retired_publication_rows,
        ),
        (BLOB_RETIRED_OPERATION_ROWS, usage.retired_operation_rows),
    ] {
        if metadata.get(field)?.map(|value| value.value()) != Some(expected) {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle accounting metadata disagrees with exact rows",
            )));
        }
    }
    let allocated_generation = metadata
        .get(BLOB_NEXT_RETIREMENT_GENERATION)?
        .map(|value| value.value())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle retirement generation high-water is missing",
        )))?;
    if allocated_generation < usage.next_retirement_generation {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle retirement generation high-water is below a durable retirement",
        )));
    }
    usage.next_retirement_generation = allocated_generation;
    Ok(usage)
}

fn audit_v2_metadata(
    metadata: &impl ReadableTable<&'static str, u64>,
    mut usage: BlobLifecycleUsage,
) -> Result<BlobLifecycleUsage, StoreError> {
    if metadata.len()? != 13 {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v2 accounting metadata is incomplete",
        )));
    }
    for (field, expected) in [
        (BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD, 2),
        (BLOB_LINEAGE_ROWS, usage.lineage_rows),
        (BLOB_LINEAGE_BYTES, usage.lineage_bytes),
        (BLOB_REPLAY_ROWS, usage.replay_rows),
        (BLOB_REPLAY_BYTES, usage.replay_bytes),
        (BLOB_PUBLICATION_ROWS, usage.publication_rows),
        (BLOB_REFERENCE_ROWS, usage.reference_rows),
        (BLOB_OPERATION_OWNER_ROWS, usage.operation_owner_rows),
        (BLOB_DELIVERY_OWNER_ROWS, usage.delivery_owner_rows),
        (BLOB_DEADLINE_ROWS, usage.deadline_rows),
        (
            BLOB_RETIRED_PUBLICATION_ROWS,
            usage.retired_publication_rows,
        ),
        (BLOB_RETIRED_OPERATION_ROWS, usage.retired_operation_rows),
    ] {
        if metadata.get(field)?.map(|value| value.value()) != Some(expected) {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v2 accounting differs from exact rows",
            )));
        }
    }
    let allocated_generation = metadata
        .get(BLOB_NEXT_RETIREMENT_GENERATION)?
        .map(|value| value.value())
        .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v2 retirement generation high-water is missing",
        )))?;
    if allocated_generation < usage.next_retirement_generation {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v2 retirement generation high-water is below a durable retirement",
        )));
    }
    usage.next_retirement_generation = allocated_generation;
    Ok(usage)
}

fn collect_retirement_resolvers(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, StoreError> {
    let mut rows = BTreeMap::new();
    for row in table.iter()? {
        let (key, value) = row?;
        let owner = decode_retirement_resolver_key(key.value())?;
        validate_retirement_resolver(owner, value.value())?;
        if rows
            .insert(key.value().to_vec(), value.value().to_vec())
            .is_some()
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "multiple Blob retirement resolvers claim one owner",
            )));
        }
    }
    Ok(rows)
}

fn collect_inverse_owners(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, StoreError> {
    let mut rows = BTreeMap::new();
    for row in table.iter()? {
        let (key, value) = row?;
        if key.value().len() != 64 || value.value().is_empty() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob inverse owner row is not canonical",
            )));
        }
        if key.value()[32..] != Sha256::digest(value.value())[..] {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob inverse owner digest differs from its forward key",
            )));
        }
        rows.insert(key.value().to_vec(), value.value().to_vec());
    }
    Ok(rows)
}

fn merge_v1_retained_lineages(
    lineages: &impl ReadableTable<&'static [u8], &'static [u8]>,
    expected: &mut ExpectedLifecycleImage,
    owner_binding: [u8; 32],
) -> Result<(), StoreError> {
    let required = expected.lineages.clone();
    let mut retained = BTreeMap::new();
    let mut lineage_bytes = 0u64;
    for row in lineages.iter()? {
        let (key, value) = row?;
        if key.value().len() != 32 {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v1 lineage fence has an invalid variant key",
            )));
        }
        let fence = LineageFence::decode(value.value()).map_err(StoreError::Blob)?;
        if fence.owner_binding != owner_binding {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v1 lineage authority has the wrong owner binding",
            )));
        }
        if let Some(required_value) = required.get(key.value()) {
            if !fence
                .same_authority(LineageFence::decode(required_value).map_err(StoreError::Blob)?)
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle-v1 lineage authority differs",
                )));
            }
        } else if !fence.bulk_reclamation_observed() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v1 orphan lineage lacks finalized reclamation authority",
            )));
        }
        lineage_bytes = lineage_bytes
            .checked_add(entry_bytes(key.value(), value.value())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        retained.insert(key.value().to_vec(), value.value().to_vec());
    }
    if required.keys().any(|key| !retained.contains_key(key)) {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v1 lineage fence is missing",
        )));
    }
    expected.usage.lineage_rows =
        u64::try_from(retained.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    expected.usage.lineage_bytes = lineage_bytes;
    expected.lineages = retained;
    Ok(())
}

fn audit_v1_before_migration(
    write_metadata: &impl ReadableTable<&'static str, u64>,
    references: &impl ReadableTable<&'static [u8], &'static [u8]>,
    lineages: &impl ReadableTable<&'static [u8], &'static [u8]>,
    replays: &impl ReadableTable<&'static [u8], &'static [u8]>,
    cursors: &impl ReadableTable<u8, &'static [u8]>,
    expected: &ExpectedLifecycleImage,
    owner_binding: [u8; 32],
) -> Result<(), StoreError> {
    const V1_FIELDS: [&str; 7] = [
        BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
        BLOB_LINEAGE_ROWS,
        BLOB_LINEAGE_BYTES,
        BLOB_REPLAY_ROWS,
        BLOB_REPLAY_BYTES,
        BLOB_PUBLICATION_ROWS,
        BLOB_REFERENCE_ROWS,
    ];
    if write_metadata.len()? != V1_FIELDS.len() as u64 {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v1 accounting metadata is incomplete",
        )));
    }
    for (field, expected_value) in [
        (BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD, 1),
        (BLOB_LINEAGE_ROWS, expected.usage.lineage_rows),
        (BLOB_LINEAGE_BYTES, expected.usage.lineage_bytes),
        (BLOB_REPLAY_ROWS, expected.usage.replay_rows),
        (BLOB_REPLAY_BYTES, expected.usage.replay_bytes),
        (BLOB_PUBLICATION_ROWS, expected.usage.publication_rows),
        (BLOB_REFERENCE_ROWS, expected.usage.reference_rows),
    ] {
        if write_metadata.get(field)?.map(|value| value.value()) != Some(expected_value) {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v1 accounting differs from exact rows",
            )));
        }
    }
    validate_maintenance_cursors(cursors)?;
    let actual_references = references
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            Ok((key.value().to_vec(), value.value().to_vec()))
        })
        .collect::<Result<BTreeMap<_, _>, redb::StorageError>>()?;
    let actual_replays = replays
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            ReplayFence::decode(value.value()).map_err(StoreError::Blob)?;
            Ok((key.value().to_vec(), value.value().to_vec()))
        })
        .collect::<Result<BTreeMap<_, _>, StoreError>>()?;
    if actual_references != expected.references || actual_replays != expected.replays {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle-v1 relations are incomplete or mismatched",
        )));
    }
    let mut actual_lineages = BTreeMap::new();
    for row in lineages.iter()? {
        let (key, value) = row?;
        let fence = LineageFence::decode(value.value()).map_err(StoreError::Blob)?;
        if fence.owner_binding != owner_binding
            || (!expected.lineages.contains_key(key.value()) && !fence.bulk_reclamation_observed())
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v1 lineage authority is invalid",
            )));
        }
        actual_lineages.insert(key.value().to_vec(), value.value().to_vec());
    }
    for (key, expected_value) in &expected.lineages {
        let actual =
            actual_lineages
                .get(key)
                .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle-v1 lineage fence is missing",
                )))?;
        if !LineageFence::decode(actual)
            .map_err(StoreError::Blob)?
            .same_authority(LineageFence::decode(expected_value).map_err(StoreError::Blob)?)
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle-v1 lineage authority differs",
            )));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Exact bidirectional audit spans every lifecycle table.
fn audit_current_rows(
    metadata: &impl ReadableTable<&'static str, u64>,
    references: &impl ReadableTable<&'static [u8], &'static [u8]>,
    lineages: &impl ReadableTable<&'static [u8], &'static [u8]>,
    replays: &impl ReadableTable<&'static [u8], &'static [u8]>,
    cursors: &impl ReadableTable<u8, &'static [u8]>,
    operation_owners: &impl ReadableTable<&'static [u8], &'static [u8]>,
    delivery_owners: &impl ReadableTable<&'static [u8], &'static [u8]>,
    deadlines: &impl ReadableTable<&'static [u8], &'static [u8]>,
    retirement_resolvers: Option<BTreeMap<Vec<u8>, Vec<u8>>>,
    expected: &ExpectedLifecycleImage,
    owner_binding: [u8; 32],
    schema_version: u64,
) -> Result<BlobLifecycleUsage, StoreError> {
    validate_maintenance_cursors(cursors)?;

    let mut actual_lineages = BTreeMap::new();
    let mut actual_usage = expected.usage;
    actual_usage.lineage_bytes = 0;
    for row in lineages.iter()? {
        let (key, value) = row?;
        if key.value().len() != 32 {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lineage fence has an invalid variant key",
            )));
        }
        let fence = LineageFence::decode(value.value()).map_err(StoreError::Blob)?;
        if fence.owner_binding != owner_binding {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lineage fence has the wrong depot owner binding",
            )));
        }
        actual_usage.lineage_bytes = actual_usage
            .lineage_bytes
            .checked_add(entry_bytes(key.value(), value.value())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if !expected.lineages.contains_key(key.value()) && !fence.bulk_reclamation_observed() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "orphan Blob lineage fence lacks finalized reclamation authority",
            )));
        }
        actual_lineages.insert(key.value().to_vec(), value.value().to_vec());
    }
    actual_usage.lineage_rows = u64::try_from(actual_lineages.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    let mut actual_replays = BTreeMap::new();
    let mut retired_replays = BTreeMap::<Vec<u8>, u64>::new();
    actual_usage.replay_bytes = 0;
    for row in replays.iter()? {
        let (key, value) = row?;
        if key.value().len() != 40 {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob replay fence has an invalid publisher-dot key",
            )));
        }
        let fence = ReplayFence::decode(value.value()).map_err(StoreError::Blob)?;
        if key.value()[..32] != fence.publisher || key.value()[32..] != fence.counter.to_be_bytes()
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob replay fence key differs from its publisher dot",
            )));
        }
        actual_usage.replay_bytes = actual_usage
            .replay_bytes
            .checked_add(entry_bytes(key.value(), value.value())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if expected
            .retired_publications
            .contains(fence.transfer_id.as_bytes().as_slice())
        {
            let count = retired_replays
                .entry(fence.transfer_id.as_bytes().to_vec())
                .or_default();
            *count = count
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
        } else if expected
            .live_publications
            .contains(fence.transfer_id.as_bytes().as_slice())
            && expected.replays.get(key.value()).map(Vec::as_slice) != Some(value.value())
        {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "live Blob publication has a noncanonical extra replay fence",
            )));
        }
        actual_replays.insert(key.value().to_vec(), value.value().to_vec());
    }
    actual_usage.replay_rows =
        u64::try_from(actual_replays.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    let mut actual_references = BTreeMap::new();
    for row in references.iter()? {
        let (key, value) = row?;
        if key.value().len() != 65 || !value.value().is_empty() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob variant reference is not canonical",
            )));
        }
        VariantReferenceOwner::decode(&key.value()[32..33]).map_err(StoreError::Blob)?;
        actual_references.insert(key.value().to_vec(), value.value().to_vec());
    }
    let actual_operation_owners = collect_inverse_owners(operation_owners)?;
    let actual_delivery_owners = collect_inverse_owners(delivery_owners)?;
    let mut actual_deadlines = BTreeMap::new();
    for row in deadlines.iter()? {
        let (key, value) = row?;
        if schema_version == 2 {
            decode_retention_deadline_key_v2(key.value())?;
        } else {
            decode_retention_deadline_key(key.value())?;
        }
        if !value.value().is_empty() {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob retention deadline value is not empty",
            )));
        }
        actual_deadlines.insert(key.value().to_vec(), value.value().to_vec());
    }
    actual_usage.operation_owner_rows = u64::try_from(actual_operation_owners.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    actual_usage.delivery_owner_rows = u64::try_from(actual_delivery_owners.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    actual_usage.deadline_rows = u64::try_from(actual_deadlines.len())
        .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    if let Some(resolvers) = retirement_resolvers.as_ref() {
        actual_usage.retirement_resolver_rows =
            u64::try_from(resolvers.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    }
    if expected
        .retired_publications
        .iter()
        .any(|transfer| retired_replays.get(transfer) != Some(&1))
        || retired_replays.len() != expected.retired_publications.len()
        || expected
            .replays
            .iter()
            .any(|(key, value)| actual_replays.get(key) != Some(value))
        || actual_references != expected.references
        || actual_operation_owners != expected.operation_owners
        || actual_delivery_owners != expected.delivery_owners
        || actual_deadlines != expected.deadlines
        || retirement_resolvers
            .as_ref()
            .is_some_and(|actual| actual != &expected.retirement_resolvers)
    {
        return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle authority relations are incomplete or mismatched",
        )));
    }
    for (key, value) in &expected.lineages {
        let Some(actual) = actual_lineages.get(key) else {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle authority relations are incomplete or mismatched",
            )));
        };
        let actual = LineageFence::decode(actual).map_err(StoreError::Blob)?;
        let expected = LineageFence::decode(value).map_err(StoreError::Blob)?;
        if !actual.same_authority(expected) {
            return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle authority relations are incomplete or mismatched",
            )));
        }
    }
    match schema_version {
        2 => audit_v2_metadata(metadata, actual_usage),
        3 => audit_metadata(metadata, actual_usage, 3),
        BLOB_LIFECYCLE_SCHEMA_VERSION => {
            audit_metadata(metadata, actual_usage, BLOB_LIFECYCLE_SCHEMA_VERSION)
        }
        _ => Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
            "Blob lifecycle schema version is unknown",
        ))),
    }
}

fn preflight_migration_limits(
    usage: BlobLifecycleUsage,
    limits: BlobLifecycleLimits,
) -> Result<(), StoreError> {
    if usage.lineage_rows > limits.max_lineage_rows()
        || usage.lineage_bytes > limits.max_lineage_bytes()
    {
        return Err(StoreError::Blob(BlobStoreError::LineageFenceCapacity {
            required_rows: usage.lineage_rows,
            required_bytes: usage.lineage_bytes,
            max_rows: limits.max_lineage_rows(),
            max_bytes: limits.max_lineage_bytes(),
        }));
    }
    if usage.replay_rows > limits.max_replay_rows()
        || usage.replay_bytes > limits.max_replay_bytes()
    {
        return Err(StoreError::Blob(BlobStoreError::ReplayFenceCapacity {
            required_rows: usage.replay_rows,
            required_bytes: usage.replay_bytes,
            max_rows: limits.max_replay_rows(),
            max_bytes: limits.max_replay_bytes(),
        }));
    }
    if usage.publication_rows > limits.max_publication_rows() {
        return Err(StoreError::Blob(
            BlobStoreError::PublicationLifecycleCapacity {
                required_rows: usage.publication_rows,
                max_rows: limits.max_publication_rows(),
            },
        ));
    }
    Ok(())
}

/// Reconstructs and preflights a complete predecessor image, or strictly
/// audits an already-current lifecycle schema without repairing it.
pub(crate) fn stage_blob_lifecycle_migration_write(
    write: &redb::WriteTransaction,
    limits: BlobLifecycleLimits,
    owner_binding: [u8; 32],
    stats: &mut BlobStoreStats,
) -> Result<Option<BlobLifecycleMigration>, StoreError> {
    let mut schema = lifecycle_schema_state_write(write)?;
    if schema == LifecycleSchemaState::Current {
        let version = write
            .open_table(BLOB_LIFECYCLE_METADATA)?
            .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
            .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle metadata lacks its schema version",
            )))?;
        schema = match version {
            3 => LifecycleSchemaState::V3,
            BLOB_LIFECYCLE_SCHEMA_VERSION => LifecycleSchemaState::Current,
            _ => {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle schema version is unknown",
                )));
            }
        };
    }
    #[cfg(test)]
    if schema == LifecycleSchemaState::Legacy && TEST_BLOB_LIFECYCLE_MIGRATION_DISABLED.get() {
        return Ok(None);
    }
    let delivery_owners = crate::blob_subscription::lifecycle_delivery_owners_write(write)?;
    let publications = write.open_table(super::BLOB_PUBLICATIONS)?;
    let source_bytes = write.open_table(super::BLOB_BYTES)?;
    let operations = write.open_table(super::BLOB_OPERATIONS)?;
    let pending = write.open_table(super::BLOB_PENDING_SOURCES)?;
    let pending_rows = pending
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            Ok((key.value().to_vec(), value.value().to_vec()))
        })
        .collect::<Result<Vec<_>, redb::StorageError>>()?;
    let mut expected = reconstruct_expected_image(
        &publications,
        &source_bytes,
        &operations,
        pending_rows,
        delivery_owners,
        depot::audited_lifecycle_imports_write(write)?,
        owner_binding,
        schema,
    )?;
    if schema == LifecycleSchemaState::V1 {
        merge_v1_retained_lineages(
            &write.open_table(BLOB_LINEAGE_FENCES)?,
            &mut expected,
            owner_binding,
        )?;
        audit_v1_before_migration(
            &write.open_table(BLOB_LIFECYCLE_METADATA)?,
            &write.open_table(BLOB_VARIANT_REFERENCES)?,
            &write.open_table(BLOB_LINEAGE_FENCES)?,
            &write.open_table(BLOB_REPLAY_FENCES)?,
            &write.open_table(BLOB_MAINTENANCE_CURSORS)?,
            &expected,
            owner_binding,
        )?;
    }
    match schema {
        LifecycleSchemaState::Legacy | LifecycleSchemaState::V1 => {
            preflight_migration_limits(expected.usage, limits)?;
            let operation_rows = u64::try_from(expected.operations.len())
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
            if operation_rows > super::MAX_BLOB_OPERATIONS
                || expected.operation_bytes > super::MAX_BLOB_OPERATION_BYTES
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "wrapped Blob operation usage exceeds its durable safety caps",
                )));
            }
            expected.usage.apply_to_stats(stats);
            Ok(Some(BlobLifecycleMigration { image: expected }))
        }
        LifecycleSchemaState::V2 => {
            let upgraded_publications = std::mem::take(&mut expected.publications);
            expected.publications = publications
                .iter()?
                .map(|row| {
                    let (key, value) = row?;
                    Ok((key.value().to_vec(), value.value().to_vec()))
                })
                .collect::<Result<BTreeMap<_, _>, redb::StorageError>>()?;
            let actual_usage = audit_current_rows(
                &write.open_table(BLOB_LIFECYCLE_METADATA)?,
                &write.open_table(BLOB_VARIANT_REFERENCES)?,
                &write.open_table(BLOB_LINEAGE_FENCES)?,
                &write.open_table(BLOB_REPLAY_FENCES)?,
                &write.open_table(BLOB_MAINTENANCE_CURSORS)?,
                &write.open_table(BLOB_OPERATION_OWNERS)?,
                &write.open_table(BLOB_DELIVERY_OWNERS)?,
                &write.open_table(BLOB_RETENTION_DEADLINES)?,
                None,
                &expected,
                owner_binding,
                2,
            )?;
            preflight_migration_limits(actual_usage, limits)?;
            expected.publications = upgraded_publications;
            expected.deadlines = expected
                .deadlines
                .keys()
                .map(|key| {
                    let (deadline, owner) = decode_retention_deadline_key_v2(key)?;
                    Ok((retention_deadline_key(deadline, owner).to_vec(), Vec::new()))
                })
                .collect::<Result<BTreeMap<_, _>, StoreError>>()?;
            // The exact v2 audit includes permanent replay and finalized
            // lineage fences that are intentionally retained after their
            // publication is retired.  Carry that audited accounting into
            // v3 instead of replacing it with only the rows reconstructible
            // from the retired wrapper.
            expected.usage = actual_usage;
            expected.usage.retirement_resolver_rows =
                u64::try_from(expected.retirement_resolvers.len())
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?;
            expected.usage.apply_to_stats(stats);
            Ok(Some(BlobLifecycleMigration { image: expected }))
        }
        LifecycleSchemaState::V3 => {
            let upgraded_publications = std::mem::take(&mut expected.publications);
            expected.publications = publications
                .iter()?
                .map(|row| {
                    let (key, value) = row?;
                    Ok((key.value().to_vec(), value.value().to_vec()))
                })
                .collect::<Result<BTreeMap<_, _>, redb::StorageError>>()?;
            let actual_usage = audit_current_rows(
                &write.open_table(BLOB_LIFECYCLE_METADATA)?,
                &write.open_table(BLOB_VARIANT_REFERENCES)?,
                &write.open_table(BLOB_LINEAGE_FENCES)?,
                &write.open_table(BLOB_REPLAY_FENCES)?,
                &write.open_table(BLOB_MAINTENANCE_CURSORS)?,
                &write.open_table(BLOB_OPERATION_OWNERS)?,
                &write.open_table(BLOB_DELIVERY_OWNERS)?,
                &write.open_table(BLOB_RETENTION_DEADLINES)?,
                Some(collect_retirement_resolvers(
                    &write.open_table(BLOB_RETIREMENT_RESOLVERS)?,
                )?),
                &expected,
                owner_binding,
                3,
            )?;
            preflight_migration_limits(actual_usage, limits)?;
            expected.publications = upgraded_publications;
            expected.usage = actual_usage;
            expected.usage.apply_to_stats(stats);
            Ok(Some(BlobLifecycleMigration { image: expected }))
        }
        LifecycleSchemaState::Current => {
            if u64::try_from(expected.publications.len())
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?
                != publications.len()?
                || u64::try_from(expected.operations.len())
                    .map_err(|_| StoreError::ItemCountAccountingOverflow)?
                    != operations.len()?
            {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle wrappers are not bidirectionally complete",
                )));
            }
            let actual_usage = audit_current_rows(
                &write.open_table(BLOB_LIFECYCLE_METADATA)?,
                &write.open_table(BLOB_VARIANT_REFERENCES)?,
                &write.open_table(BLOB_LINEAGE_FENCES)?,
                &write.open_table(BLOB_REPLAY_FENCES)?,
                &write.open_table(BLOB_MAINTENANCE_CURSORS)?,
                &write.open_table(BLOB_OPERATION_OWNERS)?,
                &write.open_table(BLOB_DELIVERY_OWNERS)?,
                &write.open_table(BLOB_RETENTION_DEADLINES)?,
                Some(collect_retirement_resolvers(
                    &write.open_table(BLOB_RETIREMENT_RESOLVERS)?,
                )?),
                &expected,
                owner_binding,
                BLOB_LIFECYCLE_SCHEMA_VERSION,
            )?;
            preflight_migration_limits(actual_usage, limits)?;
            actual_usage.apply_to_stats(stats);
            Ok(None)
        }
    }
}

/// Strict read-only predecessor/current audit. A complete predecessor is
/// reconstructed in memory only; current authority must match bidirectionally.
pub(crate) fn inspect_blob_lifecycle_read(
    read: &redb::ReadTransaction,
) -> Result<BlobLifecycleUsage, StoreError> {
    let normal = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let mut schema = lifecycle_schema_state_read(read)?;
    if schema == LifecycleSchemaState::Current {
        let version = read
            .open_table(BLOB_LIFECYCLE_METADATA)?
            .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
            .ok_or(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob lifecycle metadata lacks its schema version",
            )))?;
        schema = match version {
            3 => LifecycleSchemaState::V3,
            BLOB_LIFECYCLE_SCHEMA_VERSION => LifecycleSchemaState::Current,
            _ => {
                return Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "Blob lifecycle schema version is unknown",
                )));
            }
        };
    }
    let pending_rows = if normal.contains(super::BLOB_PENDING_SOURCES.name()) {
        read.open_table(super::BLOB_PENDING_SOURCES)?
            .iter()?
            .map(|row| {
                let (key, value) = row?;
                Ok((key.value().to_vec(), value.value().to_vec()))
            })
            .collect::<Result<Vec<_>, redb::StorageError>>()?
    } else {
        Vec::new()
    };
    let owner_binding = depot::depot_owner_binding_read(read)?;
    let mut expected = reconstruct_expected_image(
        &read.open_table(super::BLOB_PUBLICATIONS)?,
        &read.open_table(super::BLOB_BYTES)?,
        &read.open_table(super::BLOB_OPERATIONS)?,
        pending_rows,
        crate::blob_subscription::lifecycle_delivery_owners_read(read)?,
        depot::audited_lifecycle_imports_read(read)?,
        owner_binding,
        schema,
    )?;
    if schema == LifecycleSchemaState::V1 {
        merge_v1_retained_lineages(
            &read.open_table(BLOB_LINEAGE_FENCES)?,
            &mut expected,
            owner_binding,
        )?;
        audit_v1_before_migration(
            &read.open_table(BLOB_LIFECYCLE_METADATA)?,
            &read.open_table(BLOB_VARIANT_REFERENCES)?,
            &read.open_table(BLOB_LINEAGE_FENCES)?,
            &read.open_table(BLOB_REPLAY_FENCES)?,
            &read.open_table(BLOB_MAINTENANCE_CURSORS)?,
            &expected,
            owner_binding,
        )?;
    }
    if matches!(
        schema,
        LifecycleSchemaState::V2 | LifecycleSchemaState::V3 | LifecycleSchemaState::Current
    ) {
        if matches!(schema, LifecycleSchemaState::V2 | LifecycleSchemaState::V3) {
            expected.publications = read
                .open_table(super::BLOB_PUBLICATIONS)?
                .iter()?
                .map(|row| {
                    let (key, value) = row?;
                    Ok((key.value().to_vec(), value.value().to_vec()))
                })
                .collect::<Result<BTreeMap<_, _>, redb::StorageError>>()?;
        }
        return audit_current_rows(
            &read.open_table(BLOB_LIFECYCLE_METADATA)?,
            &read.open_table(BLOB_VARIANT_REFERENCES)?,
            &read.open_table(BLOB_LINEAGE_FENCES)?,
            &read.open_table(BLOB_REPLAY_FENCES)?,
            &read.open_table(BLOB_MAINTENANCE_CURSORS)?,
            &read.open_table(BLOB_OPERATION_OWNERS)?,
            &read.open_table(BLOB_DELIVERY_OWNERS)?,
            &read.open_table(BLOB_RETENTION_DEADLINES)?,
            if matches!(
                schema,
                LifecycleSchemaState::V3 | LifecycleSchemaState::Current
            ) {
                Some(collect_retirement_resolvers(
                    &read.open_table(BLOB_RETIREMENT_RESOLVERS)?,
                )?)
            } else {
                None
            },
            &expected,
            owner_binding,
            if schema == LifecycleSchemaState::Current {
                BLOB_LIFECYCLE_SCHEMA_VERSION
            } else if schema == LifecycleSchemaState::V3 {
                3
            } else {
                2
            },
        );
    }
    Ok(expected.usage)
}

impl BlobLifecycleMigration {
    pub(crate) fn apply(&self, write: &redb::WriteTransaction) -> Result<(), StoreError> {
        let mut metadata = write.open_table(BLOB_LIFECYCLE_METADATA)?;
        for (field, value) in [
            (
                BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
                BLOB_LIFECYCLE_SCHEMA_VERSION,
            ),
            (BLOB_LINEAGE_ROWS, self.image.usage.lineage_rows),
            (BLOB_LINEAGE_BYTES, self.image.usage.lineage_bytes),
            (BLOB_REPLAY_ROWS, self.image.usage.replay_rows),
            (BLOB_REPLAY_BYTES, self.image.usage.replay_bytes),
            (BLOB_PUBLICATION_ROWS, self.image.usage.publication_rows),
            (BLOB_REFERENCE_ROWS, self.image.usage.reference_rows),
            (
                BLOB_OPERATION_OWNER_ROWS,
                self.image.usage.operation_owner_rows,
            ),
            (
                BLOB_DELIVERY_OWNER_ROWS,
                self.image.usage.delivery_owner_rows,
            ),
            (BLOB_DEADLINE_ROWS, self.image.usage.deadline_rows),
            (
                BLOB_RETIREMENT_RESOLVER_ROWS,
                self.image.usage.retirement_resolver_rows,
            ),
            (
                BLOB_RETIRED_PUBLICATION_ROWS,
                self.image.usage.retired_publication_rows,
            ),
            (
                BLOB_RETIRED_OPERATION_ROWS,
                self.image.usage.retired_operation_rows,
            ),
            (
                BLOB_NEXT_RETIREMENT_GENERATION,
                self.image.usage.next_retirement_generation,
            ),
        ] {
            metadata.insert(field, value)?;
        }
        drop(metadata);
        initialize_maintenance_cursors(write)?;

        let mut lineages = write.open_table(BLOB_LINEAGE_FENCES)?;
        for (key, value) in &self.image.lineages {
            lineages.insert(key.as_slice(), value.as_slice())?;
        }
        drop(lineages);
        let mut replays = write.open_table(BLOB_REPLAY_FENCES)?;
        for (key, value) in &self.image.replays {
            replays.insert(key.as_slice(), value.as_slice())?;
        }
        drop(replays);
        let mut references = write.open_table(BLOB_VARIANT_REFERENCES)?;
        for (key, value) in &self.image.references {
            references.insert(key.as_slice(), value.as_slice())?;
        }
        drop(references);
        let mut operation_owners = write.open_table(BLOB_OPERATION_OWNERS)?;
        for (key, value) in &self.image.operation_owners {
            operation_owners.insert(key.as_slice(), value.as_slice())?;
        }
        drop(operation_owners);
        let mut delivery_owners = write.open_table(BLOB_DELIVERY_OWNERS)?;
        for (key, value) in &self.image.delivery_owners {
            delivery_owners.insert(key.as_slice(), value.as_slice())?;
        }
        drop(delivery_owners);
        let existing_deadline_keys = write
            .open_table(BLOB_RETENTION_DEADLINES)?
            .iter()?
            .map(|row| row.map(|(key, _)| key.value().to_vec()))
            .collect::<Result<Vec<_>, redb::StorageError>>()?;
        let mut deadlines = write.open_table(BLOB_RETENTION_DEADLINES)?;
        for key in existing_deadline_keys {
            deadlines.remove(key.as_slice())?;
        }
        for (key, value) in &self.image.deadlines {
            deadlines.insert(key.as_slice(), value.as_slice())?;
        }
        drop(deadlines);
        let mut resolvers = write.open_table(BLOB_RETIREMENT_RESOLVERS)?;
        for (key, value) in &self.image.retirement_resolvers {
            resolvers.insert(key.as_slice(), value.as_slice())?;
        }
        drop(resolvers);
        let mut publications = write.open_table(super::BLOB_PUBLICATIONS)?;
        for (key, value) in &self.image.publications {
            publications.insert(key.as_slice(), value.as_slice())?;
        }
        drop(publications);
        let mut operations = write.open_table(super::BLOB_OPERATIONS)?;
        for (key, value) in &self.image.operations {
            operations.insert(key.as_slice(), value.as_slice())?;
        }
        drop(operations);
        let mut pending = write.open_table(super::BLOB_PENDING_SOURCES)?;
        for (key, value) in &self.image.pending_sources {
            pending.insert(key.as_slice(), value.as_slice())?;
        }
        drop(pending);
        let pending_bytes =
            self.image
                .pending_sources
                .iter()
                .try_fold(0u64, |total, (key, value)| {
                    total
                        .checked_add(super::staging_entry_bytes(key.len(), value.len())?)
                        .ok_or(StoreError::PayloadByteAccountingOverflow)
                })?;
        let mut network_metadata = write.open_table(super::BLOB_NETWORK_METADATA)?;
        network_metadata.insert(
            super::BLOB_NETWORK_STAGING_ROWS,
            u64::try_from(self.image.pending_sources.len())
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        )?;
        network_metadata.insert(super::BLOB_NETWORK_STAGING_BYTES, pending_bytes)?;
        write.open_table(super::METADATA)?.insert(
            super::BLOB_OPERATION_TOTAL_BYTES,
            self.image.operation_bytes,
        )?;
        Ok(())
    }
}

/// Durable maintenance classes in the approved eligibility order.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobMaintenanceClass {
    ExpiredPublicationsAndPendingSources,
    InvalidPendingWork,
    UnreferencedLocalImportStaging,
    UnreferencedCompletedVariants,
    ExpiredRetirementRecords,
    ManifestBackedPhysicalDeletion,
}

impl BlobMaintenanceClass {
    pub const ALL: [Self; 6] = [
        Self::ExpiredPublicationsAndPendingSources,
        Self::InvalidPendingWork,
        Self::UnreferencedLocalImportStaging,
        Self::UnreferencedCompletedVariants,
        Self::ExpiredRetirementRecords,
        Self::ManifestBackedPhysicalDeletion,
    ];

    pub const fn cursor_key(self) -> u8 {
        match self {
            Self::ExpiredPublicationsAndPendingSources => 1,
            Self::InvalidPendingWork => 2,
            Self::UnreferencedLocalImportStaging => 3,
            Self::UnreferencedCompletedVariants => 4,
            Self::ExpiredRetirementRecords => 5,
            Self::ManifestBackedPhysicalDeletion => 6,
        }
    }

    pub(crate) const fn from_cursor_key(key: u8) -> Option<Self> {
        match key {
            1 => Some(Self::ExpiredPublicationsAndPendingSources),
            2 => Some(Self::InvalidPendingWork),
            3 => Some(Self::UnreferencedLocalImportStaging),
            4 => Some(Self::UnreferencedCompletedVariants),
            5 => Some(Self::ExpiredRetirementRecords),
            6 => Some(Self::ManifestBackedPhysicalDeletion),
            _ => None,
        }
    }

    pub(crate) const fn next(self) -> Self {
        match self {
            Self::ExpiredPublicationsAndPendingSources => Self::InvalidPendingWork,
            Self::InvalidPendingWork => Self::UnreferencedLocalImportStaging,
            Self::UnreferencedLocalImportStaging => Self::UnreferencedCompletedVariants,
            Self::UnreferencedCompletedVariants => Self::ExpiredRetirementRecords,
            Self::ExpiredRetirementRecords => Self::ManifestBackedPhysicalDeletion,
            Self::ManifestBackedPhysicalDeletion => Self::ExpiredPublicationsAndPendingSources,
        }
    }
}

/// Independent bounds for one internal Blob maintenance turn.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobMaintenanceBudget {
    pub(crate) rows: u64,
    pub(crate) files: u64,
    pub(crate) bytes: u64,
}

impl BlobMaintenanceBudget {
    /// Constructs a maintenance budget with every bound enabled.
    pub const fn new(rows: u64, files: u64, bytes: u64) -> Result<Self, BlobStoreError> {
        if rows == 0 || files == 0 || bytes == 0 {
            return Err(BlobStoreError::InvalidMaintenanceBudget);
        }
        Ok(Self { rows, files, bytes })
    }

    pub const fn rows(self) -> u64 {
        self.rows
    }

    pub const fn files(self) -> u64 {
        self.files
    }

    pub const fn bytes(self) -> u64 {
        self.bytes
    }
}

/// A bounded destructive discovery which deliberately remains pending until a
/// later retention/deletion handler is available.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobMaintenanceCandidate {
    UnreferencedLocalImport {
        staging_variant: super::BlobVariantId,
    },
    UnreferencedCompletedVariant {
        variant: super::BlobVariantId,
    },
}

/// Observable result of one bounded internal maintenance scheduling turn.
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobMaintenanceProgress {
    pub class: BlobMaintenanceClass,
    pub rows_examined: u64,
    pub files_examined: u64,
    pub bytes_examined: u64,
    pub candidates: Vec<BlobMaintenanceCandidate>,
    pub class_has_more_work: bool,
    pub awaiting_later_handler: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobMaintenanceCursor {
    pub(crate) class: BlobMaintenanceClass,
    pub(crate) position: Option<Vec<u8>>,
}

fn cursor_invariant(reason: &'static str) -> StoreError {
    StoreError::Blob(BlobStoreError::SchemaInvariant(reason))
}

fn encode_class_cursor(position: Option<&[u8]>) -> Vec<u8> {
    let mut encoded = vec![
        MAINTENANCE_CURSOR_VERSION,
        if position.is_some() {
            MAINTENANCE_CURSOR_POSITION_TAG
        } else {
            MAINTENANCE_CURSOR_UNSET_TAG
        },
    ];
    if let Some(position) = position {
        encoded.extend_from_slice(position);
    }
    encoded
}

fn validate_class_position(class: BlobMaintenanceClass, position: &[u8]) -> Result<(), StoreError> {
    let canonical = match class {
        BlobMaintenanceClass::ExpiredPublicationsAndPendingSources => {
            position.len() == 33
                && matches!(
                    position[0],
                    MAINTENANCE_PUBLICATION_SOURCE_TAG | MAINTENANCE_PENDING_SOURCE_TAG
                )
        }
        BlobMaintenanceClass::InvalidPendingWork => {
            (position.len() == 33 && position[0] == MAINTENANCE_INVALID_PENDING_SOURCE_TAG)
                || (position.len() == 66
                    && position[0] == MAINTENANCE_CARRIER_SOURCE_TAG
                    && position[33] == 2)
        }
        BlobMaintenanceClass::UnreferencedLocalImportStaging
        | BlobMaintenanceClass::UnreferencedCompletedVariants => position.len() == 32,
        BlobMaintenanceClass::ExpiredRetirementRecords => {
            !position.is_empty() && position.len() <= super::MAX_BLOB_OPERATION_KEY_BYTES
        }
        BlobMaintenanceClass::ManifestBackedPhysicalDeletion => {
            (position.len() == 33
                && matches!(
                    position[0],
                    MAINTENANCE_DELETION_MANIFEST_TAG | MAINTENANCE_DELETION_MANIFEST_RESUME_TAG
                ))
                || (position.len() == 41
                    && matches!(
                        position[0],
                        MAINTENANCE_DELETION_CHUNK_TAG | MAINTENANCE_DELETION_CHUNK_RESUME_TAG
                    ))
        }
    };
    if canonical {
        Ok(())
    } else {
        Err(cursor_invariant(
            "Blob maintenance cursor has a malformed class position",
        ))
    }
}

fn decode_class_cursor(
    class: BlobMaintenanceClass,
    encoded: &[u8],
) -> Result<Option<Vec<u8>>, StoreError> {
    if encoded.len() < 2 || encoded[0] != MAINTENANCE_CURSOR_VERSION {
        return Err(cursor_invariant(
            "Blob maintenance cursor has an unknown encoding version",
        ));
    }
    match encoded[1] {
        MAINTENANCE_CURSOR_UNSET_TAG if encoded.len() == 2 => Ok(None),
        MAINTENANCE_CURSOR_POSITION_TAG if encoded.len() > 2 => {
            let position = encoded[2..].to_vec();
            validate_class_position(class, &position)?;
            Ok(Some(position))
        }
        _ => Err(cursor_invariant(
            "Blob maintenance cursor has a noncanonical position encoding",
        )),
    }
}

fn decode_next_class(encoded: &[u8]) -> Result<BlobMaintenanceClass, StoreError> {
    let [version, class] = encoded else {
        return Err(cursor_invariant(
            "Blob maintenance next-class cursor has an invalid length",
        ));
    };
    if *version != MAINTENANCE_CURSOR_VERSION {
        return Err(cursor_invariant(
            "Blob maintenance next-class cursor has an unknown encoding version",
        ));
    }
    BlobMaintenanceClass::from_cursor_key(*class).ok_or_else(|| {
        cursor_invariant("Blob maintenance next-class cursor names an unknown class")
    })
}

fn validate_maintenance_cursors(
    cursors: &impl ReadableTable<u8, &'static [u8]>,
) -> Result<(), StoreError> {
    if cursors.len()? != 1 + BlobMaintenanceClass::ALL.len() as u64 {
        return Err(cursor_invariant(
            "Blob maintenance cursor set is incomplete or contains unknown rows",
        ));
    }
    let next = cursors
        .get(MAINTENANCE_NEXT_CLASS_KEY)?
        .ok_or_else(|| cursor_invariant("Blob maintenance next-class cursor is missing"))?;
    decode_next_class(next.value())?;
    for class in BlobMaintenanceClass::ALL {
        let encoded = cursors
            .get(class.cursor_key())?
            .ok_or_else(|| cursor_invariant("Blob maintenance class cursor is missing"))?;
        decode_class_cursor(class, encoded.value())?;
    }
    Ok(())
}

fn initialize_maintenance_cursors(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let mut cursors = write.open_table(BLOB_MAINTENANCE_CURSORS)?;
    if cursors.len()? != 0 {
        return validate_maintenance_cursors(&cursors);
    }
    cursors.insert(
        MAINTENANCE_NEXT_CLASS_KEY,
        [
            MAINTENANCE_CURSOR_VERSION,
            BlobMaintenanceClass::ALL[0].cursor_key(),
        ]
        .as_slice(),
    )?;
    let unset = encode_class_cursor(None);
    for class in BlobMaintenanceClass::ALL {
        cursors.insert(class.cursor_key(), unset.as_slice())?;
    }
    Ok(())
}

pub(crate) fn load_maintenance_cursor(
    write: &redb::WriteTransaction,
) -> Result<BlobMaintenanceCursor, StoreError> {
    let cursors = write.open_table(BLOB_MAINTENANCE_CURSORS)?;
    validate_maintenance_cursors(&cursors)?;
    let next = cursors
        .get(MAINTENANCE_NEXT_CLASS_KEY)?
        .ok_or_else(|| cursor_invariant("Blob maintenance next-class cursor is missing"))?;
    let class = decode_next_class(next.value())?;
    let position = cursors
        .get(class.cursor_key())?
        .ok_or_else(|| cursor_invariant("Blob maintenance class cursor is missing"))?;
    Ok(BlobMaintenanceCursor {
        class,
        position: decode_class_cursor(class, position.value())?,
    })
}

pub(crate) fn load_maintenance_cursor_read(
    read: &redb::ReadTransaction,
) -> Result<BlobMaintenanceCursor, StoreError> {
    let cursors = read.open_table(BLOB_MAINTENANCE_CURSORS)?;
    validate_maintenance_cursors(&cursors)?;
    let next = cursors
        .get(MAINTENANCE_NEXT_CLASS_KEY)?
        .ok_or_else(|| cursor_invariant("Blob maintenance next-class cursor is missing"))?;
    let class = decode_next_class(next.value())?;
    let position = cursors
        .get(class.cursor_key())?
        .ok_or_else(|| cursor_invariant("Blob maintenance class cursor is missing"))?;
    Ok(BlobMaintenanceCursor {
        class,
        position: decode_class_cursor(class, position.value())?,
    })
}

pub(crate) fn advance_maintenance_cursor(
    write: &redb::WriteTransaction,
    selected: BlobMaintenanceClass,
    position: Option<&[u8]>,
) -> Result<(), StoreError> {
    if let Some(position) = position {
        validate_class_position(selected, position)?;
    }
    let mut cursors = write.open_table(BLOB_MAINTENANCE_CURSORS)?;
    cursors.insert(
        selected.cursor_key(),
        encode_class_cursor(position).as_slice(),
    )?;
    super::deletion::manifest_admission_mutation_boundary()?;
    cursors.insert(
        MAINTENANCE_NEXT_CLASS_KEY,
        [MAINTENANCE_CURSOR_VERSION, selected.next().cursor_key()].as_slice(),
    )?;
    super::deletion::manifest_admission_mutation_boundary()?;
    Ok(())
}

/// Performs only constant-time table-metadata/accounting checks needed before
/// a bounded turn. Full row validation remains bounded by the selected page.
pub(crate) fn require_maintenance_accounting(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let metadata = write.open_table(BLOB_LIFECYCLE_METADATA)?;
    if metadata.len()? != BLOB_LIFECYCLE_METADATA_FIELDS.len() as u64
        || metadata
            .get(BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
            != Some(BLOB_LIFECYCLE_SCHEMA_VERSION)
    {
        return Err(cursor_invariant(
            "Blob lifecycle accounting metadata is incomplete or unknown",
        ));
    }
    let counter = |field| {
        metadata
            .get(field)
            .map_err(StoreError::from)?
            .map(|value| value.value())
            .ok_or_else(|| cursor_invariant("Blob lifecycle accounting field is missing"))
    };
    let lineage_rows = counter(BLOB_LINEAGE_ROWS)?;
    let replay_rows = counter(BLOB_REPLAY_ROWS)?;
    let publication_rows = counter(BLOB_PUBLICATION_ROWS)?;
    let reference_rows = counter(BLOB_REFERENCE_ROWS)?;
    let operation_owner_rows = counter(BLOB_OPERATION_OWNER_ROWS)?;
    let delivery_owner_rows = counter(BLOB_DELIVERY_OWNER_ROWS)?;
    let deadline_rows = counter(BLOB_DEADLINE_ROWS)?;
    let retirement_resolver_rows = counter(BLOB_RETIREMENT_RESOLVER_ROWS)?;
    let lineage_bytes = lineage_rows
        .checked_mul(32 + LineageFence::ENCODED_BYTES as u64)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    let replay_bytes = replay_rows
        .checked_mul(40 + ReplayFence::ENCODED_BYTES as u64)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if counter(BLOB_LINEAGE_BYTES)? != lineage_bytes
        || counter(BLOB_REPLAY_BYTES)? != replay_bytes
        || write.open_table(BLOB_LINEAGE_FENCES)?.len()? != lineage_rows
        || write.open_table(BLOB_REPLAY_FENCES)?.len()? != replay_rows
        || write.open_table(BLOB_VARIANT_REFERENCES)?.len()? != reference_rows
        || write.open_table(super::BLOB_PUBLICATIONS)?.len()? != publication_rows
        || write.open_table(BLOB_OPERATION_OWNERS)?.len()? != operation_owner_rows
        || write.open_table(BLOB_DELIVERY_OWNERS)?.len()? != delivery_owner_rows
        || write.open_table(BLOB_RETENTION_DEADLINES)?.len()? != deadline_rows
        || write.open_table(BLOB_RETIREMENT_RESOLVERS)?.len()? != retirement_resolver_rows
    {
        return Err(cursor_invariant(
            "Blob lifecycle accounting cannot describe the durable rows",
        ));
    }
    Ok(())
}

pub(crate) fn variant_has_reference(
    write: &redb::WriteTransaction,
    variant: super::BlobVariantId,
) -> Result<bool, StoreError> {
    let references = write.open_table(BLOB_VARIANT_REFERENCES)?;
    let start = variant.as_bytes().as_slice();
    let Some((key, value)) = references.range(start..)?.next().transpose()? else {
        return Ok(false);
    };
    if key.value().starts_with(start) {
        if key.value().len() != 65 || !value.value().is_empty() {
            return Err(cursor_invariant("Blob variant reference is not canonical"));
        }
        VariantReferenceOwner::decode(&key.value()[32..33]).map_err(StoreError::Blob)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub(crate) fn validate_maintenance_lineage_evidence(
    physical_lineage: [u8; 32],
    owner_binding: [u8; 32],
    encoded: &[u8],
) -> Result<(), StoreError> {
    let fence = LineageFence::decode(encoded).map_err(StoreError::Blob)?;
    if !fence.same_authority(LineageFence::new(physical_lineage, owner_binding)) {
        return Err(cursor_invariant(
            "retained Blob import conflicts with its lineage fence",
        ));
    }
    Ok(())
}

pub(crate) fn validate_maintenance_replay_evidence(
    expected: ReplayFence,
    encoded: &[u8],
) -> Result<(), StoreError> {
    let fence = ReplayFence::decode(encoded).map_err(StoreError::Blob)?;
    if fence != expected {
        return Err(cursor_invariant(
            "live Blob publication conflicts with its replay fence",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use aster_mesh::CustodySample;
    use redb::{Database, ReadableDatabase};

    use crate::{BlobSemanticId, BlobTransferId};

    use super::*;

    static NEXT_RETIREMENT_AUDIT_DB: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn expired_replay_causal_evidence_cannot_exist_without_blob_lifecycle_schema() {
        let path = std::env::temp_dir().join(format!(
            "aster-blob-orphan-causal-fence-{}-{}",
            std::process::id(),
            NEXT_RETIREMENT_AUDIT_DB.fetch_add(1, Ordering::Relaxed)
        ));
        let database = Database::create(&path).expect("create orphan causal-fence database");
        let write = database.begin_write().expect("orphan causal-fence write");
        write
            .open_table(BLOB_REPLAY_CAUSAL_FENCES)
            .expect("orphan causal-fence table")
            .insert([0x91; 40].as_slice(), [0x92; 32].as_slice())
            .expect("insert orphan causal-fence row");
        assert!(matches!(
            require_blob_lifecycle_absent_write(&write),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(_)))
        ));
        write.commit().expect("commit orphan causal-fence fixture");
        let read = database.begin_read().expect("orphan causal-fence read");
        assert!(matches!(
            require_blob_lifecycle_absent_read(&read),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(_)))
        ));
        drop(read);
        drop(database);
        std::fs::remove_file(path).expect("remove orphan causal-fence database");
    }

    fn audit_retired_test_image(
        write: &redb::WriteTransaction,
        expected: &ExpectedLifecycleImage,
    ) -> Result<BlobLifecycleUsage, StoreError> {
        audit_current_rows(
            &write.open_table(BLOB_LIFECYCLE_METADATA)?,
            &write.open_table(BLOB_VARIANT_REFERENCES)?,
            &write.open_table(BLOB_LINEAGE_FENCES)?,
            &write.open_table(BLOB_REPLAY_FENCES)?,
            &write.open_table(BLOB_MAINTENANCE_CURSORS)?,
            &write.open_table(BLOB_OPERATION_OWNERS)?,
            &write.open_table(BLOB_DELIVERY_OWNERS)?,
            &write.open_table(BLOB_RETENTION_DEADLINES)?,
            Some(collect_retirement_resolvers(
                &write.open_table(BLOB_RETIREMENT_RESOLVERS)?,
            )?),
            expected,
            [0x73; 32],
            BLOB_LIFECYCLE_SCHEMA_VERSION,
        )
    }

    #[test]
    fn blob_lifecycle_limits_reject_zero_and_preserve_exact_defaults() {
        assert_eq!(
            BlobLifecycleLimits::default(),
            BlobLifecycleLimits::new(65_536, 16 * 1024 * 1024, 65_536, 16 * 1024 * 1024, 65_536,)
                .expect("documented defaults are valid"),
        );
        assert_eq!(BlobLifecycleLimits::default().max_lineage_rows(), 65_536);
        assert_eq!(
            BlobLifecycleLimits::default().max_lineage_bytes(),
            16 * 1024 * 1024
        );
        assert_eq!(BlobLifecycleLimits::default().max_replay_rows(), 65_536);
        assert_eq!(
            BlobLifecycleLimits::default().max_replay_bytes(),
            16 * 1024 * 1024
        );
        assert_eq!(
            BlobLifecycleLimits::default().max_publication_rows(),
            65_536
        );
        assert_eq!(
            BlobLifecycleLimits::default().retain_for_ms(),
            3_888_000_000
        );

        for limits in [
            (0, 1, 1, 1, 1),
            (1, 0, 1, 1, 1),
            (1, 1, 0, 1, 1),
            (1, 1, 1, 0, 1),
            (1, 1, 1, 1, 0),
        ] {
            assert!(
                BlobLifecycleLimits::new(limits.0, limits.1, limits.2, limits.3, limits.4).is_err()
            );
        }
    }

    #[test]
    fn blob_lifecycle_codecs_reject_noncanonical_records() {
        assert_eq!(PublicationState::Live.encode(), [1]);
        assert_eq!(OperationState::Active.encode(), [1]);
        assert_eq!(VariantReferenceOwner::Publication.encode(), [1]);
        assert_eq!(VariantReferenceOwner::PendingSource.encode(), [2]);
        assert!(PublicationState::decode(&[0]).is_err());
        assert!(PublicationState::decode(&[1, 0]).is_err());
        assert!(OperationState::decode(&[2]).is_err());
        assert!(OperationState::decode(&[1, 0]).is_err());
        assert!(VariantReferenceOwner::decode(&[0]).is_err());
        assert!(VariantReferenceOwner::decode(&[1, 0]).is_err());

        let lineage = LineageFence::new([0x11; 32], [0x22; 32]);
        let mut expected_lineage = [0u8; 65];
        expected_lineage[0] = 1;
        expected_lineage[1..33].fill(0x11);
        expected_lineage[33..].fill(0x22);
        assert_eq!(lineage.encode(), expected_lineage);
        assert_eq!(
            LineageFence::decode(&expected_lineage).expect("canonical lineage"),
            lineage
        );
        assert!(LineageFence::decode(&expected_lineage[..64]).is_err());
        let mut reclaimed_lineage = expected_lineage;
        reclaimed_lineage[0] = RECLAIMED_LINEAGE_FENCE_VERSION;
        assert!(
            LineageFence::decode(&reclaimed_lineage)
                .expect("canonical reclaimed lineage")
                .bulk_reclamation_observed()
        );
        let mut lineage_with_unknown_version = expected_lineage;
        lineage_with_unknown_version[0] = 3;
        assert!(LineageFence::decode(&lineage_with_unknown_version).is_err());
        let mut lineage_with_trailing = expected_lineage.to_vec();
        lineage_with_trailing.push(0);
        assert!(LineageFence::decode(&lineage_with_trailing).is_err());

        let replay = ReplayFence::new(
            [0x33; 32],
            9,
            BlobSemanticId::new([0x44; 32]),
            BlobTransferId::new([0x55; 32]),
            123,
            [0x66; 32],
        );
        let mut expected_replay = [0u8; 145];
        expected_replay[0] = 1;
        expected_replay[1..33].fill(0x33);
        expected_replay[33..41].copy_from_slice(&9u64.to_be_bytes());
        expected_replay[41..73].fill(0x44);
        expected_replay[73..105].fill(0x55);
        expected_replay[105..113].copy_from_slice(&123u64.to_be_bytes());
        expected_replay[113..].fill(0x66);
        assert_eq!(replay.encode(), expected_replay);
        assert_eq!(
            ReplayFence::decode(&expected_replay).expect("canonical replay"),
            replay
        );
        assert!(ReplayFence::decode(&expected_replay[..144]).is_err());
        let mut replay_with_unknown_version = expected_replay;
        replay_with_unknown_version[0] = 2;
        assert!(ReplayFence::decode(&replay_with_unknown_version).is_err());
        let mut replay_with_trailing = expected_replay.to_vec();
        replay_with_trailing.push(0);
        assert!(ReplayFence::decode(&replay_with_trailing).is_err());
    }

    #[test]
    fn publication_v3_collision_is_resolved_only_by_trusted_schema_generation() {
        let metadata_like = [3, 1, 3, 0xaa, 0xbb];
        // Mutation caught: content sniffing would unwrap this valid metadata-v3
        // prefix merely because its transfer bytes resemble a v1 wrapper.
        assert_eq!(
            publication_payload_for_encoding(
                &metadata_like,
                PublicationEncodingGeneration::RawCurrent,
            )
            .unwrap(),
            metadata_like
        );
        assert!(
            publication_payload_for_encoding(
                &metadata_like,
                PublicationEncodingGeneration::LifecycleV1,
            )
            .is_err(),
            "historical lifecycle-v1 authority cannot admit a metadata-v3 payload"
        );

        let malformed_wrapper_that_starts_like_metadata = [3, 0, 3, 0xcc];
        // Mutation caught: fallback parse order must not reinterpret malformed
        // lifecycle-v1 state as current metadata under a v1 schema authority.
        assert!(
            publication_payload_for_encoding(
                &malformed_wrapper_that_starts_like_metadata,
                PublicationEncodingGeneration::LifecycleV1,
            )
            .is_err()
        );
        assert_eq!(
            publication_payload_for_encoding(
                &malformed_wrapper_that_starts_like_metadata,
                PublicationEncodingGeneration::RawCurrent,
            )
            .unwrap(),
            malformed_wrapper_that_starts_like_metadata
        );
    }

    #[test]
    fn blob_retirement_codecs_bind_reason_generation_digest_and_age_canonically() {
        // Break caught: retirement evidence must not admit an ambiguous reason,
        // generation, operation-key digest, clock sample, or trailing bytes.
        let sample = CustodySample {
            clock_id: [0x31; 16],
            tick_ms: 44,
        };
        let age = RetirementAge::new(55, sample, 123).expect("nonzero record retention");
        let publication = PublicationState::Retired {
            reason: RetirementReason::Evicted,
            generation: 66,
            age,
        };
        let operation = OperationState::Retired {
            reason: RetirementReason::Expired,
            generation: 77,
            operation_key_digest: [0x41; 32],
            intent_digest: [0x42; 32],
            age,
        };

        let publication_bytes = publication.encode();
        let operation_bytes = operation.encode();
        assert_eq!(
            PublicationState::decode(&publication_bytes).expect("publication retirement"),
            publication
        );
        assert_eq!(
            OperationState::decode(&operation_bytes).expect("operation retirement"),
            operation
        );
        assert_eq!(RetirementReason::decode(1), Some(RetirementReason::Expired));
        assert_eq!(
            RetirementReason::decode(2),
            Some(RetirementReason::Invalidated)
        );
        assert_eq!(RetirementReason::decode(3), Some(RetirementReason::Evicted));
        assert_eq!(RetirementReason::decode(0), None);
        assert_eq!(RetirementReason::decode(4), None);
        assert_eq!(age.retain_for_ms(), 123);
        assert!(RetirementAge::new(55, sample, 0).is_err());

        let mut trailing = publication_bytes.clone();
        trailing.push(0);
        assert!(PublicationState::decode(&trailing).is_err());
        let mut unknown_reason = operation_bytes;
        unknown_reason[1] = 0;
        assert!(OperationState::decode(&unknown_reason).is_err());
    }

    #[test]
    fn blob_retirement_clock_projects_same_domain_restart_and_known_deadline() {
        // Break caught: reopening in the same suspend-inclusive domain must
        // include elapsed restart time and retain an exact deadline.
        let accepted = CustodySample {
            clock_id: [0x51; 16],
            tick_ms: 100,
        };
        let projection = RetirementAge::new(40, accepted, 200)
            .expect("nonzero record retention")
            .project(Some(CustodySample {
                clock_id: accepted.clock_id,
                tick_ms: 160,
            }))
            .expect("same-domain projection");
        assert_eq!(projection.age.cumulative_age_ms(), 100);
        assert!(!projection.is_lower_bound);
        assert!(!projection.retention_elapsed);
        assert_eq!(
            projection.deadline,
            Some(CustodySample {
                clock_id: accepted.clock_id,
                tick_ms: 260,
            })
        );
    }

    #[test]
    fn blob_retirement_clock_loss_accumulates_lower_bound_across_domains_to_45_days() {
        // Break caught: a changed domain, rollback, or missing sample must not
        // invent freshness, and later measurable domains must still prove the
        // exact 45-day retirement bound.
        let retain_for_ms = DEFAULT_BLOB_RETIREMENT_RETENTION_MS;
        let domain_a = CustodySample {
            clock_id: [0xa1; 16],
            tick_ms: 10,
        };
        let first = RetirementAge::new(retain_for_ms - 30, domain_a, retain_for_ms)
            .expect("nonzero record retention")
            .project(Some(CustodySample {
                clock_id: domain_a.clock_id,
                tick_ms: 20,
            }))
            .expect("domain A interval");
        assert_eq!(first.age.cumulative_age_ms(), retain_for_ms - 20);
        assert!(!first.is_lower_bound);

        let domain_b = CustodySample {
            clock_id: [0xb2; 16],
            tick_ms: 500,
        };
        let changed = first.age.project(Some(domain_b)).expect("changed domain");
        assert!(changed.is_lower_bound);
        assert_eq!(changed.age.cumulative_age_ms(), retain_for_ms - 20);

        let rollback = changed
            .age
            .project(Some(CustodySample {
                clock_id: domain_b.clock_id,
                tick_ms: 400,
            }))
            .expect("rollback installs a conservative anchor");
        assert!(rollback.is_lower_bound);
        let missing = rollback
            .age
            .project(None)
            .expect("missing sample preserves lower bound");
        assert!(missing.is_lower_bound);
        assert_eq!(missing.deadline, None);

        let domain_c = CustodySample {
            clock_id: [0xc3; 16],
            tick_ms: 1_000,
        };
        let anchored = missing
            .age
            .project(Some(domain_c))
            .expect("new lower-bound anchor");
        let elapsed = anchored
            .age
            .project(Some(CustodySample {
                clock_id: domain_c.clock_id,
                tick_ms: 1_020,
            }))
            .expect("new measurable interval");
        assert_eq!(elapsed.age.cumulative_age_ms(), retain_for_ms);
        assert!(elapsed.is_lower_bound);
        assert!(elapsed.retention_elapsed);
        assert_eq!(elapsed.deadline, None);
    }

    #[test]
    fn blob_retirement_clock_overflow_fails_closed_as_elapsed() {
        // Break caught: checked-age overflow must never retain a retry fence as
        // apparently young or synthesize a wrapping deadline.
        let sample = CustodySample {
            clock_id: [0xf1; 16],
            tick_ms: 1,
        };
        let projection = RetirementAge::new(u64::MAX - 1, sample, u64::MAX)
            .expect("nonzero record retention")
            .project(Some(CustodySample {
                clock_id: sample.clock_id,
                tick_ms: 3,
            }))
            .expect("overflow is a conservative elapsed result");
        assert_eq!(projection.age.cumulative_age_ms(), u64::MAX);
        assert!(projection.is_lower_bound);
        assert!(projection.retention_elapsed);
        assert_eq!(projection.deadline, None);
    }

    #[test]
    fn blob_retired_rows_reconstruct_deadlines_counters_and_generation_across_reopen() {
        // Break caught: canonical retired rows and their exact deadline index
        // must be self-auditing; a restart must not reinterpret them as live or
        // require the retirement counters/high-water to remain zero.
        let sequence = NEXT_RETIREMENT_AUDIT_DB.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "aster-blob-retirement-audit-{}-{sequence}.redb",
            std::process::id()
        ));
        let transfer = BlobTransferId::new([0x71; 32]);
        let operation_key = b"retired-operation";
        let operation_digest: [u8; 32] = Sha256::digest(operation_key).into();
        let clock_id = [0x72; 16];
        let replay = ReplayFence::new(
            [0x74; 32],
            4,
            BlobSemanticId::new([0x75; 32]),
            transfer,
            321,
            [0x76; 32],
        );
        let replay_key = super::super::accepted_dot_key(crate::Dot {
            publisher: replay.publisher,
            counter: replay.counter,
        });
        let replay_value = replay.encode();
        let replay_bytes = entry_bytes(&replay_key, &replay_value).expect("replay bytes");
        let publication_age = RetirementAge::new(
            50,
            CustodySample {
                clock_id,
                tick_ms: 100,
            },
            200,
        )
        .expect("publication retention");
        let operation_age = RetirementAge::new(
            25,
            CustodySample {
                clock_id,
                tick_ms: 100,
            },
            200,
        )
        .expect("operation retention");
        let publication_state = PublicationState::Retired {
            reason: RetirementReason::Evicted,
            generation: 7,
            age: publication_age,
        };
        let operation_state = OperationState::Retired {
            reason: RetirementReason::Expired,
            generation: 9,
            operation_key_digest: operation_digest,
            intent_digest: [0x5a; 32],
            age: operation_age,
        };
        let mut publication_record = vec![CURRENT_PUBLICATION_RECORD_VERSION];
        publication_record.extend_from_slice(&publication_state.encode());
        let mut operation_record = vec![CURRENT_OPERATION_RECORD_VERSION];
        operation_record.extend_from_slice(&operation_state.encode());

        let database = Database::create(&path).expect("create retirement audit database");
        let write = database.begin_write().expect("retirement audit write");
        write
            .open_table(super::super::BLOB_PUBLICATIONS)
            .expect("publications")
            .insert(
                transfer.as_bytes().as_slice(),
                publication_record.as_slice(),
            )
            .expect("retired publication");
        write
            .open_table(super::super::BLOB_BYTES)
            .expect("source bytes");
        write
            .open_table(super::super::BLOB_OPERATIONS)
            .expect("operations")
            .insert(operation_key.as_slice(), operation_record.as_slice())
            .expect("retired operation");
        for table in [
            BLOB_VARIANT_REFERENCES,
            BLOB_LINEAGE_FENCES,
            BLOB_REPLAY_FENCES,
            BLOB_OPERATION_OWNERS,
            BLOB_DELIVERY_OWNERS,
            BLOB_RETENTION_DEADLINES,
            BLOB_RETIREMENT_RESOLVERS,
        ] {
            write.open_table(table).expect("lifecycle table");
        }
        write
            .open_table(BLOB_REPLAY_FENCES)
            .expect("replays")
            .insert(replay_key.as_slice(), replay_value.as_slice())
            .expect("permanent replay fence");
        initialize_maintenance_cursors(&write).expect("maintenance cursors");
        let publication_deadline = CustodySample {
            clock_id,
            tick_ms: 250,
        };
        let operation_deadline = CustodySample {
            clock_id,
            tick_ms: 275,
        };
        {
            let mut deadlines = write
                .open_table(BLOB_RETENTION_DEADLINES)
                .expect("retention deadlines");
            deadlines
                .insert(
                    retention_deadline_key(
                        publication_deadline,
                        RetentionDeadlineOwner::Publication(transfer),
                    )
                    .as_slice(),
                    &[][..],
                )
                .expect("publication deadline");
            deadlines
                .insert(
                    retention_deadline_key(
                        operation_deadline,
                        RetentionDeadlineOwner::Operation(operation_digest),
                    )
                    .as_slice(),
                    &[][..],
                )
                .expect("operation deadline");
        }
        {
            let mut resolvers = write
                .open_table(BLOB_RETIREMENT_RESOLVERS)
                .expect("retirement resolvers");
            resolvers
                .insert(
                    retirement_resolver_key(RetentionDeadlineOwner::Publication(transfer))
                        .as_slice(),
                    &[][..],
                )
                .expect("publication resolver");
            resolvers
                .insert(
                    retirement_resolver_key(RetentionDeadlineOwner::Operation(operation_digest))
                        .as_slice(),
                    operation_key.as_slice(),
                )
                .expect("operation resolver");
        }
        {
            let mut metadata = write
                .open_table(BLOB_LIFECYCLE_METADATA)
                .expect("lifecycle metadata");
            for (field, value) in [
                (
                    BLOB_LIFECYCLE_SCHEMA_VERSION_FIELD,
                    BLOB_LIFECYCLE_SCHEMA_VERSION,
                ),
                (BLOB_LINEAGE_ROWS, 0),
                (BLOB_LINEAGE_BYTES, 0),
                (BLOB_REPLAY_ROWS, 1),
                (BLOB_REPLAY_BYTES, replay_bytes),
                (BLOB_PUBLICATION_ROWS, 1),
                (BLOB_REFERENCE_ROWS, 0),
                (BLOB_OPERATION_OWNER_ROWS, 0),
                (BLOB_DELIVERY_OWNER_ROWS, 0),
                (BLOB_DEADLINE_ROWS, 2),
                (BLOB_RETIREMENT_RESOLVER_ROWS, 2),
                (BLOB_RETIRED_PUBLICATION_ROWS, 1),
                (BLOB_RETIRED_OPERATION_ROWS, 1),
                (BLOB_NEXT_RETIREMENT_GENERATION, 11),
            ] {
                metadata.insert(field, value).expect("metadata field");
            }
        }

        let expected = reconstruct_expected_image(
            &write
                .open_table(super::super::BLOB_PUBLICATIONS)
                .expect("publications"),
            &write
                .open_table(super::super::BLOB_BYTES)
                .expect("source bytes"),
            &write
                .open_table(super::super::BLOB_OPERATIONS)
                .expect("operations"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            [0x73; 32],
            LifecycleSchemaState::Current,
        )
        .expect("reconstruct retired authority");
        assert_eq!(expected.usage.retired_publication_rows, 1);
        assert_eq!(expected.usage.retired_operation_rows, 1);
        assert_eq!(expected.usage.deadline_rows, 2);
        assert_eq!(expected.usage.next_retirement_generation, 9);
        let audited = audit_retired_test_image(&write, &expected).expect("audit retired authority");
        assert_eq!(audited.next_retirement_generation, 11);
        assert_eq!(audited.replay_rows, 1);
        assert_eq!(audited.replay_bytes, replay_bytes);

        write
            .open_table(BLOB_LIFECYCLE_METADATA)
            .expect("metadata")
            .insert(BLOB_NEXT_RETIREMENT_GENERATION, 8)
            .expect("lower generation high-water");
        assert!(audit_retired_test_image(&write, &expected).is_err());
        write
            .open_table(BLOB_LIFECYCLE_METADATA)
            .expect("metadata")
            .insert(BLOB_NEXT_RETIREMENT_GENERATION, 11)
            .expect("restore generation high-water");

        let publication_deadline_key = retention_deadline_key(
            publication_deadline,
            RetentionDeadlineOwner::Publication(transfer),
        );
        write
            .open_table(BLOB_RETENTION_DEADLINES)
            .expect("deadlines")
            .remove(publication_deadline_key.as_slice())
            .expect("remove deadline");
        assert!(audit_retired_test_image(&write, &expected).is_err());
        write
            .open_table(BLOB_RETENTION_DEADLINES)
            .expect("deadlines")
            .insert(publication_deadline_key.as_slice(), &[][..])
            .expect("restore deadline");

        let publication_resolver_key =
            retirement_resolver_key(RetentionDeadlineOwner::Publication(transfer));
        write
            .open_table(BLOB_RETIREMENT_RESOLVERS)
            .expect("retirement resolvers")
            .remove(publication_resolver_key.as_slice())
            .expect("remove publication resolver");
        assert!(
            audit_retired_test_image(&write, &expected).is_err(),
            "every retired record must remain exactly discoverable"
        );
        write
            .open_table(BLOB_RETIREMENT_RESOLVERS)
            .expect("retirement resolvers")
            .insert(publication_resolver_key.as_slice(), &[][..])
            .expect("restore publication resolver");
        write.commit().expect("commit retirement authority");
        drop(database);

        let database = Database::open(&path).expect("reopen retirement audit database");
        let read = database.begin_read().expect("retirement audit read");
        let expected = reconstruct_expected_image(
            &read
                .open_table(super::super::BLOB_PUBLICATIONS)
                .expect("publications"),
            &read
                .open_table(super::super::BLOB_BYTES)
                .expect("source bytes"),
            &read
                .open_table(super::super::BLOB_OPERATIONS)
                .expect("operations"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            [0x73; 32],
            LifecycleSchemaState::Current,
        )
        .expect("reconstruct reopened retired authority");
        assert_eq!(expected.usage.deadline_rows, 2);
        audit_current_rows(
            &read.open_table(BLOB_LIFECYCLE_METADATA).expect("metadata"),
            &read
                .open_table(BLOB_VARIANT_REFERENCES)
                .expect("references"),
            &read.open_table(BLOB_LINEAGE_FENCES).expect("lineages"),
            &read.open_table(BLOB_REPLAY_FENCES).expect("replays"),
            &read.open_table(BLOB_MAINTENANCE_CURSORS).expect("cursors"),
            &read.open_table(BLOB_OPERATION_OWNERS).expect("owners"),
            &read
                .open_table(BLOB_DELIVERY_OWNERS)
                .expect("delivery owners"),
            &read
                .open_table(BLOB_RETENTION_DEADLINES)
                .expect("deadlines"),
            Some(
                collect_retirement_resolvers(
                    &read
                        .open_table(BLOB_RETIREMENT_RESOLVERS)
                        .expect("retirement resolvers"),
                )
                .expect("collect retirement resolvers"),
            ),
            &expected,
            [0x73; 32],
            BLOB_LIFECYCLE_SCHEMA_VERSION,
        )
        .expect("audit reopened retired authority");
        drop(read);
        drop(database);
        std::fs::remove_file(path).expect("remove retirement audit database");
    }

    #[test]
    fn blob_maintenance_class_order_keys_reverse_mapping_and_wraparound_are_stable() {
        use BlobMaintenanceClass::{
            ExpiredPublicationsAndPendingSources, ExpiredRetirementRecords, InvalidPendingWork,
            ManifestBackedPhysicalDeletion, UnreferencedCompletedVariants,
            UnreferencedLocalImportStaging,
        };

        assert_eq!(
            BlobMaintenanceClass::ALL,
            [
                ExpiredPublicationsAndPendingSources,
                InvalidPendingWork,
                UnreferencedLocalImportStaging,
                UnreferencedCompletedVariants,
                ExpiredRetirementRecords,
                ManifestBackedPhysicalDeletion,
            ]
        );
        for (class, key, next) in [
            (ExpiredPublicationsAndPendingSources, 1, InvalidPendingWork),
            (InvalidPendingWork, 2, UnreferencedLocalImportStaging),
            (
                UnreferencedLocalImportStaging,
                3,
                UnreferencedCompletedVariants,
            ),
            (UnreferencedCompletedVariants, 4, ExpiredRetirementRecords),
            (ExpiredRetirementRecords, 5, ManifestBackedPhysicalDeletion),
            (
                ManifestBackedPhysicalDeletion,
                6,
                ExpiredPublicationsAndPendingSources,
            ),
        ] {
            assert_eq!(class.cursor_key(), key);
            assert_eq!(BlobMaintenanceClass::from_cursor_key(key), Some(class));
            assert_eq!(class.next(), next);
        }
        assert_eq!(BlobMaintenanceClass::from_cursor_key(0), None);
        assert_eq!(BlobMaintenanceClass::from_cursor_key(7), None);
        assert_eq!(BlobMaintenanceClass::from_cursor_key(u8::MAX), None);
    }

    #[test]
    fn blob_manifest_deletion_cursor_accepts_canonical_work_and_resume_positions() {
        let class = BlobMaintenanceClass::ManifestBackedPhysicalDeletion;
        let mut manifest = [0x11; 33];
        manifest[0] = MAINTENANCE_DELETION_MANIFEST_TAG;
        let mut chunk = [0x22; 41];
        chunk[0] = MAINTENANCE_DELETION_CHUNK_TAG;
        let mut manifest_resume = manifest;
        manifest_resume[0] = MAINTENANCE_DELETION_MANIFEST_RESUME_TAG;
        let mut chunk_resume = chunk;
        chunk_resume[0] = MAINTENANCE_DELETION_CHUNK_RESUME_TAG;

        assert_eq!(
            decode_class_cursor(class, &encode_class_cursor(Some(&manifest)))
                .expect("canonical manifest cursor"),
            Some(manifest.to_vec())
        );
        assert_eq!(
            decode_class_cursor(class, &encode_class_cursor(Some(&chunk)))
                .expect("canonical chunk cursor"),
            Some(chunk.to_vec())
        );
        assert!(validate_class_position(class, &manifest_resume).is_ok());
        assert!(validate_class_position(class, &chunk_resume).is_ok());

        manifest[0] = MAINTENANCE_DELETION_CHUNK_TAG;
        chunk[0] = MAINTENANCE_DELETION_MANIFEST_TAG;
        assert!(validate_class_position(class, &manifest).is_err());
        assert!(validate_class_position(class, &chunk).is_err());
        assert!(validate_class_position(class, &[MAINTENANCE_DELETION_MANIFEST_TAG; 32]).is_err());
        assert!(validate_class_position(class, &[MAINTENANCE_DELETION_CHUNK_TAG; 40]).is_err());
    }

    mod blob_lifecycle_budget {
        use super::*;

        #[test]
        fn blob_maintenance_budget_requires_each_nonzero_bound() {
            assert_eq!(
                BlobMaintenanceBudget::new(5, 6, 7).expect("nonzero budget"),
                BlobMaintenanceBudget {
                    rows: 5,
                    files: 6,
                    bytes: 7,
                }
            );
            assert!(BlobMaintenanceBudget::new(0, 1, 1).is_err());
            assert!(BlobMaintenanceBudget::new(1, 0, 1).is_err());
            assert!(BlobMaintenanceBudget::new(1, 1, 0).is_err());
        }
    }
}
