//! Mission-bound Blob publication metadata and crash-safe ciphertext depot.
//!
//! Signed Blob publications live in redb, while potentially large encrypted
//! chunks live below the fixed sibling `blob-depot-v1` directory.  A depot
//! variant is keyed by `(BlobId, content group, content epoch)`, so distinct
//! publishers and priorities may reference the same immutable encrypted
//! content without aliasing their source-authenticated publication identities.
//! Depot limits bound durable import/chunk metadata rows and redb-marked chunk
//! file bytes. They do not claim a bound on unmarked, temporary, or hostile
//! untracked filesystem allocation.

pub(crate) mod depot;

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use aster_mesh::{
    BlobId, BlobRouteCommitment, ContentVerifiedBlobEnvelope, MAX_BLOB_CHUNK_SIZE, MAX_BLOB_CHUNKS,
    MAX_BLOB_MANIFEST_BYTES, SELECTED_BLOB_CHUNK_SIZE as CORE_SELECTED_BLOB_CHUNK_SIZE,
};
use redb::{ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle};

use super::*;

pub use depot::{BlobDepot, BlobDepotCompletion};

pub(crate) const BLOB_PUBLICATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-publications.v1");
pub(crate) const BLOB_BYTES: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-bytes.v1");
pub(crate) const BLOB_SEMANTIC_ITEMS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-items.v1");
// Composite `(topic, scope, BlobId, semantic publication id)` keys retain
// every signed publication which references one immutable Blob.
pub(crate) const BLOB_CONTENT_INDEX: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.semantic-blob-content.v1");
pub(crate) const BLOB_ACCEPTANCE_MARKERS: TableDefinition<&[u8], u64> =
    TableDefinition::new("aster.semantic-blob-markers.v1");
pub(crate) const BLOB_OPERATIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-operations.v1");
pub(crate) const BLOB_IMPORTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-imports.v1");
pub(crate) const BLOB_CHUNKS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-chunks.v1");
pub(crate) const BLOB_DEPOT_METADATA: TableDefinition<&str, u64> =
    TableDefinition::new("aster.blob-depot-metadata.v1");

pub(crate) const BLOB_ITEM_COUNT: &str = "semantic_blob_item_count";
pub(crate) const BLOB_TOTAL_BYTES: &str = "semantic_blob_total_bytes";
pub(crate) const LAST_BLOB_ACCEPTANCE_MARKER: &str = "last_semantic_blob_acceptance_marker";
pub(crate) const BLOB_OPERATION_COUNT: &str = "semantic_blob_operation_count";
pub(crate) const BLOB_OPERATION_TOTAL_BYTES: &str = "semantic_blob_operation_total_bytes";

pub(crate) const DEPOT_SCHEMA_VERSION: &str = "schema_version";
pub(crate) const DEPOT_VARIANT_COUNT: &str = "variant_count";
pub(crate) const DEPOT_COMMITTED_CHUNK_COUNT: &str = "committed_chunk_count";
pub(crate) const DEPOT_COMMITTED_FILE_BYTES: &str = "committed_file_bytes";
pub(crate) const DEPOT_OWNER_TOKEN_0: &str = "owner_token_0";
pub(crate) const DEPOT_OWNER_TOKEN_1: &str = "owner_token_1";
pub(crate) const DEPOT_OWNER_TOKEN_2: &str = "owner_token_2";
pub(crate) const DEPOT_OWNER_TOKEN_3: &str = "owner_token_3";
pub(crate) const DEPOT_OWNER_BINDING_0: &str = "owner_binding_0";
pub(crate) const DEPOT_OWNER_BINDING_1: &str = "owner_binding_1";
pub(crate) const DEPOT_OWNER_BINDING_2: &str = "owner_binding_2";
pub(crate) const DEPOT_OWNER_BINDING_3: &str = "owner_binding_3";
pub(crate) const BLOB_DEPOT_SCHEMA_VERSION: u64 = 1;

const BLOB_METADATA_VERSION: u8 = 1;
const BLOB_OPERATION_VERSION: u8 = 1;
const BLOB_PUBLICATION_INTENT_DOMAIN: &[u8] = b"aster/blob-publication-intent/v1";
const BLOB_VARIANT_DOMAIN: &[u8] = b"aster/blob-depot-variant/v1";

/// Selected interoperable Blob chunk size (64 KiB).
pub const SELECTED_BLOB_CHUNK_SIZE: u32 = CORE_SELECTED_BLOB_CHUNK_SIZE;
/// Maximum chunks representable by the selected one-MiB manifest bound.
pub const MAX_SELECTED_BLOB_CHUNKS: u64 = MAX_BLOB_CHUNKS;
/// Maximum byte length of one durable Blob operation key.
pub const MAX_BLOB_OPERATION_KEY_BYTES: usize = 256;
/// Maximum durable idempotent Blob operation mappings per store.
pub const MAX_BLOB_OPERATIONS: u64 = 4_096;
/// Maximum aggregate operation-key plus operation-record bytes.
pub const MAX_BLOB_OPERATION_BYTES: u64 = 512 * 1024;
/// Maximum signed publications retained for one `(topic, scope, BlobId)` read plan.
pub const MAX_BLOB_PUBLICATIONS_PER_CONTENT: usize = 1_024;
/// Default aggregate redb-marked chunk-file byte cap (512 MiB).
pub const DEFAULT_MAX_BLOB_DEPOT_BYTES: u64 = 512 * 1024 * 1024;
/// Default aggregate durable chunk-metadata row cap.
///
/// Plaintext-digest or expected-record staging consumes this cap before a file
/// becomes committed.
pub const DEFAULT_MAX_BLOB_DEPOT_CHUNKS: u64 = 100_000;
/// Default aggregate durable epoch-specific import-row cap.
///
/// An unfinished import consumes this cap.
pub const DEFAULT_MAX_BLOB_DEPOT_VARIANTS: u64 = 4_096;

/// Dedicated durable-admission limits for one mission-bound Blob depot.
///
/// `max_bytes` counts redb-marked chunk-file bytes, including each fixed file
/// header. `max_chunks` counts all durable chunk metadata rows, including
/// unfinished digest/expected-record staging. `max_variants` counts all durable
/// import rows, including unfinished imports. Abandoned staging remains durable
/// until a future explicit garbage-collection design; writable reopen reclaims
/// only unmarked physical artifacts. These limits intentionally do not bound
/// unmarked, temporary, or hostile untracked filesystem allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobDepotLimits {
    max_bytes: u64,
    max_chunks: u64,
    max_variants: u64,
}

impl BlobDepotLimits {
    /// Constructs nonzero aggregate physical depot limits.
    pub const fn new(
        max_bytes: u64,
        max_chunks: u64,
        max_variants: u64,
    ) -> Result<Self, BlobStoreError> {
        if max_bytes == 0 || max_chunks == 0 || max_variants == 0 {
            return Err(BlobStoreError::InvalidDepotLimits);
        }
        Ok(Self {
            max_bytes,
            max_chunks,
            max_variants,
        })
    }

    /// Maximum aggregate redb-marked chunk-file bytes.
    pub const fn max_bytes(self) -> u64 {
        self.max_bytes
    }

    /// Maximum durable chunk metadata rows, including unfinished staging.
    pub const fn max_chunks(self) -> u64 {
        self.max_chunks
    }

    /// Maximum durable import rows, including unfinished imports.
    pub const fn max_variants(self) -> u64 {
        self.max_variants
    }
}

impl Default for BlobDepotLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BLOB_DEPOT_BYTES,
            max_chunks: DEFAULT_MAX_BLOB_DEPOT_CHUNKS,
            max_variants: DEFAULT_MAX_BLOB_DEPOT_VARIANTS,
        }
    }
}

/// Blob-specific durable-schema, policy, and depot failures.
#[derive(Debug)]
pub enum BlobStoreError {
    InvalidDepotLimits,
    InvalidOperationKey {
        length: usize,
    },
    InvalidPublication(&'static str),
    Verification(String),
    OperationConflict,
    PublisherRevoked(NodeId),
    KeyEpochStale {
        current: u64,
        received: u64,
    },
    KeyEpochNotActive {
        current: u64,
        received: u64,
    },
    ReservationChanged,
    ReadPlanChanged,
    PublicationLimitExceeded {
        current: usize,
        limit: usize,
    },
    OperationLimitExceeded {
        current: u64,
        limit: u64,
    },
    OperationByteLimitExceeded {
        current: u64,
        incoming: u64,
        limit: u64,
    },
    DepotByteLimitExceeded {
        current: u64,
        incoming: u64,
        limit: u64,
    },
    DepotChunkLimitExceeded {
        current: u64,
        limit: u64,
    },
    DepotVariantLimitExceeded {
        current: u64,
        limit: u64,
    },
    SchemaInvariant(&'static str),
    DepotIntegrity(&'static str),
    CompletionMismatch,
    Io(std::io::Error),
}

impl fmt::Display for BlobStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDepotLimits => formatter.write_str("Blob depot limits must be nonzero"),
            Self::InvalidOperationKey { length } => write!(
                formatter,
                "Blob operation key length {length} is outside 1..={MAX_BLOB_OPERATION_KEY_BYTES}"
            ),
            Self::InvalidPublication(reason) => {
                write!(formatter, "invalid Blob publication: {reason}")
            }
            Self::Verification(reason) => write!(formatter, "Blob verification failed: {reason}"),
            Self::OperationConflict => {
                formatter.write_str("Blob operation key is bound to another intent")
            }
            Self::PublisherRevoked(publisher) => {
                write!(formatter, "Blob publisher {publisher:?} is revoked")
            }
            Self::KeyEpochStale { current, received } => write!(
                formatter,
                "Blob key epoch {received} is stale; current epoch is {current}"
            ),
            Self::KeyEpochNotActive { current, received } => write!(
                formatter,
                "Blob key epoch {received} is not active; current epoch is {current}"
            ),
            Self::ReservationChanged => {
                formatter.write_str("Blob reservation changed before commit")
            }
            Self::ReadPlanChanged => formatter.write_str("Blob read plan changed before use"),
            Self::PublicationLimitExceeded { current, limit } => write!(
                formatter,
                "Blob publication set has {current} rows at its {limit}-row limit"
            ),
            Self::OperationLimitExceeded { current, limit } => write!(
                formatter,
                "Blob operation ledger has {current} rows at its {limit}-row limit"
            ),
            Self::OperationByteLimitExceeded {
                current,
                incoming,
                limit,
            } => write!(
                formatter,
                "Blob operation ledger has {current} bytes and cannot admit {incoming} bytes under limit {limit}"
            ),
            Self::DepotByteLimitExceeded {
                current,
                incoming,
                limit,
            } => write!(
                formatter,
                "Blob depot has {current} bytes and cannot admit {incoming} bytes under limit {limit}"
            ),
            Self::DepotChunkLimitExceeded { current, limit } => write!(
                formatter,
                "Blob depot has {current} durable chunk rows at its {limit}-row limit"
            ),
            Self::DepotVariantLimitExceeded { current, limit } => write!(
                formatter,
                "Blob depot has {current} durable import rows at its {limit}-row limit"
            ),
            Self::SchemaInvariant(reason) => {
                write!(formatter, "durable Blob schema invariant failed: {reason}")
            }
            Self::DepotIntegrity(reason) => {
                write!(formatter, "Blob depot integrity failed: {reason}")
            }
            Self::CompletionMismatch => {
                formatter.write_str("Blob depot completion does not match the verified publication")
            }
            Self::Io(error) => write!(formatter, "Blob depot I/O failed: {error}"),
        }
    }
}

impl Error for BlobStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for BlobStoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

fn blob_error(error: BlobStoreError) -> StoreError {
    StoreError::Blob(error)
}

/// Exact SHA-256 identity of one stable source-sealed Blob manifest envelope.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobTransferId([u8; 32]);

impl BlobTransferId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Source-authenticated semantic identity of one signed Blob publication.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobSemanticId([u8; 32]);

impl BlobSemanticId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Physical encrypted-content partition for one Blob content group and epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobVariantId([u8; 32]);

impl BlobVariantId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives the exact physical partition for authenticated content metadata.
    pub fn for_content(blob_id: BlobId, content_group: &[u8; 32], epoch: u64) -> Self {
        let mut digest = Sha256::new();
        digest.update(BLOB_VARIANT_DOMAIN);
        digest.update(blob_id.as_bytes());
        digest.update(content_group);
        digest.update(epoch.to_be_bytes());
        Self::from_bytes(digest.finalize().into())
    }
}

pub(crate) fn blob_variant_id(
    blob_id: BlobId,
    content_group: &[u8; 32],
    epoch: u64,
) -> BlobVariantId {
    BlobVariantId::for_content(blob_id, content_group, epoch)
}

/// Bounded application idempotency key for one local Blob publication.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BlobOperationKey(Vec<u8>);

impl BlobOperationKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, StoreError> {
        let bytes = bytes.into();
        if bytes.is_empty() || bytes.len() > MAX_BLOB_OPERATION_KEY_BYTES {
            return Err(blob_error(BlobStoreError::InvalidOperationKey {
                length: bytes.len(),
            }));
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Canonical epoch-independent public request identity for Blob publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPublicationIntent {
    publisher: NodeId,
    topic: Topic,
    scope: Scope,
    priority: Priority,
    blob_id: BlobId,
    digest: [u8; 32],
}

impl BlobPublicationIntent {
    pub fn new(
        publisher: NodeId,
        topic: Topic,
        scope: Scope,
        priority: Priority,
        blob_id: BlobId,
    ) -> Result<Self, StoreError> {
        let mut intent = Self {
            publisher,
            topic,
            scope,
            priority,
            blob_id,
            digest: [0; 32],
        };
        intent.digest = blob_publication_intent_digest(&intent)?;
        Ok(intent)
    }

    pub const fn publisher(&self) -> NodeId {
        self.publisher
    }

    pub const fn topic(&self) -> &Topic {
        &self.topic
    }

    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    pub const fn priority(&self) -> Priority {
        self.priority
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Exact borrowed inputs for one idempotent Blob publication operation.
pub struct BlobOperationRequest<'a> {
    operation: &'a BlobOperationKey,
    intent: &'a BlobPublicationIntent,
}

impl<'a> BlobOperationRequest<'a> {
    pub const fn new(operation: &'a BlobOperationKey, intent: &'a BlobPublicationIntent) -> Self {
        Self { operation, intent }
    }

    pub const fn operation(&self) -> &BlobOperationKey {
        self.operation
    }

    pub const fn intent(&self) -> &BlobPublicationIntent {
        self.intent
    }
}

/// Optimistic Blob publication reservation over shared causal ledgers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReservation {
    control_policy: ControlPolicySnapshot,
    publisher: NodeId,
    topic: Topic,
    scope: Scope,
    previous_counter: u64,
    counter: u64,
    context: VersionVector,
}

impl BlobReservation {
    pub const fn control_policy(&self) -> &ControlPolicySnapshot {
        &self.control_policy
    }

    pub const fn publisher(&self) -> NodeId {
        self.publisher
    }

    pub const fn counter(&self) -> u64 {
        self.counter
    }

    pub const fn context(&self) -> &VersionVector {
        &self.context
    }

    /// Builds the exact selected Blob manifest-envelope header.
    pub fn header(
        &self,
        priority: Priority,
        route: BlobRouteCommitment,
        manifest_len: u64,
        key_epoch: u64,
    ) -> Result<EnvelopeHeader, StoreError> {
        let header = EnvelopeHeader {
            class: SemanticDataClass::Blob,
            topic: self.topic.clone(),
            scope: self.scope.clone(),
            priority,
            stamp: CausalStamp {
                dot: Dot {
                    publisher: self.publisher,
                    counter: self.counter,
                },
                context: self.context.clone(),
            },
            event_sequence: None,
            logical_key: route.blob_id().as_bytes().to_vec(),
            blob_route: Some(route),
            ttl_ms: None,
            content_len: manifest_len,
            tombstone: false,
            key_epoch,
        };
        validate_blob_header(&header)?;
        Ok(header)
    }
}

/// One source-authenticated Blob publication and its exact retained envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredBlob {
    pub transfer_id: BlobTransferId,
    pub semantic_id: BlobSemanticId,
    pub blob_id: BlobId,
    pub variant_id: BlobVariantId,
    pub manifest_digest: [u8; 32],
    pub header: EnvelopeHeader,
    pub sealed: Vec<u8>,
    pub acceptance_marker: u64,
}

/// Result of one atomic idempotent Blob publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobOnceOutcome {
    Inserted { blob: StoredBlob },
    BoundExisting { blob: StoredBlob },
    Existing { blob: StoredBlob },
}

impl BlobOnceOutcome {
    pub const fn blob(&self) -> &StoredBlob {
        match self {
            Self::Inserted { blob } | Self::BoundExisting { blob } | Self::Existing { blob } => {
                blob
            }
        }
    }

    pub const fn inserted(&self) -> bool {
        matches!(self, Self::Inserted { .. })
    }
}

/// Structural current-policy disposition in a bounded Blob read plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobPublicationDisposition {
    Current,
    Alternate,
}

/// One retained signed publication requiring fresh source/content verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReadCandidate {
    blob: StoredBlob,
    disposition: Option<BlobPublicationDisposition>,
}

impl BlobReadCandidate {
    pub const fn blob(&self) -> &StoredBlob {
        &self.blob
    }

    pub const fn disposition(&self) -> Option<BlobPublicationDisposition> {
        self.disposition
    }
}

/// Exact bounded publication set for one immutable Blob under settled policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobReadPlan {
    control_policy: ControlPolicySnapshot,
    topic: Topic,
    scope: Scope,
    blob_id: BlobId,
    candidates: Vec<BlobReadCandidate>,
}

impl BlobReadPlan {
    pub const fn control_policy(&self) -> &ControlPolicySnapshot {
        &self.control_policy
    }

    pub const fn topic(&self) -> &Topic {
        &self.topic
    }

    pub const fn scope(&self) -> &Scope {
        &self.scope
    }

    pub const fn blob_id(&self) -> BlobId {
        self.blob_id
    }

    pub fn candidates(&self) -> &[BlobReadCandidate] {
        &self.candidates
    }

    pub fn current(&self) -> Option<&BlobReadCandidate> {
        self.candidates
            .iter()
            .find(|candidate| candidate.disposition == Some(BlobPublicationDisposition::Current))
    }
}

/// Consistent redb and physical-depot counts for the Blob namespace.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlobStoreStats {
    pub publications: u64,
    pub acceptance_markers: u64,
    pub total_sealed_bytes: u64,
    pub last_acceptance_marker: u64,
    pub operations: u64,
    pub operation_bytes: u64,
    pub variants: u64,
    pub finalized_variants: u64,
    pub committed_chunks: u64,
    pub committed_file_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobMetadata {
    transfer_id: BlobTransferId,
    semantic_id: BlobSemanticId,
    blob_id: BlobId,
    variant_id: BlobVariantId,
    manifest_digest: [u8; 32],
    header: EnvelopeHeader,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobOperationRecord {
    transfer_id: BlobTransferId,
    intent_digest: [u8; 32],
}

#[derive(Default)]
pub(crate) struct BlobAuditSnapshot {
    pub stats: BlobStoreStats,
}

impl Store {
    /// Returns the dedicated physical limits configured for this handle.
    pub const fn blob_depot_limits(&self) -> BlobDepotLimits {
        self.blob_depot_limits
    }

    /// Acquires the single mission-bound depot adapter used by the generic core engine.
    pub fn blob_depot(&self) -> Result<BlobDepot<'_>, StoreError> {
        self.require_live()?;
        self.require_bound_mission()?;
        BlobDepot::open(self)
    }

    /// Reserves the next Blob publication dot under exact settled policy.
    pub fn reserve_blob_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        publisher: NodeId,
        topic: &Topic,
        scope: &Scope,
    ) -> Result<BlobReservation, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        if control_principal_revoked_read(&read, publisher)? {
            return Err(blob_error(BlobStoreError::PublisherRevoked(publisher)));
        }
        let previous_counter = read
            .open_table(PUBLISHER_HIGH_WATER)?
            .get(publisher.as_slice())?
            .map_or(0, |value| value.value());
        let counter = previous_counter.checked_add(1).ok_or_else(|| {
            blob_error(BlobStoreError::InvalidPublication(
                "publisher causal counter is exhausted",
            ))
        })?;
        let prefix = event_domain_prefix(topic, scope)?;
        let frontier = read.open_table(CAUSAL_FRONTIER)?;
        let mut context = VersionVector::default();
        let mut direct_publishers = 0usize;
        for row in frontier.iter()? {
            let (key, value) = row?;
            let key = key.value();
            if !key.starts_with(&prefix) {
                continue;
            }
            if key.len() != prefix.len() + 32 || value.value() == 0 {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "causal frontier contains an invalid Blob-domain row",
                )));
            }
            direct_publishers = direct_publishers
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            if direct_publishers > MAX_CAUSAL_CONTEXT_ENTRIES {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "Blob causal frontier exceeds the proven context bound",
                )));
            }
            let context_publisher: NodeId = key[prefix.len()..].try_into().map_err(|_| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob causal frontier key is invalid",
                ))
            })?;
            context.observe(Dot {
                publisher: context_publisher,
                counter: value.value(),
            });
        }
        if context.counter(&publisher) == 0 && direct_publishers == MAX_CAUSAL_CONTEXT_ENTRIES {
            return Err(blob_error(BlobStoreError::InvalidPublication(
                "causal frontier publisher limit reached",
            )));
        }
        Ok(BlobReservation {
            control_policy: *policy,
            publisher,
            topic: topic.clone(),
            scope: scope.clone(),
            previous_counter,
            counter,
            context,
        })
    }

    /// Policy-bound idempotency preflight before allocating a current-epoch variant.
    pub fn blob_for_operation_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        request: &BlobOperationRequest<'_>,
    ) -> Result<Option<StoredBlob>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        if control_principal_revoked_read(&read, request.intent.publisher)? {
            return Err(blob_error(BlobStoreError::PublisherRevoked(
                request.intent.publisher,
            )));
        }
        let existing = read
            .open_table(BLOB_OPERATIONS)?
            .get(request.operation.as_bytes())?
            .map(|value| decode_blob_operation_record(value.value()))
            .transpose()?;
        match existing {
            Some(existing) if existing.intent_digest != request.intent.digest() => {
                Err(blob_error(BlobStoreError::OperationConflict))
            }
            Some(existing) => load_blob_from_read(&read, existing.transfer_id),
            None => Ok(None),
        }
    }

    /// Resolves one operation without treating persisted metadata as live authority.
    pub fn blob_for_operation(
        &self,
        operation: &BlobOperationKey,
    ) -> Result<Option<StoredBlob>, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let transfer = read
            .open_table(BLOB_OPERATIONS)?
            .get(operation.as_bytes())?
            .map(|value| {
                decode_blob_operation_record(value.value()).map(|record| record.transfer_id)
            })
            .transpose()?;
        transfer
            .map(|transfer| load_blob_from_read(&read, transfer))
            .transpose()
            .map(Option::flatten)
    }

    /// Privileged raw lookup by exact source-envelope transfer identity.
    pub fn get_blob(&self, transfer_id: BlobTransferId) -> Result<Option<StoredBlob>, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        load_blob_from_read(&read, transfer_id)
    }

    /// Privileged raw lookup by source-authenticated semantic publication identity.
    pub fn blob_by_semantic_id(
        &self,
        semantic_id: BlobSemanticId,
    ) -> Result<Option<StoredBlob>, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let transfer = read
            .open_table(BLOB_SEMANTIC_ITEMS)?
            .get(semantic_id.as_bytes().as_slice())?
            .map(|value| parse_blob_transfer_id("Blob semantic item table", value.value()))
            .transpose()?;
        transfer
            .map(|transfer| load_blob_from_read(&read, transfer))
            .transpose()
            .map(Option::flatten)
    }

    /// Prepares every retained signed publication for one immutable Blob.
    pub fn prepare_blob_read_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        topic: &Topic,
        scope: &Scope,
        blob_id: BlobId,
    ) -> Result<BlobReadPlan, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        blob_read_plan_read(&read, *policy, topic, scope, blob_id)
    }

    /// Rechecks exact policy and the complete freshly verified Blob publication set.
    pub fn require_blob_read_plan_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        plan: &BlobReadPlan,
    ) -> Result<(), StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        if policy != plan.control_policy() {
            return Err(blob_error(BlobStoreError::ReadPlanChanged));
        }
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let current =
            blob_read_plan_read(&read, *policy, plan.topic(), plan.scope(), plan.blob_id())?;
        if current != *plan {
            return Err(blob_error(BlobStoreError::ReadPlanChanged));
        }
        Ok(())
    }

    /// Returns a typed, disjoint inventory of signed Blob publication transfers.
    pub fn blob_inventory(&self) -> Result<Vec<BlobTransferId>, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let table = read.open_table(BLOB_PUBLICATIONS)?;
        let mut inventory = Vec::with_capacity(
            usize::try_from(table.len()?).map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        );
        for row in table.iter()? {
            let (key, _) = row?;
            inventory.push(parse_blob_transfer_id(
                "Blob publication table",
                key.value(),
            )?);
        }
        Ok(inventory)
    }

    /// Returns audited redb counters and verifies every marked depot artifact.
    pub fn blob_stats(&self) -> Result<BlobStoreStats, StoreError> {
        self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let stats = inspect_blob_tables_read(&read)?.stats;
        depot::audit_depot_read(
            &read,
            &self.path,
            self.backing_identity,
            self.blob_depot_owner_token,
            stats,
        )?;
        Ok(stats)
    }

    /// Commits a signed Blob publication only after strong content and depot completion proofs.
    pub fn commit_reserved_blob_once_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        request: &BlobOperationRequest<'_>,
        reservation: &BlobReservation,
        blob: &ContentVerifiedBlobEnvelope,
        sealed: &[u8],
        completion: &BlobDepotCompletion,
    ) -> Result<BlobOnceOutcome, StoreError> {
        self.require_live()?;
        if policy != reservation.control_policy() {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let prepared = PreparedBlobPublication::from_verified(blob, sealed, completion)?;
        validate_blob_reservation(reservation, &prepared)?;
        validate_blob_publication_intent(request.intent, &prepared)?;

        let _depot_guard = self
            .blob_depot_lock
            .lock()
            .map_err(|_| blob_error(BlobStoreError::DepotIntegrity("depot lock is poisoned")))?;
        self.require_live()?;
        depot::verify_completion(self, completion)?;

        let write = self.database.begin_write()?;
        enforce_live_write(&write)?;
        enforce_blob_policy_write(&write, prepared.mission_authority, policy, &prepared.header)?;

        // Current authorization and exact active epoch are rechecked before an
        // operation replay may resolve an older, already committed publication.
        if let Some(existing) = write
            .open_table(BLOB_OPERATIONS)?
            .get(request.operation.as_bytes())?
            .map(|value| decode_blob_operation_record(value.value()))
            .transpose()?
        {
            if existing.intent_digest != request.intent.digest() {
                return Err(blob_error(BlobStoreError::OperationConflict));
            }
            let blob = load_blob_from_write(&write, existing.transfer_id)?.ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob operation points to a missing publication",
                ))
            })?;
            return Ok(BlobOnceOutcome::Existing { blob });
        }

        if transfer_id_exists_outside_blob(&write, prepared.transfer_id.as_bytes())? {
            return Err(StoreError::TransferNamespaceCollision {
                transfer_id: *prepared.transfer_id.as_bytes(),
            });
        }
        if semantic_id_exists_outside_blob(&write, prepared.semantic_id.as_bytes())? {
            return Err(StoreError::SemanticNamespaceCollision {
                semantic_id: *prepared.semantic_id.as_bytes(),
            });
        }

        let accepted_representation = {
            let semantic_items = write.open_table(BLOB_SEMANTIC_ITEMS)?;
            semantic_items
                .get(prepared.semantic_id.as_bytes().as_slice())?
                .map(|value| parse_blob_transfer_id("Blob semantic item table", value.value()))
                .transpose()?
        };
        if let Some(accepted) = accepted_representation {
            if accepted != prepared.transfer_id {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "one Blob semantic publication has conflicting exact envelopes",
                )));
            }
            let stored = load_blob_from_write(&write, accepted)?.ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob semantic item index points to a missing publication",
                ))
            })?;
            if stored.header != prepared.header
                || stored.sealed != prepared.sealed
                || stored.variant_id != prepared.variant_id
                || stored.manifest_digest != prepared.manifest_digest
            {
                return Err(blob_error(BlobStoreError::SchemaInvariant(
                    "accepted Blob differs from its exact replay",
                )));
            }
            insert_blob_operation(&write, self.limits, request, prepared.transfer_id)?;
            write.commit()?;
            return Ok(BlobOnceOutcome::BoundExisting { blob: stored });
        }

        let current_counter = write
            .open_table(PUBLISHER_HIGH_WATER)?
            .get(reservation.publisher.as_slice())?
            .map_or(0, |value| value.value());
        if current_counter != reservation.previous_counter {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let dot_key = accepted_dot_key(prepared.header.stamp.dot);
        if let Some(accepted) = write
            .open_table(ACCEPTED_DOTS)?
            .get(dot_key.as_slice())?
            .map(|value| parse_digest32("accepted dot table", value.value()))
            .transpose()?
        {
            if accepted != *prepared.semantic_id.as_bytes() {
                return Err(StoreError::CausalEquivocation {
                    publisher: prepared.header.stamp.dot.publisher,
                    counter: prepared.header.stamp.dot.counter,
                });
            }
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "accepted Blob dot is missing its semantic index",
            )));
        }
        ensure_frontier_capacity(
            &write,
            &prepared.header.topic,
            &prepared.header.scope,
            prepared.header.stamp.dot.publisher,
            SemanticDataClass::Blob,
        )?;
        if write
            .open_table(BLOB_PUBLICATIONS)?
            .get(prepared.transfer_id.as_bytes().as_slice())?
            .is_some()
            || write
                .open_table(BLOB_BYTES)?
                .get(prepared.transfer_id.as_bytes().as_slice())?
                .is_some()
            || write
                .open_table(BLOB_ACCEPTANCE_MARKERS)?
                .get(prepared.transfer_id.as_bytes().as_slice())?
                .is_some()
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob exact namespace contains an unindexed partial publication",
            )));
        }

        let content_prefix = blob_content_prefix(
            &prepared.header.topic,
            &prepared.header.scope,
            prepared.blob_id,
        )?;
        let content = write.open_table(BLOB_CONTENT_INDEX)?;
        let mut publication_count = 0usize;
        for row in content.iter()? {
            let (key, _) = row?;
            if key.value().starts_with(&content_prefix) {
                publication_count = publication_count
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?;
            }
        }
        drop(content);
        if publication_count >= MAX_BLOB_PUBLICATIONS_PER_CONTENT {
            return Err(blob_error(BlobStoreError::PublicationLimitExceeded {
                current: publication_count,
                limit: MAX_BLOB_PUBLICATIONS_PER_CONTENT,
            }));
        }

        let incoming = u64::try_from(prepared.sealed.len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
        let marker = {
            let mut metadata = write.open_table(METADATA)?;
            require_aggregate_capacity(&metadata, self.limits, 1, incoming)?;
            let current_items = metadata
                .get(BLOB_ITEM_COUNT)?
                .map_or(0, |value| value.value());
            let current_bytes = metadata
                .get(BLOB_TOTAL_BYTES)?
                .map_or(0, |value| value.value());
            let previous_marker = metadata
                .get(LAST_BLOB_ACCEPTANCE_MARKER)?
                .map_or(0, |value| value.value());
            let marker = previous_marker
                .checked_add(1)
                .ok_or(StoreError::AcceptanceMarkerExhausted)?;
            metadata.insert(
                BLOB_ITEM_COUNT,
                current_items
                    .checked_add(1)
                    .ok_or(StoreError::ItemCountAccountingOverflow)?,
            )?;
            metadata.insert(
                BLOB_TOTAL_BYTES,
                current_bytes
                    .checked_add(incoming)
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?,
            )?;
            metadata.insert(LAST_BLOB_ACCEPTANCE_MARKER, marker)?;
            marker
        };

        write.open_table(BLOB_BYTES)?.insert(
            prepared.transfer_id.as_bytes().as_slice(),
            prepared.sealed.as_slice(),
        )?;
        write
            .open_table(BLOB_ACCEPTANCE_MARKERS)?
            .insert(prepared.transfer_id.as_bytes().as_slice(), marker)?;
        write.open_table(BLOB_PUBLICATIONS)?.insert(
            prepared.transfer_id.as_bytes().as_slice(),
            prepared.encoded_metadata.as_slice(),
        )?;
        write.open_table(BLOB_SEMANTIC_ITEMS)?.insert(
            prepared.semantic_id.as_bytes().as_slice(),
            prepared.transfer_id.as_bytes().as_slice(),
        )?;
        let content_key = blob_content_key(
            &prepared.header.topic,
            &prepared.header.scope,
            prepared.blob_id,
            prepared.semantic_id,
        )?;
        write.open_table(BLOB_CONTENT_INDEX)?.insert(
            content_key.as_slice(),
            prepared.transfer_id.as_bytes().as_slice(),
        )?;
        write.open_table(ACCEPTED_DOTS)?.insert(
            dot_key.as_slice(),
            prepared.semantic_id.as_bytes().as_slice(),
        )?;
        update_causal_high_water(
            &write,
            prepared.header.stamp.dot.publisher,
            &prepared.header.topic,
            &prepared.header.scope,
            prepared.header.stamp.dot.counter,
        )?;
        insert_blob_operation(&write, self.limits, request, prepared.transfer_id)?;
        write.commit()?;

        Ok(BlobOnceOutcome::Inserted {
            blob: StoredBlob {
                transfer_id: prepared.transfer_id,
                semantic_id: prepared.semantic_id,
                blob_id: prepared.blob_id,
                variant_id: prepared.variant_id,
                manifest_digest: prepared.manifest_digest,
                header: prepared.header,
                sealed: prepared.sealed,
                acceptance_marker: marker,
            },
        })
    }
}

struct PreparedBlobPublication {
    mission_authority: NodeId,
    transfer_id: BlobTransferId,
    semantic_id: BlobSemanticId,
    blob_id: BlobId,
    variant_id: BlobVariantId,
    manifest_digest: [u8; 32],
    header: EnvelopeHeader,
    sealed: Vec<u8>,
    encoded_metadata: Vec<u8>,
}

impl PreparedBlobPublication {
    fn from_verified(
        blob: &ContentVerifiedBlobEnvelope,
        sealed: &[u8],
        completion: &BlobDepotCompletion,
    ) -> Result<Self, StoreError> {
        blob.verify_exact_sealed(sealed)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        let header = blob.header().clone();
        validate_blob_header(&header)?;
        let manifest = blob.manifest();
        let blob_id = manifest.id();
        let route = header.blob_route.ok_or_else(|| {
            blob_error(BlobStoreError::InvalidPublication(
                "authenticated Blob route commitment is missing",
            ))
        })?;
        if route.blob_id() != blob_id
            || route.chunk_count() != manifest.chunk_count()
            || header.key_epoch != manifest.content_epoch()
            || header.content_len != blob.content_len()
            || header.logical_key.as_slice() != blob_id.as_bytes()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let manifest_digest = *blob.manifest_digest();
        let variant_id =
            blob_variant_id(blob_id, manifest.content_group(), manifest.content_epoch());
        if completion.blob_id != blob_id
            || completion.variant_id != variant_id
            || completion.content_group != *manifest.content_group()
            || completion.epoch != manifest.content_epoch()
            || completion.manifest_digest != manifest_digest
            || completion.chunk_count != manifest.chunk_count()
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let transfer_id = BlobTransferId::new(blob.envelope_id());
        let semantic_id = BlobSemanticId::new(blob.item_id());
        let encoded_metadata = encode_blob_metadata(BlobMetadata {
            transfer_id,
            semantic_id,
            blob_id,
            variant_id,
            manifest_digest,
            header: header.clone(),
        })?;
        Ok(Self {
            mission_authority: blob.mission_authority_id(),
            transfer_id,
            semantic_id,
            blob_id,
            variant_id,
            manifest_digest,
            header,
            sealed: sealed.to_vec(),
            encoded_metadata,
        })
    }
}

fn validate_blob_reservation(
    reservation: &BlobReservation,
    prepared: &PreparedBlobPublication,
) -> Result<(), StoreError> {
    let header = &prepared.header;
    if header.stamp.dot.publisher != reservation.publisher
        || header.stamp.dot.counter != reservation.counter
        || header.topic != reservation.topic
        || header.scope != reservation.scope
        || header.stamp.context != reservation.context
    {
        return Err(blob_error(BlobStoreError::InvalidPublication(
            "sealed Blob does not match its durable reservation",
        )));
    }
    Ok(())
}

fn validate_blob_publication_intent(
    intent: &BlobPublicationIntent,
    prepared: &PreparedBlobPublication,
) -> Result<(), StoreError> {
    if prepared.header.stamp.dot.publisher != intent.publisher
        || prepared.header.topic != intent.topic
        || prepared.header.scope != intent.scope
        || prepared.header.priority != intent.priority
        || prepared.blob_id != intent.blob_id
    {
        return Err(blob_error(BlobStoreError::OperationConflict));
    }
    Ok(())
}

fn enforce_blob_policy_write(
    write: &redb::WriteTransaction,
    authority: NodeId,
    expected: &ControlPolicySnapshot,
    header: &EnvelopeHeader,
) -> Result<(), StoreError> {
    require_control_policy_write(write, authority, expected)?;
    let publisher = header.stamp.dot.publisher;
    if control_principal_revoked_write(write, publisher)? {
        return Err(blob_error(BlobStoreError::PublisherRevoked(publisher)));
    }
    let current_epoch = write
        .open_table(CONTROL_SCOPE_EPOCHS)?
        .get(header.scope.as_str())?
        .map(|value| decode_scope_epoch_index(value.value()))
        .transpose()?
        .map_or(1, |(epoch, _)| epoch);
    if header.key_epoch < current_epoch {
        return Err(blob_error(BlobStoreError::KeyEpochStale {
            current: current_epoch,
            received: header.key_epoch,
        }));
    }
    if header.key_epoch > current_epoch {
        return Err(blob_error(BlobStoreError::KeyEpochNotActive {
            current: current_epoch,
            received: header.key_epoch,
        }));
    }
    Ok(())
}

fn insert_blob_operation(
    write: &redb::WriteTransaction,
    limits: StoreLimits,
    request: &BlobOperationRequest<'_>,
    transfer_id: BlobTransferId,
) -> Result<(), StoreError> {
    let encoded = encode_blob_operation_record(BlobOperationRecord {
        transfer_id,
        intent_digest: request.intent.digest(),
    });
    let incoming = request
        .operation
        .as_bytes()
        .len()
        .checked_add(encoded.len())
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    let mut metadata = write.open_table(METADATA)?;
    let current_count = metadata
        .get(BLOB_OPERATION_COUNT)?
        .map_or(0, |value| value.value());
    let next_count = current_count
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if next_count > MAX_BLOB_OPERATIONS {
        return Err(blob_error(BlobStoreError::OperationLimitExceeded {
            current: current_count,
            limit: MAX_BLOB_OPERATIONS,
        }));
    }
    let current_bytes = metadata
        .get(BLOB_OPERATION_TOTAL_BYTES)?
        .map_or(0, |value| value.value());
    let next_bytes = current_bytes
        .checked_add(incoming)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if next_bytes > MAX_BLOB_OPERATION_BYTES {
        return Err(blob_error(BlobStoreError::OperationByteLimitExceeded {
            current: current_bytes,
            incoming,
            limit: MAX_BLOB_OPERATION_BYTES,
        }));
    }
    require_aggregate_capacity(&metadata, limits, 1, incoming)?;
    metadata.insert(BLOB_OPERATION_COUNT, next_count)?;
    metadata.insert(BLOB_OPERATION_TOTAL_BYTES, next_bytes)?;
    drop(metadata);
    write
        .open_table(BLOB_OPERATIONS)?
        .insert(request.operation.as_bytes(), encoded.as_slice())?;
    Ok(())
}

fn blob_read_plan_read(
    read: &redb::ReadTransaction,
    policy: ControlPolicySnapshot,
    topic: &Topic,
    scope: &Scope,
    blob_id: BlobId,
) -> Result<BlobReadPlan, StoreError> {
    let prefix = blob_content_prefix(topic, scope, blob_id)?;
    let content = read.open_table(BLOB_CONTENT_INDEX)?;
    let mut rows = Vec::new();
    for row in content.iter()? {
        let (key, value) = row?;
        if !key.value().starts_with(&prefix) {
            continue;
        }
        if rows.len() >= MAX_BLOB_PUBLICATIONS_PER_CONTENT {
            return Err(blob_error(BlobStoreError::PublicationLimitExceeded {
                current: rows.len() + 1,
                limit: MAX_BLOB_PUBLICATIONS_PER_CONTENT,
            }));
        }
        let transfer = parse_blob_transfer_id("Blob content index", value.value())?;
        rows.push(load_blob_from_read(read, transfer)?.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob content index points to a missing publication",
            ))
        })?);
    }
    rows.sort_by_key(|blob| blob.semantic_id);
    let current_epoch = read
        .open_table(CONTROL_SCOPE_EPOCHS)?
        .get(scope.as_str())?
        .map(|value| decode_scope_epoch_index(value.value()))
        .transpose()?
        .map_or(1, |(epoch, _)| epoch);
    let mut active = Vec::with_capacity(rows.len());
    for blob in &rows {
        active.push(
            blob.header.key_epoch == current_epoch
                && !control_principal_revoked_read(read, blob.header.stamp.dot.publisher)?,
        );
    }
    let selected = rows
        .iter()
        .zip(&active)
        .filter(|(_, active)| **active)
        .map(|(blob, _)| blob.semantic_id)
        .max();
    let candidates = rows
        .into_iter()
        .zip(active)
        .map(|(blob, active)| BlobReadCandidate {
            disposition: if !active {
                None
            } else if Some(blob.semantic_id) == selected {
                Some(BlobPublicationDisposition::Current)
            } else {
                Some(BlobPublicationDisposition::Alternate)
            },
            blob,
        })
        .collect();
    Ok(BlobReadPlan {
        control_policy: policy,
        topic: topic.clone(),
        scope: scope.clone(),
        blob_id,
        candidates,
    })
}

fn load_blob_from_read(
    read: &redb::ReadTransaction,
    transfer_id: BlobTransferId,
) -> Result<Option<StoredBlob>, StoreError> {
    let metadata = read
        .open_table(BLOB_PUBLICATIONS)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| decode_blob_metadata(value.value()))
        .transpose()?;
    metadata
        .map(|metadata| {
            let sealed = read
                .open_table(BLOB_BYTES)?
                .get(transfer_id.as_bytes().as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob publication is missing exact source bytes",
                    ))
                })?;
            let marker = read
                .open_table(BLOB_ACCEPTANCE_MARKERS)?
                .get(transfer_id.as_bytes().as_slice())?
                .map(|value| value.value())
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob publication is missing its acceptance marker",
                    ))
                })?;
            Ok(StoredBlob {
                transfer_id,
                semantic_id: metadata.semantic_id,
                blob_id: metadata.blob_id,
                variant_id: metadata.variant_id,
                manifest_digest: metadata.manifest_digest,
                header: metadata.header,
                sealed,
                acceptance_marker: marker,
            })
        })
        .transpose()
}

fn load_blob_from_write(
    write: &redb::WriteTransaction,
    transfer_id: BlobTransferId,
) -> Result<Option<StoredBlob>, StoreError> {
    let metadata = write
        .open_table(BLOB_PUBLICATIONS)?
        .get(transfer_id.as_bytes().as_slice())?
        .map(|value| decode_blob_metadata(value.value()))
        .transpose()?;
    metadata
        .map(|metadata| {
            let sealed = write
                .open_table(BLOB_BYTES)?
                .get(transfer_id.as_bytes().as_slice())?
                .map(|value| value.value().to_vec())
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob publication is missing exact source bytes",
                    ))
                })?;
            let marker = write
                .open_table(BLOB_ACCEPTANCE_MARKERS)?
                .get(transfer_id.as_bytes().as_slice())?
                .map(|value| value.value())
                .ok_or_else(|| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob publication is missing its acceptance marker",
                    ))
                })?;
            Ok(StoredBlob {
                transfer_id,
                semantic_id: metadata.semantic_id,
                blob_id: metadata.blob_id,
                variant_id: metadata.variant_id,
                manifest_digest: metadata.manifest_digest,
                header: metadata.header,
                sealed,
                acceptance_marker: marker,
            })
        })
        .transpose()
}

fn transfer_id_exists_outside_blob(
    write: &redb::WriteTransaction,
    id: &[u8; 32],
) -> Result<bool, StoreError> {
    Ok(write.open_table(EVENTS)?.get(id.as_slice())?.is_some()
        || write.open_table(STATES)?.get(id.as_slice())?.is_some()
        || write.open_table(RECORDS)?.get(id.as_slice())?.is_some()
        || write.open_table(ROUTE_CACHE)?.get(id.as_slice())?.is_some()
        || write
            .open_table(CONTROL_RECORDS)?
            .get(id.as_slice())?
            .is_some())
}

fn semantic_id_exists_outside_blob(
    write: &redb::WriteTransaction,
    id: &[u8; 32],
) -> Result<bool, StoreError> {
    if write
        .open_table(SEMANTIC_ITEMS)?
        .get(id.as_slice())?
        .is_some()
        || write
            .open_table(STATE_SEMANTIC_ITEMS)?
            .get(id.as_slice())?
            .is_some()
        || write
            .open_table(RECORD_SEMANTIC_ITEMS)?
            .get(id.as_slice())?
            .is_some()
    {
        return Ok(true);
    }
    for row in write.open_table(ROUTE_CACHE_CLAIMS)?.iter()? {
        let (_, claim) = row?;
        if decode_event_metadata(claim.value())?.semantic_id.as_bytes() == id {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn blob_schema_present_write(
    write: &redb::WriteTransaction,
) -> Result<bool, StoreError> {
    let tables = blob_table_names();
    if write
        .list_multimap_tables()?
        .any(|table| tables.contains(&table.name()))
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "mission-scoped Blob schema has the wrong table kind",
        )));
    }
    let existing = write
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let present = tables
        .iter()
        .filter(|table| existing.contains(**table))
        .count();
    let metadata = write.open_table(METADATA)?;
    let global = blob_global_metadata_fields();
    let global_present = global
        .iter()
        .map(|field| metadata.get(*field).map(|value| value.is_some()))
        .collect::<Result<Vec<_>, _>>()?;
    drop(metadata);
    if present == 0 && global_present.iter().all(|present| !present) {
        return Ok(false);
    }
    if present != tables.len() || global_present.iter().any(|present| !present) {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "mission-scoped Blob schema group is incomplete",
        )));
    }
    Ok(true)
}

pub(crate) fn audit_blob_tables_write(
    write: &redb::WriteTransaction,
    shared: &mut StateAuditSnapshot,
) -> Result<BlobAuditSnapshot, StoreError> {
    if !blob_schema_present_write(write)? {
        initialize_blob_schema(write)?;
    }
    let publications = write.open_table(BLOB_PUBLICATIONS)?;
    let bytes = write.open_table(BLOB_BYTES)?;
    let markers = write.open_table(BLOB_ACCEPTANCE_MARKERS)?;
    let semantic_items = write.open_table(BLOB_SEMANTIC_ITEMS)?;
    let content = write.open_table(BLOB_CONTENT_INDEX)?;
    let operations = write.open_table(BLOB_OPERATIONS)?;
    let accepted_dots = write.open_table(ACCEPTED_DOTS)?;
    let publisher_high = write.open_table(PUBLISHER_HIGH_WATER)?;
    let frontier = write.open_table(CAUSAL_FRONTIER)?;
    let mut stats = BlobStoreStats::default();
    let mut marker_values = BTreeSet::new();
    let mut expected_content = BTreeMap::new();
    let mut content_counts = BTreeMap::<Vec<u8>, usize>::new();

    for row in publications.iter()? {
        let (key, value) = row?;
        let transfer_id = parse_blob_transfer_id("Blob publication table", key.value())?;
        let publication = decode_blob_metadata(value.value())?;
        if publication.transfer_id != transfer_id {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob metadata transfer identity differs from its key",
            )));
        }
        let route = publication.header.blob_route.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "accepted Blob publication is missing its route commitment",
            ))
        })?;
        depot::audit_publication_import_write(
            write,
            publication.variant_id,
            publication.blob_id,
            publication.header.key_epoch,
            publication.manifest_digest,
            route.chunk_count(),
        )?;
        if transfer_id_exists_outside_blob(write, transfer_id.as_bytes())? {
            return Err(StoreError::TransferNamespaceCollision {
                transfer_id: *transfer_id.as_bytes(),
            });
        }
        if semantic_id_exists_outside_blob(write, publication.semantic_id.as_bytes())? {
            return Err(StoreError::SemanticNamespaceCollision {
                semantic_id: *publication.semantic_id.as_bytes(),
            });
        }
        let exact = bytes.get(key.value())?.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob metadata is missing exact source bytes",
            ))
        })?;
        if BlobTransferId::new(Sha256::digest(exact.value()).into()) != transfer_id {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob source bytes fail exact transfer identity audit",
            )));
        }
        let marker = markers
            .get(key.value())?
            .map(|value| value.value())
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob metadata is missing its acceptance marker",
                ))
            })?;
        if marker == 0 || !marker_values.insert(marker) {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob acceptance markers must be nonzero and unique",
            )));
        }
        let indexed = semantic_items
            .get(publication.semantic_id.as_bytes().as_slice())?
            .map(|value| parse_blob_transfer_id("Blob semantic item table", value.value()))
            .transpose()?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publication is missing its semantic index",
                ))
            })?;
        if indexed != transfer_id {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob semantic index points to another publication",
            )));
        }
        let content_key = blob_content_key(
            &publication.header.topic,
            &publication.header.scope,
            publication.blob_id,
            publication.semantic_id,
        )?;
        if expected_content.insert(content_key, transfer_id).is_some() {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "multiple Blob publications claim one content index key",
            )));
        }
        let content_prefix = blob_content_prefix(
            &publication.header.topic,
            &publication.header.scope,
            publication.blob_id,
        )?;
        let content_count = content_counts.entry(content_prefix).or_default();
        *content_count = content_count
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if *content_count > MAX_BLOB_PUBLICATIONS_PER_CONTENT {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob content publication count exceeds its durable safety cap",
            )));
        }
        let dot = publication.header.stamp.dot;
        let dot_key = accepted_dot_key(dot).to_vec();
        if shared
            .expected_dots
            .insert(dot_key.clone(), *publication.semantic_id.as_bytes())
            .is_some()
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "multiple semantic classes claim one accepted causal dot",
            )));
        }
        let accepted = accepted_dots
            .get(dot_key.as_slice())?
            .map(|value| parse_digest32("accepted dot table", value.value()))
            .transpose()?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publication is missing its accepted-dot row",
                ))
            })?;
        if accepted != *publication.semantic_id.as_bytes() {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "accepted-dot ledger points to another semantic publication",
            )));
        }
        let durable_high = publisher_high
            .get(dot.publisher.as_slice())?
            .map_or(0, |value| value.value());
        if durable_high < dot.counter {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "publisher high-water is behind an accepted Blob dot",
            )));
        }
        shared
            .expected_publisher_high
            .entry(dot.publisher.to_vec())
            .and_modify(|current| *current = (*current).max(dot.counter))
            .or_insert(dot.counter);
        let frontier_key = causal_frontier_key(
            &publication.header.topic,
            &publication.header.scope,
            dot.publisher,
        )?;
        if frontier
            .get(frontier_key.as_slice())?
            .map_or(0, |value| value.value())
            < dot.counter
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "causal frontier is behind an accepted Blob dot",
            )));
        }
        shared
            .expected_frontier
            .entry(frontier_key)
            .and_modify(|current| *current = (*current).max(dot.counter))
            .or_insert(dot.counter);
        shared
            .domain_publishers
            .entry(event_domain_prefix(
                &publication.header.topic,
                &publication.header.scope,
            )?)
            .or_default()
            .insert(dot.publisher);
        stats.publications = stats
            .publications
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        stats.total_sealed_bytes = stats
            .total_sealed_bytes
            .checked_add(
                u64::try_from(exact.value().len())
                    .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
            )
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        stats.last_acceptance_marker = stats.last_acceptance_marker.max(marker);
    }
    if stats.last_acceptance_marker != stats.publications
        || marker_values.iter().copied().ne(1..=stats.publications)
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob acceptance markers are not a contiguous allocation history",
        )));
    }
    stats.acceptance_markers = markers.len()?;
    if bytes.len()? != stats.publications
        || markers.len()? != stats.publications
        || semantic_items.len()? != stats.publications
        || content.len()? != stats.publications
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob publication schema has missing or orphan rows",
        )));
    }
    for row in content.iter()? {
        let (key, value) = row?;
        let transfer = parse_blob_transfer_id("Blob content index", value.value())?;
        if expected_content.get(key.value()) != Some(&transfer) {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob content index contains an orphan or mismatched row",
            )));
        }
    }
    for row in operations.iter()? {
        let (key, value) = row?;
        BlobOperationKey::new(key.value().to_vec())?;
        let operation = decode_blob_operation_record(value.value())?;
        if publications
            .get(operation.transfer_id.as_bytes().as_slice())?
            .is_none()
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob operation points to a missing publication",
            )));
        }
        stats.operations = stats
            .operations
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        stats.operation_bytes = stats
            .operation_bytes
            .checked_add(
                key.value()
                    .len()
                    .checked_add(value.value().len())
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?,
            )
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    }
    if stats.operations > MAX_BLOB_OPERATIONS || stats.operation_bytes > MAX_BLOB_OPERATION_BYTES {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob operation usage exceeds its durable safety caps",
        )));
    }
    let depot_stats = depot::audit_depot_metadata_write(write)?;
    stats.variants = depot_stats.variants;
    stats.finalized_variants = depot_stats.finalized_variants;
    stats.committed_chunks = depot_stats.committed_chunks;
    stats.committed_file_bytes = depot_stats.committed_file_bytes;
    let mut metadata = write.open_table(METADATA)?;
    audit_or_initialize_counter(&mut metadata, BLOB_ITEM_COUNT, stats.publications)?;
    audit_or_initialize_counter(&mut metadata, BLOB_TOTAL_BYTES, stats.total_sealed_bytes)?;
    audit_or_initialize_counter(
        &mut metadata,
        LAST_BLOB_ACCEPTANCE_MARKER,
        stats.last_acceptance_marker,
    )?;
    audit_or_initialize_counter(&mut metadata, BLOB_OPERATION_COUNT, stats.operations)?;
    audit_or_initialize_counter(
        &mut metadata,
        BLOB_OPERATION_TOTAL_BYTES,
        stats.operation_bytes,
    )?;
    Ok(BlobAuditSnapshot { stats })
}

pub(crate) fn inspect_blob_tables_read(
    read: &redb::ReadTransaction,
) -> Result<BlobAuditSnapshot, StoreError> {
    let tables = blob_table_names();
    if read
        .list_multimap_tables()?
        .any(|table| tables.contains(&table.name()))
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "mission-scoped Blob schema has the wrong table kind",
        )));
    }
    let existing = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    let present = tables
        .iter()
        .filter(|table| existing.contains(**table))
        .count();
    let metadata = read.open_table(METADATA)?;
    let global = blob_global_metadata_fields();
    let global_present = global
        .iter()
        .map(|field| metadata.get(*field).map(|value| value.is_some()))
        .collect::<Result<Vec<_>, _>>()?;
    if present == 0 && global_present.iter().all(|present| !present) {
        return Ok(BlobAuditSnapshot::default());
    }
    if present != tables.len() || global_present.iter().any(|present| !present) {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "mission-scoped Blob schema group is incomplete",
        )));
    }
    drop(metadata);

    // The read-only audit uses a temporary shared snapshot and verifies Blob
    // rows directly; the caller later checks the complete shared ledgers after
    // combining Event, State, Record, and Blob expectations.
    let publications = read.open_table(BLOB_PUBLICATIONS)?;
    let bytes = read.open_table(BLOB_BYTES)?;
    let markers = read.open_table(BLOB_ACCEPTANCE_MARKERS)?;
    let semantic = read.open_table(BLOB_SEMANTIC_ITEMS)?;
    let content = read.open_table(BLOB_CONTENT_INDEX)?;
    let operations = read.open_table(BLOB_OPERATIONS)?;
    let mut stats = BlobStoreStats::default();
    let mut marker_values = BTreeSet::new();
    let mut expected_content = BTreeMap::new();
    let mut content_counts = BTreeMap::<Vec<u8>, usize>::new();
    for row in publications.iter()? {
        let (key, value) = row?;
        let transfer = parse_blob_transfer_id("Blob publication table", key.value())?;
        let publication = decode_blob_metadata(value.value())?;
        if publication.transfer_id != transfer {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob metadata transfer identity differs from its key",
            )));
        }
        let route = publication.header.blob_route.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "accepted Blob publication is missing its route commitment",
            ))
        })?;
        depot::audit_publication_import_read(
            read,
            publication.variant_id,
            publication.blob_id,
            publication.header.key_epoch,
            publication.manifest_digest,
            route.chunk_count(),
        )?;
        let exact = bytes.get(key.value())?.ok_or_else(|| {
            blob_error(BlobStoreError::SchemaInvariant(
                "Blob metadata is missing exact source bytes",
            ))
        })?;
        if BlobTransferId::new(Sha256::digest(exact.value()).into()) != transfer {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob source bytes fail exact transfer identity audit",
            )));
        }
        let marker = markers
            .get(key.value())?
            .map(|value| value.value())
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob metadata is missing its acceptance marker",
                ))
            })?;
        if marker == 0 || !marker_values.insert(marker) {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob acceptance markers must be nonzero and unique",
            )));
        }
        let indexed = semantic
            .get(publication.semantic_id.as_bytes().as_slice())?
            .map(|value| parse_blob_transfer_id("Blob semantic item table", value.value()))
            .transpose()?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publication is missing its semantic index",
                ))
            })?;
        if indexed != transfer {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob semantic index points to another publication",
            )));
        }
        expected_content.insert(
            blob_content_key(
                &publication.header.topic,
                &publication.header.scope,
                publication.blob_id,
                publication.semantic_id,
            )?,
            transfer,
        );
        let content_prefix = blob_content_prefix(
            &publication.header.topic,
            &publication.header.scope,
            publication.blob_id,
        )?;
        let content_count = content_counts.entry(content_prefix).or_default();
        *content_count = content_count
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        if *content_count > MAX_BLOB_PUBLICATIONS_PER_CONTENT {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob content publication count exceeds its durable safety cap",
            )));
        }
        stats.publications += 1;
        stats.total_sealed_bytes = stats
            .total_sealed_bytes
            .checked_add(
                u64::try_from(exact.value().len())
                    .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
            )
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        stats.last_acceptance_marker = stats.last_acceptance_marker.max(marker);
    }
    stats.acceptance_markers = markers.len()?;
    if stats.last_acceptance_marker != stats.publications
        || marker_values.iter().copied().ne(1..=stats.publications)
        || bytes.len()? != stats.publications
        || markers.len()? != stats.publications
        || semantic.len()? != stats.publications
        || content.len()? != stats.publications
    {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob publication schema has missing, orphan, or noncontiguous rows",
        )));
    }
    for row in content.iter()? {
        let (key, value) = row?;
        let transfer = parse_blob_transfer_id("Blob content index", value.value())?;
        if expected_content.get(key.value()) != Some(&transfer) {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob content index contains an orphan or mismatched row",
            )));
        }
    }
    for row in operations.iter()? {
        let (key, value) = row?;
        BlobOperationKey::new(key.value().to_vec())?;
        let operation = decode_blob_operation_record(value.value())?;
        if publications
            .get(operation.transfer_id.as_bytes().as_slice())?
            .is_none()
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob operation points to a missing publication",
            )));
        }
        stats.operations += 1;
        stats.operation_bytes = stats
            .operation_bytes
            .checked_add(
                key.value()
                    .len()
                    .checked_add(value.value().len())
                    .and_then(|value| u64::try_from(value).ok())
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?,
            )
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    }
    if stats.operations > MAX_BLOB_OPERATIONS || stats.operation_bytes > MAX_BLOB_OPERATION_BYTES {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob operation usage exceeds its durable safety caps",
        )));
    }
    let depot_stats = depot::inspect_depot_metadata_read(read)?;
    stats.variants = depot_stats.variants;
    stats.finalized_variants = depot_stats.finalized_variants;
    stats.committed_chunks = depot_stats.committed_chunks;
    stats.committed_file_bytes = depot_stats.committed_file_bytes;
    let metadata = read.open_table(METADATA)?;
    for (field, reconstructed) in [
        (BLOB_ITEM_COUNT, stats.publications),
        (BLOB_TOTAL_BYTES, stats.total_sealed_bytes),
        (LAST_BLOB_ACCEPTANCE_MARKER, stats.last_acceptance_marker),
        (BLOB_OPERATION_COUNT, stats.operations),
        (BLOB_OPERATION_TOTAL_BYTES, stats.operation_bytes),
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
    Ok(BlobAuditSnapshot { stats })
}

/// Extends the exact shared causal-ledger reconstruction used by strict inspection.
pub(crate) fn inspect_blob_tables_read_with_shared(
    read: &redb::ReadTransaction,
    shared: &mut StateAuditSnapshot,
) -> Result<BlobAuditSnapshot, StoreError> {
    let snapshot = inspect_blob_tables_read(read)?;
    let table_names = read
        .list_tables()?
        .map(|table| table.name().to_owned())
        .collect::<BTreeSet<_>>();
    if !table_names.contains(BLOB_PUBLICATIONS.name()) {
        return Ok(snapshot);
    }
    let publications = read.open_table(BLOB_PUBLICATIONS)?;
    let accepted_dots = table_names
        .contains(ACCEPTED_DOTS.name())
        .then(|| read.open_table(ACCEPTED_DOTS))
        .transpose()?;
    let publisher_high = table_names
        .contains(PUBLISHER_HIGH_WATER.name())
        .then(|| read.open_table(PUBLISHER_HIGH_WATER))
        .transpose()?;
    let frontier = table_names
        .contains(CAUSAL_FRONTIER.name())
        .then(|| read.open_table(CAUSAL_FRONTIER))
        .transpose()?;
    let events = table_names
        .contains(EVENTS.name())
        .then(|| read.open_table(EVENTS))
        .transpose()?;
    let states = table_names
        .contains(STATES.name())
        .then(|| read.open_table(STATES))
        .transpose()?;
    let records = table_names
        .contains(RECORDS.name())
        .then(|| read.open_table(RECORDS))
        .transpose()?;
    let route_cache = table_names
        .contains(ROUTE_CACHE.name())
        .then(|| read.open_table(ROUTE_CACHE))
        .transpose()?;
    let controls = table_names
        .contains(CONTROL_RECORDS.name())
        .then(|| read.open_table(CONTROL_RECORDS))
        .transpose()?;
    let event_semantic = table_names
        .contains(SEMANTIC_ITEMS.name())
        .then(|| read.open_table(SEMANTIC_ITEMS))
        .transpose()?;
    let state_semantic = table_names
        .contains(STATE_SEMANTIC_ITEMS.name())
        .then(|| read.open_table(STATE_SEMANTIC_ITEMS))
        .transpose()?;
    let record_semantic = table_names
        .contains(RECORD_SEMANTIC_ITEMS.name())
        .then(|| read.open_table(RECORD_SEMANTIC_ITEMS))
        .transpose()?;
    let route_semantic_ids = if table_names.contains(ROUTE_CACHE_CLAIMS.name()) {
        read.open_table(ROUTE_CACHE_CLAIMS)?
            .iter()?
            .map(|row| {
                let (_, claim) = row?;
                Ok(*decode_event_metadata(claim.value())?.semantic_id.as_bytes())
            })
            .collect::<Result<BTreeSet<_>, StoreError>>()?
    } else {
        BTreeSet::new()
    };
    for row in publications.iter()? {
        let (key, value) = row?;
        let publication = decode_blob_metadata(value.value())?;
        if events
            .as_ref()
            .map(|table| table.get(key.value()))
            .transpose()?
            .flatten()
            .is_some()
            || states
                .as_ref()
                .map(|table| table.get(key.value()))
                .transpose()?
                .flatten()
                .is_some()
            || records
                .as_ref()
                .map(|table| table.get(key.value()))
                .transpose()?
                .flatten()
                .is_some()
            || route_cache
                .as_ref()
                .map(|table| table.get(key.value()))
                .transpose()?
                .flatten()
                .is_some()
            || controls
                .as_ref()
                .map(|table| table.get(key.value()))
                .transpose()?
                .flatten()
                .is_some()
        {
            return Err(StoreError::TransferNamespaceCollision {
                transfer_id: *publication.transfer_id.as_bytes(),
            });
        }
        let semantic = publication.semantic_id.as_bytes().as_slice();
        if event_semantic
            .as_ref()
            .map(|table| table.get(semantic))
            .transpose()?
            .flatten()
            .is_some()
            || state_semantic
                .as_ref()
                .map(|table| table.get(semantic))
                .transpose()?
                .flatten()
                .is_some()
            || record_semantic
                .as_ref()
                .map(|table| table.get(semantic))
                .transpose()?
                .flatten()
                .is_some()
            || route_semantic_ids.contains(publication.semantic_id.as_bytes())
        {
            return Err(StoreError::SemanticNamespaceCollision {
                semantic_id: *publication.semantic_id.as_bytes(),
            });
        }
        let dot = publication.header.stamp.dot;
        let dot_key = accepted_dot_key(dot).to_vec();
        if shared
            .expected_dots
            .insert(dot_key.clone(), *publication.semantic_id.as_bytes())
            .is_some()
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "multiple semantic classes claim one accepted causal dot",
            )));
        }
        let accepted = accepted_dots
            .as_ref()
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publications exist without the shared accepted-dot ledger",
                ))
            })?
            .get(dot_key.as_slice())?
            .map(|value| parse_digest32("accepted dot table", value.value()))
            .transpose()?
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publication is missing its accepted-dot row",
                ))
            })?;
        if accepted != *publication.semantic_id.as_bytes() {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "accepted-dot ledger points to another semantic publication",
            )));
        }
        if publisher_high
            .as_ref()
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publications exist without the shared publisher high-water ledger",
                ))
            })?
            .get(dot.publisher.as_slice())?
            .map_or(0, |value| value.value())
            < dot.counter
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "publisher high-water is behind an accepted Blob dot",
            )));
        }
        shared
            .expected_publisher_high
            .entry(dot.publisher.to_vec())
            .and_modify(|current| *current = (*current).max(dot.counter))
            .or_insert(dot.counter);
        let frontier_key = causal_frontier_key(
            &publication.header.topic,
            &publication.header.scope,
            dot.publisher,
        )?;
        if frontier
            .as_ref()
            .ok_or_else(|| {
                blob_error(BlobStoreError::SchemaInvariant(
                    "Blob publications exist without the shared causal frontier",
                ))
            })?
            .get(frontier_key.as_slice())?
            .map_or(0, |value| value.value())
            < dot.counter
        {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "causal frontier is behind an accepted Blob dot",
            )));
        }
        shared
            .expected_frontier
            .entry(frontier_key)
            .and_modify(|current| *current = (*current).max(dot.counter))
            .or_insert(dot.counter);
        shared
            .domain_publishers
            .entry(event_domain_prefix(
                &publication.header.topic,
                &publication.header.scope,
            )?)
            .or_default()
            .insert(dot.publisher);
    }
    Ok(snapshot)
}

fn initialize_blob_schema(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let _ = write.open_table(BLOB_PUBLICATIONS)?;
    let _ = write.open_table(BLOB_BYTES)?;
    let _ = write.open_table(BLOB_SEMANTIC_ITEMS)?;
    let _ = write.open_table(BLOB_CONTENT_INDEX)?;
    let _ = write.open_table(BLOB_ACCEPTANCE_MARKERS)?;
    let _ = write.open_table(BLOB_OPERATIONS)?;
    let _ = write.open_table(BLOB_IMPORTS)?;
    let _ = write.open_table(BLOB_CHUNKS)?;
    {
        let owner_token = generate_depot_owner_token()?;
        let mut depot = write.open_table(BLOB_DEPOT_METADATA)?;
        depot.insert(DEPOT_SCHEMA_VERSION, BLOB_DEPOT_SCHEMA_VERSION)?;
        depot.insert(DEPOT_VARIANT_COUNT, 0)?;
        depot.insert(DEPOT_COMMITTED_CHUNK_COUNT, 0)?;
        depot.insert(DEPOT_COMMITTED_FILE_BYTES, 0)?;
        for (field, chunk) in depot_owner_token_fields()
            .into_iter()
            .zip(owner_token.chunks_exact(8))
        {
            depot.insert(
                field,
                u64::from_be_bytes(chunk.try_into().map_err(|_| {
                    blob_error(BlobStoreError::SchemaInvariant(
                        "Blob depot owner token chunk has invalid length",
                    ))
                })?),
            )?;
        }
    }
    let mut metadata = write.open_table(METADATA)?;
    for field in blob_global_metadata_fields() {
        metadata.insert(field, 0)?;
    }
    Ok(())
}

fn blob_table_names() -> [&'static str; 9] {
    [
        BLOB_PUBLICATIONS.name(),
        BLOB_BYTES.name(),
        BLOB_SEMANTIC_ITEMS.name(),
        BLOB_CONTENT_INDEX.name(),
        BLOB_ACCEPTANCE_MARKERS.name(),
        BLOB_OPERATIONS.name(),
        BLOB_IMPORTS.name(),
        BLOB_CHUNKS.name(),
        BLOB_DEPOT_METADATA.name(),
    ]
}

fn blob_global_metadata_fields() -> [&'static str; 5] {
    [
        BLOB_ITEM_COUNT,
        BLOB_TOTAL_BYTES,
        LAST_BLOB_ACCEPTANCE_MARKER,
        BLOB_OPERATION_COUNT,
        BLOB_OPERATION_TOTAL_BYTES,
    ]
}

pub(crate) const fn depot_owner_token_fields() -> [&'static str; 4] {
    [
        DEPOT_OWNER_TOKEN_0,
        DEPOT_OWNER_TOKEN_1,
        DEPOT_OWNER_TOKEN_2,
        DEPOT_OWNER_TOKEN_3,
    ]
}

pub(crate) const fn depot_owner_binding_fields() -> [&'static str; 4] {
    [
        DEPOT_OWNER_BINDING_0,
        DEPOT_OWNER_BINDING_1,
        DEPOT_OWNER_BINDING_2,
        DEPOT_OWNER_BINDING_3,
    ]
}

fn generate_depot_owner_token() -> Result<[u8; 32], StoreError> {
    // An all-zero token is reserved as structurally invalid. Retry a bounded
    // number of independent OS draws so initialization can never commit a
    // token that the next audit must reject.
    for _ in 0..4 {
        let mut token = [0u8; 32];
        getrandom::fill(&mut token).map_err(|_| {
            blob_error(BlobStoreError::DepotIntegrity(
                "operating-system entropy is unavailable for the Blob depot owner token",
            ))
        })?;
        if token != [0; 32] {
            return Ok(token);
        }
    }
    Err(blob_error(BlobStoreError::DepotIntegrity(
        "operating-system entropy returned an invalid Blob depot owner token",
    )))
}

fn validate_blob_header(header: &EnvelopeHeader) -> Result<(), StoreError> {
    let route = header.blob_route.ok_or_else(|| {
        blob_error(BlobStoreError::InvalidPublication(
            "Blob route commitment is missing",
        ))
    })?;
    if header.class != SemanticDataClass::Blob
        || header.event_sequence.is_some()
        || header.ttl_ms.is_some()
        || header.tombstone
        || header.content_len == 0
        || header.content_len > MAX_BLOB_MANIFEST_BYTES
        || header.key_epoch == 0
        || route.chunk_count() == 0
        || route.chunk_count() > MAX_SELECTED_BLOB_CHUNKS
        || header.logical_key.as_slice() != route.blob_id().as_bytes()
        || header.stamp.dot.counter == 0
        || header.stamp.context.len() > MAX_CAUSAL_CONTEXT_ENTRIES
        || header
            .stamp
            .context
            .iter()
            .any(|(_, counter)| *counter == 0)
        || header.stamp.context.counter(&header.stamp.dot.publisher) >= header.stamp.dot.counter
    {
        return Err(blob_error(BlobStoreError::InvalidPublication(
            "authenticated Blob header violates the selected profile",
        )));
    }
    Ok(())
}

fn encode_blob_metadata(metadata: BlobMetadata) -> Result<Vec<u8>, StoreError> {
    validate_blob_header(&metadata.header)?;
    let route = metadata.header.blob_route.ok_or_else(|| {
        blob_error(BlobStoreError::InvalidPublication(
            "Blob route commitment is missing",
        ))
    })?;
    if route.blob_id() != metadata.blob_id {
        return Err(blob_error(BlobStoreError::InvalidPublication(
            "Blob metadata identity differs from its route commitment",
        )));
    }
    let mut output = Vec::new();
    output.push(BLOB_METADATA_VERSION);
    output.extend_from_slice(metadata.transfer_id.as_bytes());
    output.extend_from_slice(metadata.semantic_id.as_bytes());
    output.extend_from_slice(metadata.blob_id.as_bytes());
    output.extend_from_slice(metadata.variant_id.as_bytes());
    output.extend_from_slice(&metadata.manifest_digest);
    output.push(metadata.header.priority as u8);
    output.extend_from_slice(&metadata.header.stamp.dot.publisher);
    output.extend_from_slice(&metadata.header.stamp.dot.counter.to_be_bytes());
    output.extend_from_slice(&metadata.header.content_len.to_be_bytes());
    output.extend_from_slice(&metadata.header.key_epoch.to_be_bytes());
    output.extend_from_slice(&route.chunk_count().to_be_bytes());
    output.extend_from_slice(route.root());
    push_short_bytes(&mut output, metadata.header.topic.as_str().as_bytes())?;
    push_short_bytes(&mut output, metadata.header.scope.as_str().as_bytes())?;
    let context_len = u32::try_from(metadata.header.stamp.context.len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "causal context exceeds durable encoding bound",
        ))
    })?;
    output.extend_from_slice(&context_len.to_be_bytes());
    for (publisher, counter) in metadata.header.stamp.context.iter() {
        output.extend_from_slice(publisher);
        output.extend_from_slice(&counter.to_be_bytes());
    }
    Ok(output)
}

pub(crate) fn decode_blob_metadata(bytes: &[u8]) -> Result<BlobMetadata, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != BLOB_METADATA_VERSION {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "unknown Blob metadata encoding version",
        )));
    }
    let transfer_id = BlobTransferId::new(cursor.array()?);
    let semantic_id = BlobSemanticId::new(cursor.array()?);
    let blob_id = BlobId::from_bytes(cursor.array()?);
    let variant_id = BlobVariantId::from_bytes(cursor.array()?);
    let manifest_digest = cursor.array()?;
    let priority = Priority::from_wire(cursor.u8()?).ok_or_else(|| {
        blob_error(BlobStoreError::SchemaInvariant(
            "unknown authenticated Blob priority",
        ))
    })?;
    let publisher = cursor.array()?;
    let counter = cursor.u64()?;
    let content_len = cursor.u64()?;
    let key_epoch = cursor.u64()?;
    let chunk_count = cursor.u64()?;
    let root = cursor.array()?;
    let topic = Topic::new(cursor.short_string()?).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "invalid Blob topic encoding",
        ))
    })?;
    let scope = Scope::new(cursor.short_string()?).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "invalid Blob scope encoding",
        ))
    })?;
    let context_len = usize::try_from(cursor.u32()?).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "invalid Blob causal context length",
        ))
    })?;
    if context_len > MAX_CAUSAL_CONTEXT_ENTRIES {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "Blob causal context exceeds its bound",
        )));
    }
    let mut context = VersionVector::default();
    for _ in 0..context_len {
        let context_publisher = cursor.array()?;
        let context_counter = cursor.u64()?;
        if context_counter == 0 || context.counter(&context_publisher) != 0 {
            return Err(blob_error(BlobStoreError::SchemaInvariant(
                "Blob causal context is not canonical",
            )));
        }
        context.observe(Dot {
            publisher: context_publisher,
            counter: context_counter,
        });
    }
    cursor.finish()?;
    let route = BlobRouteCommitment::from_parts(blob_id, chunk_count, root).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "invalid Blob route commitment encoding",
        ))
    })?;
    let header = EnvelopeHeader {
        class: SemanticDataClass::Blob,
        topic,
        scope,
        priority,
        stamp: CausalStamp {
            dot: Dot { publisher, counter },
            context,
        },
        event_sequence: None,
        logical_key: blob_id.as_bytes().to_vec(),
        blob_route: Some(route),
        ttl_ms: None,
        content_len,
        tombstone: false,
        key_epoch,
    };
    validate_blob_header(&header).map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "decoded Blob metadata is internally inconsistent",
        ))
    })?;
    Ok(BlobMetadata {
        transfer_id,
        semantic_id,
        blob_id,
        variant_id,
        manifest_digest,
        header,
    })
}

fn encode_blob_operation_record(record: BlobOperationRecord) -> Vec<u8> {
    let mut output = Vec::with_capacity(65);
    output.push(BLOB_OPERATION_VERSION);
    output.extend_from_slice(record.transfer_id.as_bytes());
    output.extend_from_slice(&record.intent_digest);
    output
}

fn decode_blob_operation_record(bytes: &[u8]) -> Result<BlobOperationRecord, StoreError> {
    let mut cursor = MetadataCursor::new(bytes);
    if cursor.u8()? != BLOB_OPERATION_VERSION {
        return Err(blob_error(BlobStoreError::SchemaInvariant(
            "unknown Blob operation encoding version",
        )));
    }
    let record = BlobOperationRecord {
        transfer_id: BlobTransferId::new(cursor.array()?),
        intent_digest: cursor.array()?,
    };
    cursor.finish()?;
    Ok(record)
}

fn blob_publication_intent_digest(intent: &BlobPublicationIntent) -> Result<[u8; 32], StoreError> {
    let topic_len = u16::try_from(intent.topic.as_str().len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "topic exceeds intent encoding bound",
        ))
    })?;
    let scope_len = u16::try_from(intent.scope.as_str().len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "scope exceeds intent encoding bound",
        ))
    })?;
    let mut digest = Sha256::new();
    digest.update(BLOB_PUBLICATION_INTENT_DOMAIN);
    digest.update(intent.publisher);
    digest.update(topic_len.to_be_bytes());
    digest.update(intent.topic.as_str().as_bytes());
    digest.update(scope_len.to_be_bytes());
    digest.update(intent.scope.as_str().as_bytes());
    digest.update([intent.priority as u8]);
    digest.update(intent.blob_id.as_bytes());
    Ok(digest.finalize().into())
}

fn blob_content_prefix(
    topic: &Topic,
    scope: &Scope,
    blob_id: BlobId,
) -> Result<Vec<u8>, StoreError> {
    let topic_len = u16::try_from(topic.as_str().len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "topic exceeds content-index encoding bound",
        ))
    })?;
    let scope_len = u16::try_from(scope.as_str().len()).map_err(|_| {
        blob_error(BlobStoreError::InvalidPublication(
            "scope exceeds content-index encoding bound",
        ))
    })?;
    let mut output = Vec::with_capacity(2 + topic.as_str().len() + 2 + scope.as_str().len() + 32);
    output.extend_from_slice(&topic_len.to_be_bytes());
    output.extend_from_slice(topic.as_str().as_bytes());
    output.extend_from_slice(&scope_len.to_be_bytes());
    output.extend_from_slice(scope.as_str().as_bytes());
    output.extend_from_slice(blob_id.as_bytes());
    Ok(output)
}

fn blob_content_key(
    topic: &Topic,
    scope: &Scope,
    blob_id: BlobId,
    semantic_id: BlobSemanticId,
) -> Result<Vec<u8>, StoreError> {
    let mut key = blob_content_prefix(topic, scope, blob_id)?;
    key.extend_from_slice(semantic_id.as_bytes());
    Ok(key)
}

fn parse_blob_transfer_id(
    _table: &'static str,
    bytes: &[u8],
) -> Result<BlobTransferId, StoreError> {
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| {
        blob_error(BlobStoreError::SchemaInvariant(
            "Blob transfer identifier has invalid length",
        ))
    })?;
    Ok(BlobTransferId::new(bytes))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use aster_mesh::{
        BlobContentVerification, BlobMetadata as CoreBlobMetadata, BlobStore as CoreBlobStore,
        EventContentVerification, FinishedBlob, ProvisioningAccess, ReferenceEnvelopeSealer,
        ReferenceProvisioner, prepare_blob,
    };

    use super::*;

    static NEXT_BLOB_ROOT: AtomicU64 = AtomicU64::new(1);

    struct BlobTestRoot {
        path: PathBuf,
        database: PathBuf,
    }

    impl BlobTestRoot {
        fn new(label: &str) -> Self {
            let sequence = NEXT_BLOB_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "aster-redb-blob-{label}-{}-{sequence}",
                std::process::id()
            ));
            std::fs::create_dir(&path).expect("create Blob test state root");
            let database = path.join("state.redb");
            Self { path, database }
        }

        fn depot(&self) -> PathBuf {
            self.path.join("blob-depot-v1")
        }

        fn chunk_path(&self, variant: BlobVariantId, index: u64) -> PathBuf {
            self.depot()
                .join(test_hex32(variant.as_bytes()))
                .join(format!("{index:020}.chunk"))
        }
    }

    impl Drop for BlobTestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    struct BlobServices {
        publisher: ReferenceEnvelopeSealer,
        reader: ReferenceEnvelopeSealer,
        authority: NodeId,
    }

    fn blob_topic() -> Topic {
        Topic::new("selected-blob").expect("Blob topic")
    }

    fn blob_scope() -> Scope {
        Scope::new("mission/selected-blob").expect("Blob scope")
    }

    fn test_hex32(bytes: &[u8; 32]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(64);
        for byte in bytes {
            output.push(char::from(HEX[usize::from(byte >> 4)]));
            output.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        output
    }

    fn blob_services(seed: u8) -> BlobServices {
        let mut provisioner = ReferenceProvisioner::from_seed([seed; 32]).expect("provisioner");
        let access = ProvisioningAccess::member(blob_scope(), vec![1, 2, 3], vec![blob_topic()])
            .expect("Blob member access");
        let publisher = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("Blob publisher");
        let reader = provisioner
            .issue_node(2, &[access])
            .and_then(ReferenceEnvelopeSealer::open)
            .expect("Blob reader");
        let authority = publisher.mission_authority_id();
        BlobServices {
            publisher,
            reader,
            authority,
        }
    }

    fn prepared_blob(bytes: &[u8]) -> aster_mesh::PreparedBlob {
        prepare_blob(
            &mut Cursor::new(bytes),
            SELECTED_BLOB_CHUNK_SIZE,
            CoreBlobMetadata::new(Some("application/octet-stream".into()), vec![7, 9])
                .expect("Blob identity metadata"),
        )
        .expect("prepare Blob")
    }

    fn finish_variant(
        store: &Store,
        publisher: &ReferenceEnvelopeSealer,
        prepared: &aster_mesh::PreparedBlob,
        plaintext: &[u8],
        epoch: u64,
    ) -> Result<FinishedBlob, String> {
        let depot = store.blob_depot().map_err(|error| error.to_string())?;
        let mut service = publisher
            .blob_service_with_store(&blob_scope(), &blob_topic(), epoch, depot)
            .map_err(|error| error.to_string())?;
        let manifest = service
            .install_prepared(prepared)
            .map_err(|error| error.to_string())?;
        let progress = service
            .encrypt_some(&mut Cursor::new(plaintext), &manifest, u64::MAX)
            .map_err(|error| error.to_string())?;
        if !progress.complete {
            return Err("Blob encryption stopped before completion".into());
        }
        service
            .finish_manifest(&manifest)
            .map_err(|error| error.to_string())
    }

    struct BlobProof {
        policy: ControlPolicySnapshot,
        reservation: BlobReservation,
        blob: ContentVerifiedBlobEnvelope,
        manifest_bytes: Vec<u8>,
        sealed: Vec<u8>,
        completion: BlobDepotCompletion,
    }

    fn prepare_blob_proof(
        store: &Store,
        services: &mut BlobServices,
        prepared: &aster_mesh::PreparedBlob,
        plaintext: &[u8],
        epoch: u64,
    ) -> BlobProof {
        let policy = store.control_policy_snapshot().expect("Blob policy");
        let reservation = store
            .reserve_blob_with_policy(
                &policy,
                services.publisher.identity(),
                &blob_topic(),
                &blob_scope(),
            )
            .expect("Blob reservation");
        let finished = finish_variant(store, &services.publisher, prepared, plaintext, epoch)
            .expect("finish Blob depot variant");
        let header = reservation
            .header(
                Priority::Immediate,
                finished.route_commitment(),
                u64::try_from(finished.manifest_bytes().len()).expect("manifest length"),
                epoch,
            )
            .expect("Blob header");
        let sealed = services
            .publisher
            .seal_blob_manifest(&header, finished.manifest_bytes())
            .expect("seal Blob manifest")
            .bytes;
        let route = services
            .reader
            .verify_blob(&sealed)
            .expect("verify Blob route");
        let (blob, manifest_bytes) = match services
            .reader
            .verify_blob_content(route, &sealed)
            .expect("verify Blob content")
        {
            BlobContentVerification::ContentVerified {
                blob,
                manifest_bytes,
            } => (blob, manifest_bytes),
            BlobContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        };
        let completion = store
            .blob_depot()
            .and_then(|mut depot| depot.completed_blob(&blob, &manifest_bytes))
            .expect("complete exact Blob depot variant");
        BlobProof {
            policy,
            reservation,
            blob,
            manifest_bytes,
            sealed,
            completion,
        }
    }

    fn publish_blob(
        store: &Store,
        services: &mut BlobServices,
        prepared: &aster_mesh::PreparedBlob,
        plaintext: &[u8],
        epoch: u64,
        operation_bytes: &[u8],
    ) -> (StoredBlob, BlobOperationKey, BlobPublicationIntent) {
        let operation = BlobOperationKey::new(operation_bytes.to_vec()).expect("operation key");
        let intent = BlobPublicationIntent::new(
            services.publisher.identity(),
            blob_topic(),
            blob_scope(),
            Priority::Immediate,
            prepared.id(),
        )
        .expect("Blob intent");
        let request = BlobOperationRequest::new(&operation, &intent);
        let policy = store.control_policy_snapshot().expect("Blob policy");
        assert_eq!(
            store
                .blob_for_operation_with_policy(&policy, &request)
                .expect("operation preflight"),
            None
        );
        let proof = prepare_blob_proof(store, services, prepared, plaintext, epoch);
        assert_eq!(proof.policy, policy);
        let outcome = store
            .commit_reserved_blob_once_with_policy(
                &policy,
                &request,
                &proof.reservation,
                &proof.blob,
                &proof.sealed,
                &proof.completion,
            )
            .expect("commit Blob publication");
        assert!(outcome.inserted());
        (outcome.blob().clone(), operation, intent)
    }

    fn reserved_event(
        store: &Store,
        services: &mut BlobServices,
        policy: &ControlPolicySnapshot,
        payload: &[u8],
    ) -> (
        EventReservation,
        aster_mesh::ContentVerifiedEventEnvelope,
        Vec<u8>,
    ) {
        let reservation = store
            .reserve_event_with_policy(
                policy,
                services.publisher.identity(),
                &blob_topic(),
                &blob_scope(),
            )
            .expect("Event reservation after Blob");
        let header = reservation
            .header(
                Priority::Immediate,
                b"after/blob".to_vec(),
                None,
                u64::try_from(payload.len()).expect("Event length"),
                false,
                1,
            )
            .expect("Event header");
        let sealed = services
            .publisher
            .seal_event(&header, payload)
            .expect("seal Event");
        let route = services
            .reader
            .verify_event(&sealed.bytes)
            .expect("verify Event route");
        let event = match services
            .reader
            .verify_event_content(route, &sealed.bytes)
            .expect("verify Event content")
        {
            EventContentVerification::ContentVerified { event, .. } => event,
            EventContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        };
        (reservation, event, sealed.bytes)
    }

    fn assert_depot_integrity(error: &StoreError) {
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::DepotIntegrity(_))
        ));
    }

    fn assert_blob_schema_invariant(error: &StoreError) {
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::SchemaInvariant(_))
        ));
    }

    fn directory_entry_count(path: &Path) -> usize {
        std::fs::read_dir(path)
            .expect("read depot directory")
            .count()
    }

    fn file_digest(path: &Path) -> [u8; 32] {
        Sha256::digest(std::fs::read(path).expect("read digest fixture")).into()
    }

    fn blob_database_digest(path: &Path) -> [u8; 32] {
        let database = redb::Builder::new()
            .open_read_only(path)
            .expect("read-only Blob digest database");
        let read = database.begin_read().expect("Blob digest transaction");
        let mut digest = Sha256::new();
        macro_rules! bytes_table {
            ($definition:expr) => {
                for row in read
                    .open_table($definition)
                    .expect("Blob digest bytes table")
                    .iter()
                    .expect("Blob digest bytes rows")
                {
                    let (key, value) = row.expect("Blob digest bytes row");
                    digest.update(
                        u64::try_from(key.value().len())
                            .expect("Blob digest key length")
                            .to_be_bytes(),
                    );
                    digest.update(key.value());
                    digest.update(
                        u64::try_from(value.value().len())
                            .expect("Blob digest value length")
                            .to_be_bytes(),
                    );
                    digest.update(value.value());
                }
            };
        }
        macro_rules! byte_u64_table {
            ($definition:expr) => {
                for row in read
                    .open_table($definition)
                    .expect("Blob digest byte/u64 table")
                    .iter()
                    .expect("Blob digest byte/u64 rows")
                {
                    let (key, value) = row.expect("Blob digest byte/u64 row");
                    digest.update(
                        u64::try_from(key.value().len())
                            .expect("Blob digest key length")
                            .to_be_bytes(),
                    );
                    digest.update(key.value());
                    digest.update(value.value().to_be_bytes());
                }
            };
        }
        bytes_table!(BLOB_PUBLICATIONS);
        bytes_table!(BLOB_BYTES);
        bytes_table!(BLOB_SEMANTIC_ITEMS);
        bytes_table!(BLOB_CONTENT_INDEX);
        bytes_table!(BLOB_OPERATIONS);
        bytes_table!(BLOB_IMPORTS);
        bytes_table!(BLOB_CHUNKS);
        bytes_table!(ACCEPTED_DOTS);
        byte_u64_table!(BLOB_ACCEPTANCE_MARKERS);
        byte_u64_table!(PUBLISHER_HIGH_WATER);
        byte_u64_table!(CAUSAL_FRONTIER);
        for row in read
            .open_table(BLOB_DEPOT_METADATA)
            .expect("Blob depot digest metadata")
            .iter()
            .expect("Blob depot digest rows")
        {
            let (key, value) = row.expect("Blob depot digest row");
            digest.update(key.value().as_bytes());
            digest.update(value.value().to_be_bytes());
        }
        for field in blob_global_metadata_fields() {
            digest.update(field.as_bytes());
            digest.update(
                read.open_table(METADATA)
                    .expect("Blob digest global metadata")
                    .get(field)
                    .expect("Blob digest global read")
                    .map_or(u64::MAX, |value| value.value())
                    .to_be_bytes(),
            );
        }
        digest.finalize().into()
    }

    fn depot_file_snapshot(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        fn visit(base: &Path, current: &Path, output: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in std::fs::read_dir(current).expect("read depot snapshot") {
                let entry = entry.expect("depot snapshot entry");
                let path = entry.path();
                if entry.file_type().expect("depot snapshot type").is_dir() {
                    visit(base, &path, output);
                } else {
                    output.insert(
                        path.strip_prefix(base)
                            .expect("depot snapshot relative path")
                            .to_path_buf(),
                        std::fs::read(path).expect("depot snapshot bytes"),
                    );
                }
            }
        }

        let mut output = BTreeMap::new();
        if root.exists() {
            visit(root, root, &mut output);
        }
        output
    }

    #[test]
    fn publication_reopen_exact_retry_duplicate_no_growth_and_epoch_partition() {
        let root = BlobTestRoot::new("reopen-dedup-rekey");
        let mut services = blob_services(0x61);
        let plaintext = vec![0x5a; SELECTED_BLOB_CHUNK_SIZE as usize + 17];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (stored, operation, intent) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"publish-one",
        );
        let first = store.blob_stats().expect("first Blob stats");
        assert_eq!(first.publications, 1);
        assert_eq!(first.operations, 1);
        assert_eq!(first.variants, 1);
        assert_eq!(first.finalized_variants, 1);
        assert_eq!(first.committed_chunks, 2);

        let policy = store.control_policy_snapshot().expect("retry policy");
        let request = BlobOperationRequest::new(&operation, &intent);
        assert_eq!(
            store
                .blob_for_operation_with_policy(&policy, &request)
                .expect("exact retry preflight"),
            Some(stored.clone())
        );
        let changed_intent = BlobPublicationIntent::new(
            services.publisher.identity(),
            blob_topic(),
            blob_scope(),
            Priority::Routine,
            prepared.id(),
        )
        .expect("changed intent");
        assert!(matches!(
            store.blob_for_operation_with_policy(
                &policy,
                &BlobOperationRequest::new(&operation, &changed_intent),
            ),
            Err(StoreError::Blob(BlobStoreError::OperationConflict))
        ));
        assert_eq!(store.blob_stats().expect("retry stats"), first);

        let same = finish_variant(&store, &services.publisher, &prepared, &plaintext, 1)
            .expect("repeat same variant");
        assert_eq!(same.id(), stored.blob_id);
        assert_eq!(store.blob_stats().expect("same variant stats"), first);

        let epoch_two = finish_variant(&store, &services.publisher, &prepared, &plaintext, 2)
            .expect("separate epoch variant");
        assert_eq!(epoch_two.id(), stored.blob_id);
        let partitioned = store.blob_stats().expect("partitioned stats");
        assert_eq!(partitioned.variants, 2);
        assert_eq!(partitioned.finalized_variants, 2);
        assert_eq!(partitioned.committed_chunks, 4);
        assert_ne!(
            blob_variant_id(stored.blob_id, &[0; 32], 1),
            blob_variant_id(stored.blob_id, &[0; 32], 2)
        );
        drop(store);

        let reopened = Store::open_for_mission(&root.database, services.authority).expect("reopen");
        assert_eq!(reopened.blob_stats().expect("reopened stats"), partitioned);
        let current = reopened.control_policy_snapshot().expect("reopened policy");
        assert_eq!(
            reopened
                .blob_for_operation_with_policy(
                    &current,
                    &BlobOperationRequest::new(&operation, &intent),
                )
                .expect("reopened exact retry"),
            Some(stored)
        );
        drop(reopened);
        assert_eq!(
            Store::inspect_existing(&root.database)
                .expect("strict Blob inspection")
                .blob_stats,
            partitioned
        );
    }

    #[test]
    fn unmarked_crash_boundary_artifacts_are_reclaimed_before_exact_retry() {
        for (label, point) in [
            ("after-temp-sync", depot::DepotFaultPoint::TempSynced),
            ("after-rename", depot::DepotFaultPoint::Renamed),
            (
                "after-directory-sync",
                depot::DepotFaultPoint::DirectorySynced,
            ),
        ] {
            let root = BlobTestRoot::new(label);
            let services = blob_services(0x62);
            let plaintext = vec![0x33; 4_097];
            let prepared = prepared_blob(&plaintext);
            let store =
                Store::open_for_mission(&root.database, services.authority).expect("fault store");
            depot::inject_test_fault(&root.path, point);
            assert!(
                finish_variant(&store, &services.publisher, &prepared, &plaintext, 1).is_err(),
                "{point:?} must interrupt before the redb marker"
            );
            let variant = {
                let read = store.database.begin_read().expect("fault import read");
                let imports = read.open_table(BLOB_IMPORTS).expect("imports");
                let row = imports
                    .iter()
                    .expect("iterate imports")
                    .next()
                    .expect("import")
                    .expect("import row");
                BlobVariantId::from_bytes(row.0.value().try_into().expect("variant id"))
            };
            let variant_path = root.depot().join(test_hex32(variant.as_bytes()));
            assert!(directory_entry_count(&variant_path) > 0);
            let interrupted = store.blob_stats().expect("interrupted stats");
            assert_eq!(interrupted.variants, 1);
            assert_eq!(interrupted.committed_chunks, 0);
            drop(store);

            let reopened =
                Store::open_for_mission(&root.database, services.authority).expect("reclaim open");
            assert_eq!(directory_entry_count(&variant_path), 0);
            let finished = finish_variant(&reopened, &services.publisher, &prepared, &plaintext, 1)
                .expect("retry interrupted variant");
            assert_eq!(finished.id(), prepared.id());
            let recovered = reopened.blob_stats().expect("recovered stats");
            assert_eq!(recovered.variants, 1);
            assert_eq!(recovered.finalized_variants, 1);
            assert_eq!(recovered.committed_chunks, 1);
        }
    }

    #[test]
    fn marked_missing_truncated_and_hash_mismatched_chunks_fail_without_repair() {
        for (index, mode) in ["missing", "truncated", "hash-mismatch"]
            .into_iter()
            .enumerate()
        {
            let root = BlobTestRoot::new(mode);
            let mut services = blob_services(0x70 + u8::try_from(index).expect("seed"));
            let plaintext = vec![0x90 + u8::try_from(index).expect("byte"); 8_191];
            let prepared = prepared_blob(&plaintext);
            let store = Store::open_for_mission(&root.database, services.authority)
                .expect("corruption store");
            let (stored, _, _) = publish_blob(
                &store,
                &mut services,
                &prepared,
                &plaintext,
                1,
                mode.as_bytes(),
            );
            let chunk = root.chunk_path(stored.variant_id, 0);
            let original = std::fs::read(&chunk).expect("marked chunk");
            drop(store);

            let expected = match mode {
                "missing" => {
                    std::fs::remove_file(&chunk).expect("remove marked chunk");
                    None
                }
                "truncated" => {
                    let file = std::fs::OpenOptions::new()
                        .write(true)
                        .open(&chunk)
                        .expect("open marked chunk");
                    file.set_len(u64::try_from(original.len() - 1).expect("truncated length"))
                        .expect("truncate marked chunk");
                    Some(std::fs::read(&chunk).expect("truncated bytes"))
                }
                "hash-mismatch" => {
                    let mut corrupt = original.clone();
                    *corrupt.last_mut().expect("ciphertext byte") ^= 1;
                    std::fs::write(&chunk, &corrupt).expect("corrupt marked chunk");
                    Some(corrupt)
                }
                _ => unreachable!(),
            };

            let inspect_error = Store::inspect_existing(&root.database)
                .expect_err("strict inspection must reject marked corruption");
            assert_depot_integrity(&inspect_error);
            let reopen_error = match Store::open_for_mission(&root.database, services.authority) {
                Ok(_) => panic!("writable reopen must reject marked corruption"),
                Err(error) => error,
            };
            assert_depot_integrity(&reopen_error);
            match expected {
                None => assert!(!chunk.exists(), "missing marker target must stay missing"),
                Some(bytes) => assert_eq!(
                    std::fs::read(&chunk).expect("corrupt chunk remains"),
                    bytes,
                    "marked corruption must never be repaired silently"
                ),
            }
        }
    }

    #[test]
    fn blob_schema_migrates_only_as_one_whole_absent_group() {
        let legacy = BlobTestRoot::new("whole-absent-schema");
        let services = blob_services(0x76);
        {
            let store =
                Store::open_for_mission(&legacy.database, services.authority).expect("schema base");
            drop(store);
            let database = Database::open(&legacy.database).expect("raw schema database");
            let write = database.begin_write().expect("raw schema write");
            write.delete_table(BLOB_PUBLICATIONS).expect("publications");
            write.delete_table(BLOB_BYTES).expect("bytes");
            write.delete_table(BLOB_SEMANTIC_ITEMS).expect("semantic");
            write.delete_table(BLOB_CONTENT_INDEX).expect("content");
            write
                .delete_table(BLOB_ACCEPTANCE_MARKERS)
                .expect("markers");
            write.delete_table(BLOB_OPERATIONS).expect("operations");
            write.delete_table(BLOB_IMPORTS).expect("imports");
            write.delete_table(BLOB_CHUNKS).expect("chunks");
            write
                .delete_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata");
            {
                let mut metadata = write.open_table(METADATA).expect("metadata");
                for field in blob_global_metadata_fields() {
                    metadata.remove(field).expect("remove Blob counter");
                }
            }
            write.commit().expect("commit whole-absent schema");
        }
        assert_eq!(
            Store::inspect_existing(&legacy.database)
                .expect("inspect whole-absent Blob group")
                .blob_stats,
            BlobStoreStats::default()
        );
        let migrated = Store::open_for_mission(&legacy.database, services.authority)
            .expect("migrate whole-absent Blob group");
        assert_eq!(
            migrated.blob_stats().expect("migrated Blob stats"),
            BlobStoreStats::default()
        );
        drop(migrated);

        let partial = BlobTestRoot::new("partial-schema");
        {
            let store = Store::open_for_mission(&partial.database, services.authority)
                .expect("partial base");
            drop(store);
            let database = Database::open(&partial.database).expect("partial database");
            let write = database.begin_write().expect("partial write");
            write.delete_table(BLOB_CHUNKS).expect("delete one table");
            write.commit().expect("commit partial schema");
        }
        let inspect_error = Store::inspect_existing(&partial.database)
            .expect_err("inspection rejects partial Blob schema");
        let reopen_error = match Store::open_for_mission(&partial.database, services.authority) {
            Ok(_) => panic!("reopen rejects partial Blob schema"),
            Err(error) => error,
        };
        for error in [inspect_error, reopen_error] {
            assert!(matches!(
                error,
                StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "mission-scoped Blob schema group is incomplete"
                ))
            ));
        }

        let missing_counter = BlobTestRoot::new("missing-counter");
        {
            let store = Store::open_for_mission(&missing_counter.database, services.authority)
                .expect("counter base");
            drop(store);
            let database = Database::open(&missing_counter.database).expect("counter database");
            let write = database.begin_write().expect("counter write");
            write
                .open_table(METADATA)
                .expect("metadata")
                .remove(BLOB_OPERATION_COUNT)
                .expect("remove Blob counter");
            write.commit().expect("commit missing counter");
        }
        assert!(matches!(
            Store::inspect_existing(&missing_counter.database),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "mission-scoped Blob schema group is incomplete"
            )))
        ));
        assert!(matches!(
            Store::open_for_mission(&missing_counter.database, services.authority),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "mission-scoped Blob schema group is incomplete"
            )))
        ));
        let database = redb::Builder::new()
            .open_read_only(&missing_counter.database)
            .expect("read missing counter");
        assert!(
            database
                .begin_read()
                .expect("read transaction")
                .open_table(METADATA)
                .expect("metadata")
                .get(BLOB_OPERATION_COUNT)
                .expect("counter read")
                .is_none(),
            "failed writable reopen must not repair a partial Blob schema"
        );

        let wrong_kind = BlobTestRoot::new("wrong-kind");
        {
            let store = Store::open_for_mission(&wrong_kind.database, services.authority)
                .expect("wrong-kind base");
            drop(store);
            let database = Database::open(&wrong_kind.database).expect("wrong-kind database");
            let write = database.begin_write().expect("wrong-kind write");
            write
                .delete_table(BLOB_OPERATIONS)
                .expect("delete normal Blob operations");
            let definition =
                redb::MultimapTableDefinition::<&[u8], &[u8]>::new("aster.blob-operations.v1");
            write
                .open_multimap_table(definition)
                .expect("wrong-kind Blob operations")
                .insert(b"operation".as_slice(), b"row".as_slice())
                .expect("wrong-kind row");
            write.commit().expect("commit wrong-kind schema");
        }
        assert!(matches!(
            Store::inspect_existing(&wrong_kind.database),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "mission-scoped Blob schema has the wrong table kind"
            )))
        ));
        assert!(matches!(
            Store::open_for_mission(&wrong_kind.database, services.authority),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "mission-scoped Blob schema has the wrong table kind"
            )))
        ));
    }

    #[test]
    fn terminal_open_rejects_before_touching_unmarked_depot_artifacts() {
        let root = BlobTestRoot::new("terminal-gate");
        let services = blob_services(0x77);
        let mut store = Store::open_for_mission(&root.database, services.authority).expect("store");
        drop(store.blob_depot().expect("create fixed depot"));
        let orphan = root.depot().join(".aster-blob-tmp-terminal-proof");
        let orphan_bytes = b"unmarked ciphertext remains outside terminal reopen";
        std::fs::write(&orphan, orphan_bytes).expect("write orphan");
        let intent = ZeroizationIntent::new(
            b"mission bundle descriptor".to_vec(),
            b"carrier identity descriptor".to_vec(),
        )
        .expect("zeroization intent");
        store.begin_zeroization(&intent).expect("terminal marker");
        drop(store);

        assert!(matches!(
            Store::open_for_mission(&root.database, services.authority),
            Err(StoreError::StoreZeroized(
                StoreZeroizationState::CleanupPending
            ))
        ));
        assert_eq!(
            std::fs::read(&orphan).expect("terminal orphan preserved"),
            orphan_bytes,
            "terminal gate must run before depot scan or cleanup"
        );
    }

    #[test]
    fn terminal_entry_closes_new_and_already_held_blob_depot_io_before_mutation() {
        let public_root = BlobTestRoot::new("terminal-depot-public-gate");
        let public_services = blob_services(0xb4);
        let mut public_store =
            Store::open_for_mission(&public_root.database, public_services.authority)
                .expect("public terminal store");
        drop(public_store.blob_depot().expect("initial depot adapter"));
        let before_terminal = depot_file_snapshot(&public_root.depot());
        let intent = ZeroizationIntent::new(
            b"terminal depot mission descriptor".to_vec(),
            b"terminal depot identity descriptor".to_vec(),
        )
        .expect("terminal intent");
        public_store
            .begin_zeroization(&intent)
            .expect("terminal entry");
        assert!(matches!(
            public_store.blob_depot(),
            Err(StoreError::StoreZeroized(
                StoreZeroizationState::CleanupPending
            ))
        ));
        assert_eq!(depot_file_snapshot(&public_root.depot()), before_terminal);

        let held_root = BlobTestRoot::new("terminal-depot-held-gate");
        let held_services = blob_services(0xb5);
        let held_store = Store::open_for_mission(&held_root.database, held_services.authority)
            .expect("held adapter store");
        let prepared = prepared_blob(b"held adapter gate");
        let mut held = held_store.blob_depot().expect("held adapter");
        let before_files = depot_file_snapshot(&held_root.depot());
        let before_rows = {
            let read = held_store.database.begin_read().expect("held gate read");
            (
                read.open_table(BLOB_IMPORTS)
                    .expect("imports")
                    .len()
                    .expect("import rows"),
                read.open_table(BLOB_CHUNKS)
                    .expect("chunks")
                    .len()
                    .expect("chunk rows"),
            )
        };
        held_store.live.store(false, Ordering::SeqCst);
        assert!(matches!(
            CoreBlobStore::plaintext_digest(&mut held, prepared.id(), 0),
            Err(StoreError::StoreZeroized(
                StoreZeroizationState::CleanupPending
            ))
        ));
        assert!(matches!(
            CoreBlobStore::put_plaintext_digest(&mut held, prepared.id(), 0, [0x55; 32]),
            Err(StoreError::StoreZeroized(
                StoreZeroizationState::CleanupPending
            ))
        ));
        let after_rows = {
            let read = held_store.database.begin_read().expect("held gate reread");
            (
                read.open_table(BLOB_IMPORTS)
                    .expect("imports")
                    .len()
                    .expect("import rows"),
                read.open_table(BLOB_CHUNKS)
                    .expect("chunks")
                    .len()
                    .expect("chunk rows"),
            )
        };
        assert_eq!(after_rows, before_rows);
        assert_eq!(depot_file_snapshot(&held_root.depot()), before_files);
        held_store.live.store(true, Ordering::SeqCst);
        drop(held);
    }

    #[test]
    fn blob_and_event_share_causal_ledgers_and_strict_corruption_authority() {
        let root = BlobTestRoot::new("shared-causal");
        let mut services = blob_services(0x78);
        let plaintext = vec![0x78; 1_337];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"causal-blob",
        );
        let policy = store.control_policy_snapshot().expect("policy");
        let (reservation, event, sealed) =
            reserved_event(&store, &mut services, &policy, b"observes Blob");
        assert_eq!(reservation.counter(), 2);
        assert_eq!(
            reservation
                .context()
                .counter(&services.publisher.identity()),
            1
        );
        store
            .commit_reserved_event_with_policy(&policy, &reservation, &event, &sealed)
            .expect("commit Event after Blob");
        assert_eq!(store.event_stats().expect("Event stats").events, 1);
        assert_eq!(store.blob_stats().expect("Blob stats").publications, 1);
        drop(store);
        let inspection = Store::inspect_existing(&root.database).expect("shared inspection");
        assert_eq!(inspection.event_stats.events, 1);
        assert_eq!(inspection.blob_stats.publications, 1);

        let database = Database::open(&root.database).expect("raw corruption database");
        let write = database.begin_write().expect("raw corruption write");
        write
            .open_table(ACCEPTED_DOTS)
            .expect("accepted dots")
            .remove(accepted_dot_key(stored.header.stamp.dot).as_slice())
            .expect("remove Blob dot");
        write.commit().expect("commit Blob dot corruption");
        drop(database);
        assert!(matches!(
            Store::inspect_existing(&root.database),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob publication is missing its accepted-dot row"
            )))
        ));
        assert!(matches!(
            Store::open_for_mission(&root.database, services.authority),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob publication is missing its accepted-dot row"
            )))
        ));
    }

    #[test]
    fn blob_usage_counts_toward_cross_class_aggregate_quota_after_reopen() {
        let root = BlobTestRoot::new("aggregate-quota");
        let mut services = blob_services(0x79);
        let limits = StoreLimits::new(2, u64::MAX).expect("aggregate limits");
        let plaintext = vec![0x79; 2_049];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_with_limits_for_mission(&root.database, limits, services.authority)
            .expect("quota store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"quota-blob",
        );
        let policy = store.control_policy_snapshot().expect("quota policy");
        let (reservation, event, sealed) =
            reserved_event(&store, &mut services, &policy, b"must roll back");
        let rejected =
            store.commit_reserved_event_with_policy(&policy, &reservation, &event, &sealed);
        assert!(
            matches!(
                rejected,
                Err(StoreError::ItemLimitExceeded {
                    current: 2,
                    limit: 2,
                })
            ),
            "unexpected aggregate result: {rejected:?}"
        );
        assert_eq!(
            store.event_stats().expect("rolled-back Event stats").events,
            0
        );
        assert_eq!(
            store.blob_inventory().expect("Blob inventory"),
            vec![stored.transfer_id]
        );
        drop(store);

        let reopened =
            Store::open_with_limits_for_mission(&root.database, limits, services.authority)
                .expect("quota reopen");
        let reopened_rejected =
            reopened.commit_reserved_event_with_policy(&policy, &reservation, &event, &sealed);
        assert!(
            matches!(
                reopened_rejected,
                Err(StoreError::ItemLimitExceeded {
                    current: 2,
                    limit: 2,
                })
            ),
            "unexpected reopened aggregate result: {reopened_rejected:?}"
        );
        assert_eq!(
            reopened.event_stats().expect("reopened Event stats").events,
            0
        );
        assert_eq!(
            reopened
                .blob_stats()
                .expect("reopened Blob stats")
                .publications,
            1
        );
    }

    #[test]
    fn cross_class_transfer_collision_is_rejected_on_inspection_and_reopen() {
        let root = BlobTestRoot::new("cross-class-collision");
        let mut services = blob_services(0x7a);
        let plaintext = vec![0x7a; 777];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"collision-blob",
        );
        drop(store);
        let database = Database::open(&root.database).expect("collision database");
        let write = database.begin_write().expect("collision write");
        write
            .open_table(EVENTS)
            .expect("Events")
            .insert(
                stored.transfer_id.as_bytes().as_slice(),
                b"opaque collision".as_slice(),
            )
            .expect("insert transfer collision");
        write.commit().expect("commit transfer collision");
        drop(database);
        assert!(matches!(
            Store::inspect_existing(&root.database),
            Err(StoreError::TransferNamespaceCollision { transfer_id })
                if transfer_id == *stored.transfer_id.as_bytes()
        ));
        assert!(matches!(
            Store::open_for_mission(&root.database, services.authority),
            Err(StoreError::TransferNamespaceCollision { transfer_id })
                if transfer_id == *stored.transfer_id.as_bytes()
        ));

        let database = Database::open(&root.database).expect("semantic collision database");
        let write = database.begin_write().expect("semantic collision write");
        write
            .open_table(EVENTS)
            .expect("Events")
            .remove(stored.transfer_id.as_bytes().as_slice())
            .expect("remove transfer collision");
        write
            .open_table(SEMANTIC_ITEMS)
            .expect("Event semantic items")
            .insert(
                stored.semantic_id.as_bytes().as_slice(),
                stored.transfer_id.as_bytes().as_slice(),
            )
            .expect("insert semantic collision");
        write.commit().expect("commit semantic collision");
        drop(database);
        assert!(matches!(
            Store::inspect_existing(&root.database),
            Err(StoreError::SemanticNamespaceCollision { semantic_id })
                if semantic_id == *stored.semantic_id.as_bytes()
        ));
        assert!(matches!(
            Store::open_for_mission(&root.database, services.authority),
            Err(StoreError::SemanticNamespaceCollision { semantic_id })
                if semantic_id == *stored.semantic_id.as_bytes()
        ));
    }

    #[test]
    fn completion_rejects_forged_final_digest_with_wrong_committed_records() {
        let genuine_root = BlobTestRoot::new("genuine-manifest");
        let forged_root = BlobTestRoot::new("forged-completion");
        let mut services = blob_services(0x7b);
        let plaintext = vec![0x7b; 4_321];
        let prepared = prepared_blob(&plaintext);
        let genuine = Store::open_for_mission(&genuine_root.database, services.authority)
            .expect("genuine depot");
        let (manifest, finished) = {
            let depot = genuine.blob_depot().expect("genuine adapter");
            let mut service = services
                .publisher
                .blob_service_with_store(&blob_scope(), &blob_topic(), 1, depot)
                .expect("genuine service");
            let manifest = service
                .install_prepared(&prepared)
                .expect("genuine manifest");
            let progress = service
                .encrypt_some(&mut Cursor::new(&plaintext), &manifest, u64::MAX)
                .expect("genuine encryption");
            assert!(progress.complete);
            let finished = service
                .finish_manifest(&manifest)
                .expect("genuine finalization");
            (manifest, finished)
        };

        let forged = Store::open_for_mission(&forged_root.database, services.authority)
            .expect("forged depot");
        let policy = forged.control_policy_snapshot().expect("forged policy");
        let reservation = forged
            .reserve_blob_with_policy(
                &policy,
                services.publisher.identity(),
                &blob_topic(),
                &blob_scope(),
            )
            .expect("forged reservation");
        let header = reservation
            .header(
                Priority::Immediate,
                finished.route_commitment(),
                u64::try_from(finished.manifest_bytes().len()).expect("manifest length"),
                1,
            )
            .expect("source header");
        let sealed = services
            .publisher
            .seal_blob_manifest(&header, finished.manifest_bytes())
            .expect("source seal");
        let route = services
            .reader
            .verify_blob(&sealed.bytes)
            .expect("source route");
        let (blob, manifest_bytes) = match services
            .reader
            .verify_blob_content(route, &sealed.bytes)
            .expect("source content")
        {
            BlobContentVerification::ContentVerified {
                blob,
                manifest_bytes,
            } => (blob, manifest_bytes),
            BlobContentVerification::RouteOnly(_) => panic!("member unexpectedly route-only"),
        };

        {
            let mut depot = forged.blob_depot().expect("forged adapter");
            CoreBlobStore::begin_blob(&mut depot, &manifest).expect("begin forged import");
            let wrong_plaintext_digest = [0xa5; 32];
            let ciphertext = vec![0x5a; plaintext.len() + 16];
            let ciphertext_digest: [u8; 32] = Sha256::digest(&ciphertext).into();
            let record = aster_mesh::BlobChunkRecord::from_parts(
                wrong_plaintext_digest,
                ciphertext_digest,
                u32::try_from(plaintext.len()).expect("plaintext length"),
                u32::try_from(ciphertext.len()).expect("ciphertext length"),
            )
            .expect("forged internally consistent record");
            CoreBlobStore::put_plaintext_digest(
                &mut depot,
                manifest.id(),
                0,
                wrong_plaintext_digest,
            )
            .expect("stage forged digest");
            CoreBlobStore::commit_verified_chunk(&mut depot, manifest.id(), 0, record, &ciphertext)
                .expect("commit forged record");
            CoreBlobStore::finalize_blob(&mut depot, manifest.id(), *blob.manifest_digest())
                .expect("forge final digest through public storage mechanics");
        }

        let error = forged
            .blob_depot()
            .and_then(|mut depot| depot.completed_blob(&blob, &manifest_bytes))
            .expect_err("strong completion must reject wrong authenticated records");
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::CompletionMismatch)
        ));
        let stats = forged
            .blob_stats()
            .expect("forged depot remains inspectable");
        assert_eq!(stats.finalized_variants, 1);
        assert_eq!(stats.publications, 0);
    }

    #[test]
    fn completion_capability_is_bound_to_one_exact_store_instance() {
        let first_root = BlobTestRoot::new("completion-instance-first");
        let second_root = BlobTestRoot::new("completion-instance-second");
        let mut services = blob_services(0x7d);
        let plaintext = vec![0x7d; 2_048];
        let prepared = prepared_blob(&plaintext);
        let first =
            Store::open_for_mission(&first_root.database, services.authority).expect("first store");
        let second = Store::open_for_mission(&second_root.database, services.authority)
            .expect("second store");
        let proof = prepare_blob_proof(&first, &mut services, &prepared, &plaintext, 1);
        let second_finished =
            finish_variant(&second, &services.publisher, &prepared, &plaintext, 1)
                .expect("install identical second-store variant");
        assert_eq!(
            second_finished.manifest_digest(),
            proof.blob.manifest_digest(),
            "both stores contain the same exact finalized variant"
        );

        let policy = second.control_policy_snapshot().expect("second policy");
        let reservation = second
            .reserve_blob_with_policy(
                &policy,
                services.publisher.identity(),
                &blob_topic(),
                &blob_scope(),
            )
            .expect("second reservation");
        let operation =
            BlobOperationKey::new(b"cross-store-completion".to_vec()).expect("operation key");
        let intent = BlobPublicationIntent::new(
            services.publisher.identity(),
            blob_topic(),
            blob_scope(),
            Priority::Immediate,
            prepared.id(),
        )
        .expect("publication intent");
        let request = BlobOperationRequest::new(&operation, &intent);

        // Equalize the portable file-identity defense so this exercises the
        // private Store-instance token on Unix and non-Unix platforms alike.
        let mut replayed = proof.completion.clone();
        replayed.backing_identity = second.backing_identity;
        let error = second
            .commit_reserved_blob_once_with_policy(
                &policy,
                &request,
                &reservation,
                &proof.blob,
                &proof.sealed,
                &replayed,
            )
            .expect_err("another Store instance cannot replay a completion capability");
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::CompletionMismatch)
        ));
        let stats = second.blob_stats().expect("second stats after rejection");
        assert_eq!(stats.publications, 0);
        assert_eq!(stats.operations, 0);
    }

    #[test]
    fn accepted_publication_requires_its_exact_finalized_import_without_repair() {
        let root = BlobTestRoot::new("missing-publication-import");
        let mut services = blob_services(0x7c);
        let plaintext = vec![0x7c; 1_111];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"missing-import",
        );
        let variant_path = root.depot().join(test_hex32(stored.variant_id.as_bytes()));
        drop(store);

        let database = Database::open(&root.database).expect("raw import database");
        let write = database.begin_write().expect("raw import write");
        write
            .open_table(BLOB_IMPORTS)
            .expect("imports")
            .remove(stored.variant_id.as_bytes().as_slice())
            .expect("remove import");
        let chunk_keys = write
            .open_table(BLOB_CHUNKS)
            .expect("chunks")
            .iter()
            .expect("iterate chunks")
            .map(|row| row.map(|(key, _)| key.value().to_vec()))
            .collect::<Result<Vec<_>, _>>()
            .expect("chunk keys");
        {
            let mut chunks = write.open_table(BLOB_CHUNKS).expect("chunks");
            for key in chunk_keys {
                chunks.remove(key.as_slice()).expect("remove chunk marker");
            }
        }
        {
            let mut depot = write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata");
            depot.insert(DEPOT_VARIANT_COUNT, 0).expect("variant count");
            depot
                .insert(DEPOT_COMMITTED_CHUNK_COUNT, 0)
                .expect("chunk count");
            depot
                .insert(DEPOT_COMMITTED_FILE_BYTES, 0)
                .expect("byte count");
        }
        write.commit().expect("commit coherent depot deletion");
        drop(database);
        std::fs::remove_dir_all(&variant_path).expect("remove physical variant");

        for error in [
            Store::inspect_existing(&root.database)
                .expect_err("inspection rejects missing publication import"),
            match Store::open_for_mission(&root.database, services.authority) {
                Ok(_) => panic!("reopen rejects missing publication import"),
                Err(error) => error,
            },
        ] {
            assert!(matches!(
                error,
                StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "accepted Blob publication is missing its depot import"
                ))
            ));
        }
        assert!(
            !variant_path.exists(),
            "failed reopen must not manufacture an accepted publication import"
        );
    }

    #[test]
    fn accepted_publication_rejects_mismatched_finalized_import_digest() {
        let root = BlobTestRoot::new("mismatched-import-digest");
        let mut services = blob_services(0x83);
        let plaintext = vec![0x83; 1_234];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"digest-import",
        );
        drop(store);
        let database = Database::open(&root.database).expect("raw import database");
        let write = database.begin_write().expect("raw import write");
        let mut encoded = write
            .open_table(BLOB_IMPORTS)
            .expect("imports")
            .get(stored.variant_id.as_bytes().as_slice())
            .expect("import read")
            .expect("import row")
            .value()
            .to_vec();
        const FINALIZED_FLAG_OFFSET: usize = 157;
        const FINALIZED_DIGEST_OFFSET: usize = FINALIZED_FLAG_OFFSET + 1;
        assert_eq!(encoded[FINALIZED_FLAG_OFFSET], 1);
        encoded[FINALIZED_DIGEST_OFFSET] ^= 1;
        write
            .open_table(BLOB_IMPORTS)
            .expect("imports")
            .insert(stored.variant_id.as_bytes().as_slice(), encoded.as_slice())
            .expect("replace final digest");
        write.commit().expect("commit final digest mismatch");
        drop(database);

        for error in [
            Store::inspect_existing(&root.database)
                .expect_err("inspection rejects mismatched import digest"),
            match Store::open_for_mission(&root.database, services.authority) {
                Ok(_) => panic!("reopen rejects mismatched import digest"),
                Err(error) => error,
            },
        ] {
            assert!(matches!(
                error,
                StoreError::Blob(BlobStoreError::SchemaInvariant(
                    "accepted Blob publication differs from its finalized depot import"
                ))
            ));
        }
        let database = redb::Builder::new()
            .open_read_only(&root.database)
            .expect("read corrupt import");
        let read = database.begin_read().expect("read transaction");
        assert_eq!(
            read.open_table(BLOB_IMPORTS)
                .expect("imports")
                .get(stored.variant_id.as_bytes().as_slice())
                .expect("import read")
                .expect("import row")
                .value(),
            encoded.as_slice(),
            "failed reopen must not rewrite a mismatched final digest"
        );
    }

    #[test]
    fn own_dot_observing_blob_context_is_rejected_as_durable_corruption() {
        let root = BlobTestRoot::new("own-dot-context");
        let mut services = blob_services(0x7d);
        let plaintext = vec![0x7d; 999];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (stored, _, _) =
            publish_blob(&store, &mut services, &prepared, &plaintext, 1, b"own-dot");
        drop(store);

        let database = Database::open(&root.database).expect("raw metadata database");
        let write = database.begin_write().expect("raw metadata write");
        let mut encoded = write
            .open_table(BLOB_PUBLICATIONS)
            .expect("publications")
            .get(stored.transfer_id.as_bytes().as_slice())
            .expect("publication read")
            .expect("publication row")
            .value()
            .to_vec();
        assert_eq!(&encoded[encoded.len() - 4..], &[0, 0, 0, 0]);
        let context_offset = encoded.len() - 4;
        encoded[context_offset..].copy_from_slice(&1u32.to_be_bytes());
        encoded.extend_from_slice(&stored.header.stamp.dot.publisher);
        encoded.extend_from_slice(&stored.header.stamp.dot.counter.to_be_bytes());
        write
            .open_table(BLOB_PUBLICATIONS)
            .expect("publications")
            .insert(stored.transfer_id.as_bytes().as_slice(), encoded.as_slice())
            .expect("corrupt context");
        write.commit().expect("commit context corruption");
        drop(database);

        assert!(matches!(
            Store::inspect_existing(&root.database),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "decoded Blob metadata is internally inconsistent"
            )))
        ));
        assert!(matches!(
            Store::open_for_mission(&root.database, services.authority),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "decoded Blob metadata is internally inconsistent"
            )))
        ));
    }

    #[test]
    fn unbound_interrupted_import_cannot_be_rebound_or_physically_reclaimed() {
        let root = BlobTestRoot::new("unbound-interrupted");
        let services = blob_services(0x7e);
        let other = blob_services(0x7f);
        let plaintext = vec![0x7e; 3_333];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        depot::inject_test_fault(&root.path, depot::DepotFaultPoint::TempSynced);
        assert!(finish_variant(&store, &services.publisher, &prepared, &plaintext, 1).is_err());
        drop(store);
        let variant = std::fs::read_dir(root.depot())
            .expect("depot root")
            .map(|entry| entry.expect("depot entry"))
            .find(|entry| entry.file_type().expect("depot entry type").is_dir())
            .expect("variant directory");
        let artifact = std::fs::read_dir(variant.path())
            .expect("variant directory")
            .next()
            .expect("interrupted artifact")
            .expect("artifact entry")
            .path();
        let artifact_bytes = std::fs::read(&artifact).expect("artifact bytes");

        let database = Database::open(&root.database).expect("raw unbind database");
        let write = database.begin_write().expect("raw unbind write");
        write
            .open_table(SEMANTIC_DOMAIN)
            .expect("semantic domain")
            .remove(MISSION_AUTHORITY_ID)
            .expect("remove mission binding");
        write.commit().expect("commit unbound fixture");
        drop(database);

        assert!(matches!(
            Store::open_for_mission(&root.database, other.authority),
            Err(StoreError::SemanticInvariant(
                "unbound store contains mission-scoped Event, State, Record, Blob, or control state"
            ))
        ));
        assert_eq!(
            std::fs::read(&artifact).expect("unbound artifact remains"),
            artifact_bytes,
            "mission preflight must reject before depot cleanup"
        );
        assert_eq!(
            inspect_mission_binding_read_only(&root.database)
                .expect_err("unbound Blob rows remain unbindable")
                .to_string(),
            StoreError::SemanticInvariant(
                "unbound store contains mission-scoped Event, State, Record, Blob, or control state"
            )
            .to_string()
        );
    }

    #[test]
    fn operation_row_and_byte_caps_roll_back_atomically_and_survive_reopen() {
        for byte_cap in [false, true] {
            let root = BlobTestRoot::new(if byte_cap {
                "operation-bytes"
            } else {
                "operation-rows"
            });
            let mut services = blob_services(if byte_cap { 0x80 } else { 0x81 });
            let plaintext = vec![if byte_cap { 0x80 } else { 0x81 }; 512];
            let prepared = prepared_blob(&plaintext);
            let store = Store::open_for_mission(&root.database, services.authority).expect("store");
            let (stored, _, _) = publish_blob(
                &store,
                &mut services,
                &prepared,
                &plaintext,
                1,
                b"original-operation",
            );
            let write = store.database.begin_write().expect("seed operation ledger");
            {
                let mut operations = write.open_table(BLOB_OPERATIONS).expect("operations");
                if byte_cap {
                    let mut index = 0u32;
                    loop {
                        let mut key = vec![b'b'; 200];
                        key[..4].copy_from_slice(&index.to_be_bytes());
                        let encoded = encode_blob_operation_record(BlobOperationRecord {
                            transfer_id: stored.transfer_id,
                            intent_digest: [u8::try_from(index % 251).expect("intent byte"); 32],
                        });
                        let current_bytes = operations
                            .iter()
                            .expect("operation rows")
                            .map(|row| {
                                row.map(|(key, value)| key.value().len() + value.value().len())
                            })
                            .collect::<Result<Vec<_>, _>>()
                            .expect("operation row lengths")
                            .into_iter()
                            .sum::<usize>();
                        if u64::try_from(current_bytes + key.len() + encoded.len())
                            .expect("operation bytes")
                            > MAX_BLOB_OPERATION_BYTES - 64
                        {
                            break;
                        }
                        operations
                            .insert(key.as_slice(), encoded.as_slice())
                            .expect("seed byte-cap operation");
                        index = index.checked_add(1).expect("operation index");
                    }
                } else {
                    for index in 1..MAX_BLOB_OPERATIONS {
                        let key = format!("r{index:04}").into_bytes();
                        let encoded = encode_blob_operation_record(BlobOperationRecord {
                            transfer_id: stored.transfer_id,
                            intent_digest: [u8::try_from(index % 251).expect("intent byte"); 32],
                        });
                        operations
                            .insert(key.as_slice(), encoded.as_slice())
                            .expect("seed row-cap operation");
                    }
                }
            }
            let (count, bytes) = {
                let operations = write.open_table(BLOB_OPERATIONS).expect("operations");
                let count = operations.len().expect("operation count");
                let bytes = operations
                    .iter()
                    .expect("operation rows")
                    .map(|row| {
                        row.map(|(key, value)| {
                            u64::try_from(key.value().len() + value.value().len())
                                .expect("operation row bytes")
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .expect("operation row lengths")
                    .into_iter()
                    .sum::<u64>();
                (count, bytes)
            };
            {
                let mut metadata = write.open_table(METADATA).expect("metadata");
                metadata
                    .insert(BLOB_OPERATION_COUNT, count)
                    .expect("operation count accounting");
                metadata
                    .insert(BLOB_OPERATION_TOTAL_BYTES, bytes)
                    .expect("operation byte accounting");
            }
            write.commit().expect("commit seeded operation ledger");
            drop(store);

            let reopened = Store::open_for_mission(&root.database, services.authority)
                .expect("reopen seeded operation ledger");
            let before = reopened
                .blob_stats()
                .expect("operation stats before rejection");
            assert_eq!(before.operations, count);
            assert_eq!(before.operation_bytes, bytes);
            let operation = BlobOperationKey::new(vec![b'z'; 256]).expect("new operation");
            let intent = BlobPublicationIntent::new(
                services.publisher.identity(),
                blob_topic(),
                blob_scope(),
                Priority::Immediate,
                stored.blob_id,
            )
            .expect("operation intent");
            let request = BlobOperationRequest::new(&operation, &intent);
            let write = reopened
                .database
                .begin_write()
                .expect("rejected operation write");
            let error =
                insert_blob_operation(&write, reopened.limits, &request, stored.transfer_id)
                    .expect_err("operation cap must reject");
            if byte_cap {
                assert!(matches!(
                    error,
                    StoreError::Blob(BlobStoreError::OperationByteLimitExceeded { .. })
                ));
            } else {
                assert!(matches!(
                    error,
                    StoreError::Blob(BlobStoreError::OperationLimitExceeded { .. })
                ));
            }
            drop(write);
            assert_eq!(reopened.blob_stats().expect("post-rejection stats"), before);
            drop(reopened);
            assert_eq!(
                Store::inspect_existing(&root.database)
                    .expect("strict operation inspection")
                    .blob_stats,
                before
            );
        }
    }

    #[test]
    fn depot_owner_staging_recovers_every_durable_first_install_boundary() {
        for (index, point) in [
            depot::DepotFaultPoint::OwnerStagingCreated,
            depot::DepotFaultPoint::OwnerTempCreated,
            depot::DepotFaultPoint::OwnerTempPartiallyWritten,
            depot::DepotFaultPoint::OwnerTempSynced,
            depot::DepotFaultPoint::OwnerMarkerRenamed,
            depot::DepotFaultPoint::OwnerMarkerDirectorySynced,
            depot::DepotFaultPoint::OwnerRootSynced,
            depot::DepotFaultPoint::OwnerRenamed,
            depot::DepotFaultPoint::OwnerDirectorySynced,
        ]
        .into_iter()
        .enumerate()
        {
            let root = BlobTestRoot::new(&format!("owner-crash-{index}"));
            let services = blob_services(0xa0 + u8::try_from(index).expect("fault index"));
            let store =
                Store::open_for_mission(&root.database, services.authority).expect("empty store");
            depot::inject_test_fault(&root.path, point);
            assert!(store.blob_depot().is_err(), "fault {point:?} must fire");
            drop(store);
            let reopened = Store::open_for_mission(&root.database, services.authority)
                .expect("reopen interrupted owner election");
            drop(reopened.blob_depot().expect("same-DB owner-election retry"));
            assert_eq!(
                reopened.blob_stats().expect("owner-election retry stats"),
                BlobStoreStats::default()
            );
            let marker = root.depot().join(".aster-store-owner-v1");
            assert_eq!(std::fs::metadata(&marker).expect("owner marker").len(), 72);
            assert!(
                std::fs::read_dir(&root.path)
                    .expect("state root")
                    .map(|entry| entry.expect("state entry").file_name())
                    .all(|name| !name
                        .to_string_lossy()
                        .starts_with(".aster-blob-depot-pending-v1-")),
                "successful retry must publish, not strand, its pending directory"
            );
        }
    }

    #[test]
    fn distinct_same_parent_stores_elect_one_depot_without_mutating_the_loser() {
        let root = BlobTestRoot::new("same-parent-election");
        let second_path = root.path.join("second.redb");
        let services = blob_services(0xb1);
        let first =
            Store::open_for_mission(&root.database, services.authority).expect("first store");
        let second =
            Store::open_for_mission(&second_path, services.authority).expect("second store");
        let first_database_before = file_digest(&root.database);
        let second_database_before = file_digest(&second_path);
        let barrier = std::sync::Barrier::new(3);
        let (first_result, second_result) = std::thread::scope(|scope| {
            let first_thread = scope.spawn(|| {
                barrier.wait();
                first.blob_depot().map(drop)
            });
            let second_thread = scope.spawn(|| {
                barrier.wait();
                second.blob_depot().map(drop)
            });
            barrier.wait();
            (
                first_thread.join().expect("first election thread"),
                second_thread.join().expect("second election thread"),
            )
        });
        assert_ne!(first_result.is_ok(), second_result.is_ok());
        let marker = root.depot().join(".aster-store-owner-v1");
        let marker_before = std::fs::read(&marker).expect("winner marker");
        let (winner, loser, loser_database, loser_before) = if first_result.is_ok() {
            (&first, &second, &second_path, second_database_before)
        } else {
            (&second, &first, &root.database, first_database_before)
        };
        drop(winner.blob_depot().expect("winner retry"));
        let loser_error = match loser.blob_depot() {
            Err(error) => error,
            Ok(_) => panic!("loser must fail closed"),
        };
        assert_depot_integrity(&loser_error);
        assert_eq!(
            std::fs::read(&marker).expect("unchanged winner marker"),
            marker_before
        );
        assert_eq!(file_digest(loser_database), loser_before);
        assert_eq!(
            winner.blob_stats().expect("winner empty stats"),
            BlobStoreStats::default()
        );
    }

    #[test]
    fn malformed_owner_marker_and_same_path_replacement_fail_without_repair() {
        let malformed = BlobTestRoot::new("owner-marker-malformed");
        let services = blob_services(0xb2);
        let store =
            Store::open_for_mission(&malformed.database, services.authority).expect("marker store");
        drop(store.blob_depot().expect("create marker"));
        drop(store);
        let marker = malformed.depot().join(".aster-store-owner-v1");
        std::fs::write(&marker, b"truncated-owner-marker").expect("truncate marker");
        let corrupted = depot_file_snapshot(&malformed.depot());
        assert_depot_integrity(
            &Store::inspect_existing(&malformed.database).expect_err("inspect malformed marker"),
        );
        let reopen_error = match Store::open_for_mission(&malformed.database, services.authority) {
            Err(error) => error,
            Ok(_) => panic!("reopen malformed marker must fail"),
        };
        assert_depot_integrity(&reopen_error);
        assert_eq!(depot_file_snapshot(&malformed.depot()), corrupted);

        #[cfg(unix)]
        {
            let replaced = BlobTestRoot::new("owner-same-path-replacement");
            let replacement_services = blob_services(0xb3);
            let live = Store::open_for_mission(&replaced.database, replacement_services.authority)
                .expect("live original");
            drop(live.blob_depot().expect("bind original depot"));
            let before = depot_file_snapshot(&replaced.depot());
            let parked = replaced.path.join("parked.redb");
            std::fs::rename(&replaced.database, &parked).expect("park original backing");
            assert!(
                Store::open_for_mission(&replaced.database, replacement_services.authority)
                    .is_err()
            );
            assert_eq!(depot_file_snapshot(&replaced.depot()), before);
            drop(live);
        }
    }

    #[test]
    fn owner_binding_migration_is_empty_only_and_partial_or_relocated_state_fails_closed() {
        let services = blob_services(0xb6);
        let empty = BlobTestRoot::new("owner-binding-empty-migration");
        drop(
            Store::open_for_mission(&empty.database, services.authority)
                .expect("empty binding store"),
        );
        {
            let database = Database::open(&empty.database).expect("raw empty binding database");
            let write = database.begin_write().expect("remove empty binding");
            let mut depot = write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata");
            for field in depot_owner_binding_fields() {
                depot.remove(field).expect("remove owner binding field");
            }
            drop(depot);
            write.commit().expect("commit absent owner binding");
        }
        assert!(Store::inspect_existing(&empty.database).is_err());
        drop(
            Store::open_for_mission(&empty.database, services.authority)
                .expect("canonical empty binding migration"),
        );
        Store::inspect_existing(&empty.database).expect("inspect migrated binding");

        let partial = BlobTestRoot::new("owner-binding-partial");
        drop(
            Store::open_for_mission(&partial.database, services.authority)
                .expect("partial binding base"),
        );
        {
            let database = Database::open(&partial.database).expect("raw partial database");
            let write = database.begin_write().expect("partial binding write");
            write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata")
                .remove(DEPOT_OWNER_BINDING_3)
                .expect("remove one binding field");
            write.commit().expect("commit partial binding");
        }
        assert!(Store::inspect_existing(&partial.database).is_err());
        assert!(Store::open_for_mission(&partial.database, services.authority).is_err());

        let copied = empty.path.join("copied.redb");
        std::fs::copy(&empty.database, &copied).expect("copy canonical empty database");
        assert!(Store::inspect_existing(&copied).is_err());
        assert!(Store::open_for_mission(&copied, services.authority).is_err());
        Store::inspect_existing(&empty.database).expect("original binding remains valid");

        let rooted = BlobTestRoot::new("owner-binding-empty-root-present");
        let rooted_store = Store::open_for_mission(&rooted.database, services.authority)
            .expect("empty rooted binding store");
        drop(
            rooted_store
                .blob_depot()
                .expect("bind empty physical depot"),
        );
        drop(rooted_store);
        {
            let database = Database::open(&rooted.database).expect("raw rooted database");
            let write = database.begin_write().expect("remove rooted binding");
            let mut depot = write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata");
            for field in depot_owner_binding_fields() {
                depot.remove(field).expect("remove rooted binding field");
            }
            drop(depot);
            write.commit().expect("commit rooted missing binding");
        }
        let database_before = blob_database_digest(&rooted.database);
        let depot_before = depot_file_snapshot(&rooted.depot());
        assert!(Store::inspect_existing(&rooted.database).is_err());
        assert!(Store::open_for_mission(&rooted.database, services.authority).is_err());
        assert_eq!(blob_database_digest(&rooted.database), database_before);
        assert_eq!(depot_file_snapshot(&rooted.depot()), depot_before);
    }

    #[test]
    fn depot_owner_token_migration_is_rootless_empty_and_all_or_nothing() {
        let services = blob_services(0xbb);
        let remove_all_owner_fields = |path: &Path| {
            let database = Database::open(path).expect("raw owner-token database");
            let write = database.begin_write().expect("owner-token removal write");
            let mut depot = write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata");
            for field in depot_owner_token_fields() {
                depot.remove(field).expect("remove owner-token field");
            }
            for field in depot_owner_binding_fields() {
                depot.remove(field).expect("remove owner-binding field");
            }
            drop(depot);
            write.commit().expect("commit owner-token removal");
        };

        let migratable = BlobTestRoot::new("owner-token-empty-migration");
        drop(
            Store::open_for_mission(&migratable.database, services.authority)
                .expect("owner-token migration base"),
        );
        remove_all_owner_fields(&migratable.database);
        assert!(Store::inspect_existing(&migratable.database).is_err());
        drop(
            Store::open_for_mission(&migratable.database, services.authority)
                .expect("migrate exact empty pre-token schema"),
        );
        Store::inspect_existing(&migratable.database).expect("inspect migrated owner token");
        {
            let database = redb::Builder::new()
                .open_read_only(&migratable.database)
                .expect("read migrated owner token");
            let read = database.begin_read().expect("owner-token read transaction");
            assert_ne!(
                depot::depot_owner_token_read(&read).expect("canonical migrated owner token"),
                [0; 32]
            );
            let depot = read
                .open_table(BLOB_DEPOT_METADATA)
                .expect("migrated depot metadata");
            for field in depot_owner_binding_fields() {
                assert!(
                    depot
                        .get(field)
                        .expect("migrated owner binding read")
                        .is_some()
                );
            }
        }

        let partial = BlobTestRoot::new("owner-token-partial");
        drop(
            Store::open_for_mission(&partial.database, services.authority)
                .expect("partial owner-token base"),
        );
        {
            let database = Database::open(&partial.database).expect("raw partial-token database");
            let write = database.begin_write().expect("partial-token removal write");
            write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata")
                .remove(DEPOT_OWNER_TOKEN_3)
                .expect("remove one owner-token field");
            write.commit().expect("commit partial owner token");
        }
        let partial_before = blob_database_digest(&partial.database);
        assert!(Store::inspect_existing(&partial.database).is_err());
        assert!(Store::open_for_mission(&partial.database, services.authority).is_err());
        assert_eq!(blob_database_digest(&partial.database), partial_before);
        assert!(!partial.depot().exists());

        for (name, table) in [
            ("publication", BLOB_PUBLICATIONS),
            ("import", BLOB_IMPORTS),
            ("chunk", BLOB_CHUNKS),
        ] {
            let populated = BlobTestRoot::new(&format!("owner-token-populated-{name}"));
            drop(
                Store::open_for_mission(&populated.database, services.authority)
                    .expect("populated owner-token base"),
            );
            remove_all_owner_fields(&populated.database);
            {
                let database = Database::open(&populated.database)
                    .expect("raw populated owner-token database");
                let write = database.begin_write().expect("populated owner-token write");
                write
                    .open_table(table)
                    .expect("Blob row table")
                    .insert(b"unattributed".as_slice(), b"row".as_slice())
                    .expect("insert unattributed Blob row");
                write.commit().expect("commit unattributed Blob row");
            }
            let before = blob_database_digest(&populated.database);
            assert!(Store::inspect_existing(&populated.database).is_err());
            assert!(Store::open_for_mission(&populated.database, services.authority).is_err());
            assert_eq!(blob_database_digest(&populated.database), before);
            assert!(!populated.depot().exists());
        }

        let counted = BlobTestRoot::new("owner-token-nonzero-counter");
        drop(
            Store::open_for_mission(&counted.database, services.authority)
                .expect("counter owner-token base"),
        );
        remove_all_owner_fields(&counted.database);
        {
            let database = Database::open(&counted.database).expect("raw counter database");
            let write = database.begin_write().expect("counter corruption write");
            write
                .open_table(METADATA)
                .expect("global metadata")
                .insert(BLOB_ITEM_COUNT, 1)
                .expect("insert nonzero Blob counter");
            write.commit().expect("commit nonzero Blob counter");
        }
        let counted_before = blob_database_digest(&counted.database);
        assert!(Store::inspect_existing(&counted.database).is_err());
        assert!(Store::open_for_mission(&counted.database, services.authority).is_err());
        assert_eq!(blob_database_digest(&counted.database), counted_before);
        assert!(!counted.depot().exists());

        let rooted = BlobTestRoot::new("owner-token-root-present");
        let rooted_store = Store::open_for_mission(&rooted.database, services.authority)
            .expect("rooted owner-token base");
        drop(
            rooted_store
                .blob_depot()
                .expect("create attributed depot root"),
        );
        drop(rooted_store);
        remove_all_owner_fields(&rooted.database);
        let rooted_database_before = blob_database_digest(&rooted.database);
        let rooted_depot_before = depot_file_snapshot(&rooted.depot());
        assert!(Store::inspect_existing(&rooted.database).is_err());
        assert!(Store::open_for_mission(&rooted.database, services.authority).is_err());
        assert_eq!(
            blob_database_digest(&rooted.database),
            rooted_database_before
        );
        assert_eq!(depot_file_snapshot(&rooted.depot()), rooted_depot_before);
    }

    #[test]
    fn populated_owner_marker_or_root_loss_never_recreates_or_repairs() {
        for remove_root in [false, true] {
            let root = BlobTestRoot::new(if remove_root {
                "populated-root-loss"
            } else {
                "populated-marker-loss"
            });
            let mut services = blob_services(if remove_root { 0xb7 } else { 0xb8 });
            let plaintext = b"owner loss must not repair".to_vec();
            let prepared = prepared_blob(&plaintext);
            let store =
                Store::open_for_mission(&root.database, services.authority).expect("owner store");
            publish_blob(
                &store,
                &mut services,
                &prepared,
                &plaintext,
                1,
                b"owner-loss-publication",
            );
            let stats = store.blob_stats().expect("owner loss stats");
            drop(store);
            if remove_root {
                std::fs::remove_dir_all(root.depot()).expect("remove populated depot root");
            } else {
                std::fs::remove_file(root.depot().join(".aster-store-owner-v1"))
                    .expect("remove populated owner marker");
            }
            let database_before = blob_database_digest(&root.database);
            let depot_before = depot_file_snapshot(&root.depot());
            assert!(Store::inspect_existing(&root.database).is_err());
            assert!(Store::open_for_mission(&root.database, services.authority).is_err());
            assert_eq!(blob_database_digest(&root.database), database_before);
            assert_eq!(depot_file_snapshot(&root.depot()), depot_before);
            assert_eq!(stats.publications, 1);
        }

        let populated = BlobTestRoot::new("populated-prebinding-rejected");
        let mut populated_services = blob_services(0xb9);
        let plaintext = b"populated binding removal".to_vec();
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&populated.database, populated_services.authority)
            .expect("populated binding store");
        publish_blob(
            &store,
            &mut populated_services,
            &prepared,
            &plaintext,
            1,
            b"populated-binding-publication",
        );
        drop(store);
        {
            let database = Database::open(&populated.database).expect("raw populated binding");
            let write = database.begin_write().expect("remove populated binding");
            let mut depot = write
                .open_table(BLOB_DEPOT_METADATA)
                .expect("depot metadata");
            for field in depot_owner_binding_fields() {
                depot.remove(field).expect("remove populated binding field");
            }
            drop(depot);
            write.commit().expect("commit populated missing binding");
        }
        let files_before = depot_file_snapshot(&populated.depot());
        assert!(Store::inspect_existing(&populated.database).is_err());
        assert!(
            Store::open_for_mission(&populated.database, populated_services.authority).is_err()
        );
        assert_eq!(depot_file_snapshot(&populated.depot()), files_before);
    }

    #[test]
    fn structural_audit_rejects_content_publication_cap_plus_one_without_repair() {
        let root = BlobTestRoot::new("content-cap-corruption");
        let mut services = blob_services(0xba);
        let plaintext = b"one physical variant, too many synthetic publications".to_vec();
        let prepared = prepared_blob(&plaintext);
        let store =
            Store::open_for_mission(&root.database, services.authority).expect("content cap store");
        let (stored, _, _) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"content-cap-base",
        );
        let base_stats = store.blob_stats().expect("base content stats");
        drop(store);

        let database = Database::open(&root.database).expect("raw content-cap database");
        let write = database
            .begin_write()
            .expect("content-cap corruption write");
        let base = write
            .open_table(BLOB_PUBLICATIONS)
            .expect("publications")
            .get(stored.transfer_id.as_bytes().as_slice())
            .expect("base metadata read")
            .map(|value| decode_blob_metadata(value.value()))
            .transpose()
            .expect("decode base metadata")
            .expect("base metadata");
        let mut total_bytes = base_stats.total_sealed_bytes;
        for counter in
            2..=u64::try_from(MAX_BLOB_PUBLICATIONS_PER_CONTENT + 1).expect("content cap counter")
        {
            let sealed = format!("synthetic-over-cap-source-{counter}").into_bytes();
            let transfer_id = BlobTransferId::new(Sha256::digest(&sealed).into());
            let semantic_id = BlobSemanticId::new(
                Sha256::digest(format!("synthetic-over-cap-semantic-{counter}")).into(),
            );
            let mut metadata = base.clone();
            metadata.transfer_id = transfer_id;
            metadata.semantic_id = semantic_id;
            metadata.header.stamp.dot.counter = counter;
            metadata.header.stamp.context = VersionVector::default();
            let encoded = encode_blob_metadata(metadata).expect("encode synthetic metadata");
            write
                .open_table(BLOB_PUBLICATIONS)
                .expect("publications")
                .insert(transfer_id.as_bytes().as_slice(), encoded.as_slice())
                .expect("insert synthetic metadata");
            write
                .open_table(BLOB_BYTES)
                .expect("source bytes")
                .insert(transfer_id.as_bytes().as_slice(), sealed.as_slice())
                .expect("insert synthetic source");
            write
                .open_table(BLOB_ACCEPTANCE_MARKERS)
                .expect("markers")
                .insert(transfer_id.as_bytes().as_slice(), counter)
                .expect("insert synthetic marker");
            write
                .open_table(BLOB_SEMANTIC_ITEMS)
                .expect("semantic index")
                .insert(
                    semantic_id.as_bytes().as_slice(),
                    transfer_id.as_bytes().as_slice(),
                )
                .expect("insert synthetic semantic");
            let content_key = blob_content_key(
                &base.header.topic,
                &base.header.scope,
                base.blob_id,
                semantic_id,
            )
            .expect("synthetic content key");
            write
                .open_table(BLOB_CONTENT_INDEX)
                .expect("content index")
                .insert(content_key.as_slice(), transfer_id.as_bytes().as_slice())
                .expect("insert synthetic content");
            let dot_key = accepted_dot_key(Dot {
                publisher: base.header.stamp.dot.publisher,
                counter,
            });
            write
                .open_table(ACCEPTED_DOTS)
                .expect("accepted dots")
                .insert(dot_key.as_slice(), semantic_id.as_bytes().as_slice())
                .expect("insert synthetic dot");
            total_bytes = total_bytes
                .checked_add(u64::try_from(sealed.len()).expect("synthetic source length"))
                .expect("synthetic byte accounting");
        }
        let over_cap = u64::try_from(MAX_BLOB_PUBLICATIONS_PER_CONTENT + 1)
            .expect("over-cap publication count");
        write
            .open_table(PUBLISHER_HIGH_WATER)
            .expect("publisher high water")
            .insert(base.header.stamp.dot.publisher.as_slice(), over_cap)
            .expect("update publisher high water");
        let frontier_key = causal_frontier_key(
            &base.header.topic,
            &base.header.scope,
            base.header.stamp.dot.publisher,
        )
        .expect("frontier key");
        write
            .open_table(CAUSAL_FRONTIER)
            .expect("causal frontier")
            .insert(frontier_key.as_slice(), over_cap)
            .expect("update frontier");
        {
            let mut metadata = write.open_table(METADATA).expect("global metadata");
            metadata
                .insert(BLOB_ITEM_COUNT, over_cap)
                .expect("update Blob count");
            metadata
                .insert(BLOB_TOTAL_BYTES, total_bytes)
                .expect("update Blob bytes");
            metadata
                .insert(LAST_BLOB_ACCEPTANCE_MARKER, over_cap)
                .expect("update Blob marker");
        }
        write.commit().expect("commit over-cap corruption");
        drop(database);

        let database_before = blob_database_digest(&root.database);
        assert!(matches!(
            Store::inspect_existing(&root.database),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob content publication count exceeds its durable safety cap"
            )))
        ));
        assert!(matches!(
            Store::open_for_mission(&root.database, services.authority),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(
                "Blob content publication count exceeds its durable safety cap"
            )))
        ));
        assert_eq!(blob_database_digest(&root.database), database_before);
    }

    #[test]
    fn stale_future_epoch_and_revocation_reject_before_operation_replay() {
        let root = BlobTestRoot::new("policy-before-replay");
        let mut services = blob_services(0x82);
        let plaintext = vec![0x82; 1_024];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let (_stored, operation, intent) = publish_blob(
            &store,
            &mut services,
            &prepared,
            &plaintext,
            1,
            b"policy-operation",
        );
        let stale = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
        let current = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 2);
        let future = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 3);
        for proof in [&stale, &current, &future] {
            proof
                .blob
                .verify_exact_manifest(&proof.manifest_bytes)
                .expect("proof retains exact manifest bytes");
        }
        let request = BlobOperationRequest::new(&operation, &intent);

        let effect_id = ControlTransferId::new([0x82; 32]);
        {
            let write = store.database.begin_write().expect("epoch write");
            let encoded = encode_scope_epoch_index(2, effect_id);
            write
                .open_table(CONTROL_SCOPE_EPOCHS)
                .expect("scope epochs")
                .insert(blob_scope().as_str(), encoded.as_slice())
                .expect("activate epoch two");
            write.commit().expect("commit epoch two");
        }
        assert!(matches!(
            store.commit_reserved_blob_once_with_policy(
                &stale.policy,
                &request,
                &stale.reservation,
                &stale.blob,
                &stale.sealed,
                &stale.completion,
            ),
            Err(StoreError::Blob(BlobStoreError::KeyEpochStale {
                current: 2,
                received: 1,
            }))
        ));
        assert!(matches!(
            store.commit_reserved_blob_once_with_policy(
                &future.policy,
                &request,
                &future.reservation,
                &future.blob,
                &future.sealed,
                &future.completion,
            ),
            Err(StoreError::Blob(BlobStoreError::KeyEpochNotActive {
                current: 2,
                received: 3,
            }))
        ));

        {
            let write = store.database.begin_write().expect("revocation write");
            let encoded = encode_revocation_index(services.authority, 1, effect_id);
            write
                .open_table(CONTROL_REVOCATIONS)
                .expect("revocations")
                .insert(services.publisher.identity().as_slice(), encoded.as_slice())
                .expect("revoke publisher");
            write.commit().expect("commit revocation");
        }
        assert!(matches!(
            store.commit_reserved_blob_once_with_policy(
                &current.policy,
                &request,
                &current.reservation,
                &current.blob,
                &current.sealed,
                &current.completion,
            ),
            Err(StoreError::Blob(BlobStoreError::PublisherRevoked(publisher)))
                if publisher == services.publisher.identity()
        ));
        assert_eq!(
            store
                .blob_stats()
                .expect("policy rejection stats")
                .publications,
            1
        );
    }

    #[test]
    fn import_profile_corruption_fails_read_and_write_audit_without_repair() {
        let cases = [
            ("oversized-media", Some(256), None, None),
            ("oversized-schema", None, Some(1_025), None),
            ("noncanonical-count", None, None, Some(2)),
        ];
        for (index, (label, media_len, schema_len, chunk_count)) in cases.into_iter().enumerate() {
            let root = BlobTestRoot::new(label);
            let mut services = blob_services(0x90 + u8::try_from(index).expect("case index"));
            let plaintext = vec![0x90; 777];
            let prepared = prepared_blob(&plaintext);
            let store =
                Store::open_for_mission(&root.database, services.authority).expect("case store");
            let (stored, _, _) = publish_blob(
                &store,
                &mut services,
                &prepared,
                &plaintext,
                1,
                label.as_bytes(),
            );
            let chunk_path = root.chunk_path(stored.variant_id, 0);
            let chunk_before = std::fs::read(&chunk_path).expect("marked chunk before corruption");
            drop(store);

            let database = Database::open(&root.database).expect("corruption database");
            let write = database.begin_write().expect("corruption write");
            depot::corrupt_import_profile_for_test(
                &write,
                stored.variant_id,
                media_len,
                schema_len,
                chunk_count,
            )
            .expect("corrupt import profile");
            write.commit().expect("commit import corruption");
            drop(database);

            let error = Store::inspect_existing(&root.database)
                .expect_err("read-only audit rejects corrupt import profile");
            assert_blob_schema_invariant(&error);
            match Store::open_for_mission(&root.database, services.authority) {
                Err(error) => assert_blob_schema_invariant(&error),
                Ok(_) => panic!("writable reopen rejects corrupt import profile"),
            }
            assert_eq!(
                std::fs::read(&chunk_path).expect("marked chunk after rejected opens"),
                chunk_before,
                "profile rejection must not repair or rewrite the marked artifact"
            );
        }
    }

    #[test]
    fn incomplete_finalize_and_wrong_last_record_length_are_rejected_without_repair() {
        let root = BlobTestRoot::new("incomplete-finalize-last-length");
        let services = blob_services(0x94);
        let plaintext = vec![0x94; SELECTED_BLOB_CHUNK_SIZE as usize + 37];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let manifest = {
            let depot = store.blob_depot().expect("depot");
            let mut service = services
                .publisher
                .blob_service_with_store(&blob_scope(), &blob_topic(), 1, depot)
                .expect("Blob service");
            service
                .install_prepared(&prepared)
                .expect("install prepared Blob")
        };
        let variant = BlobVariantId::for_content(
            manifest.id(),
            manifest.content_group(),
            manifest.content_epoch(),
        );
        {
            let mut depot = store.blob_depot().expect("active depot");
            CoreBlobStore::begin_blob(&mut depot, &manifest).expect("resume import");
            let finalize_error =
                CoreBlobStore::finalize_blob(&mut depot, manifest.id(), [0x94; 32])
                    .expect_err("incomplete import cannot finalize");
            assert_depot_integrity(&finalize_error);
            assert_eq!(
                CoreBlobStore::finalized_manifest_digest(&mut depot, manifest.id())
                    .expect("read finalization state"),
                None,
                "rejected finalization must not write its arbitrary digest"
            );

            let last = manifest.chunk_count() - 1;
            let plaintext_digest = CoreBlobStore::plaintext_digest(&mut depot, manifest.id(), last)
                .expect("read staged digest")
                .expect("last digest is staged");
            let expected =
                aster_mesh::BlobChunkRecord::from_parts(plaintext_digest, [0x49; 32], 37, 53)
                    .expect("correct last-record lengths");
            CoreBlobStore::put_expected_chunk_record(&mut depot, manifest.id(), last, expected)
                .expect("stage correct last record");
        }
        drop(store);

        let database = Database::open(&root.database).expect("corruption database");
        let write = database.begin_write().expect("corruption write");
        depot::corrupt_expected_chunk_lengths_for_test(
            &write,
            variant,
            manifest.chunk_count() - 1,
            SELECTED_BLOB_CHUNK_SIZE,
            SELECTED_BLOB_CHUNK_SIZE + 16,
        )
        .expect("corrupt last-record lengths");
        write.commit().expect("commit chunk-record corruption");
        let read = database.begin_read().expect("corrupt row read");
        let key = depot::test_chunk_key(variant, manifest.chunk_count() - 1);
        let row_before = read
            .open_table(BLOB_CHUNKS)
            .expect("Blob chunks")
            .get(key.as_slice())
            .expect("read corrupt chunk")
            .expect("corrupt chunk exists")
            .value()
            .to_vec();
        drop(read);
        drop(database);

        let error = Store::inspect_existing(&root.database)
            .expect_err("read-only audit rejects wrong last-record length");
        assert_blob_schema_invariant(&error);
        match Store::open_for_mission(&root.database, services.authority) {
            Err(error) => assert_blob_schema_invariant(&error),
            Ok(_) => panic!("writable reopen rejects wrong last-record length"),
        }
        let database = Database::open(&root.database).expect("post-rejection database");
        let read = database.begin_read().expect("post-rejection read");
        let row_after = read
            .open_table(BLOB_CHUNKS)
            .expect("Blob chunks")
            .get(key.as_slice())
            .expect("read corrupt chunk after rejection")
            .expect("corrupt chunk remains")
            .value()
            .to_vec();
        assert_eq!(
            row_after, row_before,
            "audit rejection must not repair metadata"
        );
    }

    #[test]
    fn depot_read_round_trips_with_one_core_bounded_chunk_buffer() {
        let root = BlobTestRoot::new("bounded-depot-read");
        let mut services = blob_services(0x95);
        let plaintext = vec![0x95; SELECTED_BLOB_CHUNK_SIZE as usize + 37];
        let prepared = prepared_blob(&plaintext);
        let store = Store::open_for_mission(&root.database, services.authority).expect("store");
        let proof = prepare_blob_proof(&store, &mut services, &prepared, &plaintext, 1);
        let depot = store.blob_depot().expect("read depot");
        let mut service = services
            .reader
            .blob_service_with_store(&blob_scope(), &blob_topic(), 1, depot)
            .expect("reader service");
        service
            .install_verified_manifest(&proof.blob, &proof.manifest_bytes)
            .expect("install exact verified manifest");
        let mut reader = service
            .reader_for_verified(&proof.blob)
            .expect("verified reader");
        let mut output = Vec::new();
        let stats = reader.stream_into(&mut output).expect("stream Blob");
        assert_eq!(output, plaintext);
        assert_eq!(stats.plaintext_bytes, plaintext.len() as u64);
        assert_eq!(stats.verified_chunks, 2);
        assert!(
            stats.peak_working_buffer_bytes <= SELECTED_BLOB_CHUNK_SIZE as usize + 16,
            "depot adapter must read its fixed header on the stack and ciphertext directly into the core-owned chunk buffer"
        );
    }

    #[test]
    fn physical_depot_byte_chunk_and_variant_caps_are_durable_and_atomic() {
        let byte_root = BlobTestRoot::new("depot-byte-cap");
        let byte_services = blob_services(0x84);
        let byte_plaintext = vec![0x84; 512];
        let byte_prepared = prepared_blob(&byte_plaintext);
        let byte_store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &byte_root.database,
            StoreLimits::default(),
            BlobDepotLimits::new(1, 10, 10).expect("byte limits"),
            byte_services.authority,
        )
        .expect("byte-cap store");
        assert!(
            finish_variant(
                &byte_store,
                &byte_services.publisher,
                &byte_prepared,
                &byte_plaintext,
                1,
            )
            .is_err()
        );
        let byte_stats = byte_store.blob_stats().expect("byte-cap stats");
        assert_eq!(byte_stats.variants, 1);
        assert_eq!(byte_stats.committed_chunks, 0);
        assert_eq!(byte_stats.committed_file_bytes, 0);
        drop(byte_store);
        let byte_reopen = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &byte_root.database,
            StoreLimits::default(),
            BlobDepotLimits::new(1, 10, 10).expect("byte limits"),
            byte_services.authority,
        )
        .expect("byte-cap reopen");
        assert_eq!(
            byte_reopen.blob_stats().expect("reopened byte stats"),
            byte_stats
        );

        let chunk_root = BlobTestRoot::new("depot-chunk-cap");
        let chunk_services = blob_services(0x85);
        let chunk_plaintext = vec![0x85; SELECTED_BLOB_CHUNK_SIZE as usize + 1];
        let chunk_prepared = prepared_blob(&chunk_plaintext);
        let chunk_store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &chunk_root.database,
            StoreLimits::default(),
            BlobDepotLimits::new(u64::MAX, 1, 10).expect("chunk limits"),
            chunk_services.authority,
        )
        .expect("chunk-cap store");
        assert!(
            finish_variant(
                &chunk_store,
                &chunk_services.publisher,
                &chunk_prepared,
                &chunk_plaintext,
                1,
            )
            .is_err()
        );
        let chunk_stats = chunk_store.blob_stats().expect("chunk-cap stats");
        assert_eq!(chunk_stats.variants, 1);
        assert_eq!(chunk_stats.committed_chunks, 0);
        assert_eq!(chunk_stats.committed_file_bytes, 0);
        drop(chunk_store);
        let chunk_reopen = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &chunk_root.database,
            StoreLimits::default(),
            BlobDepotLimits::new(u64::MAX, 1, 10).expect("chunk limits"),
            chunk_services.authority,
        )
        .expect("chunk-cap reopen");
        assert_eq!(
            chunk_reopen.blob_stats().expect("reopened chunk stats"),
            chunk_stats
        );

        let variant_root = BlobTestRoot::new("depot-variant-cap");
        let variant_services = blob_services(0x86);
        let variant_plaintext = vec![0x86; 1_024];
        let variant_prepared = prepared_blob(&variant_plaintext);
        let variant_store = Store::open_with_limits_and_blob_depot_limits_for_mission(
            &variant_root.database,
            StoreLimits::default(),
            BlobDepotLimits::new(u64::MAX, 10, 1).expect("variant limits"),
            variant_services.authority,
        )
        .expect("variant-cap store");
        finish_variant(
            &variant_store,
            &variant_services.publisher,
            &variant_prepared,
            &variant_plaintext,
            1,
        )
        .expect("first variant");
        let before_second = variant_store.blob_stats().expect("first variant stats");
        assert!(
            finish_variant(
                &variant_store,
                &variant_services.publisher,
                &variant_prepared,
                &variant_plaintext,
                2,
            )
            .is_err()
        );
        assert_eq!(
            variant_store.blob_stats().expect("variant-cap stats"),
            before_second
        );
    }
}
