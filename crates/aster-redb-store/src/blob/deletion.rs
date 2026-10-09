use std::collections::{BTreeMap, BTreeSet};

use aster_mesh::{BlobId, CustodySample};
use redb::{
    MultimapTableHandle, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
};

use super::{BlobStoreError, BlobVariantId, MAX_SELECTED_BLOB_CHUNKS};
use crate::StoreError;
use crate::custody::{LowerBoundAgeCheckpoint, LowerBoundContinuity, project_lower_bound_age};

pub(crate) const BLOB_DELETION_METADATA: TableDefinition<&str, u64> =
    TableDefinition::new("aster.blob-deletion-metadata.v1");
pub(crate) const BLOB_DELETION_MANIFESTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-deletion-manifests.v1");
pub(crate) const BLOB_DELETION_CHUNKS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-deletion-chunks.v1");
pub(crate) const BLOB_DELETION_CONTINUITY: TableDefinition<u8, &[u8]> =
    TableDefinition::new("aster.blob-deletion-continuity.v1");

pub(crate) const BLOB_DELETION_SCHEMA_VERSION_FIELD: &str = "schema_version";
pub(crate) const BLOB_DELETION_MAINTENANCE_TURN: &str = "maintenance_turn";
pub(crate) const BLOB_DELETION_MANIFEST_ROWS: &str = "manifest_rows";
pub(crate) const BLOB_DELETION_MANIFEST_BYTES: &str = "manifest_bytes";
pub(crate) const BLOB_DELETION_CHUNK_ROWS: &str = "chunk_rows";
pub(crate) const BLOB_DELETION_CHUNK_BYTES: &str = "chunk_bytes";
pub(crate) const BLOB_DELETION_QUEUED_CHUNKS: &str = "queued_chunks";
pub(crate) const BLOB_DELETION_DELETED_CHUNKS: &str = "deleted_chunks";
pub(crate) const BLOB_DELETION_CHARGED_VARIANTS: &str = "charged_variants";
pub(crate) const BLOB_DELETION_CHARGED_FILES: &str = "charged_files";
pub(crate) const BLOB_DELETION_CHARGED_RESERVED_BYTES: &str = "charged_reserved_bytes";
pub(crate) const BLOB_DELETION_CHARGED_COMMITTED_BYTES: &str = "charged_committed_bytes";
pub(crate) const BLOB_DELETION_SCHEMA_VERSION: u64 = 1;

const DELETION_METADATA_FIELDS: [&str; 12] = [
    BLOB_DELETION_SCHEMA_VERSION_FIELD,
    BLOB_DELETION_MAINTENANCE_TURN,
    BLOB_DELETION_MANIFEST_ROWS,
    BLOB_DELETION_MANIFEST_BYTES,
    BLOB_DELETION_CHUNK_ROWS,
    BLOB_DELETION_CHUNK_BYTES,
    BLOB_DELETION_QUEUED_CHUNKS,
    BLOB_DELETION_DELETED_CHUNKS,
    BLOB_DELETION_CHARGED_VARIANTS,
    BLOB_DELETION_CHARGED_FILES,
    BLOB_DELETION_CHARGED_RESERVED_BYTES,
    BLOB_DELETION_CHARGED_COMMITTED_BYTES,
];

const MANIFEST_VERSION: u8 = 1;
const CHUNK_VERSION: u8 = 1;
const CONTINUITY_VERSION: u8 = 1;
const CONTINUITY_KEY: u8 = 0;
const MAX_LINEAGE_FENCE_EVIDENCE_BYTES: usize = 256;
const MAX_IMPORT_EVIDENCE_BYTES: usize = 1024 * 1024;
const MAX_CHUNK_EVIDENCE_BYTES: usize = 256;

#[cfg(test)]
const MANIFEST_PHASE_OFFSET: usize = 1;
#[cfg(test)]
const MANIFEST_RESERVED_OFFSET: usize = 2;
#[cfg(test)]
const MANIFEST_CHUNK_COUNT_OFFSET: usize = 208;
#[cfg(test)]
const MANIFEST_QUEUED_COUNT_OFFSET: usize = 216;
#[cfg(test)]
const MANIFEST_FAILURE_OFFSET: usize = 264;
const MANIFEST_FIXED_BYTES: usize = 330;
#[cfg(test)]
const CHUNK_STATE_OFFSET: usize = 1;
#[cfg(test)]
const CHUNK_RESERVED_OFFSET: usize = 2;
const CHUNK_FIXED_BYTES: usize = 32;

const PHASE_DELETING_CHUNKS: u8 = 1;
const PHASE_DIRECTORY_DELETE_PENDING: u8 = 2;
const CHUNK_DELETE_QUEUED: u8 = 1;
const CHUNK_DELETED_DURABLE: u8 = 2;

fn invariant(reason: &'static str) -> StoreError {
    StoreError::Blob(BlobStoreError::SchemaInvariant(reason))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobDeletionPhase {
    DeletingChunks,
    DirectoryDeletePending,
}

impl BlobDeletionPhase {
    #[allow(dead_code)]
    const fn encode(self) -> u8 {
        match self {
            Self::DeletingChunks => PHASE_DELETING_CHUNKS,
            Self::DirectoryDeletePending => PHASE_DIRECTORY_DELETE_PENDING,
        }
    }

    fn decode(value: u8) -> Result<Self, StoreError> {
        match value {
            PHASE_DELETING_CHUNKS => Ok(Self::DeletingChunks),
            PHASE_DIRECTORY_DELETE_PENDING => Ok(Self::DirectoryDeletePending),
            _ => Err(invariant("Blob deletion manifest phase is not canonical")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobDeletionChunkState {
    DeleteQueued,
    DeletedDurable,
}

impl BlobDeletionChunkState {
    #[allow(dead_code)]
    const fn encode(self) -> u8 {
        match self {
            Self::DeleteQueued => CHUNK_DELETE_QUEUED,
            Self::DeletedDurable => CHUNK_DELETED_DURABLE,
        }
    }

    fn decode(value: u8) -> Result<Self, StoreError> {
        match value {
            CHUNK_DELETE_QUEUED => Ok(Self::DeleteQueued),
            CHUNK_DELETED_DURABLE => Ok(Self::DeletedDurable),
            _ => Err(invariant("Blob deletion chunk state is not canonical")),
        }
    }
}

/// Sanitized durable failure class. No path or operating-system text enters
/// this record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BlobDeletionFailureCategory {
    VariantDirectoryAccess,
    ChunkUnlink,
    ChunkDirectorySync,
    VariantDirectoryRemove,
    DepotDirectorySync,
}

impl BlobDeletionFailureCategory {
    #[allow(dead_code)]
    const fn encode(self) -> u8 {
        match self {
            Self::VariantDirectoryAccess => 1,
            Self::ChunkUnlink => 2,
            Self::ChunkDirectorySync => 3,
            Self::VariantDirectoryRemove => 4,
            Self::DepotDirectorySync => 5,
        }
    }

    fn decode(value: u8) -> Result<Option<Self>, StoreError> {
        match value {
            0 => Ok(None),
            1 => Ok(Some(Self::VariantDirectoryAccess)),
            2 => Ok(Some(Self::ChunkUnlink)),
            3 => Ok(Some(Self::ChunkDirectorySync)),
            4 => Ok(Some(Self::VariantDirectoryRemove)),
            5 => Ok(Some(Self::DepotDirectorySync)),
            _ => Err(invariant("Blob deletion failure category is not canonical")),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BlobDeletionRetry {
    pub(crate) category: Option<BlobDeletionFailureCategory>,
    pub(crate) attempts: u32,
    pub(crate) next_retry_turn: u64,
}

impl BlobDeletionRetry {
    fn validate(self) -> Result<(), StoreError> {
        match self.category {
            None if self.attempts == 0 && self.next_retry_turn == 0 => Ok(()),
            Some(_) if self.attempts != 0 && self.next_retry_turn != 0 => Ok(()),
            _ => Err(invariant("Blob deletion retry state is not canonical")),
        }
    }

    /// Returns the next durable retry checkpoint using bounded exponential
    /// turn-based backoff. No wall-clock value enters deletion authority.
    #[allow(dead_code)]
    pub(crate) fn after_failure(
        self,
        current_turn: u64,
        category: BlobDeletionFailureCategory,
    ) -> Result<Self, StoreError> {
        let attempts = self
            .attempts
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let exponent = attempts.saturating_sub(1).min(6);
        let delay = 1u64
            .checked_shl(exponent)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        let next_retry_turn = current_turn
            .checked_add(delay)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        Ok(Self {
            category: Some(category),
            attempts,
            next_retry_turn,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlobDeletionAge {
    pub(crate) cumulative_age_ms: u64,
    pub(crate) checkpoint: Option<CustodySample>,
    pub(crate) continuity_generation: u64,
    pub(crate) continuity_lost: bool,
}

impl BlobDeletionAge {
    fn validate(self) -> Result<(), StoreError> {
        match self.checkpoint {
            None if self.continuity_generation == 0 => Ok(()),
            Some(_) if self.continuity_generation != 0 => Ok(()),
            _ => Err(invariant("Blob deletion age checkpoint is not canonical")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlobDeletionContinuity {
    pub(crate) generation: u64,
    pub(crate) last_sample: CustodySample,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BlobDeletionTotals {
    pub(crate) chunks: u64,
    pub(crate) queued: u64,
    pub(crate) deleted: u64,
    pub(crate) charged_variants: u64,
    pub(crate) charged_files: u64,
    pub(crate) charged_reserved_bytes: u64,
    pub(crate) charged_committed_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobDeletionChunk {
    pub(crate) index: u64,
    pub(crate) state: BlobDeletionChunkState,
    pub(crate) original_chunk: Vec<u8>,
    pub(crate) charged_reserved_bytes: u64,
    pub(crate) charged_committed_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlobDeletionManifest {
    pub(crate) variant_id: BlobVariantId,
    pub(crate) blob_id: BlobId,
    pub(crate) content_group: [u8; 32],
    pub(crate) epoch: u64,
    pub(crate) physical_lineage: [u8; 32],
    pub(crate) owner_binding: [u8; 32],
    pub(crate) lineage_fence: Vec<u8>,
    pub(crate) original_import: Vec<u8>,
    pub(crate) finalized_root: Option<[u8; 32]>,
    pub(crate) phase: BlobDeletionPhase,
    pub(crate) retry: BlobDeletionRetry,
    pub(crate) age: BlobDeletionAge,
    pub(crate) totals: BlobDeletionTotals,
    pub(crate) chunks: Vec<BlobDeletionChunk>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct BlobDeletionStats {
    pub(crate) manifests: u64,
    pub(crate) manifest_bytes: u64,
    pub(crate) chunks: u64,
    pub(crate) chunk_bytes: u64,
    pub(crate) queued_chunks: u64,
    pub(crate) deleted_chunks: u64,
    pub(crate) charged_variants: u64,
    pub(crate) charged_files: u64,
    pub(crate) charged_reserved_bytes: u64,
    pub(crate) charged_committed_bytes: u64,
    pub(crate) maintenance_turn: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct BlobDeletionAudit {
    pub(crate) manifests: BTreeMap<BlobVariantId, BlobDeletionManifest>,
    pub(crate) stats: BlobDeletionStats,
}

impl BlobDeletionManifest {
    fn validate(&self) -> Result<(), StoreError> {
        if self.epoch == 0
            || self.variant_id
                != BlobVariantId::for_content(self.blob_id, &self.content_group, self.epoch)
            || self.owner_binding == [0; 32]
            || self.lineage_fence.is_empty()
            || self.lineage_fence.len() > MAX_LINEAGE_FENCE_EVIDENCE_BYTES
            || self.original_import.is_empty()
            || self.original_import.len() > MAX_IMPORT_EVIDENCE_BYTES
        {
            return Err(invariant(
                "Blob deletion manifest identity is not canonical",
            ));
        }
        self.retry.validate()?;
        self.age.validate()?;
        if self.totals.chunks > MAX_SELECTED_BLOB_CHUNKS
            || self.totals.charged_variants != 1
            || self.totals.charged_files > self.totals.chunks
            || self.totals.charged_committed_bytes > self.totals.charged_reserved_bytes
            || u64::try_from(self.chunks.len()).ok() != Some(self.totals.chunks)
            || (self.finalized_root.is_some()
                && (self.totals.chunks == 0 || self.totals.charged_files != self.totals.chunks))
        {
            return Err(invariant("Blob deletion manifest totals are not canonical"));
        }
        let mut queued = 0u64;
        let mut deleted = 0u64;
        let mut charged_files = 0u64;
        let mut reserved_bytes = 0u64;
        let mut committed_bytes = 0u64;
        let mut previous_index = None;
        for chunk in &self.chunks {
            if previous_index.is_some_and(|previous| previous >= chunk.index)
                || chunk.original_chunk.is_empty()
                || chunk.original_chunk.len() > MAX_CHUNK_EVIDENCE_BYTES
                || chunk.charged_committed_bytes > chunk.charged_reserved_bytes
            {
                return Err(invariant("Blob deletion chunk is not canonical"));
            }
            previous_index = Some(chunk.index);
            match chunk.state {
                BlobDeletionChunkState::DeleteQueued => {
                    queued = queued
                        .checked_add(1)
                        .ok_or(StoreError::ItemCountAccountingOverflow)?;
                }
                BlobDeletionChunkState::DeletedDurable => {
                    deleted = deleted
                        .checked_add(1)
                        .ok_or(StoreError::ItemCountAccountingOverflow)?;
                }
            }
            charged_files = charged_files
                .checked_add(u64::from(chunk.charged_committed_bytes != 0))
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            reserved_bytes = reserved_bytes
                .checked_add(chunk.charged_reserved_bytes)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            committed_bytes = committed_bytes
                .checked_add(chunk.charged_committed_bytes)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        }
        if queued != self.totals.queued
            || deleted != self.totals.deleted
            || queued
                .checked_add(deleted)
                .ok_or(StoreError::ItemCountAccountingOverflow)?
                != self.totals.chunks
            || charged_files != self.totals.charged_files
            || reserved_bytes != self.totals.charged_reserved_bytes
            || committed_bytes != self.totals.charged_committed_bytes
            || (self.phase == BlobDeletionPhase::DirectoryDeletePending && queued != 0)
        {
            return Err(invariant(
                "Blob deletion phase and chunk totals do not agree",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct BlobDeletionManifestHeader {
    variant_id: BlobVariantId,
    blob_id: BlobId,
    content_group: [u8; 32],
    epoch: u64,
    physical_lineage: [u8; 32],
    owner_binding: [u8; 32],
    lineage_fence: Vec<u8>,
    original_import: Vec<u8>,
    finalized_root: Option<[u8; 32]>,
    phase: BlobDeletionPhase,
    retry: BlobDeletionRetry,
    age: BlobDeletionAge,
    totals: BlobDeletionTotals,
}

#[allow(dead_code)]
fn encode_manifest_record(manifest: &BlobDeletionManifest) -> Result<Vec<u8>, StoreError> {
    manifest.validate()?;
    let lineage_len = u16::try_from(manifest.lineage_fence.len())
        .map_err(|_| invariant("Blob deletion lineage evidence exceeds its bound"))?;
    let import_len = u32::try_from(manifest.original_import.len())
        .map_err(|_| invariant("Blob deletion import evidence exceeds its bound"))?;
    let capacity = MANIFEST_FIXED_BYTES
        .checked_add(manifest.lineage_fence.len())
        .and_then(|value| value.checked_add(manifest.original_import.len()))
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    let mut output = Vec::with_capacity(capacity);
    output.push(MANIFEST_VERSION);
    output.push(manifest.phase.encode());
    output.extend_from_slice(&[0; 2]);
    output.extend_from_slice(manifest.variant_id.as_bytes());
    output.extend_from_slice(manifest.blob_id.as_bytes());
    output.extend_from_slice(&manifest.content_group);
    output.extend_from_slice(&manifest.epoch.to_be_bytes());
    output.extend_from_slice(&manifest.physical_lineage);
    output.extend_from_slice(&manifest.owner_binding);
    output.push(u8::from(manifest.finalized_root.is_some()));
    output.extend_from_slice(&[0; 3]);
    output.extend_from_slice(&manifest.finalized_root.unwrap_or([0; 32]));
    for value in [
        manifest.totals.chunks,
        manifest.totals.queued,
        manifest.totals.deleted,
        manifest.totals.charged_variants,
        manifest.totals.charged_files,
        manifest.totals.charged_reserved_bytes,
        manifest.totals.charged_committed_bytes,
    ] {
        output.extend_from_slice(&value.to_be_bytes());
    }
    output.push(
        manifest
            .retry
            .category
            .map_or(0, |category| category.encode()),
    );
    output.extend_from_slice(&[0; 3]);
    output.extend_from_slice(&manifest.retry.attempts.to_be_bytes());
    output.extend_from_slice(&manifest.retry.next_retry_turn.to_be_bytes());
    output.extend_from_slice(&manifest.age.cumulative_age_ms.to_be_bytes());
    output.push(u8::from(manifest.age.checkpoint.is_some()));
    output.push(u8::from(manifest.age.continuity_lost));
    output.extend_from_slice(&[0; 2]);
    output.extend_from_slice(&manifest.age.continuity_generation.to_be_bytes());
    if let Some(checkpoint) = manifest.age.checkpoint {
        output.extend_from_slice(&checkpoint.clock_id);
        output.extend_from_slice(&checkpoint.tick_ms.to_be_bytes());
    } else {
        output.extend_from_slice(&[0; 24]);
    }
    output.extend_from_slice(&lineage_len.to_be_bytes());
    output.extend_from_slice(&import_len.to_be_bytes());
    output.extend_from_slice(&manifest.lineage_fence);
    output.extend_from_slice(&manifest.original_import);
    debug_assert_eq!(output.len(), capacity);
    Ok(output)
}

#[allow(dead_code)]
fn encode_chunk_record(chunk: &BlobDeletionChunk) -> Result<Vec<u8>, StoreError> {
    if chunk.original_chunk.is_empty()
        || chunk.original_chunk.len() > MAX_CHUNK_EVIDENCE_BYTES
        || chunk.charged_committed_bytes > chunk.charged_reserved_bytes
    {
        return Err(invariant("Blob deletion chunk is not canonical"));
    }
    let evidence_len = u16::try_from(chunk.original_chunk.len())
        .map_err(|_| invariant("Blob deletion chunk evidence exceeds its bound"))?;
    let mut output = Vec::with_capacity(CHUNK_FIXED_BYTES + chunk.original_chunk.len());
    output.push(CHUNK_VERSION);
    output.push(chunk.state.encode());
    output.extend_from_slice(&[0; 2]);
    output.extend_from_slice(&chunk.index.to_be_bytes());
    output.extend_from_slice(&chunk.charged_reserved_bytes.to_be_bytes());
    output.extend_from_slice(&chunk.charged_committed_bytes.to_be_bytes());
    output.extend_from_slice(&evidence_len.to_be_bytes());
    output.extend_from_slice(&[0; 2]);
    output.extend_from_slice(&chunk.original_chunk);
    Ok(output)
}

struct SliceCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SliceCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        let output = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invariant("Blob deletion record is truncated"))?;
        self.offset = end;
        Ok(output)
    }

    fn u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, StoreError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| invariant("Blob deletion u16 is malformed"),
        )?))
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| invariant("Blob deletion u32 is malformed"),
        )?))
    }

    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| invariant("Blob deletion u64 is malformed"),
        )?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        self.take(N)?
            .try_into()
            .map_err(|_| invariant("Blob deletion fixed field is malformed"))
    }

    fn finish(self) -> Result<(), StoreError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(invariant("Blob deletion record has trailing bytes"))
        }
    }
}

fn decode_manifest_header(bytes: &[u8]) -> Result<BlobDeletionManifestHeader, StoreError> {
    if bytes.len() < MANIFEST_FIXED_BYTES {
        return Err(invariant("Blob deletion manifest is truncated"));
    }
    let mut cursor = SliceCursor::new(bytes);
    if cursor.u8()? != MANIFEST_VERSION {
        return Err(invariant(
            "Blob deletion manifest has an unknown encoding version",
        ));
    }
    let phase = BlobDeletionPhase::decode(cursor.u8()?)?;
    if cursor.take(2)? != [0; 2] {
        return Err(invariant(
            "Blob deletion manifest reserved bytes are nonzero",
        ));
    }
    let variant_id = BlobVariantId::from_bytes(cursor.array()?);
    let blob_id = BlobId::from_bytes(cursor.array()?);
    let content_group = cursor.array()?;
    let epoch = cursor.u64()?;
    let physical_lineage = cursor.array()?;
    let owner_binding = cursor.array()?;
    let finalized_root_present = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(invariant("Blob deletion root-presence flag is invalid")),
    };
    if cursor.take(3)? != [0; 3] {
        return Err(invariant("Blob deletion root reserved bytes are nonzero"));
    }
    let finalized_root_bytes = cursor.array()?;
    let finalized_root = if finalized_root_present {
        Some(finalized_root_bytes)
    } else {
        if finalized_root_bytes != [0; 32] {
            return Err(invariant(
                "Blob deletion absent root retains nonzero evidence",
            ));
        }
        None
    };
    let totals = BlobDeletionTotals {
        chunks: cursor.u64()?,
        queued: cursor.u64()?,
        deleted: cursor.u64()?,
        charged_variants: cursor.u64()?,
        charged_files: cursor.u64()?,
        charged_reserved_bytes: cursor.u64()?,
        charged_committed_bytes: cursor.u64()?,
    };
    if totals.chunks > MAX_SELECTED_BLOB_CHUNKS {
        return Err(invariant(
            "Blob deletion manifest chunk count exceeds its bound",
        ));
    }
    let category = BlobDeletionFailureCategory::decode(cursor.u8()?)?;
    if cursor.take(3)? != [0; 3] {
        return Err(invariant("Blob deletion retry reserved bytes are nonzero"));
    }
    let retry = BlobDeletionRetry {
        category,
        attempts: cursor.u32()?,
        next_retry_turn: cursor.u64()?,
    };
    retry.validate()?;
    let cumulative_age_ms = cursor.u64()?;
    let checkpoint_present = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(invariant("Blob deletion age checkpoint flag is invalid")),
    };
    let continuity_lost = match cursor.u8()? {
        0 => false,
        1 => true,
        _ => return Err(invariant("Blob deletion continuity-loss flag is invalid")),
    };
    if cursor.take(2)? != [0; 2] {
        return Err(invariant("Blob deletion age reserved bytes are nonzero"));
    }
    let continuity_generation = cursor.u64()?;
    let checkpoint_clock = cursor.array()?;
    let checkpoint_tick = cursor.u64()?;
    let checkpoint = if checkpoint_present {
        Some(CustodySample {
            clock_id: checkpoint_clock,
            tick_ms: checkpoint_tick,
        })
    } else {
        if checkpoint_clock != [0; 16] || checkpoint_tick != 0 {
            return Err(invariant(
                "Blob deletion absent checkpoint retains nonzero fields",
            ));
        }
        None
    };
    let age = BlobDeletionAge {
        cumulative_age_ms,
        checkpoint,
        continuity_generation,
        continuity_lost,
    };
    age.validate()?;
    let lineage_len = usize::from(cursor.u16()?);
    let import_len = usize::try_from(cursor.u32()?)
        .map_err(|_| invariant("Blob deletion import length cannot be represented"))?;
    if lineage_len == 0
        || lineage_len > MAX_LINEAGE_FENCE_EVIDENCE_BYTES
        || import_len == 0
        || import_len > MAX_IMPORT_EVIDENCE_BYTES
    {
        return Err(invariant(
            "Blob deletion embedded evidence exceeds its bound",
        ));
    }
    let remaining = bytes
        .len()
        .checked_sub(cursor.offset)
        .ok_or_else(|| invariant("Blob deletion manifest length is invalid"))?;
    if remaining
        != lineage_len
            .checked_add(import_len)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?
    {
        return Err(invariant(
            "Blob deletion embedded evidence length is not canonical",
        ));
    }
    let lineage_fence = cursor.take(lineage_len)?.to_vec();
    let original_import = cursor.take(import_len)?.to_vec();
    cursor.finish()?;
    Ok(BlobDeletionManifestHeader {
        variant_id,
        blob_id,
        content_group,
        epoch,
        physical_lineage,
        owner_binding,
        lineage_fence,
        original_import,
        finalized_root,
        phase,
        retry,
        age,
        totals,
    })
}

fn decode_chunk_record(bytes: &[u8]) -> Result<BlobDeletionChunk, StoreError> {
    if bytes.len() < CHUNK_FIXED_BYTES {
        return Err(invariant("Blob deletion chunk record is truncated"));
    }
    let mut cursor = SliceCursor::new(bytes);
    if cursor.u8()? != CHUNK_VERSION {
        return Err(invariant(
            "Blob deletion chunk has an unknown encoding version",
        ));
    }
    let state = BlobDeletionChunkState::decode(cursor.u8()?)?;
    if cursor.take(2)? != [0; 2] {
        return Err(invariant("Blob deletion chunk reserved bytes are nonzero"));
    }
    let index = cursor.u64()?;
    let charged_reserved_bytes = cursor.u64()?;
    let charged_committed_bytes = cursor.u64()?;
    let evidence_len = usize::from(cursor.u16()?);
    if cursor.take(2)? != [0; 2] {
        return Err(invariant(
            "Blob deletion chunk evidence reserved bytes are nonzero",
        ));
    }
    if evidence_len == 0 || evidence_len > MAX_CHUNK_EVIDENCE_BYTES {
        return Err(invariant("Blob deletion chunk evidence exceeds its bound"));
    }
    let original_chunk = cursor.take(evidence_len)?.to_vec();
    cursor.finish()?;
    let chunk = BlobDeletionChunk {
        index,
        state,
        original_chunk,
        charged_reserved_bytes,
        charged_committed_bytes,
    };
    if chunk.charged_committed_bytes > chunk.charged_reserved_bytes {
        return Err(invariant("Blob deletion chunk charge is not canonical"));
    }
    Ok(chunk)
}

#[cfg(test)]
fn decode_manifest_record(
    bytes: &[u8],
    encoded_chunks: &[Vec<u8>],
) -> Result<BlobDeletionManifest, StoreError> {
    let header = decode_manifest_header(bytes)?;
    if u64::try_from(encoded_chunks.len()).ok() != Some(header.totals.chunks) {
        return Err(invariant(
            "Blob deletion manifest chunk cardinality is incomplete",
        ));
    }
    let mut chunks = Vec::with_capacity(encoded_chunks.len());
    for encoded in encoded_chunks {
        chunks.push(decode_chunk_record(encoded)?);
    }
    let manifest = BlobDeletionManifest {
        variant_id: header.variant_id,
        blob_id: header.blob_id,
        content_group: header.content_group,
        epoch: header.epoch,
        physical_lineage: header.physical_lineage,
        owner_binding: header.owner_binding,
        lineage_fence: header.lineage_fence,
        original_import: header.original_import,
        finalized_root: header.finalized_root,
        phase: header.phase,
        retry: header.retry,
        age: header.age,
        totals: header.totals,
        chunks,
    };
    manifest.validate()?;
    Ok(manifest)
}

fn deletion_table_names() -> [&'static str; 4] {
    [
        BLOB_DELETION_METADATA.name(),
        BLOB_DELETION_MANIFESTS.name(),
        BLOB_DELETION_CHUNKS.name(),
        BLOB_DELETION_CONTINUITY.name(),
    ]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeletionSchemaState {
    Predecessor,
    Current,
}

fn deletion_schema_state(
    normal: &BTreeSet<String>,
    multimap: &BTreeSet<String>,
) -> Result<DeletionSchemaState, StoreError> {
    let names = deletion_table_names();
    if multimap.iter().any(|name| names.contains(&name.as_str())) {
        return Err(invariant("Blob deletion schema has the wrong table kind"));
    }
    let present = names.iter().filter(|name| normal.contains(**name)).count();
    match present {
        0 => Ok(DeletionSchemaState::Predecessor),
        count if count == names.len() => Ok(DeletionSchemaState::Current),
        _ => Err(invariant("Blob deletion schema group is incomplete")),
    }
}

fn deletion_schema_state_write(
    write: &redb::WriteTransaction,
) -> Result<DeletionSchemaState, StoreError> {
    deletion_schema_state(
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

fn deletion_schema_state_read(
    read: &redb::ReadTransaction,
) -> Result<DeletionSchemaState, StoreError> {
    deletion_schema_state(
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

pub(crate) fn require_blob_deletion_absent_write(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    if deletion_schema_state_write(write)? == DeletionSchemaState::Current {
        return Err(invariant(
            "Blob deletion authority exists without its base schema",
        ));
    }
    Ok(())
}

pub(crate) fn require_blob_deletion_absent_read(
    read: &redb::ReadTransaction,
) -> Result<(), StoreError> {
    if deletion_schema_state_read(read)? == DeletionSchemaState::Current {
        return Err(invariant(
            "Blob deletion authority exists without its base schema",
        ));
    }
    Ok(())
}

fn initialize_blob_deletion_schema(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let _ = write.open_table(BLOB_DELETION_MANIFESTS)?;
    let _ = write.open_table(BLOB_DELETION_CHUNKS)?;
    let _ = write.open_table(BLOB_DELETION_CONTINUITY)?;
    let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
    if metadata.len()? != 0 {
        return Err(invariant(
            "Blob deletion metadata exists during empty migration",
        ));
    }
    for (field, value) in DELETION_METADATA_FIELDS.into_iter().zip([
        BLOB_DELETION_SCHEMA_VERSION,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]) {
        metadata.insert(field, value)?;
    }
    Ok(())
}

/// Advances the durable sequence exactly once for a caller-owned bounded
/// maintenance turn. Later maintenance tasks use the returned value for
/// retry eligibility and never derive it from wall-clock time.
#[allow(dead_code)]
pub(crate) fn advance_blob_deletion_maintenance_turn(
    write: &redb::WriteTransaction,
) -> Result<u64, StoreError> {
    if deletion_schema_state_write(write)? != DeletionSchemaState::Current {
        return Err(invariant("Blob deletion schema is not current"));
    }
    let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
    if metadata.len()? != DELETION_METADATA_FIELDS.len() as u64
        || metadata
            .get(BLOB_DELETION_SCHEMA_VERSION_FIELD)?
            .map(|value| value.value())
            != Some(BLOB_DELETION_SCHEMA_VERSION)
    {
        return Err(invariant(
            "Blob deletion metadata is incomplete or has an unknown version",
        ));
    }
    let current = metadata
        .get(BLOB_DELETION_MAINTENANCE_TURN)?
        .ok_or_else(|| invariant("Blob deletion maintenance turn is missing"))?
        .value();
    let next = current
        .checked_add(1)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    metadata.insert(BLOB_DELETION_MAINTENANCE_TURN, next)?;
    Ok(next)
}

fn audit_metadata(
    metadata: &impl ReadableTable<&'static str, u64>,
    stats: BlobDeletionStats,
) -> Result<(), StoreError> {
    if metadata.len()? != DELETION_METADATA_FIELDS.len() as u64 {
        return Err(invariant("Blob deletion accounting metadata is incomplete"));
    }
    for (field, expected) in [
        (
            BLOB_DELETION_SCHEMA_VERSION_FIELD,
            BLOB_DELETION_SCHEMA_VERSION,
        ),
        (BLOB_DELETION_MAINTENANCE_TURN, stats.maintenance_turn),
        (BLOB_DELETION_MANIFEST_ROWS, stats.manifests),
        (BLOB_DELETION_MANIFEST_BYTES, stats.manifest_bytes),
        (BLOB_DELETION_CHUNK_ROWS, stats.chunks),
        (BLOB_DELETION_CHUNK_BYTES, stats.chunk_bytes),
        (BLOB_DELETION_QUEUED_CHUNKS, stats.queued_chunks),
        (BLOB_DELETION_DELETED_CHUNKS, stats.deleted_chunks),
        (BLOB_DELETION_CHARGED_VARIANTS, stats.charged_variants),
        (BLOB_DELETION_CHARGED_FILES, stats.charged_files),
        (
            BLOB_DELETION_CHARGED_RESERVED_BYTES,
            stats.charged_reserved_bytes,
        ),
        (
            BLOB_DELETION_CHARGED_COMMITTED_BYTES,
            stats.charged_committed_bytes,
        ),
    ] {
        if metadata.get(field)?.map(|value| value.value()) != Some(expected) {
            return Err(invariant(
                "Blob deletion accounting metadata disagrees with durable rows",
            ));
        }
    }
    Ok(())
}

fn encoded_row_bytes(key: &[u8], value: &[u8]) -> Result<u64, StoreError> {
    key.len()
        .checked_add(value.len())
        .and_then(|length| u64::try_from(length).ok())
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

#[derive(Clone, Copy)]
struct BlobDeletionAllocationBounds {
    manifest_rows: u64,
    manifest_bytes: u64,
    chunk_rows: u64,
    chunk_bytes: u64,
}

fn required_deletion_counter(
    metadata: &impl ReadableTable<&'static str, u64>,
    field: &'static str,
) -> Result<u64, StoreError> {
    metadata
        .get(field)?
        .map(|value| value.value())
        .ok_or_else(|| invariant("Blob deletion accounting metadata is incomplete"))
}

fn preflight_allocation_bounds(
    metadata: &impl ReadableTable<&'static str, u64>,
    manifests: &impl ReadableTable<&'static [u8], &'static [u8]>,
    deletion_chunks: &impl ReadableTable<&'static [u8], &'static [u8]>,
    imports: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BlobDeletionAllocationBounds, StoreError> {
    if metadata.len()? != DELETION_METADATA_FIELDS.len() as u64
        || required_deletion_counter(metadata, BLOB_DELETION_SCHEMA_VERSION_FIELD)?
            != BLOB_DELETION_SCHEMA_VERSION
    {
        return Err(invariant(
            "Blob deletion metadata is incomplete or has an unknown version",
        ));
    }
    let bounds = BlobDeletionAllocationBounds {
        manifest_rows: required_deletion_counter(metadata, BLOB_DELETION_MANIFEST_ROWS)?,
        manifest_bytes: required_deletion_counter(metadata, BLOB_DELETION_MANIFEST_BYTES)?,
        chunk_rows: required_deletion_counter(metadata, BLOB_DELETION_CHUNK_ROWS)?,
        chunk_bytes: required_deletion_counter(metadata, BLOB_DELETION_CHUNK_BYTES)?,
    };
    if manifests.len()? != bounds.manifest_rows || deletion_chunks.len()? != bounds.chunk_rows {
        return Err(invariant(
            "Blob deletion table cardinality disagrees with durable accounting",
        ));
    }
    if bounds.manifest_rows > imports.len()? {
        return Err(invariant(
            "Blob deletion manifest rows exceed their exact import bound",
        ));
    }

    let mut max_manifest_bytes = 0u64;
    let mut max_chunk_rows = 0u64;
    for row in imports.iter()? {
        let (key, value) = row?;
        let import = super::depot::deletion_import_projection(key.value(), value.value())?;
        max_manifest_bytes = max_manifest_bytes
            .checked_add(
                u64::try_from(
                    32usize
                        .checked_add(MANIFEST_FIXED_BYTES)
                        .and_then(|bytes| bytes.checked_add(MAX_LINEAGE_FENCE_EVIDENCE_BYTES))
                        .and_then(|bytes| bytes.checked_add(value.value().len()))
                        .ok_or(StoreError::PayloadByteAccountingOverflow)?,
                )
                .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
            )
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        max_chunk_rows = max_chunk_rows
            .checked_add(import.chunk_count)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
    }
    if bounds.manifest_bytes > max_manifest_bytes {
        return Err(invariant(
            "Blob deletion manifest bytes exceed their exact import bound",
        ));
    }
    if bounds.chunk_rows > max_chunk_rows {
        return Err(invariant(
            "Blob deletion chunk rows exceed their exact import bound",
        ));
    }
    let max_chunk_bytes = max_chunk_rows
        .checked_mul(
            u64::try_from(40 + CHUNK_FIXED_BYTES + MAX_CHUNK_EVIDENCE_BYTES)
                .map_err(|_| StoreError::PayloadByteAccountingOverflow)?,
        )
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if bounds.chunk_bytes > max_chunk_bytes {
        return Err(invariant(
            "Blob deletion chunk bytes exceed their exact import bound",
        ));
    }
    Ok(bounds)
}

fn parse_variant_key(bytes: &[u8]) -> Result<BlobVariantId, StoreError> {
    Ok(BlobVariantId::from_bytes(bytes.try_into().map_err(
        |_| invariant("Blob deletion manifest variant key has invalid length"),
    )?))
}

fn parse_chunk_key(bytes: &[u8]) -> Result<(BlobVariantId, u64), StoreError> {
    if bytes.len() != 40 {
        return Err(invariant("Blob deletion chunk key has invalid length"));
    }
    let variant = BlobVariantId::from_bytes(
        bytes[..32]
            .try_into()
            .map_err(|_| invariant("Blob deletion chunk variant key is malformed"))?,
    );
    let index = u64::from_be_bytes(
        bytes[32..]
            .try_into()
            .map_err(|_| invariant("Blob deletion chunk index key is malformed"))?,
    );
    Ok((variant, index))
}

#[allow(dead_code)]
fn chunk_key(variant: BlobVariantId, index: u64) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..32].copy_from_slice(variant.as_bytes());
    key[32..].copy_from_slice(&index.to_be_bytes());
    key
}

#[allow(clippy::too_many_arguments)]
fn audit_blob_deletion_rows(
    metadata: &impl ReadableTable<&'static str, u64>,
    manifests: &impl ReadableTable<&'static [u8], &'static [u8]>,
    deletion_chunks: &impl ReadableTable<&'static [u8], &'static [u8]>,
    continuity: &impl ReadableTable<u8, &'static [u8]>,
    imports: &impl ReadableTable<&'static [u8], &'static [u8]>,
    active_chunks: &impl ReadableTable<&'static [u8], &'static [u8]>,
    variant_references: &impl ReadableTable<&'static [u8], &'static [u8]>,
    lineage_fences: &impl ReadableTable<&'static [u8], &'static [u8]>,
    owner_binding: Option<[u8; 32]>,
) -> Result<BlobDeletionAudit, StoreError> {
    let allocation = preflight_allocation_bounds(metadata, manifests, deletion_chunks, imports)?;
    let continuity = audited_continuity(continuity)?;
    let maintenance_turn = metadata
        .get(BLOB_DELETION_MAINTENANCE_TURN)?
        .map(|value| value.value())
        .ok_or_else(|| invariant("Blob deletion maintenance turn is missing"))?;
    let mut headers = BTreeMap::<BlobVariantId, BlobDeletionManifestHeader>::new();
    let mut manifest_rows = 0u64;
    let mut manifest_bytes = 0u64;
    for row in manifests.iter()? {
        let (key, value) = row?;
        manifest_rows = manifest_rows
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        manifest_bytes = manifest_bytes
            .checked_add(encoded_row_bytes(key.value(), value.value())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if manifest_rows > allocation.manifest_rows || manifest_bytes > allocation.manifest_bytes {
            return Err(invariant(
                "Blob deletion manifest rows exceed their durable allocation bound",
            ));
        }
        let variant = parse_variant_key(key.value())?;
        let header = decode_manifest_header(value.value())?;
        validate_age_against_continuity(header.age, continuity)?;
        if header.variant_id != variant || headers.contains_key(&variant) {
            return Err(invariant(
                "Blob deletion manifest key differs from its exact variant",
            ));
        }
        if owner_binding != Some(header.owner_binding) {
            return Err(invariant(
                "Blob deletion manifest owner binding is unavailable or mismatched",
            ));
        }
        headers.insert(variant, header);
    }

    for row in variant_references.iter()? {
        let (key, value) = row?;
        if key.value().len() != 65 || !value.value().is_empty() {
            return Err(invariant("Blob variant reference is not canonical"));
        }
        let variant = BlobVariantId::from_bytes(
            key.value()[..32]
                .try_into()
                .map_err(|_| invariant("Blob variant reference key is malformed"))?,
        );
        if headers.contains_key(&variant) {
            return Err(invariant(
                "Blob deletion manifest retains a live variant reference",
            ));
        }
    }

    for row in active_chunks.iter()? {
        let (key, _) = row?;
        if key.value().len() == 40 {
            let (variant, _) = parse_chunk_key(key.value())?;
            if headers.contains_key(&variant) {
                return Err(invariant(
                    "Blob variant has duplicate active and deletion chunk authority",
                ));
            }
        }
    }

    let mut grouped_chunks = BTreeMap::<BlobVariantId, Vec<BlobDeletionChunk>>::new();
    let mut chunk_rows = 0u64;
    let mut chunk_bytes = 0u64;
    for row in deletion_chunks.iter()? {
        let (key, value) = row?;
        chunk_rows = chunk_rows
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        chunk_bytes = chunk_bytes
            .checked_add(encoded_row_bytes(key.value(), value.value())?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if chunk_rows > allocation.chunk_rows || chunk_bytes > allocation.chunk_bytes {
            return Err(invariant(
                "Blob deletion chunk rows exceed their durable allocation bound",
            ));
        }
        let (variant, index) = parse_chunk_key(key.value())?;
        let expected_chunks = headers
            .get(&variant)
            .ok_or_else(|| invariant("Blob deletion chunk references a missing manifest"))?
            .totals
            .chunks;
        let grouped = grouped_chunks.entry(variant).or_default();
        let grouped_len =
            u64::try_from(grouped.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
        if grouped_len >= expected_chunks {
            return Err(invariant(
                "Blob deletion chunk rows exceed their manifest bound",
            ));
        }
        let chunk = decode_chunk_record(value.value())?;
        if chunk.index != index {
            return Err(invariant(
                "Blob deletion chunk key differs from its retained index",
            ));
        }
        grouped.push(chunk);
    }

    let mut audited = BlobDeletionAudit {
        manifests: BTreeMap::new(),
        stats: BlobDeletionStats {
            manifest_bytes,
            chunk_bytes,
            maintenance_turn,
            ..BlobDeletionStats::default()
        },
    };
    for (variant, header) in headers {
        let import = imports
            .get(variant.as_bytes().as_slice())?
            .ok_or_else(|| invariant("Blob deletion manifest import is missing"))?;
        if import.value() != header.original_import.as_slice() {
            return Err(invariant(
                "Blob deletion manifest import evidence is not exact",
            ));
        }
        let import_projection =
            super::depot::deletion_import_projection(variant.as_bytes(), import.value())?;
        if import_projection.variant_id != variant
            || import_projection.blob_id != header.blob_id
            || import_projection.content_group != header.content_group
            || import_projection.epoch != header.epoch
            || import_projection.physical_lineage != header.physical_lineage
            || import_projection.finalized_root != header.finalized_root
            || header.totals.chunks > import_projection.chunk_count
        {
            return Err(invariant(
                "Blob deletion manifest differs from its exact import",
            ));
        }
        let lineage = lineage_fences
            .get(variant.as_bytes().as_slice())?
            .ok_or_else(|| invariant("Blob deletion manifest lineage fence is missing"))?;
        if lineage.value() != header.lineage_fence.as_slice() {
            return Err(invariant(
                "Blob deletion manifest lineage evidence is not exact",
            ));
        }
        super::lifecycle::validate_maintenance_lineage_evidence(
            header.physical_lineage,
            header.owner_binding,
            lineage.value(),
        )?;

        let chunks = grouped_chunks.remove(&variant).unwrap_or_default();
        if u64::try_from(chunks.len()).ok() != Some(header.totals.chunks) {
            return Err(invariant("Blob deletion manifest chunk set is incomplete"));
        }
        let manifest = BlobDeletionManifest {
            variant_id: header.variant_id,
            blob_id: header.blob_id,
            content_group: header.content_group,
            epoch: header.epoch,
            physical_lineage: header.physical_lineage,
            owner_binding: header.owner_binding,
            lineage_fence: header.lineage_fence,
            original_import: header.original_import,
            finalized_root: header.finalized_root,
            phase: header.phase,
            retry: header.retry,
            age: header.age,
            totals: header.totals,
            chunks,
        };
        manifest.validate()?;
        let mut records = Vec::with_capacity(manifest.chunks.len());
        for chunk in &manifest.chunks {
            let projected = super::depot::deletion_chunk_projection(
                &manifest.original_import,
                chunk.index,
                &chunk.original_chunk,
            )?;
            if projected.charged_reserved_bytes != chunk.charged_reserved_bytes
                || projected.charged_committed_bytes != chunk.charged_committed_bytes
            {
                return Err(invariant(
                    "Blob deletion chunk charge differs from its original row",
                ));
            }
            if let Some(record) = projected.record {
                records.push(record);
            }
        }
        super::depot::validate_deletion_manifest_root(
            &manifest.original_import,
            &records,
            manifest.finalized_root,
        )?;
        audited.stats.manifests = audited
            .stats
            .manifests
            .checked_add(1)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        audited.stats.chunks = audited
            .stats
            .chunks
            .checked_add(manifest.totals.chunks)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        audited.stats.queued_chunks = audited
            .stats
            .queued_chunks
            .checked_add(manifest.totals.queued)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        audited.stats.deleted_chunks = audited
            .stats
            .deleted_chunks
            .checked_add(manifest.totals.deleted)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        audited.stats.charged_variants = audited
            .stats
            .charged_variants
            .checked_add(manifest.totals.charged_variants)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        audited.stats.charged_files = audited
            .stats
            .charged_files
            .checked_add(manifest.totals.charged_files)
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        audited.stats.charged_reserved_bytes = audited
            .stats
            .charged_reserved_bytes
            .checked_add(manifest.totals.charged_reserved_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        audited.stats.charged_committed_bytes = audited
            .stats
            .charged_committed_bytes
            .checked_add(manifest.totals.charged_committed_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        audited.manifests.insert(variant, manifest);
    }
    if !grouped_chunks.is_empty() {
        return Err(invariant(
            "Blob deletion chunk set contains orphan variant rows",
        ));
    }
    audit_metadata(metadata, audited.stats)?;
    Ok(audited)
}

pub(crate) fn audit_blob_deletion_write(
    write: &redb::WriteTransaction,
    owner_binding: Option<[u8; 32]>,
) -> Result<BlobDeletionAudit, StoreError> {
    let metadata = write.open_table(BLOB_DELETION_METADATA)?;
    let manifests = write.open_table(BLOB_DELETION_MANIFESTS)?;
    let chunks = write.open_table(BLOB_DELETION_CHUNKS)?;
    let continuity = write.open_table(BLOB_DELETION_CONTINUITY)?;
    if manifests.is_empty()? && chunks.is_empty()? {
        let maintenance_turn = metadata
            .get(BLOB_DELETION_MAINTENANCE_TURN)?
            .map(|value| value.value())
            .ok_or_else(|| invariant("Blob deletion maintenance turn is missing"))?;
        let audit = BlobDeletionAudit {
            manifests: BTreeMap::new(),
            stats: BlobDeletionStats {
                maintenance_turn,
                ..BlobDeletionStats::default()
            },
        };
        audit_metadata(&metadata, audit.stats)?;
        audit_continuity_table(&continuity)?;
        return Ok(audit);
    }
    audit_blob_deletion_rows(
        &metadata,
        &manifests,
        &chunks,
        &continuity,
        &write.open_table(super::BLOB_IMPORTS)?,
        &write.open_table(super::BLOB_CHUNKS)?,
        &write.open_table(super::lifecycle::BLOB_VARIANT_REFERENCES)?,
        &write.open_table(super::lifecycle::BLOB_LINEAGE_FENCES)?,
        owner_binding,
    )
}

pub(crate) fn audit_blob_deletion_read(
    read: &redb::ReadTransaction,
    owner_binding: Option<[u8; 32]>,
) -> Result<BlobDeletionAudit, StoreError> {
    let metadata = read.open_table(BLOB_DELETION_METADATA)?;
    let manifests = read.open_table(BLOB_DELETION_MANIFESTS)?;
    let chunks = read.open_table(BLOB_DELETION_CHUNKS)?;
    let continuity = read.open_table(BLOB_DELETION_CONTINUITY)?;
    if manifests.is_empty()? && chunks.is_empty()? {
        let maintenance_turn = metadata
            .get(BLOB_DELETION_MAINTENANCE_TURN)?
            .map(|value| value.value())
            .ok_or_else(|| invariant("Blob deletion maintenance turn is missing"))?;
        let audit = BlobDeletionAudit {
            manifests: BTreeMap::new(),
            stats: BlobDeletionStats {
                maintenance_turn,
                ..BlobDeletionStats::default()
            },
        };
        audit_metadata(&metadata, audit.stats)?;
        audit_continuity_table(&continuity)?;
        return Ok(audit);
    }
    audit_blob_deletion_rows(
        &metadata,
        &manifests,
        &chunks,
        &continuity,
        &read.open_table(super::BLOB_IMPORTS)?,
        &read.open_table(super::BLOB_CHUNKS)?,
        &read.open_table(super::lifecycle::BLOB_VARIANT_REFERENCES)?,
        &read.open_table(super::lifecycle::BLOB_LINEAGE_FENCES)?,
        owner_binding,
    )
}

/// Creates only an empty deletion authority when wholly absent. Existing
/// current state is audited and is never repaired.
pub(crate) fn audit_or_migrate_blob_deletion_write(
    write: &redb::WriteTransaction,
    owner_binding: Option<[u8; 32]>,
) -> Result<(bool, BlobDeletionAudit), StoreError> {
    match deletion_schema_state_write(write)? {
        DeletionSchemaState::Predecessor => {
            initialize_blob_deletion_schema(write)?;
            Ok((true, audit_blob_deletion_write(write, owner_binding)?))
        }
        DeletionSchemaState::Current => {
            Ok((false, audit_blob_deletion_write(write, owner_binding)?))
        }
    }
}

pub(crate) fn inspect_blob_deletion_read(
    read: &redb::ReadTransaction,
    owner_binding: Option<[u8; 32]>,
) -> Result<BlobDeletionAudit, StoreError> {
    match deletion_schema_state_read(read)? {
        DeletionSchemaState::Predecessor => Ok(BlobDeletionAudit::default()),
        DeletionSchemaState::Current => audit_blob_deletion_read(read, owner_binding),
    }
}

#[cfg(test)]
fn set_metadata_for_test(
    metadata: &mut redb::Table<'_, &str, u64>,
    field: &'static str,
    value: u64,
) -> Result<(), StoreError> {
    metadata.insert(field, value)?;
    Ok(())
}

#[cfg(test)]
fn load_manifest_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<BlobDeletionManifest, StoreError> {
    let manifests = write.open_table(BLOB_DELETION_MANIFESTS)?;
    let encoded_manifest = manifests
        .get(variant.as_bytes().as_slice())?
        .ok_or_else(|| invariant("Blob deletion test manifest is missing"))?
        .value()
        .to_vec();
    drop(manifests);
    let first = chunk_key(variant, 0);
    let last = chunk_key(variant, u64::MAX);
    let chunks = write.open_table(BLOB_DELETION_CHUNKS)?;
    let mut encoded_chunks = Vec::new();
    for row in chunks.range::<&[u8]>((
        std::ops::Bound::Included(first.as_slice()),
        std::ops::Bound::Included(last.as_slice()),
    ))? {
        let (_, value) = row?;
        encoded_chunks.push(value.value().to_vec());
    }
    decode_manifest_record(&encoded_manifest, &encoded_chunks)
}

/// Builds deletion authority from one unreferenced variant for exact-audit
/// tests. Production admission belongs to the bounded maintenance path.
#[cfg(test)]
pub(crate) fn move_variant_to_manifest_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<BlobDeletionManifest, StoreError> {
    let imports = write.open_table(super::BLOB_IMPORTS)?;
    let original_import = imports
        .get(variant.as_bytes().as_slice())?
        .ok_or_else(|| invariant("Blob deletion test import is missing"))?
        .value()
        .to_vec();
    drop(imports);
    let import = super::depot::deletion_import_projection(variant.as_bytes(), &original_import)?;
    let owner_binding = super::depot::depot_owner_binding_if_present_write(write)?
        .ok_or_else(|| invariant("Blob deletion test owner binding is missing"))?;
    let fences = write.open_table(super::lifecycle::BLOB_LINEAGE_FENCES)?;
    let lineage_fence = fences
        .get(variant.as_bytes().as_slice())?
        .ok_or_else(|| invariant("Blob deletion test lineage fence is missing"))?
        .value()
        .to_vec();
    drop(fences);

    let first = chunk_key(variant, 0);
    let last = chunk_key(variant, u64::MAX);
    let active_chunks = write.open_table(super::BLOB_CHUNKS)?;
    let mut originals = Vec::new();
    for row in active_chunks.range::<&[u8]>((
        std::ops::Bound::Included(first.as_slice()),
        std::ops::Bound::Included(last.as_slice()),
    ))? {
        let (key, value) = row?;
        let (_, index) = parse_chunk_key(key.value())?;
        originals.push((index, value.value().to_vec()));
    }
    drop(active_chunks);
    let mut chunks = Vec::with_capacity(originals.len());
    let mut charged_files = 0u64;
    let mut charged_reserved_bytes = 0u64;
    let mut charged_committed_bytes = 0u64;
    for (index, original_chunk) in &originals {
        let projected =
            super::depot::deletion_chunk_projection(&original_import, *index, original_chunk)?;
        charged_reserved_bytes = charged_reserved_bytes
            .checked_add(projected.charged_reserved_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        charged_committed_bytes = charged_committed_bytes
            .checked_add(projected.charged_committed_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        charged_files = charged_files
            .checked_add(u64::from(projected.charged_committed_bytes != 0))
            .ok_or(StoreError::ItemCountAccountingOverflow)?;
        chunks.push(BlobDeletionChunk {
            index: *index,
            state: BlobDeletionChunkState::DeleteQueued,
            original_chunk: original_chunk.clone(),
            charged_reserved_bytes: projected.charged_reserved_bytes,
            charged_committed_bytes: projected.charged_committed_bytes,
        });
    }
    let chunk_count =
        u64::try_from(chunks.len()).map_err(|_| StoreError::ItemCountAccountingOverflow)?;
    let manifest = BlobDeletionManifest {
        variant_id: variant,
        blob_id: import.blob_id,
        content_group: import.content_group,
        epoch: import.epoch,
        physical_lineage: import.physical_lineage,
        owner_binding,
        lineage_fence,
        original_import,
        finalized_root: import.finalized_root,
        phase: BlobDeletionPhase::DeletingChunks,
        retry: BlobDeletionRetry::default(),
        age: BlobDeletionAge {
            cumulative_age_ms: 0,
            checkpoint: None,
            continuity_generation: 0,
            continuity_lost: false,
        },
        totals: BlobDeletionTotals {
            chunks: chunk_count,
            queued: chunk_count,
            deleted: 0,
            charged_variants: 1,
            charged_files,
            charged_reserved_bytes,
            charged_committed_bytes,
        },
        chunks,
    };
    manifest.validate()?;
    let encoded_manifest = encode_manifest_record(&manifest)?;
    let encoded_chunks = manifest
        .chunks
        .iter()
        .map(encode_chunk_record)
        .collect::<Result<Vec<_>, _>>()?;

    let mut active_chunks = write.open_table(super::BLOB_CHUNKS)?;
    for (index, _) in &originals {
        active_chunks
            .remove(chunk_key(variant, *index).as_slice())?
            .ok_or_else(|| invariant("Blob deletion test chunk move lost authority"))?;
    }
    drop(active_chunks);
    write
        .open_table(BLOB_DELETION_MANIFESTS)?
        .insert(variant.as_bytes().as_slice(), encoded_manifest.as_slice())?;
    let mut deletion_chunks = write.open_table(BLOB_DELETION_CHUNKS)?;
    let mut encoded_chunk_bytes = 0u64;
    for (chunk, encoded) in manifest.chunks.iter().zip(&encoded_chunks) {
        let key = chunk_key(variant, chunk.index);
        encoded_chunk_bytes = encoded_chunk_bytes
            .checked_add(encoded_row_bytes(&key, encoded)?)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        deletion_chunks.insert(key.as_slice(), encoded.as_slice())?;
    }
    drop(deletion_chunks);

    let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
    let manifest_bytes = encoded_row_bytes(variant.as_bytes(), &encoded_manifest)?;
    for (field, delta) in [
        (BLOB_DELETION_MANIFEST_ROWS, 1),
        (BLOB_DELETION_MANIFEST_BYTES, manifest_bytes),
        (BLOB_DELETION_CHUNK_ROWS, chunk_count),
        (BLOB_DELETION_CHUNK_BYTES, encoded_chunk_bytes),
        (BLOB_DELETION_QUEUED_CHUNKS, chunk_count),
        (BLOB_DELETION_CHARGED_VARIANTS, 1),
        (BLOB_DELETION_CHARGED_FILES, charged_files),
        (BLOB_DELETION_CHARGED_RESERVED_BYTES, charged_reserved_bytes),
        (
            BLOB_DELETION_CHARGED_COMMITTED_BYTES,
            charged_committed_bytes,
        ),
    ] {
        let current = metadata
            .get(field)?
            .ok_or_else(|| invariant("Blob deletion test metadata is missing"))?
            .value();
        set_metadata_for_test(
            &mut metadata,
            field,
            current
                .checked_add(delta)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        )?;
    }
    Ok(manifest)
}

#[cfg(test)]
pub(crate) fn move_finalized_variant_to_manifest_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<BlobDeletionManifest, StoreError> {
    let manifest = move_variant_to_manifest_for_test(write, variant)?;
    if manifest.finalized_root.is_none()
        || manifest.totals.chunks
            != super::depot::deletion_import_projection(
                variant.as_bytes(),
                &manifest.original_import,
            )?
            .chunk_count
    {
        return Err(invariant(
            "Blob deletion test fixture lacks exact committed chunk rows",
        ));
    }
    Ok(manifest)
}

#[cfg(test)]
pub(crate) fn corrupt_blob_deletion_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    corruption: &str,
) -> Result<(), StoreError> {
    if corruption == "live-reference" {
        let mut key = [0xa5; 65];
        key[..32].copy_from_slice(variant.as_bytes());
        key[32] = 1;
        write
            .open_table(super::lifecycle::BLOB_VARIANT_REFERENCES)?
            .insert(key.as_slice(), &[][..])?;
        return Ok(());
    }
    if corruption == "accounting" {
        let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
        let current = metadata
            .get(BLOB_DELETION_CHARGED_COMMITTED_BYTES)?
            .ok_or_else(|| invariant("Blob deletion test accounting is missing"))?
            .value();
        return set_metadata_for_test(
            &mut metadata,
            BLOB_DELETION_CHARGED_COMMITTED_BYTES,
            current
                .checked_add(1)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?,
        );
    }
    let mut manifest = load_manifest_for_test(write, variant)?;
    match corruption {
        "root" => {
            manifest
                .finalized_root
                .as_mut()
                .ok_or_else(|| invariant("Blob deletion test manifest root is missing"))?[0] ^= 1;
        }
        "deleted-file-present" => {
            let first = manifest
                .chunks
                .first_mut()
                .ok_or_else(|| invariant("Blob deletion test manifest has no chunks"))?;
            first.state = BlobDeletionChunkState::DeletedDurable;
            manifest.totals.queued = manifest
                .totals
                .queued
                .checked_sub(1)
                .ok_or_else(|| invariant("Blob deletion queued total underflows"))?;
            manifest.totals.deleted = manifest
                .totals
                .deleted
                .checked_add(1)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            let mut metadata = write.open_table(BLOB_DELETION_METADATA)?;
            set_metadata_for_test(
                &mut metadata,
                BLOB_DELETION_QUEUED_CHUNKS,
                manifest.totals.queued,
            )?;
            set_metadata_for_test(
                &mut metadata,
                BLOB_DELETION_DELETED_CHUNKS,
                manifest.totals.deleted,
            )?;
        }
        _ => return Err(invariant("Blob deletion test corruption is unknown")),
    }
    manifest.validate()?;
    let encoded_manifest = encode_manifest_record(&manifest)?;
    write
        .open_table(BLOB_DELETION_MANIFESTS)?
        .insert(variant.as_bytes().as_slice(), encoded_manifest.as_slice())?;
    if corruption == "deleted-file-present" {
        let first = manifest
            .chunks
            .first()
            .ok_or_else(|| invariant("Blob deletion test manifest has no chunks"))?;
        let encoded_chunk = encode_chunk_record(first)?;
        write.open_table(BLOB_DELETION_CHUNKS)?.insert(
            chunk_key(variant, first.index).as_slice(),
            encoded_chunk.as_slice(),
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn set_blob_deletion_age_for_test(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    age: BlobDeletionAge,
    continuity: Option<BlobDeletionContinuity>,
) -> Result<(), StoreError> {
    let mut manifest = load_manifest_for_test(write, variant)?;
    manifest.age = age;
    manifest.validate()?;
    let encoded = encode_manifest_record(&manifest)?;
    write
        .open_table(BLOB_DELETION_MANIFESTS)?
        .insert(variant.as_bytes().as_slice(), encoded.as_slice())?;
    let mut continuity_table = write.open_table(BLOB_DELETION_CONTINUITY)?;
    match continuity {
        Some(continuity) => {
            let encoded = encode_continuity(continuity);
            continuity_table.insert(CONTINUITY_KEY, encoded.as_slice())?;
        }
        None => {
            continuity_table.remove(CONTINUITY_KEY)?;
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn encode_continuity(continuity: BlobDeletionContinuity) -> [u8; 33] {
    let mut encoded = [0u8; 33];
    encoded[0] = CONTINUITY_VERSION;
    encoded[1..9].copy_from_slice(&continuity.generation.to_be_bytes());
    encoded[9..25].copy_from_slice(&continuity.last_sample.clock_id);
    encoded[25..].copy_from_slice(&continuity.last_sample.tick_ms.to_be_bytes());
    encoded
}

fn decode_continuity(bytes: &[u8]) -> Result<BlobDeletionContinuity, StoreError> {
    let bytes: [u8; 33] = bytes
        .try_into()
        .map_err(|_| invariant("Blob deletion continuity record has invalid length"))?;
    if bytes[0] != CONTINUITY_VERSION {
        return Err(invariant(
            "Blob deletion continuity record has unknown version",
        ));
    }
    let generation = u64::from_be_bytes(
        bytes[1..9]
            .try_into()
            .map_err(|_| invariant("Blob deletion continuity generation is malformed"))?,
    );
    if generation == 0 {
        return Err(invariant(
            "Blob deletion continuity generation must be nonzero",
        ));
    }
    Ok(BlobDeletionContinuity {
        generation,
        last_sample: CustodySample {
            clock_id: bytes[9..25]
                .try_into()
                .map_err(|_| invariant("Blob deletion continuity clock is malformed"))?,
            tick_ms: u64::from_be_bytes(
                bytes[25..]
                    .try_into()
                    .map_err(|_| invariant("Blob deletion continuity tick is malformed"))?,
            ),
        },
    })
}

fn audited_continuity(
    table: &impl ReadableTable<u8, &'static [u8]>,
) -> Result<Option<BlobDeletionContinuity>, StoreError> {
    if table.len()? > 1 {
        return Err(invariant(
            "Blob deletion continuity table contains unknown rows",
        ));
    }
    let mut continuity = None;
    for row in table.iter()? {
        let (key, value) = row?;
        if key.value() != CONTINUITY_KEY {
            return Err(invariant("Blob deletion continuity key is not canonical"));
        }
        continuity = Some(decode_continuity(value.value())?);
    }
    Ok(continuity)
}

fn audit_continuity_table(table: &impl ReadableTable<u8, &'static [u8]>) -> Result<(), StoreError> {
    audited_continuity(table).map(|_| ())
}

fn validate_age_against_continuity(
    age: BlobDeletionAge,
    continuity: Option<BlobDeletionContinuity>,
) -> Result<(), StoreError> {
    age.validate()?;
    let Some(checkpoint) = age.checkpoint else {
        return Ok(());
    };
    let continuity = continuity.ok_or_else(|| {
        invariant("Blob deletion age checkpoint has no durable continuity authority")
    })?;
    if age.continuity_generation > continuity.generation {
        return Err(invariant(
            "Blob deletion age generation is ahead of durable continuity",
        ));
    }
    if age.continuity_generation == continuity.generation
        && (checkpoint.clock_id != continuity.last_sample.clock_id
            || checkpoint.tick_ms > continuity.last_sample.tick_ms)
    {
        return Err(invariant(
            "Blob deletion age checkpoint exceeds current durable continuity",
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn blob_deletion_continuity_write(
    write: &redb::WriteTransaction,
) -> Result<Option<BlobDeletionContinuity>, StoreError> {
    write
        .open_table(BLOB_DELETION_CONTINUITY)?
        .get(CONTINUITY_KEY)?
        .map(|value| decode_continuity(value.value()))
        .transpose()
}

#[allow(dead_code)]
pub(crate) fn observe_blob_deletion_continuity_write(
    write: &redb::WriteTransaction,
    sample: CustodySample,
) -> Result<BlobDeletionContinuity, StoreError> {
    let current = blob_deletion_continuity_write(write)?;
    let next = match current {
        None => BlobDeletionContinuity {
            generation: 1,
            last_sample: sample,
        },
        Some(current)
            if current.last_sample.clock_id == sample.clock_id
                && sample.tick_ms >= current.last_sample.tick_ms =>
        {
            BlobDeletionContinuity {
                generation: current.generation,
                last_sample: sample,
            }
        }
        Some(current) => BlobDeletionContinuity {
            generation: current
                .generation
                .checked_add(1)
                .ok_or_else(|| invariant("Blob deletion continuity generation overflowed"))?,
            last_sample: sample,
        },
    };
    if current != Some(next) {
        let encoded = encode_continuity(next);
        write
            .open_table(BLOB_DELETION_CONTINUITY)?
            .insert(CONTINUITY_KEY, encoded.as_slice())?;
    }
    Ok(next)
}

#[allow(dead_code)]
pub(crate) fn project_blob_deletion_age(
    age: BlobDeletionAge,
    continuity: Option<BlobDeletionContinuity>,
    sample: Option<CustodySample>,
) -> Result<BlobDeletionAge, StoreError> {
    age.validate()?;
    let Some(sample) = sample else {
        return Ok(age);
    };
    let projected = project_lower_bound_age(
        LowerBoundAgeCheckpoint {
            cumulative_age_ms: age.cumulative_age_ms,
            checkpoint: age.checkpoint,
            continuity_generation: age.continuity_generation,
            continuity_lost: age.continuity_lost,
        },
        continuity.map(|continuity| LowerBoundContinuity {
            generation: continuity.generation,
            sample: continuity.last_sample,
        }),
        Some(sample),
    );
    Ok(BlobDeletionAge {
        cumulative_age_ms: projected.cumulative_age_ms,
        checkpoint: projected.checkpoint,
        continuity_generation: projected.continuity_generation,
        continuity_lost: projected.continuity_lost,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use aster_mesh::{BlobId, CustodySample};
    use redb::{Database, ReadableDatabase, ReadableTableMetadata, TableHandle};

    use super::*;
    use crate::{BlobVariantId, MAX_SELECTED_BLOB_CHUNKS, Store};

    static NEXT_DELETION_TEST: AtomicU64 = AtomicU64::new(1);

    struct DeletionTestFile(PathBuf);

    impl DeletionTestFile {
        fn new(label: &str) -> Self {
            let sequence = NEXT_DELETION_TEST.fetch_add(1, Ordering::Relaxed);
            Self(std::env::temp_dir().join(format!(
                "aster-redb-blob-deletion-{label}-{}-{sequence}.redb",
                std::process::id()
            )))
        }
    }

    impl Drop for DeletionTestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn sample_manifest() -> BlobDeletionManifest {
        let blob_id = BlobId::from_bytes([0x22; 32]);
        let content_group = [0x33; 32];
        let checkpoint = CustodySample {
            clock_id: [0x71; 16],
            tick_ms: 900,
        };
        BlobDeletionManifest {
            variant_id: BlobVariantId::for_content(blob_id, &content_group, 7),
            blob_id,
            content_group,
            epoch: 7,
            physical_lineage: [0x44; 32],
            owner_binding: [0x55; 32],
            lineage_fence: vec![0x66; 65],
            original_import: vec![0x77; 128],
            finalized_root: Some([0x88; 32]),
            phase: BlobDeletionPhase::DeletingChunks,
            retry: BlobDeletionRetry::default(),
            age: BlobDeletionAge {
                cumulative_age_ms: 25,
                checkpoint: Some(checkpoint),
                continuity_generation: 3,
                continuity_lost: false,
            },
            totals: BlobDeletionTotals {
                chunks: 1,
                queued: 1,
                deleted: 0,
                charged_variants: 1,
                charged_files: 1,
                charged_reserved_bytes: 211,
                charged_committed_bytes: 211,
            },
            chunks: vec![BlobDeletionChunk {
                index: 0,
                state: BlobDeletionChunkState::DeleteQueued,
                original_chunk: vec![0x99; 186],
                charged_reserved_bytes: 211,
                charged_committed_bytes: 211,
            }],
        }
    }

    fn assert_schema_reason(error: &StoreError, expected: &'static str) {
        assert!(matches!(
            error,
            StoreError::Blob(BlobStoreError::SchemaInvariant(reason)) if *reason == expected
        ));
    }

    #[test]
    fn blob_deletion_schema_migrates_empty_without_inventing_work() {
        let file = DeletionTestFile::new("empty-migration");
        drop(Store::open(&file.0).expect("create current store"));

        {
            let database = Database::open(&file.0).expect("open deletion predecessor");
            let write = database.begin_write().expect("begin deletion predecessor");
            write
                .delete_table(BLOB_DELETION_METADATA)
                .expect("delete deletion metadata");
            write
                .delete_table(BLOB_DELETION_MANIFESTS)
                .expect("delete deletion manifests");
            write
                .delete_table(BLOB_DELETION_CHUNKS)
                .expect("delete deletion chunks");
            write
                .delete_table(BLOB_DELETION_CONTINUITY)
                .expect("delete deletion continuity");
            write.commit().expect("commit whole-absent predecessor");
        }

        Store::inspect_existing(&file.0).expect("whole-absent deletion schema is inspectable");
        drop(Store::open(&file.0).expect("migrate empty deletion schema"));

        let database = redb::Builder::new()
            .open_read_only(&file.0)
            .expect("inspect migrated deletion schema");
        let read = database
            .begin_read()
            .expect("read migrated deletion schema");
        let metadata = read
            .open_table(BLOB_DELETION_METADATA)
            .expect("deletion metadata");
        assert_eq!(metadata.len().expect("metadata length"), 12);
        for (field, expected) in [
            (
                BLOB_DELETION_SCHEMA_VERSION_FIELD,
                BLOB_DELETION_SCHEMA_VERSION,
            ),
            (BLOB_DELETION_MAINTENANCE_TURN, 0),
            (BLOB_DELETION_MANIFEST_ROWS, 0),
            (BLOB_DELETION_MANIFEST_BYTES, 0),
            (BLOB_DELETION_CHUNK_ROWS, 0),
            (BLOB_DELETION_CHUNK_BYTES, 0),
            (BLOB_DELETION_QUEUED_CHUNKS, 0),
            (BLOB_DELETION_DELETED_CHUNKS, 0),
            (BLOB_DELETION_CHARGED_VARIANTS, 0),
            (BLOB_DELETION_CHARGED_FILES, 0),
            (BLOB_DELETION_CHARGED_RESERVED_BYTES, 0),
            (BLOB_DELETION_CHARGED_COMMITTED_BYTES, 0),
        ] {
            assert_eq!(
                metadata
                    .get(field)
                    .expect("read deletion metadata field")
                    .map(|value| value.value()),
                Some(expected),
                "unexpected deletion metadata field {field}",
            );
        }
        assert_eq!(
            read.open_table(BLOB_DELETION_MANIFESTS)
                .expect("deletion manifests")
                .len()
                .expect("manifest length"),
            0
        );
        assert_eq!(
            read.open_table(BLOB_DELETION_CHUNKS)
                .expect("deletion chunks")
                .len()
                .expect("chunk length"),
            0
        );
        assert_eq!(
            read.open_table(BLOB_DELETION_CONTINUITY)
                .expect("deletion continuity")
                .len()
                .expect("continuity length"),
            0
        );
    }

    #[test]
    fn blob_deletion_codecs_reject_noncanonical_phase_chunk_failure_and_totals() {
        let manifest = sample_manifest();
        let encoded = encode_manifest_record(&manifest).expect("encode canonical manifest");
        let encoded_chunks = manifest
            .chunks
            .iter()
            .map(|chunk| encode_chunk_record(chunk).expect("encode canonical chunk"))
            .collect::<Vec<_>>();
        assert_eq!(
            decode_manifest_record(&encoded, &encoded_chunks).expect("decode canonical manifest"),
            manifest
        );

        let mut staging = manifest.clone();
        staging.finalized_root = None;
        staging.totals = BlobDeletionTotals {
            chunks: 2,
            queued: 2,
            deleted: 0,
            charged_variants: 1,
            charged_files: 0,
            charged_reserved_bytes: 211,
            charged_committed_bytes: 0,
        };
        staging.chunks = vec![
            BlobDeletionChunk {
                index: 1,
                state: BlobDeletionChunkState::DeleteQueued,
                original_chunk: vec![0xa1; 90],
                charged_reserved_bytes: 211,
                charged_committed_bytes: 0,
            },
            BlobDeletionChunk {
                index: 3,
                state: BlobDeletionChunkState::DeleteQueued,
                original_chunk: vec![0xa2; 34],
                charged_reserved_bytes: 0,
                charged_committed_bytes: 0,
            },
        ];
        let staging_encoded =
            encode_manifest_record(&staging).expect("encode sparse staging manifest");
        let staging_chunks = staging
            .chunks
            .iter()
            .map(|chunk| encode_chunk_record(chunk).expect("encode staging chunk"))
            .collect::<Vec<_>>();
        assert_eq!(
            decode_manifest_record(&staging_encoded, &staging_chunks)
                .expect("decode sparse staging manifest"),
            staging,
        );

        let mut unknown_phase = encoded.clone();
        unknown_phase[MANIFEST_PHASE_OFFSET] = 0xff;
        assert!(decode_manifest_record(&unknown_phase, &encoded_chunks).is_err());

        let mut reserved_manifest = encoded.clone();
        reserved_manifest[MANIFEST_RESERVED_OFFSET] = 1;
        assert!(decode_manifest_record(&reserved_manifest, &encoded_chunks).is_err());

        let mut unknown_failure = encoded.clone();
        unknown_failure[MANIFEST_FAILURE_OFFSET] = 0xff;
        assert!(decode_manifest_record(&unknown_failure, &encoded_chunks).is_err());

        let mut wrong_totals = encoded.clone();
        wrong_totals[MANIFEST_QUEUED_COUNT_OFFSET..MANIFEST_QUEUED_COUNT_OFFSET + 8]
            .copy_from_slice(&0u64.to_be_bytes());
        assert!(decode_manifest_record(&wrong_totals, &encoded_chunks).is_err());

        let mut unknown_chunk_state = encoded_chunks[0].clone();
        unknown_chunk_state[CHUNK_STATE_OFFSET] = 0xff;
        assert!(decode_manifest_record(&encoded, &[unknown_chunk_state]).is_err());

        let mut reserved_chunk = encoded_chunks[0].clone();
        reserved_chunk[CHUNK_RESERVED_OFFSET] = 1;
        assert!(decode_manifest_record(&encoded, &[reserved_chunk]).is_err());

        let mut phase_mismatch = manifest.clone();
        phase_mismatch.phase = BlobDeletionPhase::DirectoryDeletePending;
        assert!(encode_manifest_record(&phase_mismatch).is_err());

        let mut over_limit = encoded;
        over_limit[MANIFEST_CHUNK_COUNT_OFFSET..MANIFEST_CHUNK_COUNT_OFFSET + 8]
            .copy_from_slice(&(MAX_SELECTED_BLOB_CHUNKS + 1).to_be_bytes());
        assert!(decode_manifest_header(&over_limit).is_err());

        let first_retry = BlobDeletionRetry::default()
            .after_failure(7, BlobDeletionFailureCategory::ChunkUnlink)
            .expect("schedule first retry from durable turn");
        assert_eq!(first_retry.attempts, 1);
        assert_eq!(first_retry.next_retry_turn, 8);
        let second_retry = first_retry
            .after_failure(8, BlobDeletionFailureCategory::ChunkDirectorySync)
            .expect("schedule bounded exponential retry");
        assert_eq!(second_retry.attempts, 2);
        assert_eq!(second_retry.next_retry_turn, 10);
    }

    #[test]
    fn blob_deletion_partial_current_schema_fails_without_repair() {
        let file = DeletionTestFile::new("partial-current");
        drop(Store::open(&file.0).expect("create current deletion schema"));
        {
            let database = Database::open(&file.0).expect("open current deletion schema");
            let write = database.begin_write().expect("begin deletion corruption");
            write
                .delete_table(BLOB_DELETION_CHUNKS)
                .expect("remove one deletion table");
            write.commit().expect("commit partial deletion schema");
        }

        assert!(Store::inspect_existing(&file.0).is_err());
        assert!(Store::open(&file.0).is_err());

        let database = redb::Builder::new()
            .open_read_only(&file.0)
            .expect("inspect unrepaired partial deletion schema");
        let read = database.begin_read().expect("read partial deletion schema");
        let tables = read
            .list_tables()
            .expect("list partial deletion schema")
            .map(|table| table.name().to_owned())
            .collect::<std::collections::BTreeSet<_>>();
        assert!(!tables.contains(BLOB_DELETION_CHUNKS.name()));
        assert!(tables.contains(BLOB_DELETION_METADATA.name()));
        assert!(tables.contains(BLOB_DELETION_MANIFESTS.name()));
        assert!(tables.contains(BLOB_DELETION_CONTINUITY.name()));
    }

    #[test]
    fn blob_deletion_audit_bounds_corrupt_rows_before_large_evidence_allocation() {
        // Break caught: table cardinality and exact import bounds must reject
        // impossible authority before audit clones or decodes hostile 1 MiB rows.
        let oversized = vec![0xa5; MAX_IMPORT_EVIDENCE_BYTES];

        let file = DeletionTestFile::new("durable-cardinality-bound");
        drop(Store::open(&file.0).expect("create durable-bound store"));
        let database = Database::open(&file.0).expect("open durable-bound store");
        let write = database
            .begin_write()
            .expect("begin durable-bound corruption");
        write
            .open_table(BLOB_DELETION_MANIFESTS)
            .expect("durable-bound manifests")
            .insert(&[0x11; 32][..], oversized.as_slice())
            .expect("insert large unaccounted manifest");
        assert_schema_reason(
            &audit_blob_deletion_write(&write, None)
                .expect_err("durable row count must be checked before decoding"),
            "Blob deletion table cardinality disagrees with durable accounting",
        );

        for (label, manifest_row) in [("manifest", true), ("chunk", false)] {
            let file = DeletionTestFile::new(&format!("exact-{label}-bound"));
            drop(Store::open(&file.0).expect("create exact-bound store"));
            let database = Database::open(&file.0).expect("open exact-bound store");
            let write = database
                .begin_write()
                .expect("begin exact-bound corruption");
            let (rows_field, bytes_field, key_len) = if manifest_row {
                (
                    BLOB_DELETION_MANIFEST_ROWS,
                    BLOB_DELETION_MANIFEST_BYTES,
                    32usize,
                )
            } else {
                (BLOB_DELETION_CHUNK_ROWS, BLOB_DELETION_CHUNK_BYTES, 40usize)
            };
            let encoded_bytes =
                u64::try_from(key_len + oversized.len()).expect("adversarial encoded bytes");
            {
                let mut metadata = write
                    .open_table(BLOB_DELETION_METADATA)
                    .expect("exact-bound metadata");
                metadata
                    .insert(rows_field, 1)
                    .expect("set exact-bound rows");
                metadata
                    .insert(bytes_field, encoded_bytes)
                    .expect("set exact-bound bytes");
            }
            if manifest_row {
                write
                    .open_table(BLOB_DELETION_MANIFESTS)
                    .expect("exact-bound manifests")
                    .insert(&[0x22; 32][..], oversized.as_slice())
                    .expect("insert exact-bound manifest");
            } else {
                write
                    .open_table(BLOB_DELETION_CHUNKS)
                    .expect("exact-bound chunks")
                    .insert(&[0x33; 40][..], oversized.as_slice())
                    .expect("insert exact-bound chunk");
            }
            assert_schema_reason(
                &audit_blob_deletion_write(&write, None)
                    .expect_err("exact import bounds must precede decoding"),
                if manifest_row {
                    "Blob deletion manifest rows exceed their exact import bound"
                } else {
                    "Blob deletion chunk rows exceed their exact import bound"
                },
            );
        }
    }

    #[test]
    fn blob_deletion_age_lower_bound_advances_same_domain_and_survives_domain_loss() {
        let file = DeletionTestFile::new("age-continuity");
        drop(Store::open(&file.0).expect("create deletion continuity schema"));
        let clock_a = [0xa1; 16];
        let first_sample = CustodySample {
            clock_id: clock_a,
            tick_ms: 100,
        };

        let database = Database::open(&file.0).expect("open deletion continuity database");
        let write = database.begin_write().expect("begin first age observation");
        let first = observe_blob_deletion_continuity_write(&write, first_sample)
            .expect("anchor first deletion clock");
        assert_eq!(first.generation, 1);
        let age = BlobDeletionAge {
            cumulative_age_ms: 40,
            checkpoint: Some(first_sample),
            continuity_generation: first.generation,
            continuity_lost: false,
        };
        write.commit().expect("commit first deletion clock");

        let write = database
            .begin_write()
            .expect("begin same-domain observation");
        let same_domain = observe_blob_deletion_continuity_write(
            &write,
            CustodySample {
                clock_id: clock_a,
                tick_ms: 175,
            },
        )
        .expect("advance same deletion clock");
        assert_eq!(same_domain.generation, 1);
        let advanced =
            project_blob_deletion_age(age, Some(same_domain), Some(same_domain.last_sample))
                .expect("project same-domain deletion age");
        assert_eq!(advanced.cumulative_age_ms, 115);
        assert!(!advanced.continuity_lost);
        write.commit().expect("commit same-domain deletion clock");

        let write = database.begin_write().expect("begin regressed observation");
        let regressed = observe_blob_deletion_continuity_write(
            &write,
            CustodySample {
                clock_id: clock_a,
                tick_ms: 10,
            },
        )
        .expect("reanchor regressed deletion clock");
        assert_eq!(regressed.generation, 2);
        let after_regression =
            project_blob_deletion_age(advanced, Some(regressed), Some(regressed.last_sample))
                .expect("preserve age across clock regression");
        assert_eq!(after_regression.cumulative_age_ms, 115);
        assert!(after_regression.continuity_lost);
        write.commit().expect("commit regressed deletion clock");

        drop(database);
        let reopened = Database::open(&file.0).expect("reopen deletion continuity database");
        let write = reopened
            .begin_write()
            .expect("begin new-domain observation");
        let new_domain = observe_blob_deletion_continuity_write(
            &write,
            CustodySample {
                clock_id: [0xb2; 16],
                tick_ms: 5,
            },
        )
        .expect("reanchor new deletion clock domain");
        assert_eq!(new_domain.generation, 3);
        let after_domain_loss = project_blob_deletion_age(
            after_regression,
            Some(new_domain),
            Some(new_domain.last_sample),
        )
        .expect("preserve lower bound across domain loss");
        assert_eq!(after_domain_loss.cumulative_age_ms, 115);
        assert!(after_domain_loss.continuity_lost);
        assert_eq!(after_domain_loss.checkpoint, Some(new_domain.last_sample));

        let overflowed = project_blob_deletion_age(
            BlobDeletionAge {
                cumulative_age_ms: u64::MAX - 4,
                checkpoint: Some(CustodySample {
                    clock_id: new_domain.last_sample.clock_id,
                    tick_ms: 0,
                }),
                continuity_generation: new_domain.generation,
                continuity_lost: false,
            },
            Some(new_domain),
            Some(CustodySample {
                clock_id: new_domain.last_sample.clock_id,
                tick_ms: 5,
            }),
        )
        .expect("saturate deletion age overflow");
        assert_eq!(overflowed.cumulative_age_ms, u64::MAX);
        assert!(overflowed.continuity_lost);

        let exhausted = BlobDeletionContinuity {
            generation: u64::MAX,
            last_sample: new_domain.last_sample,
        };
        let exhausted_encoded = encode_continuity(exhausted);
        write
            .open_table(BLOB_DELETION_CONTINUITY)
            .expect("exhausted continuity table")
            .insert(CONTINUITY_KEY, exhausted_encoded.as_slice())
            .expect("install exhausted continuity generation");
        assert!(
            observe_blob_deletion_continuity_write(
                &write,
                CustodySample {
                    clock_id: [0xc3; 16],
                    tick_ms: 0,
                },
            )
            .is_err(),
            "continuity generation overflow must fail closed",
        );
        assert_eq!(
            advance_blob_deletion_maintenance_turn(&write)
                .expect("advance durable deletion maintenance turn"),
            1
        );
        write.commit().expect("commit new deletion clock domain");
    }
}
