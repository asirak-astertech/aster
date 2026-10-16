//! Profile-5 whole-carrier stream layout, batching, and durable checkpoints.

use super::*;
use aster_mesh::{
    BlobStore as CoreBlobStore, BlobStreamLayout, OwnedBlobStreamExtent,
    VerifiedBlobContentCompletion, VerifiedBlobStreamExtent, VerifiedBlobTransferObject,
};
use std::time::Duration;

pub const DEFAULT_BLOB_STREAM_CHECKPOINT_BATCH_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_BLOB_STREAM_CHECKPOINT_BATCH_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_BLOB_STREAM_CHECKPOINT_INTERVAL: Duration = Duration::from_millis(250);

const CHECKPOINT_VERSION: u8 = 1;
const CHECKPOINT_BYTES: usize = 1 + 8 + 8 + 8;

/// One receiver-durable carrier boundary for an exact pending source.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlobStreamCheckpoint {
    pub next_carrier_index: u64,
    pub durable_encoded_offset: u64,
    pub generation: u64,
}

impl BlobStreamCheckpoint {
    fn encode(self) -> [u8; CHECKPOINT_BYTES] {
        let mut bytes = [0; CHECKPOINT_BYTES];
        bytes[0] = CHECKPOINT_VERSION;
        bytes[1..9].copy_from_slice(&self.next_carrier_index.to_be_bytes());
        bytes[9..17].copy_from_slice(&self.durable_encoded_offset.to_be_bytes());
        bytes[17..25].copy_from_slice(&self.generation.to_be_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let bytes: [u8; CHECKPOINT_BYTES] = bytes.try_into().map_err(|_| checkpoint_error())?;
        if bytes[0] != CHECKPOINT_VERSION {
            return Err(checkpoint_error());
        }
        Ok(Self {
            next_carrier_index: u64::from_be_bytes(bytes[1..9].try_into().unwrap()),
            durable_encoded_offset: u64::from_be_bytes(bytes[9..17].try_into().unwrap()),
            generation: u64::from_be_bytes(bytes[17..25].try_into().unwrap()),
        })
    }
}

/// Complete verified carriers accumulated across one or more bounded extents.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedBlobStreamCheckpointBatch {
    first_carrier_index: u64,
    encoded_offset: u64,
    carriers: Vec<VerifiedBlobTransferObject>,
    encoded_len: u64,
}

impl VerifiedBlobStreamCheckpointBatch {
    pub fn from_extents(
        extents: impl IntoIterator<Item = VerifiedBlobStreamExtent>,
        advertised_limit: usize,
    ) -> Result<Self, StoreError> {
        let limit = advertised_limit.min(MAX_BLOB_STREAM_CHECKPOINT_BATCH_BYTES);
        if limit == 0 {
            return Err(checkpoint_error());
        }
        let mut first = None;
        let mut next = 0_u64;
        let mut offset = 0_u64;
        let mut encoded_len = 0_u64;
        let mut carriers = Vec::new();
        for extent in extents {
            if first.is_none() {
                first = Some(extent.first_carrier_index());
                next = extent.first_carrier_index();
                offset = extent.encoded_offset();
            }
            if extent.first_carrier_index() != next
                || extent.encoded_offset()
                    != offset
                        .checked_add(encoded_len)
                        .ok_or_else(checkpoint_error)?
            {
                return Err(checkpoint_error());
            }
            encoded_len = encoded_len
                .checked_add(extent.encoded_len())
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            if encoded_len > limit as u64 {
                return Err(checkpoint_error());
            }
            next = extent.next_carrier_index();
            carriers.extend_from_slice(extent.carriers());
        }
        let first_carrier_index = first.ok_or_else(checkpoint_error)?;
        if carriers.is_empty() || encoded_len == 0 {
            return Err(checkpoint_error());
        }
        Ok(Self {
            first_carrier_index,
            encoded_offset: offset,
            carriers,
            encoded_len,
        })
    }

    pub const fn first_carrier_index(&self) -> u64 {
        self.first_carrier_index
    }
    pub const fn encoded_offset(&self) -> u64 {
        self.encoded_offset
    }
    pub const fn encoded_len(&self) -> u64 {
        self.encoded_len
    }
    pub fn carriers(&self) -> &[VerifiedBlobTransferObject] {
        &self.carriers
    }
    pub fn next_carrier_index(&self) -> u64 {
        self.first_carrier_index
            .saturating_add(self.carriers.len() as u64)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobStreamCommitOutcome {
    Advanced(BlobStreamCheckpoint),
    Duplicate(BlobStreamCheckpoint),
    Complete(BlobStreamCheckpoint),
}

fn checkpoint_error() -> StoreError {
    blob_error(BlobStoreError::InvalidCarrierRange(
        "Blob stream checkpoint is not one exact forward carrier boundary",
    ))
}

impl Store {
    /// Loads the one constant-sized cumulative checkpoint for a pending source.
    pub fn blob_stream_checkpoint_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        source: BlobTransferId,
        plan: &VerifiedBlobTransferPlan,
    ) -> Result<BlobStreamCheckpoint, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        let pending = read
            .open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|row| decode_pending_blob_source(row.value()))
            .transpose()?
            .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
        require_blob_lifetime_visible_read(&read, pending.metadata.lifetime)?;
        enforce_blob_policy_read(&read, authority, policy, &pending.metadata.header)?;
        require_pending_blob_plan(&pending, plan)?;
        let checkpoint = read
            .open_table(BLOB_STREAM_CHECKPOINTS)?
            .get(source.as_bytes().as_slice())?
            .map(|row| BlobStreamCheckpoint::decode(row.value()))
            .transpose()?
            .unwrap_or_default();
        let layout = BlobStreamLayout::from_plan(plan)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        if !layout.contains_checkpoint(
            checkpoint.next_carrier_index,
            checkpoint.durable_encoded_offset,
        ) {
            return Err(checkpoint_error());
        }
        Ok(checkpoint)
    }

    /// Installs a bounded whole-carrier batch and advances the cumulative
    /// checkpoint only after every carrier is durable.
    pub fn commit_blob_stream_batch_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        source: BlobTransferId,
        plan: &VerifiedBlobTransferPlan,
        expected: BlobStreamCheckpoint,
        batch: VerifiedBlobStreamCheckpointBatch,
    ) -> Result<BlobStreamCommitOutcome, StoreError> {
        let current = self.blob_stream_checkpoint_with_policy(policy, source, plan)?;
        let layout = BlobStreamLayout::from_plan(plan)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        let batch_end = batch
            .encoded_offset()
            .checked_add(batch.encoded_len())
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        if batch.next_carrier_index() == current.next_carrier_index
            && batch_end == current.durable_encoded_offset
            && batch.first_carrier_index() < current.next_carrier_index
        {
            // A crash may commit the terminal markers/checkpoint immediately
            // before the idempotent finalization transaction. Exact replay
            // completes that last local step without moving the checkpoint.
            if current.next_carrier_index == layout.carrier_count() {
                let mut depot = BlobDepot::open_network_mutation(self, false)?;
                CoreBlobStore::begin_blob_with_lineage(
                    &mut depot,
                    plan.manifest(),
                    plan.physical_lineage(),
                )?;
                CoreBlobStore::finalize_blob(
                    &mut depot,
                    plan.manifest().id(),
                    *plan.manifest_digest(),
                )?;
            }
            return Ok(BlobStreamCommitOutcome::Duplicate(current));
        }
        if current != expected
            || batch.first_carrier_index() != current.next_carrier_index
            || batch.encoded_offset() != current.durable_encoded_offset
            || !layout.contains_checkpoint(batch.next_carrier_index(), batch_end)
        {
            return Err(checkpoint_error());
        }

        let mut depot = BlobDepot::open_network_mutation(self, false)?;
        CoreBlobStore::begin_blob_with_lineage(
            &mut depot,
            plan.manifest(),
            plan.physical_lineage(),
        )?;
        for (position, carrier) in batch.carriers().iter().enumerate() {
            let index = batch
                .first_carrier_index()
                .checked_add(position as u64)
                .ok_or(StoreError::ItemCountAccountingOverflow)?;
            if carrier.index() != index {
                return Err(checkpoint_error());
            }
        }
        let prepared = depot.prepare_verified_stream_batch(batch.carriers())?;
        let complete = batch.next_carrier_index() == layout.carrier_count();

        let checkpoint = BlobStreamCheckpoint {
            next_carrier_index: batch.next_carrier_index(),
            durable_encoded_offset: batch_end,
            generation: current
                .generation
                .checked_add(1)
                .ok_or_else(checkpoint_error)?,
        };
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        let pending = write
            .open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|row| decode_pending_blob_source(row.value()))
            .transpose()?
            .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
        require_blob_lifetime_visible_write(&write, pending.metadata.lifetime)?;
        enforce_blob_policy_write(
            &write,
            self.require_bound_mission()?,
            policy,
            &pending.metadata.header,
        )?;
        require_pending_blob_plan(&pending, plan)?;
        let durable = write
            .open_table(BLOB_STREAM_CHECKPOINTS)?
            .get(source.as_bytes().as_slice())?
            .map(|row| BlobStreamCheckpoint::decode(row.value()))
            .transpose()?
            .unwrap_or_default();
        if durable != current {
            return Err(checkpoint_error());
        }
        let variant = blob_variant_id(
            plan.manifest().id(),
            plan.manifest().content_group(),
            plan.manifest().content_epoch(),
        );
        depot::commit_prepared_stream_markers_write(&write, variant, &prepared)?;
        let encoded = checkpoint.encode();
        write
            .open_table(BLOB_STREAM_CHECKPOINTS)?
            .insert(source.as_bytes().as_slice(), encoded.as_slice())?;
        write.commit()?;
        if complete {
            CoreBlobStore::finalize_blob(
                &mut depot,
                plan.manifest().id(),
                *plan.manifest_digest(),
            )?;
        }
        drop(depot);
        Ok(if complete {
            BlobStreamCommitOutcome::Complete(checkpoint)
        } else {
            BlobStreamCommitOutcome::Advanced(checkpoint)
        })
    }

    /// Reads complete canonical carriers from one authenticated local source.
    pub fn read_completed_blob_stream_extent_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        completion: &VerifiedBlobContentCompletion,
        plan: &VerifiedBlobTransferPlan,
        checkpoint: BlobStreamCheckpoint,
        max_bytes: usize,
    ) -> Result<Option<OwnedBlobStreamExtent>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let layout = BlobStreamLayout::from_plan(plan)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        if completion.mission_authority_id() != authority
            || completion.source_envelope() != plan.source_envelope()
            || completion.blob_id() != plan.manifest().id()
            || completion.manifest_digest() != plan.manifest_digest()
            || completion.physical_lineage() != plan.physical_lineage()
            || completion.chunk_count() != plan.manifest().chunk_count()
            || completion.plaintext_bytes() != plan.manifest().total_len()
            || !layout.contains_checkpoint(
                checkpoint.next_carrier_index,
                checkpoint.durable_encoded_offset,
            )
        {
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        let source = BlobTransferId::new(plan.source_envelope().into_bytes());
        let read = self.database.begin_read()?;
        let stored = completed_blob_range_source_snapshot_read(&read, source)
            .map_err(|error| {
                blob_preflight_decode_error(error, "completed Blob stream source is malformed")
            })?
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        require_blob_lifetime_visible_read(&read, stored.metadata.lifetime)?;
        enforce_blob_policy_read(&read, authority, policy, &stored.metadata.header)?;
        drop(read);
        let mut depot = self.blob_depot()?;
        CoreBlobStore::select_blob_for_read_with_lineage(
            &mut depot,
            plan.manifest(),
            plan.physical_lineage(),
        )?;
        plan.read_stream_extent(&mut depot, checkpoint.next_carrier_index, max_bytes)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_stream_checkpoint_encoding_is_constant_sized_and_canonical() {
        let checkpoint = BlobStreamCheckpoint {
            next_carrier_index: 17,
            durable_encoded_offset: 1_u64 << 30,
            generation: 9,
        };
        let encoded = checkpoint.encode();
        assert_eq!(encoded.len(), CHECKPOINT_BYTES);
        assert_eq!(BlobStreamCheckpoint::decode(&encoded).unwrap(), checkpoint);
        assert!(BlobStreamCheckpoint::decode(&encoded[..24]).is_err());
    }
}
