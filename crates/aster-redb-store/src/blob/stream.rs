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
    pub(crate) fn encode(self) -> [u8; CHECKPOINT_BYTES] {
        let mut bytes = [0; CHECKPOINT_BYTES];
        bytes[0] = CHECKPOINT_VERSION;
        bytes[1..9].copy_from_slice(&self.next_carrier_index.to_be_bytes());
        bytes[9..17].copy_from_slice(&self.durable_encoded_offset.to_be_bytes());
        bytes[17..25].copy_from_slice(&self.generation.to_be_bytes());
        bytes
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
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

/// Result of the one-way pending-source provenance transition into profile 5.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobStreamProvenanceUpgrade {
    AlreadyV9(BlobStreamCheckpoint),
    Upgraded(BlobStreamCheckpoint),
}

fn checkpoint_error() -> StoreError {
    blob_error(BlobStoreError::InvalidCarrierRange(
        "Blob stream checkpoint is not one exact forward carrier boundary",
    ))
}

impl Store {
    /// Stages a new durable semantic-v9/profile-5 source under the configured
    /// physical depot byte/chunk limits and creates its initial checkpoint in
    /// the same transaction.
    pub fn stage_verified_durable_blob_stream_v9_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        blob: &ContentVerifiedBlobEnvelope,
        sealed: &[u8],
        plan: &VerifiedBlobTransferPlan,
    ) -> Result<BlobSourceStageOutcome, StoreError> {
        if blob.ttl_ms().is_some() {
            return Err(blob_error(BlobStoreError::InvalidPublication(
                "finite Blob stream requires authenticated custody-v2 authority",
            )));
        }
        self.stage_verified_blob_source_with_lifetime_and_profile(
            policy,
            blob,
            sealed,
            plan,
            None,
            BlobNetworkAdmissionProfile::StreamV1,
        )
    }

    /// Stages a new finite semantic-v9/profile-5 source while preserving the
    /// authenticated lower-bound age and a receiver-local continuity sample.
    #[allow(clippy::too_many_arguments)]
    pub fn stage_verified_finite_blob_stream_v9_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        blob: &ContentVerifiedBlobEnvelope,
        sealed: &[u8],
        plan: &VerifiedBlobTransferPlan,
        claim: BlobCustodyClaimV2,
        contact: AuthenticatedBlobCustodyContactV2,
        receiver_sample: aster_mesh::CustodySample,
    ) -> Result<BlobSourceStageOutcome, StoreError> {
        let transfer = BlobTransferId::new(blob.envelope_id());
        let verified = claim
            .verify_authenticated_source(
                contact,
                claim.exchange_id(),
                BlobCustodyTransferId::from_exact_hash(*transfer.as_bytes()),
                blob,
                sealed,
                0,
            )
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        let admission = VerifiedFiniteBlobAdmission {
            source_transfer_id: *verified.source_transfer_id().as_bytes(),
            source_len: verified.source_len(),
            publication_id: verified.publication_id(),
            blob_id: verified.blob_id(),
            priority: verified.priority(),
            ttl_ms: verified.ttl_ms(),
            forwarding_age_ms: verified.forwarding_age_ms(),
            receiver_sample,
            provenance: BlobFiniteProvenance::NetworkV1 {
                semantic_version: 9,
                profile_id: aster_mesh::TransferProfileId::BlobStreamV1 as u16,
            },
        };
        self.stage_verified_blob_source_with_lifetime_and_profile(
            policy,
            blob,
            sealed,
            plan,
            Some(admission),
            BlobNetworkAdmissionProfile::StreamV1,
        )
    }

    /// Atomically upgrades an exact profile-4 pending source to semantic-v9
    /// profile-5 authority. Finite work must carry a freshly authenticated,
    /// non-younger v2 claim; durable work carries no synthetic TTL authority.
    pub fn upgrade_pending_blob_to_stream_v9(
        &self,
        policy: &ControlPolicySnapshot,
        source: BlobTransferId,
        blob: &ContentVerifiedBlobEnvelope,
        sealed: &[u8],
        plan: &VerifiedBlobTransferPlan,
        finite: Option<(BlobCustodyClaimV2, AuthenticatedBlobCustodyContactV2)>,
    ) -> Result<BlobStreamProvenanceUpgrade, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        blob.verify_exact_sealed(sealed)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        blob.verify_exact_manifest(plan.manifest_bytes())
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        if BlobTransferId::new(blob.envelope_id()) != source
            || plan.source_envelope().into_bytes() != *source.as_bytes()
            || plan.manifest() != blob.manifest()
            || plan.manifest_digest() != blob.manifest_digest()
            || plan.physical_lineage() != blob.physical_lineage()
        {
            return Err(blob_error(BlobStoreError::PendingSourceConflict));
        }

        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        synchronize_blob_policy_generation_write(&write)?;
        let encoded = write
            .open_table(BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|row| row.value().to_vec())
            .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
        let mut pending = decode_pending_blob_source(&encoded)?;
        require_pending_matches_verified_source(&pending, blob, sealed)?;
        require_pending_blob_plan(&pending, plan)?;
        require_blob_lifetime_visible_write(&write, pending.metadata.lifetime)?;
        enforce_blob_policy_write(&write, authority, policy, &pending.metadata.header)?;
        pressure::require_pending_source_write(&write, source, &pending)?;
        pressure::require_variant_write(&write, pending.metadata.variant_id)?;

        let existing_checkpoint = write
            .open_table(BLOB_STREAM_CHECKPOINTS)?
            .get(source.as_bytes().as_slice())?
            .map(|row| BlobStreamCheckpoint::decode(row.value()))
            .transpose()?;
        let already_v9 = match pending.metadata.lifetime {
            BlobLifetime::Durable => existing_checkpoint.is_some(),
            BlobLifetime::Finite { provenance, .. } => {
                existing_checkpoint.is_some()
                    && matches!(
                        provenance,
                        BlobFiniteProvenance::NetworkV1 {
                            semantic_version: 9,
                            profile_id
                        } if profile_id == aster_mesh::TransferProfileId::BlobStreamV1 as u16
                    )
            }
        };
        if already_v9 {
            if finite.is_some() && matches!(pending.metadata.lifetime, BlobLifetime::Durable) {
                return Err(blob_error(BlobStoreError::PendingSourceConflict));
            }
            return Ok(BlobStreamProvenanceUpgrade::AlreadyV9(
                existing_checkpoint.unwrap_or_default(),
            ));
        }

        match pending.metadata.lifetime {
            BlobLifetime::Durable => {
                if finite.is_some() {
                    return Err(blob_error(BlobStoreError::PendingSourceConflict));
                }
            }
            BlobLifetime::Finite {
                ttl_ms,
                mut age,
                provenance,
            } => {
                let upgradable = match provenance {
                    BlobFiniteProvenance::Local => true,
                    BlobFiniteProvenance::NetworkV1 {
                        semantic_version: 8,
                        profile_id,
                    } => profile_id == aster_mesh::TransferProfileId::BlobRangesStreamV1 as u16,
                    BlobFiniteProvenance::NetworkV1 { .. } => false,
                };
                if !upgradable {
                    return Err(blob_error(BlobStoreError::PendingSourceConflict));
                }
                let (claim, contact) =
                    finite.ok_or_else(|| blob_error(BlobStoreError::PendingSourceConflict))?;
                let verified = claim
                    .verify_authenticated_source(
                        contact,
                        claim.exchange_id(),
                        BlobCustodyTransferId::from_exact_hash(*source.as_bytes()),
                        blob,
                        sealed,
                        age.cumulative_age_ms,
                    )
                    .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
                if verified.ttl_ms() != ttl_ms {
                    return Err(blob_error(BlobStoreError::PendingSourceConflict));
                }
                age.cumulative_age_ms = age.cumulative_age_ms.max(verified.forwarding_age_ms());
                pending.metadata.lifetime = BlobLifetime::Finite {
                    ttl_ms,
                    age,
                    provenance: BlobFiniteProvenance::NetworkV1 {
                        semantic_version: 9,
                        profile_id: aster_mesh::TransferProfileId::BlobStreamV1 as u16,
                    },
                };
            }
        }
        pending.metadata.lifetime =
            lifecycle::project_lifetime_for_policy_write(&write, pending.metadata.lifetime)?;
        pending.authenticated_source_binding =
            pending_blob_authenticated_source_binding(&pending.metadata, &pending.sealed)?;
        let replacement = encode_pending_blob_source(&pending)?;
        write
            .open_table(BLOB_PENDING_SOURCES)?
            .insert(source.as_bytes().as_slice(), replacement.as_slice())?;
        pressure::rekey_pending_source_lifetime_write(&write, source, &pending)?;

        let previous = existing_checkpoint.unwrap_or_default();
        let checkpoint = BlobStreamCheckpoint {
            generation: previous
                .generation
                .checked_add(1)
                .ok_or_else(checkpoint_error)?,
            ..previous
        };
        let layout = BlobStreamLayout::from_plan(plan)
            .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?;
        if !layout.contains_checkpoint(
            checkpoint.next_carrier_index,
            checkpoint.durable_encoded_offset,
        ) {
            return Err(checkpoint_error());
        }
        let encoded = checkpoint.encode();
        write
            .open_table(BLOB_STREAM_CHECKPOINTS)?
            .insert(source.as_bytes().as_slice(), encoded.as_slice())?;
        write.commit()?;
        Ok(BlobStreamProvenanceUpgrade::Upgraded(checkpoint))
    }

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
        require_blob_contact_eligibility(
            pending.metadata.lifetime,
            BlobContactEligibility::CustodyV2,
        )?;
        require_blob_lifetime_visible_read(&read, pending.metadata.lifetime)?;
        enforce_blob_policy_read(&read, authority, policy, &pending.metadata.header)?;
        require_pending_blob_plan(&pending, plan)?;
        let checkpoint = read
            .open_table(BLOB_STREAM_CHECKPOINTS)?
            .get(source.as_bytes().as_slice())?
            .map(|row| BlobStreamCheckpoint::decode(row.value()))
            .transpose()?
            .unwrap_or_default();
        if checkpoint.generation == 0 {
            return Err(blob_error(BlobStoreError::ReadPlanChanged));
        }
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
                let variant = blob_variant_id(
                    plan.manifest().id(),
                    plan.manifest().content_group(),
                    plan.manifest().content_epoch(),
                );
                let mut depot = BlobDepot::open_network_mutation(self, false)?;
                depot.acquire_carrier_extent_lease(variant)?;
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

        let variant = blob_variant_id(
            plan.manifest().id(),
            plan.manifest().content_group(),
            plan.manifest().content_epoch(),
        );
        let mut depot = BlobDepot::open_network_mutation(self, false)?;
        depot.acquire_carrier_extent_lease(variant)?;
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
        require_blob_contact_eligibility(
            pending.metadata.lifetime,
            BlobContactEligibility::CustodyV2,
        )?;
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
        require_blob_contact_eligibility(
            stored.metadata.lifetime,
            BlobContactEligibility::CustodyV2,
        )?;
        require_blob_lifetime_visible_read(&read, stored.metadata.lifetime)?;
        enforce_blob_policy_read(&read, authority, policy, &stored.metadata.header)?;
        drop(read);
        let variant = blob_variant_id(
            plan.manifest().id(),
            plan.manifest().content_group(),
            plan.manifest().content_epoch(),
        );
        let mut depot = self.blob_depot()?;
        depot.acquire_carrier_extent_lease(variant)?;
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
