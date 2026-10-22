//! Profile-5 receiver checkpoint authority for canonical Blob transfers.

use super::{
    BLOB_PROFILE5_RECEIPTS, BlobStoreError, BlobTransferId, Store, blob_error,
    synchronize_blob_policy_generation_write,
};
use crate::{ControlPolicySnapshot, StoreError, enforce_live_write, require_control_policy_write};
use aster_mesh::{NodeId, VerifiedBlobTransferPlan};
use redb::{Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata};
use sha2::{Digest, Sha256};

const PROFILE5_RECEIPT_MAGIC: &[u8; 8] = b"ASTRP5R1";
const PROFILE5_RECEIPT_VERSION: u8 = 1;
const PROFILE5_RECEIPT_KEY_BYTES: u64 = 64;
const PROFILE5_RECEIPT_VALUE_BYTES: u64 = 209;
/// Profile-5 settlement receipts share the existing durable acknowledgement
/// ledger ceiling: both retain one fixed-size idempotency authority per source.
pub const MAX_BLOB_PROFILE5_RECEIPTS: u64 =
    crate::blob_subscription::MAX_BLOB_ACKNOWLEDGEMENT_RECEIPTS;
pub const MAX_BLOB_PROFILE5_RECEIPT_BYTES: u64 =
    MAX_BLOB_PROFILE5_RECEIPTS * (PROFILE5_RECEIPT_KEY_BYTES + PROFILE5_RECEIPT_VALUE_BYTES);

fn require_profile5_receipt_capacity(current: u64) -> Result<(), StoreError> {
    if current >= MAX_BLOB_PROFILE5_RECEIPTS {
        return Err(StoreError::BlobAcknowledgementReceiptLimitExceeded {
            current,
            limit: MAX_BLOB_PROFILE5_RECEIPTS,
        });
    }
    Ok(())
}

/// Durable receiver-owned progress for one canonical semantic-v9 Blob source.
///
/// This is intentionally transport/application neutral: it contains no sender
/// operation key and grants no publication authority. The canonical pending
/// source and depot remain the only content/lifecycle authorities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobProfile5Receipt {
    receiving_authority: NodeId,
    source: BlobTransferId,
    plan_binding: [u8; 32],
    store_binding: [u8; 32],
    total_len: u64,
    chunk_count: u64,
    carrier_total_len: u64,
    max_wire_len: u64,
}

impl BlobProfile5Receipt {
    pub const fn receiving_authority(&self) -> NodeId {
        self.receiving_authority
    }

    pub const fn source(&self) -> BlobTransferId {
        self.source
    }

    pub const fn plaintext_total_bytes(&self) -> u64 {
        self.total_len
    }

    pub const fn total_units(&self) -> u64 {
        self.chunk_count
    }

    pub const fn transfer_total_bytes(&self) -> u64 {
        self.max_wire_len
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Profile5ReceiptRecord {
    receipt: BlobProfile5Receipt,
    progress: BlobStreamResume,
}

fn profile5_receipt_key(authority: NodeId, source: BlobTransferId) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(&authority);
    key[32..].copy_from_slice(source.as_bytes());
    key
}

fn profile5_plan_binding(plan: &VerifiedBlobTransferPlan) -> [u8; 32] {
    profile5_plan_binding_fields(
        plan.source_envelope().into_bytes(),
        *plan.manifest_digest(),
        *plan.physical_lineage().binding(),
        plan.manifest().total_len(),
        plan.manifest().chunk_count(),
    )
}

fn profile5_plan_binding_fields(
    source: [u8; 32],
    manifest_digest: [u8; 32],
    physical_lineage: [u8; 32],
    total_len: u64,
    chunk_count: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aster/profile5-receipt-plan/v1\0");
    hasher.update(source);
    hasher.update(manifest_digest);
    hasher.update(physical_lineage);
    hasher.update(total_len.to_be_bytes());
    hasher.update(chunk_count.to_be_bytes());
    hasher.finalize().into()
}

fn profile5_max_wire_len(plan: &VerifiedBlobTransferPlan) -> Result<u64, StoreError> {
    aster_mesh::profile5_canonical_wire_shape(plan)
        .map(|shape| shape.terminal().wire_offset)
        .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))
}

impl Profile5ReceiptRecord {
    fn encode(&self) -> [u8; 209] {
        let mut out = [0u8; 209];
        out[..8].copy_from_slice(PROFILE5_RECEIPT_MAGIC);
        out[8] = PROFILE5_RECEIPT_VERSION;
        out[9..41].copy_from_slice(&self.receipt.receiving_authority);
        out[41..73].copy_from_slice(self.receipt.source.as_bytes());
        out[73..105].copy_from_slice(&self.receipt.plan_binding);
        out[105..137].copy_from_slice(&self.receipt.store_binding);
        for (offset, value) in [
            (137, self.receipt.total_len),
            (145, self.receipt.chunk_count),
            (153, self.receipt.carrier_total_len),
            (161, self.receipt.max_wire_len),
            (169, self.progress.generation),
            (177, self.progress.next_segment_index),
            (185, self.progress.durable_plaintext_offset),
            (193, self.progress.durable_pack_len),
            (201, self.progress.durable_wire_offset),
        ] {
            out[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
        }
        out
    }

    fn decode(encoded: &[u8]) -> Result<Self, StoreError> {
        if encoded.len() != 209
            || &encoded[..8] != PROFILE5_RECEIPT_MAGIC
            || encoded[8] != PROFILE5_RECEIPT_VERSION
        {
            return Err(schema_error());
        }
        let record = Self {
            receipt: BlobProfile5Receipt {
                receiving_authority: read_array(encoded, 9)?,
                source: BlobTransferId::new(read_array(encoded, 41)?),
                plan_binding: read_array(encoded, 73)?,
                store_binding: read_array(encoded, 105)?,
                total_len: read_u64(encoded, 137)?,
                chunk_count: read_u64(encoded, 145)?,
                carrier_total_len: read_u64(encoded, 153)?,
                max_wire_len: read_u64(encoded, 161)?,
            },
            progress: BlobStreamResume {
                generation: read_u64(encoded, 169)?,
                next_segment_index: read_u64(encoded, 177)?,
                durable_plaintext_offset: read_u64(encoded, 185)?,
                durable_pack_len: read_u64(encoded, 193)?,
                durable_wire_offset: read_u64(encoded, 201)?,
            },
        };
        if record.receipt.plan_binding == [0; 32]
            || record.receipt.store_binding == [0; 32]
            || record.receipt.chunk_count > aster_mesh::MAX_BLOB_CHUNKS
            || record.receipt.max_wire_len
                > record
                    .receipt
                    .chunk_count
                    .checked_mul((aster_mesh::MAX_BLOB_TRANSFER_OBJECT_BYTES as u64) + 20)
                    .ok_or_else(schema_error)?
            || record.receipt.carrier_total_len > record.receipt.max_wire_len
            || record.progress.next_segment_index > record.receipt.chunk_count
            || record.progress.durable_plaintext_offset > record.receipt.total_len
            || record.progress.durable_pack_len > record.receipt.max_wire_len
            || record.progress.durable_wire_offset > record.receipt.max_wire_len
            || record.progress.durable_wire_offset < record.progress.durable_pack_len
            || (record.progress.generation == 0 && record.progress != BlobStreamResume::default())
            || (record.progress.next_segment_index == 0
                && (record.progress.durable_plaintext_offset != 0
                    || record.progress.durable_pack_len != 0
                    || record.progress.durable_wire_offset != 0))
            || (record.progress.next_segment_index == record.receipt.chunk_count
                && (record.progress.durable_plaintext_offset != record.receipt.total_len
                    || record.progress.durable_pack_len != record.receipt.carrier_total_len
                    || record.progress.durable_wire_offset != record.receipt.max_wire_len))
            || (record.progress.next_segment_index < record.receipt.chunk_count
                && (record.progress.durable_plaintext_offset >= record.receipt.total_len
                    || record.progress.durable_wire_offset >= record.receipt.max_wire_len))
        {
            return Err(schema_error());
        }
        Ok(record)
    }
}

#[cfg(test)]
pub(super) fn test_decode_profile5_receipt_progress(
    encoded: &[u8],
) -> Result<BlobStreamResume, StoreError> {
    Profile5ReceiptRecord::decode(encoded).map(|record| record.progress)
}

fn profile5_receipt_binding_from_metadata(
    metadata: &super::BlobMetadata,
    total_len: u64,
    chunk_count: u64,
) -> Result<([u8; 32], u64, u64), StoreError> {
    let route = metadata.header.blob_route.ok_or_else(schema_error)?;
    let physical_lineage = metadata.physical_lineage.ok_or_else(schema_error)?;
    if route.chunk_count() != chunk_count {
        return Err(schema_error());
    }
    Ok((
        profile5_plan_binding_fields(
            *metadata.transfer_id.as_bytes(),
            metadata.manifest_digest,
            physical_lineage,
            total_len,
            chunk_count,
        ),
        total_len,
        chunk_count,
    ))
}

fn profile5_shape_from_pending(
    pending: &super::PendingBlobSourceRecord,
    total_len: u64,
) -> Result<aster_mesh::Profile5CanonicalWireShape, StoreError> {
    let mut carriers = pending.carriers.clone();
    carriers.sort_by_key(|carrier| carrier.index);
    if carriers
        .iter()
        .enumerate()
        .any(|(index, carrier)| carrier.index != index as u64)
    {
        return Err(schema_error());
    }
    let chunk_size = u64::from(aster_mesh::MAX_BLOB_CHUNK_SIZE);
    let lengths = carriers
        .iter()
        .map(|carrier| {
            let offset = carrier
                .index
                .checked_mul(chunk_size)
                .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            let plaintext = total_len
                .checked_sub(offset)
                .ok_or_else(schema_error)?
                .min(chunk_size);
            if plaintext == 0 {
                return Err(schema_error());
            }
            Ok((plaintext, carrier.total_len))
        })
        .collect::<Result<Vec<_>, StoreError>>()?;
    aster_mesh::profile5_canonical_wire_shape_from_lengths(&lengths).map_err(|_| schema_error())
}

fn profile5_progress_checkpoint(
    progress: BlobStreamResume,
) -> aster_mesh::Profile5CanonicalCheckpoint {
    aster_mesh::Profile5CanonicalCheckpoint {
        next_chunk_index: progress.next_segment_index,
        plaintext_offset: progress.durable_plaintext_offset,
        carrier_offset: progress.durable_pack_len,
        wire_offset: progress.durable_wire_offset,
    }
}

fn profile5_progress_matches_shape(
    shape: &aster_mesh::Profile5CanonicalWireShape,
    progress: BlobStreamResume,
) -> bool {
    shape
        .checkpoints()
        .iter()
        .position(|checkpoint| *checkpoint == profile5_progress_checkpoint(progress))
        .is_some_and(|index| progress.generation == index as u64)
}

pub(super) fn audit_profile5_receipts(
    receipts: &impl ReadableTable<&'static [u8], &'static [u8]>,
    pending: &impl ReadableTable<&'static [u8], &'static [u8]>,
    publications: &impl ReadableTable<&'static [u8], &'static [u8]>,
    imports: &impl ReadableTable<&'static [u8], &'static [u8]>,
    chunks: &impl ReadableTable<&'static [u8], &'static [u8]>,
    mission_authority: Option<NodeId>,
    owner_binding: Option<[u8; 32]>,
    pending_encoding: super::PendingBlobEncodingGeneration,
    publication_encoding: super::lifecycle::PublicationEncodingGeneration,
) -> Result<(), StoreError> {
    let rows = receipts.len()?;
    let bytes = rows
        .checked_mul(PROFILE5_RECEIPT_KEY_BYTES + PROFILE5_RECEIPT_VALUE_BYTES)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    if rows > MAX_BLOB_PROFILE5_RECEIPTS || bytes > MAX_BLOB_PROFILE5_RECEIPT_BYTES {
        return Err(schema_error());
    }
    if rows != 0 && (mission_authority.is_none() || owner_binding.is_none()) {
        return Err(schema_error());
    }
    for row in receipts.iter()? {
        let (key, value) = row?;
        let key: [u8; 64] = key.value().try_into().map_err(|_| schema_error())?;
        if value.value().len() as u64 != PROFILE5_RECEIPT_VALUE_BYTES {
            return Err(schema_error());
        }
        let record = Profile5ReceiptRecord::decode(value.value())?;
        let authority = mission_authority.ok_or_else(schema_error)?;
        let owner = owner_binding.ok_or_else(schema_error)?;
        if record.receipt.receiving_authority != authority
            || record.receipt.store_binding != owner
            || profile5_receipt_key(authority, record.receipt.source) != key
        {
            return Err(schema_error());
        }
        let source_key = record.receipt.source.as_bytes().as_slice();
        let pending_record = pending
            .get(source_key)?
            .map(|value| {
                super::decode_pending_blob_source_for_encoding(value.value(), pending_encoding)
            })
            .transpose()?;
        let publication = publications
            .get(source_key)?
            .map(|value| {
                super::decode_blob_metadata_for_encoding(value.value(), publication_encoding)
            })
            .transpose()?;
        if pending_record.is_some() == publication.is_some() {
            return Err(schema_error());
        }
        let metadata = pending_record
            .as_ref()
            .map(|pending| &pending.metadata)
            .or(publication.as_ref())
            .ok_or_else(schema_error)?;
        let import = imports
            .get(metadata.variant_id.as_bytes().as_slice())?
            .map(|value| value.value().to_vec())
            .ok_or_else(schema_error)?;
        let (total_len, chunk_count) = if pending_record.is_some() {
            super::depot::profile5_pending_import_shape_evidence(&import, metadata)?
        } else {
            super::depot::profile5_import_shape_evidence(&import, metadata)?
        };
        let (binding, total_len, chunk_count) =
            profile5_receipt_binding_from_metadata(metadata, total_len, chunk_count)?;
        let exact_shape = super::depot::profile5_import_wire_shape_evidence(
            &import,
            chunks,
            metadata,
            publication.is_some(),
        )?;
        if record.receipt.plan_binding != binding
            || record.receipt.total_len != total_len
            || record.receipt.chunk_count != chunk_count
        {
            return Err(schema_error());
        }
        if let Some(pending) = pending_record.as_ref() {
            let shape = profile5_shape_from_pending(pending, total_len)?;
            if shape != exact_shape
                || record.receipt.max_wire_len != shape.terminal().wire_offset
                || record.receipt.carrier_total_len != shape.terminal().carrier_offset
                || !profile5_progress_matches_shape(&shape, record.progress)
            {
                return Err(schema_error());
            }
        } else if !profile5_progress_matches_shape(&exact_shape, record.progress)
            || record.receipt.max_wire_len != exact_shape.terminal().wire_offset
            || record.receipt.carrier_total_len != exact_shape.terminal().carrier_offset
            || record.progress.next_segment_index != chunk_count
            || record.progress.durable_plaintext_offset != total_len
            || record.progress.durable_pack_len != record.receipt.carrier_total_len
            || record.progress.durable_wire_offset != record.receipt.max_wire_len
        {
            return Err(schema_error());
        }
    }
    Ok(())
}

pub(super) fn profile5_receipt_expiry_charge_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
) -> Result<(u64, u64), StoreError> {
    let Some(authority) = super::read_mission_binding(write)? else {
        return Err(StoreError::MissionNotBound);
    };
    let key = profile5_receipt_key(authority, transfer);
    let value = write
        .open_table(BLOB_PROFILE5_RECEIPTS)?
        .get(key.as_slice())?
        .map(|value| value.value().to_vec());
    let Some(value) = value else {
        return Ok((0, 0));
    };
    let record = Profile5ReceiptRecord::decode(&value)?;
    if record.receipt.receiving_authority != authority || record.receipt.source != transfer {
        return Err(schema_error());
    }
    Ok((1, PROFILE5_RECEIPT_KEY_BYTES + PROFILE5_RECEIPT_VALUE_BYTES))
}

pub(super) fn profile5_receipt_maintenance_row_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
) -> Result<Option<([u8; 64], usize)>, StoreError> {
    let Some(authority) = super::read_mission_binding(write)? else {
        return Err(StoreError::MissionNotBound);
    };
    let key = profile5_receipt_key(authority, transfer);
    let value = write
        .open_table(BLOB_PROFILE5_RECEIPTS)?
        .get(key.as_slice())?
        .map(|value| value.value().to_vec());
    let Some(value) = value else {
        return Ok(None);
    };
    let record = Profile5ReceiptRecord::decode(&value)?;
    if record.receipt.receiving_authority != authority || record.receipt.source != transfer {
        return Err(schema_error());
    }
    Ok(Some((key, value.len())))
}

pub(super) fn expire_profile5_receipt_write(
    write: &redb::WriteTransaction,
    transfer: BlobTransferId,
) -> Result<(u64, u64), StoreError> {
    let charge = profile5_receipt_expiry_charge_write(write, transfer)?;
    if charge.0 == 0 {
        return Ok(charge);
    }
    let authority = super::read_mission_binding(write)?.ok_or(StoreError::MissionNotBound)?;
    let key = profile5_receipt_key(authority, transfer);
    write
        .open_table(BLOB_PROFILE5_RECEIPTS)?
        .remove(key.as_slice())?
        .ok_or_else(schema_error)?;
    Ok(charge)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlobStreamResume {
    generation: u64,
    next_segment_index: u64,
    durable_plaintext_offset: u64,
    durable_pack_len: u64,
    durable_wire_offset: u64,
}

impl BlobStreamResume {
    #[doc(hidden)]
    pub const fn profile5(
        generation: u64,
        next_chunk_index: u64,
        durable_plaintext_offset: u64,
        durable_carrier_bytes: u64,
        durable_wire_offset: u64,
    ) -> Self {
        Self {
            generation,
            next_segment_index: next_chunk_index,
            durable_plaintext_offset,
            durable_pack_len: durable_carrier_bytes,
            durable_wire_offset,
        }
    }

    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn next_segment_index(self) -> u64 {
        self.next_segment_index
    }

    pub const fn durable_plaintext_offset(self) -> u64 {
        self.durable_plaintext_offset
    }

    pub const fn durable_pack_len(self) -> u64 {
        self.durable_pack_len
    }

    pub const fn durable_wire_offset(self) -> u64 {
        self.durable_wire_offset
    }
}
fn schema_error() -> StoreError {
    blob_error(BlobStoreError::SchemaInvariant(
        "provisional Blob stream row is malformed",
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, StoreError> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], StoreError> {
    bytes
        .get(offset..offset.checked_add(N).ok_or_else(schema_error)?)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(schema_error)
}

impl Store {
    /// Reserves receiver-owned profile-5 progress for an already authenticated
    /// canonical pending source. This row is checkpoint authority only.
    pub fn reserve_profile5_receipt(
        &self,
        policy: &ControlPolicySnapshot,
        plan: &VerifiedBlobTransferPlan,
    ) -> Result<(BlobProfile5Receipt, BlobStreamResume), StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let source = BlobTransferId::new(plan.source_envelope().into_bytes());
        let key = profile5_receipt_key(authority, source);
        let receipt = BlobProfile5Receipt {
            receiving_authority: authority,
            source,
            plan_binding: profile5_plan_binding(plan),
            store_binding: self.blob_depot_owner_binding,
            total_len: plan.manifest().total_len(),
            chunk_count: plan.manifest().chunk_count(),
            carrier_total_len: aster_mesh::profile5_canonical_wire_shape(plan)
                .map_err(|error| blob_error(BlobStoreError::Verification(error.to_string())))?
                .terminal()
                .carrier_offset,
            max_wire_len: profile5_max_wire_len(plan)?,
        };
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        synchronize_blob_policy_generation_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;
        let existing = write
            .open_table(BLOB_PROFILE5_RECEIPTS)?
            .get(key.as_slice())?
            .map(|row| row.value().to_vec());
        let pending = write
            .open_table(super::BLOB_PENDING_SOURCES)?
            .get(source.as_bytes().as_slice())?
            .map(|row| super::decode_pending_blob_source(row.value()))
            .transpose()?;
        if let Some(pending) = pending.as_ref() {
            super::enforce_blob_policy_write(&write, authority, policy, &pending.metadata.header)?;
            super::require_blob_lifetime_visible_write(&write, pending.metadata.lifetime)?;
            super::require_pending_blob_plan(pending, plan)?;
        } else {
            let publication = write
                .open_table(super::BLOB_PUBLICATIONS)?
                .get(source.as_bytes().as_slice())?
                .map(|row| super::decode_blob_metadata(row.value()))
                .transpose()?
                .ok_or_else(|| blob_error(BlobStoreError::PendingSourceMissing))?;
            super::enforce_blob_policy_write(&write, authority, policy, &publication.header)?;
            super::require_blob_lifetime_visible_write(&write, publication.lifetime)?;
            let variant = super::blob_variant_id(
                plan.manifest().id(),
                plan.manifest().content_group(),
                plan.manifest().content_epoch(),
            );
            if publication.transfer_id != source
                || publication.blob_id != plan.manifest().id()
                || publication.variant_id != variant
                || publication.manifest_digest != *plan.manifest_digest()
            {
                return Err(blob_error(BlobStoreError::ReservationChanged));
            }
        }
        if let Some(encoded) = existing {
            let record = Profile5ReceiptRecord::decode(&encoded)?;
            if record.receipt != receipt {
                return Err(blob_error(BlobStoreError::ReservationChanged));
            }
            return Ok((record.receipt, record.progress));
        }
        let progress = BlobStreamResume::default();
        let record = Profile5ReceiptRecord {
            receipt: receipt.clone(),
            progress,
        };
        let mut receipts = write.open_table(BLOB_PROFILE5_RECEIPTS)?;
        let current = receipts.len()?;
        require_profile5_receipt_capacity(current)?;
        receipts.insert(key.as_slice(), record.encode().as_slice())?;
        drop(receipts);
        write.commit()?;
        Ok((receipt, progress))
    }

    /// Advances only durable, monotone receiver progress for one exact source.
    pub fn checkpoint_profile5_receipt(
        &self,
        receipt: &BlobProfile5Receipt,
        expected: BlobStreamResume,
        durable: BlobStreamResume,
    ) -> Result<BlobStreamResume, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        if receipt.receiving_authority != authority
            || receipt.store_binding != self.blob_depot_owner_binding
        {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let key = profile5_receipt_key(authority, receipt.source);
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        let encoded = write
            .open_table(BLOB_PROFILE5_RECEIPTS)?
            .get(key.as_slice())?
            .map(|row| row.value().to_vec())
            .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
        let mut record = Profile5ReceiptRecord::decode(&encoded)?;
        if record.receipt != *receipt || record.progress != expected {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let pending = write
            .open_table(super::BLOB_PENDING_SOURCES)?
            .get(receipt.source.as_bytes().as_slice())?
            .map(|row| super::decode_pending_blob_source(row.value()))
            .transpose()?;
        if durable == expected {
            return Ok(expected);
        }
        if durable.generation
            != expected
                .generation
                .checked_add(1)
                .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?
            || durable.next_segment_index < expected.next_segment_index
            || durable.durable_plaintext_offset < expected.durable_plaintext_offset
            || durable.durable_pack_len < expected.durable_pack_len
            || durable.durable_wire_offset < expected.durable_wire_offset
            || durable.next_segment_index > receipt.chunk_count
            || durable.durable_plaintext_offset > receipt.total_len
            || durable.durable_pack_len > receipt.max_wire_len
            || durable.durable_wire_offset > receipt.max_wire_len
            || durable.durable_wire_offset < durable.durable_pack_len
            || (durable.next_segment_index == receipt.chunk_count
                && (durable.durable_plaintext_offset != receipt.total_len
                    || durable.durable_wire_offset != receipt.max_wire_len))
            || (durable.next_segment_index < receipt.chunk_count
                && (durable.durable_plaintext_offset >= receipt.total_len
                    || durable.durable_wire_offset >= receipt.max_wire_len))
        {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        if let Some(pending) = pending.as_ref() {
            let shape = profile5_shape_from_pending(pending, receipt.total_len)?;
            if !profile5_progress_matches_shape(&shape, durable) {
                return Err(blob_error(BlobStoreError::ReservationChanged));
            }
        } else if profile5_progress_checkpoint(durable)
            != (aster_mesh::Profile5CanonicalCheckpoint {
                next_chunk_index: receipt.chunk_count,
                plaintext_offset: receipt.total_len,
                carrier_offset: receipt.carrier_total_len,
                wire_offset: receipt.max_wire_len,
            })
        {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        record.progress = durable;
        write
            .open_table(BLOB_PROFILE5_RECEIPTS)?
            .insert(key.as_slice(), record.encode().as_slice())?;
        write.commit()?;
        Ok(durable)
    }

    pub fn resume_profile5_receipt(
        &self,
        source: BlobTransferId,
    ) -> Result<Option<(BlobProfile5Receipt, BlobStreamResume)>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let key = profile5_receipt_key(authority, source);
        let read = self.database.begin_read()?;
        let record = read
            .open_table(BLOB_PROFILE5_RECEIPTS)?
            .get(key.as_slice())?
            .map(|row| Profile5ReceiptRecord::decode(row.value()))
            .transpose()?;
        let Some(record) = record else {
            return Ok(None);
        };
        if record.receipt.receiving_authority != authority
            || record.receipt.source != source
            || record.receipt.store_binding != self.blob_depot_owner_binding
        {
            return Err(schema_error());
        }
        Ok(Some((record.receipt, record.progress)))
    }

    /// Deletes checkpoint authority only after canonical promotion or explicit
    /// abort. Completed Blob bytes remain charged by the canonical depot.
    pub fn complete_profile5_receipt(
        &self,
        receipt: &BlobProfile5Receipt,
    ) -> Result<bool, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        if receipt.receiving_authority != authority
            || receipt.store_binding != self.blob_depot_owner_binding
        {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        let key = profile5_receipt_key(authority, receipt.source);
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        let existing = write
            .open_table(BLOB_PROFILE5_RECEIPTS)?
            .get(key.as_slice())?
            .map(|row| row.value().to_vec());
        let Some(encoded) = existing else {
            return Ok(false);
        };
        if Profile5ReceiptRecord::decode(&encoded)?.receipt != *receipt {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        write
            .open_table(BLOB_PROFILE5_RECEIPTS)?
            .remove(key.as_slice())?;
        write.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile5_receipt_identity_is_receiver_and_source_qualified() {
        let source = BlobTransferId::new([0x51; 32]);
        let first = profile5_receipt_key([0x61; 32], source);
        let second = profile5_receipt_key([0x62; 32], source);
        assert_ne!(first, second);
        assert_eq!(&first[..32], &[0x61; 32]);
        assert_eq!(&first[32..], source.as_bytes());
    }

    #[test]
    fn profile5_receipt_capacity_is_fixed_and_fail_closed() {
        assert_eq!(
            MAX_BLOB_PROFILE5_RECEIPT_BYTES,
            MAX_BLOB_PROFILE5_RECEIPTS * (64 + 209)
        );
        require_profile5_receipt_capacity(MAX_BLOB_PROFILE5_RECEIPTS - 1)
            .expect("last bounded receipt slot");
        assert!(matches!(
            require_profile5_receipt_capacity(MAX_BLOB_PROFILE5_RECEIPTS),
            Err(StoreError::BlobAcknowledgementReceiptLimitExceeded { current, limit })
                if current == limit && limit == MAX_BLOB_PROFILE5_RECEIPTS
        ));
    }
}
