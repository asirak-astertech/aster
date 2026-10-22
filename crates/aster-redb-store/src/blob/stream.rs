//! Durable provisional authority for pack-backed Blob streams.

use super::{
    BLOB_PROFILE5_RECEIPTS, BLOB_STREAM_CONFLICTS, BLOB_STREAM_OPERATIONS,
    BLOB_STREAM_PUBLICATIONS, BLOB_STREAM_RESERVATIONS, BLOB_STREAM_RETIREMENTS,
    BLOB_STREAM_VARIANTS, BlobOperationKey, BlobStoreError, BlobTransferId, BlobVariantId,
    MAX_BLOB_OPERATION_KEY_BYTES, Store, blob_content_prefix_upper_bound, blob_error,
    blob_variant_id, synchronize_blob_policy_generation_write,
};
use crate::{
    ACCEPTED_DOTS, CAUSAL_FRONTIER, CONTROL_SCOPE_EPOCHS, ControlPolicySnapshot, Dot,
    PUBLISHER_HIGH_WATER, SemanticDataClass, StateAuditSnapshot, StoreError, VersionVector,
    accepted_dot_key, causal_frontier_key, control_principal_revoked_read,
    control_principal_revoked_write, decode_scope_epoch_index, enforce_live_write,
    ensure_frontier_capacity, event_domain_prefix, require_control_policy_read,
    require_control_policy_write, update_causal_high_water,
};
use aster_mesh::{
    BLOB_STREAM_SEGMENT_BYTES, BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES, BlobId,
    BlobPublicationStreamId, BlobStreamFinalCommitment, BlobStreamFrontier, BlobStreamOpen, NodeId,
    Scope, Topic, VerifiedBlobStreamFinalCommitment, VerifiedBlobStreamOpen,
    VerifiedBlobTransferPlan,
};
use redb::{Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata};
use sha2::{Digest, Sha256};

use super::pack::{BlobPackCheckpoint, BlobPackError};

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

const PROVISIONAL_MAGIC: &[u8; 8] = b"ASTRPR02";
const PUBLICATION_MAGIC: &[u8; 8] = b"ASTRPB02";
const CONFLICT_MAGIC: &[u8; 8] = b"ASTRCF02";
const RETIREMENT_MAGIC: &[u8; 8] = b"ASTRRT02";
const PROVISIONAL_VERSION: u8 = 1;
const MAX_PROVISIONAL_STREAMS: u64 = 64;
const MAX_STREAM_CONFLICTS: u64 = 4_096;
const MAX_STREAM_RETIREMENTS: u64 = super::lifecycle::DEFAULT_MAX_BLOB_PUBLICATION_LIFECYCLE_ROWS;
const MAX_PROVISIONAL_STREAM_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const PACK_FIXED_RESERVATION_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobStreamSource {
    LocalApplication,
    AuthenticatedPeer(NodeId),
}

#[derive(Clone, Copy, Debug)]
pub struct BlobStreamReservationRequest<'a> {
    pub operation: &'a BlobOperationKey,
    pub source: BlobStreamSource,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamReservation {
    stream_id: BlobPublicationStreamId,
    open_digest: [u8; 32],
    operation: Vec<u8>,
    source: BlobStreamSource,
    reserved_bytes: u64,
    open: BlobStreamOpen,
    authenticated_open: Vec<u8>,
}

impl BlobStreamReservation {
    pub const fn stream_id(&self) -> BlobPublicationStreamId {
        self.stream_id
    }

    pub const fn open_digest(&self) -> &[u8; 32] {
        &self.open_digest
    }

    pub const fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlobStreamResume {
    generation: u64,
    next_segment_index: u64,
    durable_plaintext_offset: u64,
    durable_pack_len: u64,
    durable_wire_offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobStreamPromotion {
    stream_id: BlobPublicationStreamId,
    blob_id: BlobId,
    acceptance_marker: u64,
    duplicate: bool,
}

/// Exact transport-neutral durable lifecycle projection for one profile-5 publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobStreamInspection {
    Missing,
    AwaitingData {
        plaintext_total_bytes: u64,
        durable_plaintext_bytes: u64,
        transfer_total_bytes: u64,
        durable_transfer_bytes: u64,
        total_units: u64,
        durable_units: u64,
    },
    Receiving {
        plaintext_total_bytes: u64,
        durable_plaintext_bytes: u64,
        transfer_total_bytes: u64,
        durable_transfer_bytes: u64,
        total_units: u64,
        durable_units: u64,
    },
    ReadyToFinalize {
        plaintext_total_bytes: u64,
        durable_plaintext_bytes: u64,
        transfer_total_bytes: u64,
        durable_transfer_bytes: u64,
        total_units: u64,
        durable_units: u64,
    },
    Available {
        blob_id: BlobId,
        plaintext_total_bytes: u64,
        transfer_total_bytes: u64,
        total_units: u64,
    },
    ExpiredOrRetired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlobStreamRetirement {
    stream_id: BlobPublicationStreamId,
    mission: NodeId,
    publisher: NodeId,
    topic_digest: [u8; 32],
    scope_digest: [u8; 32],
    content_epoch: u64,
    age: super::lifecycle::RetirementAge,
}

impl BlobStreamRetirement {
    #[cfg(test)]
    fn new(reservation: &BlobStreamReservation) -> Self {
        let age = super::lifecycle::RetirementAge::unknown(
            super::lifecycle::DEFAULT_BLOB_RETIREMENT_RETENTION_MS,
        )
        .expect("default retirement retention");
        Self::with_age(reservation, age)
    }

    fn with_age(reservation: &BlobStreamReservation, age: super::lifecycle::RetirementAge) -> Self {
        Self {
            stream_id: reservation.stream_id,
            mission: *reservation.open.mission_id(),
            publisher: reservation.open.publisher(),
            topic_digest: Sha256::digest(reservation.open.topic().as_str().as_bytes()).into(),
            scope_digest: Sha256::digest(reservation.open.scope().as_str().as_bytes()).into(),
            content_epoch: reservation.open.content_epoch(),
            age,
        }
    }

    fn encode(self) -> [u8; 220] {
        let mut encoded = [0_u8; 220];
        encoded[..8].copy_from_slice(RETIREMENT_MAGIC);
        encoded[8] = PROVISIONAL_VERSION;
        encoded[9..41].copy_from_slice(self.stream_id.as_bytes());
        encoded[41..73].copy_from_slice(&self.mission);
        encoded[73..105].copy_from_slice(&self.publisher);
        encoded[105..137].copy_from_slice(&self.topic_digest);
        encoded[137..169].copy_from_slice(&self.scope_digest);
        encoded[169..177].copy_from_slice(&self.content_epoch.to_be_bytes());
        encoded[177..220].copy_from_slice(&self.age.encode());
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, StoreError> {
        if encoded.len() != 220
            || &encoded[..8] != RETIREMENT_MAGIC
            || encoded[8] != PROVISIONAL_VERSION
        {
            return Err(schema_error());
        }
        Ok(Self {
            stream_id: BlobPublicationStreamId::from_bytes(read_array(encoded, 9)?)
                .map_err(|_| schema_error())?,
            mission: read_array(encoded, 41)?,
            publisher: read_array(encoded, 73)?,
            topic_digest: read_array(encoded, 105)?,
            scope_digest: read_array(encoded, 137)?,
            content_epoch: read_u64(encoded, 169)?,
            age: super::lifecycle::RetirementAge::decode(&encoded[177..220]).map_err(blob_error)?,
        })
    }

    fn matches(&self, topic: &Topic, scope: &Scope) -> bool {
        let topic_digest: [u8; 32] = Sha256::digest(topic.as_str().as_bytes()).into();
        let scope_digest: [u8; 32] = Sha256::digest(scope.as_str().as_bytes()).into();
        self.topic_digest == topic_digest && self.scope_digest == scope_digest
    }
}

impl BlobStreamPromotion {
    pub const fn stream_id(self) -> BlobPublicationStreamId {
        self.stream_id
    }
    pub const fn blob_id(self) -> BlobId {
        self.blob_id
    }
    pub const fn acceptance_marker(self) -> u64 {
        self.acceptance_marker
    }
    pub const fn duplicate(self) -> bool {
        self.duplicate
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamPublication {
    open: BlobStreamOpen,
    commitment: BlobStreamFinalCommitment,
    authenticated_open: Vec<u8>,
    authenticated_commitment: Vec<u8>,
    acceptance_marker: u64,
    pack_len: u64,
}

impl BlobStreamPublication {
    pub const fn stream_id(&self) -> BlobPublicationStreamId {
        self.open.stream_id()
    }

    pub const fn blob_id(&self) -> BlobId {
        self.commitment.blob_id()
    }

    pub const fn open(&self) -> &BlobStreamOpen {
        &self.open
    }

    pub const fn commitment(&self) -> &BlobStreamFinalCommitment {
        &self.commitment
    }

    pub fn authenticated_open(&self) -> &[u8] {
        &self.authenticated_open
    }

    pub fn authenticated_commitment(&self) -> &[u8] {
        &self.authenticated_commitment
    }

    pub const fn acceptance_marker(&self) -> u64 {
        self.acceptance_marker
    }

    pub const fn pack_len(&self) -> u64 {
        self.pack_len
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobStreamConflictEvidence {
    stream_id: BlobPublicationStreamId,
    open_digest: [u8; 32],
    first_finish_digest: [u8; 32],
    latest_finish_digest: [u8; 32],
    distinct_finishes: u8,
}

impl BlobStreamConflictEvidence {
    pub const fn stream_id(self) -> BlobPublicationStreamId {
        self.stream_id
    }

    pub const fn distinct_finishes(self) -> u8 {
        self.distinct_finishes
    }

    fn encode(self) -> [u8; 138] {
        let mut encoded = [0_u8; 138];
        encoded[..8].copy_from_slice(CONFLICT_MAGIC);
        encoded[8] = PROVISIONAL_VERSION;
        encoded[9..41].copy_from_slice(self.stream_id.as_bytes());
        encoded[41..73].copy_from_slice(&self.open_digest);
        encoded[73..105].copy_from_slice(&self.first_finish_digest);
        encoded[105..137].copy_from_slice(&self.latest_finish_digest);
        encoded[137] = self.distinct_finishes;
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, StoreError> {
        if encoded.len() != 138
            || &encoded[..8] != CONFLICT_MAGIC
            || encoded[8] != PROVISIONAL_VERSION
        {
            return Err(schema_error());
        }
        let evidence = Self {
            stream_id: BlobPublicationStreamId::from_bytes(read_array(encoded, 9)?)
                .map_err(|_| schema_error())?,
            open_digest: read_array(encoded, 41)?,
            first_finish_digest: read_array(encoded, 73)?,
            latest_finish_digest: read_array(encoded, 105)?,
            distinct_finishes: encoded[137],
        };
        if evidence.open_digest == [0; 32]
            || evidence.first_finish_digest == [0; 32]
            || evidence.latest_finish_digest == [0; 32]
            || !matches!(evidence.distinct_finishes, 1 | 2)
            || (evidence.distinct_finishes == 1
                && evidence.first_finish_digest != evidence.latest_finish_digest)
        {
            return Err(schema_error());
        }
        Ok(evidence)
    }
}

impl BlobStreamPublication {
    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let open = self.open.encode();
        let commitment = self.commitment.encode();
        let lengths = [
            open.len(),
            commitment.len(),
            self.authenticated_open.len(),
            self.authenticated_commitment.len(),
        ]
        .map(|len| u32::try_from(len).map_err(|_| schema_error()))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
        let mut encoded = Vec::new();
        encoded.extend_from_slice(PUBLICATION_MAGIC);
        encoded.push(PROVISIONAL_VERSION);
        encoded.extend_from_slice(&self.acceptance_marker.to_be_bytes());
        encoded.extend_from_slice(&self.pack_len.to_be_bytes());
        for (bytes, len) in [
            open.as_slice(),
            commitment.as_slice(),
            self.authenticated_open.as_slice(),
            self.authenticated_commitment.as_slice(),
        ]
        .into_iter()
        .zip(lengths)
        {
            encoded.extend_from_slice(&len.to_be_bytes());
            encoded.extend_from_slice(bytes);
        }
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> Result<Self, StoreError> {
        if encoded.len() < 41
            || &encoded[..8] != PUBLICATION_MAGIC
            || encoded[8] != PROVISIONAL_VERSION
        {
            return Err(schema_error());
        }
        let acceptance_marker = read_u64(encoded, 9)?;
        let pack_len = read_u64(encoded, 17)?;
        let mut offset = 25_usize;
        let mut fields = Vec::with_capacity(4);
        for _ in 0..4 {
            let len = read_u32(encoded, offset)? as usize;
            offset = offset.checked_add(4).ok_or_else(schema_error)?;
            let end = offset.checked_add(len).ok_or_else(schema_error)?;
            fields.push(encoded.get(offset..end).ok_or_else(schema_error)?);
            offset = end;
        }
        if offset != encoded.len() || acceptance_marker == 0 || pack_len == 0 {
            return Err(schema_error());
        }
        let open = BlobStreamOpen::decode(fields[0]).map_err(|_| schema_error())?;
        let commitment =
            BlobStreamFinalCommitment::decode(fields[1]).map_err(|_| schema_error())?;
        if fields[2].is_empty()
            || fields[3].is_empty()
            || commitment.stream_id() != open.stream_id()
            || commitment.open_digest() != &open.digest()
            || commitment.total_len() != open.total_len()
            || commitment.content_epoch() != open.content_epoch()
            || commitment.ttl_ms() != open.ttl_ms()
        {
            return Err(schema_error());
        }
        Ok(Self {
            open,
            commitment,
            authenticated_open: fields[2].to_vec(),
            authenticated_commitment: fields[3].to_vec(),
            acceptance_marker,
            pack_len,
        })
    }
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

#[derive(Clone, Debug)]
struct ProvisionalBlobStream {
    reservation: BlobStreamReservation,
    checkpoint: Option<BlobPackCheckpoint>,
}

impl ProvisionalBlobStream {
    fn progress(&self) -> BlobStreamResume {
        self.checkpoint
            .as_ref()
            .map_or_else(BlobStreamResume::default, |checkpoint| BlobStreamResume {
                generation: checkpoint.generation(),
                next_segment_index: checkpoint.next_index(),
                durable_plaintext_offset: checkpoint.plaintext_offset(),
                durable_pack_len: checkpoint.pack_len(),
                durable_wire_offset: checkpoint.payload_len(),
            })
    }

    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let open = self.reservation.open.encode();
        let open_len = u32::try_from(open.len()).map_err(|_| schema_error())?;
        let authenticated_len =
            u32::try_from(self.reservation.authenticated_open.len()).map_err(|_| schema_error())?;
        let checkpoint = self
            .checkpoint
            .as_ref()
            .map(BlobPackCheckpoint::encode)
            .unwrap_or_default();
        let checkpoint_len = u32::try_from(checkpoint.len()).map_err(|_| schema_error())?;
        let mut encoded = Vec::with_capacity(
            62 + open.len() + self.reservation.authenticated_open.len() + checkpoint.len(),
        );
        encoded.extend_from_slice(PROVISIONAL_MAGIC);
        encoded.push(PROVISIONAL_VERSION);
        match self.reservation.source {
            BlobStreamSource::LocalApplication => {
                encoded.push(0);
                encoded.extend_from_slice(&[0; 32]);
            }
            BlobStreamSource::AuthenticatedPeer(peer) => {
                encoded.push(1);
                encoded.extend_from_slice(&peer);
            }
        }
        encoded.extend_from_slice(&self.reservation.reserved_bytes.to_be_bytes());
        encoded.extend_from_slice(&open_len.to_be_bytes());
        encoded.extend_from_slice(&open);
        encoded.extend_from_slice(&authenticated_len.to_be_bytes());
        encoded.extend_from_slice(&self.reservation.authenticated_open);
        encoded.extend_from_slice(&checkpoint_len.to_be_bytes());
        encoded.extend_from_slice(&checkpoint);
        Ok(encoded)
    }

    fn decode(encoded: &[u8]) -> Result<Self, StoreError> {
        if encoded.len() < 62
            || &encoded[..8] != PROVISIONAL_MAGIC
            || encoded[8] != PROVISIONAL_VERSION
        {
            return Err(schema_error());
        }
        let source = match encoded[9] {
            0 if encoded[10..42] == [0; 32] => BlobStreamSource::LocalApplication,
            1 => BlobStreamSource::AuthenticatedPeer(read_array(encoded, 10)?),
            _ => return Err(schema_error()),
        };
        let reserved_bytes = read_u64(encoded, 42)?;
        let open_len = read_u32(encoded, 50)? as usize;
        let open_start = 54_usize;
        let open_end = open_start.checked_add(open_len).ok_or_else(schema_error)?;
        let authenticated_len = read_u32(encoded, open_end)? as usize;
        let authenticated_start = open_end.checked_add(4).ok_or_else(schema_error)?;
        let authenticated_end = authenticated_start
            .checked_add(authenticated_len)
            .ok_or_else(schema_error)?;
        let checkpoint_len = read_u32(encoded, authenticated_end)? as usize;
        let checkpoint_start = authenticated_end.checked_add(4).ok_or_else(schema_error)?;
        let checkpoint_end = checkpoint_start
            .checked_add(checkpoint_len)
            .ok_or_else(schema_error)?;
        if checkpoint_end != encoded.len() || reserved_bytes == 0 || authenticated_len == 0 {
            return Err(schema_error());
        }
        let open =
            BlobStreamOpen::decode(encoded.get(open_start..open_end).ok_or_else(schema_error)?)
                .map_err(|_| schema_error())?;
        let checkpoint = if checkpoint_len == 0 {
            None
        } else {
            Some(
                BlobPackCheckpoint::decode(
                    encoded
                        .get(checkpoint_start..checkpoint_end)
                        .ok_or_else(schema_error)?,
                )
                .map_err(map_pack_error)?,
            )
        };
        let reservation = BlobStreamReservation {
            stream_id: open.stream_id(),
            open_digest: open.digest(),
            operation: open.operation_key().to_vec(),
            source,
            reserved_bytes,
            open,
            authenticated_open: encoded[authenticated_start..authenticated_end].to_vec(),
        };
        if checkpoint.as_ref().is_some_and(|checkpoint| {
            checkpoint.stream_id() != reservation.stream_id
                || checkpoint.open_digest() != &reservation.open_digest
                || checkpoint.total_len() != reservation.open.total_len()
        }) {
            return Err(schema_error());
        }
        Ok(Self {
            reservation,
            checkpoint,
        })
    }
}

fn schema_error() -> StoreError {
    blob_error(BlobStoreError::SchemaInvariant(
        "provisional Blob stream row is malformed",
    ))
}

fn map_pack_error(error: BlobPackError) -> StoreError {
    blob_error(BlobStoreError::DepotIntegrity(match error {
        BlobPackError::Invalid(message) => message,
        BlobPackError::Io(_) => "Blob pack checkpoint I/O error",
        BlobPackError::Store(_) => "Blob pack checkpoint Store error",
    }))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, StoreError> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
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

fn reserved_pack_bytes(total_len: u64) -> Result<u64, StoreError> {
    let segments = total_len
        .checked_add(BLOB_STREAM_SEGMENT_BYTES as u64 - 1)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?
        / BLOB_STREAM_SEGMENT_BYTES as u64;
    let overhead = segments
        .checked_mul(BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES as u64 + 4)
        .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    total_len
        .checked_add(overhead)
        .and_then(|value| value.checked_add(PACK_FIXED_RESERVATION_BYTES))
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

fn stream_units(total_len: u64) -> Result<u64, StoreError> {
    total_len
        .checked_add(BLOB_STREAM_SEGMENT_BYTES as u64 - 1)
        .ok_or(StoreError::PayloadByteAccountingOverflow)
        .map(|value| value / BLOB_STREAM_SEGMENT_BYTES as u64)
}

fn stream_transfer_bytes(total_len: u64) -> Result<u64, StoreError> {
    reserved_pack_bytes(total_len)?
        .checked_sub(PACK_FIXED_RESERVATION_BYTES)
        .ok_or(StoreError::PayloadByteAccountingOverflow)
}

fn stream_visible_read(
    read: &redb::ReadTransaction,
    publisher: NodeId,
    scope: &Scope,
    content_epoch: u64,
) -> Result<bool, StoreError> {
    if control_principal_revoked_read(read, publisher)? {
        return Ok(false);
    }
    let current_epoch = read
        .open_table(CONTROL_SCOPE_EPOCHS)?
        .get(scope.as_str())?
        .map(|value| decode_scope_epoch_index(value.value()))
        .transpose()?
        .map_or(1, |(epoch, _)| epoch);
    Ok(content_epoch == current_epoch)
}

fn record_stream_retirement(
    write: &redb::WriteTransaction,
    reservation: &BlobStreamReservation,
    retain_for_ms: u64,
    maximum_rows: u64,
) -> Result<(), StoreError> {
    let age =
        match crate::custody::lower_bound_continuity_write(write)?.map(|value| value.sample) {
            Some(sample) => super::lifecycle::RetirementAge::new(0, sample, retain_for_ms),
            None => super::lifecycle::RetirementAge::unknown(retain_for_ms),
        }
        .map_err(blob_error)?;
    let retirement = BlobStreamRetirement::with_age(reservation, age);
    let key = reservation.stream_id.as_bytes().as_slice();
    let mut retirements = write.open_table(BLOB_STREAM_RETIREMENTS)?;
    if let Some(existing) = retirements.get(key)? {
        if BlobStreamRetirement::decode(existing.value())? != retirement {
            return Err(schema_error());
        }
        return Ok(());
    }
    let limit = maximum_rows.min(MAX_STREAM_RETIREMENTS);
    if retirements.len()? >= limit {
        return Err(blob_error(BlobStoreError::PublicationLimitExceeded {
            current: usize::try_from(retirements.len()?)
                .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
            limit: usize::try_from(limit).map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        }));
    }
    retirements.insert(key, retirement.encode().as_slice())?;
    Ok(())
}

fn retire_provisional_stream_authority(
    write: &redb::WriteTransaction,
    reservation: &BlobStreamReservation,
    retain_for_ms: u64,
    maximum_rows: u64,
) -> Result<(), StoreError> {
    record_stream_retirement(write, reservation, retain_for_ms, maximum_rows)?;
    release_provisional_stream_authority(write, reservation)
}

fn record_stream_conflict(
    write: &redb::WriteTransaction,
    stream_id: BlobPublicationStreamId,
    open_digest: [u8; 32],
    authenticated_finish: &[u8],
) -> Result<(), StoreError> {
    let finish_digest: [u8; 32] = Sha256::digest(authenticated_finish).into();
    let key = stream_id.as_bytes().as_slice();
    let mut conflicts = write.open_table(BLOB_STREAM_CONFLICTS)?;
    let current = conflicts
        .get(key)?
        .map(|row| BlobStreamConflictEvidence::decode(row.value()))
        .transpose()?;
    let evidence = match current {
        None => {
            if conflicts.len()? >= MAX_STREAM_CONFLICTS {
                return Err(blob_error(BlobStoreError::PublicationLimitExceeded {
                    current: MAX_STREAM_CONFLICTS as usize,
                    limit: MAX_STREAM_CONFLICTS as usize,
                }));
            }
            BlobStreamConflictEvidence {
                stream_id,
                open_digest,
                first_finish_digest: finish_digest,
                latest_finish_digest: finish_digest,
                distinct_finishes: 1,
            }
        }
        Some(current) if current.open_digest != open_digest => return Err(schema_error()),
        Some(current)
            if current.first_finish_digest == finish_digest
                || current.latest_finish_digest == finish_digest =>
        {
            current
        }
        Some(mut current) => {
            current.latest_finish_digest = finish_digest;
            current.distinct_finishes = 2;
            current
        }
    };
    conflicts.insert(key, evidence.encode().as_slice())?;
    Ok(())
}

fn release_provisional_stream_authority(
    write: &redb::WriteTransaction,
    reservation: &BlobStreamReservation,
) -> Result<(), StoreError> {
    let key = reservation.stream_id.as_bytes().as_slice();
    write.open_table(BLOB_STREAM_RESERVATIONS)?.remove(key)?;
    write
        .open_table(BLOB_STREAM_OPERATIONS)?
        .remove(reservation.operation.as_slice())?;
    write.open_table(BLOB_STREAM_CONFLICTS)?.remove(key)?;
    Ok(())
}

fn publication_variant(publication: &BlobStreamPublication) -> BlobVariantId {
    blob_variant_id(
        publication.commitment.blob_id(),
        &publication.open.content_group(),
        publication.open.content_epoch(),
    )
}

fn stream_variant_key(variant: BlobVariantId, stream_id: BlobPublicationStreamId) -> [u8; 64] {
    let mut key = [0_u8; 64];
    key[..32].copy_from_slice(variant.as_bytes());
    key[32..].copy_from_slice(stream_id.as_bytes());
    key
}

fn require_stream_variant_reference(
    write: &redb::WriteTransaction,
    publication: &BlobStreamPublication,
) -> Result<(), StoreError> {
    let key = stream_variant_key(publication_variant(publication), publication.stream_id());
    let value = write
        .open_table(BLOB_STREAM_VARIANTS)?
        .get(key.as_slice())?
        .map(|value| value.value().to_vec())
        .ok_or_else(schema_error)?;
    if !value.is_empty() {
        return Err(schema_error());
    }
    Ok(())
}

pub(super) fn migrate_blob_stream_variant_index_write(
    write: &redb::WriteTransaction,
) -> Result<(), StoreError> {
    let publications = write.open_table(BLOB_STREAM_PUBLICATIONS)?;
    let mut rows = Vec::with_capacity(
        usize::try_from(publications.len()?)
            .map_err(|_| StoreError::ItemCountAccountingOverflow)?,
    );
    for row in publications.iter()? {
        let publication = BlobStreamPublication::decode(row?.1.value())?;
        rows.push(stream_variant_key(
            publication_variant(&publication),
            publication.stream_id(),
        ));
    }
    drop(publications);
    let mut variants = write.open_table(BLOB_STREAM_VARIANTS)?;
    for key in rows {
        variants.insert(key.as_slice(), &[][..])?;
    }
    Ok(())
}

pub(super) fn variant_has_publication_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<bool, StoreError> {
    let variants = write.open_table(BLOB_STREAM_VARIANTS)?;
    let Some((key, value)) = variants
        .range::<&[u8]>(variant.as_bytes().as_slice()..)?
        .next()
        .transpose()?
    else {
        return Ok(false);
    };
    if !key.value().starts_with(variant.as_bytes()) {
        return Ok(false);
    }
    if key.value().len() != 64 || !value.value().is_empty() {
        return Err(schema_error());
    }
    let stream_id = BlobPublicationStreamId::from_bytes(read_array(key.value(), 32)?)
        .map_err(|_| schema_error())?;
    let publication = write
        .open_table(BLOB_STREAM_PUBLICATIONS)?
        .get(stream_id.as_bytes().as_slice())?
        .map(|row| BlobStreamPublication::decode(row.value()))
        .transpose()?
        .ok_or_else(schema_error)?;
    if publication_variant(&publication) != variant {
        return Err(schema_error());
    }
    Ok(true)
}

pub(super) fn audit_blob_stream_tables_write(
    write: &redb::WriteTransaction,
    mission_authority: Option<NodeId>,
    accepted_dots: &impl ReadableTable<&'static [u8], &'static [u8]>,
    publisher_high: &impl ReadableTable<&'static [u8], u64>,
    frontier: &impl ReadableTable<&'static [u8], u64>,
    shared: &mut StateAuditSnapshot,
) -> Result<(), StoreError> {
    let reservations = write.open_table(BLOB_STREAM_RESERVATIONS)?;
    let operations = write.open_table(BLOB_STREAM_OPERATIONS)?;
    let publications = write.open_table(BLOB_STREAM_PUBLICATIONS)?;
    let conflicts = write.open_table(BLOB_STREAM_CONFLICTS)?;
    let variants = write.open_table(BLOB_STREAM_VARIANTS)?;
    let retirements = write.open_table(BLOB_STREAM_RETIREMENTS)?;
    let authority_rows = reservations
        .len()?
        .checked_add(publications.len()?)
        .ok_or(StoreError::ItemCountAccountingOverflow)?;
    if authority_rows != operations.len()? || reservations.len()? > MAX_PROVISIONAL_STREAMS {
        return Err(schema_error());
    }
    if conflicts.len()? > MAX_STREAM_CONFLICTS {
        return Err(schema_error());
    }
    if retirements.len()? > MAX_STREAM_RETIREMENTS {
        return Err(schema_error());
    }
    let authority = if authority_rows == 0 {
        mission_authority.unwrap_or([0; 32])
    } else {
        mission_authority.ok_or(StoreError::MissionNotBound)?
    };
    let mut reserved = 0_u64;
    for row in reservations.iter()? {
        let (key, value) = row?;
        let provisional = ProvisionalBlobStream::decode(value.value())?;
        if key.value() != provisional.reservation.stream_id.as_bytes().as_slice()
            || provisional.reservation.open.mission_id() != &authority
            || operations
                .get(provisional.reservation.operation.as_slice())?
                .is_none_or(|bound| bound.value() != key.value())
        {
            return Err(schema_error());
        }
        reserved = reserved
            .checked_add(provisional.reservation.reserved_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
    }
    if reserved > MAX_PROVISIONAL_STREAM_BYTES {
        return Err(schema_error());
    }
    let mut markers = std::collections::BTreeSet::new();
    for row in publications.iter()? {
        let (key, value) = row?;
        let publication = BlobStreamPublication::decode(value.value())?;
        if key.value() != publication.stream_id().as_bytes().as_slice()
            || publication.open.mission_id() != &authority
            || !markers.insert(publication.acceptance_marker)
            || operations
                .get(publication.open.operation_key())?
                .is_none_or(|bound| bound.value() != key.value())
        {
            return Err(schema_error());
        }
        let variant_key =
            stream_variant_key(publication_variant(&publication), publication.stream_id());
        if variants
            .get(variant_key.as_slice())?
            .is_none_or(|value| !value.value().is_empty())
        {
            return Err(schema_error());
        }
        let dot = Dot {
            publisher: publication.open.publisher(),
            counter: publication.open.publisher_counter(),
        };
        let dot_key = accepted_dot_key(dot).to_vec();
        let semantic_id = publication.open.digest();
        if shared
            .expected_dots
            .insert(dot_key.clone(), semantic_id)
            .is_some()
            || accepted_dots
                .get(dot_key.as_slice())?
                .is_none_or(|accepted| accepted.value() != semantic_id)
            || publisher_high
                .get(dot.publisher.as_slice())?
                .is_none_or(|high| high.value() < dot.counter)
        {
            return Err(schema_error());
        }
        shared
            .expected_publisher_high
            .entry(dot.publisher.to_vec())
            .and_modify(|current| *current = (*current).max(dot.counter))
            .or_insert(dot.counter);
        let frontier_key = causal_frontier_key(
            publication.open.topic(),
            publication.open.scope(),
            dot.publisher,
        )?;
        if frontier
            .get(frontier_key.as_slice())?
            .is_none_or(|high| high.value() < dot.counter)
        {
            return Err(schema_error());
        }
        shared
            .expected_frontier
            .entry(frontier_key)
            .and_modify(|current| *current = (*current).max(dot.counter))
            .or_insert(dot.counter);
        shared
            .domain_publishers
            .entry(event_domain_prefix(
                publication.open.topic(),
                publication.open.scope(),
            )?)
            .or_default()
            .insert(dot.publisher);
    }
    for row in operations.iter()? {
        let (operation, stream) = row?;
        if operation.value().is_empty()
            || operation.value().len() > MAX_BLOB_OPERATION_KEY_BYTES
            || stream.value().len() != 32
            || (reservations.get(stream.value())?.is_none()
                && publications.get(stream.value())?.is_none())
        {
            return Err(schema_error());
        }
    }
    for row in conflicts.iter()? {
        let (key, value) = row?;
        let evidence = BlobStreamConflictEvidence::decode(value.value())?;
        let provisional = reservations
            .get(key.value())?
            .map(|value| ProvisionalBlobStream::decode(value.value()))
            .transpose()?;
        let publication = publications
            .get(key.value())?
            .map(|value| BlobStreamPublication::decode(value.value()))
            .transpose()?;
        let open_digest = provisional
            .as_ref()
            .map(|value| value.reservation.open_digest)
            .or_else(|| publication.as_ref().map(|value| value.open.digest()));
        if key.value() != evidence.stream_id.as_bytes().as_slice()
            || open_digest != Some(evidence.open_digest)
        {
            return Err(schema_error());
        }
    }
    for row in variants.iter()? {
        let (key, value) = row?;
        if key.value().len() != 64 || !value.value().is_empty() {
            return Err(schema_error());
        }
        let variant = BlobVariantId::from_bytes(read_array(key.value(), 0)?);
        let stream_id = BlobPublicationStreamId::from_bytes(read_array(key.value(), 32)?)
            .map_err(|_| schema_error())?;
        let publication = publications
            .get(stream_id.as_bytes().as_slice())?
            .map(|value| BlobStreamPublication::decode(value.value()))
            .transpose()?
            .ok_or_else(schema_error)?;
        if publication_variant(&publication) != variant
            || super::deletion::variant_has_deletion_manifest_write(write, variant)?
        {
            return Err(schema_error());
        }
    }
    for row in retirements.iter()? {
        let (key, value) = row?;
        let retirement = BlobStreamRetirement::decode(value.value())?;
        if key.value() != retirement.stream_id.as_bytes().as_slice()
            || retirement.mission != authority
            || reservations.get(key.value())?.is_some()
            || publications.get(key.value())?.is_some()
        {
            return Err(schema_error());
        }
    }
    Ok(())
}

fn require_stream_policy_write(
    write: &redb::WriteTransaction,
    authority: NodeId,
    policy: &ControlPolicySnapshot,
    open: &BlobStreamOpen,
) -> Result<(), StoreError> {
    require_control_policy_write(write, authority, policy)?;
    if open.mission_id() != &authority {
        return Err(StoreError::MissionAuthorityMismatch {
            bound: authority,
            received: *open.mission_id(),
        });
    }
    if control_principal_revoked_write(write, open.publisher())? {
        return Err(blob_error(BlobStoreError::PublisherRevoked(
            open.publisher(),
        )));
    }
    let current_epoch = write
        .open_table(CONTROL_SCOPE_EPOCHS)?
        .get(open.scope().as_str())?
        .map(|value| decode_scope_epoch_index(value.value()))
        .transpose()?
        .map_or(1, |(epoch, _)| epoch);
    if open.content_epoch() < current_epoch {
        return Err(blob_error(BlobStoreError::KeyEpochStale {
            current: current_epoch,
            received: open.content_epoch(),
        }));
    }
    if open.content_epoch() > current_epoch {
        return Err(blob_error(BlobStoreError::KeyEpochNotActive {
            current: current_epoch,
            received: open.content_epoch(),
        }));
    }
    if open.policy_revision() != policy.head().map_or(1, |(revision, _)| revision) {
        return Err(StoreError::ControlPolicyChanged);
    }
    Ok(())
}

fn require_local_causal_write(
    write: &redb::WriteTransaction,
    open: &BlobStreamOpen,
) -> Result<(), StoreError> {
    let previous = write
        .open_table(PUBLISHER_HIGH_WATER)?
        .get(open.publisher().as_slice())?
        .map_or(0, |value| value.value());
    if previous.checked_add(1) != Some(open.publisher_counter()) {
        return Err(blob_error(BlobStoreError::ReservationChanged));
    }
    let prefix = event_domain_prefix(open.topic(), open.scope())?;
    let upper = blob_content_prefix_upper_bound(&prefix)?;
    let mut context = VersionVector::default();
    {
        let frontier = write.open_table(CAUSAL_FRONTIER)?;
        for row in frontier.range::<&[u8]>((
            std::ops::Bound::Included(prefix.as_slice()),
            std::ops::Bound::Excluded(upper.as_slice()),
        ))? {
            let (key, value) = row?;
            let publisher: NodeId = key.value()[prefix.len()..]
                .try_into()
                .map_err(|_| schema_error())?;
            context.observe(Dot {
                publisher,
                counter: value.value(),
            });
        }
    }
    if context != *open.causal_context() {
        return Err(blob_error(BlobStoreError::ReservationChanged));
    }
    ensure_frontier_capacity(
        write,
        open.topic(),
        open.scope(),
        open.publisher(),
        SemanticDataClass::Blob,
    )?;
    Ok(())
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

    /// Returns one exact, bounded receiver-local profile-5 lifecycle projection.
    pub fn inspect_blob_stream_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        stream_id: BlobPublicationStreamId,
        topic: &Topic,
        scope: &Scope,
    ) -> Result<BlobStreamInspection, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let key = stream_id.as_bytes().as_slice();
        let provisional = read
            .open_table(BLOB_STREAM_RESERVATIONS)?
            .get(key)?
            .map(|value| ProvisionalBlobStream::decode(value.value()))
            .transpose()?;
        let publication = read
            .open_table(BLOB_STREAM_PUBLICATIONS)?
            .get(key)?
            .map(|value| BlobStreamPublication::decode(value.value()))
            .transpose()?;
        let retirement = read
            .open_table(BLOB_STREAM_RETIREMENTS)?
            .get(key)?
            .map(|value| BlobStreamRetirement::decode(value.value()))
            .transpose()?;
        let authorities = u8::from(provisional.is_some())
            + u8::from(publication.is_some())
            + u8::from(retirement.is_some());
        if authorities > 1 {
            return Err(schema_error());
        }
        if let Some(provisional) = provisional {
            let open = &provisional.reservation.open;
            if provisional.reservation.stream_id != stream_id
                || open.mission_id() != &authority
                || open.topic() != topic
                || open.scope() != scope
                || !stream_visible_read(
                    &read,
                    open.publisher(),
                    open.scope(),
                    open.content_epoch(),
                )?
            {
                return Ok(BlobStreamInspection::Missing);
            }
            let progress = provisional.progress();
            let plaintext_total_bytes = open.total_len();
            let transfer_total_bytes = stream_transfer_bytes(plaintext_total_bytes)?;
            let total_units = stream_units(plaintext_total_bytes)?;
            if progress.durable_plaintext_offset() > plaintext_total_bytes
                || progress.durable_wire_offset() > transfer_total_bytes
                || progress.next_segment_index() > total_units
            {
                return Err(schema_error());
            }
            let fields = (
                plaintext_total_bytes,
                progress.durable_plaintext_offset(),
                transfer_total_bytes,
                progress.durable_wire_offset(),
                total_units,
                progress.next_segment_index(),
            );
            return Ok(match fields {
                (plaintext_total_bytes, 0, transfer_total_bytes, 0, total_units, 0) => {
                    BlobStreamInspection::AwaitingData {
                        plaintext_total_bytes,
                        durable_plaintext_bytes: 0,
                        transfer_total_bytes,
                        durable_transfer_bytes: 0,
                        total_units,
                        durable_units: 0,
                    }
                }
                (
                    plaintext_total_bytes,
                    durable_plaintext_bytes,
                    transfer_total_bytes,
                    durable_transfer_bytes,
                    total_units,
                    durable_units,
                ) if durable_plaintext_bytes == plaintext_total_bytes
                    && durable_units == total_units =>
                {
                    BlobStreamInspection::ReadyToFinalize {
                        plaintext_total_bytes,
                        durable_plaintext_bytes,
                        transfer_total_bytes,
                        durable_transfer_bytes,
                        total_units,
                        durable_units,
                    }
                }
                (
                    plaintext_total_bytes,
                    durable_plaintext_bytes,
                    transfer_total_bytes,
                    durable_transfer_bytes,
                    total_units,
                    durable_units,
                ) => BlobStreamInspection::Receiving {
                    plaintext_total_bytes,
                    durable_plaintext_bytes,
                    transfer_total_bytes,
                    durable_transfer_bytes,
                    total_units,
                    durable_units,
                },
            });
        }
        if let Some(publication) = publication {
            let open = publication.open();
            if publication.stream_id() != stream_id
                || open.mission_id() != &authority
                || open.topic() != topic
                || open.scope() != scope
                || !stream_visible_read(
                    &read,
                    open.publisher(),
                    open.scope(),
                    open.content_epoch(),
                )?
            {
                return Ok(BlobStreamInspection::Missing);
            }
            return Ok(BlobStreamInspection::Available {
                blob_id: publication.blob_id(),
                plaintext_total_bytes: open.total_len(),
                transfer_total_bytes: stream_transfer_bytes(open.total_len())?,
                total_units: stream_units(open.total_len())?,
            });
        }
        if let Some(retirement) = retirement {
            let current_sample = crate::custody::lower_bound_continuity_read(&read)?
                .map(|continuity| continuity.sample);
            let retention_elapsed = retirement
                .age
                .project(current_sample)
                .map_err(blob_error)?
                .retention_elapsed;
            if retirement.stream_id != stream_id
                || retirement.mission != authority
                || !retirement.matches(topic, scope)
                || !stream_visible_read(
                    &read,
                    retirement.publisher,
                    scope,
                    retirement.content_epoch,
                )?
                || retention_elapsed
            {
                return Ok(BlobStreamInspection::Missing);
            }
            return Ok(BlobStreamInspection::ExpiredOrRetired);
        }
        Ok(BlobStreamInspection::Missing)
    }

    pub fn blob_stream_publications_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
    ) -> Result<Vec<BlobStreamPublication>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let table = read.open_table(BLOB_STREAM_PUBLICATIONS)?;
        let mut publications = Vec::with_capacity(
            usize::try_from(table.len()?).map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        );
        for row in table.iter()? {
            let publication = BlobStreamPublication::decode(row?.1.value())?;
            if publication.open.mission_id() != &authority {
                return Err(schema_error());
            }
            publications.push(publication);
        }
        publications.sort_unstable_by_key(BlobStreamPublication::acceptance_marker);
        Ok(publications)
    }

    pub fn blob_stream_conflicts_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
    ) -> Result<Vec<BlobStreamConflictEvidence>, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let read = self.database.begin_read()?;
        require_control_policy_read(&read, authority, policy)?;
        let table = read.open_table(BLOB_STREAM_CONFLICTS)?;
        let mut conflicts = Vec::with_capacity(
            usize::try_from(table.len()?).map_err(|_| StoreError::ItemCountAccountingOverflow)?,
        );
        for row in table.iter()? {
            conflicts.push(BlobStreamConflictEvidence::decode(row?.1.value())?);
        }
        conflicts.sort_unstable_by_key(|evidence| evidence.stream_id);
        Ok(conflicts)
    }

    pub fn reserve_blob_stream_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        request: BlobStreamReservationRequest<'_>,
        verified: &VerifiedBlobStreamOpen,
    ) -> Result<(BlobStreamReservation, BlobStreamResume), StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let open = verified.open();
        if request.operation.as_bytes() != open.operation_key() {
            return Err(blob_error(BlobStoreError::OperationConflict));
        }
        let reserved_bytes = reserved_pack_bytes(open.total_len())?;
        if reserved_bytes > MAX_PROVISIONAL_STREAM_BYTES {
            return Err(blob_error(BlobStoreError::DepotByteLimitExceeded {
                current: 0,
                incoming: reserved_bytes,
                limit: MAX_PROVISIONAL_STREAM_BYTES,
            }));
        }
        let authenticated_open = verified.authenticated_bytes().to_vec();
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        synchronize_blob_policy_generation_write(&write)?;
        require_stream_policy_write(&write, authority, policy, open)?;
        let stream_id = open.stream_id();
        let key = stream_id.as_bytes().as_slice();
        if write
            .open_table(BLOB_STREAM_RETIREMENTS)?
            .get(key)?
            .is_some()
        {
            return Err(blob_error(BlobStoreError::ExpiredOrRetired));
        }
        if let Some(encoded) = write
            .open_table(BLOB_STREAM_RESERVATIONS)?
            .get(key)?
            .map(|row| row.value().to_vec())
        {
            let existing = ProvisionalBlobStream::decode(&encoded)?;
            if existing.reservation.open != *open
                || existing.reservation.authenticated_open != authenticated_open
                || existing.reservation.source != request.source
                || existing.reservation.operation != request.operation.as_bytes()
            {
                return Err(blob_error(BlobStoreError::OperationConflict));
            }
            return Ok((existing.reservation.clone(), existing.progress()));
        }
        if let Some(bound) = write
            .open_table(BLOB_STREAM_OPERATIONS)?
            .get(request.operation.as_bytes())?
        {
            if bound.value() != key {
                return Err(blob_error(BlobStoreError::OperationConflict));
            }
            return Err(schema_error());
        }
        if request.source == BlobStreamSource::LocalApplication {
            require_local_causal_write(&write, open)?;
        }
        let (rows, bytes) = {
            let table = write.open_table(BLOB_STREAM_RESERVATIONS)?;
            let mut bytes = 0_u64;
            for row in table.iter()? {
                bytes = bytes
                    .checked_add(
                        ProvisionalBlobStream::decode(row?.1.value())?
                            .reservation
                            .reserved_bytes,
                    )
                    .ok_or(StoreError::PayloadByteAccountingOverflow)?;
            }
            (table.len()?, bytes)
        };
        if rows >= MAX_PROVISIONAL_STREAMS {
            return Err(blob_error(BlobStoreError::DepotVariantLimitExceeded {
                current: rows,
                limit: MAX_PROVISIONAL_STREAMS,
            }));
        }
        if bytes
            .checked_add(reserved_bytes)
            .ok_or(StoreError::PayloadByteAccountingOverflow)?
            > MAX_PROVISIONAL_STREAM_BYTES
        {
            return Err(blob_error(BlobStoreError::DepotByteLimitExceeded {
                current: bytes,
                incoming: reserved_bytes,
                limit: MAX_PROVISIONAL_STREAM_BYTES,
            }));
        }
        let reservation = BlobStreamReservation {
            stream_id: open.stream_id(),
            open_digest: open.digest(),
            operation: request.operation.as_bytes().to_vec(),
            source: request.source,
            reserved_bytes,
            open: open.clone(),
            authenticated_open,
        };
        let provisional = ProvisionalBlobStream {
            reservation: reservation.clone(),
            checkpoint: None,
        };
        write
            .open_table(BLOB_STREAM_RESERVATIONS)?
            .insert(key, provisional.encode()?.as_slice())?;
        write
            .open_table(BLOB_STREAM_OPERATIONS)?
            .insert(request.operation.as_bytes(), key)?;
        write.commit()?;
        Ok((reservation, BlobStreamResume::default()))
    }

    /// Loads the redb projection of the latest pack-authoritative checkpoint.
    /// The projection never discovers or advances byte progress on its own.
    pub fn blob_stream_resume(
        &self,
        reservation: &BlobStreamReservation,
    ) -> Result<BlobStreamResume, StoreError> {
        self.require_live()?;
        let read = self.database.begin_read()?;
        let encoded = read
            .open_table(BLOB_STREAM_RESERVATIONS)?
            .get(reservation.stream_id.as_bytes().as_slice())?
            .map(|row| row.value().to_vec())
            .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
        let provisional = ProvisionalBlobStream::decode(&encoded)?;
        if provisional.reservation != *reservation {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        Ok(provisional.progress())
    }

    /// Projects a checkpoint only after the pack writer has synchronized its
    /// data and alternating journal. Therefore redb can equal, but never lead,
    /// the pack's durable byte authority.
    pub fn checkpoint_blob_stream(
        &self,
        policy: &ControlPolicySnapshot,
        reservation: &BlobStreamReservation,
        expected: BlobStreamResume,
        checkpoint: BlobPackCheckpoint,
    ) -> Result<BlobStreamResume, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        synchronize_blob_policy_generation_write(&write)?;
        let key = reservation.stream_id.as_bytes().as_slice();
        let encoded = write
            .open_table(BLOB_STREAM_RESERVATIONS)?
            .get(key)?
            .map(|row| row.value().to_vec())
            .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
        let mut provisional = ProvisionalBlobStream::decode(&encoded)?;
        if let Err(error) =
            require_stream_policy_write(&write, authority, policy, &provisional.reservation.open)
        {
            if matches!(
                error,
                StoreError::Blob(
                    BlobStoreError::PublisherRevoked(_) | BlobStoreError::KeyEpochStale { .. }
                )
            ) {
                retire_provisional_stream_authority(
                    &write,
                    &provisional.reservation,
                    self.blob_lifecycle_limits().retain_for_ms(),
                    self.blob_lifecycle_limits().max_publication_rows(),
                )?;
                write.commit()?;
            }
            return Err(error);
        }
        if provisional.reservation != *reservation
            || provisional.progress() != expected
            || checkpoint.stream_id() != reservation.stream_id
            || checkpoint.open_digest() != &reservation.open_digest
            || checkpoint.total_len() != provisional.reservation.open.total_len()
        {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        if let Some(current) = &provisional.checkpoint {
            if current == &checkpoint {
                return Ok(provisional.progress());
            }
            if checkpoint.generation()
                != current
                    .generation()
                    .checked_add(1)
                    .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?
                || checkpoint.next_index() < current.next_index()
                || checkpoint.plaintext_offset() < current.plaintext_offset()
                || checkpoint.pack_len() < current.pack_len()
            {
                return Err(blob_error(BlobStoreError::ReservationChanged));
            }
        }
        provisional.checkpoint = Some(checkpoint);
        let progress = provisional.progress();
        write
            .open_table(BLOB_STREAM_RESERVATIONS)?
            .insert(key, provisional.encode()?.as_slice())?;
        write.commit()?;
        Ok(progress)
    }

    pub fn promote_blob_stream_with_policy(
        &self,
        policy: &ControlPolicySnapshot,
        reservation: &BlobStreamReservation,
        verified: &VerifiedBlobStreamFinalCommitment,
    ) -> Result<BlobStreamPromotion, StoreError> {
        self.require_live()?;
        let authority = self.require_bound_mission()?;
        let commitment = verified.commitment();
        let key = reservation.stream_id.as_bytes().as_slice();
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        synchronize_blob_policy_generation_write(&write)?;
        require_control_policy_write(&write, authority, policy)?;

        let existing_publication = {
            let publications = write.open_table(BLOB_STREAM_PUBLICATIONS)?;
            publications.get(key)?.map(|row| row.value().to_vec())
        };
        if let Some(encoded) = existing_publication {
            let existing = BlobStreamPublication::decode(&encoded)?;
            if existing.open != reservation.open
                || existing.authenticated_open != reservation.authenticated_open
                || existing.commitment != *commitment
                || existing.authenticated_commitment != verified.authenticated_bytes()
            {
                record_stream_conflict(
                    &write,
                    reservation.stream_id,
                    reservation.open_digest,
                    verified.authenticated_bytes(),
                )?;
                write.commit()?;
                return Err(blob_error(BlobStoreError::OperationConflict));
            }
            require_stream_variant_reference(&write, &existing)?;
            return Ok(BlobStreamPromotion {
                stream_id: reservation.stream_id,
                blob_id: commitment.blob_id(),
                acceptance_marker: existing.acceptance_marker,
                duplicate: true,
            });
        }

        let encoded = write
            .open_table(BLOB_STREAM_RESERVATIONS)?
            .get(key)?
            .map(|row| row.value().to_vec())
            .ok_or_else(|| blob_error(BlobStoreError::ReservationChanged))?;
        let provisional = ProvisionalBlobStream::decode(&encoded)?;
        if let Err(error) =
            require_stream_policy_write(&write, authority, policy, &provisional.reservation.open)
        {
            if matches!(
                error,
                StoreError::Blob(
                    BlobStoreError::PublisherRevoked(_) | BlobStoreError::KeyEpochStale { .. }
                )
            ) {
                release_provisional_stream_authority(&write, &provisional.reservation)?;
                write.commit()?;
            }
            return Err(error);
        }
        let checkpoint = provisional
            .checkpoint
            .as_ref()
            .ok_or_else(|| blob_error(BlobStoreError::CompletionMismatch))?;
        let roots = BlobStreamFrontier::restore(checkpoint.frontier().clone())
            .and_then(|frontier| frontier.finish(provisional.reservation.open.total_len()))
            .map_err(|_| blob_error(BlobStoreError::CompletionMismatch))?;
        if provisional.reservation != *reservation
            || commitment.open_digest() != &reservation.open_digest
            || commitment.stream_id() != reservation.stream_id
            || commitment.total_len() != reservation.open.total_len()
            || commitment.content_epoch() != reservation.open.content_epoch()
            || commitment.ttl_ms() != reservation.open.ttl_ms()
            || checkpoint.next_index() != commitment.segment_count()
            || checkpoint.plaintext_offset() != commitment.total_len()
            || commitment.plaintext_root() != &roots.0
            || commitment.ciphertext_root() != &roots.1
        {
            record_stream_conflict(
                &write,
                reservation.stream_id,
                reservation.open_digest,
                verified.authenticated_bytes(),
            )?;
            write.commit()?;
            return Err(blob_error(BlobStoreError::CompletionMismatch));
        }
        match (
            reservation.open.ttl_ms(),
            reservation.open.initial_custody(),
            commitment.final_custody(),
        ) {
            (None, None, None) => {}
            (Some(ttl), Some(initial), Some(final_sample))
                if initial.clock_id == final_sample.clock_id
                    && final_sample.tick_ms >= initial.tick_ms
                    && final_sample.tick_ms - initial.tick_ms < ttl => {}
            (Some(_), Some(_), Some(_)) => {
                retire_provisional_stream_authority(
                    &write,
                    reservation,
                    self.blob_lifecycle_limits().retain_for_ms(),
                    self.blob_lifecycle_limits().max_publication_rows(),
                )?;
                write.commit()?;
                return Err(blob_error(BlobStoreError::ExpiredOrRetired));
            }
            _ => return Err(blob_error(BlobStoreError::CompletionMismatch)),
        }

        let acceptance_marker = {
            let table = write.open_table(BLOB_STREAM_PUBLICATIONS)?;
            table
                .iter()?
                .try_fold(0_u64, |current, row| {
                    Ok::<_, StoreError>(
                        current
                            .max(BlobStreamPublication::decode(row?.1.value())?.acceptance_marker),
                    )
                })?
                .checked_add(1)
                .ok_or(StoreError::AcceptanceMarkerExhausted)?
        };
        let publication = BlobStreamPublication {
            open: reservation.open.clone(),
            commitment: commitment.clone(),
            authenticated_open: reservation.authenticated_open.clone(),
            authenticated_commitment: verified.authenticated_bytes().to_vec(),
            acceptance_marker,
            pack_len: checkpoint.pack_len(),
        };
        let variant = publication_variant(&publication);
        super::deletion::require_variant_available_write(&write, variant)?;
        let variant_key = stream_variant_key(variant, reservation.stream_id);
        if write
            .open_table(BLOB_STREAM_VARIANTS)?
            .get(variant_key.as_slice())?
            .is_some()
        {
            return Err(schema_error());
        }
        let dot = Dot {
            publisher: reservation.open.publisher(),
            counter: reservation.open.publisher_counter(),
        };
        let dot_key = accepted_dot_key(dot);
        if let Some(accepted) = write.open_table(ACCEPTED_DOTS)?.get(dot_key.as_slice())? {
            if accepted.value() != reservation.open_digest {
                return Err(StoreError::CausalEquivocation {
                    publisher: dot.publisher,
                    counter: dot.counter,
                });
            }
            return Err(schema_error());
        }
        ensure_frontier_capacity(
            &write,
            reservation.open.topic(),
            reservation.open.scope(),
            dot.publisher,
            SemanticDataClass::Blob,
        )?;
        write
            .open_table(BLOB_STREAM_PUBLICATIONS)?
            .insert(key, publication.encode()?.as_slice())?;
        write
            .open_table(BLOB_STREAM_VARIANTS)?
            .insert(variant_key.as_slice(), &[][..])?;
        write
            .open_table(ACCEPTED_DOTS)?
            .insert(dot_key.as_slice(), reservation.open_digest.as_slice())?;
        update_causal_high_water(
            &write,
            dot.publisher,
            reservation.open.topic(),
            reservation.open.scope(),
            dot.counter,
        )?;
        write.open_table(BLOB_STREAM_RESERVATIONS)?.remove(key)?;
        write.commit()?;
        Ok(BlobStreamPromotion {
            stream_id: reservation.stream_id,
            blob_id: commitment.blob_id(),
            acceptance_marker,
            duplicate: false,
        })
    }

    /// Atomically releases one exact provisional authority and its idempotent
    /// operation binding. Pack-file removal is deliberately a separate,
    /// retryable filesystem cleanup after this durable authority transition.
    pub fn abort_blob_stream(
        &self,
        reservation: &BlobStreamReservation,
    ) -> Result<bool, StoreError> {
        self.require_live()?;
        let mut write = self.database.begin_write()?;
        write.set_durability(Durability::Immediate)?;
        enforce_live_write(&write)?;
        let key = reservation.stream_id.as_bytes().as_slice();
        let encoded = write
            .open_table(BLOB_STREAM_RESERVATIONS)?
            .get(key)?
            .map(|row| row.value().to_vec());
        let Some(encoded) = encoded else {
            if write
                .open_table(BLOB_STREAM_OPERATIONS)?
                .get(reservation.operation.as_slice())?
                .is_some_and(|bound| bound.value() == key)
            {
                return Err(schema_error());
            }
            return Ok(false);
        };
        let provisional = ProvisionalBlobStream::decode(&encoded)?;
        if provisional.reservation != *reservation {
            return Err(blob_error(BlobStoreError::ReservationChanged));
        }
        {
            let operations = write.open_table(BLOB_STREAM_OPERATIONS)?;
            if operations
                .get(reservation.operation.as_slice())?
                .is_none_or(|bound| bound.value() != key)
            {
                return Err(schema_error());
            }
        }
        release_provisional_stream_authority(&write, reservation)?;
        write.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::{BlobPackWriter, PinnedBlobPackRoot};
    use crate::{BlobOperationKey, Store};
    use aster_mesh::{
        BlobMetadata, BlobPublicationStreamId, BlobStreamOpen, BlobStreamPlainPartition, Priority,
        ProvisioningAccess, ReferenceEnvelopeSealer, ReferenceProvisioner, Scope, Topic,
        VersionVector,
    };
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

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

    #[test]
    fn network_blob_size_diagnostic_reports_selected_profile_limits() {
        let v8 = BlobStoreError::NetworkBlobTooLarge {
            total_len: 65 * 1024 * 1024,
            chunk_count: 1_025,
            max_total_len: super::super::MAX_NETWORK_BLOB_BYTES,
            max_chunks: super::super::MAX_NETWORK_BLOB_CHUNKS,
        }
        .to_string();
        assert!(v8.contains("67108864 bytes/1024 chunks"));
        let v9 = BlobStoreError::NetworkBlobTooLarge {
            total_len: 8 * 1024 * 1024 * 1024 + 1,
            chunk_count: 131_073,
            max_total_len: super::super::MAX_PROFILE5_NETWORK_BLOB_BYTES,
            max_chunks: super::super::MAX_PROFILE5_NETWORK_BLOB_CHUNKS,
        }
        .to_string();
        assert!(v9.contains("8589934592 bytes/131072 chunks"));
    }

    struct TestRoot(PathBuf);

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn fixture_with_lifetime(
        seed: u8,
        total_len: u64,
        ttl_ms: Option<u64>,
        initial_custody: Option<aster_mesh::CustodySample>,
    ) -> (
        TestRoot,
        Store,
        ReferenceEnvelopeSealer,
        BlobOperationKey,
        aster_mesh::VerifiedBlobStreamOpen,
    ) {
        let topic = Topic::new("stream-lifecycle").unwrap();
        let scope = Scope::new("mission/stream-lifecycle").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([seed; 32]).unwrap();
        let publisher = ReferenceEnvelopeSealer::open(
            provisioner.issue_control_authority(1, &[access]).unwrap(),
        )
        .unwrap();
        let operation = BlobOperationKey::new(format!("stream-{seed}")).unwrap();
        let open = BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([seed; 32]).unwrap(),
            publisher.identity(),
            operation.as_bytes().to_vec(),
            publisher.mission_authority_id(),
            1,
            VersionVector::default(),
            topic,
            scope.clone(),
            BlobMetadata::new(Some("application/octet-stream".into()), b"stream".to_vec()).unwrap(),
            Priority::Immediate,
            ttl_ms,
            initial_custody,
            total_len,
            1,
            1,
            publisher
                .blob_stream_authorization_digest(&scope, 1)
                .unwrap(),
            [0x45; 32],
        )
        .unwrap();
        let signed = publisher.seal_blob_stream_open(&open).unwrap();
        let open = publisher.verify_blob_stream_open(&signed).unwrap();
        let root = TestRoot(std::env::temp_dir().join(format!(
            "aster-stream-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed),
        )));
        std::fs::create_dir(&root.0).unwrap();
        let store =
            Store::open_for_mission(root.0.join("state.redb"), publisher.mission_authority_id())
                .unwrap();
        (root, store, publisher, operation, open)
    }

    fn fixture_with_len(
        seed: u8,
        total_len: u64,
    ) -> (
        TestRoot,
        Store,
        ReferenceEnvelopeSealer,
        BlobOperationKey,
        aster_mesh::VerifiedBlobStreamOpen,
    ) {
        fixture_with_lifetime(seed, total_len, None, None)
    }

    fn fixture(
        seed: u8,
    ) -> (
        TestRoot,
        Store,
        ReferenceEnvelopeSealer,
        BlobOperationKey,
        aster_mesh::VerifiedBlobStreamOpen,
    ) {
        fixture_with_len(seed, 1024 * 1024 * 1024)
    }

    #[test]
    fn inspect_stream_publication_reports_every_lifecycle_state() {
        let segment_len = aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64;
        let total_len = segment_len * 2;
        let (root, mut store, publisher, operation, open) = fixture_with_len(0x60, total_len);
        let policy = store.control_policy_snapshot().unwrap();
        let stream_id = open.open().stream_id();
        let topic = open.open().topic();
        let scope = open.open().scope();

        assert_eq!(
            store
                .inspect_blob_stream_with_policy(&policy, stream_id, topic, scope)
                .unwrap(),
            BlobStreamInspection::Missing
        );
        let request = BlobStreamReservationRequest {
            operation: &operation,
            source: BlobStreamSource::AuthenticatedPeer([0x61; 32]),
        };
        let (reservation, _initial) = store
            .reserve_blob_stream_with_policy(&policy, request, &open)
            .unwrap();
        assert!(matches!(
            store
                .inspect_blob_stream_with_policy(&policy, stream_id, topic, scope)
                .unwrap(),
            BlobStreamInspection::AwaitingData {
                plaintext_total_bytes,
                durable_plaintext_bytes: 0,
                durable_transfer_bytes: 0,
                total_units: 2,
                durable_units: 0,
                ..
            } if plaintext_total_bytes == total_len
        ));

        let mut writer = BlobPackWriter::create(&root.0.join("inspect-pack"), open.open()).unwrap();
        let sealer = publisher.blob_stream_segment_sealer(&open).unwrap();
        for index in 0..2_u64 {
            let (segment, leaves) = sealer
                .seal(
                    BlobStreamPlainPartition::new(
                        *stream_id.as_bytes(),
                        open.open().digest(),
                        open.open().content_epoch(),
                        index,
                        index * segment_len,
                        total_len,
                        vec![0x62 + index as u8; segment_len as usize],
                    )
                    .unwrap(),
                )
                .unwrap();
            writer.append(&segment, leaves).unwrap();
            let before = store.blob_stream_resume(&reservation).unwrap();
            let checkpoint = writer.checkpoint().unwrap();
            let progress = store
                .checkpoint_blob_stream(&policy, &reservation, before, checkpoint.clone())
                .unwrap();
            let inspected = store
                .inspect_blob_stream_with_policy(&policy, stream_id, topic, scope)
                .unwrap();
            if index == 0 {
                assert!(matches!(
                    inspected,
                    BlobStreamInspection::Receiving {
                        durable_plaintext_bytes,
                        durable_transfer_bytes,
                        durable_units: 1,
                        total_units: 2,
                        ..
                    } if durable_plaintext_bytes == segment_len
                        && durable_transfer_bytes == progress.durable_wire_offset()
                ));
                let mission = publisher.mission_authority_id();
                drop(store);
                store = Store::open_for_mission(root.0.join("state.redb"), mission).unwrap();
                assert_eq!(store.blob_stream_resume(&reservation).unwrap(), progress);
            } else {
                assert!(matches!(
                    inspected,
                    BlobStreamInspection::ReadyToFinalize {
                        durable_plaintext_bytes,
                        durable_transfer_bytes,
                        durable_units: 2,
                        total_units: 2,
                        ..
                    } if durable_plaintext_bytes == total_len
                        && durable_transfer_bytes == progress.durable_wire_offset()
                ));
                let roots = BlobStreamFrontier::restore(checkpoint.frontier().clone())
                    .unwrap()
                    .finish(total_len)
                    .unwrap();
                let commitment =
                    BlobStreamFinalCommitment::new(&open, roots.0, roots.1, 2, None).unwrap();
                let signed = publisher.seal_blob_stream_commitment(&commitment).unwrap();
                let commitment = publisher
                    .verify_blob_stream_commitment(&open, &signed)
                    .unwrap();
                let promoted = store
                    .promote_blob_stream_with_policy(&policy, &reservation, &commitment)
                    .unwrap();
                assert!(matches!(
                    store
                        .inspect_blob_stream_with_policy(&policy, stream_id, topic, scope)
                        .unwrap(),
                    BlobStreamInspection::Available {
                        blob_id,
                        plaintext_total_bytes,
                        total_units: 2,
                        ..
                    } if blob_id == promoted.blob_id() && plaintext_total_bytes == total_len
                ));
            }
        }

        let initial = aster_mesh::CustodySample {
            clock_id: [0x63; 16],
            tick_ms: 10_000,
        };
        let (expired_root, expired_store, expired_publisher, expired_operation, expired_open) =
            fixture_with_lifetime(0x64, segment_len, Some(1_000), Some(initial));
        let expired_policy = expired_store.control_policy_snapshot().unwrap();
        let expired_request = BlobStreamReservationRequest {
            operation: &expired_operation,
            source: BlobStreamSource::AuthenticatedPeer([0x65; 32]),
        };
        let (expired_reservation, resume) = expired_store
            .reserve_blob_stream_with_policy(&expired_policy, expired_request, &expired_open)
            .unwrap();
        let mut expired_writer =
            BlobPackWriter::create(&expired_root.0.join("expired-pack"), expired_open.open())
                .unwrap();
        let expired_sealer = expired_publisher
            .blob_stream_segment_sealer(&expired_open)
            .unwrap();
        let (segment, leaves) = expired_sealer
            .seal(
                BlobStreamPlainPartition::new(
                    *expired_open.open().stream_id().as_bytes(),
                    expired_open.open().digest(),
                    expired_open.open().content_epoch(),
                    0,
                    0,
                    segment_len,
                    vec![0x66; segment_len as usize],
                )
                .unwrap(),
            )
            .unwrap();
        expired_writer.append(&segment, leaves).unwrap();
        let checkpoint = expired_writer.checkpoint().unwrap();
        expired_store
            .checkpoint_blob_stream(
                &expired_policy,
                &expired_reservation,
                resume,
                checkpoint.clone(),
            )
            .unwrap();
        let roots = BlobStreamFrontier::restore(checkpoint.frontier().clone())
            .unwrap()
            .finish(segment_len)
            .unwrap();
        let expired_sample = aster_mesh::CustodySample {
            clock_id: initial.clock_id,
            tick_ms: initial.tick_ms + 1_000,
        };
        expired_store
            .observe_blob_custody_sample(expired_sample)
            .unwrap();
        let commitment = BlobStreamFinalCommitment::new(
            &expired_open,
            roots.0,
            roots.1,
            1,
            Some(expired_sample),
        )
        .unwrap();
        let signed = expired_publisher
            .seal_blob_stream_commitment(&commitment)
            .unwrap();
        let commitment = expired_publisher
            .verify_blob_stream_commitment(&expired_open, &signed)
            .unwrap();
        assert!(expired_store
            .promote_blob_stream_with_policy(
                &expired_policy,
                &expired_reservation,
                &commitment,
            )
            .is_err());
        let expired_mission = expired_publisher.mission_authority_id();
        drop(expired_store);
        let expired_store =
            Store::open_for_mission(expired_root.0.join("state.redb"), expired_mission).unwrap();
        assert_eq!(
            expired_store
                .inspect_blob_stream_with_policy(
                    &expired_policy,
                    expired_open.open().stream_id(),
                    expired_open.open().topic(),
                    expired_open.open().scope(),
                )
                .unwrap(),
            BlobStreamInspection::ExpiredOrRetired
        );
        expired_store
            .observe_blob_custody_sample(aster_mesh::CustodySample {
                clock_id: initial.clock_id,
                tick_ms: expired_sample.tick_ms
                    + super::super::lifecycle::DEFAULT_BLOB_RETIREMENT_RETENTION_MS,
            })
            .unwrap();
        assert_eq!(
            expired_store
                .inspect_blob_stream_with_policy(
                    &expired_policy,
                    expired_open.open().stream_id(),
                    expired_open.open().topic(),
                    expired_open.open().scope(),
                )
                .unwrap(),
            BlobStreamInspection::Missing
        );
    }

    #[test]
    fn inspect_stream_publication_conflates_missing_and_unauthorized() {
        let (_root, store, mut publisher, operation, open) = fixture_with_len(0x67, 1024);
        let policy = store.control_policy_snapshot().unwrap();
        let request = BlobStreamReservationRequest {
            operation: &operation,
            source: BlobStreamSource::AuthenticatedPeer([0x68; 32]),
        };
        store
            .reserve_blob_stream_with_policy(&policy, request, &open)
            .unwrap();
        let revocation = publisher
            .seal_chained_revocation_control(publisher.identity(), 1, 1, None)
            .unwrap();
        let verified = publisher.verify_control(&revocation).unwrap();
        store
            .ingest_verified_control(&verified, &revocation)
            .unwrap();
        let current = store.control_policy_snapshot().unwrap();
        assert_eq!(
            store
                .inspect_blob_stream_with_policy(
                    &current,
                    open.open().stream_id(),
                    open.open().topic(),
                    open.open().scope(),
                )
                .unwrap(),
            BlobStreamInspection::Missing
        );
        assert_eq!(
            store
                .inspect_blob_stream_with_policy(
                    &current,
                    BlobPublicationStreamId::from_bytes([0x69; 32]).unwrap(),
                    open.open().topic(),
                    open.open().scope(),
                )
                .unwrap(),
            BlobStreamInspection::Missing
        );
    }

    #[test]
    fn inspect_stream_publication_does_not_translate_legacy_identity() {
        let (_root, store, _publisher, _operation, open) = fixture_with_len(0x6a, 1024);
        let policy = store.control_policy_snapshot().unwrap();
        let legacy_shaped = BlobPublicationStreamId::from_bytes([0x6b; 32]).unwrap();
        assert_eq!(
            store
                .inspect_blob_stream_with_policy(
                    &policy,
                    legacy_shaped,
                    open.open().topic(),
                    open.open().scope(),
                )
                .unwrap(),
            BlobStreamInspection::Missing
        );
    }

    #[test]
    fn inspect_stream_publication_fails_on_contradictory_authority() {
        let (_root, store, _publisher, operation, open) = fixture_with_len(0x6c, 1024);
        let policy = store.control_policy_snapshot().unwrap();
        let request = BlobStreamReservationRequest {
            operation: &operation,
            source: BlobStreamSource::AuthenticatedPeer([0x6d; 32]),
        };
        let (reservation, _) = store
            .reserve_blob_stream_with_policy(&policy, request, &open)
            .unwrap();
        let write = store.database.begin_write().unwrap();
        write
            .open_table(BLOB_STREAM_RETIREMENTS)
            .unwrap()
            .insert(
                reservation.stream_id().as_bytes().as_slice(),
                BlobStreamRetirement::new(&reservation).encode().as_slice(),
            )
            .unwrap();
        write.commit().unwrap();
        assert!(matches!(
            store.inspect_blob_stream_with_policy(
                &policy,
                reservation.stream_id(),
                open.open().topic(),
                open.open().scope(),
            ),
            Err(StoreError::Blob(BlobStoreError::SchemaInvariant(_)))
        ));
    }

    #[test]
    fn blob_stream_reservation_is_idempotent_invisible_and_supports_one_gib() {
        let (_root, store, _publisher, operation, open) = fixture(0x71);
        let policy = store.control_policy_snapshot().unwrap();
        let request = BlobStreamReservationRequest {
            operation: &operation,
            source: BlobStreamSource::LocalApplication,
        };
        let first = store
            .reserve_blob_stream_with_policy(&policy, request, &open)
            .unwrap();
        let second = store
            .reserve_blob_stream_with_policy(&policy, request, &open)
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.1, BlobStreamResume::default());
        assert!(store.blob_inventory().unwrap().is_empty());
    }

    #[test]
    fn blob_stream_checkpoint_projection_survives_reopen_and_never_advances_itself() {
        let (root, store, publisher, operation, open) = fixture(0x72);
        let policy = store.control_policy_snapshot().unwrap();
        let request = BlobStreamReservationRequest {
            operation: &operation,
            source: BlobStreamSource::LocalApplication,
        };
        let (reservation, initial) = store
            .reserve_blob_stream_with_policy(&policy, request, &open)
            .unwrap();
        let pack_root = PinnedBlobPackRoot::open(&store).unwrap();
        let mut writer = BlobPackWriter::create_pinned(&pack_root, open.open()).unwrap();
        let sealer = publisher.blob_stream_segment_sealer(&open).unwrap();
        let plaintext = vec![0x33; aster_mesh::BLOB_STREAM_SEGMENT_BYTES];
        let (segment, leaves) = sealer
            .seal(
                BlobStreamPlainPartition::new(
                    *open.open().stream_id().as_bytes(),
                    open.open().digest(),
                    open.open().content_epoch(),
                    0,
                    0,
                    open.open().total_len(),
                    plaintext,
                )
                .unwrap(),
            )
            .unwrap();
        writer.append(&segment, leaves).unwrap();

        assert_eq!(store.blob_stream_resume(&reservation).unwrap(), initial);
        let durable = writer.checkpoint().unwrap();
        let projected = store
            .checkpoint_blob_stream(&policy, &reservation, initial, durable.clone())
            .unwrap();
        assert_eq!(projected.generation(), durable.generation());
        assert_eq!(projected.next_segment_index(), 1);
        assert_eq!(
            projected.durable_plaintext_offset(),
            aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64
        );
        assert_eq!(
            store
                .checkpoint_blob_stream(&policy, &reservation, projected, durable)
                .unwrap(),
            projected
        );

        let mission = publisher.mission_authority_id();
        drop(store);
        let reopened = Store::open_for_mission(root.0.join("state.redb"), mission).unwrap();
        assert_eq!(
            reopened.blob_stream_resume(&reservation).unwrap(),
            projected
        );
        let reopened_root = PinnedBlobPackRoot::open(&reopened).unwrap();
        let resumed = BlobPackWriter::open_projected_pinned(
            &reopened_root,
            open.open(),
            projected.generation(),
            projected.next_segment_index(),
            projected.durable_plaintext_offset(),
            projected.durable_pack_len(),
            projected.durable_wire_offset(),
        )
        .unwrap();
        assert_eq!(resumed.next_index(), 1);
        assert!(reopened.blob_inventory().unwrap().is_empty());
    }

    #[test]
    fn blob_stream_abort_atomically_releases_reservation_and_operation() {
        let (_root, store, _publisher, operation, open) = fixture(0x73);
        let policy = store.control_policy_snapshot().unwrap();
        let request = BlobStreamReservationRequest {
            operation: &operation,
            source: BlobStreamSource::LocalApplication,
        };
        let (reservation, _) = store
            .reserve_blob_stream_with_policy(&policy, request, &open)
            .unwrap();

        assert!(store.abort_blob_stream(&reservation).unwrap());
        assert!(!store.abort_blob_stream(&reservation).unwrap());
        assert!(store.blob_stream_resume(&reservation).is_err());

        let replacement = store
            .reserve_blob_stream_with_policy(&policy, request, &open)
            .unwrap();
        assert_eq!(replacement.0, reservation);
    }

    #[test]
    fn blob_stream_promotion_is_atomic_visible_idempotent_and_restart_safe() {
        let total_len = aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64;
        let (root, store, publisher, operation, open) = fixture_with_len(0x74, total_len);
        let policy = store.control_policy_snapshot().unwrap();
        let request = BlobStreamReservationRequest {
            operation: &operation,
            source: BlobStreamSource::LocalApplication,
        };
        let (reservation, initial) = store
            .reserve_blob_stream_with_policy(&policy, request, &open)
            .unwrap();
        let pack_root = root.0.join("pack");
        let mut writer = BlobPackWriter::create(&pack_root, open.open()).unwrap();
        let sealer = publisher.blob_stream_segment_sealer(&open).unwrap();
        let (segment, leaves) = sealer
            .seal(
                BlobStreamPlainPartition::new(
                    *open.open().stream_id().as_bytes(),
                    open.open().digest(),
                    open.open().content_epoch(),
                    0,
                    0,
                    total_len,
                    vec![0x41; total_len as usize],
                )
                .unwrap(),
            )
            .unwrap();
        writer.append(&segment, leaves).unwrap();
        let durable = writer.checkpoint().unwrap();
        store
            .checkpoint_blob_stream(&policy, &reservation, initial, durable.clone())
            .unwrap();
        let roots = aster_mesh::BlobStreamFrontier::restore(durable.frontier().clone())
            .unwrap()
            .finish(total_len)
            .unwrap();
        let commitment =
            aster_mesh::BlobStreamFinalCommitment::new(&open, roots.0, roots.1, 1, None).unwrap();
        let signed = publisher.seal_blob_stream_commitment(&commitment).unwrap();
        let commitment = publisher
            .verify_blob_stream_commitment(&open, &signed)
            .unwrap();

        let promoted = store
            .promote_blob_stream_with_policy(&policy, &reservation, &commitment)
            .unwrap();
        assert!(!promoted.duplicate());
        assert_eq!(promoted.blob_id(), commitment.commitment().blob_id());
        assert!(store.blob_stream_resume(&reservation).is_err());
        let publications = store.blob_stream_publications_with_policy(&policy).unwrap();
        assert_eq!(publications.len(), 1);
        assert_eq!(publications[0].blob_id(), promoted.blob_id());
        assert_eq!(publications[0].pack_len(), durable.pack_len());
        let variant = super::super::blob_variant_id(
            promoted.blob_id(),
            &open.open().content_group(),
            open.open().content_epoch(),
        );
        let write = store.database.begin_write().unwrap();
        assert!(super::super::variant_has_valid_reference_write(&write, variant).unwrap());
        drop(write);
        let next = store
            .reserve_blob_with_policy(
                &policy,
                open.open().publisher(),
                open.open().topic(),
                open.open().scope(),
            )
            .unwrap();
        assert_eq!(next.counter(), 2);
        assert_eq!(next.context().counter(&open.open().publisher()), 1);

        let duplicate = store
            .promote_blob_stream_with_policy(&policy, &reservation, &commitment)
            .unwrap();
        assert!(duplicate.duplicate());
        assert_eq!(duplicate.acceptance_marker(), promoted.acceptance_marker());

        let mission = publisher.mission_authority_id();
        drop(store);
        let database = redb::Database::create(root.0.join("state.redb")).unwrap();
        let write = database.begin_write().unwrap();
        assert!(write.delete_table(BLOB_STREAM_VARIANTS).unwrap());
        assert!(write.delete_table(BLOB_STREAM_RETIREMENTS).unwrap());
        write.commit().unwrap();
        drop(database);
        let reopened = Store::open_for_mission(root.0.join("state.redb"), mission).unwrap();
        assert_eq!(
            reopened
                .blob_stream_publications_with_policy(&policy)
                .unwrap(),
            publications
        );
    }

    #[test]
    fn blob_stream_conflicting_finish_retains_bounded_evidence_without_visibility() {
        let total_len = aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64;
        let (root, store, publisher, operation, open) = fixture_with_len(0x75, total_len);
        let policy = store.control_policy_snapshot().unwrap();
        let request = BlobStreamReservationRequest {
            operation: &operation,
            source: BlobStreamSource::LocalApplication,
        };
        let (reservation, initial) = store
            .reserve_blob_stream_with_policy(&policy, request, &open)
            .unwrap();
        let mut writer = BlobPackWriter::create(&root.0.join("pack"), open.open()).unwrap();
        let sealer = publisher.blob_stream_segment_sealer(&open).unwrap();
        let (segment, leaves) = sealer
            .seal(
                BlobStreamPlainPartition::new(
                    *open.open().stream_id().as_bytes(),
                    open.open().digest(),
                    open.open().content_epoch(),
                    0,
                    0,
                    total_len,
                    vec![0x51; total_len as usize],
                )
                .unwrap(),
            )
            .unwrap();
        writer.append(&segment, leaves).unwrap();
        let durable = writer.checkpoint().unwrap();
        store
            .checkpoint_blob_stream(&policy, &reservation, initial, durable)
            .unwrap();
        let conflicting =
            aster_mesh::BlobStreamFinalCommitment::new(&open, [0x91; 32], [0x92; 32], 1, None)
                .unwrap();
        let signed = publisher.seal_blob_stream_commitment(&conflicting).unwrap();
        let conflicting = publisher
            .verify_blob_stream_commitment(&open, &signed)
            .unwrap();

        assert!(
            store
                .promote_blob_stream_with_policy(&policy, &reservation, &conflicting)
                .is_err()
        );
        assert!(
            store
                .blob_stream_publications_with_policy(&policy)
                .unwrap()
                .is_empty()
        );
        assert!(store.blob_stream_resume(&reservation).is_ok());
        let conflicts = store.blob_stream_conflicts_with_policy(&policy).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].stream_id(), reservation.stream_id());
        assert_eq!(conflicts[0].distinct_finishes(), 1);

        assert!(
            store
                .promote_blob_stream_with_policy(&policy, &reservation, &conflicting)
                .is_err()
        );
        assert_eq!(
            store.blob_stream_conflicts_with_policy(&policy).unwrap(),
            conflicts
        );

        let another_conflict =
            aster_mesh::BlobStreamFinalCommitment::new(&open, [0xa1; 32], [0xa2; 32], 1, None)
                .unwrap();
        let signed = publisher
            .seal_blob_stream_commitment(&another_conflict)
            .unwrap();
        let another_conflict = publisher
            .verify_blob_stream_commitment(&open, &signed)
            .unwrap();
        assert!(
            store
                .promote_blob_stream_with_policy(&policy, &reservation, &another_conflict)
                .is_err()
        );
        let conflicts = store.blob_stream_conflicts_with_policy(&policy).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].distinct_finishes(), 2);

        let mission = publisher.mission_authority_id();
        drop(store);
        let reopened = Store::open_for_mission(root.0.join("state.redb"), mission).unwrap();
        assert_eq!(
            reopened.blob_stream_conflicts_with_policy(&policy).unwrap(),
            conflicts
        );
        assert!(
            reopened
                .blob_stream_publications_with_policy(&policy)
                .unwrap()
                .is_empty()
        );
        assert!(reopened.abort_blob_stream(&reservation).unwrap());
        assert!(
            reopened
                .blob_stream_conflicts_with_policy(&policy)
                .unwrap()
                .is_empty()
        );
        drop(reopened);
        let reopened = Store::open_for_mission(root.0.join("state.redb"), mission).unwrap();
        assert!(
            reopened
                .blob_stream_conflicts_with_policy(&policy)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn blob_stream_expired_finish_reclaims_provisional_authority() {
        let total_len = aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64;
        let initial = aster_mesh::CustodySample {
            clock_id: [0x31; 16],
            tick_ms: 10_000,
        };
        let (root, store, publisher, operation, open) =
            fixture_with_lifetime(0x76, total_len, Some(1_000), Some(initial));
        let policy = store.control_policy_snapshot().unwrap();
        let request = BlobStreamReservationRequest {
            operation: &operation,
            source: BlobStreamSource::LocalApplication,
        };
        let (reservation, resume) = store
            .reserve_blob_stream_with_policy(&policy, request, &open)
            .unwrap();
        let mut writer = BlobPackWriter::create(&root.0.join("pack"), open.open()).unwrap();
        let sealer = publisher.blob_stream_segment_sealer(&open).unwrap();
        let (segment, leaves) = sealer
            .seal(
                BlobStreamPlainPartition::new(
                    *open.open().stream_id().as_bytes(),
                    open.open().digest(),
                    open.open().content_epoch(),
                    0,
                    0,
                    total_len,
                    vec![0x61; total_len as usize],
                )
                .unwrap(),
            )
            .unwrap();
        writer.append(&segment, leaves).unwrap();
        let durable = writer.checkpoint().unwrap();
        store
            .checkpoint_blob_stream(&policy, &reservation, resume, durable.clone())
            .unwrap();
        let roots = BlobStreamFrontier::restore(durable.frontier().clone())
            .unwrap()
            .finish(total_len)
            .unwrap();
        let expired_sample = aster_mesh::CustodySample {
            clock_id: initial.clock_id,
            tick_ms: initial.tick_ms + 1_000,
        };
        let commitment =
            BlobStreamFinalCommitment::new(&open, roots.0, roots.1, 1, Some(expired_sample))
                .unwrap();
        let signed = publisher.seal_blob_stream_commitment(&commitment).unwrap();
        let commitment = publisher
            .verify_blob_stream_commitment(&open, &signed)
            .unwrap();

        assert!(
            store
                .promote_blob_stream_with_policy(&policy, &reservation, &commitment)
                .is_err()
        );
        assert!(store.blob_stream_resume(&reservation).is_err());
        assert!(
            store
                .blob_stream_publications_with_policy(&policy)
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .blob_stream_conflicts_with_policy(&policy)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            store.reserve_blob_stream_with_policy(&policy, request, &open),
            Err(StoreError::Blob(BlobStoreError::ExpiredOrRetired))
        ));
    }

    #[test]
    fn blob_stream_revoked_publisher_reclaims_provisional_authority() {
        let total_len = aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64;
        let (root, store, mut publisher, operation, open) = fixture_with_len(0x78, total_len);
        let policy = store.control_policy_snapshot().unwrap();
        let request = BlobStreamReservationRequest {
            operation: &operation,
            source: BlobStreamSource::LocalApplication,
        };
        let (reservation, _) = store
            .reserve_blob_stream_with_policy(&policy, request, &open)
            .unwrap();

        let revocation = publisher
            .seal_chained_revocation_control(publisher.identity(), 1, 1, None)
            .unwrap();
        let verified_revocation = publisher.verify_control(&revocation).unwrap();
        store
            .ingest_verified_control(&verified_revocation, &revocation)
            .unwrap();
        let current_policy = store.control_policy_snapshot().unwrap();
        let commitment =
            BlobStreamFinalCommitment::new(&open, [0xb1; 32], [0xb2; 32], 1, None).unwrap();
        let signed = publisher.seal_blob_stream_commitment(&commitment).unwrap();
        let commitment = publisher
            .verify_blob_stream_commitment(&open, &signed)
            .unwrap();

        assert!(matches!(
            store.promote_blob_stream_with_policy(&current_policy, &reservation, &commitment),
            Err(StoreError::Blob(BlobStoreError::PublisherRevoked(publisher_id)))
                if publisher_id == publisher.identity()
        ));
        assert!(store.blob_stream_resume(&reservation).is_err());
        drop(store);
        let reopened =
            Store::open_for_mission(root.0.join("state.redb"), publisher.mission_authority_id())
                .unwrap();
        assert!(reopened.blob_stream_resume(&reservation).is_err());
    }

    #[test]
    fn blob_stream_promotion_respects_deletion_fence() {
        let total_len = aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64;
        let (root, store, publisher, operation, open) = fixture_with_len(0x79, total_len);
        let policy = store.control_policy_snapshot().unwrap();
        let request = BlobStreamReservationRequest {
            operation: &operation,
            source: BlobStreamSource::LocalApplication,
        };
        let (reservation, resume) = store
            .reserve_blob_stream_with_policy(&policy, request, &open)
            .unwrap();
        let mut writer = BlobPackWriter::create(&root.0.join("pack"), open.open()).unwrap();
        let sealer = publisher.blob_stream_segment_sealer(&open).unwrap();
        let (segment, leaves) = sealer
            .seal(
                BlobStreamPlainPartition::new(
                    *open.open().stream_id().as_bytes(),
                    open.open().digest(),
                    open.open().content_epoch(),
                    0,
                    0,
                    total_len,
                    vec![0xc1; total_len as usize],
                )
                .unwrap(),
            )
            .unwrap();
        writer.append(&segment, leaves).unwrap();
        let durable = writer.checkpoint().unwrap();
        store
            .checkpoint_blob_stream(&policy, &reservation, resume, durable.clone())
            .unwrap();
        let roots = BlobStreamFrontier::restore(durable.frontier().clone())
            .unwrap()
            .finish(total_len)
            .unwrap();
        let commitment = BlobStreamFinalCommitment::new(&open, roots.0, roots.1, 1, None).unwrap();
        let signed = publisher.seal_blob_stream_commitment(&commitment).unwrap();
        let commitment = publisher
            .verify_blob_stream_commitment(&open, &signed)
            .unwrap();
        let content_group = open.open().content_group();
        let variant = super::super::blob_variant_id(
            commitment.commitment().blob_id(),
            &content_group,
            open.open().content_epoch(),
        );
        let write = store.database.begin_write().unwrap();
        super::super::deletion::insert_variant_fence_for_test(
            &write,
            variant,
            commitment.commitment().blob_id(),
            content_group,
            open.open().content_epoch(),
        )
        .unwrap();
        write.commit().unwrap();

        assert!(matches!(
            store.promote_blob_stream_with_policy(&policy, &reservation, &commitment),
            Err(StoreError::Blob(BlobStoreError::VariantDeleting))
        ));
        assert!(store.blob_stream_resume(&reservation).is_ok());
        assert!(
            store
                .blob_stream_publications_with_policy(&policy)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn blob_stream_conflict_table_is_additive_for_predecessor_stream_schema() {
        let (root, store, publisher, _operation, _open) = fixture(0x77);
        drop(store);
        let database = redb::Database::create(root.0.join("state.redb")).unwrap();
        let write = database.begin_write().unwrap();
        assert!(write.delete_table(BLOB_STREAM_CONFLICTS).unwrap());
        assert!(write.delete_table(BLOB_STREAM_VARIANTS).unwrap());
        assert!(write.delete_table(BLOB_STREAM_RETIREMENTS).unwrap());
        write.commit().unwrap();
        drop(database);

        let reopened =
            Store::open_for_mission(root.0.join("state.redb"), publisher.mission_authority_id())
                .unwrap();
        let policy = reopened.control_policy_snapshot().unwrap();
        assert!(
            reopened
                .blob_stream_conflicts_with_policy(&policy)
                .unwrap()
                .is_empty()
        );
    }
}
