//! PR #95 lifecycle ownership for canonical Profile-5 pack variants.

use super::pack::{BlobPackCompletion, BlobPackError};
use super::upload::BlobUploadCapacity;
use super::{BlobStoreError, BlobVariantId, StoreError, blob_error, blob_variant_id};
use aster_mesh::{
    BlobPhysicalLineage, BlobStreamFinalCommitment, BlobStreamOpen, SourceRouteLineage,
};
use redb::{ReadableTable, TableDefinition};
use sha2::{Digest, Sha256};
use std::sync::Arc;

pub(crate) const BLOB_PROFILE5_PACKS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("aster.blob-profile5-packs.v1");

const PACK_VARIANT_MAGIC: &[u8; 8] = b"ASTRPV01";
const PACK_VARIANT_VERSION: u16 = 1;
const PACK_SOURCE_MAGIC: &[u8; 8] = b"ASTRPS01";
const PACK_SOURCE_VERSION: u16 = 1;

/// Nonconstructible Store-bound projection of one lifecycle-owned Profile-5
/// physical variant.
#[derive(Clone, Debug)]
pub struct BlobPackVariant {
    variant_id: BlobVariantId,
    route_lineage: [u8; 32],
    physical_lineage: [u8; 32],
    owner_binding: [u8; 32],
    authenticated_open_digest: [u8; 32],
    open: BlobStreamOpen,
    authenticated_open: Vec<u8>,
    commitment: BlobStreamFinalCommitment,
    authenticated_commitment: Vec<u8>,
    completion: BlobPackCompletion,
    capacity: BlobUploadCapacity,
    lifecycle_owned: bool,
    authority: Arc<()>,
}

impl PartialEq for BlobPackVariant {
    fn eq(&self, other: &Self) -> bool {
        self.variant_id == other.variant_id
            && self.route_lineage == other.route_lineage
            && self.physical_lineage == other.physical_lineage
            && self.owner_binding == other.owner_binding
            && self.authenticated_open_digest == other.authenticated_open_digest
            && self.open == other.open
            && self.authenticated_open == other.authenticated_open
            && self.commitment == other.commitment
            && self.authenticated_commitment == other.authenticated_commitment
            && self.completion == other.completion
            && self.capacity == other.capacity
            && self.lifecycle_owned == other.lifecycle_owned
    }
}

impl Eq for BlobPackVariant {}

impl BlobPackVariant {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        route_lineage: SourceRouteLineage,
        physical_lineage: BlobPhysicalLineage,
        owner_binding: [u8; 32],
        open: BlobStreamOpen,
        authenticated_open: Vec<u8>,
        commitment: BlobStreamFinalCommitment,
        authenticated_commitment: Vec<u8>,
        completion: BlobPackCompletion,
        capacity: BlobUploadCapacity,
        authority: Arc<()>,
    ) -> Result<Self, StoreError> {
        let variant_id = blob_variant_id(
            commitment.blob_id(),
            &open.content_group(),
            open.content_epoch(),
        );
        let variant = Self {
            variant_id,
            route_lineage: *route_lineage.binding(),
            physical_lineage: *physical_lineage.binding(),
            owner_binding,
            authenticated_open_digest: Sha256::digest(&authenticated_open).into(),
            open,
            authenticated_open,
            commitment,
            authenticated_commitment,
            completion,
            capacity,
            lifecycle_owned: false,
            authority,
        };
        variant.validate()?;
        Ok(variant)
    }

    pub const fn variant_id(&self) -> BlobVariantId {
        self.variant_id
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

    pub const fn completion(&self) -> &BlobPackCompletion {
        &self.completion
    }

    pub const fn route_lineage(&self) -> &[u8; 32] {
        &self.route_lineage
    }

    pub const fn physical_lineage(&self) -> &[u8; 32] {
        &self.physical_lineage
    }

    pub(super) const fn capacity(&self) -> BlobUploadCapacity {
        self.capacity
    }

    pub(super) const fn lifecycle_owned(&self) -> bool {
        self.lifecycle_owned
    }

    pub(super) const fn owner_binding(&self) -> &[u8; 32] {
        &self.owner_binding
    }

    pub(super) fn source_record(&self) -> Result<Vec<u8>, StoreError> {
        let open_len = u32::try_from(self.authenticated_open.len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
        let finish_len = u32::try_from(self.authenticated_commitment.len())
            .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
        let mut source = Vec::with_capacity(
            8 + 2 + 4 + self.authenticated_open.len() + 4 + self.authenticated_commitment.len(),
        );
        source.extend_from_slice(PACK_SOURCE_MAGIC);
        source.extend_from_slice(&PACK_SOURCE_VERSION.to_be_bytes());
        source.extend_from_slice(&open_len.to_be_bytes());
        source.extend_from_slice(&self.authenticated_open);
        source.extend_from_slice(&finish_len.to_be_bytes());
        source.extend_from_slice(&self.authenticated_commitment);
        Ok(source)
    }

    pub(super) fn semantic_digest(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"aster/blob-profile5-semantic/v1\0");
        digest.update(self.open.publisher());
        digest.update(self.open.publisher_counter().to_be_bytes());
        digest.update(self.open.digest());
        digest.update(self.commitment.encode());
        digest.finalize().into()
    }

    pub(super) fn is_bound_to(&self, authority: &Arc<()>) -> bool {
        Arc::ptr_eq(&self.authority, authority) && self.completion.is_bound_to(authority)
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.route_lineage == [0; 32]
            || self.physical_lineage == [0; 32]
            || self.owner_binding == [0; 32]
            || self.authenticated_open.is_empty()
            || self.authenticated_commitment.is_empty()
            || self.variant_id
                != blob_variant_id(
                    self.commitment.blob_id(),
                    &self.open.content_group(),
                    self.open.content_epoch(),
                )
            || self.commitment.open_digest() != &self.open.digest()
            || self.commitment.stream_id() != self.open.stream_id()
            || self.commitment.total_len() != self.open.total_len()
            || self.commitment.content_epoch() != self.open.content_epoch()
            || self.commitment.ttl_ms() != self.open.ttl_ms()
            || self.completion.identity().upload_id() != self.open.stream_id()
            || self.completion.identity().request_digest() != &self.open.digest()
            || self.completion.identity().total_len() != self.open.total_len()
            || self.completion.segment_count() != self.commitment.segment_count()
            || self.completion.plaintext_root() != self.commitment.plaintext_root()
            || self.completion.ciphertext_root() != self.commitment.ciphertext_root()
            || self.completion.blob_id() != self.commitment.blob_id()
            || Sha256::digest(&self.authenticated_open).as_slice() != self.authenticated_open_digest
            || Sha256::digest(self.commitment.encode()).as_slice()
                != self.completion.commitment_digest()
            || Sha256::digest(&self.authenticated_commitment).as_slice()
                != self.completion.authenticated_commitment_digest()
            || self.capacity.bytes
                != super::pack::reserved_upload_pack_bytes(self.open.total_len())?
            || self.capacity.chunks != self.commitment.segment_count()
            || self.capacity.variants != 1
        {
            return Err(pack_schema_error());
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        self.validate()?;
        let open = self.open.encode();
        let commitment = self.commitment.encode();
        let completion = self.completion.encode().map_err(pack_store_error)?;
        let mut output = Vec::new();
        output.extend_from_slice(PACK_VARIANT_MAGIC);
        output.extend_from_slice(&PACK_VARIANT_VERSION.to_be_bytes());
        output.extend_from_slice(self.variant_id.as_bytes());
        output.extend_from_slice(&self.route_lineage);
        output.extend_from_slice(&self.physical_lineage);
        output.extend_from_slice(&self.owner_binding);
        output.extend_from_slice(&self.authenticated_open_digest);
        output.extend_from_slice(&self.capacity.bytes.to_be_bytes());
        output.extend_from_slice(&self.capacity.chunks.to_be_bytes());
        output.extend_from_slice(&self.capacity.variants.to_be_bytes());
        output.push(u8::from(self.lifecycle_owned));
        for bytes in [
            open.as_slice(),
            self.authenticated_open.as_slice(),
            commitment.as_slice(),
            self.authenticated_commitment.as_slice(),
            completion.as_slice(),
        ] {
            let len = u32::try_from(bytes.len())
                .map_err(|_| StoreError::PayloadByteAccountingOverflow)?;
            output.extend_from_slice(&len.to_be_bytes());
            output.extend_from_slice(bytes);
        }
        Ok(output)
    }

    fn decode(encoded: &[u8], authority: Arc<()>) -> Result<Self, StoreError> {
        let mut cursor = Cursor::new(encoded);
        if cursor.take(8)? != PACK_VARIANT_MAGIC || cursor.u16()? != PACK_VARIANT_VERSION {
            return Err(pack_schema_error());
        }
        let variant_id = BlobVariantId::from_bytes(cursor.array()?);
        let route_lineage = cursor.array()?;
        let physical_lineage = cursor.array()?;
        let owner_binding = cursor.array()?;
        let authenticated_open_digest = cursor.array()?;
        let capacity = BlobUploadCapacity {
            bytes: cursor.u64()?,
            chunks: cursor.u64()?,
            variants: cursor.u64()?,
        };
        let lifecycle_owned = match cursor.u8()? {
            0 => false,
            1 => true,
            _ => return Err(pack_schema_error()),
        };
        let open = BlobStreamOpen::decode(cursor.long()?).map_err(|_| pack_schema_error())?;
        let authenticated_open = cursor.long()?.to_vec();
        let commitment =
            BlobStreamFinalCommitment::decode(cursor.long()?).map_err(|_| pack_schema_error())?;
        let authenticated_commitment = cursor.long()?.to_vec();
        let completion = BlobPackCompletion::decode(cursor.long()?, Arc::clone(&authority))
            .map_err(pack_store_error)?;
        cursor.finish()?;
        let variant = Self {
            variant_id,
            route_lineage,
            physical_lineage,
            owner_binding,
            authenticated_open_digest,
            open,
            authenticated_open,
            commitment,
            authenticated_commitment,
            completion,
            capacity,
            lifecycle_owned,
            authority,
        };
        variant.validate()?;
        Ok(variant)
    }
}

pub(super) fn insert_write(
    write: &redb::WriteTransaction,
    variant: &BlobPackVariant,
) -> Result<(), StoreError> {
    require_owner_binding(
        super::depot::depot_owner_binding_if_present_write(write)?,
        variant.owner_binding,
    )?;
    let key = variant.variant_id.as_bytes().as_slice();
    let encoded = variant.encode()?;
    let mut packs = write.open_table(BLOB_PROFILE5_PACKS)?;
    if let Some(existing) = packs.get(key)? {
        let existing = BlobPackVariant::decode(existing.value(), Arc::new(()))?;
        if existing != *variant {
            return Err(blob_error(BlobStoreError::PhysicalLineageConflict));
        }
        return Ok(());
    }
    if write.open_table(super::BLOB_IMPORTS)?.get(key)?.is_some() {
        return Err(blob_error(BlobStoreError::PhysicalLineageConflict));
    }
    packs.insert(key, encoded.as_slice())?;
    Ok(())
}

pub(super) fn load_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    authority: Arc<()>,
) -> Result<Option<BlobPackVariant>, StoreError> {
    let owner_binding = super::depot::depot_owner_binding_if_present_write(write)?;
    write
        .open_table(BLOB_PROFILE5_PACKS)?
        .get(variant.as_bytes().as_slice())?
        .map(|value| {
            let expected_authority = Arc::clone(&authority);
            let pack = BlobPackVariant::decode(value.value(), authority)?;
            require_owner_binding(owner_binding, pack.owner_binding)?;
            if !pack.is_bound_to(&expected_authority) {
                return Err(pack_schema_error());
            }
            Ok(pack)
        })
        .transpose()
}

pub(super) fn load_read(
    read: &redb::ReadTransaction,
    variant: BlobVariantId,
    authority: Arc<()>,
) -> Result<Option<BlobPackVariant>, StoreError> {
    let owner_binding = super::depot::depot_owner_binding_if_present_read(read)?;
    read.open_table(BLOB_PROFILE5_PACKS)?
        .get(variant.as_bytes().as_slice())?
        .map(|value| {
            let expected_authority = Arc::clone(&authority);
            let pack = BlobPackVariant::decode(value.value(), authority)?;
            require_owner_binding(owner_binding, pack.owner_binding)?;
            if !pack.is_bound_to(&expected_authority) {
                return Err(pack_schema_error());
            }
            Ok(pack)
        })
        .transpose()
}

pub(super) fn reconstruct_capacity_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<Option<BlobUploadCapacity>, StoreError> {
    load_write(write, variant, Arc::new(())).map(|value| value.map(|value| value.capacity))
}

pub(super) fn remove_provisional_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    expected: &BlobPackCompletion,
) -> Result<(), StoreError> {
    let pack = load_write(write, variant, Arc::new(()))?.ok_or_else(pack_schema_error)?;
    if pack.lifecycle_owned || pack.completion() != expected {
        return Err(pack_schema_error());
    }
    write
        .open_table(BLOB_PROFILE5_PACKS)?
        .remove(variant.as_bytes().as_slice())?;
    Ok(())
}

pub(super) fn promote_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
    expected: &BlobPackCompletion,
    authority: Arc<()>,
) -> Result<BlobUploadCapacity, StoreError> {
    let mut pack = load_write(write, variant, authority)?.ok_or_else(pack_schema_error)?;
    if pack.completion() != expected {
        return Err(pack_schema_error());
    }
    if !pack.lifecycle_owned {
        pack.lifecycle_owned = true;
        let encoded = pack.encode()?;
        write
            .open_table(BLOB_PROFILE5_PACKS)?
            .insert(variant.as_bytes().as_slice(), encoded.as_slice())?;
    }
    Ok(pack.capacity)
}

pub(super) fn active_capacity_usage_write(
    write: &redb::WriteTransaction,
) -> Result<BlobUploadCapacity, StoreError> {
    capacity_usage(&write.open_table(BLOB_PROFILE5_PACKS)?)
}

pub(super) fn active_capacity_usage_read(
    read: &redb::ReadTransaction,
) -> Result<BlobUploadCapacity, StoreError> {
    capacity_usage(&read.open_table(BLOB_PROFILE5_PACKS)?)
}

fn capacity_usage(
    packs: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<BlobUploadCapacity, StoreError> {
    let mut usage = BlobUploadCapacity::default();
    for row in packs.iter()? {
        let (_, value) = row?;
        let pack = BlobPackVariant::decode(value.value(), Arc::new(()))?;
        if pack.lifecycle_owned {
            usage = usage.checked_add(pack.capacity())?;
        }
    }
    Ok(usage)
}

pub(super) fn active_pack_expectations_write(
    write: &redb::WriteTransaction,
) -> Result<Vec<super::pack::ExpectedBlobUploadPack>, StoreError> {
    active_pack_expectations(&write.open_table(BLOB_PROFILE5_PACKS)?)
}

pub(super) fn active_pack_expectations_read(
    read: &redb::ReadTransaction,
) -> Result<Vec<super::pack::ExpectedBlobUploadPack>, StoreError> {
    active_pack_expectations(&read.open_table(BLOB_PROFILE5_PACKS)?)
}

fn active_pack_expectations(
    packs: &impl ReadableTable<&'static [u8], &'static [u8]>,
) -> Result<Vec<super::pack::ExpectedBlobUploadPack>, StoreError> {
    let mut expected = Vec::new();
    for row in packs.iter()? {
        let (_, value) = row?;
        let pack = BlobPackVariant::decode(value.value(), Arc::new(()))?;
        if pack.lifecycle_owned {
            expected.push(super::pack::ExpectedBlobUploadPack {
                identity: pack.completion.identity(),
                checkpoint: Some(pack.completion.checkpoint().clone()),
            });
        }
    }
    Ok(expected)
}

pub(super) fn reconstruct_capacity_read(
    read: &redb::ReadTransaction,
    variant: BlobVariantId,
) -> Result<Option<BlobUploadCapacity>, StoreError> {
    load_read(read, variant, Arc::new(())).map(|value| value.map(|value| value.capacity))
}

pub(super) fn variant_progress_write(
    write: &redb::WriteTransaction,
    variant: BlobVariantId,
) -> Result<Option<(u64, u64)>, StoreError> {
    Ok(load_write(write, variant, Arc::new(()))?
        .map(|pack| (pack.open.total_len(), pack.open.total_len())))
}

pub(super) fn audit_write(write: &redb::WriteTransaction) -> Result<(), StoreError> {
    let packs = write.open_table(BLOB_PROFILE5_PACKS)?;
    let owner_binding = super::depot::depot_owner_binding_if_present_write(write)?;
    for row in packs.iter()? {
        let (key, value) = row?;
        let pack = BlobPackVariant::decode(value.value(), Arc::new(()))?;
        if key.value() != pack.variant_id.as_bytes()
            || write
                .open_table(super::BLOB_IMPORTS)?
                .get(key.value())?
                .is_some()
        {
            return Err(pack_schema_error());
        }
        require_owner_binding(owner_binding, pack.owner_binding)?;
    }
    Ok(())
}

pub(super) fn audit_read(read: &redb::ReadTransaction) -> Result<(), StoreError> {
    let packs = read.open_table(BLOB_PROFILE5_PACKS)?;
    let imports = read.open_table(super::BLOB_IMPORTS)?;
    let owner_binding = super::depot::depot_owner_binding_if_present_read(read)?;
    for row in packs.iter()? {
        let (key, value) = row?;
        let pack = BlobPackVariant::decode(value.value(), Arc::new(()))?;
        if key.value() != pack.variant_id.as_bytes() || imports.get(key.value())?.is_some() {
            return Err(pack_schema_error());
        }
        require_owner_binding(owner_binding, pack.owner_binding)?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn audit_publication_evidence(
    encoded: &[u8],
    variant: BlobVariantId,
    blob_id: aster_mesh::BlobId,
    epoch: u64,
    manifest_digest: [u8; 32],
    segment_count: u64,
    physical_lineage: Option<[u8; 32]>,
    owner_binding: [u8; 32],
) -> Result<(), StoreError> {
    let pack = BlobPackVariant::decode(encoded, Arc::new(()))?;
    if !pack.lifecycle_owned
        || pack.variant_id != variant
        || pack.commitment.blob_id() != blob_id
        || pack.open.content_epoch() != epoch
        || pack.completion.commitment_digest() != &manifest_digest
        || pack.commitment.segment_count() != segment_count
        || physical_lineage != Some(pack.physical_lineage)
        || pack.owner_binding != owner_binding
    {
        return Err(pack_schema_error());
    }
    Ok(())
}

pub(super) fn pressure_projection(
    encoded: &[u8],
) -> Result<Option<(BlobVariantId, u64)>, StoreError> {
    let pack = BlobPackVariant::decode(encoded, Arc::new(()))?;
    Ok(pack
        .lifecycle_owned
        .then_some((pack.variant_id, pack.open.total_len())))
}

pub(super) fn audited_lifecycle_imports_write(
    write: &redb::WriteTransaction,
) -> Result<Vec<super::depot::AuditedLifecycleImport>, StoreError> {
    let owner_binding = super::depot::depot_owner_binding_if_present_write(write)?;
    audited_lifecycle_imports(&write.open_table(BLOB_PROFILE5_PACKS)?, owner_binding)
}

pub(super) fn audited_lifecycle_imports_read(
    read: &redb::ReadTransaction,
) -> Result<Vec<super::depot::AuditedLifecycleImport>, StoreError> {
    let owner_binding = super::depot::depot_owner_binding_if_present_read(read)?;
    audited_lifecycle_imports(&read.open_table(BLOB_PROFILE5_PACKS)?, owner_binding)
}

fn audited_lifecycle_imports(
    packs: &impl ReadableTable<&'static [u8], &'static [u8]>,
    owner_binding: Option<[u8; 32]>,
) -> Result<Vec<super::depot::AuditedLifecycleImport>, StoreError> {
    packs
        .iter()?
        .map(|row| {
            let (key, value) = row?;
            let pack = BlobPackVariant::decode(value.value(), Arc::new(()))?;
            require_owner_binding(owner_binding, pack.owner_binding)?;
            if key.value() != pack.variant_id.as_bytes() {
                return Err(pack_schema_error());
            }
            Ok(super::depot::AuditedLifecycleImport {
                variant_id: pack.variant_id,
                physical_lineage: pack.physical_lineage,
            })
        })
        .collect()
}

fn require_owner_binding(durable: Option<[u8; 32]>, actual: [u8; 32]) -> Result<(), StoreError> {
    if durable == Some(actual) {
        Ok(())
    } else {
        Err(blob_error(BlobStoreError::PhysicalLineageConflict))
    }
}

fn pack_schema_error() -> StoreError {
    blob_error(BlobStoreError::SchemaInvariant(
        "Profile-5 pack lifecycle row is malformed",
    ))
}

fn pack_store_error(error: BlobPackError) -> StoreError {
    match error {
        BlobPackError::Store(error) => error,
        BlobPackError::Io(error) => blob_error(BlobStoreError::Io(error)),
        BlobPackError::Invalid(message) => blob_error(BlobStoreError::DepotIntegrity(message)),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], StoreError> {
        let end = self.offset.checked_add(len).ok_or_else(pack_schema_error)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(pack_schema_error)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], StoreError> {
        self.take(N)?.try_into().map_err(|_| pack_schema_error())
    }

    fn u16(&mut self) -> Result<u16, StoreError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.array::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, StoreError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn long(&mut self) -> Result<&'a [u8], StoreError> {
        let len = usize::try_from(self.u32()?).map_err(|_| pack_schema_error())?;
        self.take(len)
    }

    fn finish(self) -> Result<(), StoreError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(pack_schema_error())
        }
    }
}
