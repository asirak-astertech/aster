//! Durable provisional authority for pack-backed Blob streams.

use super::{
    BLOB_STREAM_OPERATIONS, BLOB_STREAM_RESERVATIONS, BlobOperationKey, BlobStoreError,
    MAX_BLOB_OPERATION_KEY_BYTES, Store, blob_content_prefix_upper_bound, blob_error,
    synchronize_blob_policy_generation_write,
};
use crate::{
    CAUSAL_FRONTIER, CONTROL_SCOPE_EPOCHS, ControlPolicySnapshot, Dot, PUBLISHER_HIGH_WATER,
    SemanticDataClass, StoreError, VersionVector, control_principal_revoked_write,
    decode_scope_epoch_index, enforce_live_write, ensure_frontier_capacity, event_domain_prefix,
    require_control_policy_write,
};
use aster_mesh::{
    BLOB_STREAM_SEGMENT_BYTES, BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES, BlobPublicationStreamId,
    BlobStreamOpen, NodeId, VerifiedBlobStreamOpen,
};
use redb::{Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata};

use super::pack::{BlobPackCheckpoint, BlobPackError};

const PROVISIONAL_MAGIC: &[u8; 8] = b"ASTRPR02";
const PROVISIONAL_VERSION: u8 = 1;
const MAX_PROVISIONAL_STREAMS: u64 = 64;
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
}

impl BlobStreamResume {
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

pub(super) fn audit_blob_stream_tables_write(
    write: &redb::WriteTransaction,
    mission_authority: Option<NodeId>,
) -> Result<(), StoreError> {
    let reservations = write.open_table(BLOB_STREAM_RESERVATIONS)?;
    let operations = write.open_table(BLOB_STREAM_OPERATIONS)?;
    if reservations.len()? != operations.len()? || reservations.len()? > MAX_PROVISIONAL_STREAMS {
        return Err(schema_error());
    }
    let authority = if reservations.is_empty()? {
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
    for row in operations.iter()? {
        let (operation, stream) = row?;
        if operation.value().is_empty()
            || operation.value().len() > MAX_BLOB_OPERATION_KEY_BYTES
            || stream.value().len() != 32
            || reservations.get(stream.value())?.is_none()
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
        require_stream_policy_write(&write, authority, policy, &provisional.reservation.open)?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pack::BlobPackWriter;
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

    struct TestRoot(PathBuf);

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
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
            None,
            None,
            1024 * 1024 * 1024,
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
        let pack_root = root.0.join("pack");
        let mut writer = BlobPackWriter::create(&pack_root, open.open()).unwrap();
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
        assert!(reopened.blob_inventory().unwrap().is_empty());
    }
}
