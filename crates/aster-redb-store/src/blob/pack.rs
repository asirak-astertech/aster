//! Sequential encrypted stream pack with alternating durable checkpoints.

use aster_mesh::{
    BLOB_STREAM_SEGMENT_BYTES, BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES, BlobPublicationStreamId,
    BlobStreamCheckpoint, BlobStreamFrontier, BlobStreamOpen, BlobStreamSegmentLeaves,
    BlobStreamSubtree, EncryptedBlobStreamSegment,
};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use super::depot::{OwnedDirectory, open_blob_pack_root};
use super::{BlobStoreError, blob_error};
use crate::{Store, StoreError};

const PACK_MAGIC: &[u8; 8] = b"ASTRPK02";
const CHECKPOINT_MAGIC: &[u8; 8] = b"ASTRCP02";
const PACK_VERSION: u16 = 2;
const PACK_FILE: &str = "segments.pack";
const CHECKPOINT_ZERO: &str = "checkpoint.0";
const CHECKPOINT_ONE: &str = "checkpoint.1";
pub(super) const PACK_HEADER_LEN: u64 = 8 + 2 + 32 + 32 + 8;
const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;
const PACK_FIXED_RESERVATION_BYTES: u64 = 64 * 1024;
const UPLOAD_MARKER: &str = ".aster-upload-v1";
const UPLOAD_MARKER_MAGIC: &[u8; 8] = b"ASTRUM01";
const UPLOAD_CLEANUP_MAGIC: &[u8; 8] = b"ASTRUC01";
const UPLOAD_CLEANUP_PREFIX: &str = ".aster-upload-cleanup-";
const UPLOAD_RESERVATION_MAGIC: &[u8; 8] = b"ASTRUR01";
const UPLOAD_RESERVATION_PREFIX: &str = ".aster-upload-reservation-";
const PACK_TEMP_PREFIX: &str = ".aster-blob-tmp-";
const PACK_DIRECTORY: &str = "stream-packs-v2";

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BlobPackFaultPoint {
    DataSynced,
    CheckpointZeroSynced,
    CheckpointOneSynced,
    CleanupDurable,
}

#[cfg(test)]
static TEST_PACK_FAULTS: std::sync::Mutex<Vec<(PathBuf, BlobPackFaultPoint)>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
pub(super) fn inject_test_fault(root: &PinnedBlobPackRoot, point: BlobPackFaultPoint) {
    TEST_PACK_FAULTS
        .lock()
        .expect("Blob pack test fault lock")
        .push((root.directory.path().to_owned(), point));
}

#[cfg(test)]
fn maybe_inject_fault(path: &Path, point: BlobPackFaultPoint) -> Result<(), BlobPackError> {
    let mut faults = TEST_PACK_FAULTS
        .lock()
        .map_err(|_| BlobPackError::Invalid("Blob pack test fault lock is poisoned"))?;
    if let Some(index) = faults.iter().position(|(expected, expected_point)| {
        (expected == path || path.parent() == Some(expected.as_path())) && *expected_point == point
    }) {
        faults.swap_remove(index);
        return Err(BlobPackError::Io(std::io::Error::other(
            "injected Blob pack crash boundary",
        )));
    }
    Ok(())
}

pub(crate) fn reserved_upload_pack_bytes(total_len: u64) -> Result<u64, StoreError> {
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

#[derive(Debug)]
pub enum BlobPackError {
    Io(std::io::Error),
    Store(StoreError),
    Invalid(&'static str),
}

impl Display for BlobPackError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => Display::fmt(error, formatter),
            Self::Store(error) => Display::fmt(error, formatter),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

impl Error for BlobPackError {}

impl From<std::io::Error> for BlobPackError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<StoreError> for BlobPackError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Store-owned capability for Blob pack placement. The directory remains
/// descriptor-pinned on Unix so stream reopen never follows a replaced path.
#[doc(hidden)]
pub struct PinnedBlobPackRoot {
    directory: OwnedDirectory,
    authority: Arc<()>,
}

impl PinnedBlobPackRoot {
    pub fn open(store: &Store) -> Result<Self, StoreError> {
        Ok(Self {
            directory: open_blob_pack_root(store)?,
            authority: Arc::clone(&store.blob_completion_authority),
        })
    }

    #[cfg(test)]
    pub(super) fn test_upload_path(&self, identity: &BlobPackIdentity) -> PathBuf {
        self.directory
            .path()
            .join(hex32(identity.upload_id.as_bytes()))
    }

    fn stream_id(
        &self,
        stream_id: BlobPublicationStreamId,
        create: bool,
    ) -> Result<BlobPackRoot, BlobPackError> {
        Ok(BlobPackRoot::Pinned(
            self.directory
                .open_child_directory(&hex32(stream_id.as_bytes()), create)?,
            Arc::clone(&self.authority),
        ))
    }

    fn stream(&self, open: &BlobStreamOpen, create: bool) -> Result<BlobPackRoot, BlobPackError> {
        self.stream_id(open.stream_id(), create)
    }

    fn upload(
        &self,
        identity: &BlobPackIdentity,
        create: bool,
    ) -> Result<BlobPackRoot, BlobPackError> {
        let root = self.stream_id(identity.upload_id, create)?;
        let BlobPackRoot::Pinned(directory, _) = &root else {
            unreachable!("pinned upload root")
        };
        let expected = encode_upload_marker(*identity);
        match directory.read_private_file_if_present(UPLOAD_MARKER, 82)? {
            Some(marker) if marker == expected => {}
            Some(_) => return Err(BlobPackError::Invalid("Blob upload pack marker mismatch")),
            None if create => directory.write_atomic(UPLOAD_MARKER, &expected)?,
            None => return Err(BlobPackError::Invalid("Blob upload pack marker is missing")),
        }
        Ok(root)
    }
}

fn encode_upload_marker(identity: BlobPackIdentity) -> [u8; 80] {
    let mut marker = [0_u8; 80];
    marker[..8].copy_from_slice(UPLOAD_MARKER_MAGIC);
    marker[8..40].copy_from_slice(identity.upload_id.as_bytes());
    marker[40..72].copy_from_slice(&identity.request_digest);
    marker[72..].copy_from_slice(&identity.total_len.to_be_bytes());
    marker
}

fn cleanup_marker_name(identity: BlobPackIdentity) -> String {
    format!(
        "{UPLOAD_CLEANUP_PREFIX}{}",
        hex32(identity.upload_id.as_bytes())
    )
}

fn encode_cleanup_marker(identity: BlobPackIdentity) -> [u8; 80] {
    let mut marker = encode_upload_marker(identity);
    marker[..8].copy_from_slice(UPLOAD_CLEANUP_MAGIC);
    marker
}

fn reservation_marker_name(identity: BlobPackIdentity) -> String {
    format!(
        "{UPLOAD_RESERVATION_PREFIX}{}",
        hex32(identity.upload_id.as_bytes())
    )
}

fn encode_reservation_marker(identity: BlobPackIdentity) -> [u8; 80] {
    let mut marker = encode_upload_marker(identity);
    marker[..8].copy_from_slice(UPLOAD_RESERVATION_MAGIC);
    marker
}

fn decode_reservation_marker(marker: &[u8]) -> Result<BlobPackIdentity, BlobPackError> {
    if marker.len() != 80 || &marker[..8] != UPLOAD_RESERVATION_MAGIC {
        return Err(BlobPackError::Invalid(
            "Blob upload reservation marker is invalid",
        ));
    }
    let mut upload_marker = marker.to_vec();
    upload_marker[..8].copy_from_slice(UPLOAD_MARKER_MAGIC);
    decode_upload_marker(&upload_marker)
}

pub(super) fn stage_upload_pack_reservation(
    root: &PinnedBlobPackRoot,
    identity: &BlobPackIdentity,
) -> Result<(), BlobPackError> {
    let name = reservation_marker_name(*identity);
    let expected = encode_reservation_marker(*identity);
    match root.directory.read_private_file_if_present(&name, 80)? {
        Some(marker) if marker == expected => Ok(()),
        Some(_) => Err(BlobPackError::Invalid(
            "Blob upload reservation marker mismatch",
        )),
        None => root
            .directory
            .write_atomic(&name, &expected)
            .map_err(Into::into),
    }
}

pub(super) fn finish_upload_pack_reservation(
    root: &PinnedBlobPackRoot,
    identity: &BlobPackIdentity,
) -> Result<(), BlobPackError> {
    root.directory
        .remove_if_exists(&reservation_marker_name(*identity), false)?;
    Ok(())
}

fn decode_cleanup_marker(marker: &[u8]) -> Result<BlobPackIdentity, BlobPackError> {
    if marker.len() != 80 || &marker[..8] != UPLOAD_CLEANUP_MAGIC {
        return Err(BlobPackError::Invalid(
            "Blob upload cleanup marker is invalid",
        ));
    }
    let mut upload_marker = marker.to_vec();
    upload_marker[..8].copy_from_slice(UPLOAD_MARKER_MAGIC);
    decode_upload_marker(&upload_marker)
}

pub(super) fn stage_upload_pack_cleanup(
    root: &PinnedBlobPackRoot,
    identity: &BlobPackIdentity,
) -> Result<(), BlobPackError> {
    let name = cleanup_marker_name(*identity);
    let expected = encode_cleanup_marker(*identity);
    match root.directory.read_private_file_if_present(&name, 80)? {
        Some(marker) if marker == expected => Ok(()),
        Some(_) => Err(BlobPackError::Invalid(
            "Blob upload cleanup marker mismatch",
        )),
        None => root
            .directory
            .write_atomic(&name, &expected)
            .map_err(Into::into),
    }
}

pub(super) fn finish_upload_pack_cleanup(
    root: &PinnedBlobPackRoot,
    identity: &BlobPackIdentity,
) -> Result<(), BlobPackError> {
    root.directory
        .remove_if_exists(&cleanup_marker_name(*identity), false)?;
    Ok(())
}

fn decode_upload_marker(marker: &[u8]) -> Result<BlobPackIdentity, BlobPackError> {
    if marker.len() != 80 || &marker[..8] != UPLOAD_MARKER_MAGIC {
        return Err(BlobPackError::Invalid("Blob upload pack marker is invalid"));
    }
    let upload_id = BlobPublicationStreamId::from_bytes(
        marker[8..40]
            .try_into()
            .map_err(|_| BlobPackError::Invalid("Blob upload pack marker is invalid"))?,
    )
    .map_err(|_| BlobPackError::Invalid("Blob upload pack marker is invalid"))?;
    let request_digest = marker[40..72]
        .try_into()
        .map_err(|_| BlobPackError::Invalid("Blob upload pack marker is invalid"))?;
    let total_len = u64::from_be_bytes(
        marker[72..80]
            .try_into()
            .map_err(|_| BlobPackError::Invalid("Blob upload pack marker is invalid"))?,
    );
    Ok(BlobPackIdentity::new(upload_id, request_digest, total_len))
}

/// Removes exactly one authenticated provisional-upload pack. Every unlink is
/// directory-synchronized, and callers retain the redb reservation until this
/// function has durably removed the final directory entry.
pub(super) fn remove_upload_pack(
    root: &PinnedBlobPackRoot,
    identity: &BlobPackIdentity,
) -> Result<(), BlobPackError> {
    remove_upload_pack_directory(&root.directory, identity)?;
    #[cfg(test)]
    maybe_inject_fault(root.directory.path(), BlobPackFaultPoint::CleanupDurable)?;
    Ok(())
}

fn remove_upload_pack_directory(
    parent: &OwnedDirectory,
    identity: &BlobPackIdentity,
) -> Result<(), StoreError> {
    let name = hex32(identity.upload_id.as_bytes());
    let Some(directory) = parent.open_child_directory_if_present(&name)? else {
        return Ok(());
    };
    let entries = directory.entry_names()?;
    let Some(marker) = directory.read_private_file_if_present(UPLOAD_MARKER, 80)? else {
        if entries.is_empty() {
            drop(directory);
            parent.remove_if_exists(&name, true)?;
            return Ok(());
        }
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob upload pack marker is missing",
        )));
    };
    if decode_upload_marker(&marker).map_err(pack_marker_store_error)? != *identity {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob upload pack marker mismatch",
        )));
    }
    for entry in &entries {
        if entry != PACK_FILE
            && entry != CHECKPOINT_ZERO
            && entry != CHECKPOINT_ONE
            && entry != UPLOAD_MARKER
            && !entry.starts_with(PACK_TEMP_PREFIX)
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload pack contains a foreign artifact",
            )));
        }
    }
    // The marker is the durable cleanup authority. Remove every other entry
    // first; a crash while doing so leaves the marker for exact retry. Once
    // only the marker remains, removing it leaves an empty directory that the
    // same exact identity may safely finish deleting on retry.
    for entry in entries
        .iter()
        .filter(|entry| entry.as_str() != UPLOAD_MARKER)
    {
        directory.remove_if_exists(entry, false)?;
    }
    directory.remove_if_exists(UPLOAD_MARKER, false)?;
    drop(directory);
    parent.remove_if_exists(&name, true)?;
    Ok(())
}

fn pack_marker_store_error(error: BlobPackError) -> StoreError {
    match error {
        BlobPackError::Store(error) => error,
        BlobPackError::Io(error) => blob_error(BlobStoreError::Io(error)),
        BlobPackError::Invalid(message) => blob_error(BlobStoreError::DepotIntegrity(message)),
    }
}

#[derive(Clone, Debug)]
pub(super) struct ExpectedBlobUploadPack {
    pub(super) identity: BlobPackIdentity,
    pub(super) checkpoint: Option<BlobPackCheckpoint>,
}

fn audit_expected_upload_pack(
    directory: &OwnedDirectory,
    expected: &ExpectedBlobUploadPack,
) -> Result<(), StoreError> {
    let mut data = directory
        .open_private_read_file_if_present(PACK_FILE)?
        .ok_or_else(|| {
            blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload pack data is unavailable",
            ))
        })?;
    validate_header(&mut data, expected.identity).map_err(pack_marker_store_error)?;
    let data_len = data
        .metadata()
        .map_err(BlobStoreError::Io)
        .map_err(blob_error)?
        .len();
    let mut checkpoints = Vec::new();
    for name in [CHECKPOINT_ZERO, CHECKPOINT_ONE] {
        let Some(bytes) = directory.read_private_file_if_present(name, 16 * 1024)? else {
            continue;
        };
        let Ok(checkpoint) = BlobPackCheckpoint::decode(&bytes) else {
            continue;
        };
        if checkpoint.open_digest == expected.identity.request_digest
            && checkpoint.stream_id == expected.identity.upload_id
            && checkpoint.total_len == expected.identity.total_len
            && checkpoint.pack_len <= data_len
        {
            checkpoints.push(checkpoint);
        }
    }
    let projected = match expected.checkpoint.as_ref() {
        Some(projected) => checkpoints.iter().find(|candidate| *candidate == projected),
        None => checkpoints.iter().find(|candidate| {
            candidate.next_index() == 0
                && candidate.plaintext_offset() == 0
                && candidate.pack_len() == PACK_HEADER_LEN
        }),
    }
    .ok_or_else(|| {
        blob_error(BlobStoreError::DepotIntegrity(
            "store-projected Blob upload checkpoint is unavailable",
        ))
    })?;
    data.seek(SeekFrom::Start(PACK_HEADER_LEN))
        .map_err(BlobStoreError::Io)
        .map_err(blob_error)?;
    let mut index = 0_u64;
    let mut plaintext_offset = 0_u64;
    let mut frontier = BlobStreamFrontier::new();
    let mut projected_verified = projected.next_index() == 0
        && projected.pack_len() == PACK_HEADER_LEN
        && projected.frontier().ciphertext_commitment()
            == frontier.checkpoint().ciphertext_commitment();
    while data
        .stream_position()
        .map_err(BlobStoreError::Io)
        .map_err(blob_error)?
        < data_len
    {
        let mut length = [0; 4];
        data.read_exact(&mut length)
            .map_err(BlobStoreError::Io)
            .map_err(blob_error)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_RECORD_BYTES {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload pack contains an invalid record length",
            )));
        }
        let mut encoded = vec![0; length];
        data.read_exact(&mut encoded)
            .map_err(BlobStoreError::Io)
            .map_err(blob_error)?;
        let segment = EncryptedBlobStreamSegment::decode(&encoded).map_err(|_| {
            blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload pack contains an invalid segment",
            ))
        })?;
        let header = segment.header();
        if header.index() != index
            || header.stream_id() != expected.identity.upload_id.as_bytes()
            || header.open_digest() != &expected.identity.request_digest
            || header.offset() != plaintext_offset
            || header.total_len() != expected.identity.total_len
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload pack segment differs from its durable checkpoint",
            )));
        }
        plaintext_offset = plaintext_offset
            .checked_add(u64::from(header.plaintext_len()))
            .ok_or(StoreError::PayloadByteAccountingOverflow)?;
        frontier
            .append(BlobStreamSubtree::leaf(
                index,
                segment.ciphertext_audit_leaves(),
            ))
            .map_err(|_| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob upload pack ciphertext frontier is invalid",
                ))
            })?;
        index += 1;
        if index == projected.next_index() {
            let boundary = data
                .stream_position()
                .map_err(BlobStoreError::Io)
                .map_err(blob_error)?;
            projected_verified = boundary == projected.pack_len()
                && plaintext_offset == projected.plaintext_offset()
                && frontier.checkpoint().ciphertext_commitment()
                    == projected.frontier().ciphertext_commitment();
        }
    }
    if !projected_verified || plaintext_offset > expected.identity.total_len {
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "Blob upload pack content differs from its durable checkpoint",
        )));
    }
    Ok(())
}

fn audit_upload_packs(
    depot_root: &OwnedDirectory,
    expected: &[ExpectedBlobUploadPack],
    recover: bool,
) -> Result<Vec<BlobPackIdentity>, StoreError> {
    let Some(pack_root) = depot_root.open_child_directory_if_present(PACK_DIRECTORY)? else {
        return if expected.is_empty() {
            Ok(Vec::new())
        } else {
            Err(blob_error(BlobStoreError::DepotIntegrity(
                "durable Blob upload pack root is missing",
            )))
        };
    };
    let entries = pack_root.entry_names()?;
    let mut cleanup = std::collections::BTreeMap::new();
    for name in entries
        .iter()
        .filter(|name| name.starts_with(UPLOAD_CLEANUP_PREFIX))
    {
        let marker = pack_root
            .read_private_file_if_present(name, 80)?
            .ok_or_else(|| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob upload cleanup marker disappeared during audit",
                ))
            })?;
        let identity = decode_cleanup_marker(&marker).map_err(pack_marker_store_error)?;
        if *name != cleanup_marker_name(identity)
            || cleanup
                .insert(*identity.upload_id.as_bytes(), identity)
                .is_some()
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload cleanup marker identity is inconsistent",
            )));
        }
    }
    let mut reservations = std::collections::BTreeMap::new();
    for name in entries
        .iter()
        .filter(|name| name.starts_with(UPLOAD_RESERVATION_PREFIX))
    {
        let marker = pack_root
            .read_private_file_if_present(name, 80)?
            .ok_or_else(|| {
                blob_error(BlobStoreError::DepotIntegrity(
                    "Blob upload reservation marker disappeared during audit",
                ))
            })?;
        let identity = decode_reservation_marker(&marker).map_err(pack_marker_store_error)?;
        if *name != reservation_marker_name(identity)
            || reservations
                .insert(*identity.upload_id.as_bytes(), identity)
                .is_some()
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload reservation marker identity is inconsistent",
            )));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut completed = Vec::new();
    for name in entries.into_iter().filter(|name| {
        !name.starts_with(UPLOAD_CLEANUP_PREFIX) && !name.starts_with(UPLOAD_RESERVATION_PREFIX)
    }) {
        let directory = pack_root.open_child_directory(&name, false)?;
        let Some(marker) = directory.read_private_file_if_present(UPLOAD_MARKER, 80)? else {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload pack marker is missing",
            )));
        };
        let identity = decode_upload_marker(&marker).map_err(pack_marker_store_error)?;
        if name != hex32(identity.upload_id.as_bytes()) {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload pack directory differs from its marker",
            )));
        }
        if cleanup
            .get(identity.upload_id.as_bytes())
            .is_some_and(|marker| marker != &identity)
            || reservations
                .get(identity.upload_id.as_bytes())
                .is_some_and(|marker| marker != &identity)
        {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "Blob upload transition marker differs from its pack identity",
            )));
        }
        let expected_pack = expected
            .iter()
            .find(|expected| expected.identity == identity)
            .cloned();
        let Some(expected_pack) = expected_pack else {
            if reservations.get(identity.upload_id.as_bytes()) == Some(&identity) {
                if recover {
                    drop(directory);
                    remove_upload_pack_directory(&pack_root, &identity)?;
                    pack_root.remove_if_exists(&reservation_marker_name(identity), false)?;
                }
                continue;
            }
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "unexpected Blob upload pack has no durable authority",
            )));
        };
        if !seen.insert(*identity.upload_id.as_bytes()) {
            return Err(blob_error(BlobStoreError::DepotIntegrity(
                "duplicate Blob upload pack identity",
            )));
        }
        if cleanup.get(identity.upload_id.as_bytes()) == Some(&identity) {
            if recover {
                drop(directory);
                remove_upload_pack_directory(&pack_root, &identity)?;
            }
            completed.push(identity);
        } else {
            audit_expected_upload_pack(&directory, &expected_pack)?;
            if recover && reservations.get(identity.upload_id.as_bytes()) == Some(&identity) {
                pack_root.remove_if_exists(&reservation_marker_name(identity), false)?;
            }
        }
    }
    for expected in expected {
        if seen.contains(expected.identity.upload_id.as_bytes()) {
            continue;
        }
        if cleanup.get(expected.identity.upload_id.as_bytes()) == Some(&expected.identity) {
            completed.push(expected.identity);
            continue;
        }
        return Err(blob_error(BlobStoreError::DepotIntegrity(
            "durable Blob upload pack is missing",
        )));
    }
    if recover {
        for identity in reservations.values() {
            if !seen.contains(identity.upload_id.as_bytes())
                && !expected
                    .iter()
                    .any(|expected| expected.identity == *identity)
            {
                pack_root.remove_if_exists(&reservation_marker_name(*identity), false)?;
            }
        }
    }
    Ok(completed)
}

pub(super) fn audit_upload_packs_write(
    depot_root: &OwnedDirectory,
    expected: &[ExpectedBlobUploadPack],
) -> Result<Vec<BlobPackIdentity>, StoreError> {
    audit_upload_packs(depot_root, expected, true)
}

pub(super) fn audit_upload_packs_read(
    depot_root: &OwnedDirectory,
    expected: &[ExpectedBlobUploadPack],
) -> Result<(), StoreError> {
    audit_upload_packs(depot_root, expected, false).map(|_| ())
}

enum BlobPackRoot {
    Path(PathBuf),
    Pinned(OwnedDirectory, Arc<()>),
}

impl BlobPackRoot {
    fn open_data(&self, create_new: bool) -> Result<File, BlobPackError> {
        match self {
            Self::Path(root) => Ok(OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(create_new)
                .open(root.join(PACK_FILE))?),
            Self::Pinned(root, _) => Ok(root.open_private_rw_file(PACK_FILE, create_new)?),
        }
    }

    fn open_existing_data(&self) -> Result<Option<File>, BlobPackError> {
        match self {
            Self::Path(root) => match OpenOptions::new()
                .read(true)
                .write(true)
                .open(root.join(PACK_FILE))
            {
                Ok(file) => Ok(Some(file)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            },
            Self::Pinned(root, _) => Ok(root.open_private_rw_file_if_present(PACK_FILE)?),
        }
    }

    fn read_checkpoint(&self, name: &str) -> Result<Option<Vec<u8>>, BlobPackError> {
        match self {
            Self::Path(root) => match fs::read(root.join(name)) {
                Ok(bytes) => Ok(Some(bytes)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(error.into()),
            },
            Self::Pinned(root, _) => Ok(root.read_private_file_if_present(name, 16 * 1024)?),
        }
    }

    fn write_checkpoint(&self, name: &str, bytes: &[u8]) -> Result<(), BlobPackError> {
        match self {
            Self::Path(root) => {
                let mut journal = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(root.join(name))?;
                journal.write_all(bytes)?;
                journal.sync_all()?;
                Ok(())
            }
            Self::Pinned(root, _) => Ok(root.write_atomic(name, bytes)?),
        }
    }

    fn authority(&self) -> Option<Arc<()>> {
        match self {
            Self::Path(_) => None,
            Self::Pinned(_, authority) => Some(Arc::clone(authority)),
        }
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        match self {
            Self::Path(path) => path,
            Self::Pinned(root, _) => root.path(),
        }
    }
}

/// Non-semantic identity for one node-protected provisional Blob upload pack.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPackIdentity {
    upload_id: BlobPublicationStreamId,
    request_digest: [u8; 32],
    total_len: u64,
}

impl BlobPackIdentity {
    pub(crate) const fn new(
        upload_id: BlobPublicationStreamId,
        request_digest: [u8; 32],
        total_len: u64,
    ) -> Self {
        Self {
            upload_id,
            request_digest,
            total_len,
        }
    }

    fn from_stream(open: &BlobStreamOpen) -> Self {
        Self::new(open.stream_id(), open.digest(), open.total_len())
    }

    pub const fn upload_id(&self) -> BlobPublicationStreamId {
        self.upload_id
    }

    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    pub const fn total_len(&self) -> u64 {
        self.total_len
    }
}

#[derive(Clone, Debug)]
pub struct BlobPackCheckpoint {
    generation: u64,
    open_digest: [u8; 32],
    stream_id: BlobPublicationStreamId,
    total_len: u64,
    next_index: u64,
    plaintext_offset: u64,
    pack_len: u64,
    frontier: BlobStreamCheckpoint,
    authority: Option<Arc<()>>,
}

impl PartialEq for BlobPackCheckpoint {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.open_digest == other.open_digest
            && self.stream_id == other.stream_id
            && self.total_len == other.total_len
            && self.next_index == other.next_index
            && self.plaintext_offset == other.plaintext_offset
            && self.pack_len == other.pack_len
            && self.frontier == other.frontier
    }
}

impl Eq for BlobPackCheckpoint {}

impl BlobPackCheckpoint {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
    pub const fn next_index(&self) -> u64 {
        self.next_index
    }
    pub const fn plaintext_offset(&self) -> u64 {
        self.plaintext_offset
    }
    pub const fn pack_len(&self) -> u64 {
        self.pack_len
    }
    pub const fn payload_len(&self) -> u64 {
        self.pack_len - PACK_HEADER_LEN
    }
    pub const fn frontier(&self) -> &BlobStreamCheckpoint {
        &self.frontier
    }

    pub const fn open_digest(&self) -> &[u8; 32] {
        &self.open_digest
    }

    /// Exact immutable provisional-upload request digest.
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.open_digest
    }

    pub const fn stream_id(&self) -> BlobPublicationStreamId {
        self.stream_id
    }

    /// Opaque node-local provisional-upload identity.
    pub const fn upload_id(&self) -> BlobPublicationStreamId {
        self.stream_id
    }

    pub const fn total_len(&self) -> u64 {
        self.total_len
    }

    pub(crate) fn bind_authority(&mut self, authority: Arc<()>) {
        self.authority = Some(authority);
    }

    pub(crate) fn is_bound_to(&self, authority: &Arc<()>) -> bool {
        self.authority
            .as_ref()
            .is_some_and(|bound| Arc::ptr_eq(bound, authority))
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let frontier = self.frontier.encode();
        let mut out = Vec::with_capacity(150 + frontier.len());
        out.extend_from_slice(CHECKPOINT_MAGIC);
        out.extend_from_slice(&PACK_VERSION.to_be_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.open_digest);
        out.extend_from_slice(self.stream_id.as_bytes());
        out.extend_from_slice(&self.total_len.to_be_bytes());
        out.extend_from_slice(&self.next_index.to_be_bytes());
        out.extend_from_slice(&self.plaintext_offset.to_be_bytes());
        out.extend_from_slice(&self.pack_len.to_be_bytes());
        out.extend_from_slice(&(frontier.len() as u32).to_be_bytes());
        out.extend_from_slice(&frontier);
        let checksum = Sha256::digest(&out);
        out.extend_from_slice(&checksum);
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, BlobPackError> {
        let minimum = 8 + 2 + 8 + 32 + 32 + 8 * 4 + 4 + 32;
        if bytes.len() < minimum || &bytes[..8] != CHECKPOINT_MAGIC {
            return Err(BlobPackError::Invalid("invalid Blob pack checkpoint"));
        }
        let checksum_at = bytes.len() - 32;
        if Sha256::digest(&bytes[..checksum_at]).as_slice() != &bytes[checksum_at..] {
            return Err(BlobPackError::Invalid(
                "invalid Blob pack checkpoint checksum",
            ));
        }
        let mut reader = Reader::new(&bytes[..checksum_at]);
        if reader.take(8)? != CHECKPOINT_MAGIC || reader.u16()? != PACK_VERSION {
            return Err(BlobPackError::Invalid("unsupported Blob pack checkpoint"));
        }
        let generation = reader.u64()?;
        let open_digest = reader.array()?;
        let stream_id = BlobPublicationStreamId::from_bytes(reader.array()?)
            .map_err(|_| BlobPackError::Invalid("invalid stream ID"))?;
        let total_len = reader.u64()?;
        let next_index = reader.u64()?;
        let plaintext_offset = reader.u64()?;
        let pack_len = reader.u64()?;
        let frontier_len = reader.u32()? as usize;
        let frontier = BlobStreamCheckpoint::decode(reader.take(frontier_len)?)
            .map_err(|_| BlobPackError::Invalid("invalid Blob frontier"))?;
        reader.finish()?;
        if generation == 0
            || open_digest == [0; 32]
            || plaintext_offset > total_len
            || pack_len < PACK_HEADER_LEN
            || frontier.next_index() != next_index
            || frontier.plaintext_len() != plaintext_offset
        {
            return Err(BlobPackError::Invalid("invalid Blob pack checkpoint state"));
        }
        Ok(Self {
            generation,
            open_digest,
            stream_id,
            total_len,
            next_index,
            plaintext_offset,
            pack_len,
            frontier,
            authority: None,
        })
    }
}

pub struct BlobPackWriter {
    root: BlobPackRoot,
    data: File,
    open_digest: [u8; 32],
    stream_id: BlobPublicationStreamId,
    total_len: u64,
    next_index: u64,
    plaintext_offset: u64,
    pack_len: u64,
    generation: u64,
    frontier: BlobStreamFrontier,
}

impl BlobPackWriter {
    pub const fn next_index(&self) -> u64 {
        self.next_index
    }

    pub const fn plaintext_offset(&self) -> u64 {
        self.plaintext_offset
    }

    pub fn create(root: &Path, open: &BlobStreamOpen) -> Result<Self, BlobPackError> {
        fs::create_dir_all(root)?;
        Self::create_in(
            BlobPackRoot::Path(root.to_owned()),
            BlobPackIdentity::from_stream(open),
        )
    }

    pub fn create_pinned(
        root: &PinnedBlobPackRoot,
        open: &BlobStreamOpen,
    ) -> Result<Self, BlobPackError> {
        Self::create_in(
            root.stream(open, true)?,
            BlobPackIdentity::from_stream(open),
        )
    }

    /// Creates a node-protected pack for a provisional application upload.
    pub fn create_upload_pinned(
        root: &PinnedBlobPackRoot,
        identity: &BlobPackIdentity,
    ) -> Result<Self, BlobPackError> {
        Self::create_in(root.upload(identity, true)?, *identity)
    }

    fn create_in(root: BlobPackRoot, identity: BlobPackIdentity) -> Result<Self, BlobPackError> {
        let mut data = root.open_data(true)?;
        let open_digest = identity.request_digest;
        data.write_all(PACK_MAGIC)?;
        data.write_all(&PACK_VERSION.to_be_bytes())?;
        data.write_all(&open_digest)?;
        data.write_all(identity.upload_id.as_bytes())?;
        data.write_all(&identity.total_len.to_be_bytes())?;
        data.sync_all()?;
        let mut writer = Self {
            root,
            data,
            open_digest,
            stream_id: identity.upload_id,
            total_len: identity.total_len,
            next_index: 0,
            plaintext_offset: 0,
            pack_len: PACK_HEADER_LEN,
            generation: 0,
            frontier: BlobStreamFrontier::new(),
        };
        writer.checkpoint()?;
        Ok(writer)
    }

    pub fn resume(root: &Path, open: &BlobStreamOpen) -> Result<Self, BlobPackError> {
        Self::resume_in(
            BlobPackRoot::Path(root.to_owned()),
            BlobPackIdentity::from_stream(open),
        )
    }

    pub fn resume_pinned(
        root: &PinnedBlobPackRoot,
        open: &BlobStreamOpen,
    ) -> Result<Self, BlobPackError> {
        Self::resume_in(
            root.stream(open, false)?,
            BlobPackIdentity::from_stream(open),
        )
    }

    fn resume_in(root: BlobPackRoot, identity: BlobPackIdentity) -> Result<Self, BlobPackError> {
        let mut data = root.open_data(false)?;
        validate_header(&mut data, identity)?;
        let checkpoint = recover_checkpoint(&root, identity, data.metadata()?.len())?;
        Self::restore(root, identity, data, checkpoint)
    }

    /// Opens the pack at the exact checkpoint already projected into the store.
    ///
    /// A pack checkpoint is made durable before its store projection. After a
    /// crash, the newest pack journal can therefore contain unacknowledged data.
    /// This method deliberately selects the store-authoritative journal instead
    /// of the newest journal and truncates any later tail.
    pub fn open_projected(
        root: &Path,
        open: &BlobStreamOpen,
        generation: u64,
        next_index: u64,
        plaintext_offset: u64,
        pack_len: u64,
        payload_len: u64,
    ) -> Result<Self, BlobPackError> {
        Self::open_projected_in(
            BlobPackRoot::Path(root.to_owned()),
            BlobPackIdentity::from_stream(open),
            generation,
            next_index,
            plaintext_offset,
            pack_len,
            payload_len,
        )
    }

    pub fn open_projected_pinned(
        root: &PinnedBlobPackRoot,
        open: &BlobStreamOpen,
        generation: u64,
        next_index: u64,
        plaintext_offset: u64,
        pack_len: u64,
        payload_len: u64,
    ) -> Result<Self, BlobPackError> {
        let root = root.stream(open, generation == 0)?;
        Self::open_projected_in(
            root,
            BlobPackIdentity::from_stream(open),
            generation,
            next_index,
            plaintext_offset,
            pack_len,
            payload_len,
        )
    }

    /// Reopens a provisional upload at exactly the checkpoint already
    /// projected into redb, discarding any later unprojected pack tail.
    pub fn open_projected_upload_pinned(
        root: &PinnedBlobPackRoot,
        identity: &BlobPackIdentity,
        projected: Option<&BlobPackCheckpoint>,
    ) -> Result<Self, BlobPackError> {
        if projected.is_some_and(|checkpoint| !checkpoint.is_bound_to(&root.authority)) {
            return Err(BlobPackError::Invalid(
                "Blob upload checkpoint belongs to another Store",
            ));
        }
        let root = root.upload(identity, projected.is_none())?;
        let (generation, next_index, plaintext_offset, pack_len, payload_len) =
            projected.map_or((0, 0, 0, 0, 0), |checkpoint| {
                (
                    checkpoint.generation(),
                    checkpoint.next_index(),
                    checkpoint.plaintext_offset(),
                    checkpoint.pack_len(),
                    checkpoint.payload_len(),
                )
            });
        Self::open_projected_in(
            root,
            *identity,
            generation,
            next_index,
            plaintext_offset,
            pack_len,
            payload_len,
        )
    }

    fn open_projected_in(
        root: BlobPackRoot,
        identity: BlobPackIdentity,
        generation: u64,
        next_index: u64,
        plaintext_offset: u64,
        pack_len: u64,
        payload_len: u64,
    ) -> Result<Self, BlobPackError> {
        let mut data = match root.open_existing_data()? {
            Some(data) => data,
            None if generation == 0 => {
                if next_index != 0 || plaintext_offset != 0 || pack_len != 0 || payload_len != 0 {
                    return Err(BlobPackError::Invalid(
                        "non-empty Blob projection has zero generation",
                    ));
                }
                return Self::create_in(root, identity);
            }
            None => return Err(BlobPackError::Invalid("Blob pack data is unavailable")),
        };
        validate_header(&mut data, identity)?;
        let data_len = data.metadata()?.len();
        let checkpoint = recover_checkpoints(&root, identity, data_len)?
            .into_iter()
            .filter(|checkpoint| {
                if generation == 0 {
                    checkpoint.next_index == 0
                        && checkpoint.plaintext_offset == 0
                        && checkpoint.payload_len() == 0
                } else {
                    checkpoint.generation == generation
                        && checkpoint.next_index == next_index
                        && checkpoint.plaintext_offset == plaintext_offset
                        && checkpoint.pack_len == pack_len
                        && checkpoint.payload_len() == payload_len
                }
            })
            .max_by_key(|checkpoint| checkpoint.generation)
            .ok_or(BlobPackError::Invalid(
                "store-projected Blob pack checkpoint is unavailable",
            ))?;
        Self::restore(root, identity, data, checkpoint)
    }

    fn restore(
        root: BlobPackRoot,
        identity: BlobPackIdentity,
        mut data: File,
        checkpoint: BlobPackCheckpoint,
    ) -> Result<Self, BlobPackError> {
        data.set_len(checkpoint.pack_len)?;
        data.sync_data()?;
        data.seek(SeekFrom::Start(checkpoint.pack_len))?;
        Ok(Self {
            root,
            data,
            open_digest: identity.request_digest,
            stream_id: identity.upload_id,
            total_len: identity.total_len,
            next_index: checkpoint.next_index,
            plaintext_offset: checkpoint.plaintext_offset,
            pack_len: checkpoint.pack_len,
            generation: checkpoint.generation,
            frontier: BlobStreamFrontier::restore(checkpoint.frontier)
                .map_err(|_| BlobPackError::Invalid("invalid restored frontier"))?,
        })
    }

    pub fn append(
        &mut self,
        segment: &EncryptedBlobStreamSegment,
        leaves: BlobStreamSegmentLeaves,
    ) -> Result<(), BlobPackError> {
        let encoded = segment.encode();
        self.append_encoded(&encoded, segment.header(), leaves)
    }

    pub fn append_record(
        &mut self,
        encoded: &[u8],
        leaves: BlobStreamSegmentLeaves,
    ) -> Result<(), BlobPackError> {
        let header = EncryptedBlobStreamSegment::inspect_encoded(encoded)
            .map_err(|_| BlobPackError::Invalid("invalid Blob pack segment"))?;
        self.append_encoded(encoded, header, leaves)
    }

    fn append_encoded(
        &mut self,
        encoded: &[u8],
        header: aster_mesh::EncryptedBlobStreamSegmentHeader,
        leaves: BlobStreamSegmentLeaves,
    ) -> Result<(), BlobPackError> {
        if header.index() != self.next_index
            || header.stream_id() != self.stream_id.as_bytes()
            || header.open_digest() != &self.open_digest
            || header.offset() != self.plaintext_offset
            || header.total_len() != self.total_len
        {
            return Err(BlobPackError::Invalid(
                "Blob segment is outside pack sequence",
            ));
        }
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(BlobPackError::Invalid(
                "Blob segment record exceeds pack bound",
            ));
        }
        self.data.write_all(&(encoded.len() as u32).to_be_bytes())?;
        self.data.write_all(encoded)?;
        self.frontier
            .append(BlobStreamSubtree::leaf(self.next_index, leaves))
            .map_err(|_| BlobPackError::Invalid("invalid Blob segment frontier"))?;
        self.next_index += 1;
        self.plaintext_offset = self
            .plaintext_offset
            .checked_add(u64::from(header.plaintext_len()))
            .ok_or(BlobPackError::Invalid("Blob pack offset overflow"))?;
        self.pack_len = self
            .pack_len
            .checked_add(4 + encoded.len() as u64)
            .ok_or(BlobPackError::Invalid("Blob pack length overflow"))?;
        Ok(())
    }

    pub fn checkpoint(&mut self) -> Result<BlobPackCheckpoint, BlobPackError> {
        self.data.sync_data()?;
        #[cfg(test)]
        maybe_inject_fault(self.root.path(), BlobPackFaultPoint::DataSynced)?;
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(BlobPackError::Invalid("checkpoint generation exhausted"))?;
        let checkpoint = BlobPackCheckpoint {
            generation,
            open_digest: self.open_digest,
            stream_id: self.stream_id,
            total_len: self.total_len,
            next_index: self.next_index,
            plaintext_offset: self.plaintext_offset,
            pack_len: self.pack_len,
            frontier: self.frontier.checkpoint(),
            authority: self.root.authority(),
        };
        let name = if generation % 2 == 0 {
            CHECKPOINT_ZERO
        } else {
            CHECKPOINT_ONE
        };
        self.root.write_checkpoint(name, &checkpoint.encode())?;
        #[cfg(test)]
        maybe_inject_fault(
            self.root.path(),
            if generation % 2 == 0 {
                BlobPackFaultPoint::CheckpointZeroSynced
            } else {
                BlobPackFaultPoint::CheckpointOneSynced
            },
        )?;
        self.generation = generation;
        Ok(checkpoint)
    }

    pub fn finish(mut self) -> Result<([u8; 32], [u8; 32]), BlobPackError> {
        if self.plaintext_offset != self.total_len {
            return Err(BlobPackError::Invalid("Blob pack is incomplete"));
        }
        self.checkpoint()?;
        self.frontier
            .finish(self.total_len)
            .map_err(|_| BlobPackError::Invalid("invalid final Blob roots"))
    }
}

pub struct BlobPackReader {
    data: File,
    checkpoint: BlobPackCheckpoint,
    next_index: u64,
}

/// One structurally validated canonical pack record, including its four-byte
/// length prefix. Ownership can move directly into transport framing without
/// decoding and re-encoding the encrypted segment.
pub struct BlobPackRecord {
    bytes: Vec<u8>,
}

impl BlobPackRecord {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl BlobPackReader {
    pub fn open(root: &Path, open: &BlobStreamOpen) -> Result<Self, BlobPackError> {
        Self::open_in(BlobPackRoot::Path(root.to_owned()), open)
    }

    pub fn open_pinned(
        root: &PinnedBlobPackRoot,
        open: &BlobStreamOpen,
    ) -> Result<Self, BlobPackError> {
        Self::open_in(root.stream(open, false)?, open)
    }

    /// Opens exactly the Store-projected provisional upload checkpoint. Later
    /// journal progress is intentionally invisible to canonical conversion.
    pub fn open_projected_upload_pinned(
        root: &PinnedBlobPackRoot,
        identity: &BlobPackIdentity,
        checkpoint: &BlobPackCheckpoint,
    ) -> Result<Self, BlobPackError> {
        if !checkpoint.is_bound_to(&root.authority)
            || checkpoint.upload_id() != identity.upload_id
            || checkpoint.request_digest() != &identity.request_digest
            || checkpoint.total_len() != identity.total_len
        {
            return Err(BlobPackError::Invalid(
                "Blob upload reader checkpoint is not Store-bound",
            ));
        }
        let root = root.upload(identity, false)?;
        let mut data = root
            .open_existing_data()?
            .ok_or(BlobPackError::Invalid("Blob pack data is unavailable"))?;
        validate_header(&mut data, *identity)?;
        let data_len = data.metadata()?.len();
        let recovered = recover_checkpoints(&root, *identity, data_len)?;
        if !recovered.iter().any(|candidate| candidate == checkpoint) {
            return Err(BlobPackError::Invalid(
                "store-projected Blob pack checkpoint is unavailable",
            ));
        }
        data.seek(SeekFrom::Start(PACK_HEADER_LEN))?;
        Ok(Self {
            data,
            checkpoint: checkpoint.clone(),
            next_index: 0,
        })
    }

    fn open_in(root: BlobPackRoot, open: &BlobStreamOpen) -> Result<Self, BlobPackError> {
        let identity = BlobPackIdentity::from_stream(open);
        let mut data = root
            .open_existing_data()?
            .ok_or(BlobPackError::Invalid("Blob pack data is unavailable"))?;
        validate_header(&mut data, identity)?;
        let checkpoint = recover_checkpoint(&root, identity, data.metadata()?.len())?;
        data.seek(SeekFrom::Start(PACK_HEADER_LEN))?;
        Ok(Self {
            data,
            checkpoint,
            next_index: 0,
        })
    }

    pub fn open_at_payload_offset(
        root: &Path,
        open: &BlobStreamOpen,
        next_index: u64,
        payload_offset: u64,
    ) -> Result<Self, BlobPackError> {
        Self::open_at_payload_offset_in(Self::open(root, open)?, next_index, payload_offset)
    }

    pub fn open_pinned_at_payload_offset(
        root: &PinnedBlobPackRoot,
        open: &BlobStreamOpen,
        next_index: u64,
        payload_offset: u64,
    ) -> Result<Self, BlobPackError> {
        Self::open_at_payload_offset_in(Self::open_pinned(root, open)?, next_index, payload_offset)
    }

    fn open_at_payload_offset_in(
        mut reader: Self,
        next_index: u64,
        payload_offset: u64,
    ) -> Result<Self, BlobPackError> {
        if next_index > reader.checkpoint.next_index
            || payload_offset > reader.checkpoint.payload_len()
            || (next_index == 0) != (payload_offset == 0)
            || (next_index == reader.checkpoint.next_index)
                != (payload_offset == reader.checkpoint.payload_len())
        {
            return Err(BlobPackError::Invalid(
                "Blob pack resume position is outside its durable checkpoint",
            ));
        }
        let position = PACK_HEADER_LEN
            .checked_add(payload_offset)
            .ok_or(BlobPackError::Invalid("Blob pack resume offset overflow"))?;
        reader.data.seek(SeekFrom::Start(position))?;
        reader.next_index = next_index;
        Ok(reader)
    }

    pub fn next_segment(&mut self) -> Result<Option<EncryptedBlobStreamSegment>, BlobPackError> {
        let Some(record) = self.next_record()? else {
            return Ok(None);
        };
        EncryptedBlobStreamSegment::decode(&record.as_bytes()[4..])
            .map(Some)
            .map_err(|_| BlobPackError::Invalid("invalid Blob pack segment"))
    }

    pub fn next_record(&mut self) -> Result<Option<BlobPackRecord>, BlobPackError> {
        if self.next_index >= self.checkpoint.next_index {
            return Ok(None);
        }
        let mut len = [0; 4];
        self.data.read_exact(&mut len)?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_RECORD_BYTES {
            return Err(BlobPackError::Invalid("invalid Blob pack record length"));
        }
        let mut bytes = vec![0; 4 + len];
        bytes[..4].copy_from_slice(&(len as u32).to_be_bytes());
        self.data.read_exact(&mut bytes[4..])?;
        let header = EncryptedBlobStreamSegment::inspect_encoded(&bytes[4..])
            .map_err(|_| BlobPackError::Invalid("invalid Blob pack segment"))?;
        if header.index() != self.next_index
            || header.stream_id() != self.checkpoint.stream_id.as_bytes()
            || header.open_digest() != &self.checkpoint.open_digest
            || header.offset() != self.checkpoint_segment_offset(self.next_index)?
            || header.total_len() != self.checkpoint.total_len
        {
            return Err(BlobPackError::Invalid("non-contiguous Blob pack segment"));
        }
        self.next_index += 1;
        Ok(Some(BlobPackRecord { bytes }))
    }

    pub const fn checkpoint(&self) -> &BlobPackCheckpoint {
        &self.checkpoint
    }

    fn checkpoint_segment_offset(&self, index: u64) -> Result<u64, BlobPackError> {
        index
            .checked_mul(aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64)
            .ok_or(BlobPackError::Invalid("Blob pack segment offset overflow"))
    }
}

fn validate_header(data: &mut File, identity: BlobPackIdentity) -> Result<(), BlobPackError> {
    data.seek(SeekFrom::Start(0))?;
    let mut header = [0; PACK_HEADER_LEN as usize];
    data.read_exact(&mut header)?;
    if &header[..8] != PACK_MAGIC
        || u16::from_be_bytes(header[8..10].try_into().expect("version")) != PACK_VERSION
        || header[10..42] != identity.request_digest
        || header[42..74] != *identity.upload_id.as_bytes()
        || u64::from_be_bytes(header[74..82].try_into().expect("length")) != identity.total_len
    {
        return Err(BlobPackError::Invalid("Blob pack header identity mismatch"));
    }
    Ok(())
}

fn recover_checkpoint(
    root: &BlobPackRoot,
    identity: BlobPackIdentity,
    data_len: u64,
) -> Result<BlobPackCheckpoint, BlobPackError> {
    recover_checkpoints(root, identity, data_len)?
        .into_iter()
        .max_by_key(|checkpoint| checkpoint.generation)
        .ok_or(BlobPackError::Invalid("no valid Blob pack checkpoint"))
}

fn recover_checkpoints(
    root: &BlobPackRoot,
    identity: BlobPackIdentity,
    data_len: u64,
) -> Result<Vec<BlobPackCheckpoint>, BlobPackError> {
    let mut valid = Vec::new();
    for name in [CHECKPOINT_ZERO, CHECKPOINT_ONE] {
        let Some(bytes) = root.read_checkpoint(name)? else {
            continue;
        };
        let Ok(checkpoint) = BlobPackCheckpoint::decode(&bytes) else {
            continue;
        };
        if checkpoint.open_digest == identity.request_digest
            && checkpoint.stream_id == identity.upload_id
            && checkpoint.total_len == identity.total_len
            && checkpoint.pack_len <= data_len
        {
            valid.push(checkpoint);
        }
    }
    if valid.is_empty() {
        Err(BlobPackError::Invalid("no valid Blob pack checkpoint"))
    } else {
        Ok(valid)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], BlobPackError> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(BlobPackError::Invalid("length overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(BlobPackError::Invalid("truncated record"))?;
        self.position = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], BlobPackError> {
        self.take(N)?
            .try_into()
            .map_err(|_| BlobPackError::Invalid("invalid field"))
    }
    fn u16(&mut self) -> Result<u16, BlobPackError> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32, BlobPackError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64, BlobPackError> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn finish(self) -> Result<(), BlobPackError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(BlobPackError::Invalid("trailing record bytes"))
        }
    }
}

fn hex32(value: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_mesh::{
        BLOB_STREAM_SEGMENT_BYTES, BlobMetadata, BlobStreamPlainPartition, BlobStreamSegmentSealer,
        Priority, Scope, Topic, VersionVector,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aster-pack-test-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create temp root");
            Self(path)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn open(total_len: u64) -> BlobStreamOpen {
        BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([0x11; 32]).expect("stream"),
            [0x21; 32],
            b"pack-test".to_vec(),
            [0x31; 32],
            1,
            VersionVector::default(),
            Topic::new("imagery").expect("topic"),
            Scope::new("mission/alpha").expect("scope"),
            BlobMetadata::new(Some("image/tiff".into()), Vec::new()).expect("metadata"),
            Priority::Immediate,
            None,
            None,
            total_len,
            1,
            1,
            [0x41; 32],
            [0x51; 32],
        )
        .expect("open")
    }

    fn segments(
        open: &BlobStreamOpen,
        count: u64,
    ) -> Vec<(EncryptedBlobStreamSegment, BlobStreamSegmentLeaves)> {
        let sealer = BlobStreamSegmentSealer::from_test_key(
            *open.stream_id().as_bytes(),
            open.digest(),
            open.content_epoch(),
            [0x61; 32],
            [0x71; 12],
        );
        (0..count)
            .map(|index| {
                let offset = index * BLOB_STREAM_SEGMENT_BYTES as u64;
                let len =
                    (open.total_len() - offset).min(BLOB_STREAM_SEGMENT_BYTES as u64) as usize;
                sealer
                    .seal(
                        BlobStreamPlainPartition::new(
                            *open.stream_id().as_bytes(),
                            open.digest(),
                            open.content_epoch(),
                            index,
                            offset,
                            open.total_len(),
                            vec![index as u8 + 1; len],
                        )
                        .expect("partition"),
                    )
                    .expect("seal")
            })
            .collect()
    }

    #[test]
    fn blob_pack_discards_uncheckpointed_tail_and_restores_frontier() {
        let root = TempRoot::new();
        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64 * 2 + 17;
        let open = open(total_len);
        let segments = segments(&open, 3);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create");
        writer
            .append(&segments[0].0, segments[0].1)
            .expect("append 0");
        let durable = writer.checkpoint().expect("checkpoint");
        writer
            .append(&segments[1].0, segments[1].1)
            .expect("append 1");
        drop(writer);

        let mut resumed = BlobPackWriter::resume(&root.0, &open).expect("resume");
        assert_eq!(resumed.next_index, 1);
        assert_eq!(resumed.pack_len, durable.pack_len());
        resumed
            .append(&segments[1].0, segments[1].1)
            .expect("reappend 1");
        resumed
            .append(&segments[2].0, segments[2].1)
            .expect("append 2");
        let roots = resumed.finish().expect("finish");

        let mut expected = BlobStreamFrontier::new();
        for (index, (_, leaves)) in segments.iter().enumerate() {
            expected
                .append(BlobStreamSubtree::leaf(index as u64, *leaves))
                .expect("frontier");
        }
        assert_eq!(roots, expected.finish(total_len).expect("expected roots"));
        let mut reader = BlobPackReader::open(&root.0, &open).expect("reader");
        for index in 0..3 {
            assert_eq!(
                reader
                    .next_segment()
                    .expect("read")
                    .expect("segment")
                    .index(),
                index
            );
        }
        assert!(reader.next_segment().expect("eof").is_none());
        let mut resumed_reader =
            BlobPackReader::open_at_payload_offset(&root.0, &open, 1, durable.payload_len())
                .expect("resume reader");
        assert_eq!(
            resumed_reader
                .next_segment()
                .expect("read resumed")
                .expect("resumed segment")
                .index(),
            1
        );
    }

    #[test]
    fn blob_pack_raw_reader_preserves_the_canonical_record() {
        let root = TempRoot::new();
        let open = open(BLOB_STREAM_SEGMENT_BYTES as u64);
        let segments = segments(&open, 1);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create");
        writer
            .append(&segments[0].0, segments[0].1)
            .expect("append");
        writer.finish().expect("finish");

        let encoded = segments[0].0.encode();
        let mut expected = Vec::with_capacity(4 + encoded.len());
        expected.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        expected.extend_from_slice(&encoded);
        let mut reader = BlobPackReader::open(&root.0, &open).expect("reader");
        let record = reader.next_record().expect("read").expect("record");
        assert_eq!(record.as_bytes(), expected);
        assert!(reader.next_record().expect("eof").is_none());
    }

    #[test]
    fn blob_pack_uses_older_complete_checkpoint_when_newest_is_corrupt() {
        let root = TempRoot::new();
        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64 * 2;
        let open = open(total_len);
        let segments = segments(&open, 2);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create");
        writer
            .append(&segments[0].0, segments[0].1)
            .expect("append 0");
        let older = writer.checkpoint().expect("older checkpoint");
        writer
            .append(&segments[1].0, segments[1].1)
            .expect("append 1");
        let newest = writer.checkpoint().expect("newest checkpoint");
        assert!(newest.generation() > older.generation());
        drop(writer);
        let newest_path = root.0.join(if newest.generation().is_multiple_of(2) {
            CHECKPOINT_ZERO
        } else {
            CHECKPOINT_ONE
        });
        let mut bytes = fs::read(&newest_path).expect("read newest");
        bytes[32] ^= 1;
        fs::write(newest_path, bytes).expect("corrupt newest");
        let resumed = BlobPackWriter::resume(&root.0, &open).expect("resume older");
        assert_eq!(resumed.generation, older.generation());
        assert_eq!(resumed.next_index, older.next_index());
        assert_eq!(resumed.pack_len, older.pack_len());
    }

    #[test]
    fn blob_pack_resumes_from_store_projected_checkpoint_not_newest_journal() {
        let root = TempRoot::new();
        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64 * 2;
        let open = open(total_len);
        let segments = segments(&open, 2);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create");
        writer
            .append(&segments[0].0, segments[0].1)
            .expect("append 0");
        let projected = writer.checkpoint().expect("projected checkpoint");
        writer
            .append(&segments[1].0, segments[1].1)
            .expect("append 1");
        let unprojected = writer.checkpoint().expect("unprojected checkpoint");
        assert!(unprojected.generation() > projected.generation());
        drop(writer);

        let mut resumed = BlobPackWriter::open_projected(
            &root.0,
            &open,
            projected.generation(),
            projected.next_index(),
            projected.plaintext_offset(),
            projected.pack_len(),
            projected.payload_len(),
        )
        .expect("resume projected");
        assert_eq!(resumed.generation, projected.generation());
        assert_eq!(resumed.next_index, 1);
        assert_eq!(resumed.pack_len, projected.pack_len());
        resumed
            .append(&segments[1].0, segments[1].1)
            .expect("replace unprojected segment");
    }

    #[test]
    fn blob_pack_resumes_empty_projection_over_existing_unprojected_pack() {
        let root = TempRoot::new();
        let total_len = BLOB_STREAM_SEGMENT_BYTES as u64;
        let open = open(total_len);
        let segments = segments(&open, 1);
        let mut writer = BlobPackWriter::create(&root.0, &open).expect("create");
        writer
            .append(&segments[0].0, segments[0].1)
            .expect("append 0");
        writer.checkpoint().expect("unprojected checkpoint");
        drop(writer);

        let mut resumed =
            BlobPackWriter::open_projected(&root.0, &open, 0, 0, 0, 0, 0).expect("resume empty");
        assert_eq!(resumed.next_index, 0);
        assert_eq!(resumed.plaintext_offset, 0);
        assert_eq!(resumed.pack_len, PACK_HEADER_LEN);
        resumed
            .append(&segments[0].0, segments[0].1)
            .expect("replace unprojected segment");
    }
}
