use crate::blob::BlobError;
use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Payload, array::Array},
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const BLOB_STREAM_SEGMENT_BYTES: usize = 1024 * 1024;
const FRONTIER_LEVELS: usize = 64;

#[derive(Debug)]
pub struct BlobStreamPlainPartition {
    stream_id: [u8; 32],
    open_digest: [u8; 32],
    content_epoch: u64,
    index: u64,
    offset: u64,
    total_len: u64,
    plaintext: Zeroizing<Vec<u8>>,
}

impl BlobStreamPlainPartition {
    pub fn new(
        stream_id: [u8; 32],
        open_digest: [u8; 32],
        content_epoch: u64,
        index: u64,
        offset: u64,
        total_len: u64,
        plaintext: Vec<u8>,
    ) -> Result<Self, BlobError> {
        let len = plaintext.len();
        let expected_offset = index
            .checked_mul(BLOB_STREAM_SEGMENT_BYTES as u64)
            .ok_or(BlobError::LengthOverflow)?;
        let end = offset
            .checked_add(len as u64)
            .ok_or(BlobError::LengthOverflow)?;
        if stream_id == [0; 32]
            || open_digest == [0; 32]
            || content_epoch == 0
            || total_len == 0
            || offset != expected_offset
            || len == 0
            || len > BLOB_STREAM_SEGMENT_BYTES
            || end > total_len
            || (end < total_len && len != BLOB_STREAM_SEGMENT_BYTES)
        {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self {
            stream_id,
            open_digest,
            content_epoch,
            index,
            offset,
            total_len,
            plaintext: Zeroizing::new(plaintext),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobStreamSegmentLeaves {
    plaintext: [u8; 32],
    ciphertext: [u8; 32],
    plaintext_len: u64,
    ciphertext_len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedBlobStreamSegment {
    stream_id: [u8; 32],
    open_digest: [u8; 32],
    content_epoch: u64,
    index: u64,
    offset: u64,
    total_len: u64,
    plaintext_len: u32,
    ciphertext: Vec<u8>,
}

impl EncryptedBlobStreamSegment {
    pub fn index(&self) -> u64 {
        self.index
    }

    #[cfg(test)]
    fn identity_mutations_for_test(&self) -> Vec<Self> {
        let mut output = Vec::new();
        macro_rules! changed {
            ($field:ident, $value:expr) => {{
                let mut value = self.clone();
                value.$field = $value;
                output.push(value);
            }};
        }
        changed!(stream_id, [0x91; 32]);
        changed!(open_digest, [0x92; 32]);
        changed!(content_epoch, self.content_epoch + 1);
        changed!(index, self.index + 1);
        changed!(offset, self.offset + 1);
        changed!(total_len, self.total_len + 1);
        changed!(plaintext_len, self.plaintext_len - 1);
        let mut ciphertext = self.ciphertext.clone();
        ciphertext[0] ^= 1;
        changed!(ciphertext, ciphertext);
        let mut tag = self.ciphertext.clone();
        let last = tag.len() - 1;
        tag[last] ^= 1;
        changed!(ciphertext, tag);
        output
    }
}

#[derive(Clone)]
pub struct BlobStreamSegmentSealer {
    stream_id: [u8; 32],
    open_digest: [u8; 32],
    content_epoch: u64,
    key: [u8; 32],
    base_nonce: [u8; 12],
}

impl Drop for BlobStreamSegmentSealer {
    fn drop(&mut self) {
        self.key.zeroize();
        self.base_nonce.zeroize();
    }
}

#[derive(Clone)]
pub struct BlobStreamSegmentOpener(BlobStreamSegmentSealer);

impl BlobStreamSegmentSealer {
    pub(crate) fn new(
        stream_id: [u8; 32],
        open_digest: [u8; 32],
        content_epoch: u64,
        key: [u8; 32],
        base_nonce: [u8; 12],
    ) -> Self {
        Self {
            stream_id,
            open_digest,
            content_epoch,
            key,
            base_nonce,
        }
    }

    pub fn seal(
        &self,
        partition: BlobStreamPlainPartition,
    ) -> Result<(EncryptedBlobStreamSegment, BlobStreamSegmentLeaves), BlobError> {
        if partition.stream_id != self.stream_id
            || partition.open_digest != self.open_digest
            || partition.content_epoch != self.content_epoch
        {
            return Err(BlobError::AuthenticationFailed);
        }
        let plaintext_len =
            u32::try_from(partition.plaintext.len()).map_err(|_| BlobError::LengthOverflow)?;
        let aad = segment_aad(
            partition.stream_id,
            partition.open_digest,
            partition.content_epoch,
            partition.index,
            partition.offset,
            partition.total_len,
            plaintext_len,
        );
        let cipher = Aes256Gcm::new(&Array(self.key));
        let nonce = Array(segment_nonce(self.base_nonce, partition.index)?);
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &partition.plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| BlobError::AuthenticationFailed)?;
        let leaves = segment_leaves(&aad, &partition.plaintext, &ciphertext);
        Ok((
            EncryptedBlobStreamSegment {
                stream_id: partition.stream_id,
                open_digest: partition.open_digest,
                content_epoch: partition.content_epoch,
                index: partition.index,
                offset: partition.offset,
                total_len: partition.total_len,
                plaintext_len,
                ciphertext,
            },
            leaves,
        ))
    }
}

impl BlobStreamSegmentOpener {
    pub(crate) fn new(
        stream_id: [u8; 32],
        open_digest: [u8; 32],
        content_epoch: u64,
        key: [u8; 32],
        base_nonce: [u8; 12],
    ) -> Self {
        Self(BlobStreamSegmentSealer::new(
            stream_id,
            open_digest,
            content_epoch,
            key,
            base_nonce,
        ))
    }

    pub fn open(
        &self,
        segment: &EncryptedBlobStreamSegment,
    ) -> Result<(Zeroizing<Vec<u8>>, BlobStreamSegmentLeaves), BlobError> {
        if segment.stream_id != self.0.stream_id
            || segment.open_digest != self.0.open_digest
            || segment.content_epoch != self.0.content_epoch
            || segment.plaintext_len == 0
            || segment.plaintext_len as usize > BLOB_STREAM_SEGMENT_BYTES
            || segment.offset
                != segment
                    .index
                    .checked_mul(BLOB_STREAM_SEGMENT_BYTES as u64)
                    .ok_or(BlobError::LengthOverflow)?
            || segment
                .offset
                .checked_add(u64::from(segment.plaintext_len))
                .ok_or(BlobError::LengthOverflow)?
                > segment.total_len
        {
            return Err(BlobError::AuthenticationFailed);
        }
        let aad = segment_aad(
            segment.stream_id,
            segment.open_digest,
            segment.content_epoch,
            segment.index,
            segment.offset,
            segment.total_len,
            segment.plaintext_len,
        );
        let cipher = Aes256Gcm::new(&Array(self.0.key));
        let nonce = Array(segment_nonce(self.0.base_nonce, segment.index)?);
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: &segment.ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| BlobError::AuthenticationFailed)?,
        );
        if plaintext.len() != segment.plaintext_len as usize {
            return Err(BlobError::AuthenticationFailed);
        }
        let leaves = segment_leaves(&aad, &plaintext, &segment.ciphertext);
        Ok((plaintext, leaves))
    }
}

fn segment_nonce(mut base: [u8; 12], index: u64) -> Result<[u8; 12], BlobError> {
    let start = u64::from_be_bytes(base[4..].try_into().expect("eight-byte nonce suffix"));
    let value = start.checked_add(index).ok_or(BlobError::LengthOverflow)?;
    base[4..].copy_from_slice(&value.to_be_bytes());
    Ok(base)
}

fn segment_aad(
    stream_id: [u8; 32],
    open_digest: [u8; 32],
    content_epoch: u64,
    index: u64,
    offset: u64,
    total_len: u64,
    plaintext_len: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(132);
    aad.extend_from_slice(b"ASTER/blob-stream/segment/v2\0");
    aad.extend_from_slice(&stream_id);
    aad.extend_from_slice(&open_digest);
    aad.extend_from_slice(&content_epoch.to_be_bytes());
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&offset.to_be_bytes());
    aad.extend_from_slice(&total_len.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in parts {
        hash.update((*part).len().to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}

fn segment_leaves(aad: &[u8], plaintext: &[u8], ciphertext: &[u8]) -> BlobStreamSegmentLeaves {
    BlobStreamSegmentLeaves {
        plaintext: hash_parts(b"ASTER/blob-stream/plain-leaf/v2\0", &[aad, plaintext]),
        ciphertext: hash_parts(b"ASTER/blob-stream/cipher-leaf/v2\0", &[aad, ciphertext]),
        plaintext_len: plaintext.len() as u64,
        ciphertext_len: ciphertext.len() as u64,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobStreamSubtree {
    first_index: u64,
    count: u64,
    plaintext_len: u64,
    ciphertext_len: u64,
    plaintext_root: [u8; 32],
    ciphertext_root: [u8; 32],
}

impl BlobStreamSubtree {
    pub fn leaf(index: u64, leaves: BlobStreamSegmentLeaves) -> Self {
        Self {
            first_index: index,
            count: 1,
            plaintext_len: leaves.plaintext_len,
            ciphertext_len: leaves.ciphertext_len,
            plaintext_root: leaves.plaintext,
            ciphertext_root: leaves.ciphertext,
        }
    }

    pub fn first_index(&self) -> u64 {
        self.first_index
    }

    pub fn combine(left: Self, right: Self) -> Result<Self, BlobError> {
        if left.count != right.count
            || left.first_index.checked_add(left.count) != Some(right.first_index)
        {
            return Err(BlobError::InvalidManifest);
        }
        let count = left
            .count
            .checked_add(right.count)
            .ok_or(BlobError::LengthOverflow)?;
        let plaintext_len = left
            .plaintext_len
            .checked_add(right.plaintext_len)
            .ok_or(BlobError::LengthOverflow)?;
        let ciphertext_len = left
            .ciphertext_len
            .checked_add(right.ciphertext_len)
            .ok_or(BlobError::LengthOverflow)?;
        let metadata = [
            left.first_index.to_be_bytes(),
            count.to_be_bytes(),
            plaintext_len.to_be_bytes(),
            ciphertext_len.to_be_bytes(),
        ]
        .concat();
        Ok(Self {
            first_index: left.first_index,
            count,
            plaintext_len,
            ciphertext_len,
            plaintext_root: hash_parts(
                b"ASTER/blob-stream/plain-node/v2\0",
                &[&metadata, &left.plaintext_root, &right.plaintext_root],
            ),
            ciphertext_root: hash_parts(
                b"ASTER/blob-stream/cipher-node/v2\0",
                &[&metadata, &left.ciphertext_root, &right.ciphertext_root],
            ),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamCheckpoint {
    next_index: u64,
    plaintext_len: u64,
    ciphertext_len: u64,
    levels: [Option<BlobStreamSubtree>; FRONTIER_LEVELS],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamFrontier {
    checkpoint: BlobStreamCheckpoint,
}

impl BlobStreamFrontier {
    pub fn new() -> Self {
        Self {
            checkpoint: BlobStreamCheckpoint {
                next_index: 0,
                plaintext_len: 0,
                ciphertext_len: 0,
                levels: [None; FRONTIER_LEVELS],
            },
        }
    }

    pub fn append(&mut self, mut subtree: BlobStreamSubtree) -> Result<(), BlobError> {
        if subtree.first_index != self.checkpoint.next_index || !subtree.count.is_power_of_two() {
            return Err(BlobError::InvalidManifest);
        }
        self.checkpoint.next_index = self
            .checkpoint
            .next_index
            .checked_add(subtree.count)
            .ok_or(BlobError::LengthOverflow)?;
        self.checkpoint.plaintext_len = self
            .checkpoint
            .plaintext_len
            .checked_add(subtree.plaintext_len)
            .ok_or(BlobError::LengthOverflow)?;
        self.checkpoint.ciphertext_len = self
            .checkpoint
            .ciphertext_len
            .checked_add(subtree.ciphertext_len)
            .ok_or(BlobError::LengthOverflow)?;
        let mut level = subtree.count.trailing_zeros() as usize;
        loop {
            if level >= FRONTIER_LEVELS {
                return Err(BlobError::LengthOverflow);
            }
            if let Some(left) = self.checkpoint.levels[level].take() {
                subtree = BlobStreamSubtree::combine(left, subtree)?;
                level += 1;
            } else {
                self.checkpoint.levels[level] = Some(subtree);
                return Ok(());
            }
        }
    }

    pub fn checkpoint(&self) -> BlobStreamCheckpoint {
        self.checkpoint.clone()
    }

    pub fn restore(checkpoint: BlobStreamCheckpoint) -> Result<Self, BlobError> {
        let rebuilt_plain = checkpoint
            .levels
            .iter()
            .flatten()
            .try_fold(0_u64, |sum, subtree| sum.checked_add(subtree.plaintext_len))
            .ok_or(BlobError::LengthOverflow)?;
        let rebuilt_cipher = checkpoint
            .levels
            .iter()
            .flatten()
            .try_fold(0_u64, |sum, subtree| {
                sum.checked_add(subtree.ciphertext_len)
            })
            .ok_or(BlobError::LengthOverflow)?;
        let rebuilt_count = checkpoint
            .levels
            .iter()
            .flatten()
            .try_fold(0_u64, |sum, subtree| sum.checked_add(subtree.count))
            .ok_or(BlobError::LengthOverflow)?;
        if rebuilt_plain != checkpoint.plaintext_len
            || rebuilt_cipher != checkpoint.ciphertext_len
            || rebuilt_count != checkpoint.next_index
        {
            return Err(BlobError::InvalidManifest);
        }
        Ok(Self { checkpoint })
    }

    pub fn finish(self, total_len: u64) -> Result<([u8; 32], [u8; 32]), BlobError> {
        if self.checkpoint.next_index == 0 || self.checkpoint.plaintext_len != total_len {
            return Err(BlobError::InvalidManifest);
        }
        let mut roots = self.checkpoint.levels.into_iter().flatten();
        let root = roots.next().ok_or(BlobError::InvalidManifest)?;
        if roots.next().is_some() {
            return Err(BlobError::InvalidManifest);
        }
        let final_fields = [
            total_len.to_be_bytes(),
            root.ciphertext_len.to_be_bytes(),
            root.count.to_be_bytes(),
        ]
        .concat();
        Ok((
            hash_parts(
                b"ASTER/blob-stream/plain-root/v2\0",
                &[&final_fields, &root.plaintext_root],
            ),
            hash_parts(
                b"ASTER/blob-stream/cipher-root/v2\0",
                &[&final_fields, &root.ciphertext_root],
            ),
        ))
    }
}

impl Default for BlobStreamFrontier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identities() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 12]) {
        ([0x11; 32], [0x22; 32], [0x33; 32], [0x44; 12])
    }

    fn partition(index: u64, byte: u8) -> BlobStreamPlainPartition {
        let (stream_id, open_digest, _, _) = identities();
        BlobStreamPlainPartition::new(
            stream_id,
            open_digest,
            7,
            index,
            index * BLOB_STREAM_SEGMENT_BYTES as u64,
            4 * BLOB_STREAM_SEGMENT_BYTES as u64,
            vec![byte; BLOB_STREAM_SEGMENT_BYTES],
        )
        .expect("valid partition")
    }

    fn contexts() -> (BlobStreamSegmentSealer, BlobStreamSegmentOpener) {
        let (stream_id, open_digest, key, nonce) = identities();
        (
            BlobStreamSegmentSealer::new(stream_id, open_digest, 7, key, nonce),
            BlobStreamSegmentOpener::new(stream_id, open_digest, 7, key, nonce),
        )
    }

    #[test]
    fn blob_stream_segments_seal_and_open_in_any_completion_order() {
        let (sealer, opener) = contexts();
        let mut sealed = (0..4)
            .map(|index| {
                sealer
                    .seal(partition(index, index as u8 + 1))
                    .expect("seal")
            })
            .collect::<Vec<_>>();
        sealed.swap(0, 3);
        sealed.swap(1, 2);
        for (segment, expected_leaves) in sealed {
            let (plaintext, leaves) = opener.open(&segment).expect("open shuffled segment");
            assert_eq!(plaintext[0], segment.index() as u8 + 1);
            assert_eq!(leaves, expected_leaves);
        }
    }

    fn roots_for_order(order: &[usize]) -> ([u8; 32], [u8; 32]) {
        let (sealer, _) = contexts();
        let leaves = (0..4)
            .map(|index| {
                sealer
                    .seal(partition(index, index as u8 + 1))
                    .expect("seal")
                    .1
            })
            .collect::<Vec<_>>();
        let mut ready = order
            .iter()
            .map(|index| BlobStreamSubtree::leaf(*index as u64, leaves[*index]))
            .collect::<Vec<_>>();
        ready.sort_by_key(BlobStreamSubtree::first_index);
        let left = BlobStreamSubtree::combine(ready[0], ready[1]).expect("left");
        let right = BlobStreamSubtree::combine(ready[2], ready[3]).expect("right");
        let mut frontier = BlobStreamFrontier::new();
        frontier
            .append(BlobStreamSubtree::combine(left, right).expect("root"))
            .expect("append");
        frontier
            .finish(4 * BLOB_STREAM_SEGMENT_BYTES as u64)
            .expect("finish")
    }

    #[test]
    fn blob_stream_reduction_matches_for_one_two_and_four_workers() {
        let expected = roots_for_order(&[0, 1, 2, 3]);
        assert_eq!(roots_for_order(&[1, 0, 3, 2]), expected);
        assert_eq!(roots_for_order(&[3, 1, 2, 0]), expected);
    }

    #[test]
    fn blob_stream_frontier_restores_the_same_final_roots() {
        let (sealer, _) = contexts();
        let mut frontier = BlobStreamFrontier::new();
        for index in 0..2 {
            let leaves = sealer
                .seal(partition(index, index as u8 + 1))
                .expect("seal")
                .1;
            frontier
                .append(BlobStreamSubtree::leaf(index, leaves))
                .expect("append");
        }
        let checkpoint = frontier.checkpoint();
        let mut restored = BlobStreamFrontier::restore(checkpoint).expect("restore");
        for index in 2..4 {
            let leaves = sealer
                .seal(partition(index, index as u8 + 1))
                .expect("seal")
                .1;
            restored
                .append(BlobStreamSubtree::leaf(index, leaves))
                .expect("append");
        }
        assert_eq!(
            restored
                .finish(4 * BLOB_STREAM_SEGMENT_BYTES as u64)
                .expect("finish"),
            roots_for_order(&[0, 1, 2, 3])
        );
    }

    #[test]
    fn blob_stream_segment_rejects_every_changed_identity_field() {
        let (sealer, opener) = contexts();
        let (segment, _) = sealer.seal(partition(0, 9)).expect("seal");
        for changed in segment.identity_mutations_for_test() {
            assert!(opener.open(&changed).is_err());
        }
    }
}
