//! Sequential encrypted stream pack with alternating durable checkpoints.

use aster_mesh::{
    BlobPublicationStreamId, BlobStreamCheckpoint, BlobStreamFrontier, BlobStreamOpen,
    BlobStreamSegmentLeaves, BlobStreamSubtree, EncryptedBlobStreamSegment,
};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const PACK_MAGIC: &[u8; 8] = b"ASTRPK02";
const CHECKPOINT_MAGIC: &[u8; 8] = b"ASTRCP02";
const PACK_VERSION: u16 = 2;
const PACK_FILE: &str = "segments.pack";
const CHECKPOINT_ZERO: &str = "checkpoint.0";
const CHECKPOINT_ONE: &str = "checkpoint.1";
const PACK_HEADER_LEN: u64 = 8 + 2 + 32 + 32 + 8;
const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;

#[derive(Debug)]
pub enum BlobPackError {
    Io(std::io::Error),
    Invalid(&'static str),
}

impl Display for BlobPackError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => Display::fmt(error, formatter),
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPackCheckpoint {
    generation: u64,
    open_digest: [u8; 32],
    stream_id: BlobPublicationStreamId,
    total_len: u64,
    next_index: u64,
    plaintext_offset: u64,
    pack_len: u64,
    frontier: BlobStreamCheckpoint,
}

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

    fn encode(&self) -> Vec<u8> {
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

    fn decode(bytes: &[u8]) -> Result<Self, BlobPackError> {
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
            || total_len == 0
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
        })
    }
}

pub struct BlobPackWriter {
    root: PathBuf,
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
    pub fn create(root: &Path, open: &BlobStreamOpen) -> Result<Self, BlobPackError> {
        fs::create_dir_all(root)?;
        let mut data = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(root.join(PACK_FILE))?;
        let open_digest = open.digest();
        data.write_all(PACK_MAGIC)?;
        data.write_all(&PACK_VERSION.to_be_bytes())?;
        data.write_all(&open_digest)?;
        data.write_all(open.stream_id().as_bytes())?;
        data.write_all(&open.total_len().to_be_bytes())?;
        data.sync_all()?;
        let mut writer = Self {
            root: root.to_owned(),
            data,
            open_digest,
            stream_id: open.stream_id(),
            total_len: open.total_len(),
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
        let mut data = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.join(PACK_FILE))?;
        validate_header(&mut data, open)?;
        let checkpoint = recover_checkpoint(root, open, data.metadata()?.len())?;
        data.set_len(checkpoint.pack_len)?;
        data.seek(SeekFrom::Start(checkpoint.pack_len))?;
        Ok(Self {
            root: root.to_owned(),
            data,
            open_digest: open.digest(),
            stream_id: open.stream_id(),
            total_len: open.total_len(),
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
        if segment.index() != self.next_index
            || segment.stream_id() != self.stream_id.as_bytes()
            || segment.open_digest() != &self.open_digest
            || segment.offset() != self.plaintext_offset
            || segment.total_len() != self.total_len
        {
            return Err(BlobPackError::Invalid(
                "Blob segment is outside pack sequence",
            ));
        }
        let encoded = segment.encode();
        if encoded.len() > MAX_RECORD_BYTES {
            return Err(BlobPackError::Invalid(
                "Blob segment record exceeds pack bound",
            ));
        }
        self.data.write_all(&(encoded.len() as u32).to_be_bytes())?;
        self.data.write_all(&encoded)?;
        self.frontier
            .append(BlobStreamSubtree::leaf(self.next_index, leaves))
            .map_err(|_| BlobPackError::Invalid("invalid Blob segment frontier"))?;
        self.next_index += 1;
        self.plaintext_offset = self
            .plaintext_offset
            .checked_add(u64::from(segment.plaintext_len()))
            .ok_or(BlobPackError::Invalid("Blob pack offset overflow"))?;
        self.pack_len = self
            .pack_len
            .checked_add(4 + encoded.len() as u64)
            .ok_or(BlobPackError::Invalid("Blob pack length overflow"))?;
        Ok(())
    }

    pub fn checkpoint(&mut self) -> Result<BlobPackCheckpoint, BlobPackError> {
        self.data.sync_data()?;
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
        };
        let path = self.root.join(if generation % 2 == 0 {
            CHECKPOINT_ZERO
        } else {
            CHECKPOINT_ONE
        });
        let mut journal = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        journal.write_all(&checkpoint.encode())?;
        journal.sync_all()?;
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

impl BlobPackReader {
    pub fn open(root: &Path, open: &BlobStreamOpen) -> Result<Self, BlobPackError> {
        let mut data = File::open(root.join(PACK_FILE))?;
        validate_header(&mut data, open)?;
        let checkpoint = recover_checkpoint(root, open, data.metadata()?.len())?;
        data.seek(SeekFrom::Start(PACK_HEADER_LEN))?;
        Ok(Self {
            data,
            checkpoint,
            next_index: 0,
        })
    }

    pub fn next_segment(&mut self) -> Result<Option<EncryptedBlobStreamSegment>, BlobPackError> {
        if self.next_index >= self.checkpoint.next_index {
            return Ok(None);
        }
        let mut len = [0; 4];
        self.data.read_exact(&mut len)?;
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_RECORD_BYTES {
            return Err(BlobPackError::Invalid("invalid Blob pack record length"));
        }
        let mut encoded = vec![0; len];
        self.data.read_exact(&mut encoded)?;
        let segment = EncryptedBlobStreamSegment::decode(&encoded)
            .map_err(|_| BlobPackError::Invalid("invalid Blob pack segment"))?;
        if segment.index() != self.next_index {
            return Err(BlobPackError::Invalid("non-contiguous Blob pack segment"));
        }
        self.next_index += 1;
        Ok(Some(segment))
    }

    pub const fn checkpoint(&self) -> &BlobPackCheckpoint {
        &self.checkpoint
    }
}

fn validate_header(data: &mut File, open: &BlobStreamOpen) -> Result<(), BlobPackError> {
    data.seek(SeekFrom::Start(0))?;
    let mut header = [0; PACK_HEADER_LEN as usize];
    data.read_exact(&mut header)?;
    if &header[..8] != PACK_MAGIC
        || u16::from_be_bytes(header[8..10].try_into().expect("version")) != PACK_VERSION
        || header[10..42] != open.digest()
        || header[42..74] != *open.stream_id().as_bytes()
        || u64::from_be_bytes(header[74..82].try_into().expect("length")) != open.total_len()
    {
        return Err(BlobPackError::Invalid("Blob pack header identity mismatch"));
    }
    Ok(())
}

fn recover_checkpoint(
    root: &Path,
    open: &BlobStreamOpen,
    data_len: u64,
) -> Result<BlobPackCheckpoint, BlobPackError> {
    let mut valid = Vec::new();
    for name in [CHECKPOINT_ZERO, CHECKPOINT_ONE] {
        let Ok(bytes) = fs::read(root.join(name)) else {
            continue;
        };
        let Ok(checkpoint) = BlobPackCheckpoint::decode(&bytes) else {
            continue;
        };
        if checkpoint.open_digest == open.digest()
            && checkpoint.stream_id == open.stream_id()
            && checkpoint.total_len == open.total_len()
            && checkpoint.pack_len <= data_len
        {
            valid.push(checkpoint);
        }
    }
    valid
        .into_iter()
        .max_by_key(|checkpoint| checkpoint.generation)
        .ok_or(BlobPackError::Invalid("no valid Blob pack checkpoint"))
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
        let newest_path = root.0.join(if newest.generation() % 2 == 0 {
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
}
