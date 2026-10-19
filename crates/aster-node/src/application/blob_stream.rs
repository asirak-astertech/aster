//! Single-pass local Blob adapters composed over the shared bounded pipeline.

use crate::stream_pipeline::{
    MappedPartition, PipelineError, PipelineLimits, PipelineReport, StreamJobId, StreamPartition,
    run_ordered_pipeline,
};
use aster_mesh::{
    BLOB_STREAM_SEGMENT_BYTES, BlobStreamFrontier, BlobStreamOpen, BlobStreamPlainPartition,
    BlobStreamSegmentOpener, BlobStreamSegmentSealer, BlobStreamSubtree,
    EncryptedBlobStreamSegment,
};
use aster_redb_store::pack::{BlobPackError, BlobPackReader, BlobPackWriter};
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Debug)]
pub enum BlobStreamApplicationError {
    Io(std::io::Error),
    Pack(BlobPackError),
    Pipeline(PipelineError),
    IncompleteSource,
    IdentityMismatch,
}

impl Display for BlobStreamApplicationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl Error for BlobStreamApplicationError {}
impl From<std::io::Error> for BlobStreamApplicationError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<BlobPackError> for BlobStreamApplicationError {
    fn from(error: BlobPackError) -> Self {
        Self::Pack(error)
    }
}
impl From<PipelineError> for BlobStreamApplicationError {
    fn from(error: PipelineError) -> Self {
        Self::Pipeline(error)
    }
}

pub struct BlobPublishPipelineResult {
    pub plaintext_root: [u8; 32],
    pub ciphertext_root: [u8; 32],
    pub segment_count: u64,
    pub report: PipelineReport,
}

struct PlaintextPartitions<R> {
    source: R,
    total_len: u64,
    offset: u64,
    failed: Arc<Mutex<Option<std::io::Error>>>,
}

impl<R: Read> Iterator for PlaintextPartitions<R> {
    type Item = StreamPartition;
    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.total_len || self.failed.lock().expect("source state").is_some() {
            return None;
        }
        let len = (self.total_len - self.offset).min(BLOB_STREAM_SEGMENT_BYTES as u64) as usize;
        let mut bytes = vec![0; len];
        if let Err(error) = self.source.read_exact(&mut bytes) {
            *self.failed.lock().expect("source state") = Some(error);
            return None;
        }
        let index = self.offset / BLOB_STREAM_SEGMENT_BYTES as u64;
        self.offset += len as u64;
        Some(StreamPartition::new(index, bytes))
    }
}

pub async fn publish_blob_stream<R: Read>(
    source: R,
    open: &BlobStreamOpen,
    sealer: BlobStreamSegmentSealer,
    pack_root: &Path,
    limits: PipelineLimits,
) -> Result<BlobPublishPipelineResult, BlobStreamApplicationError> {
    let failed = Arc::new(Mutex::new(None));
    let partitions = PlaintextPartitions {
        source,
        total_len: open.total_len(),
        offset: 0,
        failed: Arc::clone(&failed),
    };
    let mut writer = BlobPackWriter::create(pack_root, open)?;
    let stream_id = *open.stream_id().as_bytes();
    let open_digest = open.digest();
    let content_epoch = open.content_epoch();
    let total_len = open.total_len();
    let job_id = StreamJobId::from_bytes(
        open.stream_id().as_bytes()[..16]
            .try_into()
            .expect("job ID"),
    );
    let report = run_ordered_pipeline(
        job_id,
        partitions,
        limits,
        move |partition| {
            let index = partition.index();
            let owned = BlobStreamPlainPartition::new(
                stream_id,
                open_digest,
                content_epoch,
                index,
                index * BLOB_STREAM_SEGMENT_BYTES as u64,
                total_len,
                partition.into_bytes(),
            )
            .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
            sealer
                .seal(owned)
                .map_err(|error| PipelineError::MapFailed(error.to_string()))
        },
        |mapped| {
            let result = mapped.into_value();
            std::future::ready(
                writer
                    .append(&result.0, result.1)
                    .map_err(|error| PipelineError::SinkFailed(error.to_string())),
            )
        },
    )
    .await?;
    if failed.lock().expect("source state").is_some() || report.completed_items() == 0 {
        return Err(BlobStreamApplicationError::IncompleteSource);
    }
    let segment_count = report.completed_items();
    let (plaintext_root, ciphertext_root) = writer.finish()?;
    Ok(BlobPublishPipelineResult {
        plaintext_root,
        ciphertext_root,
        segment_count,
        report,
    })
}

pub async fn read_blob_stream<W: Write>(
    open: &BlobStreamOpen,
    opener: BlobStreamSegmentOpener,
    pack_root: &Path,
    output: &mut W,
    expected_roots: ([u8; 32], [u8; 32]),
    limits: PipelineLimits,
) -> Result<PipelineReport, BlobStreamApplicationError> {
    let mut pack = BlobPackReader::open(pack_root, open)?;
    let pack_failed = Arc::new(Mutex::new(None));
    let iterator_failed = Arc::clone(&pack_failed);
    let encoded = std::iter::from_fn(move || match pack.next_segment() {
        Ok(Some(segment)) => Some(StreamPartition::new(segment.index(), segment.encode())),
        Ok(None) => None,
        Err(error) => {
            *iterator_failed.lock().expect("pack state") = Some(error);
            None
        }
    });
    let mut frontier = BlobStreamFrontier::new();
    let job_id = StreamJobId::from_bytes(
        open.stream_id().as_bytes()[..16]
            .try_into()
            .expect("job ID"),
    );
    let report = run_ordered_pipeline(
        job_id,
        encoded,
        limits,
        move |partition| {
            let segment = EncryptedBlobStreamSegment::decode(&partition.into_bytes())
                .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
            let index = segment.index();
            let (plaintext, leaves) = opener
                .open(&segment)
                .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
            Ok((index, plaintext, leaves))
        },
        |mapped: MappedPartition<_>| {
            let (index, plaintext, leaves) = mapped.into_value();
            let result = frontier
                .append(BlobStreamSubtree::leaf(index, leaves))
                .map_err(|error| PipelineError::SinkFailed(error.to_string()))
                .and_then(|()| {
                    output
                        .write_all(&plaintext)
                        .map_err(|error| PipelineError::SinkFailed(error.to_string()))
                });
            std::future::ready(result)
        },
    )
    .await?;
    if pack_failed.lock().expect("pack state").is_some() {
        return Err(BlobStreamApplicationError::IdentityMismatch);
    }
    if frontier
        .finish(open.total_len())
        .map_err(|_| BlobStreamApplicationError::IdentityMismatch)?
        != expected_roots
    {
        return Err(BlobStreamApplicationError::IdentityMismatch);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aster_mesh::{
        BlobMetadata, BlobPublicationStreamId, Priority, Scope, Topic, VersionVector,
    };
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    struct TempRoot(std::path::PathBuf);
    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aster-local-stream-test-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).expect("temp root");
            Self(path)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct CountingReader {
        cursor: std::io::Cursor<Vec<u8>>,
        read: Arc<AtomicU64>,
    }
    impl Read for CountingReader {
        fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
            let read = self.cursor.read(output)?;
            self.read.fetch_add(read as u64, Ordering::Relaxed);
            Ok(read)
        }
    }

    fn open(total_len: u64) -> BlobStreamOpen {
        BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([0x11; 32]).expect("stream"),
            [0x21; 32],
            b"local-pipeline".to_vec(),
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

    #[tokio::test]
    async fn local_blob_pipeline_reads_plaintext_once_and_round_trips() {
        let root = TempRoot::new();
        let plaintext = (0..(2 * BLOB_STREAM_SEGMENT_BYTES + 17))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let open = open(plaintext.len() as u64);
        let read = Arc::new(AtomicU64::new(0));
        let source = CountingReader {
            cursor: std::io::Cursor::new(plaintext.clone()),
            read: Arc::clone(&read),
        };
        let limits = PipelineLimits::new(4, 4, 5 * 1024 * 1024, 4).expect("limits");
        let key = [0x61; 32];
        let nonce = [0x71; 12];
        let published = publish_blob_stream(
            source,
            &open,
            BlobStreamSegmentSealer::from_test_key(
                *open.stream_id().as_bytes(),
                open.digest(),
                open.content_epoch(),
                key,
                nonce,
            ),
            &root.0,
            limits,
        )
        .await
        .expect("publish");
        assert_eq!(read.load(Ordering::Relaxed), plaintext.len() as u64);
        assert_eq!(published.segment_count, 3);

        let mut output = Vec::new();
        let report = read_blob_stream(
            &open,
            BlobStreamSegmentOpener::from_test_key(
                *open.stream_id().as_bytes(),
                open.digest(),
                open.content_epoch(),
                key,
                nonce,
            ),
            &root.0,
            &mut output,
            (published.plaintext_root, published.ciphertext_root),
            limits,
        )
        .await
        .expect("read");
        assert_eq!(output, plaintext);
        assert_eq!(report.completed_items(), 3);
    }
}
