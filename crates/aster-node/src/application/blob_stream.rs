//! Single-pass local Blob adapters composed over the shared bounded pipeline.

use crate::stream_pipeline::{
    FixedPartitionMapPool, MappedPartition, PipelineError, PipelineLimits, PipelineReport,
    StreamJobId, StreamPartition, run_ordered_pipeline,
};
use aster_mesh::{
    BLOB_STREAM_SEGMENT_BYTES, BlobStreamFrontier, BlobStreamOpen, BlobStreamPlainPartition,
    BlobStreamSegmentLeaves, BlobStreamSegmentOpener, BlobStreamSegmentSealer, BlobStreamSubtree,
    BlobUploadDescriptor, BlobUploadPlainPartition, BlobUploadSegmentOpener,
    BlobUploadSegmentSealer, EncryptedBlobStreamSegment,
};
use aster_redb_store::{
    BlobStreamPublication, BlobUploadCheckpoint, BlobUploadReservation,
    pack::{BlobPackError, BlobPackIdentity, BlobPackReader, BlobPackWriter, PinnedBlobPackRoot},
};
use std::{
    collections::{BTreeMap, VecDeque},
    error::Error,
    fmt::{self, Display, Formatter},
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex},
};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use super::blob::{BlobPublishOptions, BlobPublishRequest, BlobPublishResult, SelectedBlobCommand};
use super::{
    ApplicationError, ApplicationErrorKind, SelectedApplicationCommand, actor_unavailable,
};

const BLOB_STREAM_CHECKPOINT_SEGMENTS: u64 = 64;
const BLOB_STREAM_MAP_WORKERS: usize = 2;
const BLOB_STREAM_MAP_QUEUE_ITEMS: usize = 4;

type SealedBlobStreamPartition = (EncryptedBlobStreamSegment, BlobStreamSegmentLeaves);

pub(super) struct LocalBlobPublishStream {
    pub(super) reservation: BlobUploadReservation,
    pub(super) checkpoint: BlobUploadCheckpoint,
    pub(super) writer: BlobPackWriter,
    pub(super) request: BlobPublishRequest,
    pub(super) options: BlobPublishOptions,
    pub(super) total_len: u64,
    pub(super) accepted_offset: u64,
    pub(super) pending: Zeroizing<Vec<u8>>,
    pub(super) map_pool: Option<FixedPartitionMapPool<SealedBlobStreamPartition>>,
    pub(super) mapped: BTreeMap<u64, MappedPartition<SealedBlobStreamPartition>>,
    pub(super) next_map_index: u64,
    pub(super) next_sink_index: u64,
    pub(super) mapped_segments: u64,
    pub(super) checkpoint_segments: u64,
}

impl LocalBlobPublishStream {
    pub(super) const fn production_checkpoint_segments() -> u64 {
        BLOB_STREAM_CHECKPOINT_SEGMENTS
    }

    pub(super) fn map_checkpoint_due(&self) -> bool {
        self.next_map_index.saturating_sub(
            self.checkpoint
                .durable_pack_checkpoint()
                .map_or(0, |checkpoint| checkpoint.next_index()),
        ) >= self.checkpoint_segments
    }

    pub(super) fn durable_checkpoint_due(&self) -> bool {
        self.writer
            .plaintext_offset()
            .saturating_sub(self.checkpoint.durable_plaintext_offset())
            >= self.checkpoint_segments * BLOB_STREAM_SEGMENT_BYTES as u64
    }

    #[cfg(test)]
    pub(super) fn set_checkpoint_segments_for_test(&mut self, segments: u64) {
        assert!(segments > 0, "checkpoint cadence must be positive");
        self.checkpoint_segments = segments;
    }
}

pub(super) struct LocalBlobReadStream {
    pub(super) publication: BlobStreamPublication,
    pub(super) reader: BlobPackReader,
    pub(super) opener: BlobStreamSegmentOpener,
    pub(super) segments: VecDeque<(u64, Zeroizing<Vec<u8>>)>,
    pub(super) last_request_offset: u64,
}

pub(super) fn take_zeroizing_bytes(mut bytes: Zeroizing<Vec<u8>>) -> Vec<u8> {
    std::mem::take(&mut *bytes)
}

pub(super) fn blob_stream_map_pool(
    upload: BlobUploadDescriptor,
    sealer: &BlobUploadSegmentSealer,
    total_len: u64,
) -> Result<FixedPartitionMapPool<SealedBlobStreamPartition>, ApplicationError> {
    let stream_id = *upload.upload_id().as_bytes();
    let open_digest = *upload.request_digest();
    let content_epoch = upload.content_epoch();
    let sealer = sealer.clone();
    FixedPartitionMapPool::new(
        BLOB_STREAM_MAP_WORKERS,
        BLOB_STREAM_MAP_QUEUE_ITEMS,
        move |partition| {
            let index = partition.index();
            let offset = index.checked_mul(BLOB_STREAM_SEGMENT_BYTES as u64).ok_or(
                PipelineError::MapFailed("blob stream offset overflow".into()),
            )?;
            let partition = BlobUploadPlainPartition::new(
                stream_id,
                open_digest,
                content_epoch,
                index,
                offset,
                total_len,
                partition.into_bytes(),
            )
            .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
            sealer
                .seal(partition)
                .map_err(|error| PipelineError::MapFailed(error.to_string()))
        },
    )
    .map_err(blob_stream_pipeline_error)
}

/// Seekable bounded plaintext view over the exact Store-projected upload pack.
/// Backward seeks reopen the durable checkpoint; normal canonical encryption
/// reads forward with at most one decrypted provisional segment resident.
pub(super) struct UploadPackPlainReader {
    root: PinnedBlobPackRoot,
    identity: BlobPackIdentity,
    checkpoint: aster_redb_store::pack::BlobPackCheckpoint,
    pack: BlobPackReader,
    opener: BlobUploadSegmentOpener,
    plaintext: Zeroizing<Vec<u8>>,
    plaintext_offset: usize,
    segment_start: u64,
    position: u64,
    total_len: u64,
}

impl UploadPackPlainReader {
    pub(super) fn open(
        root: PinnedBlobPackRoot,
        reservation: &BlobUploadReservation,
        checkpoint: &BlobUploadCheckpoint,
        opener: BlobUploadSegmentOpener,
    ) -> Result<Self, ApplicationError> {
        let identity = reservation.pack_identity();
        let durable = checkpoint.durable_pack_checkpoint().ok_or_else(|| {
            ApplicationError::new(ApplicationErrorKind::Integrity, "blob upload finalize")
        })?;
        let pack = BlobPackReader::open_projected_upload_pinned(&root, &identity, durable)
            .map_err(|error| blob_pack_application_error("blob upload finalize", error))?;
        Ok(Self {
            root,
            identity,
            checkpoint: durable.clone(),
            pack,
            opener,
            plaintext: Zeroizing::new(Vec::new()),
            plaintext_offset: 0,
            segment_start: 0,
            position: 0,
            total_len: identity.total_len(),
        })
    }

    fn reopen(&mut self) -> std::io::Result<()> {
        self.pack = BlobPackReader::open_projected_upload_pinned(
            &self.root,
            &self.identity,
            &self.checkpoint,
        )
        .map_err(std::io::Error::other)?;
        self.plaintext.clear();
        self.plaintext_offset = 0;
        self.segment_start = 0;
        self.position = 0;
        Ok(())
    }

    fn load_next_segment(&mut self) -> std::io::Result<bool> {
        let Some(segment) = self.pack.next_segment().map_err(std::io::Error::other)? else {
            return Ok(false);
        };
        let (plaintext, _) = self.opener.open(&segment).map_err(std::io::Error::other)?;
        self.segment_start = self.position;
        self.plaintext = plaintext;
        self.plaintext_offset = 0;
        Ok(true)
    }
}

impl Read for UploadPackPlainReader {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() || self.position >= self.total_len {
            return Ok(0);
        }
        if self.plaintext_offset >= self.plaintext.len() && !self.load_next_segment()? {
            return Ok(0);
        }
        let available = &self.plaintext[self.plaintext_offset..];
        let len = available.len().min(output.len());
        output[..len].copy_from_slice(&available[..len]);
        self.plaintext_offset += len;
        self.position = self
            .position
            .checked_add(len as u64)
            .ok_or_else(|| std::io::Error::other("upload position overflow"))?;
        Ok(len)
    }
}

impl std::io::Seek for UploadPackPlainReader {
    fn seek(&mut self, position: std::io::SeekFrom) -> std::io::Result<u64> {
        let target = match position {
            std::io::SeekFrom::Start(position) => Some(position),
            std::io::SeekFrom::End(delta) => self.total_len.checked_add_signed(delta),
            std::io::SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        }
        .filter(|target| *target <= self.total_len)
        .ok_or_else(|| std::io::Error::other("upload seek is out of bounds"))?;
        if target == self.position {
            return Ok(target);
        }
        let segment_end = self
            .segment_start
            .checked_add(self.plaintext.len() as u64)
            .ok_or_else(|| std::io::Error::other("upload segment bound overflow"))?;
        if !self.plaintext.is_empty() && (self.segment_start..=segment_end).contains(&target) {
            self.plaintext_offset =
                usize::try_from(target - self.segment_start).map_err(std::io::Error::other)?;
            self.position = target;
            return Ok(target);
        }
        self.reopen()?;
        while self.position < target {
            if !self.load_next_segment()? {
                return Err(std::io::Error::other("upload pack ended during seek"));
            }
            let segment_end = self
                .segment_start
                .checked_add(self.plaintext.len() as u64)
                .ok_or_else(|| std::io::Error::other("upload segment bound overflow"))?;
            if target <= segment_end {
                self.plaintext_offset =
                    usize::try_from(target - self.segment_start).map_err(std::io::Error::other)?;
                self.position = target;
                return Ok(target);
            }
            self.position = segment_end;
            self.plaintext_offset = self.plaintext.len();
        }
        Ok(target)
    }
}

pub(super) fn blob_stream_pipeline_error(_error: PipelineError) -> ApplicationError {
    ApplicationError::new(ApplicationErrorKind::Integrity, "blob stream pipeline")
}

pub(super) fn blob_pack_application_error(
    operation: &'static str,
    error: BlobPackError,
) -> ApplicationError {
    let kind = match error {
        BlobPackError::Io(_) | BlobPackError::Store(_) => ApplicationErrorKind::StateUnavailable,
        BlobPackError::Invalid(_) => ApplicationErrorKind::Integrity,
    };
    ApplicationError::new(kind, operation)
}

pub(super) fn sink_mapped_stream_partitions(
    stream: &mut LocalBlobPublishStream,
    wait_for_all: bool,
) -> Result<(), ApplicationError> {
    loop {
        let mapped = if wait_for_all && stream.mapped_segments < stream.next_map_index {
            Some(
                stream
                    .map_pool
                    .as_mut()
                    .expect("open stream map pool")
                    .recv_mapped_blocking()
                    .map_err(blob_stream_pipeline_error)?,
            )
        } else {
            stream
                .map_pool
                .as_mut()
                .expect("open stream map pool")
                .try_recv_mapped()
                .map_err(blob_stream_pipeline_error)?
        };
        let Some(mapped) = mapped else {
            break;
        };
        let index = mapped.index();
        if stream.mapped.insert(index, mapped).is_some() {
            return Err(blob_stream_pipeline_error(
                PipelineError::NonContiguousIndex {
                    expected: stream.next_sink_index,
                    actual: index,
                },
            ));
        }
        stream.mapped_segments += 1;
        while let Some(mapped) = stream.mapped.remove(&stream.next_sink_index) {
            let (segment, leaves) = mapped.into_value();
            stream
                .writer
                .append(&segment, leaves)
                .map_err(|error| blob_pack_application_error("blob stream write", error))?;
            stream.next_sink_index += 1;
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobPublishStreamRequest {
    pub publication: BlobPublishRequest,
    pub options: BlobPublishOptions,
    pub total_len: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlobPublishProgress {
    pub accepted_offset: u64,
    pub durable_offset: u64,
}

pub struct SelectedBlobPublishStream {
    commands: mpsc::Sender<SelectedApplicationCommand>,
    token: [u8; 32],
    durable_offset: u64,
}

impl SelectedBlobPublishStream {
    pub(crate) fn new(
        commands: mpsc::Sender<SelectedApplicationCommand>,
        token: [u8; 32],
        progress: BlobPublishProgress,
    ) -> Self {
        Self {
            commands,
            token,
            durable_offset: progress.durable_offset,
        }
    }

    pub const fn durable_offset(&self) -> u64 {
        self.durable_offset
    }

    pub async fn write(
        &mut self,
        offset: u64,
        bytes: Zeroizing<Vec<u8>>,
    ) -> Result<BlobPublishProgress, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.commands
            .send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::AppendPublishStream {
                    token: self.token,
                    offset,
                    bytes,
                    response,
                },
            ))
            .await
            .map_err(|_| actor_unavailable("blob stream write"))?;
        let progress = received
            .await
            .map_err(|_| actor_unavailable("blob stream write"))??;
        self.durable_offset = progress.durable_offset;
        Ok(progress)
    }

    pub async fn finish(self) -> Result<BlobPublishResult, ApplicationError> {
        let (response, received) = oneshot::channel();
        self.commands
            .send(SelectedApplicationCommand::Blob(
                SelectedBlobCommand::FinishPublishStream {
                    token: self.token,
                    response,
                },
            ))
            .await
            .map_err(|_| actor_unavailable("blob stream finish"))?;
        received
            .await
            .map_err(|_| actor_unavailable("blob stream finish"))?
    }
}

pub(crate) struct OpenedBlobPublishStream {
    pub token: [u8; 32],
    pub progress: BlobPublishProgress,
}

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

    #[test]
    fn production_checkpoint_policy_batches_sixty_four_segments() {
        assert_eq!(LocalBlobPublishStream::production_checkpoint_segments(), 64);
    }

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
