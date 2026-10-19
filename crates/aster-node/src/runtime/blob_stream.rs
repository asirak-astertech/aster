//! Profile-5 Blob network DAG composition.

use crate::{
    stream_pipeline::{
        MappedPartition, PipelineError, PipelineLimits, PipelineReport, StreamJobId,
        StreamPartition, run_ordered_channel_pipeline,
    },
    stream_transfer::{
        MAX_STREAM_CHECKPOINT_BATCH_BYTES, StreamAction, StreamClass, StreamDirection, StreamFrame,
        StreamOpenV1, StreamReceiverState, StreamResultCode, StreamSenderState,
    },
    stream_transport::{AttemptOpenRequest, IrohQuicV1Adapter, StreamTransportAdapter},
};
use aster_iroh::Connection;
use aster_mesh::{BlobStreamOpen, BlobStreamSegmentOpener, EncryptedBlobStreamSegment};
use aster_redb_store::pack::{BlobPackReader, BlobPackWriter};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
use tokio::{sync::mpsc, time::Instant};

const EXTENT_BYTES: usize = 256 * 1024;
const MAX_RECORD_BYTES: usize = 2 * 1024 * 1024;
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10 * 60);

#[derive(Debug)]
pub struct BlobNetworkReport {
    pub wire_bytes: u64,
    pub roots: ([u8; 32], [u8; 32]),
    pub checkpoints: u64,
    pub pipeline: Option<PipelineReport>,
}

fn failure(context: &str, error: impl std::fmt::Display) -> String {
    format!("{context}: {error}")
}

fn encoded(frame: StreamFrame) -> Result<Vec<u8>, String> {
    frame
        .encode_for_context(9, 5)
        .map_err(|error| error.to_string())
}

fn decoded(bytes: &[u8]) -> Result<StreamFrame, String> {
    StreamFrame::decode_for_context(9, 5, bytes).map_err(|error| error.to_string())
}

fn result_digest(open: &BlobStreamOpen, roots: ([u8; 32], [u8; 32])) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aster/blob-network-result/v1");
    hasher.update(open.digest());
    hasher.update(roots.0);
    hasher.update(roots.1);
    hasher.finalize().into()
}

fn attempt_bounds(bytes: u64) -> Result<(usize, usize), String> {
    let extents = bytes.div_ceil(EXTENT_BYTES as u64);
    let checkpoints = bytes.div_ceil(u64::from(MAX_STREAM_CHECKPOINT_BATCH_BYTES));
    let data = usize::try_from(bytes)
        .ok()
        .and_then(|value| {
            usize::try_from(extents)
                .ok()
                .and_then(|count| count.checked_mul(128))
                .and_then(|overhead| value.checked_add(overhead))
        })
        .and_then(|value| value.checked_add(4096))
        .ok_or("data stream bound overflow")?;
    let control = usize::try_from(checkpoints)
        .ok()
        .and_then(|count| count.checked_mul(192))
        .and_then(|value| value.checked_add(8192))
        .ok_or("control stream bound overflow")?;
    Ok((data, control))
}

pub fn completed_pack_wire_len(root: &Path, open: &BlobStreamOpen) -> Result<u64, String> {
    let reader = BlobPackReader::open(root, open).map_err(|error| failure("open pack", error))?;
    Ok(reader.checkpoint().payload_len())
}

pub fn expected_pack_wire_len(plaintext_len: u64) -> Result<u64, String> {
    let segments = plaintext_len.div_ceil(aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64);
    plaintext_len
        .checked_add(
            segments
                .checked_mul(4 + aster_mesh::BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES as u64)
                .ok_or("wire length overflow")?,
        )
        .ok_or_else(|| "wire length overflow".into())
}

struct PackExtentSource {
    reader: BlobPackReader,
    record: Vec<u8>,
    cursor: usize,
}

impl PackExtentSource {
    fn new(root: &Path, open: &BlobStreamOpen) -> Result<Self, String> {
        Ok(Self {
            reader: BlobPackReader::open(root, open)
                .map_err(|error| failure("open source pack", error))?,
            record: Vec::new(),
            cursor: 0,
        })
    }

    fn next_extent(&mut self) -> Result<Option<Vec<u8>>, String> {
        if self.cursor == self.record.len() {
            let Some(segment) = self
                .reader
                .next_segment()
                .map_err(|error| failure("read source segment", error))?
            else {
                return Ok(None);
            };
            let encoded = segment.encode();
            self.record.clear();
            self.record
                .extend_from_slice(&(encoded.len() as u32).to_be_bytes());
            self.record.extend_from_slice(&encoded);
            self.cursor = 0;
        }
        let end = self.record.len().min(self.cursor + EXTENT_BYTES);
        let extent = self.record[self.cursor..end].to_vec();
        self.cursor = end;
        Ok(Some(extent))
    }
}

fn protocol_open(open: &BlobStreamOpen, wire_len: u64, attempt_nonce: [u8; 32]) -> StreamOpenV1 {
    StreamOpenV1 {
        class: StreamClass::Blob,
        direction: StreamDirection::ToSessionResponder,
        session_transcript: open.digest(),
        exchange_id: 1,
        transfer_id: open.digest(),
        source_transfer_id: *open.stream_id().as_bytes(),
        publication_id: *open.stream_id().as_bytes(),
        variant_id: open.digest(),
        total_len: wire_len,
        attempt_nonce,
        checkpoint_generation: 0,
        custody_digest: None,
    }
}

pub async fn send_completed_pack(
    connection: Connection,
    open: &BlobStreamOpen,
    root: &Path,
    roots: ([u8; 32], [u8; 32]),
) -> Result<BlobNetworkReport, String> {
    let wire_len = completed_pack_wire_len(root, open)?;
    if wire_len != expected_pack_wire_len(open.total_len())? {
        return Err("completed pack wire length differs from canonical segment framing".into());
    }
    let (max_data_bytes, max_control_bytes) = attempt_bounds(wire_len)?;
    let attempt = IrohQuicV1Adapter::new(connection)
        .open_attempt(AttemptOpenRequest {
            deadline: Instant::now() + ATTEMPT_TIMEOUT,
            max_data_bytes,
            max_control_bytes,
        })
        .await
        .map_err(|error| failure("open transport attempt", format!("{error:?}")))?;
    let mut attempt_nonce = [0; 32];
    getrandom::fill(&mut attempt_nonce).map_err(|error| failure("attempt nonce", error))?;
    let transfer_open = protocol_open(open, wire_len, attempt_nonce);
    attempt
        .send_data(&encoded(StreamFrame::Open(transfer_open.clone()))?)
        .await
        .map_err(|error| failure("send open", format!("{error:?}")))?;
    let accept = attempt
        .receive_control()
        .await
        .map_err(|error| failure("receive accept", format!("{error:?}")))?
        .ok_or("control stream closed before accept")?;
    let StreamFrame::Accept(accept) = decoded(&accept)? else {
        return Err("first control frame was not accept".into());
    };
    let mut state = StreamSenderState::new(transfer_open.transfer_id, attempt_nonce, wire_len);
    state.accept(accept).map_err(|error| error.to_string())?;
    let mut source = PackExtentSource::new(root, open)?;
    let mut pending = source.next_extent()?;
    let mut checkpoints = 0;
    while let Some(extent) = pending.take() {
        match state
            .send_extent(extent.clone())
            .map_err(|error| error.to_string())?
        {
            StreamAction::Send(frame) => {
                attempt
                    .send_data(&encoded(frame)?)
                    .await
                    .map_err(|error| failure("send data", format!("{error:?}")))?;
                pending = source.next_extent()?;
            }
            StreamAction::Retry(_) => {
                let checkpoint = attempt
                    .receive_control()
                    .await
                    .map_err(|error| failure("receive checkpoint", format!("{error:?}")))?
                    .ok_or("control stream closed before checkpoint")?;
                let StreamFrame::Checkpoint(checkpoint) = decoded(&checkpoint)? else {
                    return Err("credit wait received a non-checkpoint frame".into());
                };
                state
                    .checkpoint(checkpoint)
                    .map_err(|error| error.to_string())?;
                checkpoints += 1;
                pending = Some(extent);
            }
            _ => return Err("sender produced an invalid data action".into()),
        }
    }
    let checkpoint = attempt
        .receive_control()
        .await
        .map_err(|error| failure("receive final checkpoint", format!("{error:?}")))?
        .ok_or("control stream closed before final checkpoint")?;
    let StreamFrame::Checkpoint(checkpoint) = decoded(&checkpoint)? else {
        return Err("final control frame was not checkpoint".into());
    };
    state
        .checkpoint(checkpoint)
        .map_err(|error| error.to_string())?;
    checkpoints += 1;
    let StreamAction::Send(finish) = state.finish().map_err(|error| error.to_string())? else {
        return Err("sender did not produce finish".into());
    };
    attempt
        .send_data(&encoded(finish)?)
        .await
        .map_err(|error| failure("send finish", format!("{error:?}")))?;
    let result = attempt
        .receive_control()
        .await
        .map_err(|error| failure("receive result", format!("{error:?}")))?
        .ok_or("control stream closed before result")?;
    let StreamFrame::Result(result) = decoded(&result)? else {
        return Err("terminal control frame was not result".into());
    };
    if result.code != StreamResultCode::Promoted
        || result.result_digest != result_digest(open, roots)
    {
        return Err("receiver result did not bind the expected Blob roots".into());
    }
    let (StreamAction::Send(ack), StreamAction::Terminal(StreamResultCode::Promoted)) =
        state.result(result).map_err(|error| error.to_string())?
    else {
        return Err("sender settlement action differed".into());
    };
    attempt
        .send_data(&encoded(ack)?)
        .await
        .map_err(|error| failure("send result acknowledgement", format!("{error:?}")))?;
    attempt
        .finish_data()
        .await
        .map_err(|error| failure("finish data stream", format!("{error:?}")))?;
    if attempt
        .receive_control()
        .await
        .map_err(|error| failure("receive control EOF", format!("{error:?}")))?
        .is_some()
    {
        return Err("control stream contained data after terminal result".into());
    }
    Ok(BlobNetworkReport {
        wire_bytes: wire_len,
        roots,
        checkpoints,
        pipeline: None,
    })
}

struct RecordParser {
    buffer: Vec<u8>,
    next_index: u64,
    consumed: u64,
}

impl RecordParser {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            next_index: 0,
            consumed: 0,
        }
    }

    async fn push(
        &mut self,
        bytes: &[u8],
        sender: &mpsc::Sender<Result<StreamPartition, PipelineError>>,
    ) -> Result<(), String> {
        self.buffer.extend_from_slice(bytes);
        loop {
            if self.buffer.len() < 4 {
                return Ok(());
            }
            let len =
                u32::from_be_bytes(self.buffer[..4].try_into().expect("record length")) as usize;
            if len == 0 || len > MAX_RECORD_BYTES {
                return Err("Blob network record length is out of bounds".into());
            }
            let record_len = 4usize.checked_add(len).ok_or("record length overflow")?;
            if self.buffer.len() < record_len {
                return Ok(());
            }
            let wire_end = self
                .consumed
                .checked_add(record_len as u64)
                .ok_or("wire offset overflow")?;
            let mut partition = Vec::with_capacity(8 + len);
            partition.extend_from_slice(&wire_end.to_be_bytes());
            partition.extend_from_slice(&self.buffer[4..record_len]);
            sender
                .send(Ok(StreamPartition::new(self.next_index, partition)))
                .await
                .map_err(|_| "verification pipeline closed")?;
            self.buffer.drain(..record_len);
            self.next_index += 1;
            self.consumed = wire_end;
        }
    }

    fn finish(&self, expected: u64) -> Result<(), String> {
        if self.buffer.is_empty() && self.consumed == expected {
            Ok(())
        } else {
            Err("network stream ended with an incomplete Blob record".into())
        }
    }
}

#[derive(Clone, Copy)]
struct DurableProgress {
    wire_offset: u64,
    generation: u64,
}

async fn send_durable_checkpoint(
    attempt: &std::sync::Arc<dyn crate::stream_transport::StreamReceiveAttempt>,
    state: &mut StreamReceiverState,
    progress: DurableProgress,
    wire_len: u64,
    current_limit: &mut u64,
) -> Result<(), String> {
    let window = u64::from(MAX_STREAM_CHECKPOINT_BATCH_BYTES) + MAX_RECORD_BYTES as u64;
    let new_limit = wire_len.min((*current_limit).max(progress.wire_offset.saturating_add(window)));
    let StreamAction::Send(checkpoint) = state
        .persisted(progress.wire_offset, progress.generation, new_limit)
        .map_err(|error| error.to_string())?
    else {
        return Err("receiver did not produce checkpoint".into());
    };
    attempt
        .send_control(&encoded(checkpoint)?)
        .await
        .map_err(|error| failure("send checkpoint", format!("{error:?}")))?;
    *current_limit = new_limit;
    Ok(())
}

pub async fn receive_completed_pack(
    connection: Connection,
    open: &BlobStreamOpen,
    opener: BlobStreamSegmentOpener,
    root: &Path,
    wire_len: u64,
    limits: PipelineLimits,
) -> Result<BlobNetworkReport, String> {
    let (max_data_bytes, max_control_bytes) = attempt_bounds(wire_len)?;
    let attempt = IrohQuicV1Adapter::new(connection)
        .accept_attempt(AttemptOpenRequest {
            deadline: Instant::now() + ATTEMPT_TIMEOUT,
            max_data_bytes,
            max_control_bytes,
        })
        .await
        .map_err(|error| failure("accept transport attempt", format!("{error:?}")))?;
    let frame = attempt
        .receive_data()
        .await
        .map_err(|error| failure("receive open", format!("{error:?}")))?
        .ok_or("data stream closed before open")?;
    let StreamFrame::Open(transfer_open) = decoded(&frame)? else {
        return Err("first data frame was not open".into());
    };
    if transfer_open.class != StreamClass::Blob
        || transfer_open.total_len != wire_len
        || transfer_open.session_transcript != open.digest()
        || transfer_open.publication_id != *open.stream_id().as_bytes()
    {
        return Err("transport open differs from authenticated Blob open".into());
    }
    let window = u64::from(MAX_STREAM_CHECKPOINT_BATCH_BYTES) + MAX_RECORD_BYTES as u64;
    let mut current_limit = wire_len.min(window);
    let mut state =
        StreamReceiverState::new(&transfer_open, 0, 0, current_limit, EXTENT_BYTES as u32)
            .map_err(|error| error.to_string())?;
    let StreamAction::Send(accept) = state
        .accept(MAX_STREAM_CHECKPOINT_BATCH_BYTES)
        .map_err(|error| error.to_string())?
    else {
        return Err("receiver did not produce accept".into());
    };
    attempt
        .send_control(&encoded(accept)?)
        .await
        .map_err(|error| failure("send accept", format!("{error:?}")))?;

    let (partition_tx, partition_rx) = mpsc::channel(limits.max_in_flight_items());
    let (durable_tx, mut durable_rx) = mpsc::unbounded_channel();
    let total_plaintext = open.total_len();
    let stream_job = StreamJobId::from_bytes(
        open.stream_id().as_bytes()[..16]
            .try_into()
            .expect("job ID"),
    );
    let root = root.to_owned();
    let open_owned = open.clone();
    let pipeline_task = tokio::spawn(async move {
        let mut writer = BlobPackWriter::create(&root, &open_owned)
            .map_err(|error| PipelineError::SinkFailed(error.to_string()))?;
        let mut last_checkpoint_wire = 0_u64;
        let report = run_ordered_channel_pipeline(
            stream_job,
            partition_rx,
            limits,
            move |partition| {
                let index = partition.index();
                let bytes = partition.into_bytes();
                let wire_end = u64::from_be_bytes(
                    bytes[..8]
                        .try_into()
                        .map_err(|_| PipelineError::MapFailed("missing wire offset".into()))?,
                );
                let segment = EncryptedBlobStreamSegment::decode(&bytes[8..])
                    .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
                if segment.index() != index {
                    return Err(PipelineError::MapFailed("segment index differs".into()));
                }
                let (_, leaves) = opener
                    .open(&segment)
                    .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
                Ok((segment, leaves, wire_end))
            },
            |mapped: MappedPartition<_>| {
                let (segment, leaves, wire_end) = mapped.into_value();
                let plaintext_end = segment.offset() + u64::from(segment.plaintext_len());
                let result = writer
                    .append(&segment, leaves)
                    .map_err(|error| PipelineError::SinkFailed(error.to_string()))
                    .and_then(|()| {
                        if wire_end - last_checkpoint_wire
                            >= u64::from(MAX_STREAM_CHECKPOINT_BATCH_BYTES)
                            || plaintext_end == total_plaintext
                        {
                            let checkpoint = writer
                                .checkpoint()
                                .map_err(|error| PipelineError::SinkFailed(error.to_string()))?;
                            durable_tx
                                .send(DurableProgress {
                                    wire_offset: wire_end,
                                    generation: checkpoint.generation(),
                                })
                                .map_err(|_| {
                                    PipelineError::SinkFailed("checkpoint consumer closed".into())
                                })?;
                            last_checkpoint_wire = wire_end;
                        }
                        Ok(())
                    });
                std::future::ready(result)
            },
        )
        .await?;
        let roots = writer
            .finish()
            .map_err(|error| PipelineError::SinkFailed(error.to_string()))?;
        Ok::<_, PipelineError>((report, roots))
    });

    let mut parser = RecordParser::new();
    let mut received = 0_u64;
    let mut durable_wire = 0_u64;
    let mut checkpoints = 0_u64;
    while received < wire_len {
        let frame = attempt
            .receive_data()
            .await
            .map_err(|error| failure("receive data", format!("{error:?}")))?
            .ok_or("data stream closed before completion")?;
        let StreamFrame::Data(data) = decoded(&frame)? else {
            return Err("non-data frame before complete payload".into());
        };
        let StreamAction::Persist { through } = state
            .data(data.clone())
            .map_err(|error| error.to_string())?
        else {
            return Err("receiver did not accept new data".into());
        };
        parser.push(&data.bytes, &partition_tx).await?;
        received = through;
        if parser.consumed - durable_wire >= u64::from(MAX_STREAM_CHECKPOINT_BATCH_BYTES)
            || parser.consumed == wire_len
        {
            let progress = durable_rx
                .recv()
                .await
                .ok_or("verification pipeline closed before checkpoint")?;
            send_durable_checkpoint(&attempt, &mut state, progress, wire_len, &mut current_limit)
                .await?;
            durable_wire = progress.wire_offset;
            checkpoints += 1;
        }
    }
    parser.finish(wire_len)?;
    drop(partition_tx);
    let (pipeline, roots) = pipeline_task
        .await
        .map_err(|error| failure("verification pipeline task", error))?
        .map_err(|error| failure("verification pipeline", error))?;
    let finish = attempt
        .receive_data()
        .await
        .map_err(|error| failure("receive finish", format!("{error:?}")))?
        .ok_or("data stream closed before finish")?;
    let StreamFrame::Finish(finish) = decoded(&finish)? else {
        return Err("terminal data frame was not finish".into());
    };
    let StreamAction::Promote = state.finish(finish).map_err(|error| error.to_string())? else {
        return Err("receiver did not reach promotion".into());
    };
    let digest = result_digest(open, roots);
    let StreamAction::Send(result) = state
        .promoted(StreamResultCode::Promoted, digest)
        .map_err(|error| error.to_string())?
    else {
        return Err("receiver did not produce result".into());
    };
    attempt
        .send_control(&encoded(result)?)
        .await
        .map_err(|error| failure("send result", format!("{error:?}")))?;
    let ack = attempt
        .receive_data()
        .await
        .map_err(|error| failure("receive result acknowledgement", format!("{error:?}")))?
        .ok_or("data stream closed before result acknowledgement")?;
    let StreamFrame::ResultAck(ack) = decoded(&ack)? else {
        return Err("settlement frame was not result acknowledgement".into());
    };
    let StreamAction::Terminal(StreamResultCode::Promoted) = state
        .result_ack(ack, StreamResultCode::Promoted)
        .map_err(|error| error.to_string())?
    else {
        return Err("receiver settlement action differed".into());
    };
    attempt
        .finish_control()
        .await
        .map_err(|error| failure("finish control stream", format!("{error:?}")))?;
    Ok(BlobNetworkReport {
        wire_bytes: wire_len,
        roots,
        checkpoints,
        pipeline: Some(pipeline),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{application::blob_stream::publish_blob_stream, stream_pipeline::PipelineLimits};
    use aster_iroh::{CarrierSecurityProfile, Endpoint, EndpointConfig, ExpectedPeer, SecretKey};
    use aster_mesh::{
        BLOB_STREAM_SEGMENT_BYTES, BlobMetadata, BlobPublicationStreamId, BlobStreamOpen,
        BlobStreamSegmentOpener, BlobStreamSegmentSealer, Priority, Scope, Topic, VersionVector,
    };
    use std::{
        collections::BTreeSet,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(std::path::PathBuf);
    impl TempRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "aster-network-stream-{label}-{}-{}-{}",
                std::process::id(),
                TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("clock")
                    .as_nanos()
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

    fn open(total_len: u64) -> BlobStreamOpen {
        BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([0x12; 32]).expect("stream"),
            [0x22; 32],
            b"network-pipeline".to_vec(),
            [0x32; 32],
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
            [0x42; 32],
            [0x52; 32],
        )
        .expect("open")
    }

    #[tokio::test]
    async fn completed_pack_crosses_v9_as_verified_checkpointed_segments() {
        let source_root = TempRoot::new("source");
        let receiver_root = TempRoot::new("receiver");
        let total_len = 10 * BLOB_STREAM_SEGMENT_BYTES + 17;
        let plaintext = (0..total_len)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let open = open(total_len as u64);
        let key = [0x62; 32];
        let nonce = [0x72; 12];
        let limits = PipelineLimits::new(4, 4, 5 * 1024 * 1024, 4).expect("limits");
        let published = publish_blob_stream(
            std::io::Cursor::new(plaintext),
            &open,
            BlobStreamSegmentSealer::from_test_key(
                *open.stream_id().as_bytes(),
                open.digest(),
                open.content_epoch(),
                key,
                nonce,
            ),
            &source_root.0,
            limits,
        )
        .await
        .expect("publish");
        let roots = (published.plaintext_root, published.ciphertext_root);
        let wire_len = completed_pack_wire_len(&source_root.0, &open).expect("wire length");
        assert_eq!(
            wire_len,
            expected_pack_wire_len(total_len as u64).expect("expected wire length")
        );

        let config = EndpointConfig::direct("127.0.0.1:0".parse().expect("address"));
        let server = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("server");
        let client = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .expect("client");
        let address = server
            .bound_sockets()
            .into_iter()
            .find(std::net::SocketAddr::is_ipv4)
            .expect("IPv4 address");
        let receiver = tokio::spawn({
            let server = server.clone();
            let allowed = BTreeSet::from([client.id()]);
            let open = open.clone();
            let root = receiver_root.0.clone();
            async move {
                let connection = server.accept(&allowed).await.expect("accept");
                receive_completed_pack(
                    connection,
                    &open,
                    BlobStreamSegmentOpener::from_test_key(
                        *open.stream_id().as_bytes(),
                        open.digest(),
                        open.content_epoch(),
                        key,
                        nonce,
                    ),
                    &root,
                    wire_len,
                    limits,
                )
                .await
                .expect("receive")
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address,
            })
            .await
            .expect("connect");
        let sent = send_completed_pack(connection, &open, &source_root.0, roots)
            .await
            .expect("send");
        let received = receiver.await.expect("receiver task");

        assert_eq!(sent.roots, roots);
        assert_eq!(received.roots, roots);
        assert_eq!(sent.wire_bytes, wire_len);
        assert_eq!(received.wire_bytes, wire_len);
        assert!(received.checkpoints >= 2);
        assert_eq!(
            received
                .pipeline
                .as_ref()
                .expect("receiver pipeline")
                .completed_items(),
            published.segment_count
        );
        client.close().await;
        server.close().await;
    }
}
