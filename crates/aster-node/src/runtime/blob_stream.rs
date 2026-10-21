//! Profile-5 Blob network DAG composition.

use crate::{
    event_pages::TransferProfileId,
    frame::EventDirection,
    mission::MissionSession,
    stream_pipeline::{
        MappedPartition, PipelineError, PipelineLimits, PipelineReport, StreamJobId,
        StreamPartition, run_ordered_channel_pipeline_from,
    },
    stream_transfer::{
        CanonicalBlobExtentV1, MAX_STREAM_CHECKPOINT_BATCH_BYTES, PROFILE5_ATTEMPT_TIMEOUT,
        PROFILE5_CANONICAL_EXTENT_BYTES, PROFILE5_EXTENT_BYTES, PROFILE5_IDLE_TIMEOUT,
        PROFILE5_MAX_RECORD_BYTES, StreamAction, StreamClass, StreamDirection, StreamExtentAction,
        StreamFrame, StreamOpenV1, StreamReceiverState, StreamResultCode, StreamSenderState,
        blob_pack_wire_len, encode_composite_data_prefix, profile5_attempt_bounds,
        profile5_attempt_hard_timeout, profile5_receive_limit, split_composite_data_record,
    },
    stream_transport::{
        AttemptOpenRequest, AuthenticatedPeerSupport, AuthenticatedSupportSource,
        IrohQuicV1Adapter, StreamAttempt, StreamReceiveAttempt, StreamTransportAdapter,
        StreamTransportId, TransferRequirements, TransportAdapterCandidate, TransportCandidate,
        TransportSelector,
    },
};
use aster_iroh::Connection;
use aster_mesh::{
    BlobStreamOpen, BlobStreamSegmentOpener, NodeId, VerifiedBlobStreamFinalCommitment,
    VerifiedBlobStreamOpen, VerifiedBlobTransferPlan,
};
use aster_redb_store::{
    BlobDepotCompletion, BlobOperationKey, BlobSourceRetention, BlobStreamReservation,
    BlobStreamReservationRequest, BlobStreamResume, BlobStreamSource, BlobTransferId,
    ControlPolicySnapshot, Store, StoredBlob,
    pack::{BlobPackCheckpoint, BlobPackReader, BlobPackWriter, PinnedBlobPackRoot},
};
use sha2::{Digest, Sha256};
use std::{future::Future, path::Path, sync::Arc};
use tokio::{sync::mpsc, time::Instant};

/// Capability-bearing canonical send input. Construction requires the
/// source/content-verified transfer plan and the Store's nonconstructible
/// completion proof; a raw `Store + BlobTransferId` is intentionally
/// insufficient.
pub(crate) struct CanonicalBlobSendSource {
    stored: StoredBlob,
    plan: VerifiedBlobTransferPlan,
    completion: BlobDepotCompletion,
}

impl CanonicalBlobSendSource {
    pub(crate) fn new(
        stored: StoredBlob,
        plan: VerifiedBlobTransferPlan,
        completion: BlobDepotCompletion,
    ) -> Result<Self, BlobNetworkError> {
        if *stored.transfer_id.as_bytes() != plan.source_envelope().into_bytes()
            || stored.blob_id != plan.manifest().id()
            || stored.manifest_digest != *plan.manifest_digest()
            || stored.variant_id != completion.variant_id()
            || stored.blob_id != completion.blob_id()
            || stored.manifest_digest != *completion.manifest_digest()
            || stored.header.key_epoch != completion.content_epoch()
            || stored.header.content_len
                != u64::try_from(plan.manifest_bytes().len()).unwrap_or(u64::MAX)
            || completion.total_len() != plan.manifest().total_len()
            || completion.chunk_size() != plan.manifest().chunk_size()
            || completion.chunk_count() != plan.manifest().chunk_count()
            || plan.physical_lineage().binding() != completion.physical_lineage()
        {
            return Err(authentication_failure(
                "bind canonical Blob send source",
                "verified source, manifest, and depot completion differ",
            ));
        }
        Ok(Self {
            stored,
            plan,
            completion,
        })
    }

    pub(crate) const fn publication(&self) -> BlobTransferId {
        self.stored.transfer_id
    }

    pub(crate) fn authenticated_open(&self) -> &[u8] {
        &self.stored.sealed
    }
}

fn canonical_extent_shape(
    plan: &VerifiedBlobTransferPlan,
    first_chunk_index: u64,
) -> Result<(u64, u64), BlobNetworkError> {
    if first_chunk_index >= plan.manifest().chunk_count() {
        return Err("canonical extent starts outside the manifest".into());
    }
    let mut encoded_len = crate::stream_transfer::CANONICAL_BLOB_EXTENT_HEADER_BYTES as u64;
    let mut count = 0_u64;
    for index in first_chunk_index..plan.manifest().chunk_count() {
        let carrier = plan
            .carrier_id(index)
            .map_err(|error| verification_failure("derive canonical carrier ID", error))?;
        let carrier_len = plan
            .carrier_total_len(&carrier.wire_bytes())
            .map_err(|error| verification_failure("derive canonical carrier length", error))?;
        let next = encoded_len
            .checked_add(4)
            .and_then(|value| value.checked_add(carrier_len))
            .ok_or("canonical extent length overflow")?;
        if next > PROFILE5_CANONICAL_EXTENT_BYTES as u64 {
            if count == 0 {
                return Err("one canonical carrier exceeds the profile-5 extent bound".into());
            }
            break;
        }
        encoded_len = next;
        count += 1;
    }
    Ok((count, encoded_len))
}

fn canonical_blob_wire_len(plan: &VerifiedBlobTransferPlan) -> Result<u64, BlobNetworkError> {
    let mut index = 0_u64;
    let mut total = 0_u64;
    while index < plan.manifest().chunk_count() {
        let (count, extent_len) = canonical_extent_shape(plan, index)?;
        index = index
            .checked_add(count)
            .ok_or("canonical Blob chunk index overflow")?;
        total = total
            .checked_add(extent_len)
            .ok_or("canonical Blob wire length overflow")?;
    }
    Ok(total)
}

struct CanonicalCarrierExtentSource<'a> {
    store: &'a Store,
    source: &'a CanonicalBlobSendSource,
    plan: &'a VerifiedBlobTransferPlan,
    next_chunk_index: u64,
    wire_offset: u64,
}

impl<'a> CanonicalCarrierExtentSource<'a> {
    fn new_at(
        store: &'a Store,
        source: &'a CanonicalBlobSendSource,
        wire_offset: u64,
    ) -> Result<Self, BlobNetworkError> {
        let mut next_chunk_index = 0_u64;
        let mut consumed = 0_u64;
        while consumed < wire_offset {
            let (count, extent_len) = canonical_extent_shape(&source.plan, next_chunk_index)?;
            consumed = consumed
                .checked_add(extent_len)
                .ok_or("canonical Blob resume offset overflow")?;
            next_chunk_index = next_chunk_index
                .checked_add(count)
                .ok_or("canonical Blob resume index overflow")?;
        }
        if consumed != wire_offset {
            return Err("profile-5 resume offset is not a canonical extent boundary".into());
        }
        Ok(Self {
            store,
            source,
            plan: &source.plan,
            next_chunk_index,
            wire_offset,
        })
    }

    fn next_extent(&mut self) -> Result<Option<Vec<u8>>, BlobNetworkError> {
        if self.next_chunk_index == self.plan.manifest().chunk_count() {
            return Ok(None);
        }
        let first_chunk_index = self.next_chunk_index;
        let (count, expected_len) = canonical_extent_shape(self.plan, first_chunk_index)?;
        let mut carriers = Vec::with_capacity(
            usize::try_from(count).map_err(|_| "canonical carrier count overflows")?,
        );
        {
            // The depot lock never crosses a transport await. Each extent is
            // built and rechecked synchronously, then the capability-gated
            // read adapter is dropped before backpressure can suspend us.
            let mut depot = self
                .store
                .blob_depot_for_authenticated_read(&self.source.completion)
                .map_err(|error| durability_failure("open canonical Blob depot", error))?;
            for index in first_chunk_index..first_chunk_index + count {
                carriers.push(
                    self.plan
                        .build_carrier(&mut depot, index)
                        .map_err(|error| verification_failure("build canonical carrier", error))?
                        .into_bytes(),
                );
            }
        }
        let encoded = CanonicalBlobExtentV1 {
            first_chunk_index,
            carriers,
        }
        .encode()
        .map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "encode canonical extent", error)
        })?;
        if encoded.len() as u64 != expected_len {
            return Err("canonical extent differs from its preflight length".into());
        }
        self.next_chunk_index += count;
        self.wire_offset = self
            .wire_offset
            .checked_add(expected_len)
            .ok_or("canonical wire offset overflow")?;
        Ok(Some(encoded))
    }
}

#[cfg(test)]
static ACTIVE_RECEIVE_PIPELINES: std::sync::Mutex<Vec<StreamJobId>> =
    std::sync::Mutex::new(Vec::new());

#[cfg(test)]
struct ReceivePipelineGuard {
    job: StreamJobId,
}

#[cfg(test)]
impl ReceivePipelineGuard {
    fn enter(job: StreamJobId) -> Self {
        ACTIVE_RECEIVE_PIPELINES.lock().unwrap().push(job);
        Self { job }
    }
}

#[cfg(test)]
impl Drop for ReceivePipelineGuard {
    fn drop(&mut self) {
        let mut active = ACTIVE_RECEIVE_PIPELINES.lock().unwrap();
        let index = active
            .iter()
            .position(|job| *job == self.job)
            .expect("receive pipeline guard was registered");
        active.swap_remove(index);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobNetworkStage {
    Framing,
    Authentication,
    Transport,
    Protocol,
    Verification,
    Durability,
    Lifecycle,
    Settlement,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobNetworkError {
    stage: BlobNetworkStage,
    context: String,
    detail: String,
}

impl BlobNetworkError {
    fn new(
        stage: BlobNetworkStage,
        context: impl Into<String>,
        detail: impl std::fmt::Display,
    ) -> Self {
        Self {
            stage,
            context: context.into(),
            detail: detail.to_string(),
        }
    }

    pub const fn stage(&self) -> BlobNetworkStage {
        self.stage
    }

    pub const fn public_message(&self) -> &'static str {
        match self.stage {
            BlobNetworkStage::Framing => "profile-5 Blob framing failed",
            BlobNetworkStage::Authentication => "profile-5 Blob authentication failed",
            BlobNetworkStage::Transport => "profile-5 Blob transport failed",
            BlobNetworkStage::Protocol => "profile-5 Blob protocol failed",
            BlobNetworkStage::Verification => "profile-5 Blob verification failed",
            BlobNetworkStage::Durability => "profile-5 Blob durability failed",
            BlobNetworkStage::Lifecycle => "profile-5 Blob lifecycle failed",
            BlobNetworkStage::Settlement => "profile-5 Blob settlement failed",
        }
    }
}

impl From<&'static str> for BlobNetworkError {
    fn from(detail: &'static str) -> Self {
        Self::new(
            BlobNetworkStage::Protocol,
            "profile-5 Blob protocol",
            detail,
        )
    }
}

impl From<String> for BlobNetworkError {
    fn from(detail: String) -> Self {
        Self::new(
            BlobNetworkStage::Protocol,
            "profile-5 Blob protocol",
            detail,
        )
    }
}

impl std::fmt::Display for BlobNetworkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.context, self.detail)
    }
}

impl std::error::Error for BlobNetworkError {}

async fn await_authenticated_progress<T>(
    context: &'static str,
    future: impl Future<Output = Result<T, crate::stream_transport::StreamTransportError>>,
) -> Result<T, BlobNetworkError> {
    tokio::time::timeout(PROFILE5_IDLE_TIMEOUT, future)
        .await
        .map_err(|_| transport_failure(context, "authenticated progress idle timeout"))?
        .map_err(|error| transport_failure(context, format!("{error:?}")))
}

#[derive(Debug)]
pub struct BlobNetworkReport {
    pub wire_bytes: u64,
    pub resumed_from: u64,
    pub attempt_bytes: u64,
    pub roots: ([u8; 32], [u8; 32]),
    pub checkpoints: u64,
    pub pipeline: Option<PipelineReport>,
}

pub type BlobCommitmentVerifier = Arc<
    dyn Fn(&VerifiedBlobStreamOpen, &[u8]) -> Result<VerifiedBlobStreamFinalCommitment, String>
        + Send
        + Sync,
>;

pub struct BlobReceiveStoreSession {
    store: Arc<Store>,
    policy: ControlPolicySnapshot,
    open: VerifiedBlobStreamOpen,
    authenticated_open: Vec<u8>,
    operation: BlobOperationKey,
    source: BlobStreamSource,
    verify_commitment: BlobCommitmentVerifier,
}

impl BlobReceiveStoreSession {
    pub fn new(
        store: Arc<Store>,
        policy: ControlPolicySnapshot,
        open: VerifiedBlobStreamOpen,
        authenticated_open: Vec<u8>,
        peer: NodeId,
        verify_commitment: BlobCommitmentVerifier,
    ) -> Result<Self, BlobNetworkError> {
        let operation = BlobOperationKey::new(open.open().operation_key().to_vec())
            .map_err(|error| failure("stream operation", error))?;
        Ok(Self {
            store,
            policy,
            open,
            authenticated_open,
            operation,
            source: BlobStreamSource::AuthenticatedPeer(peer),
            verify_commitment,
        })
    }

    fn reserve(&self) -> Result<(BlobStreamReservation, BlobStreamResume), BlobNetworkError> {
        self.store
            .reserve_blob_stream_with_policy(
                &self.policy,
                BlobStreamReservationRequest {
                    operation: &self.operation,
                    source: self.source,
                },
                &self.open,
            )
            .map_err(|error| lifecycle_failure("reserve stream", error))
    }
}

fn failure(context: impl Into<String>, error: impl std::fmt::Display) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Protocol, context, error)
}

fn authentication_failure(
    context: impl Into<String>,
    error: impl std::fmt::Display,
) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Authentication, context, error)
}

fn transport_failure(
    context: impl Into<String>,
    error: impl std::fmt::Display,
) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Transport, context, error)
}

fn verification_failure(
    context: impl Into<String>,
    error: impl std::fmt::Display,
) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Verification, context, error)
}

fn durability_failure(
    context: impl Into<String>,
    error: impl std::fmt::Display,
) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Durability, context, error)
}

fn lifecycle_failure(
    context: impl Into<String>,
    error: impl std::fmt::Display,
) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Lifecycle, context, error)
}

fn settlement_failure(
    context: impl Into<String>,
    error: impl std::fmt::Display,
) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Settlement, context, error)
}

pub(crate) fn select_stream_transport(
    connection: Connection,
) -> Result<Arc<dyn StreamTransportAdapter>, BlobNetworkError> {
    let adapter: Arc<dyn StreamTransportAdapter> = Arc::new(IrohQuicV1Adapter::new(connection));
    let candidates = [TransportAdapterCandidate {
        candidate: TransportCandidate {
            id: StreamTransportId::IrohQuicV1,
            locally_enabled: true,
            policy_allowed: true,
            peer_support: Some(AuthenticatedPeerSupport::new(
                AuthenticatedSupportSource::MissionSessionNegotiation,
                true,
            )),
            reliable_ordered: true,
            full_duplex: true,
            health: adapter.health(),
            configured_priority: 0,
        },
        adapter,
    }];
    TransportSelector::select_adapter(TransferRequirements::default(), &candidates).ok_or_else(
        || {
            transport_failure(
                "select stream transport",
                "no eligible transport is available",
            )
        },
    )
}

fn encoded(frame: StreamFrame) -> Result<Vec<u8>, BlobNetworkError> {
    frame.encode_for_context(9, 5).map_err(|error| {
        BlobNetworkError::new(BlobNetworkStage::Framing, "encode stream frame", error)
    })
}

fn decoded(bytes: &[u8]) -> Result<StreamFrame, BlobNetworkError> {
    StreamFrame::decode_for_context(9, 5, bytes).map_err(|error| {
        BlobNetworkError::new(BlobNetworkStage::Framing, "decode stream frame", error)
    })
}

trait BlobRecordCodec: Send {
    fn encode(&mut self, frame: StreamFrame) -> Result<Vec<u8>, BlobNetworkError>;
    fn encode_data_parts(
        &mut self,
        data: crate::stream_transfer::StreamDataV1,
    ) -> Result<(Vec<u8>, Vec<u8>), BlobNetworkError>;
    fn decode(&mut self, bytes: &[u8]) -> Result<StreamFrame, BlobNetworkError>;
}

struct PlainBlobRecordCodec;

impl BlobRecordCodec for PlainBlobRecordCodec {
    fn encode(&mut self, frame: StreamFrame) -> Result<Vec<u8>, BlobNetworkError> {
        if let StreamFrame::Data(data) = frame {
            let (mut header, body) = self.encode_data_parts(data)?;
            header.extend_from_slice(&body);
            return Ok(header);
        }
        encoded(frame)
    }

    fn encode_data_parts(
        &mut self,
        data: crate::stream_transfer::StreamDataV1,
    ) -> Result<(Vec<u8>, Vec<u8>), BlobNetworkError> {
        let (header, body) = data.into_header_and_body().map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "split data frame", error)
        })?;
        let encoded_header = header.encode_for_context(9, 5).map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "encode data header", error)
        })?;
        Ok((encoded_header, body))
    }

    fn decode(&mut self, bytes: &[u8]) -> Result<StreamFrame, BlobNetworkError> {
        decoded(bytes)
    }
}

struct MissionBlobRecordCodec<'a> {
    mission: &'a mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    attempt_nonce: [u8; 32],
}

fn stream_frame_name(frame: &StreamFrame) -> &'static str {
    match frame {
        StreamFrame::Open(_) => "open",
        StreamFrame::Source(_) => "source",
        StreamFrame::Accept(_) => "accept",
        StreamFrame::Data(_) => "data",
        StreamFrame::Checkpoint(_) => "checkpoint",
        StreamFrame::Finish(_) => "finish",
        StreamFrame::Result(_) => "result",
        StreamFrame::ResultAck(_) => "result acknowledgement",
    }
}

impl BlobRecordCodec for MissionBlobRecordCodec<'_> {
    fn encode(&mut self, frame: StreamFrame) -> Result<Vec<u8>, BlobNetworkError> {
        if let StreamFrame::Data(data) = frame {
            let (mut prefix, body) = self.encode_data_parts(data)?;
            prefix.extend_from_slice(&body);
            return Ok(prefix);
        }
        let frame_name = stream_frame_name(&frame);
        let plaintext = frame
            .encode_for_context(9, TransferProfileId::BlobStreamV1 as u16)
            .map_err(|error| {
                BlobNetworkError::new(BlobNetworkStage::Framing, "encode control frame", error)
            })?;
        self.mission
            .seal_v9_blob_application_frame(
                self.profile_digest,
                self.direction,
                self.attempt_nonce,
                &plaintext,
            )
            .map_err(|error| {
                authentication_failure(format!("seal {frame_name} mission record"), error)
            })
    }

    fn encode_data_parts(
        &mut self,
        data: crate::stream_transfer::StreamDataV1,
    ) -> Result<(Vec<u8>, Vec<u8>), BlobNetworkError> {
        let (header, body) = data.into_header_and_body().map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "split data frame", error)
        })?;
        let encoded_header = header
            .encode_for_context(9, TransferProfileId::BlobStreamV1 as u16)
            .map_err(|error| {
                BlobNetworkError::new(BlobNetworkStage::Framing, "encode data header", error)
            })?;
        let protected_header = self
            .mission
            .seal_v9_blob_data_header(
                self.profile_digest,
                self.direction,
                self.attempt_nonce,
                &encoded_header,
            )
            .map_err(|error| authentication_failure("seal data-header mission record", error))?;
        let prefix = encode_composite_data_prefix(&protected_header).map_err(|error| {
            BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "encode composite data prefix",
                error,
            )
        })?;
        Ok((prefix, body))
    }

    fn decode(&mut self, bytes: &[u8]) -> Result<StreamFrame, BlobNetworkError> {
        if bytes.starts_with(b"ASD1") {
            let (protected_header, body) = split_composite_data_record(bytes).map_err(|error| {
                BlobNetworkError::new(
                    BlobNetworkStage::Framing,
                    "split composite data record",
                    error,
                )
            })?;
            let header = self
                .mission
                .open_v9_blob_data_header(
                    self.profile_digest,
                    self.direction,
                    self.attempt_nonce,
                    protected_header,
                )
                .map_err(|error| {
                    authentication_failure("open data-header mission record", error)
                })?;
            return header
                .decode_body(body)
                .map(StreamFrame::Data)
                .map_err(|error| {
                    BlobNetworkError::new(
                        BlobNetworkStage::Framing,
                        "decode composite data body",
                        error,
                    )
                });
        }
        let plaintext = self
            .mission
            .open_v9_blob_application_frame(
                self.profile_digest,
                self.direction,
                self.attempt_nonce,
                bytes,
            )
            .map_err(|error| authentication_failure("open mission record", error))?;
        let frame =
            StreamFrame::decode_for_context(9, TransferProfileId::BlobStreamV1 as u16, &plaintext)
                .map_err(|error| {
                    BlobNetworkError::new(BlobNetworkStage::Framing, "decode control frame", error)
                })?;
        if matches!(frame, StreamFrame::Data(_)) {
            return Err("StreamData requires the profile-5 composite record".into());
        }
        Ok(frame)
    }
}

async fn send_authenticated_source(
    attempt: &dyn StreamAttempt,
    codec: &mut dyn BlobRecordCodec,
    open: &StreamOpenV1,
    source: &[u8],
) -> Result<(), BlobNetworkError> {
    if u32::try_from(source.len()).ok() != Some(open.source_len)
        || <[u8; 32]>::from(Sha256::digest(source)) != open.source_digest
    {
        return Err(authentication_failure(
            "bind authenticated source phase",
            "source length or digest differs from open",
        ));
    }
    for (sequence, chunk) in source
        .chunks(crate::stream_transfer::PROFILE5_SOURCE_CHUNK_BYTES)
        .enumerate()
    {
        let offset = sequence
            .checked_mul(crate::stream_transfer::PROFILE5_SOURCE_CHUNK_BYTES)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or("authenticated source offset overflows")?;
        let frame = StreamFrame::Source(crate::stream_transfer::StreamSourceV1 {
            transfer_id: open.transfer_id,
            attempt_nonce: open.attempt_nonce,
            sequence: u64::try_from(sequence)
                .map_err(|_| "authenticated source sequence overflows")?,
            offset,
            total_len: open.source_len,
            bytes: chunk.to_vec(),
        });
        await_authenticated_progress(
            "send authenticated source chunk",
            attempt.send_data(&codec.encode(frame)?),
        )
        .await?;
    }
    Ok(())
}

async fn receive_authenticated_source(
    attempt: &dyn StreamReceiveAttempt,
    codec: &mut dyn BlobRecordCodec,
    open: &StreamOpenV1,
) -> Result<Vec<u8>, BlobNetworkError> {
    let capacity =
        usize::try_from(open.source_len).map_err(|_| "authenticated source length overflows")?;
    if capacity == 0 || capacity > crate::stream_transfer::MAX_STREAM_AUTHENTICATED_OPEN_BYTES {
        return Err("authenticated source length is out of bounds".into());
    }
    let mut source = Vec::with_capacity(capacity);
    let mut sequence = 0_u64;
    while source.len() < capacity {
        let encoded = await_authenticated_progress(
            "receive authenticated source chunk",
            attempt.receive_data(),
        )
        .await?
        .ok_or("data stream closed during authenticated source")?;
        let StreamFrame::Source(chunk) = codec.decode(&encoded)? else {
            return Err("authenticated source phase received another frame kind".into());
        };
        if chunk.transfer_id != open.transfer_id
            || chunk.attempt_nonce != open.attempt_nonce
            || chunk.sequence != sequence
            || usize::try_from(chunk.offset).ok() != Some(source.len())
            || chunk.total_len != open.source_len
        {
            return Err(authentication_failure(
                "validate authenticated source chunk",
                "source order or attempt binding differs",
            ));
        }
        source.extend_from_slice(&chunk.bytes);
        sequence = sequence
            .checked_add(1)
            .ok_or("authenticated source sequence overflows")?;
    }
    if source.len() != capacity || <[u8; 32]>::from(Sha256::digest(&source)) != open.source_digest {
        return Err(authentication_failure(
            "validate authenticated source",
            "source length or digest differs from open",
        ));
    }
    Ok(source)
}

fn result_digest(open: &BlobStreamOpen, roots: ([u8; 32], [u8; 32])) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aster/blob-network-result/v1");
    hasher.update(open.digest());
    hasher.update(roots.0);
    hasher.update(roots.1);
    hasher.finalize().into()
}

async fn finish_receiver_attempt(
    attempt: Arc<dyn crate::stream_transport::StreamReceiveAttempt>,
) -> Result<(), BlobNetworkError> {
    if attempt
        .receive_data()
        .await
        .map_err(|error| transport_failure("receive data EOF", format!("{error:?}")))?
        .is_some()
    {
        return Err("data stream contained a frame after result acknowledgement".into());
    }
    attempt
        .finish_control()
        .await
        .map_err(|error| transport_failure("finish control stream", format!("{error:?}")))
}

pub(crate) fn completed_pack_wire_len(
    root: &Path,
    open: &BlobStreamOpen,
) -> Result<u64, BlobNetworkError> {
    let reader =
        BlobPackReader::open(root, open).map_err(|error| durability_failure("open pack", error))?;
    Ok(reader.checkpoint().payload_len())
}

#[allow(dead_code)] // The pinned receiver arm is reconnected by Task 5.
enum PackAccess<'a> {
    Path(&'a Path),
    Pinned(&'a PinnedBlobPackRoot),
}

impl PackAccess<'_> {
    fn reader(&self, open: &BlobStreamOpen) -> Result<BlobPackReader, BlobNetworkError> {
        match self {
            Self::Path(root) => BlobPackReader::open(root, open),
            Self::Pinned(root) => BlobPackReader::open_pinned(root, open),
        }
        .map_err(|error| durability_failure("open pack", error))
    }

    fn reader_at(
        &self,
        open: &BlobStreamOpen,
        next_index: u64,
        wire_offset: u64,
    ) -> Result<BlobPackReader, BlobNetworkError> {
        match self {
            Self::Path(root) => {
                BlobPackReader::open_at_payload_offset(root, open, next_index, wire_offset)
            }
            Self::Pinned(root) => {
                BlobPackReader::open_pinned_at_payload_offset(root, open, next_index, wire_offset)
            }
        }
        .map_err(|error| durability_failure("open resumed source pack", error))
    }

    fn projected_writer(
        &self,
        open: &BlobStreamOpen,
        resume: BlobStreamResume,
    ) -> Result<BlobPackWriter, BlobNetworkError> {
        match self {
            Self::Path(root) => BlobPackWriter::open_projected(
                root,
                open,
                resume.generation(),
                resume.next_segment_index(),
                resume.durable_plaintext_offset(),
                resume.durable_pack_len(),
                resume.durable_wire_offset(),
            ),
            Self::Pinned(root) => BlobPackWriter::open_projected_pinned(
                root,
                open,
                resume.generation(),
                resume.next_segment_index(),
                resume.durable_plaintext_offset(),
                resume.durable_pack_len(),
                resume.durable_wire_offset(),
            ),
        }
        .map_err(|error| durability_failure("open receiver pack", error))
    }
}

pub(crate) fn expected_pack_wire_len(plaintext_len: u64) -> Result<u64, BlobNetworkError> {
    blob_pack_wire_len(plaintext_len).map_err(|error| {
        BlobNetworkError::new(
            BlobNetworkStage::Framing,
            "calculate Blob pack wire length",
            error,
        )
    })
}

struct PackExtentSource {
    reader: BlobPackReader,
}

impl PackExtentSource {
    fn new(root: &PackAccess<'_>, open: &BlobStreamOpen) -> Result<Self, BlobNetworkError> {
        Ok(Self {
            reader: root.reader(open)?,
        })
    }

    fn new_at(
        root: &PackAccess<'_>,
        open: &BlobStreamOpen,
        wire_offset: u64,
    ) -> Result<Self, BlobNetworkError> {
        if wire_offset == 0 {
            return Self::new(root, open);
        }
        let full_record = 4_u64
            .checked_add(aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64)
            .and_then(|value| {
                value.checked_add(aster_mesh::BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES as u64)
            })
            .ok_or("Blob record length overflow")?;
        let full_segments = open.total_len() / aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64;
        let full_prefix = full_segments
            .checked_mul(full_record)
            .ok_or("Blob resume prefix overflow")?;
        let next_index = if wire_offset <= full_prefix && wire_offset.is_multiple_of(full_record) {
            wire_offset / full_record
        } else if wire_offset == expected_pack_wire_len(open.total_len())? {
            open.total_len()
                .div_ceil(aster_mesh::BLOB_STREAM_SEGMENT_BYTES as u64)
        } else {
            return Err(BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "resume source pack",
                "offset is not a canonical Blob record boundary",
            ));
        };
        Ok(Self {
            reader: root.reader_at(open, next_index, wire_offset)?,
        })
    }

    fn next_extent(&mut self) -> Result<Option<Vec<u8>>, BlobNetworkError> {
        self.reader
            .next_record()
            .map(|record| record.map(|record| record.into_bytes()))
            .map_err(|error| durability_failure("read source record", error))
    }
}

fn protocol_open(
    open: &BlobStreamOpen,
    authenticated_open: &[u8],
    wire_len: u64,
    attempt_nonce: [u8; 32],
    direction: StreamDirection,
) -> StreamOpenV1 {
    let source_len = u32::try_from(authenticated_open.len()).unwrap_or(u32::MAX);
    let source_digest = Sha256::digest(&authenticated_open).into();
    StreamOpenV1 {
        class: StreamClass::Blob,
        direction,
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
        source_len,
        source_digest,
    }
}

pub async fn send_completed_pack(
    connection: Connection,
    open: &BlobStreamOpen,
    authenticated_open: Vec<u8>,
    root: &Path,
    roots: ([u8; 32], [u8; 32]),
    semantic_commitment: Vec<u8>,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let mut codec = PlainBlobRecordCodec;
    let transport = select_stream_transport(connection)?;
    send_completed_pack_inner(
        transport.as_ref(),
        open,
        authenticated_open,
        PackAccess::Path(root),
        roots,
        semantic_commitment,
        None,
        StreamDirection::ToSessionResponder,
        &mut codec,
    )
    .await
}

fn canonical_result_digest(open: &StreamOpenV1, roots: ([u8; 32], [u8; 32])) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aster/canonical-blob-network-result/v1");
    hasher.update(open.source_transfer_id);
    hasher.update(open.publication_id);
    hasher.update(open.variant_id);
    hasher.update(open.total_len.to_be_bytes());
    hasher.update(roots.0);
    hasher.update(roots.1);
    hasher.finalize().into()
}

fn require_canonical_send_source(
    store: &Store,
    policy: &ControlPolicySnapshot,
    source: &CanonicalBlobSendSource,
) -> Result<(), BlobNetworkError> {
    let exact = store
        .get_blob(source.publication())
        .map_err(|error| lifecycle_failure("load canonical Blob source", error))?
        .ok_or_else(|| lifecycle_failure("load canonical Blob source", "publication is absent"))?;
    if exact != source.stored {
        return Err(authentication_failure(
            "recheck canonical Blob source",
            "source bytes or metadata changed",
        ));
    }
    let mut authorized = false;
    store
        .visit_retained_blob_sources(Some(policy), |retained| {
            if retained.source.transfer_id == source.publication()
                && matches!(
                    retained.retention,
                    BlobSourceRetention::Completed {
                        acceptance_marker
                    } if acceptance_marker == source.stored.acceptance_marker
                )
                && retained.source.blob_id == source.stored.blob_id
                && retained.source.manifest_digest == source.stored.manifest_digest
                && retained.source.total_len == source.plan.manifest().total_len()
                && retained.source.chunk_size == source.plan.manifest().chunk_size()
                && retained.source.chunk_count == source.plan.manifest().chunk_count()
            {
                authorized = true;
            }
        })
        .map_err(|error| lifecycle_failure("authorize canonical Blob source", error))?;
    if !authorized {
        return Err(lifecycle_failure(
            "authorize canonical Blob source",
            "publication is not current and lifecycle-visible",
        ));
    }
    Ok(())
}

/// Sends one already source/content-authenticated canonical publication.
///
/// The capability-bearing `source` is deliberately required in addition to
/// `Store + BlobTransferId`; callers cannot bypass source verification or the
/// completion-gated depot read API.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_canonical_blob_profile5(
    adapter: &dyn StreamTransportAdapter,
    store: &Store,
    policy: &ControlPolicySnapshot,
    source: &CanonicalBlobSendSource,
    session: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    attempt_nonce: [u8; 32],
) -> Result<BlobNetworkReport, BlobNetworkError> {
    require_canonical_send_source(store, policy, source)?;
    let wire_len = canonical_blob_wire_len(&source.plan)?;
    let (max_data_bytes, max_control_bytes) =
        profile5_attempt_bounds(wire_len).map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "bound canonical stream", error)
        })?;
    let attempt = await_authenticated_progress(
        "open canonical transport attempt",
        adapter.open_attempt(AttemptOpenRequest {
            deadline: Instant::now() + profile5_attempt_hard_timeout(wire_len),
            max_data_bytes,
            max_control_bytes,
        }),
    )
    .await?;
    let stream_direction = match direction {
        EventDirection::ToSessionInitiator => StreamDirection::ToSessionInitiator,
        EventDirection::ToSessionResponder => StreamDirection::ToSessionResponder,
    };
    let transfer_open = StreamOpenV1 {
        class: StreamClass::Blob,
        direction: stream_direction,
        session_transcript: session.session_id(),
        exchange_id: 1,
        transfer_id: *source.publication().as_bytes(),
        source_transfer_id: *source.publication().as_bytes(),
        publication_id: *source.stored.semantic_id.as_bytes(),
        variant_id: *source.stored.variant_id.as_bytes(),
        total_len: wire_len,
        attempt_nonce,
        checkpoint_generation: 0,
        custody_digest: None,
        source_len: u32::try_from(source.stored.sealed.len()).map_err(|_| {
            BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "bind canonical source",
                "authenticated source length overflows",
            )
        })?,
        source_digest: Sha256::digest(&source.stored.sealed).into(),
    };
    let mut codec = MissionBlobRecordCodec {
        mission: session,
        profile_digest,
        direction,
        attempt_nonce,
    };
    await_authenticated_progress(
        "send canonical open",
        attempt.send_data(&codec.encode(StreamFrame::Open(transfer_open.clone()))?),
    )
    .await?;
    send_authenticated_source(
        attempt.as_ref(),
        &mut codec,
        &transfer_open,
        &source.stored.sealed,
    )
    .await?;
    let accept =
        await_authenticated_progress("receive canonical accept", attempt.receive_control())
            .await?
            .ok_or("control stream closed before canonical accept")?;
    let StreamFrame::Accept(accept) = codec.decode(&accept)? else {
        return Err("first canonical control frame was not accept".into());
    };
    let resume_offset = accept.durable_offset;
    let mut state = StreamSenderState::new(transfer_open.transfer_id, attempt_nonce, wire_len);
    state
        .accept(accept)
        .map_err(|error| failure("accept canonical stream", error))?;
    let mut extent_source = CanonicalCarrierExtentSource::new_at(store, source, resume_offset)?;
    let mut pending = extent_source.next_extent()?;
    let mut checkpoints = 0_u64;
    while let Some(extent) = pending.take() {
        match state
            .send_extent(extent)
            .map_err(|error| failure("advance canonical sender extent", error))?
        {
            StreamExtentAction::Send(data) => {
                let (prefix, body) = codec.encode_data_parts(data)?;
                await_authenticated_progress(
                    "send canonical data",
                    attempt.send_data_parts(&prefix, &body),
                )
                .await?;
                pending = extent_source.next_extent()?;
            }
            StreamExtentAction::Retry {
                reason: crate::stream_transfer::StreamRetry::CreditBlocked,
                bytes,
            } => {
                let checkpoint = await_authenticated_progress(
                    "receive canonical checkpoint",
                    attempt.receive_control(),
                )
                .await?
                .ok_or("control stream closed before canonical checkpoint")?;
                let StreamFrame::Checkpoint(checkpoint) = codec.decode(&checkpoint)? else {
                    return Err("canonical credit wait received a non-checkpoint frame".into());
                };
                state
                    .checkpoint(checkpoint)
                    .map_err(|error| failure("advance canonical checkpoint", error))?;
                checkpoints += 1;
                pending = Some(bytes);
            }
            StreamExtentAction::Retry { .. } => {
                return Err("canonical sender produced an invalid extent retry".into());
            }
        }
    }
    if wire_len != 0 {
        let checkpoint = await_authenticated_progress(
            "receive final canonical checkpoint",
            attempt.receive_control(),
        )
        .await?
        .ok_or("control stream closed before final canonical checkpoint")?;
        let StreamFrame::Checkpoint(checkpoint) = codec.decode(&checkpoint)? else {
            return Err("final canonical control frame was not checkpoint".into());
        };
        state
            .checkpoint(checkpoint)
            .map_err(|error| failure("advance final canonical checkpoint", error))?;
        checkpoints += 1;
    }
    let StreamAction::Send(finish) = state
        .finish(source.stored.manifest_digest.to_vec())
        .map_err(|error| failure("finish canonical sender state", error))?
    else {
        return Err("canonical sender did not produce finish".into());
    };
    await_authenticated_progress(
        "send canonical finish",
        attempt.send_data(&codec.encode(finish)?),
    )
    .await?;
    let result =
        await_authenticated_progress("receive canonical result", attempt.receive_control())
            .await?
            .ok_or("control stream closed before canonical result")?;
    let StreamFrame::Result(result) = codec.decode(&result)? else {
        return Err("terminal canonical control frame was not result".into());
    };
    let roots = (
        *source.stored.blob_id.as_bytes(),
        source.stored.manifest_digest,
    );
    if !matches!(
        result.code,
        StreamResultCode::Promoted | StreamResultCode::AlreadyPresent
    ) || result.result_digest != canonical_result_digest(&transfer_open, roots)
    {
        return Err(settlement_failure(
            "validate canonical receiver result",
            "result did not bind the canonical Blob identity",
        ));
    }
    let expected_result = result.code;
    let (StreamAction::Send(ack), StreamAction::Terminal(settled)) = state
        .result(result)
        .map_err(|error| settlement_failure("settle canonical sender state", error))?
    else {
        return Err(settlement_failure(
            "settle canonical sender",
            "settlement action differed",
        ));
    };
    if settled != expected_result {
        return Err(settlement_failure(
            "settle canonical sender",
            "result code differed",
        ));
    }
    await_authenticated_progress(
        "send canonical result acknowledgement",
        attempt.send_data(&codec.encode(ack)?),
    )
    .await?;
    await_authenticated_progress("finish canonical data stream", attempt.finish_data()).await?;
    if await_authenticated_progress("receive canonical control EOF", attempt.receive_control())
        .await?
        .is_some()
    {
        return Err("canonical control stream contained data after terminal result".into());
    }
    Ok(BlobNetworkReport {
        wire_bytes: wire_len,
        resumed_from: resume_offset,
        attempt_bytes: wire_len - resume_offset,
        roots,
        checkpoints,
        pipeline: None,
    })
}

#[allow(clippy::too_many_arguments)]
async fn send_completed_pack_inner(
    transport: &dyn StreamTransportAdapter,
    open: &BlobStreamOpen,
    authenticated_open: Vec<u8>,
    root: PackAccess<'_>,
    roots: ([u8; 32], [u8; 32]),
    semantic_commitment: Vec<u8>,
    planned_nonce: Option<[u8; 32]>,
    direction: StreamDirection,
    codec: &mut dyn BlobRecordCodec,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let wire_len = root.reader(open)?.checkpoint().payload_len();
    if wire_len != expected_pack_wire_len(open.total_len())? {
        return Err(BlobNetworkError::new(
            BlobNetworkStage::Framing,
            "validate completed pack",
            "wire length differs from canonical segment framing",
        ));
    }
    let (max_data_bytes, max_control_bytes) =
        profile5_attempt_bounds(wire_len).map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "bound stream attempt", error)
        })?;
    let attempt = transport
        .open_attempt(AttemptOpenRequest {
            deadline: Instant::now() + PROFILE5_ATTEMPT_TIMEOUT,
            max_data_bytes,
            max_control_bytes,
        })
        .await
        .map_err(|error| transport_failure("open transport attempt", format!("{error:?}")))?;
    let mut attempt_nonce = planned_nonce.unwrap_or([0; 32]);
    if planned_nonce.is_none() {
        getrandom::fill(&mut attempt_nonce)
            .map_err(|error| authentication_failure("attempt nonce", error))?;
    }
    let transfer_open = protocol_open(
        open,
        &authenticated_open,
        wire_len,
        attempt_nonce,
        direction,
    );
    attempt
        .send_data(&codec.encode(StreamFrame::Open(transfer_open.clone()))?)
        .await
        .map_err(|error| transport_failure("send open", format!("{error:?}")))?;
    send_authenticated_source(attempt.as_ref(), codec, &transfer_open, &authenticated_open).await?;
    let accept = attempt
        .receive_control()
        .await
        .map_err(|error| transport_failure("receive accept", format!("{error:?}")))?
        .ok_or("control stream closed before accept")?;
    let StreamFrame::Accept(accept) = codec.decode(&accept)? else {
        return Err("first control frame was not accept".into());
    };
    let resume_offset = accept.durable_offset;
    let mut state = StreamSenderState::new(transfer_open.transfer_id, attempt_nonce, wire_len);
    state
        .accept(accept)
        .map_err(|error| failure("accept stream", error))?;
    let mut source = PackExtentSource::new_at(&root, open, resume_offset)?;
    let mut pending = source.next_extent()?;
    let mut checkpoints = 0;
    while let Some(extent) = pending.take() {
        match state
            .send_extent(extent)
            .map_err(|error| failure("advance sender extent", error))?
        {
            StreamExtentAction::Send(data) => {
                let (prefix, body) = codec.encode_data_parts(data)?;
                attempt
                    .send_data_parts(&prefix, &body)
                    .await
                    .map_err(|error| transport_failure("send data", format!("{error:?}")))?;
                pending = source.next_extent()?;
            }
            StreamExtentAction::Retry {
                reason: crate::stream_transfer::StreamRetry::CreditBlocked,
                bytes,
            } => {
                let checkpoint = attempt
                    .receive_control()
                    .await
                    .map_err(|error| transport_failure("receive checkpoint", format!("{error:?}")))?
                    .ok_or("control stream closed before checkpoint")?;
                let StreamFrame::Checkpoint(checkpoint) = codec.decode(&checkpoint)? else {
                    return Err("credit wait received a non-checkpoint frame".into());
                };
                state
                    .checkpoint(checkpoint)
                    .map_err(|error| failure("advance sender checkpoint", error))?;
                checkpoints += 1;
                pending = Some(bytes);
            }
            StreamExtentAction::Retry { .. } => {
                return Err("sender produced an invalid extent retry".into());
            }
        }
    }
    let checkpoint = attempt
        .receive_control()
        .await
        .map_err(|error| transport_failure("receive final checkpoint", format!("{error:?}")))?
        .ok_or("control stream closed before final checkpoint")?;
    let StreamFrame::Checkpoint(checkpoint) = codec.decode(&checkpoint)? else {
        return Err("final control frame was not checkpoint".into());
    };
    state
        .checkpoint(checkpoint)
        .map_err(|error| failure("advance final sender checkpoint", error))?;
    checkpoints += 1;
    let StreamAction::Send(finish) = state
        .finish(semantic_commitment)
        .map_err(|error| failure("finish sender state", error))?
    else {
        return Err("sender did not produce finish".into());
    };
    attempt
        .send_data(&codec.encode(finish)?)
        .await
        .map_err(|error| transport_failure("send finish", format!("{error:?}")))?;
    let result = attempt
        .receive_control()
        .await
        .map_err(|error| transport_failure("receive result", format!("{error:?}")))?
        .ok_or("control stream closed before result")?;
    let StreamFrame::Result(result) = codec.decode(&result)? else {
        return Err("terminal control frame was not result".into());
    };
    if !matches!(
        result.code,
        StreamResultCode::Promoted | StreamResultCode::AlreadyPresent
    ) || result.result_digest != result_digest(open, roots)
    {
        return Err(settlement_failure(
            "validate receiver result",
            "result did not bind the expected Blob roots",
        ));
    }
    let expected_result = result.code;
    let (StreamAction::Send(ack), StreamAction::Terminal(settled)) = state
        .result(result)
        .map_err(|error| settlement_failure("settle sender state", error))?
    else {
        return Err(settlement_failure(
            "settle sender",
            "settlement action differed",
        ));
    };
    if settled != expected_result {
        return Err(settlement_failure("settle sender", "result code differed"));
    }
    attempt
        .send_data(&codec.encode(ack)?)
        .await
        .map_err(|error| transport_failure("send result acknowledgement", format!("{error:?}")))?;
    attempt
        .finish_data()
        .await
        .map_err(|error| transport_failure("finish data stream", format!("{error:?}")))?;
    if attempt
        .receive_control()
        .await
        .map_err(|error| transport_failure("receive control EOF", format!("{error:?}")))?
        .is_some()
    {
        return Err("control stream contained data after terminal result".into());
    }
    Ok(BlobNetworkReport {
        wire_bytes: wire_len,
        resumed_from: resume_offset,
        attempt_bytes: wire_len - resume_offset,
        roots,
        checkpoints,
        pipeline: None,
    })
}

struct RecordPartitioner {
    next_index: u64,
    consumed: u64,
    max_record_bytes: usize,
}

impl RecordPartitioner {
    fn new(next_index: u64, consumed: u64) -> Self {
        Self {
            next_index,
            consumed,
            max_record_bytes: PROFILE5_MAX_RECORD_BYTES,
        }
    }

    #[cfg(test)]
    fn with_max_record_bytes_for_test(mut self, max_record_bytes: usize) -> Self {
        assert!(
            max_record_bytes > 0 && max_record_bytes <= PROFILE5_MAX_RECORD_BYTES,
            "test record bound must be within the production limit"
        );
        self.max_record_bytes = max_record_bytes;
        self
    }

    async fn push(
        &mut self,
        bytes: Vec<u8>,
        sender: &mpsc::Sender<Result<StreamPartition, PipelineError>>,
    ) -> Result<(), BlobNetworkError> {
        if bytes.len() < 4 {
            return Err(BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "partition network extent",
                "extent is shorter than its record length",
            ));
        }
        let len = u32::from_be_bytes(bytes[..4].try_into().expect("record length")) as usize;
        if len == 0 || len > self.max_record_bytes {
            return Err(BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "partition network extent",
                "record length is out of bounds",
            ));
        }
        let record_len = 4usize.checked_add(len).ok_or("record length overflow")?;
        if bytes.len() != record_len {
            return Err(BlobNetworkError::new(
                BlobNetworkStage::Framing,
                "partition network extent",
                "extent is not exactly one canonical record",
            ));
        }
        let wire_end = self
            .consumed
            .checked_add(record_len as u64)
            .ok_or("wire offset overflow")?;
        sender
            .send(Ok(StreamPartition::new_at(
                self.next_index,
                wire_end,
                bytes,
            )))
            .await
            .map_err(|_| {
                verification_failure("submit network extent", "verification pipeline closed")
            })?;
        self.next_index += 1;
        self.consumed = wire_end;
        Ok(())
    }

    fn finish(&self, expected: u64) -> Result<(), BlobNetworkError> {
        if self.consumed == expected {
            Ok(())
        } else {
            Err("network stream ended before the complete Blob pack".into())
        }
    }
}

#[derive(Clone)]
struct DurableProgress {
    wire_offset: u64,
    checkpoint: BlobPackCheckpoint,
}

async fn send_durable_checkpoint(
    attempt: &std::sync::Arc<dyn crate::stream_transport::StreamReceiveAttempt>,
    state: &mut StreamReceiverState,
    progress: &DurableProgress,
    wire_len: u64,
    current_limit: &mut u64,
    codec: &mut dyn BlobRecordCodec,
) -> Result<(), BlobNetworkError> {
    let new_limit = (*current_limit).max(profile5_receive_limit(
        wire_len,
        progress.wire_offset,
        MAX_STREAM_CHECKPOINT_BATCH_BYTES,
    ));
    let StreamAction::Send(checkpoint) = state
        .persisted(
            progress.wire_offset,
            progress.checkpoint.generation(),
            new_limit,
        )
        .map_err(|error| failure("advance receiver checkpoint", error))?
    else {
        return Err("receiver did not produce checkpoint".into());
    };
    attempt
        .send_control(&codec.encode(checkpoint)?)
        .await
        .map_err(|error| transport_failure("send checkpoint", format!("{error:?}")))?;
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
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let mut codec = PlainBlobRecordCodec;
    let transport = select_stream_transport(connection)?;
    receive_completed_pack_inner(
        transport.as_ref(),
        open,
        opener,
        PackAccess::Path(root),
        wire_len,
        limits,
        None,
        None,
        StreamDirection::ToSessionResponder,
        &mut codec,
    )
    .await
}

pub async fn receive_completed_pack_with_store(
    connection: Connection,
    session: BlobReceiveStoreSession,
    opener: BlobStreamSegmentOpener,
    root: &Path,
    wire_len: u64,
    limits: PipelineLimits,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let open = session.open.open().clone();
    let mut codec = PlainBlobRecordCodec;
    let transport = select_stream_transport(connection)?;
    receive_completed_pack_inner(
        transport.as_ref(),
        &open,
        opener,
        PackAccess::Path(root),
        wire_len,
        limits,
        Some(session),
        None,
        StreamDirection::ToSessionResponder,
        &mut codec,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[allow(dead_code)] // Task 5 supplies profile-5 source acceptance before this receiver.
pub(crate) async fn receive_completed_pack_with_store_protected(
    connection: Connection,
    mission: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    attempt_nonce: [u8; 32],
    session: BlobReceiveStoreSession,
    opener: BlobStreamSegmentOpener,
    root: &PinnedBlobPackRoot,
    wire_len: u64,
    limits: PipelineLimits,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let open = session.open.open().clone();
    let mut codec = MissionBlobRecordCodec {
        mission,
        profile_digest,
        direction,
        attempt_nonce,
    };
    let transport = select_stream_transport(connection)?;
    receive_completed_pack_inner(
        transport.as_ref(),
        &open,
        opener,
        PackAccess::Pinned(root),
        wire_len,
        limits,
        Some(session),
        Some(attempt_nonce),
        match direction {
            EventDirection::ToSessionInitiator => StreamDirection::ToSessionInitiator,
            EventDirection::ToSessionResponder => StreamDirection::ToSessionResponder,
        },
        &mut codec,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn receive_completed_pack_inner(
    transport: &dyn StreamTransportAdapter,
    open: &BlobStreamOpen,
    opener: BlobStreamSegmentOpener,
    root: PackAccess<'_>,
    wire_len: u64,
    limits: PipelineLimits,
    store_session: Option<BlobReceiveStoreSession>,
    planned_nonce: Option<[u8; 32]>,
    direction: StreamDirection,
    codec: &mut dyn BlobRecordCodec,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let (max_data_bytes, max_control_bytes) =
        profile5_attempt_bounds(wire_len).map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "bound stream attempt", error)
        })?;
    let attempt = transport
        .accept_attempt(AttemptOpenRequest {
            deadline: Instant::now() + PROFILE5_ATTEMPT_TIMEOUT,
            max_data_bytes,
            max_control_bytes,
        })
        .await
        .map_err(|error| transport_failure("accept transport attempt", format!("{error:?}")))?;
    let frame = attempt
        .receive_data()
        .await
        .map_err(|error| transport_failure("receive open", format!("{error:?}")))?
        .ok_or("data stream closed before open")?;
    let StreamFrame::Open(transfer_open) = codec.decode(&frame)? else {
        return Err("first data frame was not open".into());
    };
    let authenticated_source =
        receive_authenticated_source(attempt.as_ref(), codec, &transfer_open).await?;
    if transfer_open.class != StreamClass::Blob
        || transfer_open.direction != direction
        || transfer_open.total_len != wire_len
        || transfer_open.session_transcript != open.digest()
        || transfer_open.publication_id != *open.stream_id().as_bytes()
        || store_session
            .as_ref()
            .is_some_and(|session| session.authenticated_open != authenticated_source)
        || planned_nonce.is_some_and(|nonce| nonce != transfer_open.attempt_nonce)
    {
        return Err(authentication_failure(
            "validate transport open",
            "open differs from authenticated Blob open",
        ));
    }
    let mut store_state = store_session
        .as_ref()
        .map(BlobReceiveStoreSession::reserve)
        .transpose()?;
    let resume = store_state
        .as_ref()
        .map_or_else(BlobStreamResume::default, |(_, resume)| *resume);
    let durable_wire = resume.durable_wire_offset();
    let resumed_from = durable_wire;
    let mut writer = root.projected_writer(open, resume)?;
    let mut current_limit =
        profile5_receive_limit(wire_len, durable_wire, MAX_STREAM_CHECKPOINT_BATCH_BYTES);
    let mut state = StreamReceiverState::new(
        &transfer_open,
        durable_wire,
        resume.generation(),
        current_limit,
        PROFILE5_EXTENT_BYTES as u32,
    )
    .map_err(|error| failure("initialize receiver state", error))?;
    let StreamAction::Send(accept) = state
        .accept(MAX_STREAM_CHECKPOINT_BATCH_BYTES)
        .map_err(|error| failure("accept receiver stream", error))?
    else {
        return Err("receiver did not produce accept".into());
    };
    attempt
        .send_control(&codec.encode(accept)?)
        .await
        .map_err(|error| transport_failure("send accept", format!("{error:?}")))?;

    let (partition_tx, partition_rx) = mpsc::channel(limits.max_in_flight_items());
    let (durable_tx, mut durable_rx) = mpsc::unbounded_channel();
    let total_plaintext = open.total_len();
    let stream_job = StreamJobId::from_bytes(
        open.stream_id().as_bytes()[..16]
            .try_into()
            .expect("job ID"),
    );
    let pipeline = Box::pin(async move {
        #[cfg(test)]
        let _lifetime = ReceivePipelineGuard::enter(stream_job);
        let mut last_checkpoint_wire = resume.durable_wire_offset();
        let report = run_ordered_channel_pipeline_from(
            stream_job,
            partition_rx,
            resume.next_segment_index(),
            limits,
            move |partition| {
                let index = partition.index();
                let wire_end = partition.source_end();
                let bytes = partition.into_bytes();
                let (header, _plaintext, leaves) = opener
                    .open_encoded(&bytes[4..])
                    .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
                if header.index() != index {
                    return Err(PipelineError::MapFailed("segment index differs".into()));
                }
                Ok((bytes, header, leaves, wire_end))
            },
            |mapped: MappedPartition<_>| {
                let (record, header, leaves, wire_end) = mapped.into_value();
                let plaintext_end = header.offset() + u64::from(header.plaintext_len());
                let result = writer
                    .append_record(&record[4..], leaves)
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
                                    checkpoint,
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

    let mut partitioner = RecordPartitioner::new(resume.next_segment_index(), durable_wire);
    let mut received = durable_wire;
    let mut durable_wire = durable_wire;
    let mut checkpoints = 0_u64;
    let receive = Box::pin(async {
        while received < wire_len {
            let frame = attempt
                .receive_data()
                .await
                .map_err(|error| transport_failure("receive data", format!("{error:?}")))?
                .ok_or("data stream closed before completion")?;
            let StreamFrame::Data(data) = codec.decode(&frame)? else {
                return Err("non-data frame before complete payload".into());
            };
            let StreamAction::Persist { through } = state
                .data(&data)
                .map_err(|error| failure("advance receiver data", error))?
            else {
                return Err("receiver did not accept new data".into());
            };
            partitioner.push(data.bytes, &partition_tx).await?;
            received = through;
            if partitioner.consumed - durable_wire >= u64::from(MAX_STREAM_CHECKPOINT_BATCH_BYTES)
                || partitioner.consumed == wire_len
            {
                let progress = durable_rx.recv().await.ok_or_else(|| {
                    verification_failure(
                        "receive durable checkpoint",
                        "verification pipeline closed before checkpoint",
                    )
                })?;
                if let (Some(session), Some((reservation, resume))) =
                    (store_session.as_ref(), store_state.as_mut())
                {
                    *resume = session
                        .store
                        .checkpoint_blob_stream(
                            &session.policy,
                            reservation,
                            *resume,
                            progress.checkpoint.clone(),
                        )
                        .map_err(|error| durability_failure("project durable checkpoint", error))?;
                }
                send_durable_checkpoint(
                    &attempt,
                    &mut state,
                    &progress,
                    wire_len,
                    &mut current_limit,
                    codec,
                )
                .await?;
                durable_wire = progress.wire_offset;
                checkpoints += 1;
            }
        }
        partitioner.finish(wire_len)?;
        drop(partition_tx);
        Ok::<(), BlobNetworkError>(())
    });
    let verify = Box::pin(async move {
        pipeline
            .await
            .map_err(|error| verification_failure("verification pipeline", error))
    });
    let ((), (pipeline, roots)) = tokio::try_join!(receive, verify)?;
    let finish = attempt
        .receive_data()
        .await
        .map_err(|error| transport_failure("receive finish", format!("{error:?}")))?
        .ok_or("data stream closed before finish")?;
    let StreamFrame::Finish(finish) = codec.decode(&finish)? else {
        return Err("terminal data frame was not finish".into());
    };
    let semantic_commitment = finish.semantic_commitment.clone();
    let StreamAction::Promote = state
        .finish(finish)
        .map_err(|error| failure("finish receiver state", error))?
    else {
        return Err("receiver did not reach promotion".into());
    };
    let result_code = if let (Some(session), Some((reservation, _))) =
        (store_session.as_ref(), store_state.as_ref())
    {
        let commitment = (session.verify_commitment)(&session.open, &semantic_commitment)
            .map_err(|error| verification_failure("verify final commitment", error))?;
        let promotion = session
            .store
            .promote_blob_stream_with_policy(&session.policy, reservation, &commitment)
            .map_err(|error| lifecycle_failure("promote stream", error))?;
        if promotion.duplicate() {
            StreamResultCode::AlreadyPresent
        } else {
            StreamResultCode::Promoted
        }
    } else {
        StreamResultCode::Promoted
    };
    let digest = result_digest(open, roots);
    let StreamAction::Send(result) = state
        .promoted(result_code, digest)
        .map_err(|error| settlement_failure("record receiver promotion", error))?
    else {
        return Err("receiver did not produce result".into());
    };
    attempt
        .send_control(&codec.encode(result)?)
        .await
        .map_err(|error| transport_failure("send result", format!("{error:?}")))?;
    let ack = attempt
        .receive_data()
        .await
        .map_err(|error| transport_failure("receive result acknowledgement", format!("{error:?}")))?
        .ok_or("data stream closed before result acknowledgement")?;
    let StreamFrame::ResultAck(ack) = codec.decode(&ack)? else {
        return Err("settlement frame was not result acknowledgement".into());
    };
    let StreamAction::Terminal(settled) = state
        .result_ack(ack, result_code)
        .map_err(|error| settlement_failure("settle receiver state", error))?
    else {
        return Err(settlement_failure(
            "settle receiver",
            "settlement action differed",
        ));
    };
    if settled != result_code {
        return Err(settlement_failure(
            "settle receiver",
            "result code differed",
        ));
    }
    finish_receiver_attempt(attempt).await?;
    Ok(BlobNetworkReport {
        wire_bytes: wire_len,
        resumed_from,
        attempt_bytes: wire_len - resumed_from,
        roots,
        checkpoints,
        pipeline: Some(pipeline),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mission::{MissionPeerBinding, MissionSessionInitiator, MissionSessionResponder};
    use crate::stream_transfer::PROFILE5_SOURCE_CHUNK_BYTES;
    use crate::stream_transport::{
        AdapterFuture, CandidateHealth, StreamAttempt, StreamReceiveAttempt,
        StreamTransportAdapter, StreamTransportError, StreamTransportId, TransferRequirements,
    };
    use crate::{application::blob_stream::publish_blob_stream, stream_pipeline::PipelineLimits};
    use aster_iroh::{CarrierSecurityProfile, Endpoint, EndpointConfig, ExpectedPeer, SecretKey};
    use aster_mesh::{
        BLOB_STREAM_SEGMENT_BYTES, BlobMetadata, BlobPublicationStreamId,
        BlobStreamFinalCommitment, BlobStreamOpen, BlobStreamSegmentOpener,
        BlobStreamSegmentSealer, Priority, ProvisioningAccess, ProvisioningBundle,
        ReferenceEnvelopeSealer, ReferenceProvisioner, Scope, Topic, VersionVector,
    };
    use std::{
        collections::BTreeSet,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn canonical_carrier_extent_batches_whole_encrypted_records() {
        // Mutation caught: concatenating carriers without lengths, splitting a
        // carrier at the transport ceiling, or accepting trailing bytes would
        // destroy canonical resume boundaries.
        let extent = CanonicalBlobExtentV1 {
            first_chunk_index: 9,
            carriers: vec![vec![0x11; 65_000], vec![0x22; 66_000]],
        };
        let encoded = extent.encode().expect("canonical carrier extent");
        assert!(encoded.len() <= PROFILE5_CANONICAL_EXTENT_BYTES);
        assert_eq!(CanonicalBlobExtentV1::decode(&encoded).unwrap(), extent);

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(CanonicalBlobExtentV1::decode(&trailing).is_err());
        assert!(
            CanonicalBlobExtentV1 {
                first_chunk_index: 0,
                carriers: vec![vec![0; PROFILE5_CANONICAL_EXTENT_BYTES]],
            }
            .encode()
            .is_err()
        );
    }

    #[test]
    fn network_error_retains_stage_but_sanitizes_internal_detail() {
        let error = expected_pack_wire_len(u64::MAX).expect_err("wire length must overflow");

        assert_eq!(error.stage(), BlobNetworkStage::Framing);
        assert!(error.to_string().contains("wire length overflow"));
        assert_eq!(error.public_message(), "profile-5 Blob framing failed");
        assert!(!error.public_message().contains("overflow"));
    }

    #[tokio::test(start_paused = true)]
    async fn authenticated_progress_keeps_large_attempt_alive_past_ten_minutes() {
        let started = tokio::time::Instant::now();
        for _ in 0..8 {
            let value = await_authenticated_progress("slow progress", async {
                tokio::time::sleep(std::time::Duration::from_secs(90)).await;
                Ok::<_, StreamTransportError>(())
            })
            .await;
            assert!(value.is_ok());
        }
        assert!(started.elapsed() >= std::time::Duration::from_secs(12 * 60));
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_authenticated_transfer_times_out_retryably() {
        let error = await_authenticated_progress("stalled progress", async {
            std::future::pending::<Result<(), StreamTransportError>>().await
        })
        .await
        .expect_err("idle transfer must time out");
        assert_eq!(error.stage(), BlobNetworkStage::Transport);
        assert!(error.to_string().contains("idle timeout"));
    }

    fn mission_pair() -> (MissionSession, MissionSession, [u8; 32]) {
        let scope = Scope::new("mission/alpha").unwrap();
        let access =
            ProvisioningAccess::member(scope, vec![1], vec![Topic::new("imagery").unwrap()])
                .unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0xc1; 32]).unwrap();
        let initiator_bytes = provisioner
            .issue_node(1, std::slice::from_ref(&access))
            .unwrap()
            .to_bytes()
            .unwrap();
        let responder_bytes = provisioner
            .issue_node(2, &[access])
            .unwrap()
            .to_bytes()
            .unwrap();
        let initiator_identity = ReferenceEnvelopeSealer::open(
            ProvisioningBundle::from_bytes(&initiator_bytes).unwrap(),
        )
        .unwrap()
        .identity();
        let responder_identity = ReferenceEnvelopeSealer::open(
            ProvisioningBundle::from_bytes(&responder_bytes).unwrap(),
        )
        .unwrap()
        .identity();
        let initiator_carrier = SecretKey::generate();
        let responder_carrier = SecretKey::generate();
        let (initiator, first) = MissionSessionInitiator::start(
            ProvisioningBundle::from_bytes(&initiator_bytes).unwrap(),
            MissionPeerBinding::new(responder_carrier.public(), responder_identity),
            responder_carrier.public(),
        )
        .unwrap();
        let responder = MissionSessionResponder::open(
            ProvisioningBundle::from_bytes(&responder_bytes).unwrap(),
            MissionPeerBinding::new(initiator_carrier.public(), initiator_identity),
            initiator_carrier.public(),
        )
        .unwrap();
        let (responder, second) = responder.receive_client(first.as_bytes()).unwrap();
        let (initiator, third) = initiator.receive_server(second.as_bytes()).unwrap();
        let (mut responder, fourth) = responder.receive_client_auth(third.as_bytes()).unwrap();
        let mut initiator = initiator.receive_finished(fourth.as_bytes()).unwrap();

        let offer = crate::event_pages::TransferProfileOfferV1::for_semantic_version(9).unwrap();
        let initiator_offer = initiator.seal_transfer_profile_offer(&offer).unwrap();
        responder
            .open_transfer_profile_offer(&initiator_offer)
            .unwrap();
        let responder_offer = responder.seal_transfer_profile_offer(&offer).unwrap();
        initiator
            .open_transfer_profile_offer(&responder_offer)
            .unwrap();
        let negotiated = crate::event_pages::negotiate_transfer_profiles(&offer, &offer).unwrap();
        let digest = crate::event_pages::transfer_profile_digest(&offer, &offer, &negotiated);
        (initiator, responder, digest)
    }

    #[test]
    fn maximum_canonical_manifest_and_production_extent_fit_iroh_frames() {
        let (mut sender, mut receiver, profile_digest) = mission_pair();
        let attempt_nonce = [0x61; 32];
        let source = vec![0x5a; usize::try_from(aster_mesh::MAX_BLOB_MANIFEST_BYTES).unwrap()];
        let source_digest = Sha256::digest(&source).into();
        let source_len = u32::try_from(source.len()).unwrap();
        let plan = crate::frame::Frame::BlobStreamPlan {
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: Some(attempt_nonce),
            source: Some(crate::frame::BlobStreamSourceOfferV1 {
                transfer_id: [0x62; 32],
                source_len,
                source_digest,
            }),
        }
        .encode_for_semantic_version(9)
        .expect("bounded production plan");
        let protected_plan = sender.seal_application_frame(&plan).expect("protect plan");
        assert!(protected_plan.len() <= aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES);
        assert_eq!(
            receiver.open_application_frame(&protected_plan).unwrap(),
            plan
        );

        let open = StreamOpenV1 {
            class: StreamClass::Blob,
            direction: StreamDirection::ToSessionResponder,
            session_transcript: sender.session_id(),
            exchange_id: 1,
            transfer_id: [0x62; 32],
            source_transfer_id: [0x62; 32],
            publication_id: [0x63; 32],
            variant_id: [0x64; 32],
            total_len: 8 * 1024 * 1024 * 1024,
            attempt_nonce,
            checkpoint_generation: 0,
            custody_digest: None,
            source_len,
            source_digest,
        };
        let mut send_codec = MissionBlobRecordCodec {
            mission: &mut sender,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce,
        };
        let protected_open = send_codec
            .encode(StreamFrame::Open(open.clone()))
            .expect("protect open");
        assert!(protected_open.len() <= aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES);

        let mut protected_sources = Vec::new();
        for (sequence, chunk) in source
            .chunks(crate::stream_transfer::PROFILE5_SOURCE_CHUNK_BYTES)
            .enumerate()
        {
            let offset =
                u32::try_from(sequence * crate::stream_transfer::PROFILE5_SOURCE_CHUNK_BYTES)
                    .unwrap();
            let protected = send_codec
                .encode(StreamFrame::Source(
                    crate::stream_transfer::StreamSourceV1 {
                        transfer_id: open.transfer_id,
                        attempt_nonce,
                        sequence: sequence as u64,
                        offset,
                        total_len: source_len,
                        bytes: chunk.to_vec(),
                    },
                ))
                .expect("protect source chunk");
            assert!(protected.len() <= aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES);
            assert!(protected.len() + 4 <= aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES + 4);
            protected_sources.push(protected);
        }

        let carrier_len = aster_mesh::MAX_BLOB_TRANSFER_OBJECT_BYTES;
        let extent = CanonicalBlobExtentV1 {
            first_chunk_index: 0,
            carriers: vec![vec![0xa5; carrier_len]; 15],
        };
        let extent_bytes = extent.encode().expect("production canonical extent");
        let data = crate::stream_transfer::StreamDataV1 {
            transfer_id: open.transfer_id,
            attempt_nonce,
            sequence: protected_sources.len() as u64,
            offset: 0,
            bytes: extent_bytes.clone(),
        };
        let (prefix, body) = send_codec
            .encode_data_parts(data)
            .expect("protect data extent");
        assert!(prefix.len() + body.len() <= aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES);
        assert!(prefix.len() + body.len() + 4 <= aster_iroh::DEFAULT_MAX_EXCHANGE_BYTES + 4);

        let mut receive_codec = MissionBlobRecordCodec {
            mission: &mut receiver,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce,
        };
        assert_eq!(
            receive_codec.decode(&protected_open).unwrap(),
            StreamFrame::Open(open)
        );
        for protected in protected_sources {
            assert!(matches!(
                receive_codec.decode(&protected).unwrap(),
                StreamFrame::Source(_)
            ));
        }
        let mut emitted = prefix;
        emitted.extend_from_slice(&body);
        let StreamFrame::Data(decoded) = receive_codec.decode(&emitted).unwrap() else {
            panic!("production data frame decoded as another kind");
        };
        assert_eq!(
            CanonicalBlobExtentV1::decode(&decoded.bytes).unwrap(),
            extent
        );
    }

    #[test]
    fn mission_data_record_protects_only_the_canonical_header() {
        let (mut sender, mut receiver, profile_digest) = mission_pair();
        let nonce = [0xc2; 32];
        let body = vec![0xc3; 32];
        let frame = StreamFrame::Data(crate::stream_transfer::StreamDataV1 {
            transfer_id: [0xc4; 32],
            attempt_nonce: nonce,
            sequence: 0,
            offset: 0,
            bytes: body.clone(),
        });
        let mut sender_codec = MissionBlobRecordCodec {
            mission: &mut sender,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: nonce,
        };
        let encoded = sender_codec.encode(frame.clone()).unwrap();

        assert_eq!(&encoded[encoded.len() - body.len()..], body);
        assert!(
            encoded.len()
                < body.len() + crate::stream_transfer::MAX_PROTECTED_STREAM_DATA_HEADER_BYTES
        );

        let mut receiver_codec = MissionBlobRecordCodec {
            mission: &mut receiver,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: nonce,
        };
        assert_eq!(receiver_codec.decode(&encoded).unwrap(), frame);
    }

    #[test]
    fn plain_data_framing_moves_the_canonical_record_allocation() {
        let body = vec![0xc3; 32];
        let allocation = body.as_ptr();
        let data = crate::stream_transfer::StreamDataV1 {
            transfer_id: [0xc4; 32],
            attempt_nonce: [0xc2; 32],
            sequence: 0,
            offset: 0,
            bytes: body,
        };

        let (header, body) = PlainBlobRecordCodec
            .encode_data_parts(data)
            .expect("split data frame");

        assert_eq!(
            header.len(),
            crate::stream_transfer::STREAM_DATA_FIXED_BYTES
        );
        assert_eq!(body.as_ptr(), allocation);
    }

    #[test]
    fn wrong_mission_direction_is_an_authentication_failure() {
        let (mut sender, mut receiver, profile_digest) = mission_pair();
        let nonce = [0xc8; 32];
        let frame = StreamFrame::Data(crate::stream_transfer::StreamDataV1 {
            transfer_id: [0xc9; 32],
            attempt_nonce: nonce,
            sequence: 0,
            offset: 0,
            bytes: vec![0xca; 32],
        });
        let encoded = MissionBlobRecordCodec {
            mission: &mut sender,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: nonce,
        }
        .encode(frame)
        .unwrap();
        let error = MissionBlobRecordCodec {
            mission: &mut receiver,
            profile_digest,
            direction: EventDirection::ToSessionInitiator,
            attempt_nonce: nonce,
        }
        .decode(&encoded)
        .expect_err("wrong mission direction must fail");

        assert_eq!(error.stage(), BlobNetworkStage::Authentication);
        assert_eq!(
            error.public_message(),
            "profile-5 Blob authentication failed"
        );
    }

    #[test]
    fn mission_codec_rejects_a_fully_wrapped_data_record() {
        let (mut sender, mut receiver, profile_digest) = mission_pair();
        let nonce = [0xc5; 32];
        let frame = StreamFrame::Data(crate::stream_transfer::StreamDataV1 {
            transfer_id: [0xc6; 32],
            attempt_nonce: nonce,
            sequence: 0,
            offset: 0,
            bytes: vec![0xc7; 32],
        });
        let plaintext = frame.encode_for_context(9, 5).unwrap();
        let fully_wrapped = sender
            .seal_v9_blob_application_frame(
                profile_digest,
                EventDirection::ToSessionResponder,
                nonce,
                &plaintext,
            )
            .unwrap();
        let mut receiver_codec = MissionBlobRecordCodec {
            mission: &mut receiver,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: nonce,
        };

        assert!(receiver_codec.decode(&fully_wrapped).is_err());
    }

    #[test]
    #[ignore = "explicit 256 MiB profile-5 composite-record measurement"]
    fn composite_profile5_records_process_256_mib_in_bounded_extents() {
        const TOTAL: u64 = 256 * 1024 * 1024;
        let (mut sender, mut receiver, profile_digest) = mission_pair();
        let nonce = [0xd1; 32];
        let mut sender_codec = MissionBlobRecordCodec {
            mission: &mut sender,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: nonce,
        };
        let mut receiver_codec = MissionBlobRecordCodec {
            mission: &mut receiver,
            profile_digest,
            direction: EventDirection::ToSessionResponder,
            attempt_nonce: nonce,
        };
        let started = std::time::Instant::now();
        let mut offset = 0_u64;
        let mut sequence = 0_u64;
        while offset < TOTAL {
            let extent_len =
                usize::try_from((TOTAL - offset).min(PROFILE5_EXTENT_BYTES as u64)).unwrap();
            let frame = StreamFrame::Data(crate::stream_transfer::StreamDataV1 {
                transfer_id: [0xd3; 32],
                attempt_nonce: nonce,
                sequence,
                offset,
                bytes: vec![0xd2; extent_len],
            });
            let protected = sender_codec.encode(frame).unwrap();
            std::hint::black_box(receiver_codec.decode(&protected).unwrap());
            offset += extent_len as u64;
            sequence += 1;
        }
        let elapsed = started.elapsed();
        let mib_per_second = TOTAL as f64 / (1024.0 * 1024.0) / elapsed.as_secs_f64();
        eprintln!(
            "composite_profile5_record_benchmark bytes={TOTAL} extents={sequence} elapsed_ns={} mib_per_second={mib_per_second:.3}",
            elapsed.as_nanos()
        );
    }

    struct TerminalReceiveAttempt {
        events: std::sync::Mutex<Vec<&'static str>>,
    }

    struct MemorySenderAttempt {
        data: mpsc::UnboundedSender<Option<Vec<u8>>>,
        control: tokio::sync::Mutex<mpsc::UnboundedReceiver<Option<Vec<u8>>>>,
    }

    impl StreamAttempt for MemorySenderAttempt {
        fn send_data<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()> {
            Box::pin(async move {
                self.data
                    .send(Some(frame.to_vec()))
                    .map_err(|_| StreamTransportError::Closed)
            })
        }

        fn send_data_parts<'a>(
            &'a self,
            prefix: &'a [u8],
            body: &'a [u8],
        ) -> AdapterFuture<'a, ()> {
            Box::pin(async move {
                let mut frame = Vec::with_capacity(prefix.len() + body.len());
                frame.extend_from_slice(prefix);
                frame.extend_from_slice(body);
                self.data
                    .send(Some(frame))
                    .map_err(|_| StreamTransportError::Closed)
            })
        }

        fn receive_control(&self) -> AdapterFuture<'_, Option<Vec<u8>>> {
            Box::pin(async move { Ok(self.control.lock().await.recv().await.flatten()) })
        }

        fn finish_data(&self) -> AdapterFuture<'_, ()> {
            Box::pin(async move {
                self.data
                    .send(None)
                    .map_err(|_| StreamTransportError::Closed)
            })
        }
    }

    struct MemoryReceiverAttempt {
        data: tokio::sync::Mutex<mpsc::UnboundedReceiver<Option<Vec<u8>>>>,
        control: mpsc::UnboundedSender<Option<Vec<u8>>>,
        fail_after_receives: Option<usize>,
        receives: std::sync::atomic::AtomicUsize,
    }

    impl StreamReceiveAttempt for MemoryReceiverAttempt {
        fn receive_data(&self) -> AdapterFuture<'_, Option<Vec<u8>>> {
            Box::pin(async move {
                let receive = self.receives.fetch_add(1, Ordering::SeqCst);
                if self
                    .fail_after_receives
                    .is_some_and(|limit| receive >= limit)
                {
                    let _ = self.control.send(None);
                    return Err(StreamTransportError::Closed);
                }
                Ok(self.data.lock().await.recv().await.flatten())
            })
        }

        fn send_control<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()> {
            Box::pin(async move {
                self.control
                    .send(Some(frame.to_vec()))
                    .map_err(|_| StreamTransportError::Closed)
            })
        }

        fn finish_control(&self) -> AdapterFuture<'_, ()> {
            Box::pin(async move {
                self.control
                    .send(None)
                    .map_err(|_| StreamTransportError::Closed)
            })
        }
    }

    struct MemoryTransportAdapter {
        sender: Arc<MemorySenderAttempt>,
        receiver: Arc<MemoryReceiverAttempt>,
    }

    impl MemoryTransportAdapter {
        fn new() -> Self {
            Self::with_receive_failure(None)
        }

        fn with_receive_failure(fail_after_receives: Option<usize>) -> Self {
            let (data_send, data_receive) = mpsc::unbounded_channel();
            let (control_send, control_receive) = mpsc::unbounded_channel();
            Self {
                sender: Arc::new(MemorySenderAttempt {
                    data: data_send,
                    control: tokio::sync::Mutex::new(control_receive),
                }),
                receiver: Arc::new(MemoryReceiverAttempt {
                    data: tokio::sync::Mutex::new(data_receive),
                    control: control_send,
                    fail_after_receives,
                    receives: std::sync::atomic::AtomicUsize::new(0),
                }),
            }
        }
    }

    impl StreamTransportAdapter for MemoryTransportAdapter {
        fn id(&self) -> StreamTransportId {
            StreamTransportId::IrohQuicV1
        }

        fn eligibility(&self, requirements: TransferRequirements) -> bool {
            requirements.reliable_ordered && requirements.full_duplex
        }

        fn health(&self) -> CandidateHealth {
            CandidateHealth::Healthy
        }

        fn open_attempt<'a>(
            &'a self,
            _request: AttemptOpenRequest,
        ) -> AdapterFuture<'a, Arc<dyn StreamAttempt>> {
            let sender = Arc::clone(&self.sender);
            Box::pin(async move { Ok(sender as Arc<dyn StreamAttempt>) })
        }

        fn accept_attempt<'a>(
            &'a self,
            _request: AttemptOpenRequest,
        ) -> AdapterFuture<'a, Arc<dyn StreamReceiveAttempt>> {
            let receiver = Arc::clone(&self.receiver);
            Box::pin(async move { Ok(receiver as Arc<dyn StreamReceiveAttempt>) })
        }
    }

    #[tokio::test]
    async fn authenticated_source_reassembly_binds_order_length_and_digest() {
        fn receiver_with(frames: Vec<Vec<u8>>) -> Arc<MemoryReceiverAttempt> {
            let (data, receive) = mpsc::unbounded_channel();
            for frame in frames {
                data.send(Some(frame)).unwrap();
            }
            let (control, _control_receive) = mpsc::unbounded_channel();
            Arc::new(MemoryReceiverAttempt {
                data: tokio::sync::Mutex::new(receive),
                control,
                fail_after_receives: None,
                receives: std::sync::atomic::AtomicUsize::new(0),
            })
        }

        let source = vec![0x91; PROFILE5_SOURCE_CHUNK_BYTES + 3];
        let open = StreamOpenV1 {
            class: StreamClass::Blob,
            direction: StreamDirection::ToSessionResponder,
            session_transcript: [0x92; 32],
            exchange_id: 1,
            transfer_id: [0x93; 32],
            source_transfer_id: [0x93; 32],
            publication_id: [0x94; 32],
            variant_id: [0x95; 32],
            total_len: 0,
            attempt_nonce: [0x96; 32],
            checkpoint_generation: 0,
            custody_digest: None,
            source_len: source.len() as u32,
            source_digest: Sha256::digest(&source).into(),
        };
        let frames = source
            .chunks(PROFILE5_SOURCE_CHUNK_BYTES)
            .enumerate()
            .map(|(sequence, bytes)| {
                encoded(StreamFrame::Source(
                    crate::stream_transfer::StreamSourceV1 {
                        transfer_id: open.transfer_id,
                        attempt_nonce: open.attempt_nonce,
                        sequence: sequence as u64,
                        offset: (sequence * PROFILE5_SOURCE_CHUNK_BYTES) as u32,
                        total_len: open.source_len,
                        bytes: bytes.to_vec(),
                    },
                ))
                .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            receive_authenticated_source(
                receiver_with(frames.clone()).as_ref(),
                &mut PlainBlobRecordCodec,
                &open,
            )
            .await
            .unwrap(),
            source
        );

        let mut out_of_order = frames;
        out_of_order.swap(0, 1);
        let error = receive_authenticated_source(
            receiver_with(out_of_order).as_ref(),
            &mut PlainBlobRecordCodec,
            &open,
        )
        .await
        .expect_err("out-of-order source must fail closed");
        assert_eq!(error.stage(), BlobNetworkStage::Authentication);

        let mut wrong_digest = open;
        wrong_digest.source_digest = [0x97; 32];
        let valid_frames = source
            .chunks(PROFILE5_SOURCE_CHUNK_BYTES)
            .enumerate()
            .map(|(sequence, bytes)| {
                encoded(StreamFrame::Source(
                    crate::stream_transfer::StreamSourceV1 {
                        transfer_id: wrong_digest.transfer_id,
                        attempt_nonce: wrong_digest.attempt_nonce,
                        sequence: sequence as u64,
                        offset: (sequence * PROFILE5_SOURCE_CHUNK_BYTES) as u32,
                        total_len: wrong_digest.source_len,
                        bytes: bytes.to_vec(),
                    },
                ))
                .unwrap()
            })
            .collect();
        assert!(
            receive_authenticated_source(
                receiver_with(valid_frames).as_ref(),
                &mut PlainBlobRecordCodec,
                &wrong_digest,
            )
            .await
            .is_err()
        );
    }

    impl StreamReceiveAttempt for TerminalReceiveAttempt {
        fn receive_data(&self) -> AdapterFuture<'_, Option<Vec<u8>>> {
            Box::pin(async move {
                self.events.lock().unwrap().push("data-eof");
                Ok(None)
            })
        }

        fn send_control<'a>(&'a self, _frame: &'a [u8]) -> AdapterFuture<'a, ()> {
            Box::pin(async { Err(StreamTransportError::Closed) })
        }

        fn finish_control(&self) -> AdapterFuture<'_, ()> {
            Box::pin(async move {
                let mut events = self.events.lock().unwrap();
                assert_eq!(events.as_slice(), ["data-eof"]);
                events.push("control-fin");
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn receiver_consumes_data_eof_before_finishing_control() {
        let attempt = Arc::new(TerminalReceiveAttempt {
            events: std::sync::Mutex::new(Vec::new()),
        });
        finish_receiver_attempt(attempt.clone()).await.unwrap();
        assert_eq!(
            attempt.events.lock().unwrap().as_slice(),
            ["data-eof", "control-fin"]
        );
    }

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
        open_with_stream_seed(total_len, 0x12)
    }

    fn open_with_stream_seed(total_len: u64, stream_seed: u8) -> BlobStreamOpen {
        BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([stream_seed; 32]).expect("stream"),
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
    async fn pack_source_emits_one_canonical_record_per_transport_extent() {
        let source_root = TempRoot::new("record-extents");
        let total_len = 2 * BLOB_STREAM_SEGMENT_BYTES + 17;
        let open = open(total_len as u64);
        let key = [0x63; 32];
        let nonce = [0x73; 12];
        let limits = PipelineLimits::new(2, 4, 5 * 1024 * 1024, 4).expect("limits");
        let published = publish_blob_stream(
            std::io::Cursor::new(vec![0x5a; total_len]),
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
        let opener = BlobStreamSegmentOpener::from_test_key(
            *open.stream_id().as_bytes(),
            open.digest(),
            open.content_epoch(),
            key,
            nonce,
        );
        let mut source =
            PackExtentSource::new(&PackAccess::Path(&source_root.0), &open).expect("pack source");
        let mut extents = Vec::new();
        while let Some(extent) = source.next_extent().expect("next extent") {
            let declared = u32::from_be_bytes(extent[..4].try_into().expect("record length"));
            assert_eq!(extent.len(), declared as usize + 4);
            opener
                .open_encoded(&extent[4..])
                .expect("independently authenticated extent");
            extents.push(extent);
        }

        assert_eq!(extents.len() as u64, published.segment_count);
        assert_eq!(extents[0].len(), PROFILE5_EXTENT_BYTES);
        assert_eq!(extents[1].len(), PROFILE5_EXTENT_BYTES);
    }

    #[tokio::test]
    async fn record_partitioner_rejects_fragmented_or_coalesced_transport_extents() {
        let (sender, _receiver) = mpsc::channel(1);
        let mut fragmented = RecordPartitioner::new(0, 0);
        assert!(
            fragmented
                .push(vec![0, 0, 0, 3, 0xa1, 0xa2], &sender)
                .await
                .is_err()
        );

        let mut coalesced = RecordPartitioner::new(0, 0);
        assert!(
            coalesced
                .push(vec![0, 0, 0, 1, 0xa1, 0, 0, 0, 1, 0xa2], &sender)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn record_partitioner_rejects_records_larger_than_one_profile_extent() {
        let (sender, _receiver) = mpsc::channel(1);
        const TEST_RECORD_BYTES: usize = 4;
        let declared = TEST_RECORD_BYTES + 1;
        let mut bytes = vec![0; declared + crate::stream_transfer::PROFILE5_RECORD_PREFIX_BYTES];
        bytes[..crate::stream_transfer::PROFILE5_RECORD_PREFIX_BYTES]
            .copy_from_slice(&(declared as u32).to_be_bytes());

        let error = RecordPartitioner::new(0, 0)
            .with_max_record_bytes_for_test(TEST_RECORD_BYTES)
            .push(bytes, &sender)
            .await
            .expect_err("oversized profile-5 record must fail before verification");

        assert_eq!(error.stage(), BlobNetworkStage::Framing);
    }

    #[tokio::test]
    async fn completed_pack_runtime_uses_selected_transport_adapter() {
        let source_root = TempRoot::new("adapter-source");
        let receiver_root = TempRoot::new("adapter-receiver");
        let total_len = 2 * BLOB_STREAM_SEGMENT_BYTES + 17;
        let open = open(total_len as u64);
        let key = [0x66; 32];
        let nonce = [0x76; 12];
        let limits = PipelineLimits::new(2, 4, 5 * 1024 * 1024, 4).unwrap();
        let published = publish_blob_stream(
            std::io::Cursor::new(vec![0x5c; total_len]),
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
        .unwrap();
        let roots = (published.plaintext_root, published.ciphertext_root);
        let wire_len = completed_pack_wire_len(&source_root.0, &open).unwrap();
        let transport = MemoryTransportAdapter::new();
        let mut sender_codec = PlainBlobRecordCodec;
        let mut receiver_codec = PlainBlobRecordCodec;

        let sender = send_completed_pack_inner(
            &transport,
            &open,
            open.encode(),
            PackAccess::Path(&source_root.0),
            roots,
            open.digest().to_vec(),
            None,
            StreamDirection::ToSessionResponder,
            &mut sender_codec,
        );
        let receiver = receive_completed_pack_inner(
            &transport,
            &open,
            BlobStreamSegmentOpener::from_test_key(
                *open.stream_id().as_bytes(),
                open.digest(),
                open.content_epoch(),
                key,
                nonce,
            ),
            PackAccess::Path(&receiver_root.0),
            wire_len,
            limits,
            None,
            None,
            StreamDirection::ToSessionResponder,
            &mut receiver_codec,
        );
        let (sent, received) = tokio::join!(sender, receiver);
        let sent = sent.unwrap();
        let received = received.unwrap();

        assert_eq!(sent.roots, roots);
        assert_eq!(received.roots, roots);
        assert_eq!(sent.wire_bytes, wire_len);
        assert_eq!(received.wire_bytes, wire_len);
        assert_eq!(
            received.pipeline.unwrap().completed_items(),
            published.segment_count
        );
    }

    #[tokio::test]
    async fn receive_transport_failure_cancels_and_joins_pipeline() {
        let source_root = TempRoot::new("cancel-source");
        let receiver_root = TempRoot::new("cancel-receiver");
        let total_len = 3 * BLOB_STREAM_SEGMENT_BYTES + 17;
        let open = open_with_stream_seed(total_len as u64, 0x13);
        let key = [0x67; 32];
        let nonce = [0x77; 12];
        let limits = PipelineLimits::new(2, 4, 5 * 1024 * 1024, 4).unwrap();
        let published = publish_blob_stream(
            std::io::Cursor::new(vec![0x5b; total_len]),
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
        .unwrap();
        let roots = (published.plaintext_root, published.ciphertext_root);
        let wire_len = completed_pack_wire_len(&source_root.0, &open).unwrap();
        let transport = MemoryTransportAdapter::with_receive_failure(Some(2));
        let mut sender_codec = PlainBlobRecordCodec;
        let mut receiver_codec = PlainBlobRecordCodec;

        let sender = send_completed_pack_inner(
            &transport,
            &open,
            open.encode(),
            PackAccess::Path(&source_root.0),
            roots,
            open.digest().to_vec(),
            None,
            StreamDirection::ToSessionResponder,
            &mut sender_codec,
        );
        let receiver = receive_completed_pack_inner(
            &transport,
            &open,
            BlobStreamSegmentOpener::from_test_key(
                *open.stream_id().as_bytes(),
                open.digest(),
                open.content_epoch(),
                key,
                nonce,
            ),
            PackAccess::Path(&receiver_root.0),
            wire_len,
            limits,
            None,
            None,
            StreamDirection::ToSessionResponder,
            &mut receiver_codec,
        );
        let (_sent, received) = tokio::join!(sender, receiver);
        let error = received.expect_err("injected transport failure must terminate receive");

        assert_eq!(error.stage(), BlobNetworkStage::Transport);
        let job = StreamJobId::from_bytes(
            open.stream_id().as_bytes()[..16]
                .try_into()
                .expect("job ID"),
        );
        assert!(!ACTIVE_RECEIVE_PIPELINES.lock().unwrap().contains(&job));
    }

    #[tokio::test]
    async fn completed_pack_crosses_v9_as_verified_checkpointed_segments() {
        let source_root = TempRoot::new("source");
        let receiver_root = TempRoot::new("receiver");
        let total_len = 3 * BLOB_STREAM_SEGMENT_BYTES + 17;
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
                let report = receive_completed_pack(
                    connection.clone(),
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
                .expect("receive");
                connection.close();
                report
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address,
            })
            .await
            .expect("connect");
        let sent = send_completed_pack(
            connection,
            &open,
            open.encode(),
            &source_root.0,
            roots,
            open.digest().to_vec(),
        )
        .await
        .expect("send");
        let received = receiver.await.expect("receiver task");

        assert_eq!(sent.roots, roots);
        assert_eq!(received.roots, roots);
        assert_eq!(sent.wire_bytes, wire_len);
        assert_eq!(received.wire_bytes, wire_len);
        assert_eq!(received.checkpoints, 1);
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

    #[tokio::test]
    async fn receiver_projects_pack_checkpoints_and_promotes_through_store() {
        let source_root = TempRoot::new("store-source");
        let receiver_root = TempRoot::new("store-receiver");
        let total_len = 2 * BLOB_STREAM_SEGMENT_BYTES + 17;
        let topic = Topic::new("imagery").unwrap();
        let scope = Scope::new("mission/alpha").unwrap();
        let access =
            ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()]).unwrap();
        let mut provisioner = ReferenceProvisioner::from_seed([0x84; 32]).unwrap();
        let provider = Arc::new(
            ReferenceEnvelopeSealer::open(
                provisioner.issue_control_authority(1, &[access]).unwrap(),
            )
            .unwrap(),
        );
        let open = BlobStreamOpen::new(
            BlobPublicationStreamId::from_bytes([0x85; 32]).unwrap(),
            provider.identity(),
            b"network-store-session".to_vec(),
            provider.mission_authority_id(),
            1,
            VersionVector::default(),
            topic,
            scope.clone(),
            BlobMetadata::new(Some("application/octet-stream".into()), Vec::new()).unwrap(),
            Priority::Immediate,
            None,
            None,
            total_len as u64,
            1,
            1,
            provider
                .blob_stream_authorization_digest(&scope, 1)
                .unwrap(),
            [0x86; 32],
        )
        .unwrap();
        let signed_open = provider.seal_blob_stream_open(&open).unwrap();
        let verified_open = provider.verify_blob_stream_open(&signed_open).unwrap();
        let limits = PipelineLimits::new(2, 4, 5 * 1024 * 1024, 4).unwrap();
        let published = publish_blob_stream(
            std::io::Cursor::new(vec![0x5d; total_len]),
            verified_open.open(),
            provider.blob_stream_segment_sealer(&verified_open).unwrap(),
            &source_root.0,
            limits,
        )
        .await
        .unwrap();
        let roots = (published.plaintext_root, published.ciphertext_root);
        let commitment = BlobStreamFinalCommitment::new(
            &verified_open,
            roots.0,
            roots.1,
            published.segment_count,
            None,
        )
        .unwrap();
        let signed_commitment = provider.seal_blob_stream_commitment(&commitment).unwrap();
        let wire_len = completed_pack_wire_len(&source_root.0, verified_open.open()).unwrap();
        let store = Arc::new(
            Store::open_for_mission(
                receiver_root.0.join("state.redb"),
                provider.mission_authority_id(),
            )
            .unwrap(),
        );
        let policy = store.control_policy_snapshot().unwrap();
        let receiver_pack = receiver_root.0.join("pack");
        let operation =
            BlobOperationKey::new(verified_open.open().operation_key().to_vec()).unwrap();
        let (reservation, initial) = store
            .reserve_blob_stream_with_policy(
                &policy,
                BlobStreamReservationRequest {
                    operation: &operation,
                    source: BlobStreamSource::AuthenticatedPeer(provider.identity()),
                },
                &verified_open,
            )
            .unwrap();
        let mut source_reader = BlobPackReader::open(&source_root.0, verified_open.open()).unwrap();
        let first_segment = source_reader.next_segment().unwrap().unwrap();
        let (_, first_leaves) = provider
            .blob_stream_segment_opener(&verified_open)
            .unwrap()
            .open(&first_segment)
            .unwrap();
        let mut partial_writer =
            BlobPackWriter::create(&receiver_pack, verified_open.open()).unwrap();
        partial_writer.append(&first_segment, first_leaves).unwrap();
        let partial_checkpoint = partial_writer.checkpoint().unwrap();
        let partial_resume = store
            .checkpoint_blob_stream(&policy, &reservation, initial, partial_checkpoint.clone())
            .unwrap();
        assert_eq!(partial_resume.next_segment_index(), 1);
        assert_eq!(
            partial_resume.durable_wire_offset(),
            partial_checkpoint.payload_len()
        );
        let second_segment = source_reader.next_segment().unwrap().unwrap();
        let (_, second_leaves) = provider
            .blob_stream_segment_opener(&verified_open)
            .unwrap()
            .open(&second_segment)
            .unwrap();
        partial_writer
            .append(&second_segment, second_leaves)
            .unwrap();
        let unprojected_checkpoint = partial_writer.checkpoint().unwrap();
        assert!(unprojected_checkpoint.generation() > partial_resume.generation());
        drop(partial_writer);
        let verifier = {
            let provider = Arc::clone(&provider);
            Arc::new(move |open: &VerifiedBlobStreamOpen, bytes: &[u8]| {
                provider
                    .verify_blob_stream_commitment(open, bytes)
                    .map_err(|error| error.to_string())
            }) as BlobCommitmentVerifier
        };
        let session = BlobReceiveStoreSession::new(
            Arc::clone(&store),
            policy,
            verified_open.clone(),
            signed_open.clone(),
            provider.identity(),
            verifier,
        )
        .unwrap();

        let config = EndpointConfig::direct("127.0.0.1:0".parse().unwrap());
        let server = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .unwrap();
        let client = Endpoint::bind_with_security_profile(
            SecretKey::generate(),
            config,
            CarrierSecurityProfile::IrohQuicV1,
        )
        .await
        .unwrap();
        let address = server
            .bound_sockets()
            .into_iter()
            .find(std::net::SocketAddr::is_ipv4)
            .unwrap();
        let receiver = tokio::spawn({
            let server = server.clone();
            let allowed = BTreeSet::from([client.id()]);
            let root = receiver_pack;
            let opener = provider.blob_stream_segment_opener(&verified_open).unwrap();
            async move {
                let connection = server.accept(&allowed).await.unwrap();
                receive_completed_pack_with_store(
                    connection, session, opener, &root, wire_len, limits,
                )
                .await
            }
        });
        let connection = client
            .connect(ExpectedPeer {
                id: server.id(),
                address,
            })
            .await
            .unwrap();
        let sent = send_completed_pack(
            connection,
            verified_open.open(),
            signed_open,
            &source_root.0,
            roots,
            signed_commitment,
        )
        .await
        .unwrap();
        let received = receiver.await.unwrap().unwrap();

        assert_eq!(sent.roots, roots);
        assert_eq!(received.roots, roots);
        assert_eq!(sent.resumed_from, partial_resume.durable_wire_offset());
        assert_eq!(received.resumed_from, partial_resume.durable_wire_offset());
        assert_eq!(
            sent.attempt_bytes,
            wire_len - partial_resume.durable_wire_offset()
        );
        assert_eq!(received.attempt_bytes, sent.attempt_bytes);
        assert_eq!(
            received.pipeline.as_ref().unwrap().completed_items(),
            published.segment_count - 1
        );
        let publications = store.blob_stream_publications_with_policy(&policy).unwrap();
        assert_eq!(publications.len(), 1);
        assert_eq!(publications[0].blob_id(), commitment.blob_id());
        client.close().await;
        server.close().await;
    }
}
