//! Profile-5 Blob network DAG composition.

use crate::{
    event_pages::TransferProfileId,
    frame::{BlobStreamSourceOfferV1, EventDirection},
    mission::MissionSession,
    stream_pipeline::{
        MappedPartition, PipelineError, PipelineLimits, PipelineReport, StreamJobId,
        StreamPartition, run_ordered_channel_pipeline_from,
    },
    stream_transfer::{
        CanonicalBlobExtentV1, MAX_STREAM_CHECKPOINT_BATCH_BYTES, PROFILE5_CANONICAL_EXTENT_BYTES,
        PROFILE5_IDLE_TIMEOUT, StreamAction, StreamClass, StreamDirection, StreamExtentAction,
        StreamFrame, StreamOpenV1, StreamReceiverState, StreamResultCode, StreamSenderState,
        encode_composite_data_prefix, profile5_attempt_bounds, profile5_attempt_bounds_for_extents,
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
    BlobContentVerification, BlobCustodyTransferId, ContentVerifiedBlobEnvelope,
    ReferenceEnvelopeSealer, VerifiedBlobTransferPlan, profile5_canonical_wire_shape,
};
use aster_redb_store::{
    ApplyOutcome, BlobDepotCompletion, BlobSourceProjection, BlobSourceRetention,
    BlobSourceStageOutcome, BlobStreamResume, BlobTransferId, BlobVariantId, ControlPolicySnapshot,
    Store, StoredBlob,
};
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, future::Future, sync::Arc};
use tokio::sync::mpsc;
use tokio::time::Instant;
use zeroize::Zeroize;

const PROFILE5_SENDER_CARRIER_WINDOW_BYTES: usize = 4 * PROFILE5_CANONICAL_EXTENT_BYTES;
const PROFILE5_SENDER_ENCODING_WINDOW_BYTES: usize = PROFILE5_CANONICAL_EXTENT_BYTES + 4096;
pub(crate) const PROFILE5_SENDER_OWNED_BYTES: usize =
    PROFILE5_SENDER_CARRIER_WINDOW_BYTES + PROFILE5_SENDER_ENCODING_WINDOW_BYTES;

#[cfg(test)]
use crate::stream_transfer::{
    PROFILE5_ATTEMPT_TIMEOUT, PROFILE5_LEGACY_SEGMENT_RECORD_BYTES, blob_pack_wire_len,
};
#[cfg(test)]
use aster_mesh::{BlobStreamOpen, BlobStreamSegmentOpener};
#[cfg(test)]
use aster_redb_store::pack::{
    BlobPackCheckpoint, BlobPackReader, BlobPackWriter, PinnedBlobPackRoot,
};
#[cfg(test)]
use std::path::Path;

/// Capability-bearing canonical send input. Construction requires the
/// source/content-verified transfer plan and the Store's nonconstructible
/// completion proof; a raw `Store + BlobTransferId` is intentionally
/// insufficient.
pub(crate) struct CanonicalBlobSendSource {
    stored: StoredBlob,
    plan: Arc<VerifiedBlobTransferPlan>,
    completion: BlobDepotCompletion,
    finite: Option<(
        ContentVerifiedBlobEnvelope,
        BlobSourceProjection,
        BlobSourceRetention,
    )>,
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
            plan: Arc::new(plan),
            completion,
            finite: None,
        })
    }

    pub(crate) fn new_with_lifetime(
        stored: StoredBlob,
        plan: VerifiedBlobTransferPlan,
        completion: BlobDepotCompletion,
        blob: ContentVerifiedBlobEnvelope,
        projection: BlobSourceProjection,
        retention: BlobSourceRetention,
    ) -> Result<Self, BlobNetworkError> {
        let finite = blob.ttl_ms().is_some();
        let mut source = Self::new(stored, plan, completion)?;
        if finite {
            source.finite = Some((blob, projection, retention));
        }
        Ok(source)
    }

    pub(crate) const fn publication(&self) -> BlobTransferId {
        self.stored.transfer_id
    }

    pub(crate) fn authenticated_open(&self) -> &[u8] {
        &self.stored.sealed
    }

    pub(crate) const fn topic(&self) -> &aster_mesh::Topic {
        &self.stored.header.topic
    }

    pub(crate) const fn scope(&self) -> &aster_mesh::Scope {
        &self.stored.header.scope
    }

    pub(crate) const fn key_epoch(&self) -> u64 {
        self.stored.header.key_epoch
    }

    pub(crate) const fn is_finite(&self) -> bool {
        self.finite.is_some()
    }
}

fn canonical_blob_wire_len(plan: &VerifiedBlobTransferPlan) -> Result<u64, BlobNetworkError> {
    Ok(aster_mesh::profile5_canonical_wire_shape(plan)
        .map_err(|error| verification_failure("derive canonical ABX1 shape", error))?
        .terminal()
        .wire_offset)
}

fn canonical_blob_carrier_len(plan: &VerifiedBlobTransferPlan) -> Result<u64, BlobNetworkError> {
    Ok(aster_mesh::profile5_canonical_wire_shape(plan)
        .map_err(|error| verification_failure("derive canonical ABX1 shape", error))?
        .terminal()
        .carrier_offset)
}

fn canonical_sender_requires_final_checkpoint(
    accepted: StreamAction,
) -> Result<bool, BlobNetworkError> {
    match accepted {
        StreamAction::SendData => Ok(true),
        StreamAction::SendFinish => Ok(false),
        _ => Err("stream acceptance produced an invalid sender action".into()),
    }
}

struct ZeroizingCanonicalCarrier {
    bytes: Vec<u8>,
    _charge: SenderByteCharge,
    #[cfg(test)]
    zeroize_observer: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

struct SenderByteOwnership {
    current: std::sync::atomic::AtomicUsize,
    peak: std::sync::atomic::AtomicUsize,
    encoding_current: std::sync::atomic::AtomicUsize,
    encoding_peak: std::sync::atomic::AtomicUsize,
    #[cfg(test)]
    live_observer: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    peak_observer: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    extent_body_zeroize_observer: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    prefix_header_zeroize_observer: Option<Arc<std::sync::atomic::AtomicUsize>>,
    #[cfg(test)]
    encoded_header_creation_observer: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

impl SenderByteOwnership {
    fn new(sender_job: StreamJobId) -> Self {
        #[cfg(not(test))]
        let _ = sender_job;
        #[cfg(test)]
        let observers =
            crate::stream_pipeline::PipelineTestProbe::sender_ownership_observers_for_job(
                sender_job,
            );
        Self {
            current: std::sync::atomic::AtomicUsize::new(0),
            peak: std::sync::atomic::AtomicUsize::new(0),
            encoding_current: std::sync::atomic::AtomicUsize::new(0),
            encoding_peak: std::sync::atomic::AtomicUsize::new(0),
            #[cfg(test)]
            live_observer: observers
                .as_ref()
                .map(|observers| Arc::clone(&observers.live_bytes)),
            #[cfg(test)]
            peak_observer: observers
                .as_ref()
                .map(|observers| Arc::clone(&observers.peak_live_bytes)),
            #[cfg(test)]
            extent_body_zeroize_observer: observers
                .as_ref()
                .map(|observers| Arc::clone(&observers.extent_body_zeroizations)),
            #[cfg(test)]
            prefix_header_zeroize_observer: observers
                .as_ref()
                .map(|observers| Arc::clone(&observers.prefix_header_zeroizations)),
            #[cfg(test)]
            encoded_header_creation_observer: observers
                .as_ref()
                .map(|observers| Arc::clone(&observers.encoded_header_creations)),
        }
    }

    fn charge(self: &Arc<Self>, bytes: usize) -> SenderByteCharge {
        let current = self
            .current
            .fetch_add(bytes, std::sync::atomic::Ordering::SeqCst)
            + bytes;
        self.peak
            .fetch_max(current, std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        if let Some(live) = &self.live_observer {
            let observed = live.fetch_add(bytes, std::sync::atomic::Ordering::SeqCst) + bytes;
            if let Some(peak) = &self.peak_observer {
                peak.fetch_max(observed, std::sync::atomic::Ordering::SeqCst);
            }
        }
        SenderByteCharge {
            ownership: Arc::clone(self),
            bytes,
            encoding: false,
        }
    }

    fn charge_encoding(self: &Arc<Self>, bytes: usize) -> SenderByteCharge {
        let mut charge = self.charge(bytes);
        charge.encoding = true;
        let current = self
            .encoding_current
            .fetch_add(bytes, std::sync::atomic::Ordering::SeqCst)
            + bytes;
        self.encoding_peak
            .fetch_max(current, std::sync::atomic::Ordering::SeqCst);
        charge
    }

    fn peak(&self) -> usize {
        self.peak.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn encoding_peak(&self) -> usize {
        self.encoding_peak.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[derive(Clone, Copy)]
enum SenderBufferClass {
    ExtentBody,
    EncodedHeader,
    PrefixHeader,
}

struct ZeroizingSenderBuffer {
    bytes: Vec<u8>,
    _charge: SenderByteCharge,
    #[cfg(test)]
    zeroize_observer: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

impl ZeroizingSenderBuffer {
    fn new(bytes: Vec<u8>, ownership: &Arc<SenderByteOwnership>, class: SenderBufferClass) -> Self {
        #[cfg(test)]
        let zeroize_observer = match class {
            SenderBufferClass::ExtentBody => ownership.extent_body_zeroize_observer.clone(),
            SenderBufferClass::EncodedHeader | SenderBufferClass::PrefixHeader => {
                ownership.prefix_header_zeroize_observer.clone()
            }
        };
        #[cfg(test)]
        if matches!(class, SenderBufferClass::EncodedHeader)
            && let Some(observer) = &ownership.encoded_header_creation_observer
        {
            observer.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        #[cfg(not(test))]
        let _ = class;
        Self {
            _charge: ownership.charge_encoding(bytes.len()),
            bytes,
            #[cfg(test)]
            zeroize_observer,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for ZeroizingSenderBuffer {
    fn drop(&mut self) {
        #[cfg(test)]
        let had_bytes = !self.bytes.is_empty();
        self.bytes.zeroize();
        #[cfg(test)]
        if had_bytes && let Some(observer) = self.zeroize_observer.take() {
            observer.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

async fn send_owned_data_parts(
    attempt: &dyn StreamAttempt,
    prefix: ZeroizingSenderBuffer,
    body: ZeroizingSenderBuffer,
    inject_transport_failure: bool,
) -> Result<(), crate::stream_transport::StreamTransportError> {
    #[cfg(test)]
    if inject_transport_failure {
        return Err(crate::stream_transport::StreamTransportError::Closed);
    }
    #[cfg(not(test))]
    let _ = inject_transport_failure;
    attempt
        .send_data_parts(prefix.as_slice(), body.as_slice())
        .await
}

struct SenderByteCharge {
    ownership: Arc<SenderByteOwnership>,
    bytes: usize,
    encoding: bool,
}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct InjectedExtentEncodeError;
#[cfg(test)]
impl std::fmt::Display for InjectedExtentEncodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("injected extent encoding failure")
    }
}
#[cfg(test)]
impl std::error::Error for InjectedExtentEncodeError {}

#[cfg(test)]
#[derive(Debug)]
pub(crate) struct InjectedDataAuthenticationError;
#[cfg(test)]
impl std::fmt::Display for InjectedDataAuthenticationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("injected DATA authentication failure")
    }
}
#[cfg(test)]
impl std::error::Error for InjectedDataAuthenticationError {}

impl Drop for SenderByteCharge {
    fn drop(&mut self) {
        self.ownership
            .current
            .fetch_sub(self.bytes, std::sync::atomic::Ordering::SeqCst);
        if self.encoding {
            self.ownership
                .encoding_current
                .fetch_sub(self.bytes, std::sync::atomic::Ordering::SeqCst);
        }
        #[cfg(test)]
        if let Some(live) = &self.ownership.live_observer {
            live.fetch_sub(self.bytes, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl Drop for ZeroizingCanonicalCarrier {
    fn drop(&mut self) {
        #[cfg(test)]
        let had_ciphertext = !self.bytes.is_empty();
        self.bytes.zeroize();
        #[cfg(test)]
        if had_ciphertext && let Some(observer) = self.zeroize_observer.take() {
            observer.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

struct CanonicalSenderPipelineSink<'a> {
    #[cfg(test)]
    job_id: StreamJobId,
    attempt: &'a dyn StreamAttempt,
    codec: MissionBlobRecordCodec<'a>,
    state: StreamSenderState,
    extent_ends: VecDeque<u64>,
    first_chunk_index: Option<u64>,
    carriers: Vec<MappedPartition<ZeroizingCanonicalCarrier>>,
    checkpoints: u64,
    ownership: Arc<SenderByteOwnership>,
}

impl CanonicalSenderPipelineSink<'_> {
    async fn accept(
        &mut self,
        mapped: MappedPartition<ZeroizingCanonicalCarrier>,
    ) -> Result<(), PipelineError> {
        let index = mapped.index();
        self.first_chunk_index.get_or_insert(index);
        self.carriers.push(mapped);
        if self.extent_ends.front().copied() != Some(index + 1) {
            return Ok(());
        }
        self.extent_ends.pop_front();
        let first_chunk_index = self
            .first_chunk_index
            .take()
            .ok_or_else(|| failure("send canonical extent", "missing canonical extent start"))
            .map_err(pipeline_adapter)?;
        let carriers = std::mem::take(&mut self.carriers);
        let encoded = CanonicalBlobExtentV1::encode_carriers(
            first_chunk_index,
            carriers
                .iter()
                .map(|carrier| carrier.value().bytes.as_slice()),
        )
        .map_err(|error| {
            pipeline_adapter(BlobNetworkError::with_source(
                BlobNetworkStage::Framing,
                "encode canonical extent",
                error,
            ))
        })?;
        let mut encoded =
            ZeroizingSenderBuffer::new(encoded, &self.ownership, SenderBufferClass::ExtentBody);
        #[cfg(test)]
        if crate::stream_pipeline::PipelineTestProbe::sender_sink_failure_for_job(self.job_id) == 1
        {
            return Err(pipeline_adapter(BlobNetworkError::with_source(
                BlobNetworkStage::Framing,
                "encode canonical extent",
                InjectedExtentEncodeError,
            )));
        }
        let mut pending = Some(encoded.take());
        while let Some(extent) = pending.take() {
            match self
                .state
                .send_extent(extent)
                .map_err(|error| pipeline_adapter(failure("advance canonical sender", error)))?
            {
                StreamExtentAction::Send(data) => {
                    let (header, body) = data.into_header_and_body().map_err(|error| {
                        pipeline_adapter(BlobNetworkError::with_source(
                            BlobNetworkStage::Framing,
                            "split data frame",
                            error,
                        ))
                    })?;
                    encoded.bytes = body;
                    #[cfg(test)]
                    let inject_auth =
                        crate::stream_pipeline::PipelineTestProbe::sender_sink_failure_for_job(
                            self.job_id,
                        ) == 2;
                    #[cfg(not(test))]
                    let inject_auth = false;
                    let prefix = self
                        .codec
                        .encode_charged_data_prefix(header, &self.ownership, inject_auth)
                        .map_err(pipeline_adapter)?;
                    if prefix.as_slice().len() > 4096 {
                        return Err(pipeline_adapter(BlobNetworkError::new(
                            BlobNetworkStage::Framing,
                            "bound canonical DATA prefix",
                            "authenticated prefix exceeds sender encoding budget",
                        )));
                    }
                    #[cfg(test)]
                    if let Some((entered, release)) =
                        crate::stream_pipeline::PipelineTestProbe::sender_send_gate_for_job(
                            self.job_id,
                        )
                    {
                        entered.add_permits(1);
                        release
                            .acquire()
                            .await
                            .map_err(|_| PipelineError::WorkerPanicked)?
                            .forget();
                    }
                    #[cfg(test)]
                    let inject_transport_failure =
                        crate::stream_pipeline::PipelineTestProbe::sender_sink_failure_for_job(
                            self.job_id,
                        ) == 3;
                    #[cfg(not(test))]
                    let inject_transport_failure = false;
                    let send = await_authenticated_progress(
                        "send canonical data",
                        send_owned_data_parts(
                            self.attempt,
                            prefix,
                            encoded,
                            inject_transport_failure,
                        ),
                    )
                    .await;
                    drop(carriers);
                    return send.map_err(pipeline_adapter);
                }
                StreamExtentAction::Retry {
                    reason: crate::stream_transfer::StreamRetry::CreditBlocked,
                    bytes,
                } => {
                    encoded.bytes = bytes;
                    let checkpoint = await_authenticated_progress(
                        "receive canonical checkpoint",
                        self.attempt.receive_control(),
                    )
                    .await
                    .map_err(pipeline_adapter)?
                    .ok_or_else(|| {
                        pipeline_adapter(transport_failure(
                            "receive canonical checkpoint",
                            "control stream closed",
                        ))
                    })?;
                    let StreamFrame::Checkpoint(checkpoint) =
                        self.codec.decode(&checkpoint).map_err(pipeline_adapter)?
                    else {
                        return Err(pipeline_adapter(failure(
                            "receive canonical checkpoint",
                            "credit wait received a non-checkpoint frame",
                        )));
                    };
                    self.state.checkpoint(checkpoint).map_err(|error| {
                        pipeline_adapter(failure("advance canonical checkpoint", error))
                    })?;
                    self.checkpoints += 1;
                    pending = Some(encoded.take());
                }
                StreamExtentAction::Retry { .. } => {
                    return Err(pipeline_adapter(failure(
                        "advance canonical sender",
                        "invalid extent retry",
                    )));
                }
            }
        }
        unreachable!("sender extent must finish with a DATA send")
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

#[derive(Clone, Debug)]
pub struct BlobNetworkError {
    stage: BlobNetworkStage,
    context: String,
    detail: String,
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
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
            source: None,
        }
    }

    fn with_source(
        stage: BlobNetworkStage,
        context: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            stage,
            context: context.into(),
            detail: source.to_string(),
            source: Some(Arc::new(source)),
        }
    }

    #[cfg(test)]
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

impl PartialEq for BlobNetworkError {
    fn eq(&self, other: &Self) -> bool {
        self.stage == other.stage && self.context == other.context && self.detail == other.detail
    }
}

impl Eq for BlobNetworkError {}

impl std::error::Error for BlobNetworkError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn std::error::Error + 'static))
    }
}

async fn await_authenticated_progress<T>(
    context: &'static str,
    future: impl Future<Output = Result<T, crate::stream_transport::StreamTransportError>>,
) -> Result<T, BlobNetworkError> {
    tokio::time::timeout(PROFILE5_IDLE_TIMEOUT, future)
        .await
        .map_err(|_| transport_failure(context, "authenticated progress idle timeout"))?
        .map_err(|error| BlobNetworkError::with_source(BlobNetworkStage::Transport, context, error))
}

#[allow(dead_code)] // Task 5 consumes the complete receiver-facing report.
#[derive(Debug)]
pub struct BlobNetworkReport {
    pub wire_bytes: u64,
    pub resumed_from: u64,
    pub attempt_bytes: u64,
    pub roots: ([u8; 32], [u8; 32]),
    pub checkpoints: u64,
    pub pipeline: Option<PipelineReport>,
}

fn failure(context: impl Into<String>, error: impl std::fmt::Display) -> BlobNetworkError {
    BlobNetworkError::new(BlobNetworkStage::Protocol, context, error)
}

fn sender_pipeline_failure(error: PipelineError) -> BlobNetworkError {
    match error {
        PipelineError::Adapter(error) => error
            .downcast_ref::<BlobNetworkError>()
            .cloned()
            .unwrap_or_else(|| failure("run canonical sender pipeline", error)),
        error => failure("run canonical sender pipeline", error),
    }
}

fn pipeline_adapter(error: BlobNetworkError) -> PipelineError {
    PipelineError::Adapter(Arc::new(error))
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

#[cfg(test)]
fn encoded(frame: StreamFrame) -> Result<Vec<u8>, BlobNetworkError> {
    frame.encode_for_context(9, 5).map_err(|error| {
        BlobNetworkError::new(BlobNetworkStage::Framing, "encode stream frame", error)
    })
}

#[cfg(test)]
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

#[cfg(test)]
struct PlainBlobRecordCodec;

#[cfg(test)]
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
        let (header, mut body) = data.into_header_and_body().map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "split data frame", error)
        })?;
        let encoded_header = match header.encode_for_context(9, 5) {
            Ok(header) => header,
            Err(error) => {
                body.zeroize();
                return Err(BlobNetworkError::new(
                    BlobNetworkStage::Framing,
                    "encode data header",
                    error,
                ));
            }
        };
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

impl MissionBlobRecordCodec<'_> {
    fn encode_charged_data_prefix(
        &mut self,
        header: crate::stream_transfer::StreamDataHeaderV1,
        ownership: &Arc<SenderByteOwnership>,
        inject_auth_failure: bool,
    ) -> Result<ZeroizingSenderBuffer, BlobNetworkError> {
        let encoded_header = header
            .encode_for_context(9, TransferProfileId::BlobStreamV1 as u16)
            .map_err(|error| {
                BlobNetworkError::with_source(
                    BlobNetworkStage::Framing,
                    "encode data header",
                    error,
                )
            })?;
        let encoded_header =
            ZeroizingSenderBuffer::new(encoded_header, ownership, SenderBufferClass::EncodedHeader);
        #[cfg(test)]
        if inject_auth_failure {
            return Err(BlobNetworkError::with_source(
                BlobNetworkStage::Authentication,
                "seal data-header mission record",
                InjectedDataAuthenticationError,
            ));
        }
        #[cfg(not(test))]
        let _ = inject_auth_failure;
        let protected_header = self
            .mission
            .seal_v9_blob_data_header(
                self.profile_digest,
                self.direction,
                self.attempt_nonce,
                encoded_header.as_slice(),
            )
            .map_err(|error| {
                BlobNetworkError::with_source(
                    BlobNetworkStage::Authentication,
                    "seal data-header mission record",
                    error,
                )
            })?;
        let protected_header = ZeroizingSenderBuffer::new(
            protected_header,
            ownership,
            SenderBufferClass::PrefixHeader,
        );
        let prefix =
            encode_composite_data_prefix(protected_header.as_slice()).map_err(|error| {
                BlobNetworkError::with_source(
                    BlobNetworkStage::Framing,
                    "encode composite data prefix",
                    error,
                )
            })?;
        Ok(ZeroizingSenderBuffer::new(
            prefix,
            ownership,
            SenderBufferClass::PrefixHeader,
        ))
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
        let (header, mut body) = data.into_header_and_body().map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "split data frame", error)
        })?;
        let encoded_header =
            match header.encode_for_context(9, TransferProfileId::BlobStreamV1 as u16) {
                Ok(header) => header,
                Err(error) => {
                    body.zeroize();
                    return Err(BlobNetworkError::new(
                        BlobNetworkStage::Framing,
                        "encode data header",
                        error,
                    ));
                }
            };
        let protected_header = match self.mission.seal_v9_blob_data_header(
            self.profile_digest,
            self.direction,
            self.attempt_nonce,
            &encoded_header,
        ) {
            Ok(header) => header,
            Err(error) => {
                body.zeroize();
                return Err(authentication_failure(
                    "seal data-header mission record",
                    error,
                ));
            }
        };
        let prefix = match encode_composite_data_prefix(&protected_header) {
            Ok(prefix) => prefix,
            Err(error) => {
                body.zeroize();
                return Err(BlobNetworkError::new(
                    BlobNetworkStage::Framing,
                    "encode composite data prefix",
                    error,
                ));
            }
        };
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

#[cfg(all(feature = "fuzzing", test))]
pub(crate) fn fuzz_protect_profile5_data_extent(
    extent: Vec<u8>,
) -> Result<Vec<u8>, BlobNetworkError> {
    let (mut sender, _receiver, profile_digest) = crate::mission::fuzz_mission_pair();
    MissionBlobRecordCodec {
        mission: &mut sender,
        profile_digest,
        direction: EventDirection::ToSessionResponder,
        attempt_nonce: [0x22; 32],
    }
    .encode(StreamFrame::Data(crate::stream_transfer::StreamDataV1 {
        transfer_id: [0x11; 32],
        attempt_nonce: [0x22; 32],
        sequence: 0,
        offset: 0,
        bytes: extent,
    }))
}

#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_open_profile5_data_extent(
    bytes: &[u8],
) -> Result<crate::stream_transfer::StreamDataV1, BlobNetworkError> {
    let (_sender, mut receiver, profile_digest) = crate::mission::fuzz_mission_pair();
    let frame = MissionBlobRecordCodec {
        mission: &mut receiver,
        profile_digest,
        direction: EventDirection::ToSessionResponder,
        attempt_nonce: [0x22; 32],
    }
    .decode(bytes)?;
    let StreamFrame::Data(data) = frame else {
        return Err("fuzz fixture did not open as profile-5 DATA".into());
    };
    Ok(data)
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

#[allow(dead_code)] // Task 5 receiver admission consumes this staged helper.
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

#[cfg(test)]
fn result_digest(open: &BlobStreamOpen, roots: ([u8; 32], [u8; 32])) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"aster/blob-network-result/v1");
    hasher.update(open.digest());
    hasher.update(roots.0);
    hasher.update(roots.1);
    hasher.finalize().into()
}

#[cfg(test)]
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

#[cfg(test)]
pub(crate) fn completed_pack_wire_len(
    root: &Path,
    open: &BlobStreamOpen,
) -> Result<u64, BlobNetworkError> {
    let reader =
        BlobPackReader::open(root, open).map_err(|error| durability_failure("open pack", error))?;
    Ok(reader.checkpoint().payload_len())
}

#[allow(dead_code)] // The pinned receiver arm is reconnected by Task 5.
#[cfg(test)]
enum PackAccess<'a> {
    Path(&'a Path),
    Pinned(&'a PinnedBlobPackRoot),
}

#[cfg(test)]
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

#[cfg(test)]
pub(crate) fn expected_pack_wire_len(plaintext_len: u64) -> Result<u64, BlobNetworkError> {
    blob_pack_wire_len(plaintext_len).map_err(|error| {
        BlobNetworkError::new(
            BlobNetworkStage::Framing,
            "calculate Blob pack wire length",
            error,
        )
    })
}

#[cfg(test)]
struct PackExtentSource {
    reader: BlobPackReader,
}

#[cfg(test)]
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

#[cfg(test)]
fn protocol_open(
    open: &BlobStreamOpen,
    authenticated_open: &[u8],
    wire_len: u64,
    attempt_nonce: [u8; 32],
    direction: StreamDirection,
) -> StreamOpenV1 {
    let source_len = u32::try_from(authenticated_open.len()).unwrap_or(u32::MAX);
    let source_digest = Sha256::digest(authenticated_open).into();
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

#[cfg(test)]
pub(crate) async fn send_completed_pack(
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
    store: Arc<Store>,
    policy: &ControlPolicySnapshot,
    source: &CanonicalBlobSendSource,
    session: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    attempt_nonce: [u8; 32],
) -> Result<BlobNetworkReport, BlobNetworkError> {
    require_canonical_send_source(&store, policy, source)?;
    let wire_len = canonical_blob_wire_len(&source.plan)?;
    let finite_custody = if let Some((blob, projection, retention)) = &source.finite {
        let exact_len = u64::try_from(source.stored.sealed.len())
            .map_err(|_| "finite canonical source length overflows")?;
        let charge = super::custody_finalization_charge_ms(exact_len)
            .map_err(|error| lifecycle_failure("bound profile-5 custody age", error))?;
        let context = session
            .mint_blob_custody_send_context_v2(direction, 1, attempt_nonce, charge)
            .map_err(|error| authentication_failure("authorize profile-5 custody record", error))?;
        let sample = super::contact_custody_sample()
            .map_err(|error| lifecycle_failure("sample profile-5 custody clock", error))?
            .ok_or_else(|| {
                lifecycle_failure("sample profile-5 custody clock", "clock unavailable")
            })?;
        let authorization = store
            .authorize_finite_blob_send_v2_with_policy(
                policy,
                projection,
                *retention,
                blob,
                &source.stored.sealed,
                context,
                sample,
            )
            .map_err(|error| lifecycle_failure("authorize finite profile-5 source", error))?
            .ok_or_else(|| {
                lifecycle_failure("authorize finite profile-5 source", "source expired")
            })?;
        let (claim, prepared) = authorization
            .into_claim(blob, &source.stored.sealed)
            .map_err(|error| authentication_failure("construct profile-5 custody claim", error))?;
        let custody_frame = session
            .seal_blob_custody_frame_v2(profile_digest, direction, attempt_nonce, &claim)
            .map_err(|error| authentication_failure("seal profile-5 custody claim", error))?;
        let final_sample = super::contact_custody_sample()
            .map_err(|error| lifecycle_failure("finalize profile-5 custody clock", error))?
            .ok_or_else(|| {
                lifecycle_failure("finalize profile-5 custody clock", "clock unavailable")
            })?;
        if !store
            .finalize_finite_blob_send_with_policy(
                policy,
                prepared,
                blob,
                &source.stored.sealed,
                final_sample,
            )
            .map_err(|error| lifecycle_failure("finalize finite profile-5 source", error))?
        {
            return Err(lifecycle_failure(
                "finalize finite profile-5 source",
                "custody authority changed before emission",
            ));
        }
        Some((claim.digest(), custody_frame))
    } else {
        None
    };
    let wire_shape = profile5_canonical_wire_shape(&source.plan)
        .map_err(|error| authentication_failure("derive canonical wire shape", error))?;
    let extent_count = wire_shape.checkpoints().len().saturating_sub(1);
    let (max_data_bytes, max_control_bytes) =
        profile5_attempt_bounds_for_extents(wire_len, extent_count).map_err(|error| {
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
        custody_digest: finite_custody.as_ref().map(|(digest, _)| *digest),
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
    if let Some((_, custody_frame)) = finite_custody {
        await_authenticated_progress(
            "send canonical custody authority",
            attempt.send_data(&custody_frame),
        )
        .await?;
    }
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
    let accepted = state
        .accept(accept)
        .map_err(|error| failure("accept canonical stream", error))?;
    let requires_final_checkpoint = canonical_sender_requires_final_checkpoint(accepted)?;
    let resume_checkpoint = wire_shape
        .checkpoint_for_wire_offset(resume_offset)
        .ok_or("profile-5 resume offset is not a canonical extent boundary")?;
    let initial_chunk_index = resume_checkpoint.next_chunk_index;
    let extent_ends = wire_shape
        .checkpoints()
        .iter()
        .copied()
        .filter(|checkpoint| checkpoint.next_chunk_index > initial_chunk_index)
        .map(|checkpoint| checkpoint.next_chunk_index)
        .collect::<VecDeque<_>>();
    let mut sender_job = [0u8; 16];
    sender_job.copy_from_slice(&transfer_open.transfer_id[..16]);
    sender_job[0] ^= 0x80;
    let sender_job = StreamJobId::from_bytes(sender_job);
    #[cfg(test)]
    let sender_zeroize_observer =
        crate::stream_pipeline::PipelineTestProbe::mapped_ciphertext_observer_for_job(sender_job);
    let (partition_tx, partition_rx) = mpsc::channel(8);
    let producer_plan = Arc::clone(&source.plan);
    let producer = tokio::spawn(async move {
        for index in initial_chunk_index..producer_plan.manifest().chunk_count() {
            let carrier_id = producer_plan.carrier_id(index).map_err(|error| {
                pipeline_adapter(verification_failure(
                    "resolve canonical sender carrier",
                    error,
                ))
            })?;
            let carrier_len = usize::try_from(
                producer_plan
                    .carrier_total_len(&carrier_id.wire_bytes())
                    .map_err(|error| {
                        pipeline_adapter(verification_failure(
                            "bound canonical sender carrier",
                            error,
                        ))
                    })?,
            )
            .map_err(|error| pipeline_adapter(failure("bound canonical sender carrier", error)))?;
            partition_tx
                .send(Ok(StreamPartition::new_accounted(
                    index,
                    index.to_be_bytes().to_vec(),
                    carrier_len,
                )))
                .await
                .map_err(|_| PipelineError::WorkerPanicked)?;
        }
        Ok::<(), PipelineError>(())
    });
    let map_store = Arc::clone(&store);
    let map_plan = Arc::clone(&source.plan);
    let sender_ownership = Arc::new(SenderByteOwnership::new(sender_job));
    let map_ownership = Arc::clone(&sender_ownership);
    let map_session = Arc::new(
        store
            .begin_profile5_sender_read(&source.completion)
            .map_err(|error| durability_failure("open canonical sender read session", error))?,
    );
    let sink = Arc::new(tokio::sync::Mutex::new(CanonicalSenderPipelineSink {
        #[cfg(test)]
        job_id: sender_job,
        attempt: attempt.as_ref(),
        codec,
        state,
        extent_ends,
        first_chunk_index: None,
        carriers: Vec::new(),
        checkpoints: 0,
        ownership: Arc::clone(&sender_ownership),
    }));
    let sink_for_pipeline = Arc::clone(&sink);
    let pipeline_result = run_ordered_channel_pipeline_from(
        sender_job,
        partition_rx,
        initial_chunk_index,
        PipelineLimits::new(4, 128, PROFILE5_SENDER_CARRIER_WINDOW_BYTES, 128)
            .map_err(|error| failure("configure canonical sender pipeline", error))?,
        move |partition| {
            let index = partition.index();
            drop(partition.into_bytes());
            let carrier = map_store
                .read_profile5_sender_carrier(&map_session, &map_plan, index)
                .map_err(|error| {
                    pipeline_adapter(BlobNetworkError::with_source(
                        BlobNetworkStage::Verification,
                        "read canonical sender carrier",
                        error,
                    ))
                })?;
            #[cfg(test)]
            crate::stream_pipeline::PipelineTestProbe::observe_prepared_sender_carrier(sender_job);
            Ok(ZeroizingCanonicalCarrier {
                _charge: map_ownership.charge(carrier.len()),
                bytes: carrier,
                #[cfg(test)]
                zeroize_observer: sender_zeroize_observer.clone(),
            })
        },
        move |mapped| {
            let sink = Arc::clone(&sink_for_pipeline);
            async move { sink.lock().await.accept(mapped).await }
        },
    )
    .await;
    let producer_result = match producer.await {
        Ok(result) => result.map_err(sender_pipeline_failure),
        Err(error) => Err(failure("join canonical sender admission", error)),
    };
    let pipeline = match pipeline_result {
        Ok(report) if sender_ownership.peak() <= PROFILE5_SENDER_OWNED_BYTES => {
            report.include_owned_bytes(sender_ownership.peak(), sender_ownership.encoding_peak())
        }
        Ok(_) => {
            _ = await_authenticated_progress(
                "close canonical data stream after sender ownership overflow",
                attempt.finish_data(),
            )
            .await;
            return Err(failure(
                "run canonical sender pipeline",
                "sender byte ownership exceeded its declared bound",
            ));
        }
        Err(error) => {
            // A local read/map/framing failure must close the sender half so
            // the receiver observes EOF instead of waiting for DATA forever.
            _ = await_authenticated_progress(
                "close canonical data stream after sender pipeline failure",
                attempt.finish_data(),
            )
            .await;
            return Err(sender_pipeline_failure(error));
        }
    };
    if let Err(error) = producer_result {
        _ = await_authenticated_progress(
            "close canonical data stream after sender admission failure",
            attempt.finish_data(),
        )
        .await;
        return Err(error);
    }
    let sink = Arc::try_unwrap(sink)
        .map_err(|_| failure("join canonical sender pipeline", "sink remains shared"))?
        .into_inner();
    if !sink.carriers.is_empty() || !sink.extent_ends.is_empty() {
        _ = await_authenticated_progress(
            "close canonical data stream after incomplete sender pipeline",
            attempt.finish_data(),
        )
        .await;
        return Err(failure(
            "complete canonical sender pipeline",
            "canonical extent batch remained incomplete",
        ));
    }
    let CanonicalSenderPipelineSink {
        mut codec,
        mut state,
        mut checkpoints,
        ..
    } = sink;
    if requires_final_checkpoint {
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
        pipeline: Some(pipeline),
    })
}

/// Receives one canonical profile-5 publication and promotes it exclusively
/// through the ordinary pending-source/depot/application authorities.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn receive_canonical_blob_profile5(
    adapter: &dyn StreamTransportAdapter,
    store: Arc<Store>,
    policy: &ControlPolicySnapshot,
    verifier: &mut ReferenceEnvelopeSealer,
    mission: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    expected_nonce: [u8; 32],
    offer: &BlobStreamSourceOfferV1,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    // The PLAN intentionally discloses no content size. Bound the transport by
    // the selected profile ceiling until authenticated OPEN supplies the exact
    // attempt size.
    let profile_ceiling = aster_mesh::PROFILE5_MAX_CANONICAL_WIRE_BYTES;
    let (max_data_bytes, max_control_bytes) =
        profile5_attempt_bounds(profile_ceiling).map_err(|error| {
            BlobNetworkError::new(BlobNetworkStage::Framing, "bound receive attempt", error)
        })?;
    let attempt = await_authenticated_progress(
        "accept canonical transport attempt",
        adapter.accept_attempt(AttemptOpenRequest {
            deadline: Instant::now() + profile5_attempt_hard_timeout(profile_ceiling),
            max_data_bytes,
            max_control_bytes,
        }),
    )
    .await?;
    let mut codec = MissionBlobRecordCodec {
        mission,
        profile_digest,
        direction,
        attempt_nonce: expected_nonce,
    };
    let opened_custody = if offer.finite {
        let frame = await_authenticated_progress(
            "receive canonical custody authority",
            attempt.receive_data(),
        )
        .await?
        .ok_or("data stream closed before canonical custody authority")?;
        Some(
            codec
                .mission
                .open_blob_custody_frame_v2(profile_digest, direction, expected_nonce, &frame)
                .map_err(|error| {
                    authentication_failure("open profile-5 custody authority", error)
                })?,
        )
    } else {
        None
    };
    let encoded_open =
        await_authenticated_progress("receive canonical open", attempt.receive_data())
            .await?
            .ok_or("data stream closed before canonical open")?;
    let StreamFrame::Open(open) = codec.decode(&encoded_open)? else {
        return Err("first canonical data frame was not OPEN".into());
    };
    let expected_direction = match direction {
        EventDirection::ToSessionInitiator => StreamDirection::ToSessionInitiator,
        EventDirection::ToSessionResponder => StreamDirection::ToSessionResponder,
    };
    if open.class != StreamClass::Blob
        || open.direction != expected_direction
        || open.session_transcript != codec.mission.session_id()
        || open.exchange_id != 1
        || open.transfer_id != offer.transfer_id
        || open.source_transfer_id != offer.transfer_id
        || open.attempt_nonce != expected_nonce
        || open.source_len != offer.source_len
        || open.source_digest != offer.source_digest
        || (open.custody_digest.is_some() != offer.finite)
    {
        return Err(authentication_failure(
            "validate canonical OPEN",
            "OPEN differs from acknowledged PLAN/session or durable-source contract",
        ));
    }

    let sealed = receive_authenticated_source(attempt.as_ref(), &mut codec, &open).await?;
    if u32::try_from(sealed.len()).ok() != Some(offer.source_len)
        || <[u8; 32]>::from(Sha256::digest(&sealed)) != offer.source_digest
        || BlobTransferId::new(Sha256::digest(&sealed).into())
            != BlobTransferId::new(offer.transfer_id)
    {
        return Err(authentication_failure(
            "bind canonical SOURCE",
            "SOURCE differs from acknowledged PLAN identity",
        ));
    }
    let route = verifier
        .verify_blob(&sealed)
        .map_err(|error| authentication_failure("authenticate canonical SOURCE", error))?;
    let BlobContentVerification::ContentVerified {
        blob,
        manifest_bytes,
    } = verifier
        .verify_blob_content(route, &sealed)
        .map_err(|error| authentication_failure("authenticate canonical manifest", error))?
    else {
        return Err(authentication_failure(
            "authenticate canonical manifest",
            "receiver lacks the exact current content grant",
        ));
    };
    let plan = Arc::new(
        blob.transfer_plan(&manifest_bytes)
            .map_err(|error| verification_failure("derive canonical transfer plan", error))?,
    );
    let wire_len = canonical_blob_wire_len(&plan)?;
    let variant = BlobVariantId::for_content(
        blob.blob_id(),
        plan.manifest().content_group(),
        plan.manifest().content_epoch(),
    );
    if (blob.ttl_ms().is_some() != offer.finite)
        || blob.topic() != &offer.topic
        || blob.scope() != &offer.scope
        || blob.key_epoch() != offer.key_epoch
        || open.publication_id != blob.item_id()
        || open.variant_id != *variant.as_bytes()
        || open.total_len != wire_len
        || open.total_len > profile_ceiling
    {
        return Err(authentication_failure(
            "recheck canonical source metadata",
            "authenticated source differs from PLAN/OPEN metadata",
        ));
    }
    verifier
        .verify_current_blob_lineage(&blob)
        .map_err(|error| authentication_failure("recheck canonical lineage", error))?;

    let stage_outcome = if let Some((claim, authority)) = opened_custody {
        let verified = claim
            .verify_authenticated_source(
                authority,
                1,
                BlobCustodyTransferId::from_exact_hash(blob.envelope_id()),
                &blob,
                &sealed,
                claim.prior_cumulative_age_ms(),
            )
            .map_err(|error| authentication_failure("verify profile-5 custody claim", error))?;
        if open.custody_digest != Some(verified.digest()) {
            return Err(authentication_failure(
                "bind profile-5 custody claim",
                "OPEN custody digest differs from authenticated claim",
            ));
        }
        let receiver_sample = super::contact_custody_sample()
            .map_err(|error| lifecycle_failure("sample receiver custody clock", error))?
            .ok_or_else(|| {
                lifecycle_failure("sample receiver custody clock", "clock unavailable")
            })?;
        store
            .stage_verified_finite_blob_source_v2_with_policy(
                policy,
                &blob,
                &sealed,
                &plan,
                verified,
                receiver_sample,
            )
            .map_err(|error| lifecycle_failure("stage finite canonical pending source", error))?
    } else {
        store
            .stage_verified_profile5_blob_source_with_policy(policy, &blob, &sealed, &plan)
            .map_err(|error| lifecycle_failure("stage canonical pending source", error))?
    };
    let source = BlobTransferId::new(offer.transfer_id);
    let already_promoted = stage_outcome == BlobSourceStageOutcome::Duplicate
        && store
            .get_blob(source)
            .map_err(|error| lifecycle_failure("resolve canonical duplicate", error))?
            .is_some();
    let (receipt, mut progress) = store
        .reserve_profile5_receipt(policy, &plan)
        .map_err(|error| lifecycle_failure("reserve profile-5 receipt", error))?;
    if already_promoted {
        let carrier_len = canonical_blob_carrier_len(&plan)?;
        if progress.next_segment_index() != plan.manifest().chunk_count()
            || progress.durable_plaintext_offset() != plan.manifest().total_len()
            || progress.durable_pack_len() != carrier_len
            || progress.durable_wire_offset() != wire_len
        {
            let terminal = BlobStreamResume::profile5(
                progress
                    .generation()
                    .checked_add(1)
                    .ok_or("receipt generation overflow")?,
                plan.manifest().chunk_count(),
                plan.manifest().total_len(),
                carrier_len,
                wire_len,
            );
            progress = store
                .checkpoint_profile5_receipt(&receipt, progress, terminal)
                .map_err(|error| durability_failure("checkpoint canonical duplicate", error))?;
        }
    }
    let mut state = StreamReceiverState::new(
        &open,
        progress.durable_wire_offset(),
        progress.generation(),
        profile5_receive_limit(
            wire_len,
            progress.durable_wire_offset(),
            MAX_STREAM_CHECKPOINT_BATCH_BYTES,
        ),
        PROFILE5_CANONICAL_EXTENT_BYTES as u32,
    )
    .map_err(|error| failure("initialize canonical receiver", error))?;
    let StreamAction::Send(accept) = state
        .accept(MAX_STREAM_CHECKPOINT_BATCH_BYTES)
        .map_err(|error| failure("accept canonical receiver", error))?
    else {
        return Err("canonical receiver did not produce ACCEPT".into());
    };
    await_authenticated_progress(
        "send canonical ACCEPT",
        attempt.send_control(&codec.encode(accept)?),
    )
    .await?;

    let resumed_from = progress.durable_wire_offset();
    let mut job_bytes = [0u8; 16];
    job_bytes.copy_from_slice(&offer.transfer_id[..16]);
    let pipeline_job = StreamJobId::from_bytes(job_bytes);
    #[cfg(test)]
    let mapped_ciphertext_observer =
        crate::stream_pipeline::PipelineTestProbe::mapped_ciphertext_observer_for_job(pipeline_job);
    const MAX_IN_FLIGHT_EXTENTS: usize = 4;
    // A canonical selected-profile extent holds at most fifteen full 64-KiB
    // carriers plus one final short carrier. The channel owns only carriers
    // inside the four-extent byte window below; it is not an independent
    // unbounded queue.
    const MAX_CARRIERS_PER_EXTENT: usize = 16;
    const MAX_IN_FLIGHT_EXTENT_BYTES: usize = 4 * PROFILE5_CANONICAL_EXTENT_BYTES;
    let (partition_tx, partition_rx) =
        mpsc::channel(MAX_IN_FLIGHT_EXTENTS * MAX_CARRIERS_PER_EXTENT);
    let (durable_tx, mut durable_rx) = mpsc::channel(MAX_IN_FLIGHT_EXTENTS);
    let plan_for_map = Arc::clone(&plan);
    let plan_for_sink = Arc::clone(&plan);
    let store_for_sink = Arc::clone(&store);
    let policy_for_sink = *policy;
    let receipt_for_sink = receipt.clone();
    let initial_progress = progress;
    let limits = PipelineLimits::new(4, 8, 1024 * 1024, 8)
        .map_err(|error| failure("configure canonical pipeline", error))?;
    let consumer = run_ordered_channel_pipeline_from(
        pipeline_job,
        partition_rx,
        initial_progress.next_segment_index(),
        limits,
        move |partition| {
            let index = partition.index();
            let through = partition.source_end();
            let encoded_len = partition.len() as u64;
            let expected_id = plan_for_map
                .carrier_id(index)
                .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
            let verified = plan_for_map
                .verify_carrier(&expected_id.wire_bytes(), &partition.into_bytes())
                .map_err(|error| PipelineError::MapFailed(error.to_string()))?;
            #[cfg(test)]
            let verified = if let Some(observer) = mapped_ciphertext_observer.as_ref() {
                verified.observe_zeroize_for_test(Arc::clone(observer))
            } else {
                verified
            };
            if verified.index() != index {
                return Err(PipelineError::MapFailed(
                    "carrier index differs from ABX1 order".to_owned(),
                ));
            }
            Ok((verified, encoded_len, through))
        },
        {
            let mut sink_progress = initial_progress;
            let mut batch = Vec::new();
            move |mapped: MappedPartition<(aster_mesh::VerifiedBlobTransferObject, u64, u64)>| {
                let commit = (|| {
                    let (verified, encoded_len, through) = mapped.into_value();
                    batch.push((verified, encoded_len));
                    if through == 0 {
                        return Ok(None);
                    }
                    let mut plaintext = sink_progress.durable_plaintext_offset();
                    let mut carrier_bytes = sink_progress.durable_pack_len();
                    for (verified, encoded_len) in &batch {
                        plaintext = plaintext
                            .checked_add(u64::from(verified.record().plaintext_len()))
                            .ok_or_else(|| {
                                PipelineError::SinkFailed(
                                    "canonical plaintext progress overflow".into(),
                                )
                            })?;
                        carrier_bytes =
                            carrier_bytes.checked_add(*encoded_len).ok_or_else(|| {
                                PipelineError::SinkFailed(
                                    "canonical carrier progress overflow".into(),
                                )
                            })?;
                    }
                    let expected = sink_progress;
                    let durable = BlobStreamResume::profile5(
                        expected.generation().checked_add(1).ok_or_else(|| {
                            PipelineError::SinkFailed("receipt generation overflow".into())
                        })?,
                        expected
                            .next_segment_index()
                            .checked_add(batch.len() as u64)
                            .ok_or_else(|| {
                                PipelineError::SinkFailed("canonical chunk index overflow".into())
                            })?,
                        plaintext,
                        carrier_bytes,
                        through,
                    );
                    sink_progress = durable;
                    Ok(Some((expected, durable, std::mem::take(&mut batch))))
                })();
                let store = Arc::clone(&store_for_sink);
                let plan = Arc::clone(&plan_for_sink);
                let receipt = receipt_for_sink.clone();
                let durable_tx = durable_tx.clone();
                async move {
                    let Some((expected, durable, extent)) = commit? else {
                        return Ok(());
                    };
                    let committed = tokio::task::spawn_blocking(move || {
                        store.commit_verified_profile5_batch_with_policy(
                            &policy_for_sink,
                            &receipt,
                            expected,
                            durable,
                            &plan,
                            &extent,
                        )
                    })
                    .await
                    .map_err(|error| PipelineError::SinkFailed(error.to_string()))?
                    .map_err(|error| PipelineError::SinkFailed(error.to_string()))?;
                    durable_tx.send(committed).await.map_err(|_| {
                        PipelineError::SinkFailed(
                            "receiver stopped before durability result".into(),
                        )
                    })
                }
            }
        },
    );
    let producer = async {
        let mut submitted_next = initial_progress.next_segment_index();
        let mut durable_progress = initial_progress;
        let mut last_announced = resumed_from;
        let mut checkpoints = 0u64;
        let mut in_flight_extents = VecDeque::<(u64, usize)>::new();
        let mut in_flight_extent_bytes = 0usize;
        while submitted_next < plan.manifest().chunk_count() {
            while in_flight_extents.len() >= MAX_IN_FLIGHT_EXTENTS
                || in_flight_extent_bytes
                    > MAX_IN_FLIGHT_EXTENT_BYTES.saturating_sub(PROFILE5_CANONICAL_EXTENT_BYTES)
            {
                durable_progress = durable_rx.recv().await.ok_or_else(|| {
                    durability_failure(
                        "checkpoint canonical pipeline window",
                        "durable progress channel closed",
                    )
                })?;
                while in_flight_extents
                    .front()
                    .is_some_and(|(through, _)| *through <= durable_progress.durable_wire_offset())
                {
                    let (_, bytes) = in_flight_extents
                        .pop_front()
                        .expect("front was present while retiring durable extent");
                    in_flight_extent_bytes = in_flight_extent_bytes.saturating_sub(bytes);
                }
            }
            let encoded =
                await_authenticated_progress("receive canonical DATA", attempt.receive_data())
                    .await?
                    .ok_or("data stream closed before canonical completion")?;
            let frame = codec.decode(&encoded)?;
            let StreamFrame::Data(data) = frame else {
                return Err("canonical content phase received a non-DATA frame".into());
            };
            let through = match state
                .data(&data)
                .map_err(|error| failure("advance canonical receiver", error))?
            {
                StreamAction::Persist { through } => through,
                StreamAction::Retry(_) => continue,
                _ => return Err("canonical receiver produced an invalid DATA action".into()),
            };
            let extent = CanonicalBlobExtentV1::decode(&data.bytes)
                .map_err(|error| verification_failure("decode ABX1 extent", error))?;
            let extent_bytes = data.bytes.len();
            if extent.first_chunk_index != submitted_next || extent.carriers.is_empty() {
                return Err(verification_failure(
                    "order ABX1 extent",
                    "extent is empty or its chunk index differs from submitted progress",
                ));
            }
            let carrier_count = extent.carriers.len();
            for (offset, carrier) in extent.carriers.into_iter().enumerate() {
                let index = submitted_next
                    .checked_add(offset as u64)
                    .ok_or("canonical chunk index overflow")?;
                let extent_end = if offset + 1 == carrier_count {
                    through
                } else {
                    0
                };
                partition_tx
                    .send(Ok(StreamPartition::new_at(index, extent_end, carrier)))
                    .await
                    .map_err(|_| failure("partition canonical extent", "pipeline stopped"))?;
            }
            submitted_next = submitted_next
                .checked_add(carrier_count as u64)
                .ok_or("canonical chunk index overflow")?;
            in_flight_extents.push_back((through, extent_bytes));
            #[cfg(test)]
            crate::stream_pipeline::PipelineTestProbe::observe_received_extent(pipeline_job);
            in_flight_extent_bytes = in_flight_extent_bytes
                .checked_add(extent_bytes)
                .ok_or("canonical extent window byte overflow")?;
            debug_assert!(in_flight_extents.len() <= MAX_IN_FLIGHT_EXTENTS);
            debug_assert!(in_flight_extent_bytes <= MAX_IN_FLIGHT_EXTENT_BYTES);
            if through == wire_len
                || through.saturating_sub(last_announced)
                    >= u64::from(MAX_STREAM_CHECKPOINT_BATCH_BYTES)
            {
                while durable_progress.durable_wire_offset() < through {
                    durable_progress = durable_rx.recv().await.ok_or_else(|| {
                        durability_failure(
                            "checkpoint canonical pipeline",
                            "durable progress channel closed",
                        )
                    })?;
                    while in_flight_extents.front().is_some_and(|(boundary, _)| {
                        *boundary <= durable_progress.durable_wire_offset()
                    }) {
                        let (_, bytes) = in_flight_extents
                            .pop_front()
                            .expect("front was present while checkpointing durable extent");
                        in_flight_extent_bytes = in_flight_extent_bytes.saturating_sub(bytes);
                    }
                }
                let new_limit =
                    profile5_receive_limit(wire_len, through, MAX_STREAM_CHECKPOINT_BATCH_BYTES);
                let StreamAction::Send(checkpoint) = state
                    .persisted(through, durable_progress.generation(), new_limit)
                    .map_err(|error| failure("persist canonical checkpoint", error))?
                else {
                    return Err("canonical receiver did not produce CHECKPOINT".into());
                };
                await_authenticated_progress(
                    "send canonical CHECKPOINT",
                    attempt.send_control(&codec.encode(checkpoint)?),
                )
                .await?;
                last_announced = through;
                checkpoints += 1;
            }
        }
        drop(partition_tx);
        Ok::<_, BlobNetworkError>((durable_progress, checkpoints))
    };
    let consumer = async {
        consumer.await.map_err(|error| match error {
            PipelineError::MapFailed(_) => {
                verification_failure("authenticate ASTRBT01 carrier", error)
            }
            PipelineError::SinkFailed(_) => {
                durability_failure("commit canonical carrier batch", error)
            }
            _ => failure("run canonical receive pipeline", error),
        })
    };
    let mut producer = Box::pin(producer);
    let mut consumer = Box::pin(consumer);
    let (producer_result, consumer_result) = tokio::select! {
        // A transport/source failure closes the partition sender when the
        // producer future completes. Drain every already-admitted carrier to
        // its durable extent boundary before reporting that failure. A
        // verification/sink failure instead returns immediately and dropping
        // the producer cancels further transport intake.
        result = &mut consumer => {
            match result {
                Err(error) => {
                    // A map/sink failure cancels transport intake immediately.
                    // Close the control half as well so the peer does not wait
                    // indefinitely for a checkpoint from a failed receiver.
                    let _ = attempt.finish_control().await;
                    return Err(error);
                }
                Ok(report) => (producer.as_mut().await, Ok(report)),
            }
        }
        result = &mut producer => (result, consumer.as_mut().await),
    };
    let (_durable_progress, checkpoints) = producer_result?;
    let pipeline_report = consumer_result?;
    drop(producer);
    drop(consumer);

    let encoded_finish =
        await_authenticated_progress("receive canonical FINISH", attempt.receive_data())
            .await?
            .ok_or("data stream closed before canonical FINISH")?;
    let StreamFrame::Finish(finish) = codec.decode(&encoded_finish)? else {
        return Err("canonical terminal data frame was not FINISH".into());
    };
    if finish.semantic_commitment.as_slice() != plan.manifest_digest() {
        return Err(verification_failure(
            "validate canonical FINISH",
            "semantic commitment differs from authenticated manifest",
        ));
    }
    let StreamAction::Promote = state
        .finish(finish)
        .map_err(|error| settlement_failure("finish canonical receiver", error))?
    else {
        return Err("canonical receiver did not request promotion".into());
    };

    let code = if already_promoted {
        // Re-run the exact receipt gate after FINISH so policy/lifecycle changes
        // cannot turn a terminal retry into an acknowledgement of stale state.
        store
            .reserve_profile5_receipt(policy, &plan)
            .map_err(|error| lifecycle_failure("recheck promoted profile-5 receipt", error))?;
        StreamResultCode::AlreadyPresent
    } else {
        let depot_completion = store
            .completed_pending_blob_with_policy(policy, source, &blob, &manifest_bytes, &plan)
            .map_err(|error| durability_failure("complete canonical depot", error))?;
        let depot = store
            .blob_depot_for_pending_completion_verification(source, &depot_completion)
            .map_err(|error| durability_failure("open canonical verification depot", error))?;
        let content_completion = {
            let mut service = verifier
                .blob_service_with_store(blob.scope(), blob.topic(), blob.key_epoch(), depot)
                .map_err(|error| verification_failure("open canonical content verifier", error))?;
            service
                .verify_blob_content_completion(&blob, &manifest_bytes)
                .map_err(|error| {
                    verification_failure("verify canonical content completion", error)
                })?
        };
        let lineage = verifier
            .verify_current_blob_lineage(&blob)
            .map_err(|error| {
                authentication_failure("recheck canonical promotion lineage", error)
            })?;
        match store
            .apply_verified_profile5_blob_with_policy(
                policy,
                &plan,
                &lineage,
                &depot_completion,
                &content_completion,
            )
            .map_err(|error| lifecycle_failure("promote canonical Blob", error))?
        {
            ApplyOutcome::Inserted { .. } => StreamResultCode::Promoted,
            ApplyOutcome::Duplicate { .. } => StreamResultCode::AlreadyPresent,
        }
    };
    let roots = (*blob.blob_id().as_bytes(), *plan.manifest_digest());
    let digest = canonical_result_digest(&open, roots);
    let StreamAction::Send(result) = state
        .promoted(code, digest)
        .map_err(|error| settlement_failure("build canonical RESULT", error))?
    else {
        return Err("canonical receiver did not produce RESULT".into());
    };
    await_authenticated_progress(
        "send canonical RESULT",
        attempt.send_control(&codec.encode(result)?),
    )
    .await?;
    let encoded_ack = await_authenticated_progress("receive canonical ACK", attempt.receive_data())
        .await?
        .ok_or("data stream closed before canonical ACK")?;
    let StreamFrame::ResultAck(ack) = codec.decode(&encoded_ack)? else {
        return Err("canonical settlement frame was not ACK".into());
    };
    if !matches!(
        state
            .result_ack(ack, code)
            .map_err(|error| settlement_failure("settle canonical receiver", error))?,
        StreamAction::Terminal(terminal) if terminal == code
    ) {
        return Err("canonical receiver settlement did not terminate".into());
    }
    store
        .complete_profile5_receipt(&receipt)
        .map_err(|error| durability_failure("retire profile-5 receipt", error))?;
    await_authenticated_progress("finish canonical control stream", attempt.finish_control())
        .await?;
    Ok(BlobNetworkReport {
        wire_bytes: wire_len,
        resumed_from,
        attempt_bytes: wire_len.saturating_sub(resumed_from),
        roots,
        checkpoints,
        pipeline: Some(pipeline_report),
    })
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
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
    let accepted = state
        .accept(accept)
        .map_err(|error| failure("accept stream", error))?;
    let mut source = PackExtentSource::new_at(&root, open, resume_offset)?;
    let requires_final_checkpoint = canonical_sender_requires_final_checkpoint(accepted)?;
    let mut pending = if requires_final_checkpoint {
        source.next_extent()?
    } else {
        None
    };
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
    if requires_final_checkpoint {
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
    }
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

#[cfg(test)]
struct RecordPartitioner {
    next_index: u64,
    consumed: u64,
    max_record_bytes: usize,
}

#[cfg(test)]
impl RecordPartitioner {
    fn new(next_index: u64, consumed: u64) -> Self {
        Self {
            next_index,
            consumed,
            max_record_bytes: PROFILE5_LEGACY_SEGMENT_RECORD_BYTES,
        }
    }

    #[cfg(test)]
    fn with_max_record_bytes_for_test(mut self, max_record_bytes: usize) -> Self {
        assert!(
            max_record_bytes > 0 && max_record_bytes <= PROFILE5_LEGACY_SEGMENT_RECORD_BYTES,
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
#[cfg(test)]
struct DurableProgress {
    wire_offset: u64,
    checkpoint: BlobPackCheckpoint,
}

#[cfg(test)]
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

#[cfg(test)]
pub(crate) async fn receive_completed_pack(
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
        CompletedPackReceive {
            transport: transport.as_ref(),
            open,
            opener,
            root: PackAccess::Path(root),
            wire_len,
            limits,
            direction: StreamDirection::ToSessionResponder,
        },
        &mut codec,
    )
    .await
}

#[cfg(test)]
struct CompletedPackReceive<'a> {
    transport: &'a dyn StreamTransportAdapter,
    open: &'a BlobStreamOpen,
    opener: BlobStreamSegmentOpener,
    root: PackAccess<'a>,
    wire_len: u64,
    limits: PipelineLimits,
    direction: StreamDirection,
}

#[cfg(test)]
async fn receive_completed_pack_inner(
    context: CompletedPackReceive<'_>,
    codec: &mut dyn BlobRecordCodec,
) -> Result<BlobNetworkReport, BlobNetworkError> {
    let CompletedPackReceive {
        transport,
        open,
        opener,
        root,
        wire_len,
        limits,
        direction,
    } = context;
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
    receive_authenticated_source(attempt.as_ref(), codec, &transfer_open).await?;
    if transfer_open.class != StreamClass::Blob
        || transfer_open.direction != direction
        || transfer_open.total_len != wire_len
        || transfer_open.session_transcript != open.digest()
        || transfer_open.publication_id != *open.stream_id().as_bytes()
    {
        return Err(authentication_failure(
            "validate transport open",
            "open differs from authenticated Blob open",
        ));
    }
    let resume = BlobStreamResume::default();
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
        PROFILE5_CANONICAL_EXTENT_BYTES as u32,
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
    let StreamAction::Promote = state
        .finish(finish)
        .map_err(|error| failure("finish receiver state", error))?
    else {
        return Err("receiver did not reach promotion".into());
    };
    let result_code = StreamResultCode::Promoted;
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
pub(crate) mod tests {
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
        BLOB_STREAM_SEGMENT_BYTES, BlobMetadata, BlobPublicationStreamId, BlobStreamOpen,
        BlobStreamSegmentOpener, BlobStreamSegmentSealer, Priority, ProvisioningAccess,
        ProvisioningBundle, ReferenceEnvelopeSealer, ReferenceProvisioner, Scope, Topic,
        VersionVector,
    };
    use std::{
        collections::BTreeSet,
        sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        },
    };

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct PendingSendAttempt {
        entered: Arc<tokio::sync::Semaphore>,
    }

    impl StreamAttempt for PendingSendAttempt {
        fn send_data<'a>(&'a self, _frame: &'a [u8]) -> AdapterFuture<'a, ()> {
            Box::pin(async { Ok(()) })
        }

        fn send_data_parts<'a>(
            &'a self,
            _prefix: &'a [u8],
            _body: &'a [u8],
        ) -> AdapterFuture<'a, ()> {
            self.entered.add_permits(1);
            Box::pin(std::future::pending())
        }

        fn receive_control(&self) -> AdapterFuture<'_, Option<Vec<u8>>> {
            Box::pin(async { Ok(None) })
        }

        fn finish_data(&self) -> AdapterFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }
    }

    #[tokio::test]
    async fn cancelling_blocked_sender_send_zeroizes_every_owned_class_and_reclaims_bytes() {
        let job = StreamJobId::from_bytes([0x91; 16]);
        let probe = crate::stream_pipeline::PipelineTestProbe::install(job);
        let ownership = Arc::new(SenderByteOwnership::new(job));
        let entered = Arc::new(tokio::sync::Semaphore::new(0));
        let attempt = Arc::new(PendingSendAttempt {
            entered: Arc::clone(&entered),
        });
        let carrier_observer =
            crate::stream_pipeline::PipelineTestProbe::mapped_ciphertext_observer_for_job(job);
        let task = tokio::spawn({
            let ownership = Arc::clone(&ownership);
            async move {
                let _carrier = ZeroizingCanonicalCarrier {
                    bytes: vec![0x11; 128],
                    _charge: ownership.charge(128),
                    zeroize_observer: carrier_observer,
                };
                let body = ZeroizingSenderBuffer::new(
                    vec![0x22; 256],
                    &ownership,
                    SenderBufferClass::ExtentBody,
                );
                let prefix = ZeroizingSenderBuffer::new(
                    vec![0x33; 64],
                    &ownership,
                    SenderBufferClass::PrefixHeader,
                );
                send_owned_data_parts(attempt.as_ref(), prefix, body, false).await
            }
        });
        entered
            .acquire()
            .await
            .expect("blocked transport entered")
            .forget();
        task.abort();
        assert!(task.await.expect_err("send task cancelled").is_cancelled());
        assert_eq!(probe.mapped_ciphertext_zeroizations(), 1);
        assert_eq!(probe.sender_extent_body_zeroizations(), 1);
        assert_eq!(probe.sender_prefix_header_zeroizations(), 1);
        assert_eq!(probe.sender_live_bytes(), 0);
        assert_eq!(probe.sender_peak_live_bytes(), 128 + 256 + 64);
        assert_eq!(
            ownership.current.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(
            ownership
                .encoding_current
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

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

    pub(crate) fn mission_pair_from_bundles(
        initiator_bytes: &[u8],
        responder_bytes: &[u8],
    ) -> (MissionSession, MissionSession, [u8; 32]) {
        let initiator_identity =
            ReferenceEnvelopeSealer::open(ProvisioningBundle::from_bytes(initiator_bytes).unwrap())
                .unwrap()
                .identity();
        let responder_identity =
            ReferenceEnvelopeSealer::open(ProvisioningBundle::from_bytes(responder_bytes).unwrap())
                .unwrap()
                .identity();
        let initiator_carrier = SecretKey::generate();
        let responder_carrier = SecretKey::generate();
        let (initiator, first) = MissionSessionInitiator::start(
            ProvisioningBundle::from_bytes(initiator_bytes).unwrap(),
            MissionPeerBinding::new(responder_carrier.public(), responder_identity),
            responder_carrier.public(),
        )
        .unwrap();
        let responder = MissionSessionResponder::open(
            ProvisioningBundle::from_bytes(responder_bytes).unwrap(),
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
        mission_pair_from_bundles(&initiator_bytes, &responder_bytes)
    }

    #[test]
    fn fully_checkpointed_runtime_retry_settles_exactly_once() {
        let transfer_id = [0x51; 32];
        let attempt_nonce = [0x52; 32];
        let total = 1024;
        let mut sender = StreamSenderState::new(transfer_id, attempt_nonce, total);

        let action = sender
            .accept(crate::stream_transfer::StreamAcceptV1 {
                transfer_id,
                attempt_nonce,
                sequence: 0,
                durable_offset: total,
                checkpoint_generation: 9,
                absolute_receive_limit: total,
                max_extent_bytes: PROFILE5_CANONICAL_EXTENT_BYTES as u32,
                checkpoint_batch_bytes: MAX_STREAM_CHECKPOINT_BATCH_BYTES,
            })
            .expect("fully checkpointed ACCEPT");

        assert_eq!(action, StreamAction::SendFinish);
        assert!(!canonical_sender_requires_final_checkpoint(action).unwrap());
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
                topic: Topic::new("imagery").unwrap(),
                scope: Scope::new("mission/alpha").unwrap(),
                key_epoch: 1,
                source_len,
                source_digest,
                finite: false,
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
        assert_eq!(
            crate::stream_validation::decode_validation_extent(&decoded.bytes).unwrap(),
            extent,
            "production DATA must decode through the public validation path",
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

    #[cfg(feature = "fuzzing")]
    #[test]
    fn deterministic_profile5_fuzz_header_fixture_matches_production_codec() {
        for (seed, fixture) in [
            (
                include_bytes!(
                    "../../../../fuzz/corpus/stream_transfer_decode/profile5-composite-valid.bin"
                )
                .as_slice(),
                include_bytes!("../../../../conformance/profile5-protected-data-header.bin")
                    .as_slice(),
            ),
            (
                include_bytes!(
                    "../../../../fuzz/corpus/stream_transfer_decode/profile5-composite-maximum.bin"
                )
                .as_slice(),
                include_bytes!(
                    "../../../../conformance/profile5-protected-data-header-maximum.bin"
                )
                .as_slice(),
            ),
        ] {
            let (_, extent) = crate::stream_transfer::split_composite_data_record(seed).unwrap();
            let protected = super::fuzz_protect_profile5_data_extent(extent.to_vec()).unwrap();
            let (header, _) =
                crate::stream_transfer::split_composite_data_record(&protected).unwrap();
            assert!(header.starts_with(b"ASTRFR01"));
            assert_eq!(header, fixture);
        }
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
                usize::try_from((TOTAL - offset).min(PROFILE5_CANONICAL_EXTENT_BYTES as u64))
                    .unwrap();
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
        pending_data_send_entered: Option<Arc<tokio::sync::Semaphore>>,
    }

    struct SmallMtuSenderAttempt {
        data: mpsc::UnboundedSender<Option<Vec<u8>>>,
        control: tokio::sync::Mutex<mpsc::UnboundedReceiver<Option<Vec<u8>>>>,
    }

    impl StreamAttempt for SmallMtuSenderAttempt {
        fn send_data<'a>(&'a self, frame: &'a [u8]) -> AdapterFuture<'a, ()> {
            Box::pin(async move {
                let mut reassembled = Vec::with_capacity(frame.len());
                for fragment in frame.chunks(3) {
                    reassembled.extend_from_slice(fragment);
                }
                self.data
                    .send(Some(reassembled))
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
                self.send_data(&frame).await
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
                if let Some(entered) = &self.pending_data_send_entered {
                    entered.add_permits(1);
                    std::future::pending::<()>().await;
                }
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

    pub(crate) struct MemoryTransportAdapter {
        sender: Arc<MemorySenderAttempt>,
        receiver: Arc<MemoryReceiverAttempt>,
    }

    pub(crate) struct PendingDataSendControl {
        entered: Arc<tokio::sync::Semaphore>,
        data: mpsc::UnboundedSender<Option<Vec<u8>>>,
    }

    impl PendingDataSendControl {
        pub(crate) async fn wait_entered(&self) {
            self.entered
                .acquire()
                .await
                .expect("pending DATA sender remains open")
                .forget();
        }

        pub(crate) fn close_data(&self) {
            let _ = self.data.send(None);
        }
    }

    impl MemoryTransportAdapter {
        pub(crate) fn new() -> Self {
            Self::with_receive_failure(None)
        }

        pub(crate) fn with_receive_failure(fail_after_receives: Option<usize>) -> Self {
            let (data_send, data_receive) = mpsc::unbounded_channel();
            let (control_send, control_receive) = mpsc::unbounded_channel();
            Self {
                sender: Arc::new(MemorySenderAttempt {
                    data: data_send,
                    control: tokio::sync::Mutex::new(control_receive),
                    pending_data_send_entered: None,
                }),
                receiver: Arc::new(MemoryReceiverAttempt {
                    data: tokio::sync::Mutex::new(data_receive),
                    control: control_send,
                    fail_after_receives,
                    receives: std::sync::atomic::AtomicUsize::new(0),
                }),
            }
        }

        pub(crate) fn with_pending_data_send() -> (Self, PendingDataSendControl) {
            let (data_send, data_receive) = mpsc::unbounded_channel();
            let (control_send, control_receive) = mpsc::unbounded_channel();
            let entered = Arc::new(tokio::sync::Semaphore::new(0));
            let control = PendingDataSendControl {
                entered: Arc::clone(&entered),
                data: data_send.clone(),
            };
            (
                Self {
                    sender: Arc::new(MemorySenderAttempt {
                        data: data_send,
                        control: tokio::sync::Mutex::new(control_receive),
                        pending_data_send_entered: Some(entered),
                    }),
                    receiver: Arc::new(MemoryReceiverAttempt {
                        data: tokio::sync::Mutex::new(data_receive),
                        control: control_send,
                        fail_after_receives: None,
                        receives: std::sync::atomic::AtomicUsize::new(0),
                    }),
                },
                control,
            )
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

    pub(crate) struct SmallMtuTransportAdapter {
        sender: Arc<SmallMtuSenderAttempt>,
        receiver: Arc<MemoryReceiverAttempt>,
    }

    impl SmallMtuTransportAdapter {
        pub(crate) fn with_receive_failure(fail_after_receives: usize) -> Self {
            let (data_send, data_receive) = mpsc::unbounded_channel();
            let (control_send, control_receive) = mpsc::unbounded_channel();
            Self {
                sender: Arc::new(SmallMtuSenderAttempt {
                    data: data_send,
                    control: tokio::sync::Mutex::new(control_receive),
                }),
                receiver: Arc::new(MemoryReceiverAttempt {
                    data: tokio::sync::Mutex::new(data_receive),
                    control: control_send,
                    fail_after_receives: Some(fail_after_receives),
                    receives: std::sync::atomic::AtomicUsize::new(0),
                }),
            }
        }
    }

    impl StreamTransportAdapter for SmallMtuTransportAdapter {
        fn id(&self) -> StreamTransportId {
            StreamTransportId::IrohQuicV1
        }

        fn eligibility(&self, requirements: TransferRequirements) -> bool {
            requirements.reliable_ordered && requirements.full_duplex
        }

        fn health(&self) -> CandidateHealth {
            CandidateHealth::Degraded
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
    async fn legacy_pack_source_preserves_one_record_per_transport_extent() {
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
        let legacy_record_bytes = crate::stream_transfer::PROFILE5_LEGACY_RECORD_PREFIX_BYTES
            + crate::stream_transfer::PROFILE5_LEGACY_SEGMENT_RECORD_BYTES;
        assert_eq!(extents[0].len(), legacy_record_bytes);
        assert_eq!(extents[1].len(), legacy_record_bytes);
        assert!(legacy_record_bytes > PROFILE5_CANONICAL_EXTENT_BYTES);
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
        let mut bytes =
            vec![0; declared + crate::stream_transfer::PROFILE5_LEGACY_RECORD_PREFIX_BYTES];
        bytes[..crate::stream_transfer::PROFILE5_LEGACY_RECORD_PREFIX_BYTES]
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
        let total_len = PROFILE5_CANONICAL_EXTENT_BYTES
            - crate::stream_transfer::PROFILE5_LEGACY_RECORD_PREFIX_BYTES
            - aster_mesh::BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES;
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
            CompletedPackReceive {
                transport: &transport,
                open: &open,
                opener: BlobStreamSegmentOpener::from_test_key(
                    *open.stream_id().as_bytes(),
                    open.digest(),
                    open.content_epoch(),
                    key,
                    nonce,
                ),
                root: PackAccess::Path(&receiver_root.0),
                wire_len,
                limits,
                direction: StreamDirection::ToSessionResponder,
            },
            &mut receiver_codec,
        );
        let (sent, received) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(sender, receiver)
        })
        .await
        .expect("selected transport adapter round-trip must remain bounded");
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
    async fn oversized_legacy_pack_extent_fails_without_hanging_receiver() {
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
            CompletedPackReceive {
                transport: &transport,
                open: &open,
                opener: BlobStreamSegmentOpener::from_test_key(
                    *open.stream_id().as_bytes(),
                    open.digest(),
                    open.content_epoch(),
                    key,
                    nonce,
                ),
                root: PackAccess::Path(&receiver_root.0),
                wire_len,
                limits,
                direction: StreamDirection::ToSessionResponder,
            },
            &mut receiver_codec,
        );
        let error = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::try_join!(sender, receiver)
        })
        .await
        .expect("oversized legacy extent rejection must remain bounded")
        .expect_err("legacy record above the profile-5 extent bound must fail");

        assert_eq!(error.stage(), BlobNetworkStage::Protocol);
    }

    #[tokio::test]
    async fn completed_pack_crosses_v9_as_verified_checkpointed_segments() {
        let source_root = TempRoot::new("source");
        let receiver_root = TempRoot::new("receiver");
        let total_len = PROFILE5_CANONICAL_EXTENT_BYTES
            - crate::stream_transfer::PROFILE5_LEGACY_RECORD_PREFIX_BYTES
            - aster_mesh::BLOB_STREAM_SEGMENT_ENCODED_OVERHEAD_BYTES;
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
}
