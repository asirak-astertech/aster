//! Semantic-v9/profile-5 Blob stream runtime.
//!
//! Network attempts may receive ahead, but only Store-confirmed cumulative
//! checkpoints update the public durable position or recovery authority.

use crate::application::{
    BlobStreamTerminalCategory, BlobStreamTransferPhase, BlobStreamTransferStatus,
};
use crate::{
    frame::{BlobInterest, BlobStreamPlanSelectionV1, BlobStreamPlanV1},
    mission::MissionSession,
    stream_transfer::{
        MAX_STREAM_CHECKPOINT_BATCH_BYTES, MAX_STREAM_EXTENT_BYTES, StreamAction, StreamDataV1,
        StreamDirection, StreamFrame, StreamOpenV1, StreamReceiverState, StreamResultCode,
        StreamSenderState,
    },
    stream_transport::{
        AttemptOpenRequest, AuthenticatedPeerSupport, AuthenticatedSupportSource,
        IrohQuicV1Adapter, StreamAttempt, StreamReceiveAttempt, StreamTransportAdapter,
        StreamTransportError, StreamTransportId, TransferRequirements, TransportCandidate,
        TransportSelector,
    },
};
use aster_mesh::{BlobStreamLayout, VerifiedBlobTransferPlan};
use aster_redb_store::{
    BlobStreamCheckpoint, BlobStreamCommitOutcome, BlobTransferId, BlobVariantId,
    ControlPolicySnapshot, Store, VerifiedBlobStreamCheckpointBatch,
};
use sha2::{Digest as _, Sha256};
use std::{sync::Arc, time::Duration};

use super::{
    BlobContactMode, BlobStreamTransport, CompletedBlobStreamSource, EventDirection,
    EventLaneGuard, MutableApplyDisposition, NodeError, PendingBlobRecoveryDisposition,
    ReferenceEnvelopeSealer, abort_pending_blob_with_cached_claim,
    load_completed_blob_stream_source, load_pending_blob_plan,
    next_pending_blob_source_for_contact, pending_blob_claim_is_current,
    recover_and_finalize_pending_blob,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BlobStreamAttemptMetrics {
    pub(super) transport: BlobStreamTransport,
    pub(super) received_bytes: u64,
    pub(super) retransmitted_bytes: u64,
    pub(super) receive_limit_bytes: u64,
    pub(super) checkpoint_bytes: u64,
    pub(super) checkpoint_latency_ms: u64,
    pub(super) writer_commits: u32,
    pub(super) failover_recoveries: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BlobStreamAttemptOutcome {
    pub(super) code: StreamResultCode,
    pub(super) metrics: BlobStreamAttemptMetrics,
}

const STREAM_ATTEMPT_DEADLINE: Duration = Duration::from_secs(30 * 60);
const STREAM_RECEIVE_WINDOW_BYTES: u64 = 8 * 1_048_576;
const STREAM_CHECKPOINT_BATCH_BYTES: u32 = 4 * 1_048_576;
const STREAM_RECORD_BUDGET_BYTES: usize = 256;
const _: () = assert!(
    STREAM_CHECKPOINT_BATCH_BYTES as u64 + MAX_STREAM_EXTENT_BYTES as u64
        <= STREAM_RECEIVE_WINDOW_BYTES
);

fn protocol(error: impl std::fmt::Display) -> NodeError {
    NodeError::Protocol(format!("Blob stream: {error}"))
}

fn transport(error: StreamTransportError) -> NodeError {
    let category = match error {
        StreamTransportError::Ineligible => "ineligible",
        StreamTransportError::Timeout => "timeout",
        StreamTransportError::Closed => "closed",
        StreamTransportError::Bounds => "bounds",
    };
    protocol(format_args!("transport {category}"))
}

fn result_digest(
    source: BlobTransferId,
    manifest_digest: [u8; 32],
    code: StreamResultCode,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ASTER/blob-stream/result/v1\0");
    digest.update(source.as_bytes());
    digest.update(manifest_digest);
    digest.update([code as u8]);
    digest.finalize().into()
}

fn exchange_id(session: [u8; 32], direction: EventDirection, source: BlobTransferId) -> u64 {
    let mut digest = Sha256::new();
    digest.update(b"ASTER/blob-stream/exchange/v1\0");
    digest.update(session);
    digest.update([match direction {
        EventDirection::ToSessionInitiator => 1,
        EventDirection::ToSessionResponder => 2,
    }]);
    digest.update(source.as_bytes());
    u64::from_be_bytes(digest.finalize()[..8].try_into().expect("SHA-256 prefix"))
}

fn selected_iroh_adapter(
    connection: &aster_iroh::Connection,
) -> Result<IrohQuicV1Adapter, NodeError> {
    let adapter = IrohQuicV1Adapter::new(connection.clone());
    let requirements = TransferRequirements::default();
    let candidates = [TransportCandidate {
        id: adapter.id(),
        locally_enabled: true,
        policy_allowed: true,
        peer_support: Some(AuthenticatedPeerSupport::new(
            AuthenticatedSupportSource::ProvisionedPeer,
            true,
        )),
        reliable_ordered: true,
        full_duplex: true,
        health: adapter.health(),
        configured_priority: 0,
    }];
    let selected = TransportSelector::rank(requirements, &candidates)
        .into_iter()
        .next()
        .ok_or_else(|| protocol("no authenticated eligible transport"))?;
    if selected.id != StreamTransportId::IrohQuicV1 || !adapter.eligibility(requirements) {
        return Err(protocol("selected transport adapter is unavailable"));
    }
    Ok(adapter)
}

fn stream_budgets(total_len: u64, carrier_count: u64) -> Result<(usize, usize), NodeError> {
    let records = carrier_count
        .checked_add(4)
        .ok_or_else(|| protocol("stream record count overflow"))?;
    let overhead = records
        .checked_mul(STREAM_RECORD_BUDGET_BYTES as u64)
        .ok_or_else(|| protocol("stream framing budget overflow"))?;
    let data = total_len
        .checked_add(overhead)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or_else(|| protocol("stream data budget exceeds this platform"))?;
    let control = overhead
        .checked_add(64 * 1024)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or_else(|| protocol("stream control budget exceeds this platform"))?;
    Ok((data, control))
}

fn open_request(total_len: u64, carrier_count: u64) -> Result<AttemptOpenRequest, NodeError> {
    let (max_data_bytes, max_control_bytes) = stream_budgets(total_len, carrier_count)?;
    Ok(AttemptOpenRequest {
        deadline: tokio::time::Instant::now() + STREAM_ATTEMPT_DEADLINE,
        max_data_bytes,
        max_control_bytes,
    })
}

/// Derives a fresh attempt nonce from the authenticated mission session and
/// exact logical transfer. Both endpoints can derive it before opening the
/// first protected stream record; a reconnect necessarily changes `session`.
pub(super) fn attempt_nonce(
    session: [u8; 32],
    direction: EventDirection,
    transfer: [u8; 32],
    checkpoint_generation: u64,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"ASTER/blob-stream/attempt-nonce/v1\0");
    digest.update(session);
    digest.update([match direction {
        EventDirection::ToSessionInitiator => 1,
        EventDirection::ToSessionResponder => 2,
    }]);
    digest.update(transfer);
    digest.update(checkpoint_generation.to_be_bytes());
    digest.finalize().into()
}

fn protect(
    mission: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    nonce: [u8; 32],
    frame: StreamFrame,
) -> Result<Vec<u8>, NodeError> {
    let plaintext = frame.encode_for_context(9, 5).map_err(protocol)?;
    mission
        .seal_v9_blob_application_frame(profile_digest, direction, nonce, &plaintext)
        .map_err(Into::into)
}

fn open_control(
    mission: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    nonce: [u8; 32],
    protected: &[u8],
) -> Result<StreamFrame, NodeError> {
    let plaintext =
        mission.open_v9_blob_application_frame(profile_digest, direction, nonce, protected)?;
    StreamFrame::decode_for_context(9, 5, &plaintext).map_err(protocol)
}

/// Drives one sender attempt over the selected adapter. The supplied reader
/// is synchronous and bounded: it must release all Store/depot authority before
/// this function awaits network I/O.
pub(super) async fn drive_sender_attempt<R>(
    attempt: Arc<dyn StreamAttempt>,
    mission: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    open: StreamOpenV1,
    expected_checkpoint: BlobStreamPlanSelectionV1,
    mut read_extent: R,
) -> Result<StreamResultCode, NodeError>
where
    R: FnMut(u64, usize) -> Result<Vec<u8>, NodeError>,
{
    let nonce = open.attempt_nonce;
    let total = open.total_len;
    let mut state = StreamSenderState::new(open.transfer_id, nonce, total);
    let protected = protect(
        mission,
        profile_digest,
        direction,
        nonce,
        StreamFrame::Open(open),
    )?;
    attempt.send_data(&protected).await.map_err(transport)?;

    let accepted = attempt
        .receive_control()
        .await
        .map_err(transport)?
        .ok_or_else(|| protocol("control stream closed before acceptance"))?;
    let StreamFrame::Accept(accepted) =
        open_control(mission, profile_digest, direction, nonce, &accepted)?
    else {
        return Err(protocol("first control record is not acceptance"));
    };
    if accepted.durable_offset != expected_checkpoint.durable_offset
        || accepted.checkpoint_generation != expected_checkpoint.checkpoint_generation
    {
        return Err(protocol(
            "acceptance differs from the authenticated pre-open plan",
        ));
    }
    state.accept(accepted).map_err(protocol)?;

    let mut finish_sent = false;
    loop {
        if state.next_offset() < total && state.next_offset() < state.receive_limit() {
            let available = state.receive_limit() - state.next_offset();
            let maximum = usize::try_from(available.min(u64::from(state.max_extent_bytes())))
                .map_err(|_| protocol("extent bound exceeds usize"))?;
            let bytes = read_extent(state.next_offset(), maximum)?;
            match state.send_extent(bytes).map_err(protocol)? {
                StreamAction::Send(frame) => {
                    let protected = protect(mission, profile_digest, direction, nonce, frame)?;
                    attempt.send_data(&protected).await.map_err(transport)?;
                    continue;
                }
                StreamAction::Retry(_) => {}
                _ => return Err(protocol("sender produced an invalid data transition")),
            }
        } else if state.next_offset() == total && !finish_sent {
            let StreamAction::Send(frame) = state.finish().map_err(protocol)? else {
                return Err(protocol("sender produced an invalid finish transition"));
            };
            let protected = protect(mission, profile_digest, direction, nonce, frame)?;
            attempt.send_data(&protected).await.map_err(transport)?;
            finish_sent = true;
        }

        let control = attempt
            .receive_control()
            .await
            .map_err(transport)?
            .ok_or_else(|| protocol("control stream closed before settlement"))?;
        match open_control(mission, profile_digest, direction, nonce, &control)? {
            StreamFrame::Checkpoint(checkpoint) => {
                state.checkpoint(checkpoint).map_err(protocol)?;
            }
            StreamFrame::Result(result) if finish_sent => {
                let (StreamAction::Send(ack), StreamAction::Terminal(code)) =
                    state.result(result).map_err(protocol)?
                else {
                    return Err(protocol("sender produced an invalid result transition"));
                };
                let protected = protect(mission, profile_digest, direction, nonce, ack)?;
                attempt.send_data(&protected).await.map_err(transport)?;
                attempt.finish_data().await.map_err(transport)?;
                if attempt
                    .receive_control()
                    .await
                    .map_err(transport)?
                    .is_some()
                {
                    return Err(protocol("control record followed terminal settlement"));
                }
                return Ok(code);
            }
            _ => return Err(protocol("unexpected control record")),
        }
    }
}

fn expected_direction(direction: EventDirection) -> StreamDirection {
    match direction {
        EventDirection::ToSessionInitiator => StreamDirection::ToSessionInitiator,
        EventDirection::ToSessionResponder => StreamDirection::ToSessionResponder,
    }
}

fn stream_open(
    mission: &MissionSession,
    direction: EventDirection,
    source: BlobTransferId,
    loaded: &CompletedBlobStreamSource,
    layout: &BlobStreamLayout,
    checkpoint_generation: u64,
) -> StreamOpenV1 {
    let transfer = *source.as_bytes();
    let nonce = attempt_nonce(
        mission.session_id(),
        direction,
        transfer,
        checkpoint_generation,
    );
    StreamOpenV1 {
        class: crate::stream_transfer::StreamClass::Blob,
        direction: expected_direction(direction),
        session_transcript: mission.session_id(),
        exchange_id: exchange_id(mission.session_id(), direction, source),
        transfer_id: transfer,
        source_transfer_id: transfer,
        publication_id: *loaded.blob.blob_id().as_bytes(),
        variant_id: *BlobVariantId::for_content(
            loaded.blob.blob_id(),
            loaded.plan.manifest().content_group(),
            loaded.plan.manifest().content_epoch(),
        )
        .as_bytes(),
        total_len: layout.total_encoded_len(),
        attempt_nonce: nonce,
        checkpoint_generation,
        custody_digest: None,
    }
}

pub(super) fn select_receive_plan(
    store: &Store,
    verifier: &mut ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    direction: EventDirection,
    local_interest: &BlobInterest,
) -> Result<BlobStreamPlanV1, NodeError> {
    guard.check(store)?;
    let Some(projection) = next_pending_blob_source_for_contact(
        store,
        guard.policy(),
        None,
        BlobContactMode::StreamV1,
    )?
    else {
        return Ok(BlobStreamPlanV1 {
            direction,
            selection: None,
        });
    };
    let source = projection.transfer_id;
    if local_interest
        .selector(&projection.topic, &projection.scope)
        .filter(|selector| selector.epoch() == projection.epoch)
        .is_none()
    {
        if pending_blob_claim_is_current(store, verifier, &projection, BlobContactMode::StreamV1)? {
            abort_pending_blob_with_cached_claim(store, verifier, source)?;
        }
        return Ok(BlobStreamPlanV1 {
            direction,
            selection: None,
        });
    }
    let Some((blob, _, plan)) =
        load_pending_blob_plan(store, verifier, source, BlobContactMode::StreamV1)?
    else {
        return Err(protocol("selected pending source became unavailable"));
    };
    if blob.ttl_ms().is_some() {
        return Err(protocol(
            "finite pending source requires authenticated custody-v2 stream authority",
        ));
    }
    let layout = BlobStreamLayout::from_plan(&plan).map_err(protocol)?;
    let checkpoint = store.blob_stream_checkpoint_with_policy(guard.policy(), source, &plan)?;
    if !layout.contains_checkpoint(
        checkpoint.next_carrier_index,
        checkpoint.durable_encoded_offset,
    ) {
        return Err(protocol(
            "durable checkpoint is outside the selected Blob layout",
        ));
    }
    Ok(BlobStreamPlanV1 {
        direction,
        selection: Some(BlobStreamPlanSelectionV1 {
            source_id: source,
            next_carrier_index: checkpoint.next_carrier_index,
            durable_offset: checkpoint.durable_encoded_offset,
            checkpoint_generation: checkpoint.generation,
        }),
    })
}

fn load_authorized_send_source(
    store: &Store,
    mission: &MissionSession,
    verifier: &mut ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    selection: BlobStreamPlanSelectionV1,
    peer_interest: &BlobInterest,
) -> Result<(CompletedBlobStreamSource, BlobStreamLayout), NodeError> {
    guard.check(store)?;
    let loaded = load_completed_blob_stream_source(store, verifier, selection.source_id)?
        .ok_or_else(|| protocol("selected completed source is unavailable"))?;
    if loaded.blob.ttl_ms().is_some() {
        return Err(protocol(
            "finite source requires authenticated custody-v2 stream authority",
        ));
    }
    let layout = BlobStreamLayout::from_plan(&loaded.plan).map_err(protocol)?;
    if !layout.contains_checkpoint(selection.next_carrier_index, selection.durable_offset) {
        return Err(protocol(
            "pre-open checkpoint is outside the completed Blob layout",
        ));
    }
    let selector = peer_interest
        .selector(loaded.blob.topic(), loaded.blob.scope())
        .filter(|selector| selector.epoch() == loaded.blob.key_epoch())
        .ok_or_else(|| protocol("pre-open source is outside peer interest"))?;
    let peer = mission.peer().mission_id();
    let commitments = mission.peer_route_grant_commitments();
    if !verifier.peer_can_route(
        peer,
        commitments,
        loaded.blob.scope(),
        loaded.blob.key_epoch(),
    ) || !verifier.peer_can_open_blob_content(
        peer,
        commitments,
        loaded.blob.scope(),
        loaded.blob.topic(),
        loaded.blob.key_epoch(),
        selector.content_proof(),
    ) {
        return Err(protocol("peer lost exact pre-open Blob entitlement"));
    }
    Ok((loaded, layout))
}

pub(super) fn validate_send_plan(
    store: &Store,
    mission: &MissionSession,
    verifier: &mut ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    selection: BlobStreamPlanSelectionV1,
    peer_interest: &BlobInterest,
) -> Result<(), NodeError> {
    load_authorized_send_source(store, mission, verifier, guard, selection, peer_interest)?;
    Ok(())
}

/// Sends one exact durable source selected by the receiver's authenticated
/// pre-open plan.
pub(super) async fn send(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    verifier: &mut ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    direction: EventDirection,
    selection: BlobStreamPlanSelectionV1,
    peer_interest: &BlobInterest,
    profile_digest: [u8; 32],
) -> Result<BlobStreamAttemptOutcome, NodeError> {
    let source = selection.source_id;
    let (loaded, layout) =
        load_authorized_send_source(store, mission, verifier, guard, selection, peer_interest)?;
    let open = stream_open(
        mission,
        direction,
        source,
        &loaded,
        &layout,
        selection.checkpoint_generation,
    );
    let adapter = selected_iroh_adapter(connection)?;
    let attempt = adapter
        .open_attempt(open_request(
            layout.total_encoded_len(),
            layout.carrier_count(),
        )?)
        .await
        .map_err(transport)?;
    let policy = guard.policy().clone();
    let completion = loaded.completion.clone();
    let plan = &loaded.plan;
    let code = drive_sender_attempt(
        attempt,
        mission,
        profile_digest,
        direction,
        open,
        selection,
        move |offset, maximum| {
            let layout = BlobStreamLayout::from_plan(plan).map_err(protocol)?;
            let next_carrier_index = layout
                .carrier_index_at_offset(offset)
                .ok_or_else(|| protocol("sender offset is not a carrier boundary"))?;
            let checkpoint = BlobStreamCheckpoint {
                next_carrier_index,
                durable_encoded_offset: offset,
                generation: selection.checkpoint_generation,
            };
            let extent = store
                .read_completed_blob_stream_extent_with_policy(
                    &policy,
                    &completion,
                    plan,
                    checkpoint,
                    maximum,
                )?
                .ok_or_else(|| protocol("completed source ended before declared length"))?;
            Ok(extent.encoded_bytes())
        },
    )
    .await?;
    Ok(BlobStreamAttemptOutcome {
        code,
        metrics: BlobStreamAttemptMetrics {
            transport: BlobStreamTransport::IrohQuicV1,
            received_bytes: 0,
            retransmitted_bytes: 0,
            receive_limit_bytes: 0,
            checkpoint_bytes: selection.durable_offset,
            checkpoint_latency_ms: 0,
            writer_commits: 0,
            failover_recoveries: 0,
        },
    })
}

/// Receives one exact durable source selected by the receiver's authenticated
/// pre-open plan, commits bounded whole-carrier batches, and promotes only
/// after the final durable checkpoint.
#[allow(clippy::too_many_arguments)]
pub(super) async fn receive(
    store: &Store,
    connection: &aster_iroh::Connection,
    mission: &mut MissionSession,
    verifier: &mut ReferenceEnvelopeSealer,
    guard: &EventLaneGuard,
    direction: EventDirection,
    selection: BlobStreamPlanSelectionV1,
    profile_digest: [u8; 32],
) -> Result<BlobStreamAttemptOutcome, NodeError> {
    guard.check(store)?;
    let source = selection.source_id;
    let (blob, manifest_bytes, plan) =
        load_pending_blob_plan(store, verifier, source, BlobContactMode::StreamV1)?
            .ok_or_else(|| protocol("selected pending source is unavailable"))?;
    if blob.ttl_ms().is_some() {
        return Err(protocol(
            "finite pending source requires authenticated custody-v2 stream authority",
        ));
    }
    let layout = BlobStreamLayout::from_plan(&plan).map_err(protocol)?;
    let checkpoint = store.blob_stream_checkpoint_with_policy(guard.policy(), source, &plan)?;
    if checkpoint.next_carrier_index != selection.next_carrier_index
        || checkpoint.durable_encoded_offset != selection.durable_offset
        || checkpoint.generation != selection.checkpoint_generation
    {
        return Err(protocol(
            "durable checkpoint changed after the pre-open plan",
        ));
    }
    let nonce = attempt_nonce(
        mission.session_id(),
        direction,
        *source.as_bytes(),
        checkpoint.generation,
    );
    let (_, receive_limit) = layout.carrier_boundary_at_or_before(
        checkpoint
            .durable_encoded_offset
            .checked_add(STREAM_RECEIVE_WINDOW_BYTES)
            .unwrap_or(u64::MAX)
            .min(layout.total_encoded_len()),
    );
    let adapter = selected_iroh_adapter(connection)?;
    let attempt = adapter
        .accept_attempt(open_request(
            layout.total_encoded_len(),
            layout.carrier_count(),
        )?)
        .await
        .map_err(transport)?;
    let policy = guard.policy().clone();
    let commit_plan = &plan;
    let promote_plan = &plan;
    let promote_blob = blob.clone();
    let promote_manifest = manifest_bytes.clone();
    let manifest_digest = *plan.manifest_digest();
    let mut expected_checkpoint = checkpoint;
    let mut received_bytes = 0_u64;
    let mut greatest_receive_limit = receive_limit;
    let mut greatest_checkpoint_latency_ms = 0_u64;
    let mut writer_commits = 0_u32;
    let code = drive_receiver_attempt(
        attempt,
        mission,
        profile_digest,
        direction,
        nonce,
        *source.as_bytes(),
        checkpoint.durable_encoded_offset,
        checkpoint.generation,
        receive_limit,
        MAX_STREAM_EXTENT_BYTES as u32,
        STREAM_CHECKPOINT_BATCH_BYTES,
        |_, frames| {
            guard.check(store)?;
            let commit_started = std::time::Instant::now();
            let next = commit_received_batch(
                store,
                &policy,
                source,
                commit_plan,
                expected_checkpoint,
                frames,
                STREAM_CHECKPOINT_BATCH_BYTES as usize,
            )?;
            greatest_checkpoint_latency_ms = greatest_checkpoint_latency_ms
                .max(u64::try_from(commit_started.elapsed().as_millis()).unwrap_or(u64::MAX));
            writer_commits = writer_commits
                .checked_add(1)
                .ok_or_else(|| protocol("writer commit count overflow"))?;
            received_bytes = frames.iter().try_fold(received_bytes, |total, frame| {
                total
                    .checked_add(frame.bytes.len() as u64)
                    .ok_or_else(|| protocol("received byte count overflow"))
            })?;
            expected_checkpoint = next;
            let (_, new_limit) = layout.carrier_boundary_at_or_before(
                next.durable_encoded_offset
                    .checked_add(STREAM_RECEIVE_WINDOW_BYTES)
                    .unwrap_or(u64::MAX)
                    .min(layout.total_encoded_len()),
            );
            greatest_receive_limit = greatest_receive_limit.max(new_limit);
            Ok((next.durable_encoded_offset, next.generation, new_limit))
        },
        |_| {
            guard.check(store)?;
            let mut work = Vec::new();
            let disposition = recover_and_finalize_pending_blob(
                store,
                guard,
                verifier,
                source,
                &promote_blob,
                &promote_manifest,
                promote_plan,
                &mut work,
                BlobContactMode::StreamV1,
            )?
            .ok_or_else(|| protocol("complete stream did not reach promotion"))?;
            let code = match disposition {
                PendingBlobRecoveryDisposition::Apply(MutableApplyDisposition::Inserted) => {
                    StreamResultCode::Promoted
                }
                PendingBlobRecoveryDisposition::Apply(MutableApplyDisposition::Duplicate) => {
                    StreamResultCode::AlreadyPresent
                }
                PendingBlobRecoveryDisposition::Apply(
                    MutableApplyDisposition::DeferredCapacity,
                )
                | PendingBlobRecoveryDisposition::DeferredLease => {
                    StreamResultCode::DeferredCapacity
                }
            };
            Ok((code, result_digest(source, manifest_digest, code)))
        },
    )
    .await?;
    Ok(BlobStreamAttemptOutcome {
        code,
        metrics: BlobStreamAttemptMetrics {
            transport: BlobStreamTransport::IrohQuicV1,
            received_bytes,
            retransmitted_bytes: 0,
            receive_limit_bytes: greatest_receive_limit,
            checkpoint_bytes: expected_checkpoint.durable_encoded_offset,
            checkpoint_latency_ms: greatest_checkpoint_latency_ms,
            writer_commits,
            // A nonzero reopen is recovery, but it is not cross-transport
            // failover while IrohQuicV1 is the only production adapter.
            failover_recoveries: 0,
        },
    })
}

/// Verifies every received separator-free extent against the exact plan and
/// commits one Store batch. No network await occurs in this function.
pub(super) fn commit_received_batch(
    store: &Store,
    policy: &ControlPolicySnapshot,
    source: BlobTransferId,
    plan: &VerifiedBlobTransferPlan,
    expected: BlobStreamCheckpoint,
    frames: &[StreamDataV1],
    advertised_batch_bytes: usize,
) -> Result<BlobStreamCheckpoint, NodeError> {
    let mut next_carrier = expected.next_carrier_index;
    let mut next_offset = expected.durable_encoded_offset;
    let mut extents = Vec::with_capacity(frames.len());
    for frame in frames {
        if frame.offset != next_offset {
            return Err(protocol("received batch is not contiguous"));
        }
        let extent = plan
            .verify_stream_bytes(
                next_carrier,
                next_offset,
                &frame.bytes,
                MAX_STREAM_EXTENT_BYTES,
            )
            .map_err(protocol)?;
        next_carrier = extent.next_carrier_index();
        next_offset = next_offset
            .checked_add(extent.encoded_len())
            .ok_or_else(|| protocol("received batch offset overflow"))?;
        extents.push(extent);
    }
    let batch = VerifiedBlobStreamCheckpointBatch::from_extents(extents, advertised_batch_bytes)?;
    match store.commit_blob_stream_batch_with_policy(policy, source, plan, expected, batch)? {
        BlobStreamCommitOutcome::Advanced(checkpoint)
        | BlobStreamCommitOutcome::Duplicate(checkpoint)
        | BlobStreamCommitOutcome::Complete(checkpoint) => Ok(checkpoint),
    }
}

/// Drives one receiver attempt. `persist_batch` and `promote` are synchronous
/// boundaries by design, ensuring no Store/depot guard survives a network
/// await. The batch callback must return the exact cumulative durable
/// checkpoint and replenished absolute receive limit.
#[allow(clippy::too_many_arguments)]
pub(super) async fn drive_receiver_attempt<P, M>(
    attempt: Arc<dyn StreamReceiveAttempt>,
    mission: &mut MissionSession,
    profile_digest: [u8; 32],
    direction: EventDirection,
    expected_nonce: [u8; 32],
    expected_transfer: [u8; 32],
    durable_offset: u64,
    checkpoint_generation: u64,
    absolute_receive_limit: u64,
    max_extent_bytes: u32,
    checkpoint_batch_bytes: u32,
    mut persist_batch: P,
    mut promote: M,
) -> Result<StreamResultCode, NodeError>
where
    P: FnMut(&StreamOpenV1, &[StreamDataV1]) -> Result<(u64, u64, u64), NodeError>,
    M: FnMut(&StreamOpenV1) -> Result<(StreamResultCode, [u8; 32]), NodeError>,
{
    if max_extent_bytes == 0
        || max_extent_bytes as usize > MAX_STREAM_EXTENT_BYTES
        || checkpoint_batch_bytes == 0
        || checkpoint_batch_bytes > MAX_STREAM_CHECKPOINT_BATCH_BYTES
    {
        return Err(protocol("receiver configuration is out of bounds"));
    }
    let protected = attempt
        .receive_data()
        .await
        .map_err(transport)?
        .ok_or_else(|| protocol("data stream closed before open"))?;
    let StreamFrame::Open(open) = open_control(
        mission,
        profile_digest,
        direction,
        expected_nonce,
        &protected,
    )?
    else {
        return Err(protocol("first data record is not open"));
    };
    if open.attempt_nonce != expected_nonce
        || open.transfer_id != expected_transfer
        || open.session_transcript != mission.session_id()
        || open.direction != expected_direction(direction)
        || open.checkpoint_generation != checkpoint_generation
    {
        return Err(protocol("open authority differs from expected transfer"));
    }
    let mut state = StreamReceiverState::new(
        &open,
        durable_offset,
        checkpoint_generation,
        absolute_receive_limit,
        max_extent_bytes,
    )
    .map_err(protocol)?;
    let StreamAction::Send(accept) = state.accept(checkpoint_batch_bytes).map_err(protocol)? else {
        return Err(protocol("receiver produced an invalid accept transition"));
    };
    let protected = protect(mission, profile_digest, direction, expected_nonce, accept)?;
    attempt.send_control(&protected).await.map_err(transport)?;

    let mut pending = Vec::new();
    let mut pending_bytes = 0_u64;
    let mut terminal_code = None;
    loop {
        let protected = attempt
            .receive_data()
            .await
            .map_err(transport)?
            .ok_or_else(|| protocol("data stream closed before settlement"))?;
        match open_control(
            mission,
            profile_digest,
            direction,
            expected_nonce,
            &protected,
        )? {
            StreamFrame::Data(data) => {
                let StreamAction::Persist { through } =
                    state.data(data.clone()).map_err(protocol)?
                else {
                    return Err(protocol("receiver produced an invalid data transition"));
                };
                let data_bytes = data.bytes.len() as u64;
                let combined = pending_bytes
                    .checked_add(data_bytes)
                    .ok_or_else(|| protocol("receiver batch byte overflow"))?;
                if !pending.is_empty() && combined > u64::from(checkpoint_batch_bytes) {
                    let prior_through = data.offset;
                    let (durable, generation, new_limit) = persist_batch(&open, &pending)?;
                    if durable != prior_through {
                        return Err(protocol("Store checkpoint differs from received batch"));
                    }
                    let StreamAction::Send(checkpoint) = state
                        .persisted(durable, generation, new_limit)
                        .map_err(protocol)?
                    else {
                        return Err(protocol(
                            "receiver produced an invalid checkpoint transition",
                        ));
                    };
                    pending.clear();
                    pending_bytes = 0;
                    let protected = protect(
                        mission,
                        profile_digest,
                        direction,
                        expected_nonce,
                        checkpoint,
                    )?;
                    attempt.send_control(&protected).await.map_err(transport)?;
                }
                pending_bytes = pending_bytes
                    .checked_add(data_bytes)
                    .ok_or_else(|| protocol("receiver batch byte overflow"))?;
                pending.push(data);
                if pending_bytes >= u64::from(checkpoint_batch_bytes) || through == open.total_len {
                    let (durable, generation, new_limit) = persist_batch(&open, &pending)?;
                    if durable != through {
                        return Err(protocol("Store checkpoint differs from received batch"));
                    }
                    let StreamAction::Send(checkpoint) = state
                        .persisted(durable, generation, new_limit)
                        .map_err(protocol)?
                    else {
                        return Err(protocol(
                            "receiver produced an invalid checkpoint transition",
                        ));
                    };
                    pending.clear();
                    pending_bytes = 0;
                    let protected = protect(
                        mission,
                        profile_digest,
                        direction,
                        expected_nonce,
                        checkpoint,
                    )?;
                    attempt.send_control(&protected).await.map_err(transport)?;
                }
            }
            StreamFrame::Finish(finish) => {
                if !pending.is_empty() {
                    return Err(protocol("finish crossed an uncommitted receiver batch"));
                }
                let (result, code) = match state.finish(finish).map_err(protocol)? {
                    StreamAction::Promote => {
                        let (code, digest) = promote(&open)?;
                        let StreamAction::Send(result) =
                            state.promoted(code, digest).map_err(protocol)?
                        else {
                            return Err(protocol("receiver produced an invalid result transition"));
                        };
                        (result, code)
                    }
                    StreamAction::Send(result) => {
                        let code = terminal_code
                            .ok_or_else(|| protocol("replayed finish lost terminal authority"))?;
                        (result, code)
                    }
                    _ => return Err(protocol("receiver produced an invalid finish transition")),
                };
                let protected =
                    protect(mission, profile_digest, direction, expected_nonce, result)?;
                attempt.send_control(&protected).await.map_err(transport)?;
                terminal_code = Some(code);
            }
            StreamFrame::ResultAck(ack) => {
                let code = terminal_code
                    .ok_or_else(|| protocol("result acknowledgement preceded result"))?;
                let StreamAction::Terminal(code) = state.result_ack(ack, code).map_err(protocol)?
                else {
                    return Err(protocol(
                        "receiver produced an invalid acknowledgement transition",
                    ));
                };
                if attempt.receive_data().await.map_err(transport)?.is_some() {
                    return Err(protocol("data record followed terminal settlement"));
                }
                attempt.finish_control().await.map_err(transport)?;
                return Ok(code);
            }
            _ => return Err(protocol("unexpected data record")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct BlobStreamProgress {
    total_bytes: u64,
    received_bytes: u64,
    durable_bytes: u64,
    started_ms: u64,
    last_sample_ms: u64,
    last_sample_bytes: u64,
    rolling_bytes_per_second: u64,
    phase: BlobStreamTransferPhase,
    terminal: Option<BlobStreamTerminalCategory>,
}

impl BlobStreamProgress {
    pub(super) fn new(total_bytes: u64, now_ms: u64) -> Result<Self, &'static str> {
        if total_bytes == 0 {
            return Err("Blob stream total is zero");
        }
        Ok(Self {
            total_bytes,
            received_bytes: 0,
            durable_bytes: 0,
            started_ms: now_ms,
            last_sample_ms: now_ms,
            last_sample_bytes: 0,
            rolling_bytes_per_second: 0,
            phase: BlobStreamTransferPhase::Negotiating,
            terminal: None,
        })
    }

    pub(super) fn accepted(&mut self) {
        self.phase = BlobStreamTransferPhase::Receiving;
    }

    pub(super) fn received(&mut self, through: u64) -> Result<(), &'static str> {
        if through < self.received_bytes || through > self.total_bytes {
            return Err("Blob stream received position regressed or overflowed");
        }
        self.received_bytes = through;
        Ok(())
    }

    pub(super) fn durable(&mut self, through: u64, now_ms: u64) -> Result<(), &'static str> {
        if through < self.durable_bytes
            || through > self.received_bytes
            || now_ms < self.last_sample_ms
        {
            return Err("Blob stream durable position or clock regressed");
        }
        let elapsed = now_ms.saturating_sub(self.last_sample_ms);
        let advanced = through.saturating_sub(self.last_sample_bytes);
        if elapsed != 0 {
            self.rolling_bytes_per_second = advanced.saturating_mul(1_000) / elapsed;
            self.last_sample_ms = now_ms;
            self.last_sample_bytes = through;
        }
        self.durable_bytes = through;
        if through == self.total_bytes {
            self.phase = BlobStreamTransferPhase::Finalizing;
        }
        Ok(())
    }

    pub(super) fn settling(&mut self) -> Result<(), &'static str> {
        if self.durable_bytes != self.total_bytes {
            return Err("Blob stream settled before durable completion");
        }
        self.phase = BlobStreamTransferPhase::Settling;
        Ok(())
    }

    pub(super) fn complete(&mut self) -> Result<(), &'static str> {
        if self.phase != BlobStreamTransferPhase::Settling {
            return Err("Blob stream completed before settlement");
        }
        self.phase = BlobStreamTransferPhase::Complete;
        Ok(())
    }

    pub(super) fn terminal(&mut self, category: BlobStreamTerminalCategory) {
        self.phase = BlobStreamTransferPhase::Terminal;
        self.terminal = Some(category);
    }

    pub(super) const fn status(&self) -> BlobStreamTransferStatus {
        BlobStreamTransferStatus {
            phase: self.phase,
            total_bytes: self.total_bytes,
            durable_bytes: self.durable_bytes,
            throughput_bytes_per_second: self.rolling_bytes_per_second,
            terminal: self.terminal,
        }
    }

    pub(super) const fn recovery_offset(&self) -> u64 {
        self.durable_bytes
    }

    #[allow(dead_code)]
    pub(super) const fn elapsed_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.started_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_blob_stream_v9_attempt_nonce_binds_session_direction_transfer_and_checkpoint() {
        let base = attempt_nonce([1; 32], EventDirection::ToSessionResponder, [2; 32], 7);
        assert_ne!(base, [0; 32]);
        assert_eq!(
            base,
            attempt_nonce([1; 32], EventDirection::ToSessionResponder, [2; 32], 7,)
        );
        assert_ne!(
            base,
            attempt_nonce([1; 32], EventDirection::ToSessionInitiator, [2; 32], 7,)
        );
        assert_ne!(
            base,
            attempt_nonce([1; 32], EventDirection::ToSessionResponder, [3; 32], 7,)
        );
        assert_ne!(
            base,
            attempt_nonce([4; 32], EventDirection::ToSessionResponder, [2; 32], 8,)
        );
    }

    #[test]
    fn live_blob_stream_v9_status_uses_only_durable_checkpoint_authority() {
        let mut progress = BlobStreamProgress::new(16 * 1_048_576, 10).expect("progress");
        progress.accepted();
        progress.received(8 * 1_048_576).expect("received tail");
        assert_eq!(progress.status().durable_bytes, 0);
        assert_eq!(progress.recovery_offset(), 0);

        progress
            .durable(4 * 1_048_576, 1_010)
            .expect("first durable batch");
        assert_eq!(progress.recovery_offset(), 4 * 1_048_576);
        assert_eq!(progress.status().throughput_bytes_per_second, 4 * 1_048_576);

        // An unchanged credit/checkpoint heartbeat cannot manufacture durable
        // progress or become failover authority.
        progress
            .durable(4 * 1_048_576, 2_010)
            .expect("unchanged heartbeat");
        assert_eq!(progress.recovery_offset(), 4 * 1_048_576);
        assert_eq!(progress.status().throughput_bytes_per_second, 0);

        progress.received(16 * 1_048_576).expect("received all");
        progress
            .durable(16 * 1_048_576, 3_010)
            .expect("final durable batch");
        assert_eq!(progress.status().phase, BlobStreamTransferPhase::Finalizing);
        progress.settling().expect("settlement");
        progress.complete().expect("complete");
        assert_eq!(progress.status().phase, BlobStreamTransferPhase::Complete);
    }

    #[test]
    fn live_blob_stream_v9_status_rejects_regression_and_sanitizes_terminal() {
        let mut progress = BlobStreamProgress::new(1024, 0).expect("progress");
        progress.accepted();
        progress.received(512).expect("received");
        progress.durable(512, 10).expect("durable");
        assert!(progress.received(511).is_err());
        assert!(progress.durable(513, 11).is_err());
        assert!(progress.complete().is_err());
        progress.terminal(BlobStreamTerminalCategory::Transport);
        assert_eq!(
            progress.status().terminal,
            Some(BlobStreamTerminalCategory::Transport)
        );
    }
}
