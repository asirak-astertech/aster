//! Semantic-v9/profile-5 Blob stream runtime.
//!
//! Network attempts may receive ahead, but only Store-confirmed cumulative
//! checkpoints update the public durable position or recovery authority.

use crate::application::{
    BlobStreamTerminalCategory, BlobStreamTransferPhase, BlobStreamTransferStatus,
};
use crate::{
    mission::MissionSession,
    stream_transfer::{
        MAX_STREAM_CHECKPOINT_BATCH_BYTES, MAX_STREAM_EXTENT_BYTES, StreamAction, StreamDataV1,
        StreamDirection, StreamFrame, StreamOpenV1, StreamReceiverState, StreamResultCode,
        StreamSenderState,
    },
    stream_transport::{StreamAttempt, StreamReceiveAttempt, StreamTransportError},
};
use aster_mesh::VerifiedBlobTransferPlan;
use aster_redb_store::{
    BlobStreamCheckpoint, BlobStreamCommitOutcome, BlobTransferId, ControlPolicySnapshot, Store,
    VerifiedBlobStreamCheckpointBatch,
};
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

use super::{EventDirection, NodeError};

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
                pending_bytes = pending_bytes
                    .checked_add(data.bytes.len() as u64)
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
