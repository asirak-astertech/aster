//! Semantic-v9/profile-5 Blob stream runtime.
//!
//! Network attempts may receive ahead, but only Store-confirmed cumulative
//! checkpoints update the public durable position or recovery authority.

use crate::application::{
    BlobStreamTerminalCategory, BlobStreamTransferPhase, BlobStreamTransferStatus,
};

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
