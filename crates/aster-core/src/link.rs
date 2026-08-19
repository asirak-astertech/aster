//! Pluggable transport contract.

use crate::model::NodeId;
use std::io;
use std::time::{Duration, Instant};

/// Link properties available to scheduling policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinkCharacteristics {
    /// Maximum encoded frame length.
    pub mtu: u16,
    /// Estimated useful payload rate, if known.
    pub bits_per_second: Option<u64>,
    /// Relative monetary/energy cost from zero (free) to 255 (highest).
    pub cost: u8,
    /// Relative RF emission footprint from zero to 255.
    pub emission: u8,
    /// Whether one transmission can be received by multiple peers.
    pub broadcast: bool,
}

/// One received transport frame. Contents remain opaque to the adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedFrame {
    /// Authenticated peer hint when the adapter/session knows it.
    pub peer: Option<NodeId>,
    /// Opaque protocol frame bytes.
    pub bytes: Vec<u8>,
}

/// Adapter-neutral transport used by the engine.
///
/// Implementations must be nonblocking: `try_receive` returns `Ok(None)` when no
/// frame is ready. The engine sleeps until `next_wakeup`, adapter readiness, or an
/// application command, so no busy-polling is required.
pub trait Link: Send + Sync {
    /// Stable adapter instance name used only for status and policy.
    fn name(&self) -> &str;

    /// Current characteristics used by the priority scheduler.
    fn characteristics(&self) -> LinkCharacteristics;

    /// Emits one already-fragmented frame to a peer, or as a broadcast when the
    /// peer is absent and the medium supports it.
    fn send(&self, peer: Option<NodeId>, frame: &[u8]) -> io::Result<()>;

    /// Receives one frame without waiting.
    fn try_receive(&self) -> io::Result<Option<ReceivedFrame>>;

    /// Enables or disables active advertisements/discovery.
    fn set_discovery(&self, enabled: bool) -> io::Result<()>;

    /// Earliest link-maintenance deadline. `None` means event-driven only.
    fn next_wakeup(&self) -> Option<Instant> {
        None
    }

    /// Suggested retransmission floor for this link.
    fn retry_floor(&self) -> Duration {
        Duration::from_millis(250)
    }
}
