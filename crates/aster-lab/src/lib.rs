//! Deterministic and real-process laboratories for Aster Mesh.
//!
//! The Gate-H profile exposes only the shared-node native mesh experiment.
//! Historical single-contact simulations and live commands require the
//! explicit `legacy-lab` compatibility feature.

#![forbid(unsafe_code)]

#[cfg(feature = "legacy-lab")]
pub mod live;
pub mod mesh_experiment;

use std::error::Error;

/// Error result returned by a laboratory scenario.
pub type LabResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[cfg(feature = "legacy-lab")]
pub use legacy_lab::*;

#[cfg(feature = "legacy-lab")]
#[rustfmt::skip]
mod legacy_lab {
use super::LabResult;
use crate::live;
use aster_host::{MeshService, ServiceOptions, SyncProfile};
use aster_mesh::blob::{BlobMetadata, BlobStoreConfig, MAX_BLOB_CHUNK_SIZE, MIN_BLOB_CHUNK_SIZE};
use aster_mesh::engine::NodeConfig;
use aster_mesh::fragment::Fragment;
use aster_mesh::link::{Link, LinkCharacteristics, ReceivedFrame};
use aster_mesh::sync::{InterestFilter, InventoryPurpose};
use aster_mesh::wire::EnvelopeId;
use aster_mesh::{
    ApplicationNodeOptions, DataClass, NodeId, Priority, ProvisioningAccess, ProvisioningBundle,
    PublishRequest, Query, ReferenceProvisioner, Scope, Topic, open_reference_node,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, VecDeque};
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const LOSS_WINDOW_FRAMES: u16 = 1_000;
const MAX_SHARD_ITEMS: u32 = 10_000;
const MAX_LIVE_INVOCATIONS: u32 = 10_000;

/// Marker placed in a simulation directory once the CLI has claimed that
/// otherwise-empty directory for exactly one invocation.
pub const SCENARIO_OWNERSHIP_FILE: &str = ".aster-lab-invocation";

/// Deterministic frame-fault and virtual-rate profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultProfile {
    /// Seed for frame loss and delay decisions.
    pub seed: u64,
    /// Reported carrier MTU.
    pub mtu: u16,
    /// Useful bit rate represented by the virtual token bucket.
    pub bits_per_second: u64,
    /// Independently dropped frames per thousand offered frames.
    pub loss_per_mille: u16,
    /// Maximum deterministic delivery delay in virtual ticks.
    pub reorder_ticks: u16,
    /// Virtual milliseconds advanced by each receive opportunity.
    pub tick_ms: u16,
}

impl Default for FaultProfile {
    fn default() -> Self {
        Self {
            seed: 1,
            mtu: 1_200,
            bits_per_second: 1_000_000,
            loss_per_mille: 0,
            reorder_ticks: 0,
            tick_ms: 100,
        }
    }
}

impl FaultProfile {
    /// Rejects values that cannot form a useful bounded simulation.
    pub fn validate(self) -> LabResult<Self> {
        if self.mtu < 64 {
            return Err(invalid("MTU must be at least 64 bytes"));
        }
        if self.bits_per_second == 0 {
            return Err(invalid("bit rate must be nonzero"));
        }
        if self.loss_per_mille > 900 {
            return Err(invalid("loss must be between 0 and 900 per mille"));
        }
        if self.tick_ms == 0 {
            return Err(invalid("virtual tick must be nonzero"));
        }
        Ok(self)
    }

    fn with_stream(self, stream: u64) -> Self {
        Self {
            seed: mix64(self.seed ^ stream.wrapping_mul(0x9e37_79b9_7f4a_7c15)),
            ..self
        }
    }
}

/// Two-node durable application transfer scenario.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferScenario {
    pub root: PathBuf,
    pub seed: u64,
    pub items: u32,
    pub payload_bytes: usize,
    pub restart_after_delivered_frames: Option<u64>,
    pub max_pumps: u64,
    pub fault: FaultProfile,
}

/// Three-node, different-peer Blob recovery scenario.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobRecoveryScenario {
    pub root: PathBuf,
    pub seed: u64,
    pub blob_bytes: u64,
    pub chunk_bytes: u32,
    pub restart_after_delivered_frames: u64,
    pub max_pumps_per_contact: u64,
    pub fault: FaultProfile,
}

/// Three-node Event custody control with a route-only durable intermediate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteOnlyEventScenario {
    pub root: PathBuf,
    pub seed: u64,
    pub payload_bytes: usize,
    pub max_pumps_per_contact: u64,
    pub fault: FaultProfile,
    pub source_revision: String,
    pub source_diff_sha256: String,
    pub binary_sha256: String,
}

/// Exact semantic receipt for one route-only Event custody control.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteOnlyEventReceipt {
    pub seed: u64,
    pub source_revision: String,
    pub source_diff_sha256: String,
    pub binary_sha256: String,
    pub publisher: NodeId,
    pub relay: NodeId,
    pub consumer: NodeId,
    pub item_id: [u8; 32],
    pub envelope_id: [u8; 32],
    pub payload_sha256: [u8; 32],
    pub a_to_b_authenticated: bool,
    pub relay_application_unreadable: bool,
    pub relay_payload_absent_at_rest: bool,
    pub relay_payload_digest_absent_at_rest: bool,
    pub relay_logical_key_present_in_trusted_store: bool,
    pub relay_reopened_with_source_envelope: bool,
    pub b_to_c_authenticated: bool,
    pub consumer_received_same_item: bool,
    pub consumer_received_same_envelope: bool,
    pub application_acknowledged: bool,
    pub post_ack_deliveries: usize,
    pub a_c_contact_count: u64,
}

impl RouteOnlyEventReceipt {
    /// Canonical human- and machine-readable evidence record.
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"aster.phase0.route-only-event.v1\",\n",
                "  \"seed\": {},\n",
                "  \"source_revision\": \"{}\",\n",
                "  \"source_diff_sha256\": \"{}\",\n",
                "  \"binary_sha256\": \"{}\",\n",
                "  \"publisher\": \"{}\",\n",
                "  \"relay\": \"{}\",\n",
                "  \"consumer\": \"{}\",\n",
                "  \"item_id\": \"{}\",\n",
                "  \"envelope_id\": \"{}\",\n",
                "  \"payload_sha256\": \"{}\",\n",
                "  \"a_to_b_authenticated\": {},\n",
                "  \"relay_application_unreadable\": {},\n",
                "  \"relay_payload_absent_at_rest\": {},\n",
                "  \"relay_payload_digest_absent_at_rest\": {},\n",
                "  \"relay_logical_key_present_in_trusted_store\": {},\n",
                "  \"relay_reopened_with_source_envelope\": {},\n",
                "  \"b_to_c_authenticated\": {},\n",
                "  \"consumer_received_same_item\": {},\n",
                "  \"consumer_received_same_envelope\": {},\n",
                "  \"application_acknowledged\": {},\n",
                "  \"post_ack_deliveries\": {},\n",
                "  \"a_c_contact_count\": {}\n",
                "}}"
            ),
            self.seed,
            self.source_revision,
            self.source_diff_sha256,
            self.binary_sha256,
            hex_bytes(&self.publisher),
            hex_bytes(&self.relay),
            hex_bytes(&self.consumer),
            hex_bytes(&self.item_id),
            hex_bytes(&self.envelope_id),
            hex_bytes(&self.payload_sha256),
            self.a_to_b_authenticated,
            self.relay_application_unreadable,
            self.relay_payload_absent_at_rest,
            self.relay_payload_digest_absent_at_rest,
            self.relay_logical_key_present_in_trusted_store,
            self.relay_reopened_with_source_envelope,
            self.b_to_c_authenticated,
            self.consumer_received_same_item,
            self.consumer_received_same_envelope,
            self.application_acknowledged,
            self.post_ack_deliveries,
            self.a_c_contact_count,
        )
    }
}

/// Metrics plus the exact semantic receipt for one Phase-0 control trial.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteOnlyEventResult {
    pub metrics: LabMetrics,
    pub receipt: RouteOnlyEventReceipt,
}

/// One scale-worker shard. Nodes form a store-and-forward chain inside the
/// shard; process orchestration is supplied by the binary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShardScenario {
    pub root: PathBuf,
    pub seed: u64,
    pub shard_index: u32,
    pub first_node: u32,
    pub nodes: u32,
    pub items: u32,
    pub payload_bytes: usize,
    pub max_pumps_per_edge: u64,
    pub fault: FaultProfile,
}

/// Aggregatable metrics emitted by every scenario and worker process.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LabMetrics {
    pub scenario: String,
    pub seed: u64,
    pub shards: u32,
    pub nodes: u32,
    pub published_items: u64,
    pub delivered_items: u64,
    pub blob_bytes: u64,
    pub pump_calls: u64,
    pub restarts: u64,
    pub partial_restart_observed: bool,
    /// Durable encrypted Blob transfer-store bytes before an incomplete reopen.
    pub partial_durable_blob_bytes: u64,
    /// Durable encrypted Blob transfer-store bytes immediately after reopen.
    pub reopened_durable_blob_bytes: u64,
    /// Whether the pre-reopen Blob byte/chunk usage survived exactly.
    pub durable_progress_preserved: bool,
    /// Configured virtual useful bit rate.
    pub configured_bits_per_second: u64,
    /// Exact drops per complete directional `LOSS_WINDOW_FRAMES` window.
    pub configured_loss_per_mille: u16,
    /// Window over which the configured loss count is exact.
    pub loss_window_frames: u16,
    pub frames_offered: u64,
    pub frames_delivered: u64,
    pub frames_dropped: u64,
    pub wire_bytes_offered: u64,
    pub wire_bytes_delivered: u64,
    pub maximum_queued_frames: u64,
    pub simulated_link_ms: u64,
    pub elapsed_ms: u64,
    pub converged: bool,
}

impl LabMetrics {
    /// Stable single-line record used between scale coordinator and workers.
    pub fn to_record(&self) -> String {
        format!(
            "ASTER_LAB_METRICS\tscenario={}\tseed={}\tshards={}\tnodes={}\tpublished_items={}\tdelivered_items={}\tblob_bytes={}\tpump_calls={}\trestarts={}\tpartial_restart_observed={}\tpartial_durable_blob_bytes={}\treopened_durable_blob_bytes={}\tdurable_progress_preserved={}\tconfigured_bits_per_second={}\tconfigured_loss_per_mille={}\tloss_window_frames={}\tframes_offered={}\tframes_delivered={}\tframes_dropped={}\twire_bytes_offered={}\twire_bytes_delivered={}\tmaximum_queued_frames={}\tsimulated_link_ms={}\telapsed_ms={}\tconverged={}",
            self.scenario,
            self.seed,
            self.shards,
            self.nodes,
            self.published_items,
            self.delivered_items,
            self.blob_bytes,
            self.pump_calls,
            self.restarts,
            self.partial_restart_observed,
            self.partial_durable_blob_bytes,
            self.reopened_durable_blob_bytes,
            self.durable_progress_preserved,
            self.configured_bits_per_second,
            self.configured_loss_per_mille,
            self.loss_window_frames,
            self.frames_offered,
            self.frames_delivered,
            self.frames_dropped,
            self.wire_bytes_offered,
            self.wire_bytes_delivered,
            self.maximum_queued_frames,
            self.simulated_link_ms,
            self.elapsed_ms,
            self.converged,
        )
    }

    /// Parses the stable worker record without adding a serialization library.
    pub fn from_record(record: &str) -> LabResult<Self> {
        let mut fields = record.trim().split('\t');
        if fields.next() != Some("ASTER_LAB_METRICS") {
            return Err(invalid("not an Aster laboratory metrics record"));
        }
        let mut result = Self::default();
        let mut seen = BTreeSet::new();
        for field in fields {
            let (name, value) = field
                .split_once('=')
                .ok_or_else(|| invalid("malformed metrics field"))?;
            if !seen.insert(name) {
                return Err(invalid(format!("duplicate metrics field {name}")));
            }
            match name {
                "scenario" => result.scenario = value.to_owned(),
                "seed" => result.seed = parse_number(name, value)?,
                "shards" => result.shards = parse_number(name, value)?,
                "nodes" => result.nodes = parse_number(name, value)?,
                "published_items" => result.published_items = parse_number(name, value)?,
                "delivered_items" => result.delivered_items = parse_number(name, value)?,
                "blob_bytes" => result.blob_bytes = parse_number(name, value)?,
                "pump_calls" => result.pump_calls = parse_number(name, value)?,
                "restarts" => result.restarts = parse_number(name, value)?,
                "partial_restart_observed" => {
                    result.partial_restart_observed = parse_bool(name, value)?;
                }
                "partial_durable_blob_bytes" => {
                    result.partial_durable_blob_bytes = parse_number(name, value)?;
                }
                "reopened_durable_blob_bytes" => {
                    result.reopened_durable_blob_bytes = parse_number(name, value)?;
                }
                "durable_progress_preserved" => {
                    result.durable_progress_preserved = parse_bool(name, value)?;
                }
                "configured_bits_per_second" => {
                    result.configured_bits_per_second = parse_number(name, value)?;
                }
                "configured_loss_per_mille" => {
                    result.configured_loss_per_mille = parse_number(name, value)?;
                }
                "loss_window_frames" => {
                    result.loss_window_frames = parse_number(name, value)?;
                }
                "frames_offered" => result.frames_offered = parse_number(name, value)?,
                "frames_delivered" => result.frames_delivered = parse_number(name, value)?,
                "frames_dropped" => result.frames_dropped = parse_number(name, value)?,
                "wire_bytes_offered" => result.wire_bytes_offered = parse_number(name, value)?,
                "wire_bytes_delivered" => {
                    result.wire_bytes_delivered = parse_number(name, value)?;
                }
                "maximum_queued_frames" => {
                    result.maximum_queued_frames = parse_number(name, value)?;
                }
                "simulated_link_ms" => result.simulated_link_ms = parse_number(name, value)?,
                "elapsed_ms" => result.elapsed_ms = parse_number(name, value)?,
                "converged" => result.converged = parse_bool(name, value)?,
                _ => return Err(invalid(format!("unknown metrics field {name}"))),
            }
        }
        for required in [
            "scenario",
            "seed",
            "shards",
            "nodes",
            "published_items",
            "delivered_items",
            "blob_bytes",
            "pump_calls",
            "restarts",
            "partial_restart_observed",
            "partial_durable_blob_bytes",
            "reopened_durable_blob_bytes",
            "durable_progress_preserved",
            "configured_bits_per_second",
            "configured_loss_per_mille",
            "loss_window_frames",
            "frames_offered",
            "frames_delivered",
            "frames_dropped",
            "wire_bytes_offered",
            "wire_bytes_delivered",
            "maximum_queued_frames",
            "simulated_link_ms",
            "elapsed_ms",
            "converged",
        ] {
            if !seen.contains(required) {
                return Err(invalid(format!("metrics record is missing {required}")));
            }
        }
        if result.scenario.is_empty() {
            return Err(invalid("metrics scenario is empty"));
        }
        Ok(result)
    }

    /// Human- and machine-readable JSON without a runtime dependency.
    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"aster-lab-metrics/v1\",\n",
                "  \"scenario\": \"{}\",\n",
                "  \"seed\": {},\n",
                "  \"shards\": {},\n",
                "  \"nodes\": {},\n",
                "  \"published_items\": {},\n",
                "  \"delivered_items\": {},\n",
                "  \"blob_bytes\": {},\n",
                "  \"pump_calls\": {},\n",
                "  \"restarts\": {},\n",
                "  \"partial_restart_observed\": {},\n",
                "  \"partial_durable_blob_bytes\": {},\n",
                "  \"reopened_durable_blob_bytes\": {},\n",
                "  \"durable_progress_preserved\": {},\n",
                "  \"configured_bits_per_second\": {},\n",
                "  \"configured_loss_per_mille\": {},\n",
                "  \"loss_model\": \"exact-affine-per-direction-window\",\n",
                "  \"loss_window_frames\": {},\n",
                "  \"frames_offered\": {},\n",
                "  \"frames_delivered\": {},\n",
                "  \"frames_dropped\": {},\n",
                "  \"wire_bytes_offered\": {},\n",
                "  \"wire_bytes_delivered\": {},\n",
                "  \"maximum_queued_frames\": {},\n",
                "  \"simulated_link_ms\": {},\n",
                "  \"elapsed_ms\": {},\n",
                "  \"converged\": {}\n",
                "}}"
            ),
            self.scenario,
            self.seed,
            self.shards,
            self.nodes,
            self.published_items,
            self.delivered_items,
            self.blob_bytes,
            self.pump_calls,
            self.restarts,
            self.partial_restart_observed,
            self.partial_durable_blob_bytes,
            self.reopened_durable_blob_bytes,
            self.durable_progress_preserved,
            self.configured_bits_per_second,
            self.configured_loss_per_mille,
            self.loss_window_frames,
            self.frames_offered,
            self.frames_delivered,
            self.frames_dropped,
            self.wire_bytes_offered,
            self.wire_bytes_delivered,
            self.maximum_queued_frames,
            self.simulated_link_ms,
            self.elapsed_ms,
            self.converged,
        )
    }

    /// Adds one worker result into a coordinator result.
    pub fn add_worker(&mut self, worker: &Self) {
        self.shards = self.shards.saturating_add(worker.shards);
        self.nodes = self.nodes.saturating_add(worker.nodes);
        self.published_items = self.published_items.saturating_add(worker.published_items);
        self.delivered_items = self.delivered_items.saturating_add(worker.delivered_items);
        self.blob_bytes = self.blob_bytes.saturating_add(worker.blob_bytes);
        self.pump_calls = self.pump_calls.saturating_add(worker.pump_calls);
        self.restarts = self.restarts.saturating_add(worker.restarts);
        self.partial_restart_observed |= worker.partial_restart_observed;
        self.partial_durable_blob_bytes = self
            .partial_durable_blob_bytes
            .saturating_add(worker.partial_durable_blob_bytes);
        self.reopened_durable_blob_bytes = self
            .reopened_durable_blob_bytes
            .saturating_add(worker.reopened_durable_blob_bytes);
        self.durable_progress_preserved |= worker.durable_progress_preserved;
        self.configured_bits_per_second = self
            .configured_bits_per_second
            .max(worker.configured_bits_per_second);
        self.configured_loss_per_mille = self
            .configured_loss_per_mille
            .max(worker.configured_loss_per_mille);
        self.loss_window_frames = self.loss_window_frames.max(worker.loss_window_frames);
        self.frames_offered = self.frames_offered.saturating_add(worker.frames_offered);
        self.frames_delivered = self
            .frames_delivered
            .saturating_add(worker.frames_delivered);
        self.frames_dropped = self.frames_dropped.saturating_add(worker.frames_dropped);
        self.wire_bytes_offered = self
            .wire_bytes_offered
            .saturating_add(worker.wire_bytes_offered);
        self.wire_bytes_delivered = self
            .wire_bytes_delivered
            .saturating_add(worker.wire_bytes_delivered);
        self.maximum_queued_frames = self.maximum_queued_frames.max(worker.maximum_queued_frames);
        self.simulated_link_ms = self.simulated_link_ms.max(worker.simulated_link_ms);
        self.elapsed_ms = self.elapsed_ms.max(worker.elapsed_ms);
        self.converged &= worker.converged;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct LinkStats {
    frames_offered: u64,
    frames_delivered: u64,
    frames_dropped: u64,
    wire_bytes_offered: u64,
    wire_bytes_delivered: u64,
    maximum_queued_frames: u64,
    maximum_tick: u64,
}

impl LinkStats {
    fn add_to(self, metrics: &mut LabMetrics, tick_ms: u16) {
        metrics.frames_offered = metrics.frames_offered.saturating_add(self.frames_offered);
        metrics.frames_delivered = metrics
            .frames_delivered
            .saturating_add(self.frames_delivered);
        metrics.frames_dropped = metrics.frames_dropped.saturating_add(self.frames_dropped);
        metrics.wire_bytes_offered = metrics
            .wire_bytes_offered
            .saturating_add(self.wire_bytes_offered);
        metrics.wire_bytes_delivered = metrics
            .wire_bytes_delivered
            .saturating_add(self.wire_bytes_delivered);
        metrics.maximum_queued_frames = metrics
            .maximum_queued_frames
            .max(self.maximum_queued_frames);
        metrics.simulated_link_ms = metrics
            .simulated_link_ms
            .max(self.maximum_tick.saturating_mul(u64::from(tick_ms)));
    }
}

#[derive(Clone)]
struct NetworkProbe {
    stats: Arc<Mutex<LinkStats>>,
    tick_ms: u16,
    left_to_right: Arc<Mutex<Direction>>,
    right_to_left: Arc<Mutex<Direction>>,
}

impl NetworkProbe {
    fn snapshot(&self) -> LabResult<LinkStats> {
        Ok(*self.stats.lock().map_err(lock_error)?)
    }

    fn add_to(&self, metrics: &mut LabMetrics) -> LabResult<()> {
        self.snapshot()?.add_to(metrics, self.tick_ms);
        Ok(())
    }

    fn allow_next_left_to_right_logical(&self) -> LabResult<()> {
        allow_next_logical(&self.left_to_right)
    }

    fn allow_next_right_to_left_logical(&self) -> LabResult<()> {
        allow_next_logical(&self.right_to_left)
    }

    fn pending_frames(&self) -> LabResult<usize> {
        let left_to_right = self.left_to_right.lock().map_err(lock_error)?.pending.len();
        let right_to_left = self.right_to_left.lock().map_err(lock_error)?.pending.len();
        Ok(left_to_right.saturating_add(right_to_left))
    }
}

fn allow_next_logical(direction: &Arc<Mutex<Direction>>) -> LabResult<()> {
    let mut direction = direction.lock().map_err(lock_error)?;
    direction.logical_gate_enabled = true;
    direction.allowed_transfer = direction
        .pending
        .front()
        .map(|frame| Fragment::decode(&frame.bytes).map(|fragment| fragment.transfer_id))
        .transpose()?;
    Ok(())
}

#[derive(Debug)]
struct ScheduledFrame {
    ready_tick: u64,
    peer: NodeId,
    bytes: Vec<u8>,
}

#[derive(Debug, Default)]
struct Direction {
    offered_sequence: u64,
    tick: u64,
    tokens: u64,
    logical_gate_enabled: bool,
    allowed_transfer: Option<u64>,
    pending: VecDeque<ScheduledFrame>,
}

/// In-memory carrier whose fault schedule depends only on configuration and
/// offered-frame order.
#[derive(Clone)]
struct FaultLink {
    name: String,
    local_identity: NodeId,
    profile: FaultProfile,
    direction_tag: u64,
    inbound: Arc<Mutex<Direction>>,
    outbound: Arc<Mutex<Direction>>,
    stats: Arc<Mutex<LinkStats>>,
    discovery: Arc<AtomicBool>,
}

impl FaultLink {
    fn pair(
        name: &str,
        left: NodeId,
        right: NodeId,
        profile: FaultProfile,
    ) -> LabResult<(Self, Self, NetworkProbe)> {
        let profile = profile.validate()?;
        let left_to_right = Arc::new(Mutex::new(Direction::default()));
        let right_to_left = Arc::new(Mutex::new(Direction::default()));
        let stats = Arc::new(Mutex::new(LinkStats::default()));
        let discovery = Arc::new(AtomicBool::new(true));
        Ok((
            Self {
                name: format!("{name}-left"),
                local_identity: left,
                profile,
                direction_tag: 0x4c,
                inbound: right_to_left.clone(),
                outbound: left_to_right.clone(),
                stats: stats.clone(),
                discovery: discovery.clone(),
            },
            Self {
                name: format!("{name}-right"),
                local_identity: right,
                profile,
                direction_tag: 0x52,
                inbound: left_to_right.clone(),
                outbound: right_to_left.clone(),
                stats: stats.clone(),
                discovery,
            },
            NetworkProbe {
                stats,
                tick_ms: profile.tick_ms,
                left_to_right,
                right_to_left,
            },
        ))
    }

    fn receive_one(&self) -> io::Result<Option<ReceivedFrame>> {
        let mut direction = self.inbound.lock().map_err(lock_error)?;
        if direction.logical_gate_enabled && direction.allowed_transfer.is_none() {
            return Ok(None);
        }
        direction.tick = direction.tick.saturating_add(1);
        let tick = direction.tick;
        let bytes_per_tick = virtual_bytes_per_tick(self.profile);
        let bucket_capacity = u64::from(self.profile.mtu).saturating_mul(4);
        direction.tokens = direction
            .tokens
            .saturating_add(bytes_per_tick)
            .min(bucket_capacity);
        let eligible = if direction.logical_gate_enabled {
            let Some(frame) = direction.pending.front() else {
                return Ok(None);
            };
            let transfer_id = Fragment::decode(&frame.bytes)
                .map_err(io::Error::other)?
                .transfer_id;
            (Some(transfer_id) == direction.allowed_transfer
                && frame.ready_tick <= tick
                && frame.bytes.len() as u64 <= direction.tokens)
                .then_some(0)
        } else {
            direction.pending.iter().position(|frame| {
                frame.ready_tick <= tick && frame.bytes.len() as u64 <= direction.tokens
            })
        };
        let Some(index) = eligible else {
            let mut stats = self.stats.lock().map_err(lock_error)?;
            stats.maximum_tick = stats.maximum_tick.max(tick);
            return Ok(None);
        };
        let frame = direction
            .pending
            .remove(index)
            .ok_or_else(|| io::Error::other("eligible frame disappeared"))?;
        direction.tokens = direction.tokens.saturating_sub(frame.bytes.len() as u64);
        drop(direction);

        let mut stats = self.stats.lock().map_err(lock_error)?;
        stats.frames_delivered = stats.frames_delivered.saturating_add(1);
        stats.wire_bytes_delivered = stats
            .wire_bytes_delivered
            .saturating_add(frame.bytes.len() as u64);
        stats.maximum_tick = stats.maximum_tick.max(tick);
        Ok(Some(ReceivedFrame {
            peer: Some(frame.peer),
            bytes: frame.bytes,
        }))
    }
}

impl Link for FaultLink {
    fn name(&self) -> &str {
        &self.name
    }

    fn characteristics(&self) -> LinkCharacteristics {
        LinkCharacteristics {
            mtu: self.profile.mtu,
            bits_per_second: Some(self.profile.bits_per_second),
            cost: 1,
            emission: 1,
            broadcast: false,
        }
    }

    fn send(&self, _peer: Option<NodeId>, frame: &[u8]) -> io::Result<()> {
        let mut direction = self.outbound.lock().map_err(lock_error)?;
        let sequence = direction.offered_sequence;
        direction.offered_sequence = direction.offered_sequence.saturating_add(1);
        let choice = mix64(
            self.profile.seed
                ^ self.direction_tag.rotate_left(17)
                ^ sequence.wrapping_mul(0xd6e8_feb8_6659_fd93),
        );
        let mut stats = self.stats.lock().map_err(lock_error)?;
        stats.frames_offered = stats.frames_offered.saturating_add(1);
        stats.wire_bytes_offered = stats.wire_bytes_offered.saturating_add(frame.len() as u64);
        // 17 is coprime to 1,000, so this affine permutation visits every
        // slot exactly once in each complete directional window. The seed and
        // direction rotate which offered frames are lost without changing the
        // exact configured count.
        let window_position = sequence % u64::from(LOSS_WINDOW_FRAMES);
        let loss_slot = (window_position * 17
            + mix64(self.profile.seed ^ self.direction_tag) % u64::from(LOSS_WINDOW_FRAMES))
            % u64::from(LOSS_WINDOW_FRAMES);
        if loss_slot < u64::from(self.profile.loss_per_mille) {
            stats.frames_dropped = stats.frames_dropped.saturating_add(1);
            return Ok(());
        }
        let delay = if self.profile.reorder_ticks == 0 {
            0
        } else {
            choice.rotate_left(23) % (u64::from(self.profile.reorder_ticks) + 1)
        };
        let ready_tick = direction.tick.saturating_add(delay);
        direction.pending.push_back(ScheduledFrame {
            ready_tick,
            peer: self.local_identity,
            bytes: frame.to_vec(),
        });
        stats.maximum_queued_frames = stats
            .maximum_queued_frames
            .max(direction.pending.len() as u64);
        Ok(())
    }

    fn try_receive(&self) -> io::Result<Option<ReceivedFrame>> {
        self.receive_one()
    }

    fn set_discovery(&self, enabled: bool) -> io::Result<()> {
        self.discovery.store(enabled, Ordering::Release);
        Ok(())
    }

    fn next_wakeup(&self) -> Option<Instant> {
        self.inbound
            .lock()
            .ok()
            .and_then(|direction| (!direction.pending.is_empty()).then(Instant::now))
    }

    fn retry_floor(&self) -> Duration {
        serialization_floor(self.profile)
    }
}

/// Runs a two-node Event transfer, optionally reopening the receiver at a
/// deterministic delivered-frame checkpoint.
pub fn run_transfer(config: &TransferScenario) -> LabResult<LabMetrics> {
    validate_transfer(config)?;
    prepare_fresh_directory(&config.root)?;
    let started = Instant::now();
    let topic = Topic::new("lab.transfer")?;
    let scope = Scope::new("lab/transfer")?;
    let bundles = provision(config.seed, 1, 2, &scope, &topic)?;
    let options = options(
        &topic,
        &scope,
        u64::try_from(config.payload_bytes)?,
        config.items,
    );
    let left_database = config.root.join("node-000.sqlite");
    let left_blobs = config.root.join("node-000-blobs");
    let right_database = config.root.join("node-001.sqlite");
    let right_blobs = config.root.join("node-001-blobs");
    let mut left = MeshService::open(
        &left_database,
        &left_blobs,
        bundles[0].as_slice(),
        options.clone(),
    )?;
    let mut right = MeshService::open(
        &right_database,
        &right_blobs,
        bundles[1].as_slice(),
        options.clone(),
    )?;

    for ordinal in 0..config.items {
        left.publish(PublishRequest {
            class: DataClass::Event,
            topic: topic.clone(),
            scope: scope.clone(),
            priority: priority_for(ordinal),
            ttl_ms: None,
            logical_key: format!("transfer-{ordinal:08}").into_bytes(),
            payload: pattern_bytes(config.payload_bytes, config.seed, u64::from(ordinal)),
            tombstone: false,
        })?;
    }

    let left_id = left.identity();
    let right_id = right.identity();
    let (left_link, right_link, first_probe) =
        FaultLink::pair("transfer-0", left_id, right_id, config.fault.with_stream(0))?;
    left.configure_peer_carrier(right_id, left_link)?;
    right.configure_peer_carrier(left_id, right_link)?;
    left.begin_sync(right_id)?;
    right.begin_sync(left_id)?;

    let expected = usize::try_from(config.items)?;
    let mut pump_calls = 0_u64;
    let mut restart_done = config.restart_after_delivered_frames.is_none();
    let mut partial_restart = false;
    let mut probes = vec![first_probe.clone()];
    while pump_calls < config.max_pumps {
        pump_pair(&mut left, &mut right, &mut pump_calls)?;
        if !restart_done {
            let delivered_frames = first_probe.snapshot()?.frames_delivered;
            let delivered_items = query_event_count(&mut right, &topic, &scope)?;
            if delivered_frames
                >= config
                    .restart_after_delivered_frames
                    .expect("restart checkpoint is present")
                || delivered_items == expected
            {
                partial_restart = delivered_items < expected && delivered_frames > 0;
                left.pause_sync()?;
                right.pause_sync()?;
                drop(right);
                let mut reopened = MeshService::open(
                    &right_database,
                    &right_blobs,
                    bundles[1].as_slice(),
                    options.clone(),
                )?;
                if reopened.identity() != right_id {
                    return Err(invalid("receiver identity changed across durable reopen"));
                }
                let (left_link, right_link, probe) =
                    FaultLink::pair("transfer-1", left_id, right_id, config.fault.with_stream(1))?;
                left.configure_peer_carrier(right_id, left_link)?;
                reopened.configure_peer_carrier(left_id, right_link)?;
                left.begin_sync(right_id)?;
                reopened.begin_sync(left_id)?;
                right = reopened;
                probes.push(probe);
                restart_done = true;
            }
        }
        if restart_done
            && pump_calls.is_multiple_of(8)
            && query_event_count(&mut right, &topic, &scope)? == expected
        {
            break;
        }
        wait_for_pair(&left, &right, pump_calls);
    }
    let delivered = query_event_count(&mut right, &topic, &scope)?;
    let converged = delivered == expected;
    left.pause_sync()?;
    right.pause_sync()?;

    let mut metrics = LabMetrics {
        scenario: "transfer".into(),
        seed: config.seed,
        shards: 1,
        nodes: 2,
        published_items: u64::from(config.items),
        delivered_items: delivered as u64,
        pump_calls,
        restarts: u64::from(config.restart_after_delivered_frames.is_some()),
        partial_restart_observed: partial_restart,
        configured_bits_per_second: config.fault.bits_per_second,
        configured_loss_per_mille: config.fault.loss_per_mille,
        loss_window_frames: LOSS_WINDOW_FRAMES,
        elapsed_ms: elapsed_ms(started),
        converged,
        ..LabMetrics::default()
    };
    for probe in probes {
        probe.add_to(&mut metrics)?;
    }
    if !converged {
        write_metrics(&config.root, &metrics)?;
        return Err(invalid(format!(
            "transfer did not converge within {} pump calls ({} of {} items)",
            config.max_pumps, delivered, expected
        )));
    }
    Ok(metrics)
}

/// Runs the Phase-0 Event control through a durable route-only intermediate.
///
/// The publisher and consumer never share a carrier. The relay first receives
/// the stable source envelope, closes, is inspected and reopened from its
/// durable store, and only then contacts the consumer. The returned receipt
/// distinguishes opaque custody from application delivery and acknowledgement.
pub fn run_route_only_event(config: &RouteOnlyEventScenario) -> LabResult<RouteOnlyEventResult> {
    validate_route_only_event(config)?;
    prepare_fresh_directory(&config.root)?;
    let started = Instant::now();
    let topic = Topic::new("lab.phase0.command")?;
    let scope = Scope::new("lab/phase0")?;
    let member = ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()])?;
    let relay_access = ProvisioningAccess::relay(scope.clone(), vec![0])?;
    let mut provisioner = ReferenceProvisioner::from_seed(seed_bytes(config.seed))?;
    let publisher_bundle = Zeroizing::new(
        provisioner
            .issue_node(1, std::slice::from_ref(&member))?
            .to_bytes()?,
    );
    let relay_bundle = Zeroizing::new(
        provisioner
            .issue_node(2, std::slice::from_ref(&relay_access))?
            .to_bytes()?,
    );
    let consumer_bundle = Zeroizing::new(
        provisioner
            .issue_node(3, std::slice::from_ref(&member))?
            .to_bytes()?,
    );
    let service_options = options(&topic, &scope, u64::try_from(config.payload_bytes)?, 1);
    let publisher_root = config.root.join("publisher");
    let relay_root = config.root.join("relay");
    let consumer_root = config.root.join("consumer");
    for node_root in [&publisher_root, &relay_root, &consumer_root] {
        fs::create_dir_all(node_root)?;
    }
    let publisher_database = publisher_root.join("state.sqlite");
    let relay_database = relay_root.join("state.sqlite");
    let consumer_database = consumer_root.join("state.sqlite");
    let publisher_blobs = publisher_root.join("blobs");
    let relay_blobs = relay_root.join("blobs");
    let consumer_blobs = consumer_root.join("blobs");

    let mut publisher = MeshService::open(
        &publisher_database,
        &publisher_blobs,
        publisher_bundle.as_slice(),
        service_options.clone(),
    )?;
    let mut relay = MeshService::open(
        &relay_database,
        &relay_blobs,
        relay_bundle.as_slice(),
        service_options.clone(),
    )?;
    let mut consumer = MeshService::open(
        &consumer_database,
        &consumer_blobs,
        consumer_bundle.as_slice(),
        service_options.clone(),
    )?;
    let publisher_id = publisher.identity();
    let relay_id = relay.identity();
    let consumer_id = consumer.identity();
    if publisher_id == relay_id || publisher_id == consumer_id || relay_id == consumer_id {
        return Err(invalid(
            "Phase-0 provisioning produced duplicate identities",
        ));
    }

    let subscription =
        consumer.subscribe(topic.clone(), scope.clone(), Some(DataClass::Event), false)?;
    let logical_key = pattern_bytes(32, config.seed, 0x004b_4559);
    let payload = pattern_bytes(config.payload_bytes, config.seed, 0x0043_4d44);
    let payload_sha256: [u8; 32] = Sha256::digest(&payload).into();
    let published = publisher.publish(PublishRequest {
        class: DataClass::Event,
        topic: topic.clone(),
        scope: scope.clone(),
        priority: Priority::Immediate,
        ttl_ms: None,
        logical_key: logical_key.clone(),
        payload: payload.clone(),
        tombstone: false,
    })?;
    if published.publisher != publisher_id {
        return Err(invalid("Phase-0 publication changed publisher identity"));
    }

    let (publisher_link, relay_link, first_probe) = FaultLink::pair(
        "phase0-a-b",
        publisher_id,
        relay_id,
        config.fault.with_stream(0),
    )?;
    publisher.configure_peer_carrier(relay_id, publisher_link)?;
    relay.configure_peer_carrier(publisher_id, relay_link)?;
    publisher.begin_sync(relay_id)?;
    relay.begin_sync(publisher_id)?;
    let mut pump_calls = 0_u64;
    let a_to_b_authenticated = drive_until_authenticated_quiet(
        &mut publisher,
        &mut relay,
        &first_probe,
        config.max_pumps_per_contact,
        &mut pump_calls,
    )?;
    if !a_to_b_authenticated {
        return Err(invalid("Phase-0 A-to-B contact did not authenticate"));
    }
    let relay_application_unreadable = match relay.query(Query {
        topic: Some(topic.clone()),
        scope: Some(scope.clone()),
        class: Some(DataClass::Event),
        logical_key: Some(logical_key.clone()),
        limit: 2,
        ..Query::default()
    }) {
        Ok(items) => items.is_empty(),
        Err(_) => true,
    };
    if !relay_application_unreadable {
        return Err(invalid(
            "route-only relay exposed the Event through the application API",
        ));
    }
    publisher.pause_sync()?;
    relay.pause_sync()?;
    drop(publisher);
    drop(relay);

    let source_envelope = single_data_envelope(
        &publisher_database,
        publisher_bundle.as_slice(),
        &topic,
        &scope,
    )?;
    let relay_envelope =
        single_data_envelope(&relay_database, relay_bundle.as_slice(), &topic, &scope)?;
    if source_envelope != relay_envelope {
        return Err(invalid(
            "route-only relay did not retain the exact source envelope",
        ));
    }
    let payload_absent = !tree_contains_any(&relay_root, &[payload.as_slice()])?;
    let payload_digest_absent = !tree_contains_any(&relay_root, &[payload_sha256.as_slice()])?;
    let logical_key_absent = !tree_contains_any(&relay_root, &[logical_key.as_slice()])?;
    if !payload_absent || !payload_digest_absent {
        return Err(invalid(format!(
            "route-only relay durable state canary scan failed: payload_absent={payload_absent}, payload_digest_absent={payload_digest_absent}, logical_key_absent={logical_key_absent}"
        )));
    }

    let mut relay = MeshService::open(
        &relay_database,
        &relay_blobs,
        relay_bundle.as_slice(),
        service_options,
    )?;
    let relay_reopened_with_source_envelope = relay.identity() == relay_id;
    if !relay_reopened_with_source_envelope {
        return Err(invalid("route-only relay identity changed after reopen"));
    }
    let (relay_link, consumer_link, second_probe) = FaultLink::pair(
        "phase0-b-c",
        relay_id,
        consumer_id,
        config.fault.with_stream(1),
    )?;
    relay.configure_peer_carrier(consumer_id, relay_link)?;
    consumer.configure_peer_carrier(relay_id, consumer_link)?;
    relay.begin_sync(consumer_id)?;
    consumer.begin_sync(relay_id)?;

    let contact_start = pump_calls;
    let mut delivered_item = None;
    while pump_calls.saturating_sub(contact_start) < config.max_pumps_per_contact {
        pump_pair(&mut relay, &mut consumer, &mut pump_calls)?;
        if pump_calls.is_multiple_of(8) {
            let deliveries = consumer.poll(subscription, 2)?;
            if deliveries.len() > 1 {
                return Err(invalid("Phase-0 consumer received duplicate deliveries"));
            }
            if let Some(delivery) = deliveries.into_iter().next() {
                delivered_item = Some(delivery.item);
                break;
            }
        }
        wait_for_pair(&relay, &consumer, pump_calls);
    }
    let delivered = delivered_item.ok_or_else(|| {
        invalid(format!(
            "Phase-0 B-to-C contact produced no delivery within {} pump calls",
            config.max_pumps_per_contact
        ))
    })?;
    let b_to_c_authenticated = relay
        .active_contact()
        .is_some_and(|status| status.authenticated)
        && consumer
            .active_contact()
            .is_some_and(|status| status.authenticated);
    if !b_to_c_authenticated {
        return Err(invalid("Phase-0 B-to-C delivery preceded authentication"));
    }
    let consumer_received_same_item = delivered.id == published.id
        && delivered.publisher == publisher_id
        && delivered.publisher_counter == published.publisher_counter
        && delivered.class == DataClass::Event
        && delivered.topic == topic
        && delivered.scope == scope
        && delivered.logical_key == logical_key
        && delivered.payload == payload;
    if !consumer_received_same_item {
        return Err(invalid(
            "Phase-0 consumer did not receive the exact A-authored Event",
        ));
    }
    consumer.acknowledge(subscription, delivered.id)?;
    for _ in 0..32 {
        pump_pair(&mut relay, &mut consumer, &mut pump_calls)?;
    }
    let post_ack_deliveries = consumer.poll(subscription, 2)?.len();
    if post_ack_deliveries != 0 {
        return Err(invalid(
            "Phase-0 consumer redelivered an acknowledged Event",
        ));
    }
    let queried = consumer.query(Query {
        topic: Some(topic.clone()),
        scope: Some(scope.clone()),
        class: Some(DataClass::Event),
        logical_key: Some(logical_key),
        limit: 2,
        ..Query::default()
    })?;
    if queried.len() != 1 || queried[0].id != published.id {
        return Err(invalid(
            "Phase-0 consumer query did not retain the acknowledged Event",
        ));
    }
    relay.pause_sync()?;
    consumer.pause_sync()?;
    drop(relay);
    drop(consumer);

    let consumer_envelope = single_data_envelope(
        &consumer_database,
        consumer_bundle.as_slice(),
        &topic,
        &scope,
    )?;
    let consumer_received_same_envelope = consumer_envelope == source_envelope;
    if !consumer_received_same_envelope {
        return Err(invalid(
            "Phase-0 consumer did not retain the exact source envelope",
        ));
    }

    let mut metrics = LabMetrics {
        scenario: "phase0-route-only-event".into(),
        seed: config.seed,
        shards: 1,
        nodes: 3,
        published_items: 1,
        delivered_items: 1,
        pump_calls,
        restarts: 1,
        configured_bits_per_second: config.fault.bits_per_second,
        configured_loss_per_mille: config.fault.loss_per_mille,
        loss_window_frames: LOSS_WINDOW_FRAMES,
        elapsed_ms: elapsed_ms(started),
        converged: true,
        ..LabMetrics::default()
    };
    first_probe.add_to(&mut metrics)?;
    second_probe.add_to(&mut metrics)?;
    Ok(RouteOnlyEventResult {
        metrics,
        receipt: RouteOnlyEventReceipt {
            seed: config.seed,
            source_revision: config.source_revision.clone(),
            source_diff_sha256: config.source_diff_sha256.clone(),
            binary_sha256: config.binary_sha256.clone(),
            publisher: publisher_id,
            relay: relay_id,
            consumer: consumer_id,
            item_id: published.id,
            envelope_id: source_envelope.into_bytes(),
            payload_sha256,
            a_to_b_authenticated,
            relay_application_unreadable,
            relay_payload_absent_at_rest: payload_absent,
            relay_payload_digest_absent_at_rest: payload_digest_absent,
            relay_logical_key_present_in_trusted_store: !logical_key_absent,
            relay_reopened_with_source_envelope,
            b_to_c_authenticated,
            consumer_received_same_item,
            consumer_received_same_envelope,
            application_acknowledged: true,
            post_ack_deliveries,
            a_c_contact_count: 0,
        },
    })
}

/// Runs a three-node Blob scenario: source first fills an alternate peer,
/// receiver starts from the source, receiver restarts, then completes from the
/// alternate peer and verifies plaintext through the streaming reader.
pub fn run_blob_recovery(config: &BlobRecoveryScenario) -> LabResult<LabMetrics> {
    validate_blob(config)?;
    prepare_fresh_directory(&config.root)?;
    let started = Instant::now();
    let topic = Topic::new("lab.blob")?;
    let scope = Scope::new("lab/blob")?;
    let bundles = provision(config.seed, 1, 3, &scope, &topic)?;
    let options = options(&topic, &scope, config.blob_bytes, 8);
    let paths = (0..3_u32)
        .map(|index| {
            (
                config.root.join(format!("node-{index:03}.sqlite")),
                config.root.join(format!("node-{index:03}-blobs")),
            )
        })
        .collect::<Vec<_>>();
    let mut source = MeshService::open(
        &paths[0].0,
        &paths[0].1,
        bundles[0].as_slice(),
        options.clone(),
    )?;
    let mut alternate = MeshService::open(
        &paths[1].0,
        &paths[1].1,
        bundles[1].as_slice(),
        options.clone(),
    )?;
    let mut receiver = MeshService::open(
        &paths[2].0,
        &paths[2].1,
        bundles[2].as_slice(),
        options.clone(),
    )?;

    let mut blob_service = source.open_blob_service(&scope, &topic)?;
    let mut plaintext = PatternSource::new(config.blob_bytes, config.seed, 0x424c_4f42);
    let scratch_path = config.root.join("blob-digest.scratch");
    let mut scratch = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&scratch_path)?;
    let manifest = blob_service.prepare(
        &mut plaintext,
        &mut scratch,
        config.chunk_bytes,
        BlobMetadata::new(
            Some("application/octet-stream".into()),
            b"aster-lab/v1".to_vec(),
        )?,
    )?;
    drop(scratch);
    fs::remove_file(&scratch_path)?;
    let progress = blob_service.encrypt_some(&mut plaintext, &manifest, u64::MAX)?;
    if !progress.complete {
        return Err(invalid("Blob source did not finish local encryption"));
    }
    let finished = blob_service.finish(manifest.id())?;
    let blob_id = finished.id();
    drop(blob_service);
    source.publish_finished_blob(
        topic.clone(),
        scope.clone(),
        Priority::Priority,
        None,
        finished,
    )?;

    let source_id = source.identity();
    let alternate_id = alternate.identity();
    let receiver_id = receiver.identity();
    let no_loss = FaultProfile {
        loss_per_mille: 0,
        reorder_ticks: 0,
        ..config.fault.with_stream(10)
    };
    let (source_link, alternate_link, mirror_probe) =
        FaultLink::pair("blob-mirror", source_id, alternate_id, no_loss)?;
    source.configure_peer_carrier(alternate_id, source_link)?;
    alternate.configure_peer_carrier(source_id, alternate_link)?;
    source
        .begin_sync(alternate_id)
        .map_err(|error| invalid(format!("Blob mirror source start: {error}")))?;
    alternate
        .begin_sync(source_id)
        .map_err(|error| invalid(format!("Blob mirror alternate start: {error}")))?;
    let mut pump_calls = 0_u64;
    drive_until_blob(
        &mut source,
        &mut alternate,
        &scope,
        &topic,
        blob_id,
        config.max_pumps_per_contact,
        &mut pump_calls,
    )
    .map_err(|error| invalid(format!("Blob mirror contact: {error}")))?;
    source.pause_sync()?;
    alternate.pause_sync()?;

    let (source_link, receiver_link, partial_probe) = FaultLink::pair(
        "blob-partial",
        source_id,
        receiver_id,
        config.fault.with_stream(11),
    )?;
    source.configure_peer_carrier(receiver_id, source_link)?;
    receiver.configure_peer_carrier(source_id, receiver_link)?;
    source
        .begin_sync(receiver_id)
        .map_err(|error| invalid(format!("Blob partial source start: {error}")))?;
    receiver
        .begin_sync(source_id)
        .map_err(|error| invalid(format!("Blob partial receiver start: {error}")))?;
    let partial_start = pump_calls;
    let mut completed_before_restart = false;
    let mut partial_durable_blob_bytes = 0_u64;
    let mut partial_durable_blob_chunks = 0_u64;
    while pump_calls.saturating_sub(partial_start) < config.max_pumps_per_contact {
        partial_probe.allow_next_right_to_left_logical()?;
        source
            .pump()
            .map_err(|error| invalid(format!("Blob partial source contact: {error}")))?;
        pump_calls = pump_calls.saturating_add(1);
        partial_probe.allow_next_left_to_right_logical()?;
        receiver
            .pump()
            .map_err(|error| invalid(format!("Blob partial receiver contact: {error}")))?;
        pump_calls = pump_calls.saturating_add(1);
        if receiver.open_blob_reader(&scope, &topic, blob_id).is_ok() {
            completed_before_restart = true;
            break;
        }
        if partial_probe.snapshot()?.frames_delivered >= config.restart_after_delivered_frames {
            let (bytes, chunks) = receiver.blob_transfer_usage()?;
            if bytes > 0 && chunks > 0 {
                partial_durable_blob_bytes = bytes;
                partial_durable_blob_chunks = chunks;
                break;
            }
        }
        wait_for_pair(&source, &receiver, pump_calls);
    }
    let partial_stats = partial_probe.snapshot()?;
    let partial_observed = !completed_before_restart
        && partial_stats.frames_delivered >= config.restart_after_delivered_frames
        && partial_durable_blob_bytes > 0
        && partial_durable_blob_chunks > 0;
    source.pause_sync()?;
    receiver.pause_sync()?;
    drop(receiver);

    if !partial_observed {
        let mut metrics = LabMetrics {
            scenario: "blob-recovery".into(),
            seed: config.seed,
            shards: 1,
            nodes: 3,
            published_items: 1,
            delivered_items: 1 + u64::from(completed_before_restart),
            blob_bytes: config.blob_bytes,
            pump_calls,
            restarts: 0,
            partial_restart_observed: false,
            partial_durable_blob_bytes,
            reopened_durable_blob_bytes: 0,
            durable_progress_preserved: false,
            configured_bits_per_second: config.fault.bits_per_second,
            configured_loss_per_mille: config.fault.loss_per_mille,
            loss_window_frames: LOSS_WINDOW_FRAMES,
            elapsed_ms: elapsed_ms(started),
            converged: false,
            ..LabMetrics::default()
        };
        for probe in [mirror_probe, partial_probe] {
            probe.add_to(&mut metrics)?;
        }
        write_metrics(&config.root, &metrics)?;
        return Err(invalid(format!(
            "Blob partial contact did not stop after at least {} delivered frames before completion",
            config.restart_after_delivered_frames
        )));
    }

    let mut receiver = MeshService::open(&paths[2].0, &paths[2].1, bundles[2].as_slice(), options)?;
    if receiver.identity() != receiver_id {
        return Err(invalid(
            "Blob receiver identity changed across durable reopen",
        ));
    }
    let (reopened_durable_blob_bytes, reopened_durable_blob_chunks) =
        receiver.blob_transfer_usage()?;
    let durable_progress_preserved = reopened_durable_blob_bytes == partial_durable_blob_bytes
        && reopened_durable_blob_chunks == partial_durable_blob_chunks
        && partial_durable_blob_bytes > 0
        && partial_durable_blob_chunks > 0;
    if !durable_progress_preserved {
        return Err(invalid(
            "Blob receiver did not preserve its durable partial transfer-store progress across reopen",
        ));
    }
    let (alternate_link, receiver_link, recovery_probe) = FaultLink::pair(
        "blob-recovery",
        alternate_id,
        receiver_id,
        config.fault.with_stream(12),
    )?;
    alternate.configure_peer_carrier(receiver_id, alternate_link)?;
    receiver.configure_peer_carrier(alternate_id, receiver_link)?;
    alternate
        .begin_sync(receiver_id)
        .map_err(|error| invalid(format!("Blob recovery alternate start: {error}")))?;
    receiver
        .begin_sync(alternate_id)
        .map_err(|error| invalid(format!("Blob recovery receiver start: {error}")))?;
    drive_until_blob(
        &mut alternate,
        &mut receiver,
        &scope,
        &topic,
        blob_id,
        config.max_pumps_per_contact,
        &mut pump_calls,
    )
    .map_err(|error| invalid(format!("Blob recovery contact: {error}")))?;

    let mut reader = receiver.open_blob_reader(&scope, &topic, blob_id)?;
    let mut verifier = PatternVerifier::new(config.blob_bytes, config.seed, 0x424c_4f42);
    let read = reader.stream_into(&mut verifier)?;
    if read.plaintext_bytes != config.blob_bytes || !verifier.complete() {
        return Err(invalid(
            "recovered Blob plaintext verification was incomplete",
        ));
    }
    alternate.pause_sync()?;
    receiver.pause_sync()?;

    let mut metrics = LabMetrics {
        scenario: "blob-recovery".into(),
        seed: config.seed,
        shards: 1,
        nodes: 3,
        published_items: 1,
        delivered_items: 2,
        blob_bytes: config.blob_bytes,
        pump_calls,
        restarts: 1,
        partial_restart_observed: partial_observed,
        partial_durable_blob_bytes,
        reopened_durable_blob_bytes,
        durable_progress_preserved,
        configured_bits_per_second: config.fault.bits_per_second,
        configured_loss_per_mille: config.fault.loss_per_mille,
        loss_window_frames: LOSS_WINDOW_FRAMES,
        elapsed_ms: elapsed_ms(started),
        converged: true,
        ..LabMetrics::default()
    };
    for probe in [mirror_probe, partial_probe, recovery_probe] {
        probe.add_to(&mut metrics)?;
    }
    Ok(metrics)
}

/// Runs one independently provisioned chain shard for the scale coordinator.
pub fn run_shard(config: &ShardScenario) -> LabResult<LabMetrics> {
    validate_shard(config)?;
    prepare_fresh_directory(&config.root)?;
    let started = Instant::now();
    let topic = Topic::new("lab.scale")?;
    let scope = Scope::new(format!("lab/scale/shard-{:04}", config.shard_index))?;
    let serial = u64::from(config.first_node).saturating_add(1);
    let bundles = provision(config.seed, serial, config.nodes, &scope, &topic)?;
    let options = options(
        &topic,
        &scope,
        u64::try_from(config.payload_bytes)?.saturating_mul(u64::from(config.items)),
        config.items,
    );
    let mut nodes = Vec::with_capacity(usize::try_from(config.nodes)?);
    for local in 0..config.nodes {
        let global = config.first_node.saturating_add(local);
        nodes.push(MeshService::open(
            config.root.join(format!("node-{global:06}.sqlite")),
            config.root.join(format!("node-{global:06}-blobs")),
            bundles[usize::try_from(local)?].as_slice(),
            options.clone(),
        )?);
    }
    for ordinal in 0..config.items {
        nodes[0].publish(PublishRequest {
            class: DataClass::Event,
            topic: topic.clone(),
            scope: scope.clone(),
            priority: priority_for(ordinal),
            ttl_ms: None,
            logical_key: format!("shard-{:04}-{ordinal:08}", config.shard_index).into_bytes(),
            payload: pattern_bytes(
                config.payload_bytes,
                config.seed ^ u64::from(config.shard_index),
                u64::from(ordinal),
            ),
            tombstone: false,
        })?;
    }

    let local_items = query_shard_event_count(
        &mut nodes[0],
        &topic,
        &scope,
        config.shard_index,
        config.items,
    )?;
    let expected_local_items = usize::try_from(config.items)?;
    if local_items != expected_local_items {
        return Err(invalid(format!(
            "shard {} local working set contains {} of {} items",
            config.shard_index, local_items, expected_local_items
        )));
    }

    let mut metrics = LabMetrics {
        scenario: format!(
            "shard-{:04}-first-{:06}",
            config.shard_index, config.first_node
        ),
        seed: config.seed,
        shards: 1,
        nodes: config.nodes,
        published_items: u64::from(config.items),
        delivered_items: u64::from(config.items),
        configured_bits_per_second: config.fault.bits_per_second,
        configured_loss_per_mille: config.fault.loss_per_mille,
        loss_window_frames: LOSS_WINDOW_FRAMES,
        converged: true,
        ..LabMetrics::default()
    };
    for edge in 1..config.nodes {
        let receiver_index = usize::try_from(edge)?;
        let sender_index = receiver_index - 1;
        let (left_nodes, right_nodes) = nodes.split_at_mut(receiver_index);
        let sender = &mut left_nodes[sender_index];
        let receiver = &mut right_nodes[0];
        let sender_id = sender.identity();
        let receiver_id = receiver.identity();
        let (sender_link, receiver_link, probe) = FaultLink::pair(
            &format!("shard-{}-edge-{edge}", config.shard_index),
            sender_id,
            receiver_id,
            config
                .fault
                .with_stream((u64::from(config.shard_index) << 32) | u64::from(edge)),
        )?;
        sender.configure_peer_carrier(receiver_id, sender_link)?;
        receiver.configure_peer_carrier(sender_id, receiver_link)?;
        let delivery_subscription =
            receiver.subscribe(topic.clone(), scope.clone(), Some(DataClass::Event), false)?;
        let mut delivered_ids = BTreeSet::new();
        sender.begin_sync(receiver_id)?;
        receiver.begin_sync(sender_id)?;
        let before = metrics.pump_calls;
        let expected = usize::try_from(config.items)?;
        while metrics.pump_calls.saturating_sub(before) < config.max_pumps_per_edge {
            pump_pair(sender, receiver, &mut metrics.pump_calls)?;
            if metrics.pump_calls.is_multiple_of(8) {
                for delivery in receiver.poll(delivery_subscription, expected.clamp(1, 4_096))? {
                    let item = delivery.item.id;
                    delivered_ids.insert(item);
                    receiver.acknowledge(delivery_subscription, item)?;
                }
                if delivered_ids.len() == expected {
                    break;
                }
            }
            wait_for_pair(sender, receiver, metrics.pump_calls);
        }
        let delivered =
            query_shard_event_count(receiver, &topic, &scope, config.shard_index, config.items)?;
        sender.pause_sync()?;
        receiver.pause_sync()?;
        probe.add_to(&mut metrics)?;
        if delivered != expected {
            metrics.converged = false;
            metrics.elapsed_ms = elapsed_ms(started);
            write_metrics(&config.root, &metrics)?;
            return Err(invalid(format!(
                "shard {} edge {} did not converge within {} pump calls ({} of {} items)",
                config.shard_index, edge, config.max_pumps_per_edge, delivered, expected
            )));
        }
        metrics.delivered_items = metrics
            .delivered_items
            .saturating_add(u64::from(config.items));
    }
    metrics.elapsed_ms = elapsed_ms(started);
    Ok(metrics)
}

/// Writes the canonical metrics JSON into the preserved run directory.
pub fn write_metrics(root: &Path, metrics: &LabMetrics) -> LabResult<PathBuf> {
    let path = root.join("metrics.json");
    write_metrics_at(&path, metrics)?;
    Ok(path)
}

/// Writes a Phase-0 semantic receipt exactly once.
pub fn write_route_only_event_receipt(
    root: &Path,
    receipt: &RouteOnlyEventReceipt,
) -> LabResult<PathBuf> {
    let path = root.join("receipt.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(receipt.to_json().as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(path)
}

/// One atomically reserved evidence slot for a durable live-node invocation.
///
/// The reservation marker is retained even when an invocation fails or the
/// process stops between artifact writes. Consequently later invocations never
/// reuse one side of a partially written metrics/result pair.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveEvidenceInvocation {
    ordinal: u32,
    metrics_path: PathBuf,
    result_path: PathBuf,
}

impl LiveEvidenceInvocation {
    /// Reserves the next metrics/result suffix with an append-only marker.
    pub fn reserve(root: &Path) -> LabResult<Self> {
        fs::create_dir_all(root)?;
        if !fs::metadata(root)?.is_dir() {
            return Err(invalid("durable live-node root is not a directory"));
        }
        for ordinal in 1_u32..=MAX_LIVE_INVOCATIONS {
            let metrics_path = live_metrics_path(root, ordinal);
            let result_path = root.join(format!("live-result-{ordinal:04}.json"));
            let reservation_path = root.join(format!("live-invocation-{ordinal:04}.slot"));
            // Skip legacy or partially written evidence that predates slot
            // markers. A new invocation must never claim either artifact.
            if metrics_path.exists() || result_path.exists() {
                continue;
            }
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&reservation_path)
            {
                Ok(mut reservation) => {
                    writeln!(
                        reservation,
                        "ASTER_LAB_LIVE_INVOCATION\tversion=1\tordinal={ordinal}"
                    )?;
                    reservation.sync_all()?;
                    return Ok(Self {
                        ordinal,
                        metrics_path,
                        result_path,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(Box::new(error)),
            }
        }
        Err(invalid("durable live-node evidence sequence is exhausted"))
    }

    pub const fn ordinal(&self) -> u32 {
        self.ordinal
    }

    pub fn metrics_path(&self) -> &Path {
        &self.metrics_path
    }

    pub fn result_path(&self) -> &Path {
        &self.result_path
    }

    /// Writes this invocation's canonical aggregate metrics exactly once.
    pub fn write_metrics(&self, metrics: &LabMetrics) -> LabResult<PathBuf> {
        write_metrics_at(&self.metrics_path, metrics)?;
        Ok(self.metrics_path.clone())
    }

    /// Writes this invocation's live result exactly once.
    pub fn write_live_result(&self, metrics: &live::LiveMetrics) -> LabResult<PathBuf> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.result_path)?;
        file.write_all(metrics.to_json().as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(self.result_path.clone())
    }
}

fn live_metrics_path(root: &Path, ordinal: u32) -> PathBuf {
    if ordinal == 1 {
        root.join("metrics.json")
    } else {
        root.join(format!("metrics-{ordinal:04}.json"))
    }
}

fn write_metrics_at(path: &Path, metrics: &LabMetrics) -> LabResult<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(metrics.to_json().as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn drive_until_authenticated_quiet(
    left: &mut MeshService,
    right: &mut MeshService,
    probe: &NetworkProbe,
    limit: u64,
    pump_calls: &mut u64,
) -> LabResult<bool> {
    let before = *pump_calls;
    let mut previous_frames = probe.snapshot()?.frames_delivered;
    let mut quiet_pumps = 0_u16;
    while pump_calls.saturating_sub(before) < limit {
        pump_pair(left, right, pump_calls)?;
        let frames = probe.snapshot()?.frames_delivered;
        let left_status = left.active_contact();
        let right_status = right.active_contact();
        let authenticated = left_status
            .as_ref()
            .is_some_and(|status| status.authenticated)
            && right_status
                .as_ref()
                .is_some_and(|status| status.authenticated);
        let no_pending_objects = left_status
            .as_ref()
            .is_some_and(|status| status.pending_objects == 0)
            && right_status
                .as_ref()
                .is_some_and(|status| status.pending_objects == 0);
        if authenticated && no_pending_objects && frames == previous_frames {
            quiet_pumps = quiet_pumps.saturating_add(1);
        } else {
            quiet_pumps = 0;
        }
        previous_frames = frames;
        if quiet_pumps >= 256 && probe.pending_frames()? == 0 {
            return Ok(true);
        }
        wait_for_pair(left, right, *pump_calls);
    }
    Ok(false)
}

fn single_data_envelope(
    database: &Path,
    bundle: &[u8],
    topic: &Topic,
    scope: &Scope,
) -> LabResult<EnvelopeId> {
    let bundle = ProvisioningBundle::from_bytes(bundle)?;
    let mut node = open_reference_node(database, bundle, NodeConfig::default())?;
    let filter = InterestFilter {
        topics: vec![topic.as_str().to_owned()],
        scopes: vec![scope.as_str().to_owned()],
        min_priority: Priority::Routine as u8,
    };
    let descriptors = node
        .authorized_envelopes([0xff; 32], &[], &filter, InventoryPurpose::ReceiveBaseline)?
        .into_iter()
        .filter(|descriptor| !descriptor.control)
        .collect::<Vec<_>>();
    if descriptors.len() != 1 {
        return Err(invalid(format!(
            "expected one data envelope in {}, found {}",
            database.display(),
            descriptors.len()
        )));
    }
    Ok(descriptors[0].envelope_id)
}

fn tree_contains_any(root: &Path, needles: &[&[u8]]) -> LabResult<bool> {
    if !root.exists() {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() {
        return Err(invalid(format!(
            "refusing to scan symbolic link {}",
            root.display()
        )));
    }
    if metadata.is_file() {
        let bytes = fs::read(root)?;
        return Ok(needles
            .iter()
            .filter(|needle| !needle.is_empty())
            .any(|needle| bytes.windows(needle.len()).any(|window| window == *needle)));
    }
    if !metadata.is_dir() {
        return Ok(false);
    }
    for entry in fs::read_dir(root)? {
        if tree_contains_any(&entry?.path(), needles)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn drive_until_blob(
    left: &mut MeshService,
    right: &mut MeshService,
    scope: &Scope,
    topic: &Topic,
    id: aster_mesh::BlobId,
    limit: u64,
    pump_calls: &mut u64,
) -> LabResult<()> {
    let before = *pump_calls;
    while pump_calls.saturating_sub(before) < limit {
        pump_pair(left, right, pump_calls)?;
        if right.open_blob_reader(scope, topic, id).is_ok() {
            return Ok(());
        }
        wait_for_pair(left, right, *pump_calls);
    }
    Err(invalid(format!(
        "Blob contact did not complete within {limit} pump calls"
    )))
}

fn pump_pair(
    left: &mut MeshService,
    right: &mut MeshService,
    pump_calls: &mut u64,
) -> LabResult<()> {
    left.pump()?;
    *pump_calls = pump_calls.saturating_add(1);
    right.pump()?;
    *pump_calls = pump_calls.saturating_add(1);
    Ok(())
}

fn wait_for_pair(left: &MeshService, right: &MeshService, pump_calls: u64) {
    let now = Instant::now();
    let deadline = left
        .next_wakeup()
        .into_iter()
        .chain(right.next_wakeup())
        .filter(|deadline| *deadline > now)
        .min();
    if let Some(deadline) = deadline {
        thread::sleep(
            deadline
                .saturating_duration_since(now)
                .min(Duration::from_millis(50)),
        );
    } else if pump_calls.is_multiple_of(256) {
        thread::sleep(Duration::from_millis(1));
    } else {
        thread::yield_now();
    }
}

fn query_event_count(service: &mut MeshService, topic: &Topic, scope: &Scope) -> LabResult<usize> {
    Ok(service
        .query(Query {
            topic: Some(topic.clone()),
            scope: Some(scope.clone()),
            class: Some(DataClass::Event),
            limit: 4_096,
            ..Query::default()
        })?
        .len())
}

fn query_shard_event_count(
    service: &mut MeshService,
    topic: &Topic,
    scope: &Scope,
    shard_index: u32,
    items: u32,
) -> LabResult<usize> {
    if items <= 4_096 {
        return query_event_count(service, topic, scope);
    }
    let mut found = 0_usize;
    for ordinal in 0..items {
        let matches = service.query(Query {
            topic: Some(topic.clone()),
            scope: Some(scope.clone()),
            class: Some(DataClass::Event),
            logical_key: Some(format!("shard-{shard_index:04}-{ordinal:08}").into_bytes()),
            limit: 2,
            ..Query::default()
        })?;
        match matches.len() {
            0 => {}
            1 => found = found.saturating_add(1),
            _ => {
                return Err(invalid(format!(
                    "shard {shard_index} logical key {ordinal} returned duplicate projections"
                )));
            }
        }
    }
    Ok(found)
}

fn provision(
    seed: u64,
    first_serial: u64,
    count: u32,
    scope: &Scope,
    topic: &Topic,
) -> LabResult<Vec<Zeroizing<Vec<u8>>>> {
    let access = ProvisioningAccess::member(scope.clone(), vec![0], vec![topic.clone()])?;
    let mut provisioner = ReferenceProvisioner::from_seed(seed_bytes(seed))?;
    let mut bundles = Vec::with_capacity(usize::try_from(count)?);
    for index in 0..count {
        let serial = first_serial
            .checked_add(u64::from(index))
            .ok_or_else(|| invalid("provisioning serial overflow"))?;
        bundles.push(Zeroizing::new(
            provisioner
                .issue_node(serial, std::slice::from_ref(&access))?
                .to_bytes()?,
        ));
    }
    Ok(bundles)
}

fn options(topic: &Topic, scope: &Scope, application_bytes: u64, items: u32) -> ServiceOptions {
    let mut node = ApplicationNodeOptions::default();
    node.max_items = node
        .max_items
        .max(u64::from(items).saturating_mul(4).saturating_add(1_024));
    node.max_bytes = node.max_bytes.max(
        application_bytes
            .saturating_mul(4)
            .saturating_add(64 * 1024 * 1024),
    );
    let blobs = BlobStoreConfig {
        max_bytes: BlobStoreConfig::default().max_bytes.max(
            application_bytes
                .saturating_mul(4)
                .saturating_add(64 * 1024 * 1024),
        ),
        max_chunks: BlobStoreConfig::default().max_chunks.max(
            application_bytes
                .div_ceil(u64::from(MIN_BLOB_CHUNK_SIZE))
                .saturating_mul(4)
                .saturating_add(1_024),
        ),
    };
    ServiceOptions {
        node,
        blobs,
        sync: SyncProfile::new(vec![topic.clone()], vec![scope.clone()], Priority::Routine)
            .expect("fixed laboratory topic and scope form a valid profile"),
    }
}

fn validate_transfer(config: &TransferScenario) -> LabResult<()> {
    config.fault.validate()?;
    if config.items == 0 || config.items > 4_096 {
        return Err(invalid("transfer item count must be between 1 and 4096"));
    }
    if config.payload_bytes == 0 {
        return Err(invalid("transfer payload size must be nonzero"));
    }
    if config.max_pumps == 0 {
        return Err(invalid("transfer pump budget must be nonzero"));
    }
    Ok(())
}

fn validate_route_only_event(config: &RouteOnlyEventScenario) -> LabResult<()> {
    config.fault.validate()?;
    if config.payload_bytes < 32 || config.payload_bytes > 1024 * 1024 {
        return Err(invalid(
            "Phase-0 Event payload must be between 32 bytes and 1 MiB",
        ));
    }
    if config.max_pumps_per_contact < 512 {
        return Err(invalid("Phase-0 contact pump budget must be at least 512"));
    }
    validate_lower_hex("source revision", &config.source_revision, 40)?;
    validate_lower_hex("source diff SHA-256", &config.source_diff_sha256, 64)?;
    validate_lower_hex("binary SHA-256", &config.binary_sha256, 64)?;
    Ok(())
}

fn validate_lower_hex(name: &str, value: &str, length: usize) -> LabResult<()> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!(
            "{name} must contain exactly {length} lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn validate_blob(config: &BlobRecoveryScenario) -> LabResult<()> {
    config.fault.validate()?;
    if config.blob_bytes == 0 {
        return Err(invalid("Blob size must be nonzero"));
    }
    if !(MIN_BLOB_CHUNK_SIZE..=MAX_BLOB_CHUNK_SIZE).contains(&config.chunk_bytes) {
        return Err(invalid(format!(
            "Blob chunk size must be between {MIN_BLOB_CHUNK_SIZE} and {MAX_BLOB_CHUNK_SIZE}"
        )));
    }
    if config.restart_after_delivered_frames == 0 || config.max_pumps_per_contact == 0 {
        return Err(invalid("Blob checkpoint and pump budget must be nonzero"));
    }
    Ok(())
}

fn validate_shard(config: &ShardScenario) -> LabResult<()> {
    config.fault.validate()?;
    if config.nodes == 0 {
        return Err(invalid("a shard must contain at least one node"));
    }
    if config.items == 0 || config.items > MAX_SHARD_ITEMS {
        return Err(invalid(format!(
            "shard item count must be between 1 and {MAX_SHARD_ITEMS}"
        )));
    }
    if config.items > 4_096 && config.nodes != 1 {
        return Err(invalid(
            "more than 4096 items is reserved for the one-node resource working-set scenario",
        ));
    }
    if config.payload_bytes == 0 || config.max_pumps_per_edge == 0 {
        return Err(invalid("shard payload and pump budget must be nonzero"));
    }
    Ok(())
}

fn prepare_fresh_directory(path: &Path) -> LabResult<()> {
    if path.exists() {
        for entry in fs::read_dir(path)? {
            if entry?.file_name() != std::ffi::OsStr::new(SCENARIO_OWNERSHIP_FILE) {
                return Err(invalid(format!(
                    "run directory {} is not empty; refusing to mix evidence",
                    path.display()
                )));
            }
        }
    }
    fs::create_dir_all(path)?;
    Ok(())
}

fn priority_for(ordinal: u32) -> Priority {
    match ordinal % 4 {
        0 => Priority::Flash,
        1 => Priority::Immediate,
        2 => Priority::Priority,
        _ => Priority::Routine,
    }
}

fn pattern_bytes(length: usize, seed: u64, stream: u64) -> Vec<u8> {
    (0..length)
        .map(|offset| pattern_byte(seed, stream, offset as u64))
        .collect()
}

fn pattern_byte(seed: u64, stream: u64, offset: u64) -> u8 {
    let value = offset
        .wrapping_mul(0x9e37_79b1)
        .wrapping_add(stream.wrapping_mul(0x85eb_ca77))
        ^ seed.rotate_left((stream % 63) as u32);
    (mix64(value) % 251) as u8
}

fn seed_bytes(seed: u64) -> [u8; 32] {
    let mut result = [0_u8; 32];
    for (index, chunk) in result.chunks_exact_mut(8).enumerate() {
        let value = mix64(seed ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15));
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    if result == [0; 32] {
        result[0] = 1;
    }
    result
}

fn mix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn virtual_bytes_per_tick(profile: FaultProfile) -> u64 {
    let bits = u128::from(profile.bits_per_second).saturating_mul(u128::from(profile.tick_ms));
    let bytes = bits.div_ceil(8_000);
    u64::try_from(bytes).unwrap_or(u64::MAX).max(1)
}

fn serialization_floor(profile: FaultProfile) -> Duration {
    let frame_bits = u128::from(profile.mtu).saturating_mul(8);
    let serialization_ms = frame_bits
        .saturating_mul(1_000)
        .div_ceil(u128::from(profile.bits_per_second));
    let floor_ms = serialization_ms
        .max(u128::from(profile.tick_ms))
        .clamp(1, 60_000);
    Duration::from_millis(u64::try_from(floor_ms).unwrap_or(60_000))
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn parse_number<T>(name: &str, value: &str) -> LabResult<T>
where
    T: std::str::FromStr,
    T::Err: Error + Send + Sync + 'static,
{
    value
        .parse()
        .map_err(|error| invalid(format!("invalid {name}: {error}")))
}

fn parse_bool(name: &str, value: &str) -> LabResult<bool> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(invalid(format!("invalid {name}: expected true or false"))),
    }
}

fn invalid(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> io::Error {
    io::Error::other("laboratory link lock poisoned")
}

#[derive(Debug)]
struct PatternSource {
    length: u64,
    position: u64,
    seed: u64,
    stream: u64,
}

impl PatternSource {
    fn new(length: u64, seed: u64, stream: u64) -> Self {
        Self {
            length,
            position: 0,
            seed,
            stream,
        }
    }
}

impl Read for PatternSource {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let remaining = self.length.saturating_sub(self.position);
        let count = usize::try_from(remaining.min(output.len() as u64)).unwrap_or(output.len());
        for (index, byte) in output[..count].iter_mut().enumerate() {
            *byte = pattern_byte(self.seed, self.stream, self.position + index as u64);
        }
        self.position = self.position.saturating_add(count as u64);
        Ok(count)
    }
}

impl Seek for PatternSource {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let target = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::End(delta) => i128::from(self.length) + i128::from(delta),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
        };
        if target < 0 || target > i128::from(self.length) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pattern source seek is out of bounds",
            ));
        }
        self.position = u64::try_from(target).map_err(io::Error::other)?;
        Ok(self.position)
    }
}

struct PatternVerifier {
    length: u64,
    position: u64,
    seed: u64,
    stream: u64,
}

impl PatternVerifier {
    fn new(length: u64, seed: u64, stream: u64) -> Self {
        Self {
            length,
            position: 0,
            seed,
            stream,
        }
    }

    fn complete(&self) -> bool {
        self.position == self.length
    }
}

impl Write for PatternVerifier {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.position.saturating_add(bytes.len() as u64) > self.length {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "recovered Blob exceeds expected length",
            ));
        }
        for (index, byte) in bytes.iter().copied().enumerate() {
            let expected = pattern_byte(self.seed, self.stream, self.position + index as u64);
            if byte != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "recovered Blob plaintext differs from deterministic source",
                ));
            }
        }
        self.position = self.position.saturating_add(bytes.len() as u64);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static SCENARIO_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_path(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        std::env::temp_dir().join(format!(
            "aster-lab-{label}-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock must follow Unix epoch")
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ))
    }

    #[test]
    fn metrics_record_round_trips() {
        let expected = LabMetrics {
            scenario: "shard".into(),
            seed: 9,
            shards: 1,
            nodes: 7,
            published_items: 2,
            delivered_items: 14,
            frames_dropped: 3,
            converged: true,
            ..LabMetrics::default()
        };
        assert_eq!(
            LabMetrics::from_record(&expected.to_record()).unwrap(),
            expected
        );
    }

    #[test]
    fn metrics_record_rejects_missing_and_duplicate_fields() {
        let record = LabMetrics {
            scenario: "shard-0000".into(),
            converged: true,
            ..LabMetrics::default()
        }
        .to_record();
        let missing = record.replace("\tseed=0", "");
        assert!(LabMetrics::from_record(&missing).is_err());
        let duplicate = format!("{record}\tseed=0");
        assert!(LabMetrics::from_record(&duplicate).is_err());
    }

    #[test]
    fn durable_live_evidence_uses_one_slot_after_failures_and_partial_writes() {
        let root = test_path("metrics-sequence");
        fs::create_dir_all(&root).unwrap();
        let failed_metrics = LabMetrics {
            scenario: "node-udp".into(),
            seed: 1,
            ..LabMetrics::default()
        };
        let successful_metrics = LabMetrics {
            scenario: "node-udp".into(),
            seed: 2,
            converged: true,
            ..LabMetrics::default()
        };
        let live = live::LiveMetrics {
            node: [0x11; 32],
            peer: [0x22; 32],
            carrier: live::CarrierKind::FixedUdp,
            local_endpoint: None,
            resolved_peer_endpoint: None,
            durable_reopen: true,
            published_this_run: 0,
            reused_publications: 1,
            observed_items: 1,
            pump_calls: 8,
            authenticated_pumps: 4,
            maximum_pending_objects: 1,
            elapsed_ms: 10,
            authenticated: true,
            converged: true,
        };

        let failed = LiveEvidenceInvocation::reserve(&root).unwrap();
        assert_eq!(failed.ordinal(), 1);
        assert_eq!(failed.metrics_path(), root.join("metrics.json"));
        failed.write_metrics(&failed_metrics).unwrap();

        let successful = LiveEvidenceInvocation::reserve(&root).unwrap();
        assert_eq!(successful.ordinal(), 2);
        assert_eq!(successful.result_path(), root.join("live-result-0002.json"));
        assert_eq!(successful.metrics_path(), root.join("metrics-0002.json"));
        successful.write_live_result(&live).unwrap();
        successful.write_metrics(&successful_metrics).unwrap();

        let partial = LiveEvidenceInvocation::reserve(&root).unwrap();
        assert_eq!(partial.ordinal(), 3);
        partial.write_live_result(&live).unwrap();
        let after_partial = LiveEvidenceInvocation::reserve(&root).unwrap();
        assert_eq!(after_partial.ordinal(), 4);
        assert_eq!(after_partial.metrics_path(), root.join("metrics-0004.json"));
        assert_eq!(
            after_partial.result_path(),
            root.join("live-result-0004.json")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn loss_is_exact_for_each_complete_direction_window() {
        let profile = FaultProfile {
            loss_per_mille: 500,
            ..FaultProfile::default()
        };
        let (left, right, probe) = FaultLink::pair("loss", [1; 32], [2; 32], profile).unwrap();
        for _ in 0..LOSS_WINDOW_FRAMES {
            left.send(Some([2; 32]), &[0; 64]).unwrap();
            right.send(Some([1; 32]), &[0; 64]).unwrap();
        }
        let stats = probe.snapshot().unwrap();
        assert_eq!(stats.frames_offered, 2_000);
        assert_eq!(stats.frames_dropped, 1_000);
    }

    #[test]
    fn two_node_public_host_transfer_survives_reopen() {
        let _guard = SCENARIO_TEST_LOCK.lock().unwrap();
        let root = test_path("transfer");
        let metrics = run_transfer(&TransferScenario {
            root: root.clone(),
            seed: 41,
            items: 2,
            payload_bytes: 24_000,
            restart_after_delivered_frames: Some(12),
            max_pumps: 30_000,
            fault: FaultProfile {
                bits_per_second: 32_000,
                loss_per_mille: 0,
                reorder_ticks: 2,
                ..FaultProfile::default()
            },
        })
        .unwrap();
        assert!(metrics.converged);
        assert_eq!(metrics.restarts, 1);
        assert_eq!(metrics.delivered_items, 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn single_item_root_offer_converges_without_contact_teardown() {
        let _guard = SCENARIO_TEST_LOCK.lock().unwrap();
        let root = test_path("single-root-offer");
        let metrics = run_transfer(&TransferScenario {
            root: root.clone(),
            seed: 1,
            items: 1,
            payload_bytes: 16 * 1_024,
            restart_after_delivered_frames: None,
            max_pumps: 30_000,
            fault: FaultProfile::default(),
        })
        .unwrap();
        assert!(metrics.converged);
        assert_eq!(metrics.delivered_items, 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn route_only_event_survives_reopen_and_is_acknowledged_by_consumer() {
        let _guard = SCENARIO_TEST_LOCK.lock().unwrap();
        let root = test_path("phase0-route-only-event");
        let result = run_route_only_event(&RouteOnlyEventScenario {
            root: root.clone(),
            seed: 59,
            payload_bytes: 1_024,
            max_pumps_per_contact: 50_000,
            fault: FaultProfile::default(),
            source_revision: "11".repeat(20),
            source_diff_sha256: "22".repeat(32),
            binary_sha256: "33".repeat(32),
        })
        .unwrap();
        assert!(result.metrics.converged);
        assert_eq!(result.metrics.restarts, 1);
        assert!(result.receipt.a_to_b_authenticated);
        assert!(result.receipt.relay_application_unreadable);
        assert!(result.receipt.relay_payload_absent_at_rest);
        assert!(result.receipt.relay_payload_digest_absent_at_rest);
        assert!(result.receipt.relay_reopened_with_source_envelope);
        assert!(result.receipt.b_to_c_authenticated);
        assert!(result.receipt.consumer_received_same_item);
        assert!(result.receipt.consumer_received_same_envelope);
        assert!(result.receipt.application_acknowledged);
        assert_eq!(result.receipt.post_ack_deliveries, 0);
        assert_eq!(result.receipt.a_c_contact_count, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shard_chain_republishes_received_objects() {
        let _guard = SCENARIO_TEST_LOCK.lock().unwrap();
        let root = test_path("shard");
        let metrics = run_shard(&ShardScenario {
            root: root.clone(),
            seed: 73,
            shard_index: 2,
            first_node: 20,
            nodes: 3,
            items: 4,
            payload_bytes: 1_024,
            max_pumps_per_edge: 20_000,
            fault: FaultProfile::default(),
        })
        .unwrap();
        assert!(metrics.converged);
        assert_eq!(metrics.delivered_items, 12);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shard_validation_includes_required_ten_thousand_item_working_set() {
        let mut scenario = ShardScenario {
            root: test_path("shard-limit"),
            seed: 79,
            shard_index: 0,
            first_node: 0,
            nodes: 1,
            items: MAX_SHARD_ITEMS,
            payload_bytes: 64,
            max_pumps_per_edge: 1,
            fault: FaultProfile::default(),
        };
        assert!(validate_shard(&scenario).is_ok());
        scenario.nodes = 2;
        assert!(validate_shard(&scenario).is_err());
        scenario.nodes = 1;
        scenario.items = MAX_SHARD_ITEMS + 1;
        assert!(validate_shard(&scenario).is_err());
    }

    #[test]
    fn blob_recovery_reopens_and_switches_to_alternate_peer() {
        let _guard = SCENARIO_TEST_LOCK.lock().unwrap();
        let root = test_path("blob-recovery");
        let metrics = run_blob_recovery(&BlobRecoveryScenario {
            root: root.clone(),
            seed: 97,
            blob_bytes: 96 * 1_024,
            chunk_bytes: MIN_BLOB_CHUNK_SIZE,
            restart_after_delivered_frames: 16,
            max_pumps_per_contact: 50_000,
            fault: FaultProfile {
                bits_per_second: 64_000,
                reorder_ticks: 1,
                tick_ms: 1_000,
                ..FaultProfile::default()
            },
        })
        .unwrap();
        assert!(metrics.converged);
        assert_eq!(metrics.restarts, 1);
        assert!(metrics.partial_restart_observed);
        assert!(metrics.partial_durable_blob_bytes > 0);
        assert_eq!(
            metrics.reopened_durable_blob_bytes,
            metrics.partial_durable_blob_bytes
        );
        assert!(metrics.durable_progress_preserved);
        assert_eq!(metrics.blob_bytes, 96 * 1_024);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn blob_recovery_rejects_a_contact_that_completed_before_restart() {
        let _guard = SCENARIO_TEST_LOCK.lock().unwrap();
        let root = test_path("blob-not-partial");
        let error = run_blob_recovery(&BlobRecoveryScenario {
            root: root.clone(),
            seed: 101,
            blob_bytes: 32 * 1_024,
            chunk_bytes: MIN_BLOB_CHUNK_SIZE,
            restart_after_delivered_frames: u64::MAX,
            max_pumps_per_contact: 50_000,
            fault: FaultProfile {
                bits_per_second: 1_000_000,
                tick_ms: 1_000,
                ..FaultProfile::default()
            },
        })
        .unwrap_err();
        assert!(error.to_string().contains("partial contact"));
        let evidence = fs::read_to_string(root.join("metrics.json")).unwrap();
        assert!(evidence.contains("\"partial_restart_observed\": false"));
        assert!(evidence.contains("\"converged\": false"));
        fs::remove_dir_all(root).unwrap();
    }
}

}
