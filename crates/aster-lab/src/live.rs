//! Process-oriented IP laboratory helpers.
//!
//! This module composes only the public Aster application, host, and carrier
//! APIs.  It deliberately keeps provisioning bundles and carrier capabilities
//! out of metrics and manifests.  A first provisioning run obtains fresh node
//! identity entropy from the reference provisioner; deterministic laboratory
//! inputs govern file names, serials, manifest order, and application canaries.
//! Reopening an existing node reuses its protected bundle and durable stores.

#![forbid(unsafe_code)]

use crate::LabResult;
use aster_host::{MeshService, ServiceOptions, SyncProfile};
use aster_ip::{CipherRelayServer, IpLink, RelayLink, RendezvousServer, RendezvousToken};
use aster_mesh::blob::BlobStoreConfig;
use aster_mesh::link::Link;
use aster_mesh::{
    ApplicationNodeOptions, DataClass, NodeId, Priority, ProvisioningAccess, ProvisioningBundle,
    PublishRequest, Query, ReferenceEnvelopeSealer, ReferenceProvisioner, Scope, Topic,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

const MAX_LIVE_NODES: u32 = 4_096;
const MAX_LIVE_ITEMS: u32 = 4_096;
const MAX_CANARY_BYTES: usize = 1_048_576;
const MAX_CANARY_TOTAL_BYTES: usize = 64 * 1_048_576;
const MAX_BUNDLE_BYTES: usize = 1_048_576;
const MAX_METRICS_BYTES: usize = 8_192;
const MANIFEST_HEADER: &str = "ASTER_LAB_NODE_MANIFEST";
const MANIFEST_VERSION: u16 = 1;
const METRICS_HEADER: &str = "ASTER_LAB_LIVE_METRICS";
const METRICS_VERSION: u16 = 1;
const CANARY_PREFIX: &[u8] = b"ASTER-LAB-CANARY/v1\0";

/// Fresh provisioning configuration for a process-oriented laboratory.
///
/// `authority_seed` is protected input. It is redacted from `Debug` and erased
/// when this value is dropped. The caller remains responsible for obtaining it
/// from an appropriate random source outside reproducible simulation runs.
pub struct ProvisionConfig {
    pub root: PathBuf,
    pub nodes: u32,
    pub first_serial: u64,
    pub topic: Topic,
    pub scope: Scope,
    authority_seed: [u8; 32],
}

impl ProvisionConfig {
    pub fn new(
        root: PathBuf,
        authority_seed: [u8; 32],
        nodes: u32,
        first_serial: u64,
        topic: Topic,
        scope: Scope,
    ) -> Self {
        Self {
            root,
            nodes,
            first_serial,
            topic,
            scope,
            authority_seed,
        }
    }
}

impl fmt::Debug for ProvisionConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProvisionConfig")
            .field("root", &self.root)
            .field("nodes", &self.nodes)
            .field("first_serial", &self.first_serial)
            .field("topic", &self.topic)
            .field("scope", &self.scope)
            .field("authority_seed", &"[REDACTED]")
            .finish()
    }
}

impl Drop for ProvisionConfig {
    fn drop(&mut self) {
        self.authority_seed.zeroize();
    }
}

/// One public entry in the provisioned node manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestNode {
    pub index: u32,
    pub serial: u64,
    pub identity: NodeId,
}

/// Public, deterministic-order NodeID manifest. It contains no credential path
/// or carrier capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeManifest {
    pub topic: Topic,
    pub scope: Scope,
    pub nodes: Vec<ManifestNode>,
}

impl NodeManifest {
    pub fn to_text(&self) -> String {
        let mut output = format!(
            "{MANIFEST_HEADER}\tversion={MANIFEST_VERSION}\ttopic={}\tscope={}\tnodes={}\n",
            self.topic.as_str(),
            self.scope.as_str(),
            self.nodes.len()
        );
        output.push_str("index\tserial\tnode_id\n");
        for node in &self.nodes {
            output.push_str(&format!(
                "{}\t{}\t{}\n",
                node.index,
                node.serial,
                encode_node_id(&node.identity)
            ));
        }
        output
    }

    pub fn from_text(text: &str) -> LabResult<Self> {
        if text.len() > MAX_METRICS_BYTES.saturating_mul(64) {
            return Err(invalid("node manifest exceeds the laboratory bound"));
        }
        let mut lines = text.lines();
        let header = lines
            .next()
            .ok_or_else(|| invalid("node manifest is empty"))?;
        let mut header_fields = header.split('\t');
        if header_fields.next() != Some(MANIFEST_HEADER) {
            return Err(invalid("not an Aster laboratory node manifest"));
        }
        let mut values = BTreeMap::new();
        for field in header_fields {
            let (name, value) = field
                .split_once('=')
                .ok_or_else(|| invalid("malformed node manifest header"))?;
            if values.insert(name, value).is_some() {
                return Err(invalid("duplicate node manifest header field"));
            }
        }
        let version: u16 = parse_required(&values, "version")?;
        if version != MANIFEST_VERSION {
            return Err(invalid("unsupported node manifest version"));
        }
        let topic = Topic::new(required_text(&values, "topic")?.to_owned())?;
        let scope = Scope::new(required_text(&values, "scope")?.to_owned())?;
        let count: usize = parse_required(&values, "nodes")?;
        if count == 0 || count > MAX_LIVE_NODES as usize {
            return Err(invalid(
                "node manifest count is outside the laboratory bound",
            ));
        }
        if lines.next() != Some("index\tserial\tnode_id") {
            return Err(invalid("node manifest has no canonical column header"));
        }
        let mut nodes = Vec::with_capacity(count);
        let mut identities = BTreeSet::new();
        for expected_index in 0..count {
            let line = lines
                .next()
                .ok_or_else(|| invalid("node manifest is truncated"))?;
            let mut fields = line.split('\t');
            let index: u32 = parse_value("index", fields.next())?;
            let serial: u64 = parse_value("serial", fields.next())?;
            let identity = parse_node_id(
                fields
                    .next()
                    .ok_or_else(|| invalid("node manifest row is truncated"))?,
            )?;
            if fields.next().is_some() || index != u32::try_from(expected_index)? || serial == 0 {
                return Err(invalid("node manifest row is non-canonical"));
            }
            if !identities.insert(identity) {
                return Err(invalid("node manifest contains a duplicate NodeID"));
            }
            nodes.push(ManifestNode {
                index,
                serial,
                identity,
            });
        }
        if lines.any(|line| !line.is_empty()) {
            return Err(invalid("node manifest has trailing rows"));
        }
        Ok(Self {
            topic,
            scope,
            nodes,
        })
    }
}

/// One protected credential created by [`provision_private_nodes`]. The path is
/// returned to the local orchestrator but is never included in the public
/// manifest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisionedNode {
    pub manifest: ManifestNode,
    pub credential_path: PathBuf,
}

/// Result of a fresh provisioning operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProvisioningSummary {
    pub manifest_path: PathBuf,
    pub manifest: NodeManifest,
    pub private_nodes: Vec<ProvisionedNode>,
}

/// Issues fresh bundles into a mode-0700 directory and writes a public NodeID
/// manifest in deterministic serial/index order.
///
/// The root must be absent or empty. Existing files are never overwritten and
/// a partial failed run is intentionally retained for evidence review.
pub fn provision_private_nodes(config: ProvisionConfig) -> LabResult<ProvisioningSummary> {
    validate_provision(&config)?;
    prepare_fresh_root(&config.root)?;
    let private = config.root.join("private");
    create_private_directory(&private)?;

    let access =
        ProvisioningAccess::member(config.scope.clone(), vec![0], vec![config.topic.clone()])?;
    let mut provisioner = ReferenceProvisioner::from_seed(config.authority_seed)?;
    let mut nodes = Vec::with_capacity(usize::try_from(config.nodes)?);
    let mut private_nodes = Vec::with_capacity(usize::try_from(config.nodes)?);
    for index in 0..config.nodes {
        let serial = config
            .first_serial
            .checked_add(u64::from(index))
            .ok_or_else(|| invalid("provisioning serial overflow"))?;
        let bundle = provisioner.issue_node(serial, std::slice::from_ref(&access))?;
        let mut encoded = SecretBytes(bundle.to_bytes()?);
        let identity_bundle = ProvisioningBundle::from_bytes(encoded.as_slice())?;
        let identity_service = ReferenceEnvelopeSealer::open(identity_bundle)?;
        let identity = identity_service.identity();
        drop(identity_service);

        let credential_path = private.join(format!("node-{index:04}.bundle"));
        write_private_new(&credential_path, encoded.as_slice())?;
        encoded.erase();
        let manifest = ManifestNode {
            index,
            serial,
            identity,
        };
        nodes.push(manifest.clone());
        private_nodes.push(ProvisionedNode {
            manifest,
            credential_path,
        });
    }

    let manifest = NodeManifest {
        topic: config.topic.clone(),
        scope: config.scope.clone(),
        nodes,
    };
    let manifest_path = config.root.join("manifest.tsv");
    write_public_new(&manifest_path, manifest.to_text().as_bytes())?;
    Ok(ProvisioningSummary {
        manifest_path,
        manifest,
        private_nodes,
    })
}

/// Carrier used by one long-running process. Secret capability values are
/// redacted from `Debug` and erased when dropped.
pub enum LiveCarrier {
    FixedUdp {
        bind: SocketAddr,
        peer_address: SocketAddr,
        discovery_token: [u8; 16],
    },
    RendezvousUdp {
        bind: SocketAddr,
        server: SocketAddr,
        pairing_token: RendezvousToken,
        discovery_token: [u8; 16],
        resolution_timeout: Duration,
        request_interval: Duration,
    },
    DiscoveryUdp {
        bind: SocketAddr,
        discovery_target: SocketAddr,
        discovery_token: [u8; 16],
        resolution_timeout: Duration,
        announce_interval: Duration,
    },
    Relay {
        server: SocketAddr,
        channel: [u8; 32],
        connect_timeout: Duration,
    },
}

impl LiveCarrier {
    pub fn fixed_udp(
        bind: SocketAddr,
        peer_address: SocketAddr,
        discovery_token: [u8; 16],
    ) -> Self {
        Self::FixedUdp {
            bind,
            peer_address,
            discovery_token,
        }
    }

    pub fn rendezvous_udp(
        bind: SocketAddr,
        server: SocketAddr,
        pairing_token: RendezvousToken,
        discovery_token: [u8; 16],
        resolution_timeout: Duration,
        request_interval: Duration,
    ) -> Self {
        Self::RendezvousUdp {
            bind,
            server,
            pairing_token,
            discovery_token,
            resolution_timeout,
            request_interval,
        }
    }

    pub fn discovery_udp(
        bind: SocketAddr,
        discovery_target: SocketAddr,
        discovery_token: [u8; 16],
        resolution_timeout: Duration,
        announce_interval: Duration,
    ) -> Self {
        Self::DiscoveryUdp {
            bind,
            discovery_target,
            discovery_token,
            resolution_timeout,
            announce_interval,
        }
    }

    pub fn relay(server: SocketAddr, channel: [u8; 32], connect_timeout: Duration) -> Self {
        Self::Relay {
            server,
            channel,
            connect_timeout,
        }
    }

    pub fn kind(&self) -> CarrierKind {
        match self {
            Self::FixedUdp { .. } => CarrierKind::FixedUdp,
            Self::RendezvousUdp { .. } => CarrierKind::RendezvousUdp,
            Self::DiscoveryUdp { .. } => CarrierKind::DiscoveryUdp,
            Self::Relay { .. } => CarrierKind::Relay,
        }
    }
}

impl fmt::Debug for LiveCarrier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FixedUdp {
                bind, peer_address, ..
            } => formatter
                .debug_struct("FixedUdp")
                .field("bind", bind)
                .field("peer_address", peer_address)
                .field("discovery_token", &"[REDACTED]")
                .finish(),
            Self::RendezvousUdp {
                bind,
                server,
                resolution_timeout,
                request_interval,
                ..
            } => formatter
                .debug_struct("RendezvousUdp")
                .field("bind", bind)
                .field("server", server)
                .field("pairing_token", &"[REDACTED]")
                .field("discovery_token", &"[REDACTED]")
                .field("resolution_timeout", resolution_timeout)
                .field("request_interval", request_interval)
                .finish(),
            Self::DiscoveryUdp {
                bind,
                discovery_target,
                resolution_timeout,
                announce_interval,
                ..
            } => formatter
                .debug_struct("DiscoveryUdp")
                .field("bind", bind)
                .field("discovery_target", discovery_target)
                .field("discovery_token", &"[REDACTED]")
                .field("resolution_timeout", resolution_timeout)
                .field("announce_interval", announce_interval)
                .finish(),
            Self::Relay {
                server,
                connect_timeout,
                ..
            } => formatter
                .debug_struct("Relay")
                .field("server", server)
                .field("channel", &"[REDACTED]")
                .field("connect_timeout", connect_timeout)
                .finish(),
        }
    }
}

impl Drop for LiveCarrier {
    fn drop(&mut self) {
        match self {
            Self::FixedUdp {
                discovery_token, ..
            }
            | Self::RendezvousUdp {
                discovery_token, ..
            }
            | Self::DiscoveryUdp {
                discovery_token, ..
            } => discovery_token.zeroize(),
            Self::Relay { channel, .. } => channel.zeroize(),
        }
        if let Self::RendezvousUdp { pairing_token, .. } = self {
            pairing_token.zeroize();
        }
    }
}

/// Stable carrier label used in bounded metrics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierKind {
    FixedUdp,
    RendezvousUdp,
    DiscoveryUdp,
    Relay,
}

impl CarrierKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FixedUdp => "fixed-udp",
            Self::RendezvousUdp => "rendezvous-udp",
            Self::DiscoveryUdp => "discovery-udp",
            Self::Relay => "relay",
        }
    }

    fn parse(value: &str) -> LabResult<Self> {
        match value {
            "fixed-udp" => Ok(Self::FixedUdp),
            "rendezvous-udp" => Ok(Self::RendezvousUdp),
            "discovery-udp" => Ok(Self::DiscoveryUdp),
            "relay" => Ok(Self::Relay),
            _ => Err(invalid("unknown live carrier metrics value")),
        }
    }
}

/// One durable live-node run. All configurable application values are bounded
/// before any bundle is read or network socket is opened.
pub struct LiveNodeConfig {
    pub root: PathBuf,
    pub credential_path: PathBuf,
    pub peer: NodeId,
    pub topic: Topic,
    pub scope: Scope,
    pub workload_seed: u64,
    pub publish_items: u32,
    pub payload_bytes: usize,
    pub expected_items: u32,
    pub max_pumps: u64,
    pub max_runtime: Duration,
    pub query_every_pumps: u32,
    pub idle_sleep: Duration,
    pub metrics_path: Option<PathBuf>,
    carrier: LiveCarrier,
}

impl LiveNodeConfig {
    pub fn new(
        root: PathBuf,
        credential_path: PathBuf,
        peer: NodeId,
        topic: Topic,
        scope: Scope,
        carrier: LiveCarrier,
    ) -> Self {
        Self {
            metrics_path: Some(root.join("live-metrics.txt")),
            root,
            credential_path,
            peer,
            topic,
            scope,
            workload_seed: 1,
            publish_items: 0,
            payload_bytes: 1_024,
            expected_items: 0,
            max_pumps: 1_000_000,
            max_runtime: Duration::from_secs(60),
            query_every_pumps: 16,
            idle_sleep: Duration::from_millis(1),
            carrier,
        }
    }

    pub fn carrier_kind(&self) -> CarrierKind {
        self.carrier.kind()
    }
}

impl fmt::Debug for LiveNodeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LiveNodeConfig")
            .field("root", &self.root)
            .field("credential_path", &self.credential_path)
            .field("peer", &encode_node_id(&self.peer))
            .field("topic", &self.topic)
            .field("scope", &self.scope)
            .field("workload_seed", &self.workload_seed)
            .field("publish_items", &self.publish_items)
            .field("payload_bytes", &self.payload_bytes)
            .field("expected_items", &self.expected_items)
            .field("max_pumps", &self.max_pumps)
            .field("max_runtime", &self.max_runtime)
            .field("query_every_pumps", &self.query_every_pumps)
            .field("idle_sleep", &self.idle_sleep)
            .field("metrics_path", &self.metrics_path)
            .field("carrier", &self.carrier)
            .finish()
    }
}

/// Stable, bounded result from one live node process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveMetrics {
    pub node: NodeId,
    pub peer: NodeId,
    pub carrier: CarrierKind,
    pub local_endpoint: Option<SocketAddr>,
    pub resolved_peer_endpoint: Option<SocketAddr>,
    pub durable_reopen: bool,
    pub published_this_run: u32,
    pub reused_publications: u32,
    pub observed_items: u32,
    pub pump_calls: u64,
    pub authenticated_pumps: u64,
    pub maximum_pending_objects: u32,
    pub elapsed_ms: u64,
    pub authenticated: bool,
    pub converged: bool,
}

impl LiveMetrics {
    pub fn to_record(&self) -> String {
        format!(
            concat!(
                "{}\tversion={}",
                "\tnode={}\tpeer={}\tcarrier={}",
                "\tlocal_endpoint={}\tresolved_peer_endpoint={}",
                "\tdurable_reopen={}\tpublished_this_run={}",
                "\treused_publications={}\tobserved_items={}",
                "\tpump_calls={}\tauthenticated_pumps={}",
                "\tmaximum_pending_objects={}\telapsed_ms={}",
                "\tauthenticated={}\tconverged={}"
            ),
            METRICS_HEADER,
            METRICS_VERSION,
            encode_node_id(&self.node),
            encode_node_id(&self.peer),
            self.carrier.as_str(),
            display_endpoint(self.local_endpoint),
            display_endpoint(self.resolved_peer_endpoint),
            self.durable_reopen,
            self.published_this_run,
            self.reused_publications,
            self.observed_items,
            self.pump_calls,
            self.authenticated_pumps,
            self.maximum_pending_objects,
            self.elapsed_ms,
            self.authenticated,
            self.converged
        )
    }

    pub fn from_record(record: &str) -> LabResult<Self> {
        if record.len() > MAX_METRICS_BYTES {
            return Err(invalid("live metrics record exceeds the laboratory bound"));
        }
        let mut fields = record.trim().split('\t');
        if fields.next() != Some(METRICS_HEADER) {
            return Err(invalid("not an Aster live metrics record"));
        }
        let mut values = BTreeMap::new();
        for field in fields {
            let (name, value) = field
                .split_once('=')
                .ok_or_else(|| invalid("malformed live metrics field"))?;
            if values.insert(name, value).is_some() {
                return Err(invalid("duplicate live metrics field"));
            }
        }
        let version: u16 = parse_required(&values, "version")?;
        if version != METRICS_VERSION {
            return Err(invalid("unsupported live metrics version"));
        }
        Ok(Self {
            node: parse_node_id(required_text(&values, "node")?)?,
            peer: parse_node_id(required_text(&values, "peer")?)?,
            carrier: CarrierKind::parse(required_text(&values, "carrier")?)?,
            local_endpoint: parse_endpoint(required_text(&values, "local_endpoint")?)?,
            resolved_peer_endpoint: parse_endpoint(required_text(
                &values,
                "resolved_peer_endpoint",
            )?)?,
            durable_reopen: parse_required(&values, "durable_reopen")?,
            published_this_run: parse_required(&values, "published_this_run")?,
            reused_publications: parse_required(&values, "reused_publications")?,
            observed_items: parse_required(&values, "observed_items")?,
            pump_calls: parse_required(&values, "pump_calls")?,
            authenticated_pumps: parse_required(&values, "authenticated_pumps")?,
            maximum_pending_objects: parse_required(&values, "maximum_pending_objects")?,
            elapsed_ms: parse_required(&values, "elapsed_ms")?,
            authenticated: parse_required(&values, "authenticated")?,
            converged: parse_required(&values, "converged")?,
        })
    }

    pub fn to_json(&self) -> String {
        format!(
            concat!(
                "{{\n",
                "  \"schema\": \"aster-lab-live-metrics/v1\",\n",
                "  \"node\": \"{}\",\n",
                "  \"peer\": \"{}\",\n",
                "  \"carrier\": \"{}\",\n",
                "  \"local_endpoint\": {},\n",
                "  \"resolved_peer_endpoint\": {},\n",
                "  \"durable_reopen\": {},\n",
                "  \"published_this_run\": {},\n",
                "  \"reused_publications\": {},\n",
                "  \"observed_items\": {},\n",
                "  \"pump_calls\": {},\n",
                "  \"authenticated_pumps\": {},\n",
                "  \"maximum_pending_objects\": {},\n",
                "  \"elapsed_ms\": {},\n",
                "  \"authenticated\": {},\n",
                "  \"converged\": {}\n",
                "}}"
            ),
            encode_node_id(&self.node),
            encode_node_id(&self.peer),
            self.carrier.as_str(),
            json_endpoint(self.local_endpoint),
            json_endpoint(self.resolved_peer_endpoint),
            self.durable_reopen,
            self.published_this_run,
            self.reused_publications,
            self.observed_items,
            self.pump_calls,
            self.authenticated_pumps,
            self.maximum_pending_objects,
            self.elapsed_ms,
            self.authenticated,
            self.converged
        )
    }
}

/// Opens one durable node, resolves/configures its carrier, publishes missing
/// local canaries exactly once, and drives the authenticated contact until its
/// deadline, pump bound, or configured convergence count.
pub fn run_live_node(config: LiveNodeConfig) -> LabResult<LiveMetrics> {
    validate_live_node(&config)?;
    fs::create_dir_all(&config.root)?;
    if !fs::metadata(&config.root)?.is_dir() {
        return Err(invalid("live node root is not a directory"));
    }
    let database_path = config.root.join("state.sqlite");
    let blob_path = config.root.join("blobs");
    let durable_reopen = database_path.is_file();
    let bundle = read_private_file(&config.credential_path, MAX_BUNDLE_BYTES)?;
    let options = live_service_options(
        &config.topic,
        &config.scope,
        config.publish_items,
        config.payload_bytes,
    )?;
    let mut service = MeshService::open(&database_path, &blob_path, bundle.as_slice(), options)?;
    let identity = service.identity();
    if identity == config.peer {
        return Err(invalid("live peer is the local node identity"));
    }

    let (published_this_run, reused_publications) = ensure_local_canaries(
        &mut service,
        &config.topic,
        &config.scope,
        identity,
        config.workload_seed,
        config.publish_items,
        config.payload_bytes,
    )?;
    let carrier_kind = config.carrier.kind();
    let endpoints = configure_live_carrier(&mut service, config.peer, &config.carrier)?;
    service.begin_sync(config.peer)?;

    let started = Instant::now();
    let deadline = started
        .checked_add(config.max_runtime)
        .ok_or_else(|| invalid("live node runtime deadline overflow"))?;
    let mut metrics = LiveMetrics {
        node: identity,
        peer: config.peer,
        carrier: carrier_kind,
        local_endpoint: endpoints.local,
        resolved_peer_endpoint: endpoints.peer,
        durable_reopen,
        published_this_run,
        reused_publications,
        observed_items: event_count(&mut service, &config.topic, &config.scope)?,
        pump_calls: 0,
        authenticated_pumps: 0,
        maximum_pending_objects: 0,
        elapsed_ms: 0,
        authenticated: false,
        converged: false,
    };
    persist_metrics_if_configured(&config, &metrics)?;

    while metrics.pump_calls < config.max_pumps && Instant::now() < deadline {
        let report = service.pump()?;
        metrics.pump_calls = metrics.pump_calls.saturating_add(1);
        if report.authenticated {
            metrics.authenticated = true;
            metrics.authenticated_pumps = metrics.authenticated_pumps.saturating_add(1);
        }
        metrics.maximum_pending_objects = metrics
            .maximum_pending_objects
            .max(u32::try_from(report.pending_objects).unwrap_or(u32::MAX));
        if metrics
            .pump_calls
            .is_multiple_of(u64::from(config.query_every_pumps))
        {
            metrics.observed_items = event_count(&mut service, &config.topic, &config.scope)?;
            metrics.elapsed_ms = elapsed_ms(started);
            metrics.converged = metrics.authenticated
                && config.expected_items > 0
                && metrics.observed_items >= config.expected_items;
            persist_metrics_if_configured(&config, &metrics)?;
            if metrics.converged {
                break;
            }
        }
        sleep_for_live_pump(&service, config.idle_sleep);
    }

    if let Some(active) = service.active_contact() {
        metrics.authenticated |= active.authenticated;
        metrics.maximum_pending_objects = metrics
            .maximum_pending_objects
            .max(u32::try_from(active.pending_objects).unwrap_or(u32::MAX));
    }
    metrics.observed_items = event_count(&mut service, &config.topic, &config.scope)?;
    metrics.elapsed_ms = elapsed_ms(started);
    metrics.converged = metrics.authenticated
        && (config.expected_items == 0 || metrics.observed_items >= config.expected_items);
    service.pause_sync()?;
    persist_metrics_if_configured(&config, &metrics)?;
    Ok(metrics)
}

/// Writes a stable metrics record with bounded memory and an atomic same-folder
/// replacement. Metrics contain public identifiers but no bundles, discovery
/// tokens, rendezvous tokens, relay channels, or application payloads.
pub fn write_live_metrics(path: &Path, metrics: &LiveMetrics) -> LabResult<()> {
    let record = metrics.to_record();
    if record.len() > MAX_METRICS_BYTES {
        return Err(invalid("live metrics record exceeds the laboratory bound"));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)?;
    file.write_all(record.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    fs::rename(temporary, path)?;
    Ok(())
}

/// Non-secret public endpoints observed while configuring a live carrier.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct CarrierEndpoints {
    local: Option<SocketAddr>,
    peer: Option<SocketAddr>,
}

fn configure_live_carrier(
    service: &mut MeshService,
    peer: NodeId,
    carrier: &LiveCarrier,
) -> LabResult<CarrierEndpoints> {
    match carrier {
        LiveCarrier::FixedUdp {
            bind,
            peer_address,
            discovery_token,
        } => {
            let link = IpLink::bind("aster-lab-fixed-udp", *bind, *discovery_token, None)?;
            let local = link.local_addr()?;
            link.register_peer(peer, *peer_address)?;
            service.configure_peer_carrier(peer, link)?;
            Ok(CarrierEndpoints {
                local: Some(local),
                peer: Some(*peer_address),
            })
        }
        LiveCarrier::RendezvousUdp {
            bind,
            server,
            pairing_token,
            discovery_token,
            resolution_timeout,
            request_interval,
        } => {
            let link = IpLink::bind("aster-lab-rendezvous-udp", *bind, *discovery_token, None)?;
            let local = link.local_addr()?;
            let peer_address = resolve_rendezvous(
                &link,
                local,
                *server,
                *pairing_token,
                *resolution_timeout,
                *request_interval,
            )?;
            link.register_peer(peer, peer_address)?;
            service.configure_peer_carrier(peer, link)?;
            Ok(CarrierEndpoints {
                local: Some(local),
                peer: Some(peer_address),
            })
        }
        LiveCarrier::DiscoveryUdp {
            bind,
            discovery_target,
            discovery_token,
            resolution_timeout,
            announce_interval,
        } => {
            let link = IpLink::bind(
                "aster-lab-discovery-udp",
                *bind,
                *discovery_token,
                Some(*discovery_target),
            )?;
            let local = link.local_addr()?;
            let peer_address =
                resolve_discovery(&link, local, *resolution_timeout, *announce_interval)?;
            link.register_peer(peer, peer_address)?;
            service.configure_peer_carrier(peer, link)?;
            Ok(CarrierEndpoints {
                local: Some(local),
                peer: Some(peer_address),
            })
        }
        LiveCarrier::Relay {
            server,
            channel,
            connect_timeout,
        } => {
            let link =
                RelayLink::connect("aster-lab-relay", *server, *channel, peer, *connect_timeout)?;
            service.configure_peer_carrier(peer, link)?;
            Ok(CarrierEndpoints {
                local: None,
                peer: Some(*server),
            })
        }
    }
}

fn resolve_rendezvous(
    link: &IpLink,
    local: SocketAddr,
    server: SocketAddr,
    token: RendezvousToken,
    timeout: Duration,
    interval: Duration,
) -> LabResult<SocketAddr> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| invalid("rendezvous deadline overflow"))?;
    let mut next_request = Instant::now();
    while Instant::now() < deadline {
        let now = Instant::now();
        if now >= next_request {
            link.request_rendezvous(server, token)?;
            next_request = now.checked_add(interval).unwrap_or(deadline);
        }
        drain_precontact_frames(link)?;
        let mut peers = link
            .take_discovered()
            .into_iter()
            .filter(|candidate| *candidate != local)
            .collect::<Vec<_>>();
        peers.sort_unstable();
        peers.dedup();
        if peers.len() == 1 {
            return Ok(peers[0]);
        }
        if peers.len() > 1 {
            return Err(invalid(
                "rendezvous returned multiple endpoints for one pairing token",
            ));
        }
        thread::sleep(Duration::from_millis(1).min(interval));
    }
    Err(invalid("rendezvous did not resolve a peer before timeout"))
}

fn resolve_discovery(
    link: &IpLink,
    local: SocketAddr,
    timeout: Duration,
    interval: Duration,
) -> LabResult<SocketAddr> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| invalid("discovery deadline overflow"))?;
    let mut next_announcement = Instant::now();
    while Instant::now() < deadline {
        let now = Instant::now();
        if now >= next_announcement {
            link.announce()?;
            next_announcement = now.checked_add(interval).unwrap_or(deadline);
        }
        drain_precontact_frames(link)?;
        let mut peers = link
            .take_discovered()
            .into_iter()
            .filter(|candidate| *candidate != local)
            .collect::<Vec<_>>();
        peers.sort_unstable();
        peers.dedup();
        if peers.len() == 1 {
            return Ok(peers[0]);
        }
        if peers.len() > 1 {
            return Err(invalid(
                "local discovery found multiple endpoints; use fixed or rendezvous mode",
            ));
        }
        thread::sleep(Duration::from_millis(1).min(interval));
    }
    Err(invalid("local discovery found no peer before timeout"))
}

fn drain_precontact_frames(link: &IpLink) -> LabResult<()> {
    // Control datagrams are consumed internally. A peer that starts its core
    // handshake slightly earlier may contribute a data frame here; discarding
    // it is safe because the authenticated runtime retransmits after contact
    // setup and no unauthenticated bytes are committed.
    while link.try_receive()?.is_some() {}
    Ok(())
}

fn ensure_local_canaries(
    service: &mut MeshService,
    topic: &Topic,
    scope: &Scope,
    identity: NodeId,
    seed: u64,
    count: u32,
    payload_bytes: usize,
) -> LabResult<(u32, u32)> {
    let mut published = 0_u32;
    let mut reused = 0_u32;
    for ordinal in 0..count {
        let logical_key = canary_logical_key(identity, ordinal);
        let payload = canary_payload(payload_bytes, seed, identity, ordinal);
        let existing = service.query(Query {
            topic: Some(topic.clone()),
            scope: Some(scope.clone()),
            class: Some(DataClass::Event),
            logical_key: Some(logical_key.clone()),
            limit: 2,
            ..Query::default()
        })?;
        match existing.as_slice() {
            [] => {
                service.publish(PublishRequest {
                    class: DataClass::Event,
                    topic: topic.clone(),
                    scope: scope.clone(),
                    priority: Priority::Priority,
                    ttl_ms: None,
                    logical_key,
                    payload,
                    tombstone: false,
                })?;
                published = published.saturating_add(1);
            }
            [item]
                if item.publisher == identity
                    && item.logical_key == logical_key
                    && item.payload == payload
                    && !item.tombstone =>
            {
                reused = reused.saturating_add(1);
            }
            _ => {
                return Err(invalid(
                    "durable canary state conflicts with the configured workload",
                ));
            }
        }
    }
    Ok((published, reused))
}

/// Public deterministic canary key. It contains only the public NodeID and a
/// bounded ordinal, allowing capture tests to construct exact plaintext probes.
pub fn canary_logical_key(identity: NodeId, ordinal: u32) -> Vec<u8> {
    format!("aster-live-v1/{}/{ordinal:08}", encode_node_id(&identity)).into_bytes()
}

/// Public deterministic, bounded canary payload used only by the laboratory.
pub fn canary_payload(length: usize, seed: u64, identity: NodeId, ordinal: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(length.min(MAX_CANARY_BYTES));
    let prefix = CANARY_PREFIX.len().min(length);
    payload.extend_from_slice(&CANARY_PREFIX[..prefix]);
    let identity_word = u64::from_be_bytes(identity[..8].try_into().unwrap_or([0; 8]));
    while payload.len() < length.min(MAX_CANARY_BYTES) {
        let offset = payload.len() as u64;
        let mixed = mix64(
            seed ^ identity_word.rotate_left(17)
                ^ u64::from(ordinal).wrapping_mul(0x9e37_79b9_7f4a_7c15)
                ^ offset.wrapping_mul(0x94d0_49bb_1331_11eb),
        );
        payload.push((mixed % 251) as u8);
    }
    payload
}

fn event_count(service: &mut MeshService, topic: &Topic, scope: &Scope) -> LabResult<u32> {
    let count = service
        .query(Query {
            topic: Some(topic.clone()),
            scope: Some(scope.clone()),
            class: Some(DataClass::Event),
            limit: MAX_LIVE_ITEMS as usize,
            ..Query::default()
        })?
        .len();
    Ok(u32::try_from(count)?)
}

fn sleep_for_live_pump(service: &MeshService, idle: Duration) {
    let now = Instant::now();
    let delay = service
        .next_wakeup()
        .map(|wakeup| wakeup.saturating_duration_since(now).min(idle))
        .unwrap_or(idle);
    if delay.is_zero() {
        thread::yield_now();
    } else {
        thread::sleep(delay);
    }
}

fn persist_metrics_if_configured(config: &LiveNodeConfig, metrics: &LiveMetrics) -> LabResult<()> {
    if let Some(path) = &config.metrics_path {
        write_live_metrics(path, metrics)?;
    }
    Ok(())
}

fn live_service_options(
    topic: &Topic,
    scope: &Scope,
    items: u32,
    payload_bytes: usize,
) -> LabResult<ServiceOptions> {
    let application_bytes = u64::try_from(payload_bytes)?
        .checked_mul(u64::from(items.max(1)))
        .ok_or_else(|| invalid("live application byte bound overflow"))?;
    let mut node = ApplicationNodeOptions::default();
    node.max_items = node
        .max_items
        .max(u64::from(items).saturating_mul(4).saturating_add(1_024));
    node.max_bytes = node.max_bytes.max(
        application_bytes
            .saturating_mul(4)
            .saturating_add(64 * 1_048_576),
    );
    Ok(ServiceOptions {
        node,
        blobs: BlobStoreConfig::default(),
        sync: SyncProfile::new(vec![topic.clone()], vec![scope.clone()], Priority::Routine)?,
    })
}

fn validate_provision(config: &ProvisionConfig) -> LabResult<()> {
    if config.nodes == 0 || config.nodes > MAX_LIVE_NODES {
        return Err(invalid("provisioned node count must be between 1 and 4096"));
    }
    if config.first_serial == 0 {
        return Err(invalid("first provisioning serial must be nonzero"));
    }
    config
        .first_serial
        .checked_add(u64::from(config.nodes - 1))
        .ok_or_else(|| invalid("provisioning serial range overflow"))?;
    if config.authority_seed == [0; 32] {
        return Err(invalid("authority seed must be nonzero"));
    }
    Ok(())
}

fn validate_live_node(config: &LiveNodeConfig) -> LabResult<()> {
    if config.peer == [0; 32] {
        return Err(invalid("live peer NodeID cannot be all zero"));
    }
    if config.publish_items > MAX_LIVE_ITEMS || config.expected_items > MAX_LIVE_ITEMS {
        return Err(invalid("live item counts cannot exceed 4096"));
    }
    if config.expected_items != 0 && config.expected_items < config.publish_items {
        return Err(invalid(
            "expected item count cannot be smaller than local publications",
        ));
    }
    if config.payload_bytes == 0 || config.payload_bytes > MAX_CANARY_BYTES {
        return Err(invalid(
            "live canary payload size must be between 1 and 1048576 bytes",
        ));
    }
    let total = config
        .payload_bytes
        .checked_mul(usize::try_from(config.publish_items)?)
        .ok_or_else(|| invalid("live canary byte count overflow"))?;
    if total > MAX_CANARY_TOTAL_BYTES {
        return Err(invalid("live canaries exceed the 64 MiB process bound"));
    }
    if config.max_pumps == 0
        || config.max_runtime.is_zero()
        || config.query_every_pumps == 0
        || config.idle_sleep.is_zero()
        || config.idle_sleep > Duration::from_secs(1)
    {
        return Err(invalid(
            "live pump/runtime/query/sleep bounds must be positive and sleep at most one second",
        ));
    }
    match &config.carrier {
        LiveCarrier::FixedUdp {
            discovery_token, ..
        } => validate_discovery_token(discovery_token)?,
        LiveCarrier::RendezvousUdp {
            pairing_token,
            discovery_token,
            resolution_timeout,
            request_interval,
            ..
        } => {
            validate_discovery_token(discovery_token)?;
            if *pairing_token == [0; 32] {
                return Err(invalid("rendezvous pairing token cannot be all zero"));
            }
            validate_resolution_timing(*resolution_timeout, *request_interval)?;
        }
        LiveCarrier::DiscoveryUdp {
            discovery_token,
            resolution_timeout,
            announce_interval,
            ..
        } => {
            validate_discovery_token(discovery_token)?;
            validate_resolution_timing(*resolution_timeout, *announce_interval)?;
        }
        LiveCarrier::Relay {
            channel,
            connect_timeout,
            ..
        } => {
            if *channel == [0; 32] || connect_timeout.is_zero() {
                return Err(invalid(
                    "relay channel must be nonzero and timeout must be positive",
                ));
            }
        }
    }
    Ok(())
}

fn validate_discovery_token(token: &[u8; 16]) -> LabResult<()> {
    if *token == [0; 16] {
        return Err(invalid("discovery token cannot be all zero"));
    }
    Ok(())
}

fn validate_resolution_timing(timeout: Duration, interval: Duration) -> LabResult<()> {
    if timeout.is_zero()
        || timeout > Duration::from_secs(300)
        || interval.is_zero()
        || interval > timeout
    {
        return Err(invalid(
            "resolution timeout must be at most five minutes and interval must be positive",
        ));
    }
    Ok(())
}

/// Configuration for one process-owned UDP rendezvous service with an optional
/// opaque TCP relay listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RendezvousInfraConfig {
    pub rendezvous_bind: SocketAddr,
    pub relay: Option<RelayInfraConfig>,
}

/// Bounded relay listener configuration. A zero pair limit serves for the
/// lifetime of the infrastructure process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayInfraConfig {
    pub bind: SocketAddr,
    pub pair_limit: usize,
}

/// Snapshot from the nonblocking infrastructure helper.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InfraMetrics {
    pub rendezvous_address: SocketAddr,
    pub relay_address: Option<SocketAddr>,
    pub poll_calls: u64,
    pub processed_datagrams: u64,
    pub relay_finished: bool,
    pub elapsed_ms: u64,
}

impl InfraMetrics {
    pub fn to_record(self) -> String {
        format!(
            "ASTER_LAB_INFRA\tversion=1\trendezvous_address={}\trelay_address={}\tpoll_calls={}\tprocessed_datagrams={}\trelay_finished={}\telapsed_ms={}",
            self.rendezvous_address,
            display_endpoint(self.relay_address),
            self.poll_calls,
            self.processed_datagrams,
            self.relay_finished,
            self.elapsed_ms
        )
    }
}

/// Process-owned combined infrastructure. [`Self::poll`] never waits for a UDP
/// registration. The optional relay uses the adapter's bounded blocking server
/// on a background thread; dropping a still-running instance detaches that
/// process-lifetime thread rather than exposing an unsafe cancellation path.
pub struct RendezvousInfra {
    rendezvous: RendezvousServer,
    rendezvous_address: SocketAddr,
    relay_address: Option<SocketAddr>,
    relay_thread: Option<JoinHandle<io::Result<()>>>,
    relay_finished: bool,
    poll_calls: u64,
    processed_datagrams: u64,
    started: Instant,
}

impl fmt::Debug for RendezvousInfra {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RendezvousInfra")
            .field("rendezvous_address", &self.rendezvous_address)
            .field("relay_address", &self.relay_address)
            .field("relay_finished", &self.relay_finished)
            .field("poll_calls", &self.poll_calls)
            .field("processed_datagrams", &self.processed_datagrams)
            .finish()
    }
}

impl RendezvousInfra {
    pub fn bind(config: RendezvousInfraConfig) -> LabResult<Self> {
        let rendezvous = RendezvousServer::bind(config.rendezvous_bind)?;
        let rendezvous_address = rendezvous.local_addr()?;
        let (relay_address, relay_thread) = if let Some(relay_config) = config.relay {
            let relay = CipherRelayServer::bind(relay_config.bind)?;
            let address = relay.local_addr()?;
            let handle = thread::Builder::new()
                .name("aster-lab-relay-infra".into())
                .spawn(move || relay.serve(relay_config.pair_limit))?;
            (Some(address), Some(handle))
        } else {
            (None, None)
        };
        let relay_finished = relay_thread.is_none();
        Ok(Self {
            rendezvous,
            rendezvous_address,
            relay_address,
            relay_thread,
            relay_finished,
            poll_calls: 0,
            processed_datagrams: 0,
            started: Instant::now(),
        })
    }

    pub fn rendezvous_address(&self) -> SocketAddr {
        self.rendezvous_address
    }

    pub fn relay_address(&self) -> Option<SocketAddr> {
        self.relay_address
    }

    /// Processes all currently queued rendezvous datagrams and observes relay
    /// completion without blocking for new work.
    pub fn poll(&mut self) -> LabResult<InfraMetrics> {
        let processed = self.rendezvous.poll()?;
        self.poll_calls = self.poll_calls.saturating_add(1);
        self.processed_datagrams = self
            .processed_datagrams
            .saturating_add(u64::try_from(processed).unwrap_or(u64::MAX));
        if self
            .relay_thread
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
        {
            let handle = self
                .relay_thread
                .take()
                .ok_or_else(|| invalid("relay completion state changed unexpectedly"))?;
            handle
                .join()
                .map_err(|_| invalid("relay infrastructure thread panicked"))??;
            self.relay_finished = true;
        }
        Ok(self.metrics())
    }

    pub fn metrics(&self) -> InfraMetrics {
        InfraMetrics {
            rendezvous_address: self.rendezvous_address,
            relay_address: self.relay_address,
            poll_calls: self.poll_calls,
            processed_datagrams: self.processed_datagrams,
            relay_finished: self.relay_finished,
            elapsed_ms: elapsed_ms(self.started),
        }
    }
}

/// Reads exactly `N` secret bytes from a mode-0600 hexadecimal file. The file
/// contents are never included in an error.
pub fn read_private_hex<const N: usize>(path: &Path) -> LabResult<[u8; N]> {
    let encoded_bound = N
        .checked_mul(2)
        .and_then(|value| value.checked_add(2))
        .ok_or_else(|| invalid("private hexadecimal size overflow"))?;
    let bytes = read_private_file(path, encoded_bound)?;
    let text = std::str::from_utf8(bytes.as_slice())
        .map_err(|_| invalid("private hexadecimal file is not UTF-8"))?
        .trim();
    if text.len() != N.saturating_mul(2) {
        return Err(invalid("private hexadecimal file has the wrong length"));
    }
    let mut decoded = [0_u8; N];
    decode_hex_into(text, &mut decoded)?;
    Ok(decoded)
}

/// Creates a mode-0600 hexadecimal capability file without overwriting an
/// existing value.
pub fn write_private_hex<const N: usize>(path: &Path, value: &[u8; N]) -> LabResult<()> {
    let encoded = Zeroizing::new(encode_hex(value));
    write_private_new(path, encoded.as_bytes())
}

/// Canonical lowercase NodeID representation used by manifests and metrics.
pub fn encode_node_id(identity: &NodeId) -> String {
    encode_hex(identity)
}

/// Parses exactly one 32-byte hexadecimal NodeID.
pub fn parse_node_id(value: &str) -> LabResult<NodeId> {
    if value.len() != 64 {
        return Err(invalid(
            "NodeID must contain exactly 64 hexadecimal characters",
        ));
    }
    let mut identity = [0_u8; 32];
    decode_hex_into(value, &mut identity)?;
    Ok(identity)
}

fn read_private_file(path: &Path, limit: usize) -> LabResult<SecretBytes> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return Err(invalid("protected input is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(invalid("protected input must have mode 0600 or stricter"));
        }
    }
    let file = OpenOptions::new().read(true).open(path)?;
    let read_limit = u64::try_from(limit)?
        .checked_add(1)
        .ok_or_else(|| invalid("protected input size limit overflow"))?;
    let mut bytes = Vec::new();
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bytes.zeroize();
        return Err(invalid("protected input exceeds its size bound"));
    }
    Ok(SecretBytes(bytes))
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn erase(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.erase();
    }
}

fn write_private_new(path: &Path, bytes: &[u8]) -> LabResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn write_public_new(path: &Path, bytes: &[u8]) -> LabResult<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn create_private_directory(path: &Path) -> LabResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(path)?;
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    fs::create_dir(path)?;
    Ok(())
}

fn prepare_fresh_root(path: &Path) -> LabResult<()> {
    if path.exists() {
        if !fs::metadata(path)?.is_dir() {
            return Err(invalid("provisioning root is not a directory"));
        }
        if fs::read_dir(path)?.next().transpose()?.is_some() {
            return Err(invalid(
                "provisioning root is not empty; refusing to overwrite protected material",
            ));
        }
    } else {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn decode_hex_into(value: &str, output: &mut [u8]) -> LabResult<()> {
    if value.len() != output.len().saturating_mul(2) || !value.is_ascii() {
        return Err(invalid("hexadecimal value has the wrong length"));
    }
    for (index, byte) in output.iter_mut().enumerate() {
        let start = index * 2;
        *byte = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| invalid("hexadecimal value contains an invalid character"))?;
    }
    Ok(())
}

fn parse_required<T>(values: &BTreeMap<&str, &str>, name: &str) -> LabResult<T>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    let value = required_text(values, name)?;
    value
        .parse()
        .map_err(|error| invalid(format!("invalid {name}: {error}")))
}

fn required_text<'a>(values: &'a BTreeMap<&str, &str>, name: &str) -> LabResult<&'a str> {
    values
        .get(name)
        .copied()
        .ok_or_else(|| invalid(format!("missing {name}")))
}

fn parse_value<T>(name: &str, value: Option<&str>) -> LabResult<T>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    value
        .ok_or_else(|| invalid(format!("missing {name}")))?
        .parse()
        .map_err(|error| invalid(format!("invalid {name}: {error}")))
}

fn display_endpoint(endpoint: Option<SocketAddr>) -> String {
    endpoint.map_or_else(|| "-".into(), |address| address.to_string())
}

fn json_endpoint(endpoint: Option<SocketAddr>) -> String {
    endpoint.map_or_else(|| "null".into(), |address| format!("\"{address}\""))
}

fn parse_endpoint(value: &str) -> LabResult<Option<SocketAddr>> {
    if value == "-" {
        return Ok(None);
    }
    Ok(Some(value.parse().map_err(|error| {
        invalid(format!("invalid metrics endpoint: {error}"))
    })?))
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn invalid(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn node_id_and_manifest_round_trip_canonically() {
        let manifest = NodeManifest {
            topic: Topic::new("lab.live").unwrap(),
            scope: Scope::new("lab/live").unwrap(),
            nodes: vec![
                ManifestNode {
                    index: 0,
                    serial: 7,
                    identity: [1; 32],
                },
                ManifestNode {
                    index: 1,
                    serial: 8,
                    identity: [2; 32],
                },
            ],
        };
        let encoded = manifest.to_text();
        assert_eq!(NodeManifest::from_text(&encoded).unwrap(), manifest);
        assert_eq!(
            parse_node_id(&encode_node_id(&[0xab; 32])).unwrap(),
            [0xab; 32]
        );
        assert!(parse_node_id("00").is_err());
    }

    #[test]
    fn live_metrics_round_trip_without_private_capabilities() {
        let metrics = LiveMetrics {
            node: [1; 32],
            peer: [2; 32],
            carrier: CarrierKind::RendezvousUdp,
            local_endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001)),
            resolved_peer_endpoint: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4002)),
            durable_reopen: true,
            published_this_run: 0,
            reused_publications: 3,
            observed_items: 6,
            pump_calls: 92,
            authenticated_pumps: 81,
            maximum_pending_objects: 4,
            elapsed_ms: 123,
            authenticated: true,
            converged: true,
        };
        let record = metrics.to_record();
        assert_eq!(LiveMetrics::from_record(&record).unwrap(), metrics);
        assert!(!record.contains("token"));
        assert!(!record.contains("channel"));
    }

    #[test]
    fn canaries_are_deterministic_distinct_and_bounded() {
        let first = canary_payload(4_096, 9, [1; 32], 3);
        assert_eq!(first, canary_payload(4_096, 9, [1; 32], 3));
        assert_ne!(first, canary_payload(4_096, 9, [1; 32], 4));
        assert_eq!(first.len(), 4_096);
        assert!(first.starts_with(CANARY_PREFIX));
        assert_eq!(
            canary_payload(MAX_CANARY_BYTES + 1, 9, [1; 32], 3).len(),
            MAX_CANARY_BYTES
        );
    }

    #[test]
    fn carrier_debug_redacts_every_capability() {
        let token = [0x55; 32];
        let discovery = [0x44; 16];
        let carrier = LiveCarrier::rendezvous_udp(
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:9000".parse().unwrap(),
            token,
            discovery,
            Duration::from_secs(1),
            Duration::from_millis(10),
        );
        let rendered = format!("{carrier:?}");
        assert!(!rendered.contains(&encode_hex(&token)));
        assert!(!rendered.contains(&encode_hex(&discovery)));
        assert!(rendered.contains("[REDACTED]"));
    }
}
