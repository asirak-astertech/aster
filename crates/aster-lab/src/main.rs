#![forbid(unsafe_code)]

use aster_lab::live::{
    LiveCarrier, LiveNodeConfig, ProvisionConfig, RelayInfraConfig, RendezvousInfra,
    RendezvousInfraConfig, parse_node_id, provision_private_nodes, read_private_hex, run_live_node,
    write_private_hex,
};
use aster_lab::{
    BlobRecoveryScenario, FaultProfile, LabMetrics, LabResult, LiveEvidenceInvocation,
    SCENARIO_OWNERSHIP_FILE, ShardScenario, TransferScenario, run_blob_recovery, run_shard,
    run_transfer, write_metrics,
};
use aster_mesh::{Scope, Topic};
use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aster-lab: {error}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> LabResult<()> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let Some(command) = arguments.next() else {
        print_help();
        return Ok(());
    };
    let command = command
        .into_string()
        .map_err(|_| invalid("command must be valid UTF-8"))?;
    if matches!(command.as_str(), "help" | "--help" | "-h") {
        print_help();
        return Ok(());
    }
    let options = Options::parse(arguments.collect())?;
    if !known_command(&command) {
        return Err(invalid(format!("unknown command {command}")));
    }
    options.reject_unknown(&command)?;
    match command.as_str() {
        "provision" => run_provision(&options)?,
        "node-udp" => run_live_node_command(&options, LiveMode::FixedUdp)?,
        "node-rendezvous" => run_live_node_command(&options, LiveMode::RendezvousUdp)?,
        "node-discovery" => run_live_node_command(&options, LiveMode::DiscoveryUdp)?,
        "node-relay" => run_live_node_command(&options, LiveMode::Relay)?,
        "rendezvous" => run_infrastructure(&options, true)?,
        "infra" => run_infrastructure(&options, false)?,
        "transfer" => run_transfer_command(&options)?,
        "blob-recovery" => run_blob_command(&options)?,
        "scale" => run_scale_command(&options)?,
        "shard-worker" => run_shard_command(&options)?,
        _ => unreachable!("option_allowlist accepted an unknown command"),
    }
    Ok(())
}

fn print_help() {
    println!(
        "Aster deterministic simulation laboratory\n\n\
         Usage:\n\
        aster-lab provision --root PATH --nodes N [--scope NAME --topic NAME]\n\
           aster-lab node-udp --root NODE_PATH --bundle FILE --bind ADDRESS \\\n             --peer-id HEX --peer-address ADDRESS [OPTIONS]\n\
           aster-lab node-rendezvous --root NODE_PATH --bundle FILE --bind ADDRESS \\\n             --peer-id HEX --rendezvous-address ADDRESS --pairing-token FILE [OPTIONS]\n\
           aster-lab node-discovery --root NODE_PATH --bundle FILE --bind ADDRESS \\\n             --peer-id HEX --discovery-target ADDRESS --discovery-token FILE [OPTIONS]\n\
           aster-lab node-relay --root NODE_PATH --bundle FILE --peer-id HEX \\\n             --relay-address ADDRESS --relay-channel FILE [OPTIONS]\n\
           aster-lab infra --rendezvous-bind ADDRESS [--relay-bind ADDRESS --relay-pairs N]\n\
           aster-lab rendezvous --bind ADDRESS [--duration-ms N]\n\
           aster-lab transfer --root PATH [OPTIONS]\n\
           aster-lab blob-recovery --root PATH [OPTIONS]\n\
           aster-lab scale --root PATH --nodes N --shards N [OPTIONS]\n\n\
         Common fault options:\n\
           --seed N                 deterministic workload/fault seed (default 1)\n\
           --mtu N                  carrier MTU (default 1200)\n\
           --bps N                  virtual useful bits/second (default 1000000)\n\
           --loss-per-mille N       exact drops/1000-frame direction window (default 0)\n\
           --reorder-ticks N        deterministic maximum delay ticks (default 0)\n\
           --tick-ms N              virtual milliseconds per receive opportunity (default 100)\n\n\
         Transfer options:\n\
           --items N                Event items (default 4)\n\
           --payload-bytes N        bytes per item (default 65536)\n\
           --restart-after-frames N receiver reopen checkpoint (default 24; 0 disables)\n\
           --max-pumps N            total pump budget (default 200000)\n\n\
         Blob recovery options:\n\
           --blob-bytes N           streamed bytes (default 105906176)\n\
           --chunk-bytes N          Blob chunk bytes (default 65536)\n\
           --restart-after-frames N source-contact checkpoint (default 256)\n\
           --max-pumps N            budget per contact (default 2000000)\n\n\
         Scale options:\n\
           --nodes N                total nodes\n\
           --shards N               worker processes\n\
           --items N                source items per shard (default 1)\n\
           --payload-bytes N        bytes per item (default 1024)\n\
           --max-pumps N            budget per chain edge (default 100000)\n\n\
         Each successful run preserves metrics.json and prints both JSON and a stable\n\
         ASTER_LAB_METRICS key/value record. Simulation run directories must not exist yet.\n\n\
         Live node options:\n\
           --scope NAME              provisioned scope (default lab/live-ip)\n\
           --topic NAME              provisioned topic (default lab.live-ip)\n\
           --duration-ms N           process lifetime (default 60000)\n\
           --max-pumps N             pump cap (default 1000000)\n\
           --publish-items N         local Events at startup (default 0)\n\
           --payload-bytes N         bytes per local Event (default 1024)\n\
           --expect-items N          total local query count required for convergence\n\
           --query-every N           query cadence in pumps (default 16)\n\
           --idle-ms N               nonblocking pump sleep (default 1)\n\
           --resolve-timeout-ms N    discovery/rendezvous timeout (default 30000)\n\
           --request-interval-ms N   discovery/rendezvous retry interval (default 250)\n\n\
         Provision writes mode-0600 bundles and simulation capability files under\n\
         ROOT/private. Its public manifest contains only NodeIDs and serials."
    );
}

#[derive(Debug)]
struct Options(BTreeMap<String, String>);

impl Options {
    fn parse(arguments: Vec<OsString>) -> LabResult<Self> {
        let mut values = BTreeMap::new();
        let mut arguments = arguments.into_iter();
        while let Some(name) = arguments.next() {
            let name = name
                .into_string()
                .map_err(|_| invalid("option name must be valid UTF-8"))?;
            if !name.starts_with("--") || name.len() == 2 {
                return Err(invalid(format!("expected --option, found {name}")));
            }
            let value = arguments
                .next()
                .ok_or_else(|| invalid(format!("{name} requires a value")))?
                .into_string()
                .map_err(|_| invalid(format!("{name} value must be valid UTF-8")))?;
            let key = name.trim_start_matches("--").to_owned();
            if values.insert(key.clone(), value).is_some() {
                return Err(invalid(format!("duplicate option --{key}")));
            }
        }
        Ok(Self(values))
    }

    fn required_path(&self, name: &str) -> LabResult<PathBuf> {
        self.0
            .get(name)
            .map(PathBuf::from)
            .ok_or_else(|| invalid(format!("--{name} is required")))
    }

    fn text(&self, name: &str, default: &str) -> String {
        self.0
            .get(name)
            .cloned()
            .unwrap_or_else(|| default.to_owned())
    }

    fn number<T>(&self, name: &str, default: T) -> LabResult<T>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        self.0.get(name).map_or(Ok(default), |value| {
            value
                .parse()
                .map_err(|error| invalid(format!("invalid --{name}: {error}")))
        })
    }

    fn required_number<T>(&self, name: &str) -> LabResult<T>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        let value = self
            .0
            .get(name)
            .ok_or_else(|| invalid(format!("--{name} is required")))?;
        value
            .parse()
            .map_err(|error| invalid(format!("invalid --{name}: {error}")))
    }

    fn reject_unknown(&self, command: &str) -> LabResult<()> {
        if let Some(name) = self
            .0
            .keys()
            .find(|name| !option_is_allowed(command, name.as_str()))
        {
            return Err(invalid(format!(
                "option --{name} is not valid for command {command}"
            )));
        }
        Ok(())
    }
}

fn known_command(command: &str) -> bool {
    matches!(
        command,
        "provision"
            | "node-udp"
            | "node-rendezvous"
            | "node-discovery"
            | "node-relay"
            | "rendezvous"
            | "infra"
            | "transfer"
            | "blob-recovery"
            | "scale"
            | "shard-worker"
    )
}

fn option_is_allowed(command: &str, name: &str) -> bool {
    let fault = [
        "seed",
        "mtu",
        "bps",
        "loss-per-mille",
        "reorder-ticks",
        "tick-ms",
    ]
    .contains(&name);
    let live = [
        "root",
        "bundle",
        "peer-id",
        "seed",
        "topic",
        "scope",
        "duration-ms",
        "max-pumps",
        "publish-items",
        "payload-bytes",
        "expect-items",
        "query-every",
        "idle-ms",
    ]
    .contains(&name);
    match command {
        "provision" => ["root", "nodes", "scope", "topic"].contains(&name),
        "node-udp" => live || ["bind", "peer-address"].contains(&name),
        "node-rendezvous" => {
            live || [
                "bind",
                "rendezvous-address",
                "pairing-token",
                "resolve-timeout-ms",
                "request-interval-ms",
            ]
            .contains(&name)
        }
        "node-discovery" => {
            live || [
                "bind",
                "discovery-target",
                "discovery-token",
                "resolve-timeout-ms",
                "request-interval-ms",
            ]
            .contains(&name)
        }
        "node-relay" => {
            live || ["relay-address", "relay-channel", "connect-timeout-ms"].contains(&name)
        }
        "rendezvous" => [
            "bind",
            "relay-bind",
            "relay-pairs",
            "duration-ms",
            "poll-ms",
        ]
        .contains(&name),
        "infra" => [
            "rendezvous-bind",
            "relay-bind",
            "relay-pairs",
            "duration-ms",
            "poll-ms",
        ]
        .contains(&name),
        "transfer" => {
            fault
                || [
                    "root",
                    "items",
                    "payload-bytes",
                    "restart-after-frames",
                    "max-pumps",
                ]
                .contains(&name)
        }
        "blob-recovery" => {
            fault
                || [
                    "root",
                    "blob-bytes",
                    "chunk-bytes",
                    "restart-after-frames",
                    "max-pumps",
                ]
                .contains(&name)
        }
        "scale" => {
            fault
                || [
                    "root",
                    "nodes",
                    "shards",
                    "items",
                    "payload-bytes",
                    "max-pumps",
                ]
                .contains(&name)
        }
        "shard-worker" => {
            fault
                || [
                    "root",
                    "shard-index",
                    "first-node",
                    "nodes",
                    "items",
                    "payload-bytes",
                    "max-pumps",
                ]
                .contains(&name)
        }
        _ => false,
    }
}

fn run_provision(options: &Options) -> LabResult<()> {
    let root = options.required_path("root")?;
    let nodes: u32 = options.required_number("nodes")?;
    let topic = Topic::new(options.text("topic", "lab.live-ip"))?;
    let scope = Scope::new(options.text("scope", "lab/live-ip"))?;
    let authority_seed = fresh_secret::<32>()?;
    let summary = provision_private_nodes(ProvisionConfig::new(
        root.clone(),
        *authority_seed,
        nodes,
        1,
        topic,
        scope,
    ))?;
    let private = root.join("private");
    let discovery_token = fresh_secret::<16>()?;
    write_private_hex(&private.join("discovery-token.hex"), &discovery_token)?;
    let rendezvous_token = fresh_secret::<32>()?;
    write_private_hex(&private.join("rendezvous-token.hex"), &rendezvous_token)?;
    let relay_channel = fresh_secret::<32>()?;
    write_private_hex(&private.join("relay-channel.hex"), &relay_channel)?;
    println!(
        "ASTER_LAB_PROVISION\tversion=1\tnodes={}\tmanifest={}",
        summary.manifest.nodes.len(),
        summary.manifest_path.display()
    );
    let metrics = LabMetrics {
        scenario: "provision".into(),
        seed: 0,
        shards: 1,
        nodes,
        converged: true,
        ..LabMetrics::default()
    };
    emit(&root, &metrics)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveMode {
    FixedUdp,
    RendezvousUdp,
    DiscoveryUdp,
    Relay,
}

impl LiveMode {
    const fn scenario(self) -> &'static str {
        match self {
            Self::FixedUdp => "node-udp",
            Self::RendezvousUdp => "node-rendezvous",
            Self::DiscoveryUdp => "node-discovery",
            Self::Relay => "node-relay",
        }
    }
}

fn run_live_node_command(options: &Options, mode: LiveMode) -> LabResult<()> {
    let root = options.required_path("root")?;
    let bundle_path = options.required_path("bundle")?;
    let peer = parse_node_id(
        options
            .0
            .get("peer-id")
            .ok_or_else(|| invalid("--peer-id is required"))?,
    )?;
    let seed: u64 = options.number("seed", 1)?;
    let topic = Topic::new(options.text("topic", "lab.live-ip"))?;
    let scope = Scope::new(options.text("scope", "lab/live-ip"))?;
    let duration_ms: u64 = options.number("duration-ms", 60_000)?;
    let max_pumps: u64 = options.number("max-pumps", 1_000_000)?;
    let publish_items: u32 = options.number("publish-items", 0)?;
    let payload_bytes: usize = options.number("payload-bytes", 1_024)?;
    let expected_items: u32 = options.number("expect-items", 0)?;
    let query_every_pumps: u32 = options.number("query-every", 16)?;
    let idle_ms: u64 = options.number("idle-ms", 1)?;
    let carrier = live_carrier(options, mode)?;
    let evidence = LiveEvidenceInvocation::reserve(&root)?;
    let mut config = LiveNodeConfig::new(root.clone(), bundle_path, peer, topic, scope, carrier);
    config.workload_seed = seed;
    config.publish_items = publish_items;
    config.payload_bytes = payload_bytes;
    config.expected_items = expected_items;
    config.max_pumps = max_pumps;
    config.max_runtime = Duration::from_millis(duration_ms);
    config.query_every_pumps = query_every_pumps;
    config.idle_sleep = Duration::from_millis(idle_ms);
    let durable_reopen = root.join("state.sqlite").is_file();
    let started = Instant::now();
    let live = match run_live_node(config) {
        Ok(live) => live,
        Err(error) => {
            let failure = LabMetrics {
                scenario: mode.scenario().into(),
                seed,
                shards: 1,
                nodes: 1,
                restarts: u64::from(durable_reopen),
                elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                converged: false,
                ..LabMetrics::default()
            };
            return match evidence.write_metrics(&failure) {
                Ok(_) => Err(error),
                Err(write_error) => Err(invalid(format!(
                    "{error}; failure metrics could not be preserved: {write_error}"
                ))),
            };
        }
    };
    println!("{}", live.to_json());
    println!("{}", live.to_record());
    let metrics = LabMetrics {
        scenario: mode.scenario().into(),
        seed,
        shards: 1,
        nodes: 1,
        published_items: u64::from(
            live.published_this_run
                .saturating_add(live.reused_publications),
        ),
        delivered_items: u64::from(live.observed_items),
        pump_calls: live.pump_calls,
        restarts: u64::from(live.durable_reopen),
        elapsed_ms: live.elapsed_ms,
        converged: live.converged,
        ..LabMetrics::default()
    };
    emit_live(&evidence, &metrics, &live)?;
    if !live.converged {
        return Err(invalid(format!(
            "{} did not reach authenticated convergence (observed {}, required {})",
            mode.scenario(),
            live.observed_items,
            expected_items
        )));
    }
    Ok(())
}

fn live_carrier(options: &Options, mode: LiveMode) -> LabResult<LiveCarrier> {
    match mode {
        LiveMode::FixedUdp => {
            let discovery_token = fresh_secret::<16>()?;
            Ok(LiveCarrier::fixed_udp(
                required_socket(options, "bind")?,
                required_socket(options, "peer-address")?,
                *discovery_token,
            ))
        }
        LiveMode::RendezvousUdp => {
            let discovery_token = fresh_secret::<16>()?;
            Ok(LiveCarrier::rendezvous_udp(
                required_socket(options, "bind")?,
                required_socket(options, "rendezvous-address")?,
                read_private_hex::<32>(&options.required_path("pairing-token")?)?,
                *discovery_token,
                Duration::from_millis(options.number("resolve-timeout-ms", 30_000_u64)?),
                Duration::from_millis(options.number("request-interval-ms", 250_u64)?),
            ))
        }
        LiveMode::DiscoveryUdp => Ok(LiveCarrier::discovery_udp(
            required_socket(options, "bind")?,
            required_socket(options, "discovery-target")?,
            read_private_hex::<16>(&options.required_path("discovery-token")?)?,
            Duration::from_millis(options.number("resolve-timeout-ms", 30_000_u64)?),
            Duration::from_millis(options.number("request-interval-ms", 250_u64)?),
        )),
        LiveMode::Relay => Ok(LiveCarrier::relay(
            required_socket(options, "relay-address")?,
            read_private_hex::<32>(&options.required_path("relay-channel")?)?,
            Duration::from_millis(options.number("connect-timeout-ms", 30_000_u64)?),
        )),
    }
}

fn run_infrastructure(options: &Options, compatibility_alias: bool) -> LabResult<()> {
    if options.0.contains_key("relay-pairs") && !options.0.contains_key("relay-bind") {
        return Err(invalid("--relay-pairs requires --relay-bind"));
    }
    let rendezvous_bind = required_socket(
        options,
        if compatibility_alias {
            "bind"
        } else {
            "rendezvous-bind"
        },
    )?;
    let relay = if let Some(value) = options.0.get("relay-bind") {
        Some(RelayInfraConfig {
            bind: value
                .parse()
                .map_err(|error| invalid(format!("invalid --relay-bind: {error}")))?,
            pair_limit: options.number("relay-pairs", 0_usize)?,
        })
    } else {
        None
    };
    let duration_ms: u64 = options.number("duration-ms", 60_000)?;
    let poll_ms: u64 = options.number("poll-ms", 1)?;
    if duration_ms == 0 || poll_ms == 0 || poll_ms > 1_000 {
        return Err(invalid(
            "infrastructure duration must be positive and poll interval between 1 and 1000 ms",
        ));
    }
    let mut infrastructure = RendezvousInfra::bind(RendezvousInfraConfig {
        rendezvous_bind,
        relay,
    })?;
    println!(
        "ASTER_LAB_INFRA_READY\tversion=1\trendezvous_address={}\trelay_address={}",
        infrastructure.rendezvous_address(),
        infrastructure
            .relay_address()
            .map_or_else(|| "-".into(), |address| address.to_string())
    );
    let started = Instant::now();
    let deadline = started
        .checked_add(Duration::from_millis(duration_ms))
        .ok_or_else(|| invalid("infrastructure duration overflow"))?;
    while Instant::now() < deadline {
        infrastructure.poll()?;
        thread::sleep(Duration::from_millis(poll_ms));
    }
    println!("{}", infrastructure.poll()?.to_record());
    Ok(())
}

fn required_socket(options: &Options, name: &str) -> LabResult<SocketAddr> {
    options
        .0
        .get(name)
        .ok_or_else(|| invalid(format!("--{name} is required")))?
        .parse()
        .map_err(|error| invalid(format!("invalid --{name}: {error}")))
}

fn fresh_secret<const N: usize>() -> LabResult<Zeroizing<[u8; N]>> {
    let mut value = Zeroizing::new([0_u8; N]);
    getrandom::fill(&mut *value)
        .map_err(|error| invalid(format!("operating-system entropy is unavailable: {error}")))?;
    Ok(value)
}

fn fault(options: &Options) -> LabResult<FaultProfile> {
    FaultProfile {
        seed: options.number("seed", 1)?,
        mtu: options.number("mtu", 1_200)?,
        bits_per_second: options.number("bps", 1_000_000)?,
        loss_per_mille: options.number("loss-per-mille", 0)?,
        reorder_ticks: options.number("reorder-ticks", 0)?,
        tick_ms: options.number("tick-ms", 100)?,
    }
    .validate()
}

#[derive(Debug)]
struct ScenarioRootClaim {
    root: PathBuf,
}

impl ScenarioRootClaim {
    fn reserve(root: PathBuf) -> LabResult<Self> {
        match fs::symlink_metadata(&root) {
            Ok(_) => {
                return Err(invalid(format!(
                    "run path {} already exists; refusing to mix evidence",
                    root.display()
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir_all(&root)?;
            }
            Err(error) => return Err(Box::new(error)),
        }

        let marker_path = root.join(SCENARIO_OWNERSHIP_FILE);
        let mut marker = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(marker_path)?;
        marker.write_all(b"ASTER_LAB_SCENARIO_INVOCATION\tversion=1\n")?;
        marker.sync_all()?;
        Ok(Self { root })
    }
}

fn run_transfer_command(options: &Options) -> LabResult<()> {
    let claim = ScenarioRootClaim::reserve(options.required_path("root")?)?;
    let started = Instant::now();
    let mut failure = LabMetrics {
        scenario: "transfer".into(),
        shards: 1,
        nodes: 2,
        ..LabMetrics::default()
    };
    let result = match transfer_scenario(options) {
        Ok(scenario) => {
            failure.seed = scenario.seed;
            failure.published_items = u64::from(scenario.items);
            failure.configured_bits_per_second = scenario.fault.bits_per_second;
            failure.configured_loss_per_mille = scenario.fault.loss_per_mille;
            failure.loss_window_frames = 1_000;
            run_transfer(&scenario)
        }
        Err(error) => Err(error),
    };
    finish_scenario(&claim, failure, started, result)
}

fn run_blob_command(options: &Options) -> LabResult<()> {
    let claim = ScenarioRootClaim::reserve(options.required_path("root")?)?;
    let started = Instant::now();
    let mut failure = LabMetrics {
        scenario: "blob-recovery".into(),
        shards: 1,
        nodes: 3,
        published_items: 1,
        ..LabMetrics::default()
    };
    let result = match blob_scenario(options) {
        Ok(scenario) => {
            failure.seed = scenario.seed;
            failure.blob_bytes = scenario.blob_bytes;
            failure.configured_bits_per_second = scenario.fault.bits_per_second;
            failure.configured_loss_per_mille = scenario.fault.loss_per_mille;
            failure.loss_window_frames = 1_000;
            run_blob_recovery(&scenario)
        }
        Err(error) => Err(error),
    };
    finish_scenario(&claim, failure, started, result)
}

fn run_shard_command(options: &Options) -> LabResult<()> {
    let claim = ScenarioRootClaim::reserve(options.required_path("root")?)?;
    let started = Instant::now();
    let mut failure = LabMetrics {
        scenario: "shard-worker".into(),
        shards: 1,
        ..LabMetrics::default()
    };
    let result = match shard_scenario(options) {
        Ok(scenario) => {
            failure.scenario = format!(
                "shard-{:04}-first-{:06}",
                scenario.shard_index, scenario.first_node
            );
            failure.seed = scenario.seed;
            failure.nodes = scenario.nodes;
            failure.published_items = u64::from(scenario.items);
            failure.configured_bits_per_second = scenario.fault.bits_per_second;
            failure.configured_loss_per_mille = scenario.fault.loss_per_mille;
            failure.loss_window_frames = 1_000;
            run_shard(&scenario)
        }
        Err(error) => Err(error),
    };
    finish_scenario(&claim, failure, started, result)
}

fn run_scale_command(options: &Options) -> LabResult<()> {
    let claim = ScenarioRootClaim::reserve(options.required_path("root")?)?;
    let started = Instant::now();
    let failure = LabMetrics {
        scenario: "scale".into(),
        ..LabMetrics::default()
    };
    finish_action(&claim, failure, started, run_scale(options))
}

fn transfer_scenario(options: &Options) -> LabResult<TransferScenario> {
    let fault = fault(options)?;
    let checkpoint = options.number("restart-after-frames", 24_u64)?;
    Ok(TransferScenario {
        root: options.required_path("root")?,
        seed: fault.seed,
        items: options.number("items", 4)?,
        payload_bytes: options.number("payload-bytes", 65_536)?,
        restart_after_delivered_frames: (checkpoint != 0).then_some(checkpoint),
        max_pumps: options.number("max-pumps", 200_000)?,
        fault,
    })
}

fn blob_scenario(options: &Options) -> LabResult<BlobRecoveryScenario> {
    let fault = fault(options)?;
    Ok(BlobRecoveryScenario {
        root: options.required_path("root")?,
        seed: fault.seed,
        blob_bytes: options.number("blob-bytes", 105_906_176)?,
        chunk_bytes: options.number("chunk-bytes", 65_536)?,
        restart_after_delivered_frames: options.number("restart-after-frames", 256)?,
        max_pumps_per_contact: options.number("max-pumps", 2_000_000)?,
        fault,
    })
}

fn shard_scenario(options: &Options) -> LabResult<ShardScenario> {
    let fault = fault(options)?;
    Ok(ShardScenario {
        root: options.required_path("root")?,
        seed: fault.seed,
        shard_index: options.required_number("shard-index")?,
        first_node: options.required_number("first-node")?,
        nodes: options.required_number("nodes")?,
        items: options.number("items", 1)?,
        payload_bytes: options.number("payload-bytes", 1_024)?,
        max_pumps_per_edge: options.number("max-pumps", 100_000)?,
        fault,
    })
}

fn run_scale(options: &Options) -> LabResult<()> {
    let root = options.required_path("root")?;
    ensure_empty(&root)?;
    let fault = fault(options)?;
    let nodes: u32 = options.required_number("nodes")?;
    let shards: u32 = options.required_number("shards")?;
    if nodes == 0 || shards == 0 || shards > nodes {
        return Err(invalid(
            "--nodes and --shards must be nonzero and shards cannot exceed nodes",
        ));
    }
    let items: u32 = options.number("items", 1)?;
    let payload: usize = options.number("payload-bytes", 1_024)?;
    let max_pumps: u64 = options.number("max-pumps", 100_000)?;
    let started = Instant::now();
    let mut aggregate = LabMetrics {
        scenario: "scale".into(),
        seed: fault.seed,
        configured_bits_per_second: fault.bits_per_second,
        configured_loss_per_mille: fault.loss_per_mille,
        loss_window_frames: 1_000,
        converged: true,
        ..LabMetrics::default()
    };
    let executable = match env::current_exe() {
        Ok(executable) => executable,
        Err(error) => {
            return fail_scale(
                &root,
                &mut aggregate,
                started,
                format!("scale executable resolution failed: {error}"),
            );
        }
    };
    let mut children: Vec<(u32, u32, u32, std::process::Child)> = Vec::new();
    let mut first_node = 0_u32;
    for shard in 0..shards {
        let count = nodes / shards + u32::from(shard < nodes % shards);
        let shard_root = root.join(format!("shard-{shard:04}"));
        let spawn = Command::new(&executable)
            .arg("shard-worker")
            .arg("--root")
            .arg(&shard_root)
            .arg("--seed")
            .arg(fault.seed.to_string())
            .arg("--shard-index")
            .arg(shard.to_string())
            .arg("--first-node")
            .arg(first_node.to_string())
            .arg("--nodes")
            .arg(count.to_string())
            .arg("--items")
            .arg(items.to_string())
            .arg("--payload-bytes")
            .arg(payload.to_string())
            .arg("--max-pumps")
            .arg(max_pumps.to_string())
            .arg("--mtu")
            .arg(fault.mtu.to_string())
            .arg("--bps")
            .arg(fault.bits_per_second.to_string())
            .arg("--loss-per-mille")
            .arg(fault.loss_per_mille.to_string())
            .arg("--reorder-ticks")
            .arg(fault.reorder_ticks.to_string())
            .arg("--tick-ms")
            .arg(fault.tick_ms.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let child = match spawn {
            Ok(child) => child,
            Err(error) => {
                for (_, _, _, child) in &mut children {
                    let _ = child.kill();
                }
                for (_, _, _, child) in children.drain(..) {
                    let _ = child.wait_with_output();
                }
                return fail_scale(
                    &root,
                    &mut aggregate,
                    started,
                    format!("scale worker spawn failed: {error}"),
                );
            }
        };
        children.push((shard, first_node, count, child));
        first_node = first_node.saturating_add(count);
    }
    let mut completed = Vec::with_capacity(children.len());
    let mut wait_failures = Vec::new();
    for (shard, worker_first_node, count, child) in children {
        match child.wait_with_output() {
            Ok(output) => completed.push((shard, worker_first_node, count, output)),
            Err(error) => wait_failures.push(format!("shard {shard} wait failed: {error}")),
        }
    }
    for (shard, _, _, output) in &completed {
        if !output.status.success() {
            wait_failures.push(format!(
                "shard {shard} exited unsuccessfully: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
    }
    if !wait_failures.is_empty() {
        return fail_scale(
            &root,
            &mut aggregate,
            started,
            format!(
                "scale workers failed after all children were reaped: {}",
                wait_failures.join("; ")
            ),
        );
    }
    let parse_result: LabResult<()> = (|| {
        for (shard, worker_first_node, count, output) in completed {
            let stdout = String::from_utf8(output.stdout)?;
            let record = stdout
                .lines()
                .find(|line| line.starts_with("ASTER_LAB_METRICS\t"))
                .ok_or_else(|| invalid(format!("scale shard {shard} emitted no metrics record")))?;
            let worker = LabMetrics::from_record(record)?;
            validate_scale_worker(&worker, shard, worker_first_node, count, items, &fault)?;
            aggregate.add_worker(&worker);
        }
        Ok(())
    })();
    if let Err(error) = parse_result {
        return fail_scale(
            &root,
            &mut aggregate,
            started,
            format!("scale worker evidence validation failed: {error}"),
        );
    }
    let expected_published = u64::from(items).saturating_mul(u64::from(shards));
    let expected_delivered = u64::from(items).saturating_mul(u64::from(nodes));
    if !aggregate.converged
        || aggregate.shards != shards
        || aggregate.nodes != nodes
        || aggregate.published_items != expected_published
        || aggregate.delivered_items != expected_delivered
    {
        return fail_scale(
            &root,
            &mut aggregate,
            started,
            "scale aggregate does not match the requested topology and workload".into(),
        );
    }
    aggregate.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    emit(&root, &aggregate)
}

fn fail_scale(
    root: &Path,
    metrics: &mut LabMetrics,
    started: Instant,
    message: String,
) -> LabResult<()> {
    metrics.converged = false;
    metrics.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    match write_metrics(root, metrics) {
        Ok(_) => Err(invalid(message)),
        Err(write_error) => Err(invalid(format!(
            "{message}; failure metrics could not be preserved: {write_error}"
        ))),
    }
}

fn validate_scale_worker(
    worker: &LabMetrics,
    shard: u32,
    first_node: u32,
    nodes: u32,
    items: u32,
    fault: &FaultProfile,
) -> LabResult<()> {
    let expected_scenario = format!("shard-{shard:04}-first-{first_node:06}");
    let expected_delivered = u64::from(items).saturating_mul(u64::from(nodes));
    if worker.scenario != expected_scenario
        || worker.seed != fault.seed
        || worker.shards != 1
        || worker.nodes != nodes
        || worker.published_items != u64::from(items)
        || worker.delivered_items != expected_delivered
        || worker.blob_bytes != 0
        || worker.restarts != 0
        || worker.partial_restart_observed
        || worker.partial_durable_blob_bytes != 0
        || worker.reopened_durable_blob_bytes != 0
        || worker.durable_progress_preserved
        || worker.configured_bits_per_second != fault.bits_per_second
        || worker.configured_loss_per_mille != fault.loss_per_mille
        || worker.loss_window_frames != 1_000
        || !worker.converged
    {
        return Err(invalid(format!(
            "scale shard {shard} metrics do not match its requested identity or configuration"
        )));
    }
    Ok(())
}

fn ensure_empty(path: &Path) -> LabResult<()> {
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

fn finish_scenario(
    claim: &ScenarioRootClaim,
    failure: LabMetrics,
    started: Instant,
    result: LabResult<LabMetrics>,
) -> LabResult<()> {
    match result {
        Ok(metrics) => emit(&claim.root, &metrics),
        Err(error) => preserve_failure(claim, failure, started, error),
    }
}

fn finish_action(
    claim: &ScenarioRootClaim,
    failure: LabMetrics,
    started: Instant,
    result: LabResult<()>,
) -> LabResult<()> {
    match result {
        Ok(()) => Ok(()),
        Err(error) => preserve_failure(claim, failure, started, error),
    }
}

fn preserve_failure(
    claim: &ScenarioRootClaim,
    mut failure: LabMetrics,
    started: Instant,
    error: Box<dyn std::error::Error + Send + Sync>,
) -> LabResult<()> {
    if claim.root.join("metrics.json").exists() {
        return Err(error);
    }
    failure.elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    failure.converged = false;
    match write_metrics(&claim.root, &failure) {
        Ok(_) => Err(error),
        Err(write_error) => Err(invalid(format!(
            "{error}; failure metrics could not be preserved: {write_error}"
        ))),
    }
}

fn emit(root: &Path, metrics: &LabMetrics) -> LabResult<()> {
    write_metrics(root, metrics)?;
    println!("{}", metrics.to_json());
    println!("{}", metrics.to_record());
    Ok(())
}

fn emit_live(
    evidence: &LiveEvidenceInvocation,
    metrics: &LabMetrics,
    live: &aster_lab::live::LiveMetrics,
) -> LabResult<()> {
    evidence.write_live_result(live)?;
    evidence.write_metrics(metrics)?;
    println!("{}", metrics.to_json());
    println!("{}", metrics.to_record());
    Ok(())
}

fn invalid(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_path(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        std::env::temp_dir().join(format!(
            "aster-lab-main-{label}-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock must follow Unix epoch")
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ))
    }

    #[test]
    fn every_command_rejects_unlisted_options() {
        for command in [
            "provision",
            "node-udp",
            "node-rendezvous",
            "node-discovery",
            "node-relay",
            "rendezvous",
            "infra",
            "transfer",
            "blob-recovery",
            "scale",
            "shard-worker",
        ] {
            let options = Options(BTreeMap::from([("not-a-real-option".into(), "1".into())]));
            assert!(
                options.reject_unknown(command).is_err(),
                "{command} accepted an unknown option"
            );
        }
    }

    #[test]
    fn provisioning_seed_is_not_an_allowed_option() {
        assert!(!option_is_allowed("provision", "seed"));
    }

    #[test]
    fn scale_worker_metrics_are_bound_to_requested_identity_and_configuration() {
        let fault = FaultProfile::default();
        let mut worker = LabMetrics {
            scenario: "shard-0002-first-000020".into(),
            seed: fault.seed,
            shards: 1,
            nodes: 5,
            published_items: 3,
            delivered_items: 15,
            configured_bits_per_second: fault.bits_per_second,
            configured_loss_per_mille: fault.loss_per_mille,
            loss_window_frames: 1_000,
            converged: true,
            ..LabMetrics::default()
        };
        assert!(validate_scale_worker(&worker, 2, 20, 5, 3, &fault).is_ok());
        worker.nodes = 4;
        assert!(validate_scale_worker(&worker, 2, 20, 5, 3, &fault).is_err());
    }

    #[test]
    fn relay_pair_limit_requires_a_relay_listener() {
        let options = Options(BTreeMap::from([
            ("bind".into(), "127.0.0.1:0".into()),
            ("relay-pairs".into(), "1".into()),
        ]));
        assert!(run_infrastructure(&options, true).is_err());
    }

    #[test]
    fn scenario_claim_never_modifies_a_preexisting_root() {
        let root = test_path("preexisting-root");
        fs::create_dir_all(&root).unwrap();
        let sentinel = root.join("sentinel.txt");
        fs::write(&sentinel, b"preserve me").unwrap();

        let error = ScenarioRootClaim::reserve(root.clone()).unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(fs::read(&sentinel).unwrap(), b"preserve me");
        assert!(!root.join(SCENARIO_OWNERSHIP_FILE).exists());
        assert!(!root.join("metrics.json").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scale_setup_failure_preserves_metrics_in_its_owned_root() {
        let root = test_path("scale-setup-failure");
        let options = Options(BTreeMap::from([
            ("root".into(), root.display().to_string()),
            ("nodes".into(), "0".into()),
            ("shards".into(), "1".into()),
        ]));

        let error = run_scale_command(&options).unwrap_err();
        assert!(error.to_string().contains("must be nonzero"));
        assert!(root.join(SCENARIO_OWNERSHIP_FILE).is_file());
        let evidence = fs::read_to_string(root.join("metrics.json")).unwrap();
        assert!(evidence.contains("\"scenario\": \"scale\""));
        assert!(evidence.contains("\"converged\": false"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn transfer_parse_failure_preserves_metrics_in_its_owned_root() {
        let root = test_path("transfer-parse-failure");
        let options = Options(BTreeMap::from([
            ("root".into(), root.display().to_string()),
            ("items".into(), "not-a-number".into()),
        ]));

        assert!(run_transfer_command(&options).is_err());
        assert!(root.join(SCENARIO_OWNERSHIP_FILE).is_file());
        let evidence = fs::read_to_string(root.join("metrics.json")).unwrap();
        assert!(evidence.contains("\"scenario\": \"transfer\""));
        assert!(evidence.contains("\"converged\": false"));
        fs::remove_dir_all(root).unwrap();
    }
}
