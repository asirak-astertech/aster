use std::{
    collections::BTreeSet,
    env,
    fs::OpenOptions,
    io::{self, Read},
    num::NonZeroU64,
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};

use aster_iroh::{
    MAX_RELAY_CA_ROOT_BYTES, MAX_RELAY_CA_ROOT_TOTAL_BYTES, MAX_RELAY_CA_ROOTS,
    MAX_RELAY_URL_BYTES, PinnedRelay,
};
use aster_mesh::{Scope, ScopeRekeyRecipient, Topic};
use aster_node::{
    DemoScenario, MissionExpectedPeer, MutableSourceInterests, NodeApplication, NodeConfig,
    NodeIdentity, RegistryGenerationWitness, RevocationRequest, ScopeRekeyRequest,
    SelectedControlAdmin, SelectedForwardingConfig, SourceInterestSelector,
    ensure_state_accepts_normal_operation, format_control_transfer_id, format_path_field,
    format_receipt_field, inspect_store, mission::UnprotectedReferenceMission, parse_item_id,
    parse_node_id, put_opaque, run_demo_scenario, run_node, run_node_with_forwarding, zeroize_node,
};

const MAX_PUT_BYTES: u64 = 1024 * 1024;
const MAX_REKEY_REGISTRY_BYTES: u64 = 16 * 1024 * 1024;

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to start runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ERROR error={}", format_receipt_field(&error.to_string()));
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = Arguments::new(env::args().skip(1));
    match arguments.command()?.as_str() {
        "init" => {
            let state = arguments.required_path("--state")?;
            arguments.finish()?;
            ensure_state_accepts_normal_operation(&state)?;
            let identity = NodeIdentity::load_or_create(&state)?;
            println!(
                "INIT status=pass state={} id={} key={}",
                format_path_field(&state),
                identity.id(),
                format_path_field(identity.path())
            );
        }
        "put" => {
            let state = arguments.required_path("--state")?;
            let id = parse_item_id(&arguments.required("--id")?)?;
            let file = arguments.required_path("--file")?;
            arguments.finish()?;
            ensure_state_accepts_normal_operation(&state)?;
            let bytes = read_put_source(&file)?;
            let inserted = put_opaque(&state, id, &bytes)?;
            println!(
                "PUT status=pass state={} id={} inserted={} source={} semantics=opaque",
                format_path_field(&state),
                aster_node::format_item_id(id),
                inserted,
                format_path_field(&file)
            );
        }
        "inspect" => {
            let state = arguments.required_path("--state")?;
            arguments.finish()?;
            let receipt = inspect_store(&state)?;
            println!(
                "INSPECT status=pass state={} zeroization={} opaque_items={} opaque_acceptance_markers={} opaque_bytes={} events={} event_acceptance_markers={} event_sealed_bytes={} route_cached_events={} route_cached_bytes={} controls={} applied_controls={} pending_controls={} control_highwater={}",
                format_path_field(&state),
                receipt.zeroization.as_str(),
                receipt.items,
                receipt.acceptance_markers,
                receipt.payload_bytes,
                receipt.events,
                receipt.event_acceptance_markers,
                receipt.event_sealed_bytes,
                receipt.route_cached_events,
                receipt.route_cached_bytes,
                receipt.controls,
                receipt.applied_controls,
                receipt.pending_controls,
                receipt.control_highwater,
            );
            for id in receipt.ids {
                println!("ITEM id={}", aster_node::format_item_id(id));
            }
        }
        "control-revoke" => {
            let state = arguments.required_path("--state")?;
            let mission_bundle =
                arguments.required_path("--mission-bundle-unprotected-reference")?;
            let subject = parse_node_id(&arguments.required("--subject")?)?;
            let generation = arguments.required("--generation")?.parse::<NonZeroU64>()?;
            let request = RevocationRequest::new(subject, generation);
            arguments.finish()?;
            let admin = SelectedControlAdmin::open_unprotected_reference(&state, mission_bundle)?;
            let receipt = admin.publish_revocation(request)?;
            println!(
                "CONTROL status={} kind=revocation transfer_id={} sequence={} subject={} generation={} activated={} source_authenticated=true commit_before_activate=true publication_disposition={}",
                if receipt.emitted {
                    "emitted"
                } else {
                    "existing"
                },
                format_control_transfer_id(receipt.transfer_id),
                receipt.sequence,
                aster_node::format_node_id(subject),
                generation.get(),
                receipt.activated,
                if receipt.emitted {
                    "committed-this-call"
                } else {
                    "recovered-same-signer"
                },
            );
        }
        "control-rekey" => {
            let state = arguments.required_path("--state")?;
            let mission_bundle =
                arguments.required_path("--mission-bundle-unprotected-reference")?;
            let registry_path = arguments.required_path("--signed-public-registry")?;
            let minimum_registry_generation = RegistryGenerationWitness::new(
                arguments
                    .required("--minimum-registry-generation")?
                    .parse::<NonZeroU64>()?,
            );
            let scope = Scope::new(arguments.required("--scope")?)?;
            let epoch = arguments.required("--epoch")?.parse::<NonZeroU64>()?;
            let route_recipients = arguments.repeated("--route-recipient")?;
            let member_recipients = arguments.repeated("--member-recipient")?;
            arguments.finish()?;
            let recipients = parse_rekey_recipients(route_recipients, member_recipients)?;
            let registry = read_registry_source(&registry_path)?;
            let recipient_count = recipients.len();
            let request = ScopeRekeyRequest::new(
                registry,
                minimum_registry_generation,
                scope.clone(),
                epoch,
                recipients,
            )?;
            let admin = SelectedControlAdmin::open_unprotected_reference(&state, mission_bundle)?;
            let receipt = admin.publish_scope_rekey(request)?;
            println!(
                "CONTROL status={} kind=scope-rekey transfer_id={} sequence={} scope={} epoch={} recipients={} activated={} source_authenticated=true recipient_filtered=true commit_before_activate=true publication_disposition={}",
                if receipt.emitted {
                    "emitted"
                } else {
                    "existing"
                },
                format_control_transfer_id(receipt.transfer_id),
                receipt.sequence,
                scope.as_str(),
                epoch.get(),
                recipient_count,
                receipt.activated,
                if receipt.emitted {
                    "committed-this-call"
                } else {
                    "recovered-same-signer"
                },
            );
        }
        "node" => {
            let state = arguments.required_path("--state")?;
            let bind = arguments.required("--bind")?.parse()?;
            let mission_bundle =
                arguments.required_path("--mission-bundle-unprotected-reference")?;
            let peers = arguments.repeated("--peer")?;
            let peers = peers
                .iter()
                .map(|peer| peer.parse::<MissionExpectedPeer>())
                .collect::<Result<Vec<_>, _>>()?;
            let state_interests = arguments
                .repeated("--state-interest")?
                .iter()
                .map(|value| parse_source_interest(value, "State"))
                .collect::<Result<Vec<_>, _>>()?;
            let record_interests = arguments
                .repeated("--record-interest")?
                .iter()
                .map(|value| parse_source_interest(value, "Record"))
                .collect::<Result<Vec<_>, _>>()?;
            let blob_interests = arguments
                .repeated("--blob-interest")?
                .iter()
                .map(|value| parse_source_interest(value, "Blob"))
                .collect::<Result<Vec<_>, _>>()?;
            let run_for = arguments
                .optional("--run-for")?
                .map(|seconds| seconds.parse::<u64>())
                .transpose()?
                .map(Duration::from_secs);
            let interval = Duration::from_millis(
                arguments
                    .optional("--sync-ms")?
                    .map_or(Ok(500u64), |value| value.parse())?,
            );
            let application = arguments
                .optional("--application")?
                .map_or(Ok(NodeApplication::Relay), |value| {
                    NodeApplication::parse(&value)
                })?;
            let controlled_relay_url = arguments.optional_once("--controlled-relay-url")?;
            let controlled_relay_trust = arguments.optional_once("--controlled-relay-trust")?;
            let controlled_relay_ca_der = arguments
                .repeated("--controlled-relay-ca-der")?
                .into_iter()
                .map(PathBuf::from)
                .collect::<Vec<_>>();
            let controlled_relay_only = arguments.switch("--controlled-relay-only")?;
            arguments.finish_redacted()?;
            let controlled_relay = parse_controlled_relay(
                controlled_relay_url,
                controlled_relay_trust,
                controlled_relay_ca_der,
                controlled_relay_only,
            )?;
            ensure_state_accepts_normal_operation(&state)?;
            let mission = UnprotectedReferenceMission::load(&mission_bundle)?;
            let config = NodeConfig {
                state,
                bind,
                mission,
                peers,
                mutable_interests: MutableSourceInterests::new(state_interests, record_interests)
                    .with_blob(blob_interests),
                sync_interval: interval,
                run_for,
                application,
            };
            match controlled_relay {
                Some((relay, true)) => {
                    run_node_with_forwarding(
                        config,
                        SelectedForwardingConfig::default().with_controlled_relay_only(relay),
                    )
                    .await?;
                }
                Some((relay, false)) => {
                    run_node_with_forwarding(
                        config,
                        SelectedForwardingConfig::default().with_controlled_relay(relay),
                    )
                    .await?;
                }
                None => {
                    run_node(config).await?;
                }
            }
        }
        "zeroize" => {
            let state = arguments.required_path("--state")?;
            let mission_bundle =
                arguments.required_path("--mission-bundle-unprotected-reference")?;
            let wait = Duration::from_secs(
                arguments
                    .optional("--wait-seconds")?
                    .map_or(Ok(120u64), |value| value.parse())?,
            );
            arguments.finish()?;
            let receipt = zeroize_node(&state, &mission_bundle, wait).await?;
            println!(
                "ZEROIZE status=pass mode={} state={} mission_destroyed={} carrier_identity_destroyed={} mission_pathname={} carrier_identity_pathname={} data_rows_preserved=true opaque_items={} events={} route_cached_events={} controls={} assurance=bounded-software physical_sanitization=not-claimed local_authority=same-uid-operator state_root={}",
                if receipt.live_request {
                    "live"
                } else {
                    "stopped"
                },
                receipt.state.as_str(),
                receipt.mission_destroyed,
                receipt.identity_destroyed,
                receipt.mission_pathname.as_str(),
                receipt.identity_pathname.as_str(),
                receipt.preserved.items,
                receipt.preserved.events,
                receipt.preserved.route_cached_events,
                receipt.preserved.controls,
                format_path_field(&state),
            );
        }
        "demo" => {
            let nodes = arguments.required("--nodes")?.parse()?;
            let root = arguments.required_path("--root")?;
            let base_port = arguments
                .optional("--base-port")?
                .map_or(Ok(0u16), |value| value.parse())?;
            let scenario = arguments
                .optional("--scenario")?
                .map_or(Ok(DemoScenario::PingPong), |value| {
                    DemoScenario::parse(&value)
                })?;
            arguments.finish()?;
            run_demo_scenario(scenario, nodes, &root, base_port)?;
        }
        "help" | "--help" | "-h" => print_help(),
        command => return Err(format!("unknown command {command:?}; run `aster help`").into()),
    }
    Ok(())
}

fn read_put_source(path: &Path) -> io::Result<Vec<u8>> {
    read_regular_bounded(path, MAX_PUT_BYTES, "put source")
}

fn read_registry_source(path: &Path) -> io::Result<Vec<u8>> {
    read_regular_bounded(
        path,
        MAX_REKEY_REGISTRY_BYTES,
        "signed public rekey registry",
    )
}

fn read_regular_bounded(path: &Path, limit: u64, label: &str) -> io::Result<Vec<u8>> {
    let path_metadata = std::fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} must not be a symbolic link"),
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if path_metadata.dev() != metadata.dev() || path_metadata.ino() != metadata.ino() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{label} changed while opening"),
            ));
        }
    }
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{label} must be a regular file"),
        ));
    }
    if metadata.len() > limit {
        return Err(source_too_large(label, limit));
    }

    // Metadata is only a preflight. The bounded reader remains authoritative
    // if a regular file grows after inspection.
    read_bounded_limit(file, metadata.len(), limit, label)
}

#[cfg(test)]
fn read_bounded(reader: impl Read, length_hint: u64) -> io::Result<Vec<u8>> {
    read_bounded_limit(reader, length_hint, MAX_PUT_BYTES, "put source")
}

fn read_bounded_limit(
    reader: impl Read,
    length_hint: u64,
    limit: u64,
    label: &str,
) -> io::Result<Vec<u8>> {
    let capacity =
        usize::try_from(length_hint.min(limit)).expect("the one-MiB put limit fits in usize");
    let mut bytes = Vec::with_capacity(capacity);
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).expect("vector length fits in u64") > limit {
        return Err(source_too_large(label, limit));
    }
    Ok(bytes)
}

fn source_too_large(label: &str, limit: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{label} exceeds the {limit}-byte limit"),
    )
}

fn parse_rekey_recipients(
    route_specs: Vec<String>,
    member_specs: Vec<String>,
) -> Result<Vec<ScopeRekeyRecipient>, Box<dyn std::error::Error>> {
    let mut seen = BTreeSet::new();
    let mut recipients = Vec::new();
    for spec in route_specs {
        let node = parse_node_id(&spec)?;
        if !seen.insert(node) {
            return Err(format!("duplicate rekey recipient {spec}").into());
        }
        recipients.push(ScopeRekeyRecipient::route_only(node));
    }
    for spec in member_specs {
        let (node, topics) = spec.split_once('=').ok_or_else(|| {
            "member recipient must be MISSION_NODE_ID_HEX64=TOPIC[,TOPIC...]".to_owned()
        })?;
        let node = parse_node_id(node)?;
        if !seen.insert(node) {
            return Err(format!(
                "duplicate rekey recipient {}",
                aster_node::format_node_id(node)
            )
            .into());
        }
        let topics = topics
            .split(',')
            .map(Topic::new)
            .collect::<Result<Vec<_>, _>>()?;
        recipients.push(ScopeRekeyRecipient::member(node, topics)?);
    }
    if recipients.is_empty() {
        return Err("scope rekey requires at least one recipient".into());
    }
    Ok(recipients)
}

fn parse_controlled_relay(
    url: Option<String>,
    trust: Option<String>,
    ca_paths: Vec<PathBuf>,
    relay_only: bool,
) -> Result<Option<(PinnedRelay, bool)>, Box<dyn std::error::Error>> {
    let Some(url) = url else {
        if trust.is_some() || !ca_paths.is_empty() || relay_only {
            return Err(
                "controlled relay trust, CA roots, and relay-only mode require --controlled-relay-url"
                    .into(),
            );
        }
        return Ok(None);
    };
    let trust = trust.ok_or(
        "--controlled-relay-url requires explicit --controlled-relay-trust webpki|der-roots",
    )?;
    if url.len() > MAX_RELAY_URL_BYTES {
        return Err(format!("controlled relay URL exceeds {MAX_RELAY_URL_BYTES} bytes").into());
    }
    let url = url.parse()?;
    let relay = match trust.as_str() {
        "webpki" => {
            if !ca_paths.is_empty() {
                return Err(
                    "--controlled-relay-ca-der is incompatible with webpki relay trust".into(),
                );
            }
            PinnedRelay::new(url)?
        }
        "der-roots" => {
            if ca_paths.is_empty() {
                return Err(
                    "der-roots relay trust requires at least one --controlled-relay-ca-der".into(),
                );
            }
            if ca_paths.len() > MAX_RELAY_CA_ROOTS {
                return Err(format!(
                    "controlled relay CA root count {} exceeds {MAX_RELAY_CA_ROOTS}",
                    ca_paths.len()
                )
                .into());
            }
            let mut roots = Vec::with_capacity(ca_paths.len());
            let mut total = 0usize;
            for path in ca_paths {
                let root = read_regular_bounded(
                    &path,
                    u64::try_from(MAX_RELAY_CA_ROOT_BYTES)
                        .expect("relay CA root byte bound fits u64"),
                    "controlled relay DER CA root",
                )?;
                total = total
                    .checked_add(root.len())
                    .ok_or("controlled relay CA root total exceeds the platform address space")?;
                if total > MAX_RELAY_CA_ROOT_TOTAL_BYTES {
                    return Err(format!(
                        "controlled relay CA roots total {total} bytes exceeds {MAX_RELAY_CA_ROOT_TOTAL_BYTES}"
                    )
                    .into());
                }
                roots.push(root);
            }
            PinnedRelay::with_ca_roots(url, roots)?
        }
        _ => {
            return Err("controlled relay trust must be webpki or der-roots".into());
        }
    };
    Ok(Some((relay, relay_only)))
}

fn parse_source_interest(
    value: &str,
    class: &str,
) -> Result<SourceInterestSelector, Box<dyn std::error::Error>> {
    let (topic, scope) = value
        .split_once('@')
        .ok_or_else(|| format!("{class} interest must use exact TOPIC@SCOPE syntax"))?;
    if scope.contains('@') {
        return Err(format!("{class} interest contains more than one separator").into());
    }
    Ok(SourceInterestSelector::new(
        Topic::new(topic)?,
        Scope::new(scope)?,
        false,
    ))
}

fn print_help() {
    println!(
        "Aster selected-stack mesh CLI\n\n\
         Commands:\n\
           aster init --state DIR\n\
           aster put --state DIR --id HEX64 --file PATH  # maximum 1,048,576 bytes\n\
           aster inspect --state DIR\n\
           aster zeroize --state DIR \\
             --mission-bundle-unprotected-reference FILE [--wait-seconds SEC]\n\
           aster control-revoke --state DIR \\
             --mission-bundle-unprotected-reference FILE \\
             --subject MISSION_NODE_ID_HEX64 --generation N\n\
           aster control-rekey --state DIR \\
             --mission-bundle-unprotected-reference FILE \\
             --signed-public-registry FILE --scope SCOPE --epoch N \\
             --minimum-registry-generation NONZERO_N \\
             [--route-recipient MISSION_NODE_ID_HEX64 ...] \\
             [--member-recipient MISSION_NODE_ID_HEX64=TOPIC[,TOPIC...] ...]\n\
           aster node --state DIR --bind IP:PORT \\
             --mission-bundle-unprotected-reference FILE \\
             [--peer CARRIER_ID@IP:PORT=MISSION_NODE_ID_HEX64 ...] \\
             [--state-interest TOPIC@SCOPE ...] [--record-interest TOPIC@SCOPE ...] \\
             [--blob-interest TOPIC@SCOPE ...] \\
             [--controlled-relay-url HTTPS_URL \\
              --controlled-relay-trust webpki|der-roots \\
              [--controlled-relay-ca-der FILE ...] [--controlled-relay-only]] \\
             [--sync-ms N] [--run-for SEC] \
             [--application relay|ping-emitter|epoch2-ping-emitter|pong-responder]\n\
           aster demo --nodes N --root DIR [--base-port PORT] \
             [--scenario ping-pong|control]\n\n\
         Every node contact requires the aster-core hybrid-PQ mission handshake before\n\
         inventory or object frames. Carrier IDs and mission NodeIDs are independent exact\n\
         checks. On Unix the explicitly named unprotected-reference bundle requires owner-only\n\
         permissions; unsupported platforms fail closed. It is NOT production-secure at-rest\n\
         provisioning, and the selected Iroh carrier identity is not mission authorization.\n\
         Controlled relay routing is an explicit single-URL opt-in. WebPKI uses embedded roots;\n\
         der-roots requires bounded explicit DER CA files. No insecure TLS, hosted lookup, or public\n\
         relay fallback is enabled. The operator-supplied initial route set is bounded; authenticated\n\
         Iroh NAT negotiation may add direct paths after connection. --controlled-relay-only disables\n\
         IP transport. Carrier path and transition fields are bounded observations, never\n\
         authorization; NAT acceptance remains explicitly unclaimed.\n\
         Authority commands use the existing recipient-filtered aster-core control format and\n\
         reserve/seal/verify/commit controls idempotently before provider activation. Node/demo\n\
         contacts reconcile those mission-wide Flash controls in a distinct lane before carrying\n\
         exact source-sealed Aster objects. Events follow durable application Consume/Carry\n\
         selectors. Repeatable --state-interest, --record-interest, and --blob-interest values opt\n\
         the receiver into exact topic/scope source lanes; an empty class interest means\n\
         receive-none. Blob source and resumable carrier phases require semantic v5.\n\
         Record ingest retains concurrent revisions and never executes application merge code.\n\
         The demo defaults to the N-instance ping-pong scenario;\n\
         the explicit control scenario requires exactly four role-bound nodes. Concurrent demos\n\
         must use disjoint explicit --base-port blocks; automatic selection is a single-demo\n\
         convenience. Semantic admission\n\
         and application reaction require successful content authentication; payload-blind relays\n\
         retain only bounded route-verified bytes. The put command remains an isolated opaque\n\
         compatibility lane and is never advertised by Event reconciliation. Semantic v3 binds\n\
         finite-TTL dissemination to authenticated cumulative custody age, exact source claims,\n\
         quotas, and final send checks; production finite-TTL clocks are currently Linux-only.\n\
         Zeroize is an irreversible same-UID local operator hook. It durably locks the exact\n\
         state before destroying mission/carrier key contents through retained file descriptors\n\
         and preserves mesh data rows.\n\
         Its receipt proves bounded software erasure only, not flash, snapshot, swap, or backup\n\
         sanitization; uniquely linked owner-only artifacts are required and replacements are kept."
    );
}

struct Arguments {
    values: Vec<String>,
}

impl Arguments {
    fn new(values: impl Iterator<Item = String>) -> Self {
        Self {
            values: values.collect(),
        }
    }

    fn command(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        if self.values.is_empty() {
            return Err("missing command; run `aster help`".into());
        }
        Ok(self.values.remove(0))
    }

    fn required(&mut self, flag: &str) -> Result<String, Box<dyn std::error::Error>> {
        self.optional(flag)?
            .ok_or_else(|| format!("missing required {flag}").into())
    }

    fn required_path(&mut self, flag: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
        self.required(flag).map(PathBuf::from)
    }

    fn optional(&mut self, flag: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let Some(index) = self.values.iter().position(|value| value == flag) else {
            return Ok(None);
        };
        if index + 1 >= self.values.len() || self.values[index + 1].starts_with("--") {
            return Err(format!("{flag} requires a value").into());
        }
        self.values.remove(index);
        Ok(Some(self.values.remove(index)))
    }

    fn optional_once(&mut self, flag: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        if self.values.iter().filter(|value| *value == flag).count() > 1 {
            return Err(format!("{flag} may be specified at most once").into());
        }
        self.optional(flag)
    }

    fn repeated(&mut self, flag: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let mut output = Vec::new();
        while let Some(value) = self.optional(flag)? {
            output.push(value);
        }
        Ok(output)
    }

    fn switch(&mut self, flag: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let matches = self.values.iter().filter(|value| *value == flag).count();
        if matches > 1 {
            return Err(format!("{flag} may be specified at most once").into());
        }
        let Some(index) = self.values.iter().position(|value| value == flag) else {
            return Ok(false);
        };
        self.values.remove(index);
        Ok(true)
    }

    fn finish(self) -> Result<(), Box<dyn std::error::Error>> {
        if self.values.is_empty() {
            Ok(())
        } else {
            Err(format!("unexpected arguments: {}", self.values.join(" ")).into())
        }
    }

    fn finish_redacted(self) -> Result<(), Box<dyn std::error::Error>> {
        if self.values.is_empty() {
            Ok(())
        } else {
            Err("unexpected, duplicate, or valueless node argument".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs::{self, OpenOptions},
        io,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

    struct TestFile(PathBuf);

    impl TestFile {
        fn new(label: &str) -> Self {
            let sequence = NEXT_PATH.fetch_add(1, Ordering::Relaxed);
            Self(env::temp_dir().join(format!(
                "aster-node-main-{}-{sequence}-{label}",
                std::process::id()
            )))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    #[test]
    fn exact_put_limit_is_accepted() {
        let source = TestFile::new("exact-limit");
        fs::write(
            source.path(),
            vec![0x5a; usize::try_from(MAX_PUT_BYTES).expect("limit")],
        )
        .expect("write source");

        let bytes = read_put_source(source.path()).expect("read exact-limit source");
        assert_eq!(bytes.len(), usize::try_from(MAX_PUT_BYTES).expect("limit"));
        assert!(bytes.iter().all(|byte| *byte == 0x5a));
    }

    #[test]
    fn regular_file_is_rejected_from_metadata_before_payload_allocation() {
        let source = TestFile::new("oversized-sparse");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(source.path())
            .expect("create source");
        file.set_len(MAX_PUT_BYTES + 1).expect("set sparse length");

        let error = read_put_source(source.path()).expect_err("reject oversized source");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("1048576-byte limit"));
    }

    #[test]
    fn stream_without_eof_is_stopped_at_one_byte_over_limit() {
        let error = read_bounded(io::repeat(0xa5), 0).expect_err("reject endless stream");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("1048576-byte limit"));
    }

    #[test]
    fn stale_small_metadata_hint_cannot_bypass_the_read_limit() {
        let input = vec![0x33; usize::try_from(MAX_PUT_BYTES + 1).expect("limit plus one")];
        let error = read_bounded(io::Cursor::new(input), 1).expect_err("reject grown input");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn non_regular_put_source_is_rejected() {
        let source = TestFile::new("directory");
        fs::create_dir(source.path()).expect("create source directory");
        let error = read_put_source(source.path()).expect_err("reject directory source");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::IsADirectory
        ));
        fs::remove_dir(source.path()).expect("remove source directory");
    }

    #[test]
    fn mutable_interest_requires_one_exact_topic_scope_pair() {
        let selector = parse_source_interest("sensors@mission/alpha", "State")
            .expect("parse exact State interest");
        assert_eq!(selector.topic().as_str(), "sensors");
        assert_eq!(selector.scope().as_str(), "mission/alpha");
        assert!(!selector.include_descendant_scopes());

        assert!(parse_source_interest("sensors", "Record").is_err());
        assert!(parse_source_interest("sensors@mission@alpha", "Record").is_err());
    }

    #[test]
    fn help_advertises_opt_in_semantic_v5_blob_reconciliation() {
        let source = include_str!("main.rs");
        assert!(source.contains("[--blob-interest TOPIC@SCOPE ...]"));
        assert!(source.contains("Blob source and resumable carrier phases require semantic v5."));
    }

    #[test]
    fn controlled_relay_flags_are_inseparable_and_trust_is_explicit() {
        let error = parse_controlled_relay(None, Some("webpki".into()), Vec::new(), false)
            .expect_err("relay trust without URL must fail");
        assert!(error.to_string().contains("--controlled-relay-url"));

        let error = parse_controlled_relay(
            Some("https://relay.example.invalid".into()),
            None,
            Vec::new(),
            false,
        )
        .expect_err("relay URL without trust must fail");
        assert!(error.to_string().contains("--controlled-relay-trust"));

        let error = parse_controlled_relay(
            Some("https://relay.example.invalid".into()),
            Some("webpki".into()),
            vec![PathBuf::from("must-not-be-read.der")],
            false,
        )
        .expect_err("WebPKI plus explicit roots is ambiguous");
        assert!(error.to_string().contains("incompatible"));

        let secret = "trust-secret-must-not-appear";
        let error = parse_controlled_relay(
            Some("https://relay.example.invalid".into()),
            Some(secret.into()),
            Vec::new(),
            false,
        )
        .expect_err("unknown relay trust mode must fail without echoing its value");
        assert!(error.to_string().contains("webpki or der-roots"));
        assert!(!error.to_string().contains(secret));

        let oversized_secret = "oversized-secret-must-not-appear";
        let oversized_url = oversized_secret.repeat(
            MAX_RELAY_URL_BYTES
                .checked_div(oversized_secret.len())
                .expect("nonempty secret")
                + 1,
        );
        let error = parse_controlled_relay(
            Some(oversized_url),
            Some("webpki".into()),
            Vec::new(),
            false,
        )
        .expect_err("oversized relay URL must fail before URL parsing");
        assert!(error.to_string().contains("controlled relay URL exceeds"));
        assert!(!error.to_string().contains(oversized_secret));

        let (relay, relay_only) = parse_controlled_relay(
            Some("https://relay.example.invalid".into()),
            Some("webpki".into()),
            Vec::new(),
            true,
        )
        .expect("valid bounded WebPKI relay")
        .expect("configured relay");
        assert!(relay.ca_roots_der().is_empty());
        assert!(relay_only);
    }

    #[test]
    fn relay_only_switch_rejects_duplicate_ambiguity() {
        let mut arguments = Arguments::new(
            ["--controlled-relay-only", "--controlled-relay-only"]
                .into_iter()
                .map(str::to_owned),
        );
        let error = arguments
            .switch("--controlled-relay-only")
            .expect_err("duplicate switch must fail");
        assert!(error.to_string().contains("at most once"));
    }

    #[test]
    fn controlled_relay_value_duplicates_are_rejected_without_echoing_values() {
        let secret = "https://user:do-not-log@relay.invalid/?token=do-not-log";
        let mut arguments = Arguments::new(
            [
                "--controlled-relay-url",
                "https://relay.example.invalid",
                "--controlled-relay-url",
                secret,
            ]
            .into_iter()
            .map(str::to_owned),
        );
        let error = arguments
            .optional_once("--controlled-relay-url")
            .expect_err("duplicate relay URL must fail");
        assert!(error.to_string().contains("at most once"));
        assert!(!error.to_string().contains("do-not-log"));

        let error = Arguments::new([secret.to_owned()].into_iter())
            .finish_redacted()
            .expect_err("unexpected node argument must be redacted");
        assert!(!error.to_string().contains("do-not-log"));
    }

    #[test]
    fn help_advertises_bounded_controlled_relay_without_authority_claims() {
        let source = include_str!("main.rs");
        assert!(source.contains("--controlled-relay-trust webpki|der-roots"));
        assert!(source.contains("[--controlled-relay-ca-der FILE ...]"));
        assert!(source.contains("operator-supplied initial route set is bounded"));
        assert!(source.contains("authenticated Iroh NAT negotiation may add direct paths"));
        assert!(source.contains("NAT acceptance remains explicitly unclaimed"));
    }

    #[cfg(unix)]
    #[test]
    fn symbolic_link_put_source_is_rejected_before_open() {
        use std::os::unix::fs::symlink;

        let target = TestFile::new("symlink-target");
        let source = TestFile::new("symlink-source");
        fs::write(target.path(), b"payload").expect("write target");
        symlink(target.path(), source.path()).expect("create source symlink");
        let error = read_put_source(source.path()).expect_err("reject symlink source");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}
