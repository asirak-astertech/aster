// Copyright 2026 Defense Unicorns, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Dedicated, bounded alpha -> parent -> bravo hierarchy MVP process.
//!
//! This binary is intentionally not a general operator surface. `init` creates
//! one shared set of demo-only unprotected reference artifacts across five
//! mounted state roots. `run` starts exactly one fixed role, optionally enables
//! rosterless nearby discovery, and lets the selected node runtime carry the
//! opaque bridge frames. The publisher role creates three fixed Events and
//! emits hashes, never payload plaintext.

use std::{
    error::Error,
    fs::{self, File, OpenOptions},
    io::Write as _,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr as _,
    time::Duration,
};

use aster_mesh::{
    BridgeAuthorizationLink, Priority, ProvisioningAccess, ReferenceEnvelopeSealer,
    ReferenceProvisioner, Scope, SelectedBridgeAuthorizationPolicy, SelectedBridgeNarrowingPolicy,
    SelectedEventBridgeAdapter, Topic,
};
use aster_node::application::EventPublishRequest;
use aster_node::bridge_runtime::{SelectedEventBridgeConfig, SelectedEventBridgeEdge};
use aster_node::mission::UnprotectedReferenceMission;
use aster_node::{
    EventEmissionPolicy, NodeApplication, NodeConfig, SelectedForwardingConfig, StoreLimits,
    format_node_id, format_receipt_field, start_node_with_forwarding,
};
use sha2::{Digest as _, Sha256};

const ROLES: [&str; 5] = [
    "publisher",
    "bridge-alpha",
    "bridge-bravo",
    "consumer",
    "outsider",
];
const MISSION_FILE: &str = "mission.unprotected-reference.bundle";
const FIRST_AUTHORIZATION_FILE: &str = "bridge-authorization-1.bin";
const SECOND_AUTHORIZATION_FILE: &str = "bridge-authorization-2.bin";
const COMPLETE_FILE: &str = ".hierarchy-provisioned-v1";
const ALPHA_SCOPE: &str = "demo/alpha";
const PARENT_SCOPE: &str = "demo/parent";
const BRAVO_SCOPE: &str = "demo/bravo";
const ALLOWED_TOPIC: &str = "mesh.allowed";
const DENIED_TOPIC: &str = "mesh.denied";
const ALLOWED_PAYLOAD: &[u8] = b"HIERARCHY_ALLOWED_PAYLOAD_SENTINEL_4f923b";
const DENIED_TOPIC_PAYLOAD: &[u8] = b"HIERARCHY_DENIED_TOPIC_SENTINEL_81f2a0";
const DENIED_PRIORITY_PAYLOAD: &[u8] = b"HIERARCHY_DENIED_PRIORITY_SENTINEL_6d35cc";
const MAX_AUTHORIZATION_FILE_BYTES: u64 = 65_536;
const MAX_DISCOVERY_IPV4_INTERFACES: usize = 8;

type DemoResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Publisher,
    BridgeAlpha,
    BridgeBravo,
    Consumer,
    Outsider,
}

impl Role {
    fn parse(value: &str) -> DemoResult<Self> {
        match value {
            "publisher" => Ok(Self::Publisher),
            "bridge-alpha" => Ok(Self::BridgeAlpha),
            "bridge-bravo" => Ok(Self::BridgeBravo),
            "consumer" => Ok(Self::Consumer),
            "outsider" => Ok(Self::Outsider),
            _ => Err("unknown hierarchy role".into()),
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Publisher => "publisher",
            Self::BridgeAlpha => "bridge-alpha",
            Self::BridgeBravo => "bridge-bravo",
            Self::Consumer => "consumer",
            Self::Outsider => "outsider",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Command {
    Init {
        root: PathBuf,
    },
    Run {
        role: Role,
        state: PathBuf,
        bind: SocketAddr,
        sync: Duration,
        nearby_window: Option<Duration>,
        nearby_ipv4_interfaces: Vec<Ipv4Addr>,
    },
}

#[derive(Clone, Copy)]
struct Fixture {
    case: &'static str,
    topic: &'static str,
    priority: Priority,
    priority_name: &'static str,
    payload: &'static [u8],
}

const FIXTURES: [Fixture; 3] = [
    Fixture {
        case: "allowed",
        topic: ALLOWED_TOPIC,
        priority: Priority::Immediate,
        priority_name: "immediate",
        payload: ALLOWED_PAYLOAD,
    },
    Fixture {
        case: "denied-topic",
        topic: DENIED_TOPIC,
        priority: Priority::Immediate,
        priority_name: "immediate",
        payload: DENIED_TOPIC_PAYLOAD,
    },
    Fixture {
        case: "denied-priority",
        topic: ALLOWED_TOPIC,
        priority: Priority::Routine,
        priority_name: "routine",
        payload: DENIED_PRIORITY_PAYLOAD,
    },
];

#[tokio::main]
async fn main() -> ExitCode {
    match parse_command(std::env::args().skip(1).collect()).and_then(|command| {
        match &command {
            Command::Init { root } => provision(root),
            Command::Run { .. } => Ok(()),
        }
        .map(|()| command)
    }) {
        Ok(Command::Init { .. }) => ExitCode::SUCCESS,
        Ok(command @ Command::Run { .. }) => match run_role(command).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!(
                    "HIERARCHY_DEMO status=error error={}",
                    format_receipt_field(&error.to_string())
                );
                ExitCode::from(2)
            }
        },
        Err(error) => {
            eprintln!(
                "HIERARCHY_DEMO status=error error={}",
                format_receipt_field(&error.to_string())
            );
            ExitCode::from(2)
        }
    }
}

fn parse_command(values: Vec<String>) -> DemoResult<Command> {
    let mut values = values.into_iter();
    match values.next().as_deref() {
        Some("init") => {
            let root = required_option(&mut values, "--root")?;
            reject_remaining(values)?;
            Ok(Command::Init {
                root: PathBuf::from(root),
            })
        }
        Some("run") => {
            let role = Role::parse(&required_option(&mut values, "--role")?)?;
            let state = PathBuf::from(required_option(&mut values, "--state")?);
            let bind = SocketAddr::from_str(&required_option(&mut values, "--bind")?)?;
            let sync_ms = positive_u64(&required_option(&mut values, "--sync-ms")?, "sync-ms")?;
            let remaining = values.collect::<Vec<_>>();
            let (nearby_window, nearby_ipv4_interfaces) = match remaining.as_slice() {
                [] => (None, Vec::new()),
                [discover, window_flag, seconds, interfaces_flag, interfaces]
                    if discover == "--discover-lan"
                        && window_flag == "--nearby-window"
                        && interfaces_flag == "--discovery-ipv4-interfaces" =>
                {
                    (
                        Some(Duration::from_secs(positive_u64(
                            seconds,
                            "nearby-window",
                        )?)),
                        discovery_ipv4_interfaces(interfaces)?,
                    )
                }
                _ => return Err("run accepts only --discover-lan --nearby-window SECONDS --discovery-ipv4-interfaces ADDR[,ADDR] after required options".into()),
            };
            Ok(Command::Run {
                role,
                state,
                bind,
                sync: Duration::from_millis(sync_ms),
                nearby_window,
                nearby_ipv4_interfaces,
            })
        }
        _ => Err("expected init or run command".into()),
    }
}

fn required_option(
    values: &mut impl Iterator<Item = String>,
    expected: &'static str,
) -> DemoResult<String> {
    if values.next().as_deref() != Some(expected) {
        return Err(format!("expected {expected}").into());
    }
    values
        .next()
        .filter(|value| !value.is_empty() && !value.starts_with('-'))
        .ok_or_else(|| format!("{expected} requires a value").into())
}

fn reject_remaining(mut values: impl Iterator<Item = String>) -> DemoResult<()> {
    if values.next().is_some() {
        Err("unexpected trailing arguments".into())
    } else {
        Ok(())
    }
}

fn positive_u64(value: &str, label: &str) -> DemoResult<u64> {
    let value = value.parse::<u64>()?;
    if value == 0 {
        return Err(format!("{label} must be positive").into());
    }
    Ok(value)
}

fn discovery_ipv4_interfaces(value: &str) -> DemoResult<Vec<Ipv4Addr>> {
    let mut interfaces = value
        .split(',')
        .map(|candidate| -> DemoResult<Ipv4Addr> {
            if candidate.is_empty() || candidate.trim() != candidate {
                return Err("discovery IPv4 interfaces must be comma-separated addresses".into());
            }
            Ipv4Addr::from_str(candidate).map_err(Into::into)
        })
        .collect::<DemoResult<Vec<_>>>()?;
    if interfaces.is_empty() || interfaces.len() > MAX_DISCOVERY_IPV4_INTERFACES {
        return Err(format!(
            "discovery IPv4 interface count must be within 1..={MAX_DISCOVERY_IPV4_INTERFACES}"
        )
        .into());
    }
    interfaces.sort_unstable();
    let original_len = interfaces.len();
    interfaces.dedup();
    if interfaces.len() != original_len {
        return Err("discovery IPv4 interfaces must be unique".into());
    }
    Ok(interfaces)
}

fn scope(value: &str) -> DemoResult<Scope> {
    Scope::new(value).map_err(Into::into)
}

fn topic(value: &str) -> DemoResult<Topic> {
    Topic::new(value).map_err(Into::into)
}

fn relay(value: &str, epoch: u64) -> DemoResult<ProvisioningAccess> {
    ProvisioningAccess::relay(scope(value)?, vec![epoch]).map_err(Into::into)
}

fn member(value: &str, epoch: u64, topics: &[&str]) -> DemoResult<ProvisioningAccess> {
    ProvisioningAccess::member(
        scope(value)?,
        vec![epoch],
        topics
            .iter()
            .map(|value| topic(value))
            .collect::<DemoResult<Vec<_>>>()?,
    )
    .map_err(Into::into)
}

fn content_only(value: &str, epoch: u64, topics: &[&str]) -> DemoResult<ProvisioningAccess> {
    ProvisioningAccess::content_only(
        scope(value)?,
        vec![epoch],
        topics
            .iter()
            .map(|value| topic(value))
            .collect::<DemoResult<Vec<_>>>()?,
    )
    .map_err(Into::into)
}

fn provision(root: &Path) -> DemoResult<()> {
    let role_roots = ROLES
        .iter()
        .map(|&role| (role, root.join(role)))
        .collect::<Vec<_>>();
    for (_, path) in &role_roots {
        fs::create_dir_all(path)?;
    }
    if role_roots
        .iter()
        .all(|(_, path)| path.join(COMPLETE_FILE).is_file())
    {
        validate_existing_provisioning(&role_roots)?;
        println!(
            "HIERARCHY_INIT status=pass disposition=existing nodes=5 authorities=2 edges=2 provisioning=unprotected-reference"
        );
        return Ok(());
    }
    if role_roots
        .iter()
        .any(|(_, path)| directory_has_entries(path))
    {
        return Err("hierarchy provisioning roots are partially initialized".into());
    }

    let alpha = relay(ALPHA_SCOPE, 1)?;
    let parent = relay(PARENT_SCOPE, 2)?;
    let bravo = relay(BRAVO_SCOPE, 3)?;
    let topics = [ALLOWED_TOPIC, DENIED_TOPIC];
    let mut provisioner = ReferenceProvisioner::from_seed([0x91; 32])?;

    let authority_bundle =
        provisioner.issue_control_authority(1, &[alpha.clone(), parent.clone(), bravo.clone()])?;
    let mut authority = ReferenceEnvelopeSealer::open(authority_bundle)?;

    let publisher_bundle = provisioner.issue_node(2, &[member(ALPHA_SCOPE, 1, &topics)?])?;
    let publisher_bytes = publisher_bundle.to_bytes()?;

    let first_bridge_bundle = provisioner.issue_node(3, &[alpha.clone(), parent.clone()])?;
    let first_bridge_bytes = first_bridge_bundle.to_bytes()?;
    let first_bridge = ReferenceEnvelopeSealer::open(first_bridge_bundle)?;

    let second_bridge_bundle =
        provisioner.issue_node(4, &[alpha.clone(), parent.clone(), bravo.clone()])?;
    let second_bridge_bytes = second_bridge_bundle.to_bytes()?;
    let second_bridge = ReferenceEnvelopeSealer::open(second_bridge_bundle)?;

    let consumer_bundle = provisioner.issue_node(
        5,
        &[
            member(BRAVO_SCOPE, 3, &topics)?,
            content_only(ALPHA_SCOPE, 1, &topics)?,
        ],
    )?;
    let consumer_bytes = consumer_bundle.to_bytes()?;

    let enrollment_one = SelectedEventBridgeAdapter::create_enrollment(
        &first_bridge,
        &scope(ALPHA_SCOPE)?,
        1,
        &scope(PARENT_SCOPE)?,
        2,
    )?;
    let verified_one = SelectedEventBridgeAdapter::verify_enrollment(&authority, &enrollment_one)?;
    let policy = SelectedBridgeAuthorizationPolicy::new(
        vec![topic(ALLOWED_TOPIC)?],
        vec![Priority::Immediate],
        2,
    )?;
    let authorization_one = SelectedEventBridgeAdapter::issue_authorization(
        &mut authority,
        &verified_one,
        BridgeAuthorizationLink::new(1, None, 1)?,
        &policy,
    )?;
    let enrollment_two = SelectedEventBridgeAdapter::create_enrollment(
        &second_bridge,
        &scope(PARENT_SCOPE)?,
        2,
        &scope(BRAVO_SCOPE)?,
        3,
    )?;
    let verified_two = SelectedEventBridgeAdapter::verify_enrollment(&authority, &enrollment_two)?;
    let authorization_two = SelectedEventBridgeAdapter::issue_authorization(
        &mut authority,
        &verified_two,
        BridgeAuthorizationLink::new(2, Some(authorization_one.envelope_id()), 1)?,
        &policy,
    )?;

    let mut outsider_provisioner = ReferenceProvisioner::from_seed([0xd2; 32])?;
    let outsider_bundle = outsider_provisioner.issue_node(1, &[relay(PARENT_SCOPE, 2)?])?;
    let outsider_bytes = outsider_bundle.to_bytes()?;

    write_owner_only(&root.join("publisher").join(MISSION_FILE), &publisher_bytes)?;
    write_owner_only(
        &root.join("bridge-alpha").join(MISSION_FILE),
        &first_bridge_bytes,
    )?;
    write_owner_only(
        &root.join("bridge-bravo").join(MISSION_FILE),
        &second_bridge_bytes,
    )?;
    write_owner_only(&root.join("consumer").join(MISSION_FILE), &consumer_bytes)?;
    write_owner_only(&root.join("outsider").join(MISSION_FILE), &outsider_bytes)?;
    for role in ["bridge-alpha", "bridge-bravo", "consumer"] {
        write_owner_only(
            &root.join(role).join(FIRST_AUTHORIZATION_FILE),
            authorization_one.exact_bytes(),
        )?;
        write_owner_only(
            &root.join(role).join(SECOND_AUTHORIZATION_FILE),
            authorization_two.exact_bytes(),
        )?;
    }
    for (_, path) in &role_roots {
        write_owner_only(&path.join(COMPLETE_FILE), b"aster-hierarchy-demo/v1\n")?;
        File::open(path)?.sync_all()?;
    }
    println!(
        "HIERARCHY_INIT status=pass disposition=created nodes=5 authorities=2 edges=2 provisioning=unprotected-reference"
    );
    Ok(())
}

fn directory_has_entries(path: &Path) -> bool {
    fs::read_dir(path)
        .ok()
        .and_then(|mut entries| entries.next())
        .is_some()
}

fn validate_existing_provisioning(role_roots: &[(&str, PathBuf)]) -> DemoResult<()> {
    for (role, path) in role_roots {
        if !path.join(MISSION_FILE).is_file() {
            return Err(format!("{role} provisioning is incomplete").into());
        }
        if matches!(*role, "bridge-alpha" | "bridge-bravo" | "consumer")
            && (!path.join(FIRST_AUTHORIZATION_FILE).is_file()
                || !path.join(SECOND_AUTHORIZATION_FILE).is_file())
        {
            return Err(format!("{role} bridge authorization chain is incomplete").into());
        }
    }
    Ok(())
}

fn write_owner_only(path: &Path, bytes: &[u8]) -> DemoResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn load_authorization(path: &Path) -> DemoResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_AUTHORIZATION_FILE_BYTES
    {
        return Err("bridge authorization file is missing or outside its bound".into());
    }
    fs::read(path).map_err(Into::into)
}

fn bridge_config(role: Role, state: &Path) -> DemoResult<Option<SelectedEventBridgeConfig>> {
    if matches!(role, Role::Publisher | Role::Outsider) {
        return Ok(None);
    }
    let first = load_authorization(&state.join(FIRST_AUTHORIZATION_FILE))?;
    let second = load_authorization(&state.join(SECOND_AUTHORIZATION_FILE))?;
    let first_id: [u8; 32] = Sha256::digest(&first).into();
    let second_id: [u8; 32] = Sha256::digest(&second).into();
    let narrowing =
        SelectedBridgeNarrowingPolicy::new(vec![topic(ALLOWED_TOPIC)?], vec![Priority::Immediate])?;
    let edges = match role {
        Role::BridgeAlpha => vec![SelectedEventBridgeEdge::new(first_id, narrowing)],
        Role::BridgeBravo => vec![SelectedEventBridgeEdge::new(second_id, narrowing)],
        Role::Consumer => Vec::new(),
        Role::Publisher | Role::Outsider => unreachable!("non-bridge roles returned above"),
    };
    SelectedEventBridgeConfig::new(vec![first, second], edges, role == Role::Consumer)
        .map(Some)
        .map_err(Into::into)
}

async fn run_role(command: Command) -> DemoResult<()> {
    let Command::Run {
        role,
        state,
        bind,
        sync,
        nearby_window,
        nearby_ipv4_interfaces,
    } = command
    else {
        return Err("run_role received an initializer command".into());
    };
    if !state.join(COMPLETE_FILE).is_file() {
        return Err("hierarchy state is not initialized".into());
    }
    let mission = UnprotectedReferenceMission::load(state.join(MISSION_FILE))?;
    let mission_id = mission.identity();
    let mission_authority = mission.mission_authority_id();
    let mut config = NodeConfig::new(&state, bind, mission);
    config.sync_interval = sync;
    config.application = NodeApplication::Relay;
    let mut forwarding =
        SelectedForwardingConfig::new(EventEmissionPolicy::Normal, StoreLimits::default());
    if let Some(bridge) = bridge_config(role, &state)? {
        forwarding = forwarding.with_event_bridge(bridge);
    }
    #[cfg(feature = "nearby-discovery")]
    if let Some(window) = nearby_window {
        forwarding = forwarding
            .with_automatic_nearby_discovery_on_ipv4_interfaces(window, nearby_ipv4_interfaces)?;
    }
    #[cfg(not(feature = "nearby-discovery"))]
    if nearby_window.is_some() {
        let _ = nearby_ipv4_interfaces;
        return Err("nearby discovery support is not compiled".into());
    }

    let running = start_node_with_forwarding(config, forwarding).await?;
    println!(
        "HIERARCHY_READY status=started role={} mission_id={} mission_authority={} nearby_discovery={}",
        role.name(),
        format_node_id(mission_id),
        format_node_id(mission_authority),
        if nearby_window.is_some() {
            "active-evaluation"
        } else {
            "disabled"
        },
    );
    if role == Role::Publisher {
        publish_fixtures(&running.selected_events()).await?;
    }
    running.wait().await?;
    Ok(())
}

async fn publish_fixtures(events: &aster_node::application::SelectedEventHandle) -> DemoResult<()> {
    for fixture in FIXTURES {
        let published = events
            .publish(EventPublishRequest {
                operation_key: format!("hierarchy/publish/{}", fixture.case).into_bytes(),
                predecessor: None,
                topic: topic(fixture.topic)?,
                scope: scope(ALPHA_SCOPE)?,
                priority: fixture.priority,
                logical_key: format!("hierarchy/{}", fixture.case).into_bytes(),
                payload: fixture.payload.to_vec(),
                tombstone: false,
            })
            .await?;
        println!(
            "BRIDGE_SOURCE status=published case={} source_id={} topic={} priority={} payload_sha256={}",
            fixture.case,
            published.id,
            fixture.topic,
            fixture.priority_name,
            format_node_id(Sha256::digest(fixture.payload).into()),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_keeps_init_and_run_modes_bounded() {
        assert_eq!(
            parse_command(vec!["init".into(), "--root".into(), "/tmp/x".into()]).expect("init"),
            Command::Init {
                root: PathBuf::from("/tmp/x")
            }
        );
        let run = parse_command(vec![
            "run".into(),
            "--role".into(),
            "consumer".into(),
            "--state".into(),
            "/tmp/x".into(),
            "--bind".into(),
            "0.0.0.0:4433".into(),
            "--sync-ms".into(),
            "500".into(),
            "--discover-lan".into(),
            "--nearby-window".into(),
            "3".into(),
            "--discovery-ipv4-interfaces".into(),
            "172.30.252.11,172.30.251.11".into(),
        ])
        .expect("run");
        assert!(matches!(
            run,
            Command::Run {
                role: Role::Consumer,
                nearby_window: Some(_),
                ref nearby_ipv4_interfaces,
                ..
            } if nearby_ipv4_interfaces == &[
                Ipv4Addr::new(172, 30, 251, 11),
                Ipv4Addr::new(172, 30, 252, 11),
            ]
        ));
        assert!(
            parse_command(vec![
                "run".into(),
                "--role".into(),
                "consumer".into(),
                "--state".into(),
                "/tmp/x".into(),
                "--bind".into(),
                "0.0.0.0:4433".into(),
                "--sync-ms".into(),
                "500".into(),
                "--discover-lan".into(),
                "--nearby-window".into(),
                "3".into(),
            ])
            .is_err()
        );
        assert!(parse_command(vec!["run".into(), "--role".into()]).is_err());
    }
}
