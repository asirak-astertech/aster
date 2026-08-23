#![forbid(unsafe_code)]

use aster_lab::LabResult;
use aster_lab::mesh_experiment::{
    MeshPrepareConfig, NativeMeshNodeConfig, consume_and_ack_ip_mesh, prepare_ip_mesh,
    run_native_mesh_node, verify_ip_mesh_duplicate_suppression, verify_ip_mesh_relay_custody,
};
use aster_mesh::{NodeId, Scope, Topic};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::error::Error;
use std::ffi::OsString;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("aster-gate-h: {error}");
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
    if !known_command(&command) {
        return Err(invalid(format!(
            "command {command} is unavailable in the Gate-H profile"
        )));
    }
    let options = Options::parse(arguments.collect())?;
    options.reject_unknown(&command)?;
    match command.as_str() {
        "mesh-native-node" => run_native_node(&options)?,
        "mesh-prepare" => run_prepare(&options)?,
        "mesh-verify-relay" => run_verify_relay(&options)?,
        "mesh-consume" => run_consume(&options)?,
        "mesh-verify-duplicate" => run_verify_duplicate(&options)?,
        _ => unreachable!("known_command accepted an unavailable command"),
    }
    Ok(())
}

fn print_help() {
    println!(
        "Aster formal Gate-H native mesh laboratory\n\n\
         Commands: mesh-prepare, mesh-native-node, mesh-verify-relay, \
         mesh-consume, mesh-verify-duplicate"
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

    fn required_text(&self, name: &str) -> LabResult<&str> {
        self.0
            .get(name)
            .map(String::as_str)
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
        "mesh-native-node"
            | "mesh-prepare"
            | "mesh-verify-relay"
            | "mesh-consume"
            | "mesh-verify-duplicate"
    )
}

fn option_is_allowed(command: &str, name: &str) -> bool {
    match command {
        "mesh-native-node" => [
            "root",
            "bundle",
            "invocation",
            "topic",
            "scope",
            "duration-ms",
            "bind",
            "discovery-target",
            "discovery-token",
            "max-candidates",
            "max-active-contacts",
            "expected-peers",
            "discovery-enabled",
            "manual-peers",
            "emission-mode",
            "gate-h-control",
            "gate-h-stale-target-peer",
            "durable-item-probe",
        ]
        .contains(&name),
        "mesh-prepare" => ["root", "seed", "payload-bytes"].contains(&name),
        "mesh-verify-relay" | "mesh-consume" | "mesh-verify-duplicate" => {
            ["root", "invocation"].contains(&name)
        }
        _ => false,
    }
}

fn run_native_node(options: &Options) -> LabResult<()> {
    let expected_peers = options
        .text("expected-peers", "")
        .split(',')
        .filter(|value| !value.is_empty())
        .map(parse_node_id)
        .collect::<LabResult<BTreeSet<_>>>()?;
    let discovery_enabled = match options.text("discovery-enabled", "true").as_str() {
        "true" => true,
        "false" => false,
        _ => return Err(invalid("--discovery-enabled must be true or false")),
    };
    let config = NativeMeshNodeConfig {
        invocation: options.required_text("invocation")?.to_owned(),
        root: options.required_path("root")?,
        credential_path: options.required_path("bundle")?,
        topic: Topic::new(options.text("topic", "lab.ip-mesh.commands"))?,
        scope: Scope::new(options.text("scope", "lab/ip-mesh"))?,
        discovery_token: read_private_hex::<16>(&options.required_path("discovery-token")?)?,
        bind: options
            .text("bind", "0.0.0.0:47101")
            .parse()
            .map_err(|error| invalid(format!("invalid --bind: {error}")))?,
        discovery_target: options
            .required_text("discovery-target")?
            .parse::<SocketAddr>()
            .map_err(|error| invalid(format!("invalid --discovery-target: {error}")))?,
        max_candidates: options.number("max-candidates", 128_usize)?,
        max_active_contacts: options.number("max-active-contacts", 8_usize)?,
        run_for: Duration::from_millis(options.number("duration-ms", 60_000_u64)?),
        discovery_enabled,
        expected_peers,
        manual_peers: options.text("manual-peers", ""),
        emission_mode: options.text("emission-mode", "normal"),
        gate_h_control_path: options.0.get("gate-h-control").map(PathBuf::from),
        gate_h_stale_target_peer: options
            .0
            .get("gate-h-stale-target-peer")
            .map(|value| parse_node_id(value))
            .transpose()?,
        durable_item_probe: options
            .0
            .get("durable-item-probe")
            .map(|value| parse_node_id(value))
            .transpose()?,
    };
    println!("{}", run_native_mesh_node(&config)?.to_json());
    Ok(())
}

fn run_prepare(options: &Options) -> LabResult<()> {
    let receipt = prepare_ip_mesh(&MeshPrepareConfig {
        root: options.required_path("root")?,
        seed: options.number("seed", 1_u64)?,
        payload_bytes: options.number("payload-bytes", 1_024_usize)?,
    })?;
    println!("{}", receipt.to_json());
    Ok(())
}

fn run_verify_relay(options: &Options) -> LabResult<()> {
    let receipt = verify_ip_mesh_relay_custody(
        &options.required_path("root")?,
        options.required_text("invocation")?,
    )?;
    println!("{}", receipt.to_json());
    Ok(())
}

fn run_consume(options: &Options) -> LabResult<()> {
    let receipt = consume_and_ack_ip_mesh(
        &options.required_path("root")?,
        options.required_text("invocation")?,
    )?;
    println!("{}", receipt.to_json());
    Ok(())
}

fn run_verify_duplicate(options: &Options) -> LabResult<()> {
    verify_ip_mesh_duplicate_suppression(
        &options.required_path("root")?,
        options.required_text("invocation")?,
    )?;
    println!("{{\"duplicate_suppression\":true}}");
    Ok(())
}

fn parse_node_id(value: &str) -> LabResult<NodeId> {
    parse_hex_array::<32>(value, "node ID")
}

fn read_private_hex<const N: usize>(path: &PathBuf) -> LabResult<[u8; N]> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > 4_096 {
        return Err(invalid("private hex input must be a bounded regular file"));
    }
    let value = fs::read_to_string(path)?;
    parse_hex_array::<N>(value.trim(), "private hex input")
}

fn parse_hex_array<const N: usize>(value: &str, kind: &str) -> LabResult<[u8; N]> {
    if value.len() != N.saturating_mul(2) {
        return Err(invalid(format!(
            "{kind} must contain exactly {} hex digits",
            N.saturating_mul(2)
        )));
    }
    let mut bytes = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair)?;
        bytes[index] = u8::from_str_radix(pair, 16)
            .map_err(|error| invalid(format!("invalid {kind}: {error}")))?;
    }
    Ok(bytes)
}

fn invalid(message: impl Into<String>) -> Box<dyn Error + Send + Sync> {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message.into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_h_profile_exposes_only_native_shared_node_commands() {
        for command in [
            "mesh-native-node",
            "mesh-prepare",
            "mesh-verify-relay",
            "mesh-consume",
            "mesh-verify-duplicate",
        ] {
            assert!(known_command(command));
        }
        for legacy in ["transfer", "node-udp", "route-only-event", "blob-recovery"] {
            assert!(!known_command(legacy));
        }
    }

    #[test]
    fn gate_h_profile_rejects_legacy_and_unlisted_options() {
        assert!(!option_is_allowed("mesh-native-node", "peer-address"));
        assert!(!option_is_allowed("transfer", "root"));
        assert!(option_is_allowed("mesh-native-node", "gate-h-control"));
    }
}
