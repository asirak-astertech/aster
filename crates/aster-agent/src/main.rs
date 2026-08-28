use std::{env, net::SocketAddr, path::PathBuf, process::ExitCode, time::Duration};

use aster_agent::{BoundAgent, ClientToken};
use aster_node::application::{Scope, Topic};
use aster_node::mission::UnprotectedReferenceMission;
use aster_node::{
    MissionExpectedPeer, MutableSourceInterests, NodeApplication, NodeConfig,
    SourceInterestSelector, ensure_state_accepts_normal_operation, format_path_field, start_node,
};
#[cfg(feature = "nearby-discovery")]
use aster_node::{MissionNearbyPeer, SelectedForwardingConfig, start_node_with_forwarding};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

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
            eprintln!("ERROR {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), BoxError> {
    let mut arguments = Arguments::new(env::args().skip(1));
    if arguments.take_flag("--help") || arguments.take_flag("-h") {
        print_help();
        return Ok(());
    }

    let state = arguments.required_path("--state")?;
    let mesh_bind: SocketAddr = arguments.required("--mesh-bind")?.parse()?;
    let listen: SocketAddr = arguments
        .optional("--listen")?
        .unwrap_or_else(|| "127.0.0.1:8181".to_owned())
        .parse()?;
    let mission_bundle = arguments.required_path("--mission-bundle-unprotected-reference")?;
    let client_token_file = arguments.required_path("--client-token-file")?;
    let peers = arguments
        .repeated("--peer")?
        .into_iter()
        .map(|peer| peer.parse::<MissionExpectedPeer>())
        .collect::<Result<Vec<_>, _>>()?;
    #[cfg(feature = "nearby-discovery")]
    let nearby_peers = arguments
        .repeated("--nearby-peer")?
        .into_iter()
        .map(|peer| peer.parse::<MissionNearbyPeer>())
        .collect::<Result<Vec<_>, _>>()?;
    #[cfg(feature = "nearby-discovery")]
    let nearby_window = arguments
        .optional("--nearby-window")?
        .map(|seconds| seconds.parse::<u64>())
        .transpose()?;
    let state_interests = arguments
        .repeated("--state-interest")?
        .into_iter()
        .map(|value| parse_source_interest(&value, "State"))
        .collect::<Result<Vec<_>, _>>()?;
    let record_interests = arguments
        .repeated("--record-interest")?
        .into_iter()
        .map(|value| parse_source_interest(&value, "Record"))
        .collect::<Result<Vec<_>, _>>()?;
    let sync_interval = Duration::from_millis(
        arguments
            .optional("--sync-ms")?
            .map_or(Ok(500_u64), |value| value.parse())?,
    );
    arguments.finish()?;

    ensure_state_accepts_normal_operation(&state)?;
    let agent = BoundAgent::bind(listen).await?;
    let listen = agent.local_addr()?;
    let client_token = ClientToken::load(&client_token_file)?;
    let mission = UnprotectedReferenceMission::load(&mission_bundle)?;
    let config = NodeConfig {
        state: state.clone(),
        bind: mesh_bind,
        mission,
        peers,
        mutable_interests: MutableSourceInterests::new(state_interests, record_interests),
        sync_interval,
        run_for: None,
        application: NodeApplication::Relay,
    };
    #[cfg(feature = "nearby-discovery")]
    let node = if nearby_peers.is_empty() {
        if nearby_window.is_some() {
            return Err("--nearby-window requires at least one --nearby-peer".into());
        }
        start_node(config).await?
    } else {
        let forwarding = SelectedForwardingConfig::default().with_nearby_discovery(
            nearby_peers,
            Duration::from_secs(nearby_window.unwrap_or(10)),
        )?;
        start_node_with_forwarding(config, forwarding).await?
    };
    #[cfg(not(feature = "nearby-discovery"))]
    let node = start_node(config).await?;
    let events = node.selected_events();

    println!(
        "AGENT status=ready listen=http://{listen} mesh_bind={mesh_bind} state={} protocol=connect+grpc+grpc-web api=aster.application.v1alpha1 event_live=true state_live=false record_live=false plaintext=loopback-only",
        format_path_field(&state),
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let signal = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = shutdown_tx.send(true);
    });
    let server_result = agent.serve(events, client_token, shutdown_rx).await;
    signal.abort();
    let node_result = node.shutdown().await;
    server_result?;
    node_result?;
    Ok(())
}

fn parse_source_interest(value: &str, class: &str) -> Result<SourceInterestSelector, BoxError> {
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
        r#"Aster process-local ConnectRPC agent

Usage:
  aster-agent --state DIR --mesh-bind IP:PORT \
    --mission-bundle-unprotected-reference FILE \
    --client-token-file FILE \
    [--listen 127.0.0.1:8181] \
    [--peer CARRIER_ID@IP:PORT=MISSION_NODE_ID_HEX64 ...] \
    [--nearby-peer CARRIER_ID=MISSION_NODE_ID_HEX64 ...] \
    [--nearby-window SECONDS] \
    [--state-interest TOPIC@SCOPE ...] \
    [--record-interest TOPIC@SCOPE ...] [--sync-ms N]

The plaintext application listener is restricted to loopback and every RPC
requires an owner-provisioned bearer token from an owner-only regular file.
This makes the deployment unit suitable for a same-host process or Kubernetes
sidecar, not a remotely exposed service. State and Record interests configure
mesh carriage; their live application RPCs remain unavailable until
handle-backed APIs exist. The explicitly named unprotected-reference mission
bundle is non-production provisioning and must remain owner-only on supported
Unix platforms. Nearby flags are available only in explicitly discovery-enabled
demo/evaluation builds; they publish carrier identity and direct address hints
for a bounded window, never mission or application metadata."#
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

    fn take_flag(&mut self, flag: &str) -> bool {
        let Some(index) = self.values.iter().position(|value| value == flag) else {
            return false;
        };
        self.values.remove(index);
        true
    }

    fn required(&mut self, flag: &str) -> Result<String, BoxError> {
        self.optional(flag)?
            .ok_or_else(|| format!("missing required {flag}").into())
    }

    fn required_path(&mut self, flag: &str) -> Result<PathBuf, BoxError> {
        self.required(flag).map(PathBuf::from)
    }

    fn optional(&mut self, flag: &str) -> Result<Option<String>, BoxError> {
        let Some(index) = self.values.iter().position(|value| value == flag) else {
            return Ok(None);
        };
        if index + 1 >= self.values.len() || self.values[index + 1].starts_with("--") {
            return Err(format!("{flag} requires a value").into());
        }
        self.values.remove(index);
        Ok(Some(self.values.remove(index)))
    }

    fn repeated(&mut self, flag: &str) -> Result<Vec<String>, BoxError> {
        let mut output = Vec::new();
        while let Some(value) = self.optional(flag)? {
            output.push(value);
        }
        Ok(output)
    }

    fn finish(self) -> Result<(), BoxError> {
        if self.values.is_empty() {
            Ok(())
        } else {
            Err(format!("unexpected arguments: {}", self.values.join(" ")).into())
        }
    }
}
