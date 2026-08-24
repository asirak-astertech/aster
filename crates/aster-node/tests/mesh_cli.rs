use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aster_mesh::{ProvisioningAccess, ReferenceEnvelopeSealer, ReferenceProvisioner, Scope, Topic};
#[cfg(unix)]
use aster_node::{NodeIdentity, mission::UnprotectedReferenceMission};
#[cfg(unix)]
use aster_redb_store::{Store, ZeroizationIntent};

static ROOT_SEQUENCE: AtomicU64 = AtomicU64::new(0);
// Auto-selected UDP blocks are intentionally released before the real child
// binds them. Serialize this binary's process tests so parallel harness workers
// cannot select overlapping blocks and authenticate the wrong test mission.
static PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

fn serialize_process_test() -> MutexGuard<'static, ()> {
    PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn fresh_root(test: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let sequence = ROOT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "aster-selected-mesh-smoke-{test}-{}-{nonce}-{sequence}",
        std::process::id(),
    ))
}

fn receipt_counter(line: &str, field: &str) -> Option<usize> {
    let prefix = format!("{field}=");
    line.split_ascii_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))?
        .parse()
        .ok()
}

fn assert_exact_event_edge(root: &std::path::Path, phase: &str, source: usize, destination: usize) {
    let source_log = std::fs::read_to_string(root.join(format!("logs/{phase}-node-{source}.log")))
        .expect("exact Event source log");
    let destination_log =
        std::fs::read_to_string(root.join(format!("logs/{phase}-node-{destination}.log")))
            .expect("exact Event destination log");
    let controls_are_zero = |line: &str| {
        [
            "control_offered",
            "control_fetched",
            "control_retained",
            "control_duplicates",
            "control_activated",
            "control_remaining",
        ]
        .into_iter()
        .all(|field| receipt_counter(line, field) == Some(0))
    };
    assert!(source_log.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.ends_with("status=pass")
            && controls_are_zero(line)
            && receipt_counter(line, "offered") == Some(1)
            && receipt_counter(line, "fetched") == Some(0)
            && receipt_counter(line, "inserted") == Some(0)
            && receipt_counter(line, "duplicates") == Some(0)
            && receipt_counter(line, "remaining") == Some(0)
    }));
    assert!(destination_log.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.ends_with("status=pass")
            && controls_are_zero(line)
            && receipt_counter(line, "offered") == Some(0)
            && receipt_counter(line, "fetched") == Some(1)
            && receipt_counter(line, "inserted") == Some(1)
            && receipt_counter(line, "duplicates") == Some(0)
            && receipt_counter(line, "remaining") == Some(0)
    }));
    assert!(
        !source_log
            .lines()
            .chain(destination_log.lines())
            .any(|line| line.starts_with("APPLICATION "))
    );
}

fn assert_peerless_application(
    root: &std::path::Path,
    phase: &str,
    node: usize,
    application: &str,
    kind: &str,
) {
    let log = std::fs::read_to_string(root.join(format!("logs/{phase}-node-{node}.log")))
        .expect("peerless application log");
    assert!(log.lines().any(|line| {
        line.starts_with("READY ")
            && line.contains(" peers=0 ")
            && line.contains(&format!(" application={application} "))
    }));
    assert!(log.contains(&format!("APPLICATION status=emitted kind={kind} ")));
    assert!(log.lines().any(|line| {
        line.starts_with("STOP ")
            && line.contains(" sync_status=no_successful_contact ")
            && line.contains(" contacts=0 ")
    }));
    assert!(!log.lines().any(|line| line.starts_with("CONTACT ")));
}

fn assert_default_noop_node(root: &std::path::Path, node: usize, endpoint: bool) {
    let noop = std::fs::read_to_string(root.join(format!("logs/noop-node-{node}.log")))
        .expect("equal-inventory no-op log");
    let passing_contacts = noop
        .lines()
        .filter(|line| line.starts_with("CONTACT ") && line.ends_with("status=pass"))
        .collect::<Vec<_>>();
    assert!(!passing_contacts.is_empty());
    assert!(passing_contacts.iter().all(|line| {
        [
            " control_offered=0 ",
            " control_fetched=0 ",
            " control_retained=0 ",
            " control_duplicates=0 ",
            " control_activated=0 ",
            " control_remaining=0 ",
            " offered=0 ",
            " fetched=0 ",
            " inserted=0 ",
            " duplicates=0 ",
            " remaining=0 ",
        ]
        .into_iter()
        .all(|field| line.contains(field))
    }));
    let stop = noop
        .lines()
        .find(|line| line.starts_with("STOP "))
        .expect("equal-inventory no-op STOP receipt");
    assert!(stop.contains(" controls=0 "));
    assert!(stop.contains(" applied_controls=0 "));
    assert!(stop.contains(" pending_controls=0 "));
    assert!(stop.contains(" control_highwater=0 "));
    if endpoint {
        assert!(stop.contains(" events=2 "));
        assert!(stop.contains(" route_cached_events=0 "));
    } else {
        assert!(stop.contains(" events=0 "));
        assert!(stop.contains(" route_cached_events=2 "));
    }
}

fn persist_zeroization_bundle(path: &std::path::Path, seed: u8) -> Vec<u8> {
    let scope = Scope::new("test/process-zeroization").expect("scope");
    let topic = Topic::new("zeroization-event").expect("topic");
    let access = ProvisioningAccess::member(scope, vec![1], vec![topic]).expect("access");
    let mut provisioner =
        ReferenceProvisioner::from_seed([seed; 32]).expect("zeroization provisioner");
    let bytes = provisioner
        .issue_node(1, &[access])
        .expect("zeroization bundle")
        .to_bytes()
        .expect("encode zeroization bundle");
    std::fs::write(path, &bytes).expect("write zeroization bundle");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only mission permissions");
    }
    bytes
}

fn bytes_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn wait_for_ready(child: &mut std::process::Child, lines: &mpsc::Receiver<String>) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(line) = lines.recv_timeout(Duration::from_millis(100))
            && line.starts_with("READY selected=true ")
        {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll live node") {
            panic!("node exited before READY with {status}");
        }
    }
    panic!("live node did not emit READY before deadline");
}

fn wait_for_protected_contact(
    child: &mut std::process::Child,
    lines: &mpsc::Receiver<String>,
    expected_prefix: &str,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if let Ok(line) = lines.recv_timeout(Duration::from_millis(100))
            && line.starts_with(expected_prefix)
            && line.ends_with("status=pass")
            && line.contains(" mission_auth=hybrid-pq ")
            && receipt_counter(&line, "handshake_frames") == Some(4)
            && receipt_counter(&line, "handshake_bytes").is_some_and(|bytes| bytes > 0)
            && receipt_counter(&line, "protected_frames").is_some_and(|frames| frames > 0)
            && receipt_counter(&line, "protected_bytes").is_some_and(|bytes| bytes > 0)
        {
            return line;
        }
        if let Some(status) = child.try_wait().expect("poll contact node") {
            panic!("node exited before protected contact with {status}");
        }
    }
    panic!("node did not emit a completed hybrid/protected contact before deadline");
}

#[test]
fn manual_node_requires_explicit_unprotected_reference_mission_bundle_before_state() {
    let _process_test = serialize_process_test();
    let state = fresh_root("missing-mission");
    let output = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args([
            "node",
            "--state",
            state.to_str().expect("UTF-8 state"),
            "--bind",
            "127.0.0.1:0",
            "--run-for",
            "1",
        ])
        .output()
        .expect("run node without mission provisioning");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(
        stderr.contains("ERROR error=")
            && stderr.contains("--mission-bundle-unprotected-reference"),
        "unexpected rejection: {stderr}"
    );
    assert!(
        !state.exists(),
        "missing mission provisioning created node state at {}",
        state.display()
    );
}

#[test]
fn live_node_excludes_a_second_authority_process_on_the_exact_store_path() {
    let _process_test = serialize_process_test();
    let root = fresh_root("cross-process-store-lock");
    let state = root.join("state");
    let mission_path = root.join("authority.bundle");
    std::fs::create_dir_all(&root).expect("test root");
    let scope = Scope::new("test/process-lock").expect("scope");
    let topic = Topic::new("lock-event").expect("topic");
    let access = ProvisioningAccess::member(scope, vec![1], vec![topic]).expect("access");
    let mut provisioner =
        ReferenceProvisioner::from_seed([0xc1; 32]).expect("lock test provisioner");
    let authority_bundle = provisioner
        .issue_control_authority(1, std::slice::from_ref(&access))
        .expect("authority bundle");
    let authority_bytes = authority_bundle
        .to_bytes()
        .expect("encode authority bundle");
    let subject_bundle = provisioner
        .issue_node(2, &[access])
        .expect("subject bundle");
    let subject = ReferenceEnvelopeSealer::open(subject_bundle)
        .expect("subject service")
        .identity();
    std::fs::write(&mission_path, authority_bytes).expect("write authority bundle");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&mission_path, std::fs::Permissions::from_mode(0o600))
            .expect("secure authority bundle permissions");
    }

    let mut node = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "2", "--sync-ms", "100"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn live node");
    let stdout = node.stdout.take().expect("node stdout");
    let (line_sender, line_receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("UTF-8 node output");
            let _ = line_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    let ready_deadline = Instant::now() + Duration::from_secs(10);
    let mut ready = false;
    while Instant::now() < ready_deadline {
        if let Ok(line) = line_receiver.recv_timeout(Duration::from_millis(100))
            && line.starts_with("READY selected=true ")
        {
            ready = true;
            break;
        }
        if let Some(status) = node.try_wait().expect("poll live node") {
            panic!("node exited before READY with {status}");
        }
    }
    assert!(ready, "live node did not emit READY before deadline");

    let competing = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["control-revoke", "--state"])
        .arg(&state)
        .arg("--mission-bundle-unprotected-reference")
        .arg(&mission_path)
        .arg("--subject")
        .arg(aster_node::format_node_id(subject))
        .args(["--generation", "1"])
        .output()
        .expect("run competing authority process");
    assert!(
        !competing.status.success(),
        "second writer unexpectedly opened the live exact store: {}",
        String::from_utf8_lossy(&competing.stdout)
    );
    let competing_error = String::from_utf8(competing.stderr).expect("UTF-8 competing stderr");
    assert!(
        competing_error.contains("already open")
            || competing_error.contains("exclusive")
            || competing_error.contains("lock")
            || competing_error.contains("writable%20owner"),
        "unexpected second-writer rejection: {competing_error}"
    );

    let status = node.wait().expect("wait live node");
    let node_lines = reader.join().expect("join node stdout reader");
    assert!(status.success(), "live node failed: {node_lines:?}");

    // The identical authority operation succeeds once the node releases the
    // OS-backed exact-path writer lock, proving the overlap rejection was the
    // selected state-ownership boundary rather than malformed input.
    let stopped = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["control-revoke", "--state"])
        .arg(&state)
        .arg("--mission-bundle-unprotected-reference")
        .arg(&mission_path)
        .arg("--subject")
        .arg(aster_node::format_node_id(subject))
        .args(["--generation", "1"])
        .output()
        .expect("run stopped-state authority process");
    assert!(
        stopped.status.success(),
        "stopped-state authority failed: {}",
        String::from_utf8_lossy(&stopped.stderr)
    );
    assert!(
        String::from_utf8(stopped.stdout)
            .expect("UTF-8 stopped stdout")
            .contains("emitted_by=authority-process")
    );
    std::fs::remove_dir_all(root).expect("cleanup process-lock root");
}

#[cfg(unix)]
#[test]
fn live_zeroization_drains_node_blocks_restored_credentials_and_preserves_rows() {
    use std::{
        io::Read as _,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };

    let _process_test = serialize_process_test();
    let root = fresh_root("live-zeroization");
    let state = root.join("state");
    let mission_path = root.join("mission.bundle");
    let payload_path = root.join("payload.bin");
    std::fs::create_dir_all(&root).expect("root");
    let mission_bytes = persist_zeroization_bundle(&mission_path, 0xd1);
    std::fs::write(&payload_path, b"preserved-through-zeroization").expect("payload");
    let put = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["put", "--state"])
        .arg(&state)
        .args([
            "--id",
            "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4",
            "--file",
        ])
        .arg(&payload_path)
        .output()
        .expect("put preserved row");
    assert!(
        put.status.success(),
        "put failed: {}",
        String::from_utf8_lossy(&put.stderr)
    );

    let mut node = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "30", "--sync-ms", "100"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn live zeroization node");
    let stdout = node.stdout.take().expect("node stdout");
    let (line_sender, line_receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("UTF-8 node output");
            let _ = line_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    wait_for_ready(&mut node, &line_receiver);
    let identity_path = state.join("identity.key");
    let identity_bytes = std::fs::read(&identity_path).expect("live identity bytes");

    let zeroize = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["zeroize", "--state"])
        .arg(&state)
        .arg("--mission-bundle-unprotected-reference")
        .arg(&mission_path)
        .args(["--wait-seconds", "20"])
        .output()
        .expect("request live zeroization");
    let zeroize_stdout = String::from_utf8(zeroize.stdout).expect("zeroize stdout");
    let zeroize_stderr = String::from_utf8(zeroize.stderr).expect("zeroize stderr");
    assert!(
        zeroize.status.success(),
        "live zeroization failed: stdout={zeroize_stdout} stderr={zeroize_stderr}"
    );
    assert!(zeroize_stdout.contains("ZEROIZE status=pass mode=live state=complete"));
    assert!(zeroize_stdout.contains("data_rows_preserved=true opaque_items=1"));
    assert!(zeroize_stdout.contains(
        "mission_pathname=retained-zero-length carrier_identity_pathname=retained-zero-length"
    ));
    assert!(
        zeroize_stdout.contains("assurance=bounded-software physical_sanitization=not-claimed")
    );

    let node_status = node.wait().expect("wait zeroized node");
    let node_lines = reader.join().expect("join node reader");
    let mut node_stderr = String::new();
    node.stderr
        .take()
        .expect("node stderr")
        .read_to_string(&mut node_stderr)
        .expect("read node stderr");
    assert!(
        node_status.success(),
        "zeroized node failed: {node_lines:?} {node_stderr}"
    );
    assert!(node_lines.iter().any(|line| {
        line.starts_with("STOP lifecycle=zeroized ")
            && line.contains("assurance=bounded-software")
            && line.contains("physical_sanitization=not-claimed")
    }));
    let mission_tombstone = std::fs::symlink_metadata(&mission_path).expect("mission tombstone");
    let identity_tombstone = std::fs::symlink_metadata(&identity_path).expect("identity tombstone");
    assert_eq!(mission_tombstone.len(), 0);
    assert_eq!(identity_tombstone.len(), 0);

    let inspect = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["inspect", "--state"])
        .arg(&state)
        .output()
        .expect("inspect terminal store");
    let inspect_stdout = String::from_utf8(inspect.stdout).expect("inspect stdout");
    assert!(
        inspect.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    assert!(inspect_stdout.contains("zeroization=complete opaque_items=1"));

    // Rewriting the retained tombstones preserves their inode identities.
    // Terminal state still blocks every normal reopen, and idempotent cleanup
    // deliberately neither overwrites nor deletes the externally restored data.
    std::fs::write(&mission_path, &mission_bytes).expect("restore mission tombstone");
    std::fs::set_permissions(&mission_path, std::fs::Permissions::from_mode(0o600))
        .expect("mission replacement mode");
    std::fs::write(&identity_path, &identity_bytes).expect("restore identity tombstone");
    std::fs::set_permissions(&identity_path, std::fs::Permissions::from_mode(0o600))
        .expect("identity replacement mode");
    assert_eq!(
        std::fs::symlink_metadata(&mission_path)
            .expect("restored mission metadata")
            .ino(),
        mission_tombstone.ino()
    );
    assert_eq!(
        std::fs::symlink_metadata(&identity_path)
            .expect("restored identity metadata")
            .ino(),
        identity_tombstone.ino()
    );
    let restart = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "1"])
        .output()
        .expect("attempt terminal restart");
    assert!(!restart.status.success(), "terminal node restarted");
    let restart_error = String::from_utf8(restart.stderr).expect("restart stderr");
    assert!(restart_error.contains("terminally") || restart_error.contains("locked out"));

    let replay = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["zeroize", "--state"])
        .arg(&state)
        .arg("--mission-bundle-unprotected-reference")
        .arg(&mission_path)
        .output()
        .expect("replay zeroization");
    let replay_stdout = String::from_utf8(replay.stdout).expect("replay stdout");
    assert!(
        replay.status.success(),
        "replay failed: {}",
        String::from_utf8_lossy(&replay.stderr)
    );
    assert!(replay_stdout.contains("mode=stopped state=complete"));
    assert!(replay_stdout.contains(
        "mission_pathname=retained-external-change carrier_identity_pathname=retained-external-change"
    ));
    assert_eq!(
        std::fs::read(&mission_path).expect("mission retained"),
        mission_bytes
    );
    assert_eq!(
        std::fs::read(&identity_path).expect("identity retained"),
        identity_bytes
    );

    let combined = format!(
        "{zeroize_stdout}{zeroize_stderr}{}{node_stderr}{restart_error}{replay_stdout}",
        node_lines.join("\n")
    );
    assert!(!combined.contains(&bytes_hex(&mission_bytes)));
    assert!(!combined.contains(&bytes_hex(&identity_bytes)));
    std::fs::remove_dir_all(root).expect("cleanup live zeroization root");
}

#[cfg(unix)]
#[test]
fn live_zeroization_stops_a_configured_protected_edge_and_blocks_recontact() {
    use std::{io::Read as _, net::UdpSocket, os::unix::fs::PermissionsExt as _};

    let _process_test = serialize_process_test();
    let root = fresh_root("configured-contact-zeroization");
    let first_state = root.join("first-state");
    let second_state = root.join("second-state");
    let first_mission_path = root.join("first.bundle");
    let second_mission_path = root.join("second.bundle");
    std::fs::create_dir_all(&first_state).expect("first state");
    std::fs::create_dir_all(&second_state).expect("second state");

    let scope = Scope::new("test/configured-contact-zeroization").expect("scope");
    let topic = Topic::new("configured-contact-zeroization").expect("topic");
    let access = ProvisioningAccess::member(scope, vec![1], vec![topic]).expect("access");
    let mut provisioner = ReferenceProvisioner::from_seed([0xd5; 32]).expect("shared provisioner");
    let first_mission_bytes = provisioner
        .issue_node(1, std::slice::from_ref(&access))
        .expect("first mission")
        .to_bytes()
        .expect("encode first mission");
    let second_mission_bytes = provisioner
        .issue_node(2, std::slice::from_ref(&access))
        .expect("second mission")
        .to_bytes()
        .expect("encode second mission");
    let first_mission = UnprotectedReferenceMission::from_bytes(first_mission_bytes.clone())
        .expect("parse first mission");
    let first_mission_id = first_mission.identity();
    drop(first_mission);
    let second_mission = UnprotectedReferenceMission::from_bytes(second_mission_bytes.clone())
        .expect("parse second mission");
    let second_mission_id = second_mission.identity();
    drop(second_mission);
    std::fs::write(&first_mission_path, &first_mission_bytes).expect("write first mission");
    std::fs::write(&second_mission_path, &second_mission_bytes).expect("write second mission");
    std::fs::set_permissions(&first_mission_path, std::fs::Permissions::from_mode(0o600))
        .expect("first mission permissions");
    std::fs::set_permissions(&second_mission_path, std::fs::Permissions::from_mode(0o600))
        .expect("second mission permissions");

    let first_identity = NodeIdentity::load_or_create(&first_state).expect("first identity");
    let first_carrier = first_identity.id();
    let first_identity_path = first_identity.path().to_path_buf();
    let first_identity_bytes = std::fs::read(&first_identity_path).expect("first identity bytes");
    drop(first_identity);
    let second_identity = NodeIdentity::load_or_create(&second_state).expect("second identity");
    let second_carrier = second_identity.id();
    let second_identity_path = second_identity.path().to_path_buf();
    let second_identity_bytes =
        std::fs::read(&second_identity_path).expect("second identity bytes");
    drop(second_identity);

    let first_port = UdpSocket::bind("127.0.0.1:0").expect("reserve first UDP port");
    let second_port = UdpSocket::bind("127.0.0.1:0").expect("reserve second UDP port");
    let first_address = first_port.local_addr().expect("first address");
    let second_address = second_port.local_addr().expect("second address");

    // The selected runtime initiates only from the lower carrier ID. Make that
    // process the survivor so it can observe target endpoint closure itself.
    let (
        target_state,
        target_mission_path,
        target_mission_bytes,
        target_mission_id,
        target_carrier,
        target_identity_path,
        target_identity_bytes,
        target_address,
        target_port,
        survivor_state,
        survivor_mission_path,
        survivor_mission_id,
        survivor_carrier,
        survivor_address,
        survivor_port,
    ) = if first_carrier > second_carrier {
        (
            first_state,
            first_mission_path,
            first_mission_bytes,
            first_mission_id,
            first_carrier,
            first_identity_path,
            first_identity_bytes,
            first_address,
            first_port,
            second_state,
            second_mission_path,
            second_mission_id,
            second_carrier,
            second_address,
            second_port,
        )
    } else {
        (
            second_state,
            second_mission_path,
            second_mission_bytes,
            second_mission_id,
            second_carrier,
            second_identity_path,
            second_identity_bytes,
            second_address,
            second_port,
            first_state,
            first_mission_path,
            first_mission_id,
            first_carrier,
            first_address,
            first_port,
        )
    };
    assert!(survivor_carrier < target_carrier);
    let target_peer = format!(
        "{survivor_carrier}@{survivor_address}={}",
        aster_node::format_node_id(survivor_mission_id)
    );
    let survivor_peer = format!(
        "{target_carrier}@{target_address}={}",
        aster_node::format_node_id(target_mission_id)
    );

    drop(target_port);
    let mut target = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&target_state)
        .arg("--bind")
        .arg(target_address.to_string())
        .arg("--mission-bundle-unprotected-reference")
        .arg(&target_mission_path)
        .arg("--peer")
        .arg(&target_peer)
        .args(["--sync-ms", "500", "--run-for", "30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn target node");
    let target_stdout = target.stdout.take().expect("target stdout");
    let (target_line_sender, target_line_receiver) = mpsc::channel();
    let target_reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(target_stdout).lines() {
            let line = line.expect("UTF-8 target stdout");
            let _ = target_line_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    let mut target_stderr = target.stderr.take().expect("target stderr");
    let target_error_reader = thread::spawn(move || {
        let mut error = String::new();
        target_stderr
            .read_to_string(&mut error)
            .expect("read target stderr");
        error
    });
    wait_for_ready(&mut target, &target_line_receiver);

    drop(survivor_port);
    let mut survivor = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&survivor_state)
        .arg("--bind")
        .arg(survivor_address.to_string())
        .arg("--mission-bundle-unprotected-reference")
        .arg(&survivor_mission_path)
        .arg("--peer")
        .arg(&survivor_peer)
        .args(["--sync-ms", "500", "--run-for", "15"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn survivor node");
    let survivor_stdout = survivor.stdout.take().expect("survivor stdout");
    let (survivor_line_sender, survivor_line_receiver) = mpsc::channel();
    let survivor_reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(survivor_stdout).lines() {
            let line = line.expect("UTF-8 survivor stdout");
            let _ = survivor_line_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    let survivor_stderr = survivor.stderr.take().expect("survivor stderr");
    let (survivor_error_sender, survivor_error_receiver) = mpsc::channel();
    let survivor_error_reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(survivor_stderr).lines() {
            let line = line.expect("UTF-8 survivor stderr");
            let _ = survivor_error_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    wait_for_ready(&mut survivor, &survivor_line_receiver);
    let survivor_contact_prefix = format!(
        "CONTACT direction=out carrier_peer={target_carrier} mission_peer={} ",
        aster_node::format_node_id(target_mission_id)
    );
    let target_contact_prefix = format!(
        "CONTACT direction=in carrier_peer={survivor_carrier} mission_peer={} ",
        aster_node::format_node_id(survivor_mission_id)
    );
    let _ = wait_for_protected_contact(
        &mut survivor,
        &survivor_line_receiver,
        &survivor_contact_prefix,
    );
    let _ = wait_for_protected_contact(&mut target, &target_line_receiver, &target_contact_prefix);

    let zeroize = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["zeroize", "--state"])
        .arg(&target_state)
        .arg("--mission-bundle-unprotected-reference")
        .arg(&target_mission_path)
        .args(["--wait-seconds", "20"])
        .output()
        .expect("zeroize configured target");
    let zeroize_stdout = String::from_utf8(zeroize.stdout).expect("zeroize stdout");
    let zeroize_stderr = String::from_utf8(zeroize.stderr).expect("zeroize stderr");
    assert!(
        zeroize.status.success(),
        "configured live zeroization failed: stdout={zeroize_stdout} stderr={zeroize_stderr}"
    );
    assert!(zeroize_stdout.contains("ZEROIZE status=pass mode=live state=complete"));
    assert!(zeroize_stdout.contains(
        "mission_pathname=retained-zero-length carrier_identity_pathname=retained-zero-length"
    ));

    let target_deadline = Instant::now() + Duration::from_secs(10);
    let target_status = loop {
        if let Some(status) = target.try_wait().expect("poll zeroized target") {
            break status;
        }
        if Instant::now() >= target_deadline {
            target.kill().expect("kill stuck zeroized target");
            let _ = target.wait();
            panic!("configured target did not exit after live zeroization");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let target_lines = target_reader.join().expect("join target reader");
    let target_errors = target_error_reader.join().expect("join target errors");
    assert!(
        target_status.success(),
        "zeroized target failed: {target_lines:?} {target_errors}"
    );
    assert!(target_lines.iter().any(|line| {
        line.starts_with("STOP lifecycle=zeroized sync_status=terminal-lockout ")
            && receipt_counter(line, "contacts").is_some_and(|contacts| contacts > 0)
    }));
    assert_eq!(
        std::fs::symlink_metadata(&target_mission_path)
            .expect("target mission tombstone")
            .len(),
        0
    );
    assert_eq!(
        std::fs::symlink_metadata(&target_identity_path)
            .expect("target identity tombstone")
            .len(),
        0
    );
    let inspect = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["inspect", "--state"])
        .arg(&target_state)
        .output()
        .expect("inspect terminal target");
    assert!(inspect.status.success());
    assert!(
        String::from_utf8(inspect.stdout)
            .expect("inspect stdout")
            .contains("zeroization=complete")
    );

    // A quiet reader-channel interval establishes that pre-STOP pipe backlog
    // was consumed before classifying any later contact receipt or error.
    let expected_closure_prefix = format!(
        "CONTACT direction=out carrier_peer={target_carrier} expected_mission_peer={} status=error error=",
        aster_node::format_node_id(target_mission_id)
    );
    let baseline_deadline = Instant::now() + Duration::from_secs(3);
    let mut quiet_since = Instant::now();
    loop {
        let mut activity = false;
        while survivor_line_receiver.try_recv().is_ok() {
            activity = true;
        }
        while survivor_error_receiver.try_recv().is_ok() {
            activity = true;
        }
        if activity {
            quiet_since = Instant::now();
        } else if quiet_since.elapsed() >= Duration::from_millis(250) {
            break;
        }
        assert!(
            Instant::now() < baseline_deadline,
            "survivor output never reached a quiet post-STOP baseline"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let mut closure_observed = false;
    let closure_deadline = Instant::now() + Duration::from_secs(12);
    let mut protected_after_stop = Vec::new();
    while !closure_observed && Instant::now() < closure_deadline {
        while let Ok(line) = survivor_line_receiver.try_recv() {
            if line.starts_with(&survivor_contact_prefix) && line.ends_with("status=pass") {
                protected_after_stop.push(line);
            }
        }
        if let Ok(line) = survivor_error_receiver.recv_timeout(Duration::from_millis(50)) {
            closure_observed |= line.starts_with(&expected_closure_prefix);
        }
    }
    assert!(
        closure_observed,
        "survivor did not observe target endpoint closure"
    );
    std::fs::write(&target_mission_path, &target_mission_bytes)
        .expect("restore target mission tombstone");
    std::fs::set_permissions(&target_mission_path, std::fs::Permissions::from_mode(0o600))
        .expect("restored mission permissions");
    std::fs::write(&target_identity_path, &target_identity_bytes)
        .expect("restore target identity tombstone");
    std::fs::set_permissions(
        &target_identity_path,
        std::fs::Permissions::from_mode(0o600),
    )
    .expect("restored identity permissions");
    let restart = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&target_state)
        .arg("--bind")
        .arg(target_address.to_string())
        .arg("--mission-bundle-unprotected-reference")
        .arg(&target_mission_path)
        .arg("--peer")
        .arg(&target_peer)
        .args(["--sync-ms", "500", "--run-for", "1"])
        .output()
        .expect("attempt restored target recontact");
    let restart_stdout = String::from_utf8(restart.stdout).expect("restart stdout");
    let restart_stderr = String::from_utf8(restart.stderr).expect("restart stderr");
    assert!(!restart.status.success(), "terminal target restarted");
    assert!(!restart_stdout.contains("READY selected=true"));
    assert!(!restart_stdout.contains("CONTACT "));
    assert!(restart_stderr.contains("terminally") || restart_stderr.contains("locked out"));
    assert_eq!(
        std::fs::read(&target_mission_path).expect("restored mission retained"),
        target_mission_bytes
    );
    assert_eq!(
        std::fs::read(&target_identity_path).expect("restored identity retained"),
        target_identity_bytes
    );

    let survivor_status = survivor.wait().expect("graceful survivor exit");
    let survivor_lines = survivor_reader.join().expect("join survivor reader");
    let survivor_errors = survivor_error_reader.join().expect("join survivor errors");
    while let Ok(line) = survivor_line_receiver.try_recv() {
        if line.starts_with(&survivor_contact_prefix) && line.ends_with("status=pass") {
            protected_after_stop.push(line);
        }
    }
    assert!(
        protected_after_stop.is_empty(),
        "protected contact completed after the quiet post-STOP baseline: {protected_after_stop:?}"
    );
    assert!(
        survivor_status.success(),
        "survivor did not exit through its finite runtime: {survivor_errors:?}"
    );
    assert!(
        survivor_lines
            .iter()
            .any(|line| line.starts_with(&survivor_contact_prefix) && line.ends_with("status=pass"))
    );
    assert!(survivor_lines.iter().any(|line| {
        line.starts_with("STOP lifecycle=complete sync_status=contacts_observed ")
            && receipt_counter(line, "contact_errors").is_some_and(|errors| errors > 0)
    }));
    assert!(
        survivor_errors
            .iter()
            .any(|line| line.starts_with(&expected_closure_prefix))
    );
    let combined = format!(
        "{zeroize_stdout}{zeroize_stderr}{target_errors}{restart_stdout}{restart_stderr}{}{}",
        target_lines.join("\n"),
        survivor_lines.join("\n")
    );
    assert!(!combined.contains(&bytes_hex(&target_mission_bytes)));
    assert!(!combined.contains(&bytes_hex(&target_identity_bytes)));
    std::fs::remove_dir_all(root).expect("cleanup configured contact root");
}

#[cfg(unix)]
#[test]
fn live_socket_replacement_after_accept_begins_fails_node_once() {
    use std::{
        io::Read as _,
        os::unix::fs::{FileTypeExt as _, MetadataExt as _},
    };

    let _process_test = serialize_process_test();
    let root = fresh_root("live-socket-replacement");
    let state = root.join("state");
    let mission_path = root.join("mission.bundle");
    std::fs::create_dir_all(&root).expect("root");
    persist_zeroization_bundle(&mission_path, 0xd4);

    let mut node = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn socket-integrity node");
    let stdout = node.stdout.take().expect("node stdout");
    let (line_sender, line_receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("UTF-8 node output");
            let _ = line_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    wait_for_ready(&mut node, &line_receiver);

    let store = std::fs::symlink_metadata(state.join("mesh.redb")).expect("store metadata");
    let control_directory = std::fs::canonicalize("/tmp")
        .expect("canonical tmp")
        .join(format!(
            "aster-zeroize-{}",
            rustix::process::geteuid().as_raw()
        ));
    let socket_path = control_directory.join(format!(
        "mesh-{:016x}-{:016x}.sock",
        store.dev(),
        store.ino()
    ));
    let socket = std::fs::symlink_metadata(&socket_path).expect("live socket metadata");
    assert!(socket.file_type().is_socket());
    let displaced_socket = socket_path.with_extension("sock.displaced");
    std::fs::rename(&socket_path, &displaced_socket).expect("replace pathname after accept began");

    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = node.try_wait().expect("poll integrity-failed node") {
            break status;
        }
        if Instant::now() >= deadline {
            node.kill()
                .expect("kill nonterminating integrity-failed node");
            let _ = node.wait();
            panic!("node stayed live after its exact zeroization socket was replaced");
        }
        thread::sleep(Duration::from_millis(20));
    };
    let node_lines = reader.join().expect("join node reader");
    let mut stderr = String::new();
    node.stderr
        .take()
        .expect("node stderr")
        .read_to_string(&mut stderr)
        .expect("read node stderr");
    assert!(
        !status.success(),
        "socket-integrity failure exited successfully"
    );
    assert_eq!(
        stderr
            .matches("ZEROIZE lifecycle=live control=failed")
            .count(),
        1,
        "integrity failure was not reported exactly once: {stderr}"
    );
    assert!(
        !node_lines
            .iter()
            .any(|line| line.starts_with("STOP lifecycle=complete"))
    );
    std::fs::remove_file(displaced_socket).expect("remove displaced socket");
    std::fs::remove_dir_all(root).expect("cleanup socket-integrity root");
}

#[cfg(unix)]
#[test]
fn sigkill_dirty_live_cli_node_restart_recovers_before_identity_and_socket() {
    use std::io::Read as _;

    let _process_test = serialize_process_test();
    let root = fresh_root("sigkill-dirty-live-restart");
    let state = root.join("state");
    let mission_path = root.join("mission.bundle");
    std::fs::create_dir_all(&root).expect("root");
    persist_zeroization_bundle(&mission_path, 0xd3);

    let mut first = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "30"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn first node");
    let stdout = first.stdout.take().expect("first stdout");
    let (line_sender, line_receiver) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut lines = Vec::new();
        for line in BufReader::new(stdout).lines() {
            let line = line.expect("UTF-8 first-node output");
            let _ = line_sender.send(line.clone());
            lines.push(line);
        }
        lines
    });
    wait_for_ready(&mut first, &line_receiver);
    first.kill().expect("SIGKILL first node");
    let killed = first.wait().expect("wait for killed node");
    assert!(!killed.success());
    let first_lines = reader.join().expect("join first reader");
    assert!(
        first_lines
            .iter()
            .any(|line| line.starts_with("READY selected=true"))
    );
    let mut first_stderr = String::new();
    first
        .stderr
        .take()
        .expect("first stderr")
        .read_to_string(&mut first_stderr)
        .expect("read first stderr");

    let dirty_inspect = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["inspect", "--state"])
        .arg(&state)
        .output()
        .expect("inspect dirty live state");
    assert!(
        !dirty_inspect.status.success(),
        "SIGKILL did not leave dirty redb state"
    );
    assert!(
        String::from_utf8_lossy(&dirty_inspect.stderr).contains("Database%20repair%20aborted"),
        "unexpected dirty inspection error: {}",
        String::from_utf8_lossy(&dirty_inspect.stderr)
    );

    let restarted = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "1"])
        .output()
        .expect("restart dirty live node");
    let restarted_stdout = String::from_utf8(restarted.stdout).expect("restart stdout");
    let restarted_stderr = String::from_utf8(restarted.stderr).expect("restart stderr");
    assert!(
        restarted.status.success(),
        "dirty live restart failed: stdout={restarted_stdout} stderr={restarted_stderr} first_stderr={first_stderr}"
    );
    assert!(restarted_stdout.contains("READY selected=true"));
    assert!(restarted_stdout.contains("STOP lifecycle=complete"));
    assert!(!restarted_stderr.contains("repair%20aborted"));
    std::fs::remove_dir_all(root).expect("cleanup dirty live root");
}

#[cfg(unix)]
#[test]
fn zeroization_marker_child_process() {
    let Some(state) = std::env::var_os("ASTER_INTEGRATION_ZEROIZATION_CHILD_STATE") else {
        return;
    };
    let mission_path = std::env::var_os("ASTER_INTEGRATION_ZEROIZATION_CHILD_MISSION")
        .expect("child mission path");
    let state = PathBuf::from(state);
    let mission_path = PathBuf::from(mission_path);
    let mission = UnprotectedReferenceMission::load(&mission_path).expect("load mission");
    let identity = NodeIdentity::load_existing(&state).expect("load identity");
    let prepared_mission = mission
        .prepare_software_erasure()
        .expect("preflight mission");
    let prepared_identity = identity
        .prepare_software_erasure()
        .expect("preflight identity");
    let intent = ZeroizationIntent::new(
        prepared_mission.target().to_bytes(),
        prepared_identity.target().to_bytes(),
    )
    .expect("zeroization intent");
    let store = Store::open_for_mission(
        state.join("mesh.redb"),
        prepared_mission.mission_authority_id(),
    )
    .expect("bind store to retained mission");
    store
        .require_process_exclusive_lock()
        .expect("exclusive store writer");
    store.begin_zeroization(&intent).expect("durable marker");
    // This harness is linked only into the integration-test executable. Exit
    // without dropping the redb/artifact handles to model an abrupt process
    // loss immediately after the Immediate-durability marker commit.
    std::process::exit(86);
}

#[cfg(unix)]
#[test]
fn interrupted_terminal_marker_resumes_without_losing_data_rows() {
    let _process_test = serialize_process_test();
    let root = fresh_root("interrupted-zeroization");
    let state = root.join("state");
    let mission_path = root.join("mission.bundle");
    let payload_path = root.join("payload.bin");
    std::fs::create_dir_all(&root).expect("root");
    let mission_bytes = persist_zeroization_bundle(&mission_path, 0xd2);
    std::fs::write(&payload_path, b"survives-interrupted-cleanup").expect("payload");
    let init = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["init", "--state"])
        .arg(&state)
        .output()
        .expect("initialize identity");
    assert!(
        init.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let identity_path = state.join("identity.key");
    let identity_bytes = std::fs::read(&identity_path).expect("identity bytes");
    let put = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["put", "--state"])
        .arg(&state)
        .args([
            "--id",
            "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5",
            "--file",
        ])
        .arg(&payload_path)
        .output()
        .expect("put row");
    assert!(
        put.status.success(),
        "put failed: {}",
        String::from_utf8_lossy(&put.stderr)
    );

    let interrupted = Command::new(std::env::current_exe().expect("integration test executable"))
        .args(["--exact", "zeroization_marker_child_process", "--nocapture"])
        .env("ASTER_INTEGRATION_ZEROIZATION_CHILD_STATE", &state)
        .env("ASTER_INTEGRATION_ZEROIZATION_CHILD_MISSION", &mission_path)
        .output()
        .expect("interrupt child after marker");
    assert_eq!(interrupted.status.code(), Some(86));
    assert!(mission_path.exists());
    assert!(identity_path.exists());

    // Model credentials restored while the retained database is dirty and
    // terminal. Actual CLI startup must recover lifecycle truth and reject
    // before creating an endpoint or accepting the restored bundle.
    std::fs::write(&mission_path, &mission_bytes).expect("restore mission bytes");
    std::fs::write(&identity_path, &identity_bytes).expect("restore identity bytes");
    let terminal_restart = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["node", "--state"])
        .arg(&state)
        .args([
            "--bind",
            "127.0.0.1:0",
            "--mission-bundle-unprotected-reference",
        ])
        .arg(&mission_path)
        .args(["--run-for", "1"])
        .output()
        .expect("reject dirty terminal restart");
    let terminal_stdout = String::from_utf8(terminal_restart.stdout).expect("terminal stdout");
    let terminal_stderr = String::from_utf8(terminal_restart.stderr).expect("terminal stderr");
    assert!(
        !terminal_restart.status.success(),
        "dirty terminal node restarted"
    );
    assert!(!terminal_stdout.contains("READY selected=true"));
    assert!(terminal_stderr.contains("terminally%20locked%20out"));
    assert!(!terminal_stderr.contains("repair%20aborted"));
    assert_eq!(
        std::fs::read(&mission_path).expect("mission retained"),
        mission_bytes
    );
    assert_eq!(
        std::fs::read(&identity_path).expect("identity retained"),
        identity_bytes
    );

    let resumed = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["zeroize", "--state"])
        .arg(&state)
        .arg("--mission-bundle-unprotected-reference")
        .arg(&mission_path)
        .output()
        .expect("resume cleanup");
    let resumed_stdout = String::from_utf8(resumed.stdout).expect("resumed stdout");
    assert!(
        resumed.status.success(),
        "resume failed: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert!(resumed_stdout.contains("state=complete"));
    assert!(resumed_stdout.contains("data_rows_preserved=true opaque_items=1"));
    assert!(resumed_stdout.contains(
        "mission_pathname=retained-zero-length carrier_identity_pathname=retained-zero-length"
    ));
    assert_eq!(
        std::fs::metadata(&mission_path)
            .expect("mission tombstone")
            .len(),
        0
    );
    assert_eq!(
        std::fs::metadata(&identity_path)
            .expect("identity tombstone")
            .len(),
        0
    );

    let inspect = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["inspect", "--state"])
        .arg(&state)
        .output()
        .expect("inspect resumed terminal state");
    assert!(
        inspect.status.success(),
        "terminal inspect failed: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    assert!(
        String::from_utf8(inspect.stdout)
            .expect("inspect stdout")
            .contains("zeroization=complete opaque_items=1")
    );
    std::fs::remove_dir_all(root).expect("cleanup interrupted zeroization root");
}

#[test]
fn four_real_processes_default_to_ping_pong_and_restart_cleanly() {
    let _process_test = serialize_process_test();
    let root = fresh_root("four-process-default-ping-pong-mesh");
    let mut child = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["demo", "--nodes", "4", "--root"])
        .arg(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mesh demo");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if child.try_wait().expect("poll mesh demo").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out mesh demo");
            let output = child.wait_with_output().expect("collect timed-out demo");
            panic!(
                "mesh demo exceeded 120 seconds; root={}; stdout={} stderr={}",
                root.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    let output = child.wait_with_output().expect("collect mesh demo");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(
        output.status.success(),
        "mesh demo failed; root={}; stdout={stdout} stderr={stderr}",
        root.display()
    );
    assert!(stdout.contains("PING status=received"));
    assert!(stdout.contains("emitted_by=origin-process"));
    assert!(stdout.contains("producer_process_absent=true"));
    assert!(stdout.contains("PONG status=received"));
    assert!(stdout.contains("emitted_by=destination-process"));
    assert!(stdout.contains(
        "RELAY status=pass intermediates=2 exact_forward=true content_access=denied semantic_acceptance=none"
    ));
    assert!(stdout.contains(
        "PHASE status=pass name=ping-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable"
    ));
    for phase in [
        "ping-forward-0-to-1",
        "ping-forward-1-to-2",
        "ping-forward-2-to-3",
        "pong-return-3-to-2",
        "pong-return-2-to-1",
        "pong-return-1-to-0",
    ] {
        assert!(stdout.contains(&format!("PHASE status=pass name={phase} processes=2")));
    }
    assert!(stdout.contains(
        "PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable"
    ));
    assert!(stdout.contains("PHASE status=pass name=noop processes=4"));
    assert!(stdout.contains(
        "DEMO_RESULT status=pass scenario=ping-pong nodes=4 processes=18 contacts=real-iroh"
    ));
    assert!(stdout.contains(
        "reconciliation=negentropy producer_process_absent=true restarts=pass atomic_reaction=pass equal_inventory_noop=pass transfers_each=2 semantics=source-authenticated-event emitted_by=running-node-processes payload_blind_relays=pass ttl=durable-none"
    ));
    let process_logs = std::fs::read_dir(root.join("logs"))
        .expect("read process logs")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "log"))
        .collect::<Vec<_>>();
    assert_eq!(process_logs.len(), 18, "one stdout log per child process");
    let mut emitted_ping = 0usize;
    let mut emitted_pong = 0usize;
    for path in &process_logs {
        let log = std::fs::read_to_string(path).expect("read process log");
        emitted_ping += log.matches("APPLICATION status=emitted kind=ping ").count();
        emitted_pong += log.matches("APPLICATION status=emitted kind=pong ").count();
        assert!(
            log.contains("mission_auth=hybrid-pq provisioning=unprotected-reference"),
            "child omitted the mission/provisioning receipt: {}\n{log}",
            path.display()
        );
        let isolated_application = if path.ends_with("ping-publish-node-0.log") {
            Some("ping-emitter")
        } else if path.ends_with("pong-publish-node-3.log") {
            Some("pong-responder")
        } else {
            None
        };
        if let Some(application) = isolated_application {
            assert!(log.lines().any(|line| {
                line.starts_with("READY ")
                    && line.contains(" peers=0 ")
                    && line.contains(&format!(" application={application} "))
            }));
            assert!(log.lines().any(|line| {
                line.starts_with("STOP ")
                    && line.contains(" sync_status=no_successful_contact ")
                    && line.contains(" contacts=0 ")
            }));
            assert!(!log.lines().any(|line| line.starts_with("CONTACT ")));
            continue;
        }
        assert!(
            log.contains("STOP lifecycle=complete sync_status=contacts_observed"),
            "child did not report a successful mission contact: {}\n{log}",
            path.display()
        );
        let protected_contact = log.lines().any(|line| {
            line.starts_with("CONTACT ")
                && line.ends_with("status=pass")
                && line.contains(" mission_auth=hybrid-pq ")
                && receipt_counter(line, "handshake_frames") == Some(4)
                && receipt_counter(line, "handshake_bytes").is_some_and(|bytes| bytes > 0)
                && receipt_counter(line, "protected_frames").is_some_and(|frames| frames > 0)
                && receipt_counter(line, "protected_bytes").is_some_and(|bytes| bytes > 0)
        });
        assert!(
            protected_contact,
            "child omitted a completed authenticated/protected contact receipt: {}\n{log}",
            path.display()
        );
    }
    assert_eq!(
        emitted_ping, 1,
        "Ping must be emitted by one live process once"
    );
    assert_eq!(
        emitted_pong, 1,
        "Pong must be emitted by one live process once"
    );

    let ping_publish = std::fs::read_to_string(root.join("logs/ping-publish-node-0.log"))
        .expect("isolated Ping publisher log");
    assert!(ping_publish.contains("APPLICATION status=emitted kind=ping "));
    let pong_publish = std::fs::read_to_string(root.join("logs/pong-publish-node-3.log"))
        .expect("isolated Pong publisher log");
    assert!(pong_publish.contains("APPLICATION status=emitted kind=pong "));

    for left in 0..3 {
        let right = left + 1;
        assert_exact_event_edge(
            &root,
            &format!("ping-forward-{left}-to-{right}"),
            left,
            right,
        );
    }
    for left in (0..3).rev() {
        let right = left + 1;
        assert_exact_event_edge(
            &root,
            &format!("pong-return-{right}-to-{left}"),
            right,
            left,
        );
    }

    let noop_ping =
        std::fs::read_to_string(root.join("logs/noop-node-0.log")).expect("read no-op Ping log");
    let noop_pong =
        std::fs::read_to_string(root.join("logs/noop-node-3.log")).expect("read no-op Pong log");
    assert!(noop_ping.contains("APPLICATION status=existing kind=ping "));
    assert!(noop_pong.contains("APPLICATION status=existing kind=pong "));
    for node in 0..4 {
        assert_default_noop_node(&root, node, node == 0 || node == 3);
    }
    std::fs::remove_dir_all(&root).expect("remove successful demo root");
}

#[test]
fn two_real_processes_use_the_same_stopped_state_ping_pong_plan() {
    let _process_test = serialize_process_test();
    let root = fresh_root("two-process-default-ping-pong-mesh");
    let mut child = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["demo", "--nodes", "2", "--root"])
        .arg(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn two-node mesh demo");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if child.try_wait().expect("poll two-node mesh demo").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out two-node mesh demo");
            let output = child
                .wait_with_output()
                .expect("collect timed-out two-node demo");
            panic!(
                "two-node mesh demo exceeded 120 seconds; root={}; stdout={} stderr={}",
                root.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    let output = child
        .wait_with_output()
        .expect("collect two-node mesh demo");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(
        output.status.success(),
        "two-node mesh demo failed; root={}; stdout={stdout} stderr={stderr}",
        root.display()
    );
    assert!(stdout.contains(
        "PHASE status=pass name=ping-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable"
    ));
    assert!(stdout.contains("PHASE status=pass name=ping-forward-0-to-1 processes=2"));
    assert!(stdout.contains(
        "PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable"
    ));
    assert!(stdout.contains("PHASE status=pass name=pong-return-1-to-0 processes=2"));
    assert!(stdout.contains("PHASE status=pass name=noop processes=2"));
    assert!(stdout.contains("PING status=received emitted_by=origin-process"));
    assert!(stdout.contains("producer_process_absent=true"));
    assert!(stdout.contains("PONG status=received emitted_by=destination-process"));
    assert!(stdout.contains("RELAY status=not-applicable intermediates=0"));
    assert!(stdout.contains(
        "DEMO_RESULT status=pass scenario=ping-pong nodes=2 processes=8 contacts=real-iroh"
    ));
    assert!(stdout.contains("payload_blind_relays=not-applicable ttl=durable-none"));

    let process_logs = std::fs::read_dir(root.join("logs"))
        .expect("read two-node process logs")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "log"))
        .collect::<Vec<_>>();
    assert_eq!(process_logs.len(), 8, "one stdout log per child process");
    let emitted_ping = process_logs
        .iter()
        .map(|path| std::fs::read_to_string(path).expect("read two-node process log"))
        .map(|log| log.matches("APPLICATION status=emitted kind=ping ").count())
        .sum::<usize>();
    let emitted_pong = process_logs
        .iter()
        .map(|path| std::fs::read_to_string(path).expect("read two-node process log"))
        .map(|log| log.matches("APPLICATION status=emitted kind=pong ").count())
        .sum::<usize>();
    assert_eq!(emitted_ping, 1);
    assert_eq!(emitted_pong, 1);
    assert_peerless_application(&root, "ping-publish", 0, "ping-emitter", "ping");
    assert_peerless_application(&root, "pong-publish", 1, "pong-responder", "pong");
    assert_exact_event_edge(&root, "ping-forward-0-to-1", 0, 1);
    assert_exact_event_edge(&root, "pong-return-1-to-0", 1, 0);

    let noop_ping =
        std::fs::read_to_string(root.join("logs/noop-node-0.log")).expect("two-node no-op Ping");
    let noop_pong =
        std::fs::read_to_string(root.join("logs/noop-node-1.log")).expect("two-node no-op Pong");
    assert!(noop_ping.contains("APPLICATION status=existing kind=ping "));
    assert!(noop_pong.contains("APPLICATION status=existing kind=pong "));
    assert_default_noop_node(&root, 0, true);
    assert_default_noop_node(&root, 1, true);
    std::fs::remove_dir_all(&root).expect("remove successful two-node demo root");
}

#[test]
fn four_real_processes_propagate_controls_without_authority_and_exclude_captured_leaf() {
    let _process_test = serialize_process_test();
    let root = fresh_root("four-process-controlled-mesh");
    let mut child = Command::new(env!("CARGO_BIN_EXE_aster"))
        .args(["demo", "--nodes", "4", "--scenario", "control", "--root"])
        .arg(&root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn controlled mesh demo");
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if child.try_wait().expect("poll controlled demo").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().expect("kill timed-out controlled demo");
            let output = child.wait_with_output().expect("collect timed-out demo");
            panic!(
                "controlled mesh demo exceeded 120 seconds; root={}; stdout={} stderr={}",
                root.display(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        thread::sleep(Duration::from_millis(100));
    }
    let output = child.wait_with_output().expect("collect controlled demo");
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 stdout");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(
        output.status.success(),
        "controlled mesh demo failed; root={}; stdout={stdout} stderr={stderr}",
        root.display()
    );
    assert!(stdout.contains("PHASE status=pass name=control-authority-seed processes=2"));
    assert!(stdout.contains("PHASE status=pass name=control-authority-absent-forward processes=2"));
    assert!(stdout.contains(
        "PHASE status=pass name=control-authority-absent-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable"
    ));
    assert!(
        stdout
            .contains("PHASE status=pass name=control-authority-absent-event-forward processes=2")
    );
    assert!(stdout.contains("PHASE status=pass name=captured-publication-denied processes=2"));
    assert!(stdout.contains("PHASE status=pass name=captured-rejoin-denied processes=2"));
    assert!(stdout.contains("PHASE status=pass name=pong-ping-forward processes=2"));
    assert!(stdout.contains(
        "PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable"
    ));
    assert!(stdout.contains("PHASE status=pass name=pong-relay-forward processes=2"));
    assert!(stdout.contains("PHASE status=pass name=pong-return processes=2"));
    assert!(stdout.contains("PHASE status=pass name=noop processes=3"));
    assert!(stdout.contains("PING status=received") && stdout.contains("key_epoch=2"));
    assert!(stdout.contains("PONG status=received") && stdout.contains("key_epoch=2"));
    assert!(stdout.contains(
        "CONTROL_RESULT status=pass nodes=4 authority_processes=2 emitted_by=authority-process controls=2 control_priority=flash authority_absent_forwarding=pass route_only_forward=pass survivor_epoch=2 captured_node=3 captured_sync=denied captured_epoch2_read=denied captured_mesh_publication=denied captured_rejoin=denied captured_local_signing=stale-only"
    ));
    assert!(stdout.contains(
        "DEMO_RESULT status=pass scenario=control nodes=4 processes=23 contacts=real-iroh mission_auth=hybrid-pq"
    ));
    let revoke = std::fs::read_to_string(root.join("logs/authority-revoke.log"))
        .expect("authority revoke log");
    let rekey = std::fs::read_to_string(root.join("logs/authority-rekey.log"))
        .expect("authority rekey log");
    assert!(revoke.contains("status=emitted") && revoke.contains("emitted_by=authority-process"));
    assert!(rekey.contains("status=emitted") && rekey.contains("recipient_filtered=true"));
    assert!(
        !root
            .join("logs/control-authority-absent-forward-node-0.log")
            .exists()
    );
    assert!(
        !root
            .join("logs/control-authority-absent-event-forward-node-0.log")
            .exists()
    );
    assert!(
        !root
            .join("logs/control-authority-absent-publish-node-0.log")
            .exists()
    );
    let isolated_publisher =
        std::fs::read_to_string(root.join("logs/control-authority-absent-publish-node-2.log"))
            .expect("isolated epoch-two publisher log");
    assert!(isolated_publisher.lines().any(|line| {
        line.starts_with("READY ")
            && line.contains(" peers=0 ")
            && line.contains(" application=epoch2-ping-emitter ")
    }));
    assert!(isolated_publisher.contains("APPLICATION status=emitted kind=ping "));
    assert!(isolated_publisher.lines().any(|line| {
        line.starts_with("STOP ")
            && line.contains(" sync_status=no_successful_contact ")
            && line.contains(" contacts=0 ")
    }));
    assert!(
        !isolated_publisher
            .lines()
            .any(|line| line.starts_with("CONTACT "))
    );

    let event_forward = [1, 2]
        .into_iter()
        .map(|node| {
            std::fs::read_to_string(root.join(format!(
                "logs/control-authority-absent-event-forward-node-{node}.log"
            )))
            .expect("authority-absent Event-forward log")
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(event_forward.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.contains(" control_offered=0 ")
            && line.contains(" control_fetched=0 ")
            && line.contains(" offered=1 ")
            && line.ends_with("status=pass")
    }));

    let ping_forward = [0, 1]
        .into_iter()
        .map(|node| {
            std::fs::read_to_string(root.join(format!("logs/pong-ping-forward-node-{node}.log")))
                .expect("Ping-to-Pong-member forwarding log")
        })
        .collect::<Vec<_>>()
        .join("\n");
    assert!(ping_forward.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.contains(" control_offered=0 ")
            && line.contains(" control_fetched=0 ")
            && line.contains(" offered=1 ")
            && line.ends_with("status=pass")
    }));
    assert!(ping_forward.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.contains(" control_offered=0 ")
            && line.contains(" control_fetched=0 ")
            && line.contains(" fetched=1 ")
            && line.contains(" inserted=1 ")
            && line.contains(" remaining=0 ")
            && line.ends_with("status=pass")
    }));

    let isolated_pong = std::fs::read_to_string(root.join("logs/pong-publish-node-0.log"))
        .expect("isolated Pong publisher log");
    assert!(isolated_pong.lines().any(|line| {
        line.starts_with("READY ")
            && line.contains(" peers=0 ")
            && line.contains(" application=pong-responder ")
    }));
    assert!(isolated_pong.contains("APPLICATION status=emitted kind=pong "));
    assert!(isolated_pong.lines().any(|line| {
        line.starts_with("STOP ")
            && line.contains(" sync_status=no_successful_contact ")
            && line.contains(" contacts=0 ")
    }));
    assert!(
        !isolated_pong
            .lines()
            .any(|line| line.starts_with("CONTACT "))
    );

    for (phase, source, destination) in [("pong-relay-forward", 0, 1), ("pong-return", 1, 2)] {
        let source_log =
            std::fs::read_to_string(root.join(format!("logs/{phase}-node-{source}.log")))
                .expect("Pong forwarding source log");
        let destination_log =
            std::fs::read_to_string(root.join(format!("logs/{phase}-node-{destination}.log")))
                .expect("Pong forwarding destination log");
        assert!(source_log.lines().any(|line| {
            line.starts_with("CONTACT ")
                && line.contains(" control_offered=0 ")
                && line.contains(" control_fetched=0 ")
                && line.contains(" offered=1 ")
                && line.ends_with("status=pass")
        }));
        assert!(destination_log.lines().any(|line| {
            line.starts_with("CONTACT ")
                && line.contains(" control_offered=0 ")
                && line.contains(" control_fetched=0 ")
                && line.contains(" fetched=1 ")
                && line.contains(" inserted=1 ")
                && line.contains(" remaining=0 ")
                && line.ends_with("status=pass")
        }));
    }
    assert!(event_forward.lines().any(|line| {
        line.starts_with("CONTACT ")
            && line.contains(" control_offered=0 ")
            && line.contains(" control_fetched=0 ")
            && line.contains(" fetched=1 ")
            && line.contains(" inserted=1 ")
            && line.contains(" remaining=0 ")
            && line.ends_with("status=pass")
    }));

    for node in 0..3 {
        let noop = std::fs::read_to_string(root.join(format!("logs/noop-node-{node}.log")))
            .expect("equal-inventory no-op log");
        let passing_contacts = noop
            .lines()
            .filter(|line| line.starts_with("CONTACT ") && line.ends_with("status=pass"))
            .collect::<Vec<_>>();
        assert!(!passing_contacts.is_empty());
        assert!(passing_contacts.iter().all(|line| {
            [
                " control_offered=0 ",
                " control_fetched=0 ",
                " control_retained=0 ",
                " control_duplicates=0 ",
                " control_activated=0 ",
                " control_remaining=0 ",
                " offered=0 ",
                " fetched=0 ",
                " inserted=0 ",
                " duplicates=0 ",
                " remaining=0 ",
            ]
            .into_iter()
            .all(|field| line.contains(field))
        }));
        let stop = noop
            .lines()
            .find(|line| line.starts_with("STOP "))
            .expect("equal-inventory no-op STOP receipt");
        assert!(stop.contains(" controls=2 "));
        assert!(stop.contains(" applied_controls=2 "));
        assert!(stop.contains(" pending_controls=0 "));
        assert!(stop.contains(" control_highwater=2 "));
        if node == 1 {
            assert!(stop.contains(" events=0 "));
            assert!(stop.contains(" route_cached_events=2 "));
        } else {
            assert!(stop.contains(" events=2 "));
            assert!(stop.contains(" route_cached_events=0 "));
        }
    }
    for phase in ["captured-publication-denied", "captured-rejoin-denied"] {
        let survivor = std::fs::read_to_string(root.join(format!("logs/{phase}-node-2.log")))
            .expect("survivor denial log");
        let captured = std::fs::read_to_string(root.join(format!("logs/{phase}-node-3.log")))
            .expect("captured denial log");
        assert!(!survivor.contains("status=pass"));
        assert!(!captured.contains("status=pass"));
    }
    std::fs::remove_dir_all(&root).expect("remove successful controlled demo root");
}
