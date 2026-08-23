import argparse
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import signal
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "ip_mesh_experiment.py"
SPEC = importlib.util.spec_from_file_location("aster_ip_mesh_experiment", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
experiment = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = experiment
SPEC.loader.exec_module(experiment)


def write_gate_h_buildx_state(root: Path, docker_config: Path) -> None:
    state = docker_config / "buildx"
    for relative in (
        "activity",
        "defaults",
        "instances",
        "refs/default/default",
    ):
        (state / relative).mkdir(parents=True, mode=0o700, exist_ok=True)
    (state / ".lock").write_bytes(b"")
    (state / ".buildNodeID").write_bytes(b"0123456789abcdef")
    (state / "activity/default").write_bytes(b"2026-08-21T00:00:00Z")
    ref = {
        "Target": "default",
        "LocalPath": str((root / "gate-h-signed-source").resolve()),
        "DockerfilePath": str(
            (root / "gate-h-signed-source/lab/Dockerfile").resolve()
        ),
    }
    (state / "refs/default/default" / ("a" * 25)).write_text(
        json.dumps(ref, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    state.chmod(0o700)
    for path in state.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)
    (state / "refs/default/default" / ("a" * 25)).chmod(0o644)


def native_shared_node_receipt():
    limits = dict(experiment.GATE_H_NATIVE_RESOURCE_LIMITS)
    current = {field: 0 for field in experiment.NODE_RESOURCE_FIELDS}
    current.update(experiment.GATE_H_NATIVE_PROVIDER_BASE)
    high_water = dict(current)
    for field, value in experiment.GATE_H_NATIVE_ADMITTED_CONTACT.items():
        high_water[field] = high_water.get(field, 0) + 2 * value
    high_water["candidates"] = 2
    return {
        "schema": experiment.NATIVE_SHARED_NODE_SCHEMA,
        "frame_counter_scope": "aster_protocol",
        "frames_received": 3,
        "frames_sent": 5,
        "aster_frames_received": 3,
        "aster_frames_sent": 5,
        "aster_bytes_received": 30,
        "aster_bytes_sent": 50,
        "carrier_control_frames_received": 2,
        "carrier_control_frames_sent": 2,
        "carrier_control_bytes_received": 20,
        "carrier_control_bytes_sent": 20,
        "candidates_rejected_capacity": 0,
        "contact_failures": 0,
        "duplicate_contacts": 0,
        "unauthorized_peers": [],
        "admitted_contact_high_water": 2,
        "authorization_generation_checks": 2,
        "authorization_generation_mismatches": 0,
        "authorization_generation_unavailable": 0,
        "authorization_generation_current": 0,
        "durable_item_probe_id": "d" * 64,
        "durable_item_present": True,
        "gate_h_control_id": None,
        "gate_h_generation_before": None,
        "gate_h_generation_after": None,
        "gate_h_stale_target_peer": None,
        "gate_h_stale_target_contact": None,
        "gate_h_stale_queued_frames": 0,
        "gate_h_stale_send_frames_before": 0,
        "gate_h_stale_send_frames_after": 0,
        "gate_h_stale_send_bytes_before": 0,
        "gate_h_stale_send_bytes_after": 0,
        "gate_h_stale_zero_bytes_emitted": False,
        "gate_h_stale_contacts_retired": 0,
        "gate_h_provider_epoch_rotations": 0,
        "gate_h_fresh_target_contact": None,
        "gate_h_fresh_target_generation": None,
        "gate_h_fresh_aster_frames_sent": 0,
        "gate_h_fresh_aster_bytes_sent": 0,
        "gate_h_completed": False,
        "durable_authority_open_count": 1,
        "sqlite_node_open_count": 1,
        "blob_authority_open_count": 1,
        "semantic_backend_construction_count": 1,
        "process_authority_construction_count": 1,
        "admitted_peers": ["a" * 64],
        "node_resource_limits": limits,
        "node_resource_current": current,
        "node_resource_high_water": high_water,
        "node_resource_rejections": {
            field: 0 for field in experiment.NODE_RESOURCE_FIELDS
        },
        "node_resource_rejected_claims": 0,
    }


class IpMeshExperimentTests(unittest.TestCase):
    def test_real_hermetic_bootstrap_flags_import_worktree_modules(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "evidence"
            root.mkdir()
            environment = experiment.gate_h_host_environment(
                root=root,
                docker_host="unix:///tmp/gate-h-bootstrap-import.sock",
                home=base,
                repository_workspace=experiment.WORKSPACE,
                signed_controller=True,
            )
            Path(environment["DOCKER_CONFIG"]).mkdir()
            Path(environment["TMPDIR"]).mkdir()
            python = str(Path(sys.executable).resolve())
            result = experiment.bounded_subprocess_run(
                [
                    python,
                    *experiment.GATE_H_PYTHON_FLAGS,
                    str(Path(experiment.__file__).resolve()),
                    "--help",
                ],
                cwd=experiment.WORKSPACE,
                environment=environment,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage:", result.stdout)

    def test_gate_h_bootstrap_generates_hidden_handoff_only_at_execve(self):
        class ExecveReached(Exception):
            pass

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            controller = root / "gate-h-signed-source/lab/ip_mesh_experiment.py"
            controller.parent.mkdir(parents=True)
            controller.write_text("# signed controller\n", encoding="utf-8")
            python = Path(sys.executable).resolve()
            args = argparse.Namespace(
                root=root,
                docker_host="unix:///tmp/gate-h-bootstrap.sock",
                build_command="docker build",
                git_binary=Path("/usr/bin/git"),
                ssh_keygen_binary=Path("/usr/bin/ssh-keygen"),
                ssh_binary=Path("/usr/bin/ssh"),
                allowed_signers=Path("/tmp/allowed-signers"),
                signer_principal="test@example",
                gate_h_signed_reexec_handoff=None,
                gate_h_signed_reexec_handoff_sha256=None,
                gate_h_signed_reexec_sentinel=None,
            )
            environment = experiment.gate_h_host_environment(
                root=root,
                docker_host=args.docker_host,
                home=Path(temporary),
                repository_workspace=experiment.WORKSPACE,
                signed_controller=True,
            )
            tools = {
                "python": {
                    "invocation_path": str(python),
                    "path": str(python),
                    "size_bytes": python.stat().st_size,
                    "sha256": experiment.sha256_file(python),
                },
                "git": {"invocation_path": "/usr/bin/git"},
            }
            raw_argv = ["--execute", "--root", str(root)]
            freeze = {"candidate_commit": "c" * 40, "candidate_tree": "d" * 40}
            signed_source = {
                "export": {"path": str(controller.parents[1])},
                "files": [],
            }
            calls = []

            def fake_execve(path, argv, child_environment):
                calls.append((path, argv, child_environment))
                raise ExecveReached

            with (
                mock.patch.object(
                    experiment.gate_h_signature,
                    "prepare_signature_trust",
                    return_value={"principal": "test@example"},
                ),
                mock.patch.object(
                    experiment.gate_h_signature,
                    "validate_signature_request_matches_trust",
                    return_value={"passed": True},
                ),
                mock.patch.object(experiment, "source_freeze", return_value=freeze),
                mock.patch.object(
                    experiment.gate_h_source,
                    "materialize_signed_tree",
                    return_value=signed_source,
                ),
                mock.patch.object(
                    experiment.gate_h_source,
                    "validate_signed_tree_receipt",
                    return_value=controller.parents[1],
                ),
                mock.patch.object(
                    experiment,
                    "gate_h_bootstrap_module_bindings",
                    return_value={"ip_mesh_experiment": {"passed": True}},
                ),
                mock.patch.object(experiment.secrets, "token_hex", return_value="ab" * 32),
                mock.patch.object(experiment.os, "execve", side_effect=fake_execve),
                self.assertRaises(ExecveReached),
            ):
                experiment.prepare_gate_h_export_handoff(
                    args,
                    raw_argv,
                    tools=tools,
                    environment=environment,
                )
            self.assertEqual(len(calls), 1)
            handoff_path = experiment._gate_h_handoff_path(root)
            expected_digest = experiment.sha256_file(handoff_path)
            self.assertEqual(
                calls[0],
                (
                    str(python),
                    [
                        str(python),
                        *experiment.GATE_H_PYTHON_FLAGS,
                        str(controller.resolve()),
                        *raw_argv,
                        "--gate-h-signed-reexec-handoff",
                        str(handoff_path),
                        "--gate-h-signed-reexec-handoff-sha256",
                        expected_digest,
                        "--gate-h-signed-reexec-sentinel",
                        "ab" * 32,
                    ],
                    environment,
                ),
            )
            retained = json.loads(handoff_path.read_text(encoding="utf-8"))
            self.assertEqual(
                retained["sentinel_sha256"],
                experiment.hashlib.sha256(("ab" * 32).encode("ascii")).hexdigest(),
            )
            self.assertNotIn("gate_h_signed_reexec_handoff", retained)

    def test_signed_controller_origin_rejects_hidden_worktree_bytes_and_pyc(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "repository"
            export = repository / "evidence/gate-h-signed-source"
            relative_paths = {
                "ip_mesh_experiment": "lab/ip_mesh_experiment.py",
                **experiment.GATE_H_EXPORT_MODULES,
            }
            source_files = []
            for relative in relative_paths.values():
                source = experiment.CODE_ROOT / relative
                value = source.read_bytes()
                for root, mode in ((repository, 0o644), (export, 0o444)):
                    destination = root / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(value)
                    destination.chmod(mode)
                source_files.append(
                    {
                        "path": relative,
                        "mode": "100644",
                        "git_blob": experiment.gate_h_source._git_blob_id(value),
                        "size_bytes": len(value),
                        "sha256": experiment.hashlib.sha256(value).hexdigest(),
                    }
                )
            signed_source = {
                "export": {"path": str(export)},
                "files": source_files,
            }
            module_objects = {
                "gate_h_faults": experiment.gate_h_fault_contract,
                "gate_h_signature": experiment.gate_h_signature,
                "gate_h_source": experiment.gate_h_source,
            }
            module_patches = [
                mock.patch.object(
                    module_objects[name], "__file__", str(export / relative)
                )
                for name, relative in experiment.GATE_H_EXPORT_MODULES.items()
            ]
            module_patches.extend(
                mock.patch.object(module, "__cached__", None)
                for module in module_objects.values()
            )
            python_path = Path(sys.executable).resolve()
            python_binding = {
                "invocation_path": str(python_path),
                "path": str(python_path),
                "size_bytes": python_path.stat().st_size,
                "sha256": experiment.sha256_file(python_path),
            }
            raw_argv = ["--execute"]
            expected_orig_argv = [
                str(python_path),
                *experiment.GATE_H_PYTHON_FLAGS,
                str((export / experiment.GATE_H_CONTROLLER_RELATIVE_PATH).resolve()),
                *raw_argv,
            ]
            flags = argparse.Namespace(
                dont_write_bytecode=1,
                ignore_environment=1,
                no_site=1,
                no_user_site=1,
            )
            with ExitStack() as stack:
                stack.enter_context(mock.patch.object(experiment, "WORKSPACE", repository))
                stack.enter_context(mock.patch.object(experiment, "CODE_ROOT", export))
                stack.enter_context(
                    mock.patch.object(
                        experiment,
                        "__file__",
                        str(export / experiment.GATE_H_CONTROLLER_RELATIVE_PATH),
                    )
                )
                stack.enter_context(
                    mock.patch.object(experiment, "__cached__", None, create=True)
                )
                stack.enter_context(mock.patch.dict(sys.modules, module_objects))
                stack.enter_context(
                    mock.patch.object(sys, "path", [str(export / "lab"), "/stdlib"])
                )
                stack.enter_context(mock.patch.object(sys, "flags", flags))
                stack.enter_context(
                    mock.patch.object(sys, "orig_argv", expected_orig_argv)
                )
                for patcher in module_patches:
                    stack.enter_context(patcher)
                bootstrap = {
                    name: experiment._gate_h_export_file_binding(
                        raw_file=str(repository / relative),
                        relative_path=relative,
                        export_root=repository,
                        signed_source=signed_source,
                        cached_path=None,
                        require_materialized_mode=False,
                    )
                    for name, relative in relative_paths.items()
                }
                receipt = experiment.gate_h_export_execution_snapshot(
                    signed_source=signed_source,
                    python_binding=python_binding,
                    environment={"ASTER_GATE_H_SIGNED_CONTROLLER": "test"},
                    raw_argv=raw_argv,
                    handoff={
                        "path": str(base / "handoff.json"),
                        "size_bytes": 1,
                        "sha256": "a" * 64,
                        "payload_sha256": "b" * 64,
                    },
                    sentinel_sha256="c" * 64,
                    signature_anchor={"passed": True},
                    bootstrap_modules=bootstrap,
                )
                self.assertEqual(
                    receipt["runner"]["path"],
                    str(
                        (export / experiment.GATE_H_CONTROLLER_RELATIVE_PATH).resolve()
                    ),
                )
                sys.path.append(str(repository / "lab"))
                try:
                    with self.assertRaisesRegex(
                        experiment.ExperimentError, "admits the worktree"
                    ):
                        experiment.gate_h_export_execution_snapshot(
                            signed_source=signed_source,
                            python_binding=python_binding,
                            environment={
                                "ASTER_GATE_H_SIGNED_CONTROLLER": "test"
                            },
                            raw_argv=raw_argv,
                            handoff=receipt["handoff"],
                            sentinel_sha256=receipt["sentinel_sha256"],
                            signature_anchor=receipt["signature_anchor"],
                            bootstrap_modules=bootstrap,
                        )
                finally:
                    sys.path.pop()
                tampered = repository / "lab/gate_h_source.py"
                tampered.write_bytes(b"x" * tampered.stat().st_size)
                with self.assertRaisesRegex(
                    experiment.ExperimentError, "source differs"
                ):
                    experiment.gate_h_bootstrap_module_bindings(signed_source)
                pycache = export / "lab/__pycache__"
                pycache.mkdir()
                (pycache / "gate_h_source.pyc").write_bytes(b"stale")
                with self.assertRaisesRegex(
                    experiment.ExperimentError, "contains Python bytecode"
                ):
                    experiment.gate_h_export_execution_snapshot(
                        signed_source=signed_source,
                        python_binding=python_binding,
                        environment={"ASTER_GATE_H_SIGNED_CONTROLLER": "test"},
                        raw_argv=raw_argv,
                        handoff=receipt["handoff"],
                        sentinel_sha256=receipt["sentinel_sha256"],
                        signature_anchor=receipt["signature_anchor"],
                        bootstrap_modules=bootstrap,
                    )

    def test_runner_records_a_bounded_command_timeout(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = experiment.Runner(Path(temporary), True)
            timeout = experiment.subprocess.TimeoutExpired(
                ["docker", "inspect", "wedged"], 120, output="partial"
            )
            with mock.patch.object(
                experiment, "bounded_subprocess_run", side_effect=timeout
            ):
                with self.assertRaisesRegex(
                    experiment.ExperimentError, "120-second deadline"
                ):
                    runner.run(["docker", "inspect", "wedged"])
            records = (
                Path(temporary) / "commands.jsonl"
            ).read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(records), 1)
            receipt = json.loads(records[0])
            self.assertEqual(receipt["returncode"], 124)
            self.assertEqual(receipt["stdout"], "partial")

    def test_runner_records_an_early_candidate_exit_exactly_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = experiment.Runner(Path(temporary), True)
            process = runner.popen(
                [sys.executable, "-c", "raise SystemExit(7)"]
            )
            self.assertEqual(runner.wait_process(process, 5, check=False), 7)
            result_path = process._aster_prefix.with_suffix(".result.json")
            receipt = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["returncode"], 7)
            self.assertFalse(receipt["timed_out"])
            with self.assertRaisesRegex(
                experiment.ExperimentError, "candidate node exited 7"
            ):
                runner.wait_process(process, 0)
            self.assertEqual(
                json.loads(result_path.read_text(encoding="utf-8")), receipt
            )

    def test_runner_terminates_and_receipts_every_owned_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = experiment.Runner(Path(temporary), True)
            process = runner.popen(
                [sys.executable, "-c", "import time; time.sleep(60)"]
            )
            runner.terminate_owned_processes()
            self.assertIsNotNone(process.poll())
            self.assertEqual(runner._owned_processes, {})
            result_path = process._aster_prefix.with_suffix(".result.json")
            receipt = json.loads(result_path.read_text(encoding="utf-8"))
            self.assertTrue(receipt["interrupted"])
            self.assertTrue(process._aster_stdout.closed)
            self.assertTrue(process._aster_stderr.closed)

    def test_bound_synchronous_command_is_reaped_and_receipted_on_ctrl_c(self):
        with tempfile.TemporaryDirectory() as temporary:
            environment = {"PATH": "/usr/bin:/bin"}
            runner = experiment.Runner(
                Path(temporary), True, environment=environment
            )
            interrupt = threading.Timer(
                0.05, lambda: os.kill(os.getpid(), signal.SIGINT)
            )
            original_signal_group = experiment._signal_process_group

            def signal_group_with_repeated_interrupt(process, signum):
                if signum == signal.SIGTERM:
                    os.kill(os.getpid(), signal.SIGINT)
                original_signal_group(process, signum)

            interrupt.start()
            try:
                with (
                    mock.patch.object(
                        experiment,
                        "_signal_process_group",
                        side_effect=signal_group_with_repeated_interrupt,
                    ),
                    self.assertRaises(KeyboardInterrupt) as caught,
                ):
                    runner.run(
                        [sys.executable, "-c", "import time; time.sleep(60)"],
                        timeout=120,
                    )
            finally:
                interrupt.join()
            self.assertIn(
                signal.SIGINT, caught.exception._aster_deferred_signals
            )
            records = (
                Path(temporary) / "commands.jsonl"
            ).read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(records), 1)
            receipt = json.loads(records[0])
            self.assertNotEqual(receipt["returncode"], 0)
            self.assertEqual(
                receipt["environment_sha256"],
                experiment.canonical_sha256(environment),
            )

    def test_main_finalizes_ctrl_c_and_sigterm_with_distinct_exit_codes(self):
        for interruption_name, expected_code, expected_error_type in (
            ("ctrl-c", 130, "ControlledInterruption"),
            ("sigterm", 143, "ControlledInterruption"),
        ):
            with self.subTest(expected_code=expected_code), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary)
                root = base / "evidence"
                binary = base / "aster-gate-h"
                binary.write_bytes(b"candidate")
                fault = base / "fault.json"
                fault.write_text("{}", encoding="utf-8")
                allowed_signers = base / "allowed-signers"
                allowed_signers.write_text(
                    "test@example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest\n",
                    encoding="utf-8",
                )
                environment = experiment.gate_h_host_environment(
                    root=root,
                    docker_host="unix:///tmp/gate-h-interrupt.sock",
                    home=base,
                )
                root.mkdir()
                Path(environment["DOCKER_CONFIG"]).mkdir()
                Path(environment["TMPDIR"]).mkdir()
                tools = {
                    "python": {
                        "path": str(Path(sys.executable).resolve()),
                        "invocation_path": str(Path(sys.executable).resolve()),
                    },
                    "docker": {
                        "path": str(Path("/bin/echo").resolve()),
                        "invocation_path": str(Path("/bin/echo").resolve()),
                    },
                    "docker_buildx": experiment._tool_file_binding(
                        Path("/bin/echo"), label="Docker buildx"
                    ),
                    "git": {
                        "path": str(Path("/usr/bin/git").resolve()),
                        "invocation_path": str(Path("/usr/bin/git").resolve()),
                    },
                }
                launched = []

                def interrupt_after_launch(runner):
                    experiment.install_gate_h_docker_buildx_plugin(runner)
                    write_gate_h_buildx_state(
                        root, Path(environment["DOCKER_CONFIG"])
                    )
                    runner.register_docker_resource(
                        "container",
                        "aster-mesh-0123abcd-t00-interrupt-owned",
                        owner="outer-interruption-test",
                    )
                    launched.append(
                        runner.popen(
                            [sys.executable, "-c", "import time; time.sleep(60)"]
                        )
                    )
                    signum = (
                        signal.SIGTERM
                        if interruption_name == "sigterm"
                        else signal.SIGINT
                    )
                    os.kill(os.getpid(), signum)
                    raise AssertionError("interruption handler returned")

                argv = [
                    "--arm",
                    "native",
                    "--scenario",
                    "gate-h",
                    "--binary",
                    str(binary),
                    "--root",
                    str(root),
                    "--trials",
                    "10",
                    "--payload-bytes",
                    "1048576",
                    "--duration-ms",
                    "6000",
                    "--image",
                    "aster-lab:test",
                    "--build-command",
                    experiment.gate_h_build_command("aster-lab:test"),
                    "--gate-h-fault-receipt",
                    str(fault),
                    "--docker-binary",
                    "/bin/echo",
                    "--docker-buildx-binary",
                    "/bin/echo",
                    "--git-binary",
                    "/usr/bin/git",
                    "--ssh-keygen-binary",
                    "/bin/echo",
                    "--ssh-binary",
                    "/bin/echo",
                    "--allowed-signers",
                    str(allowed_signers),
                    "--signer-principal",
                    "test@example",
                    "--docker-host",
                    "unix:///tmp/gate-h-interrupt.sock",
                    "--execute",
                ]
                freeze = {
                    "candidate_commit": "c" * 40,
                    "candidate_tree": "d" * 40,
                    "signature_status": "G",
                    "signature_signer": "test signer",
                    "signature_fingerprint": "test fingerprint",
                }
                signature_request = experiment.gate_h_signature.SignatureRequest(
                    git=Path("/usr/bin/git"),
                    ssh_keygen=Path("/bin/echo"),
                    ssh=Path("/bin/echo"),
                    allowed_signers=allowed_signers,
                    principal="test@example",
                )
                export_execution = {
                    "argv": [
                        tools["python"]["invocation_path"],
                        *experiment.GATE_H_PYTHON_FLAGS,
                        str(Path(experiment.__file__).resolve()),
                        *argv,
                    ]
                }
                with (
                    mock.patch.object(
                        experiment,
                        "gate_h_export_controller",
                        return_value=Path(experiment.__file__).resolve(),
                    ),
                    mock.patch.object(
                        experiment,
                        "ensure_gate_h_controller_environment",
                        return_value=(tools, environment),
                    ),
                    mock.patch.object(
                        experiment,
                        "load_gate_h_export_handoff",
                        return_value=(
                            export_execution,
                            signature_request,
                            {"principal": "test@example"},
                            {"passed": True},
                            freeze,
                            {"schema": experiment.gate_h_source.SCHEMA},
                            "f" * 64,
                            root / "gate-h-signed-source",
                        ),
                    ),
                    mock.patch.object(
                        experiment,
                        "collect_gate_h_host_execution",
                        return_value={"schema": experiment.GATE_H_HOST_EXECUTION_SCHEMA},
                    ),
                    mock.patch.object(
                        experiment.gate_h_signature,
                        "prepare_signature_trust",
                        return_value={"principal": "test@example"},
                    ),
                    mock.patch.object(
                        experiment.gate_h_signature,
                        "validate_signature_request_matches_trust",
                        return_value={"passed": True},
                    ),
                    mock.patch.object(experiment, "source_freeze", return_value=freeze),
                    mock.patch.object(
                        experiment.gate_h_source,
                        "materialize_signed_tree",
                        return_value={"schema": experiment.gate_h_source.SCHEMA},
                    ),
                    mock.patch.object(
                        experiment.gate_h_source,
                        "validate_signed_tree_receipt",
                        return_value=root / "gate-h-signed-source",
                    ),
                    mock.patch.object(
                        experiment,
                        "validate_gate_h_fault_receipt",
                        return_value={},
                    ),
                    mock.patch.object(
                        experiment,
                        "docker_available",
                        side_effect=interrupt_after_launch,
                    ),
                ):
                    self.assertEqual(experiment.main(argv), expected_code)
                self.assertEqual(len(launched), 1)
                self.assertIsNotNone(launched[0].poll())
                failure = json.loads((root / "failure.json").read_text())
                self.assertEqual(failure["error_type"], expected_error_type)
                final = json.loads(
                    (root / "gate-h-host-execution-final.json").read_text()
                )
                self.assertTrue(final["passed"])
                self.assertEqual(final["owned_processes"], 0)
                self.assertEqual(final["registered_docker_resources"], 0)
                self.assertTrue(final["docker_buildx_cleanup"]["plugin_removed"])
                self.assertTrue(
                    final["docker_buildx_cleanup"]["directory_removed"]
                )
                self.assertTrue(
                    final["docker_buildx_cleanup"]["state_cleanup"]["removed"]
                )
                self.assertEqual(
                    final["docker_buildx_cleanup"]["state_cleanup"]["inventory"][
                        "entry_count"
                    ],
                    11,
                )
                self.assertEqual(list(Path(environment["DOCKER_CONFIG"]).iterdir()), [])
                index = json.loads((root / "evidence-index.json").read_text())
                indexed = {entry["path"] for entry in index["entries"]}
                self.assertIn("failure.json", indexed)
                self.assertIn("gate-h-host-execution-final.json", indexed)
                self.assertIn("gate-h-resource-cleanup.jsonl", indexed)

    def test_buildx_state_is_bounded_hash_bound_and_removed_exactly(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            environment = experiment.gate_h_host_environment(
                root=root,
                docker_host="unix:///tmp/gate-h-buildx-state.sock",
                home=Path(temporary),
            )
            root.mkdir()
            docker_config = Path(environment["DOCKER_CONFIG"])
            docker_config.mkdir()
            Path(environment["TMPDIR"]).mkdir()
            runner = experiment.Runner(
                root,
                True,
                environment=environment,
                docker_binary="/bin/echo",
                docker_buildx_binding=experiment._tool_file_binding(
                    Path("/bin/echo"), label="Docker buildx"
                ),
            )
            experiment.install_gate_h_docker_buildx_plugin(runner)
            write_gate_h_buildx_state(root, docker_config)

            receipt = experiment.cleanup_gate_h_docker_buildx_plugin(runner)
            self.assertTrue(receipt["passed"])
            self.assertEqual(list(docker_config.iterdir()), [])
            state = receipt["state_cleanup"]
            self.assertTrue(state["present_before"])
            self.assertTrue(state["removed"])
            self.assertEqual(state["inventory"]["entry_count"], 11)
            self.assertEqual(
                state["inventory"]["entries_sha256"],
                experiment.canonical_sha256(state["inventory"]["entries"]),
            )
            self.assertEqual(
                experiment.cleanup_gate_h_docker_buildx_plugin(runner), receipt
            )

    def test_buildx_state_symlink_tamper_is_retained_and_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            environment = experiment.gate_h_host_environment(
                root=root,
                docker_host="unix:///tmp/gate-h-buildx-tamper.sock",
                home=Path(temporary),
            )
            root.mkdir()
            docker_config = Path(environment["DOCKER_CONFIG"])
            docker_config.mkdir()
            Path(environment["TMPDIR"]).mkdir()
            runner = experiment.Runner(
                root,
                True,
                environment=environment,
                docker_binary="/bin/echo",
                docker_buildx_binding=experiment._tool_file_binding(
                    Path("/bin/echo"), label="Docker buildx"
                ),
            )
            experiment.install_gate_h_docker_buildx_plugin(runner)
            write_gate_h_buildx_state(root, docker_config)
            state = docker_config / "buildx"
            (state / ".lock").unlink()
            os.symlink("/dev/null", state / ".lock")

            receipt = experiment.cleanup_gate_h_docker_buildx_plugin(runner)
            self.assertFalse(receipt["passed"])
            self.assertTrue(state.is_dir())
            self.assertTrue((state / ".lock").is_symlink())
            self.assertIn("contains a symlink", " ".join(receipt["errors"]))

    def test_normal_buildx_finalization_defers_sigint_and_sigterm_until_empty(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "evidence"
                environment = experiment.gate_h_host_environment(
                    root=root,
                    docker_host="unix:///tmp/gate-h-buildx-signal.sock",
                    home=Path(temporary),
                )
                root.mkdir()
                docker_config = Path(environment["DOCKER_CONFIG"])
                docker_config.mkdir()
                Path(environment["TMPDIR"]).mkdir()
                runner = experiment.Runner(
                    root,
                    True,
                    environment=environment,
                    docker_binary="/bin/echo",
                    docker_buildx_binding=experiment._tool_file_binding(
                        Path("/bin/echo"), label="Docker buildx"
                    ),
                )
                experiment.install_gate_h_docker_buildx_plugin(runner)
                write_gate_h_buildx_state(root, docker_config)
                cleanup = experiment._cleanup_gate_h_docker_buildx_state

                def interrupt_during_cleanup(value):
                    os.kill(os.getpid(), signum)
                    return cleanup(value)

                with (
                    mock.patch.object(
                        experiment,
                        "_cleanup_gate_h_docker_buildx_state",
                        side_effect=interrupt_during_cleanup,
                    ),
                    self.assertRaises(experiment.ControlledInterruption) as caught,
                ):
                    experiment.finalize_gate_h_host_execution_signal_safe(runner)
                self.assertEqual(caught.exception.signum, signum)
                self.assertEqual(list(docker_config.iterdir()), [])
                final = json.loads(
                    (root / "gate-h-host-execution-final.json").read_text()
                )
                self.assertTrue(final["passed"])
                self.assertTrue(
                    final["docker_buildx_cleanup"]["state_cleanup"]["removed"]
                )

    def test_failure_evidence_is_hash_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "manifest.json").write_text("{}\n", encoding="utf-8")
            args = argparse.Namespace(arm="native", scenario="primary")
            retained = experiment.finalize_failure_evidence(
                root, args, experiment.ExperimentError("candidate exited 7")
            )
            self.assertIsNotNone(retained)
            failure = json.loads((root / "failure.json").read_text(encoding="utf-8"))
            self.assertEqual(failure["error"], "candidate exited 7")
            index = json.loads(
                (root / "evidence-index.json").read_text(encoding="utf-8")
            )
            paths = {entry["path"] for entry in index["entries"]}
            self.assertEqual(paths, {"failure.json", "manifest.json"})
            self.assertEqual(
                retained["evidence_index_sha256"],
                experiment.sha256_file(root / "evidence-index.json"),
            )

    def test_late_interruption_appends_a_failure_specific_evidence_index(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "manifest.json").write_text("{}\n", encoding="utf-8")
            experiment.write_json(
                root / "evidence-index.json", experiment.evidence_index(root)
            )
            args = argparse.Namespace(arm="native", scenario="gate-h")
            retained = experiment.finalize_failure_evidence(
                root, args, KeyboardInterrupt()
            )
            failure_index = root / "failure-evidence-index.json"
            self.assertEqual(retained["evidence_index"], str(failure_index))
            value = json.loads(failure_index.read_text(encoding="utf-8"))
            paths = {entry["path"] for entry in value["entries"]}
            self.assertEqual(
                paths,
                {"evidence-index.json", "failure.json", "manifest.json"},
            )

    def test_gate_h_build_extracts_and_hash_binds_the_image_binary(self):
        class BuildRunner(experiment.Runner):
            def __init__(self, root, image_binary):
                super().__init__(root, True)
                self.image_binary = image_binary
                self.commands = []

            def run(self, command, **_kwargs):
                self.sequence += 1
                self.commands.append(command)
                stdout = ""
                if command[:3] == ["docker", "image", "inspect"]:
                    stdout = json.dumps(
                        [{"Id": "sha256:" + "b" * 64, "RepoDigests": []}]
                    )
                elif command[:2] == ["docker", "create"]:
                    stdout = "container-id\n"
                elif command[:2] == ["docker", "cp"]:
                    Path(command[-1]).write_bytes(self.image_binary)
                return experiment.subprocess.CompletedProcess(command, 0, stdout, "")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source-aster-lab"
            source.write_bytes(b"signed source binary")
            build_context = root / "signed-source"
            build_context.mkdir()
            runner = BuildRunner(root, source.read_bytes())
            image, metadata = experiment.build_and_verify_gate_h_binary(
                runner,
                image="aster-lab:validation",
                source_binary=source,
                candidate_commit="c" * 40,
                run_id="0123abcd",
                build_context=build_context,
                signed_source_sha256="f" * 64,
            )
            self.assertEqual(image["id"], "sha256:" + "b" * 64)
            self.assertEqual(metadata["binary_sha256"], experiment.sha256_file(source))
            self.assertEqual(
                runner.commands[0],
                experiment.gate_h_build_argv("aster-lab:validation"),
            )
            self.assertEqual(runner.commands[-1][:3], ["docker", "rm", "--force"])

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source-aster-lab"
            source.write_bytes(b"supplied")
            build_context = root / "signed-source"
            build_context.mkdir()
            runner = BuildRunner(root, b"different image binary")
            with self.assertRaisesRegex(experiment.ExperimentError, "differs"):
                experiment.build_and_verify_gate_h_binary(
                    runner,
                    image="aster-lab:validation",
                    source_binary=source,
                    candidate_commit="c" * 40,
                    run_id="0123abcd",
                    build_context=build_context,
                    signed_source_sha256="f" * 64,
                )
            self.assertEqual(runner.commands[-1][:3], ["docker", "rm", "--force"])

    def test_gate_h_extraction_defers_sigint_and_sigterm_until_removal(self):
        class InterruptBuildRunner(experiment.Runner):
            def __init__(self, root, image_binary, signum):
                super().__init__(root, True)
                self.image_binary = image_binary
                self.signum = signum
                self.commands = []
                self.timers = []
                self.interrupted_cleanup = False

            def run(self, command, **_kwargs):
                self.sequence += 1
                self.commands.append(command)
                stdout = ""
                if command[:3] == ["docker", "image", "inspect"]:
                    stdout = json.dumps(
                        [{"Id": "sha256:" + "b" * 64, "RepoDigests": []}]
                    )
                elif command[:2] == ["docker", "create"]:
                    stdout = "container-id\n"
                elif command[:2] == ["docker", "cp"]:
                    Path(command[-1]).write_bytes(self.image_binary)
                elif (
                    command[:3] == ["docker", "rm", "--force"]
                    and not self.interrupted_cleanup
                ):
                    self.interrupted_cleanup = True
                    for delay in (0.01, 0.02):
                        timer = threading.Timer(
                            delay,
                            lambda: os.kill(os.getpid(), self.signum),
                        )
                        timer.start()
                        self.timers.append(timer)
                    experiment.time.sleep(0.05)
                return experiment.subprocess.CompletedProcess(command, 0, stdout, "")

        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "source-aster-lab"
                source.write_bytes(b"signed source binary")
                build_context = root / "signed-source"
                build_context.mkdir()
                runner = InterruptBuildRunner(root, source.read_bytes(), signum)
                with self.assertRaises(experiment.ControlledInterruption) as caught:
                    experiment.build_and_verify_gate_h_binary(
                        runner,
                        image="aster-lab:validation",
                        source_binary=source,
                        candidate_commit="c" * 40,
                        run_id="0123abcd",
                        build_context=build_context,
                        signed_source_sha256="f" * 64,
                    )
                for timer in runner.timers:
                    timer.join()
                self.assertEqual(caught.exception.signum, signum)
                self.assertEqual(128 + caught.exception.signum, 130 if signum == signal.SIGINT else 143)
                self.assertEqual(runner._docker_resources, {})
                removals = [
                    command
                    for command in runner.commands
                    if command[:3] == ["docker", "rm", "--force"]
                ]
                self.assertEqual(
                    removals,
                    [["docker", "rm", "--force", "aster-mesh-0123abcd-t00-build-extract"]],
                )
                cleanup = [
                    json.loads(line)
                    for line in (root / "gate-h-resource-cleanup.jsonl")
                    .read_text(encoding="utf-8")
                    .splitlines()
                ]
                self.assertTrue(cleanup[-1]["passed"])
                self.assertEqual(cleanup[-1]["deferred_signals"], [signum])

    def test_named_gate_h_offline_interruptions_force_exact_cleanup(self):
        class OfflineRunner(experiment.Runner):
            def __init__(self, root, signum):
                super().__init__(root, True)
                self.signum = signum
                self.commands = []

            def run(self, command, **_kwargs):
                self.sequence += 1
                self.commands.append(command)
                if command[:3] == ["docker", "run", "--rm"]:
                    raise experiment.ControlledInterruption(self.signum)
                return experiment.subprocess.CompletedProcess(command, 0, "", "")

        cases = (
            (signal.SIGINT, "prepare", "mesh-prepare"),
            (signal.SIGTERM, "delivery", "mesh-consume"),
        )
        for signum, role, offline_command in cases:
            with self.subTest(role=role), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                trial_root = root / "trial-01"
                trial_root.mkdir()
                binary = root / "candidate-aster-lab"
                binary.write_bytes(b"candidate")
                args = argparse.Namespace(binary=binary, image="aster-lab:test")
                runner = OfflineRunner(root, signum)
                name = experiment.resource_name("0123abcd", 1, "offline", role)
                with self.assertRaises(experiment.ControlledInterruption) as caught:
                    experiment.run_offline(
                        runner,
                        args,
                        trial_root,
                        [offline_command, "--root", "/lab/run"],
                        container_name=name,
                    )
                self.assertEqual(caught.exception.signum, signum)
                self.assertEqual(runner._docker_resources, {})
                self.assertIn("--name", runner.commands[0])
                self.assertEqual(
                    runner.commands[-1], ["docker", "rm", "--force", name]
                )
                cleanup = json.loads(
                    (root / "gate-h-resource-cleanup.jsonl")
                    .read_text(encoding="utf-8")
                    .splitlines()[-1]
                )
                self.assertTrue(cleanup["passed"])
                self.assertEqual(cleanup["remaining_registered_resources"], 0)

    def test_daemon_errors_never_prove_registered_container_or_network_absent(self):
        class DaemonErrorRunner(experiment.Runner):
            def __init__(self, root):
                super().__init__(root, True)
                self.commands = []

            def run(self, command, **_kwargs):
                self.commands.append(command)
                returncode = 125 if "ls" in command else 1
                return experiment.subprocess.CompletedProcess(
                    command, returncode, "", "cannot connect to Docker daemon"
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = DaemonErrorRunner(root)
            container = "aster-mesh-0123abcd-t01-offline-prepare"
            network = "aster-mesh-0123abcd-t01-live-ab"
            runner.register_docker_resource("container", container, owner="offline")
            runner.register_docker_resource("network", network, owner="trial")
            receipt, cleanup_error = runner.cleanup_registered_docker_resources(
                reason="daemon-error-negative"
            )
            self.assertIsNone(cleanup_error)
            self.assertFalse(receipt["passed"])
            self.assertEqual(receipt["remaining_registered_resources"], 2)
            self.assertEqual(
                set(runner._docker_resources),
                {("container", container), ("network", network)},
            )
            enumerations = [command for command in runner.commands if "ls" in command]
            self.assertEqual(len(enumerations), 2)
            self.assertIn(f"name=^/{container}$", enumerations[1])
            self.assertIn(f"name=^{network}$", enumerations[0])

    def test_interrupted_offline_daemon_error_remains_registered(self):
        class InterruptedDaemonRunner(experiment.Runner):
            def __init__(self, root):
                super().__init__(root, True)
                self.commands = []

            def run(self, command, **_kwargs):
                self.commands.append(command)
                if command[:3] == ["docker", "run", "--rm"]:
                    raise experiment.ControlledInterruption(signal.SIGTERM)
                if "ls" in command:
                    return experiment.subprocess.CompletedProcess(
                        command, 125, "", "permission denied"
                    )
                return experiment.subprocess.CompletedProcess(
                    command, 1, "", "daemon unavailable"
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trial_root = root / "trial-01"
            trial_root.mkdir()
            binary = root / "candidate-aster-lab"
            binary.write_bytes(b"candidate")
            args = argparse.Namespace(binary=binary, image="aster-lab:test")
            runner = InterruptedDaemonRunner(root)
            name = experiment.resource_name("0123abcd", 1, "offline", "prepare")
            with self.assertRaises(experiment.ControlledInterruption) as caught:
                experiment.run_offline(
                    runner,
                    args,
                    trial_root,
                    ["mesh-prepare", "--root", "/lab/run"],
                    container_name=name,
                )
            self.assertEqual(caught.exception.signum, signal.SIGTERM)
            self.assertIn(("container", name), runner._docker_resources)
            receipt = json.loads(
                (root / "gate-h-resource-cleanup.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()[-1]
            )
            self.assertFalse(receipt["passed"])
            self.assertEqual(receipt["resources"][0]["absence_check"]["returncode"], 125)

    def test_gate_h_trial_finalization_defers_repeated_signals(self):
        class FinalizationRunner(experiment.Runner):
            def __init__(self, root, signum):
                super().__init__(root, True)
                self.signum = signum
                self.commands = []
                self.timers = []
                self.sent = False

            def run(self, command, **_kwargs):
                self.sequence += 1
                self.commands.append(command)
                if not self.sent:
                    self.sent = True
                    for delay in (0.01, 0.02):
                        timer = threading.Timer(
                            delay,
                            lambda: os.kill(os.getpid(), self.signum),
                        )
                        timer.start()
                        self.timers.append(timer)
                    experiment.time.sleep(0.05)
                return experiment.subprocess.CompletedProcess(command, 0, "", "")

        containers = tuple(
            f"aster-mesh-0123abcd-t01-gate-{role}" for role in ("a", "b", "c")
        )
        networks = (
            "aster-mesh-0123abcd-t01-live-ab",
            "aster-mesh-0123abcd-t01-live-bc",
        )
        for signum in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signum=signum), tempfile.TemporaryDirectory() as temporary:
                trial_root = Path(temporary)
                runner = FinalizationRunner(trial_root, signum)
                for name in containers:
                    runner.register_docker_resource("container", name, owner="trial")
                for name in networks:
                    runner.register_docker_resource("network", name, owner="trial")
                with self.assertRaises(experiment.ControlledInterruption) as caught:
                    experiment.finalize_gate_h_trial_resources(
                        runner,
                        trial_root=trial_root,
                        trial=1,
                        processes=(),
                        containers=containers,
                        networks=networks,
                        primary_error=None,
                    )
                for timer in runner.timers:
                    timer.join()
                self.assertEqual(caught.exception.signum, signum)
                self.assertEqual(runner._owned_processes, {})
                self.assertEqual(runner._docker_resources, {})
                receipt = json.loads(
                    (trial_root / "cleanup.json").read_text(encoding="utf-8")
                )
                self.assertTrue(receipt["passed"])
                self.assertEqual(len(receipt["commands"]), 5)
                self.assertEqual(len(runner.commands), 5)

    def test_gate_h_trial_finalization_rethrows_system_exit_after_cleanup(self):
        class ExitRunner(experiment.Runner):
            def __init__(self, root):
                super().__init__(root, True)
                self.commands = []
                self.injected = False

            def run(self, command, **_kwargs):
                self.commands.append(command)
                if not self.injected:
                    self.injected = True
                    raise SystemExit(19)
                return experiment.subprocess.CompletedProcess(command, 0, "", "")

        with tempfile.TemporaryDirectory() as temporary:
            trial_root = Path(temporary)
            runner = ExitRunner(trial_root)
            containers = tuple(
                f"aster-mesh-0123abcd-t01-gate-{role}"
                for role in ("a", "b", "c")
            )
            networks = (
                "aster-mesh-0123abcd-t01-live-ab",
                "aster-mesh-0123abcd-t01-live-bc",
            )
            for name in containers:
                runner.register_docker_resource("container", name, owner="trial")
            for name in networks:
                runner.register_docker_resource("network", name, owner="trial")
            with self.assertRaises(SystemExit) as caught:
                experiment.finalize_gate_h_trial_resources(
                    runner,
                    trial_root=trial_root,
                    trial=1,
                    processes=(),
                    containers=containers,
                    networks=networks,
                    primary_error=None,
                )
            self.assertEqual(caught.exception.code, 19)
            self.assertEqual(runner._docker_resources, {})
            receipt = json.loads(
                (trial_root / "cleanup.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(receipt["commands"]), 5)

    def test_gate_h_cleanup_retains_primary_and_cleanup_failures(self):
        class CleanupRunner:
            def __init__(self):
                self.commands = []

            def run(self, command, **_kwargs):
                self.commands.append(command)
                return experiment.subprocess.CompletedProcess(
                    command,
                    1 if command[-1].endswith("gate-b") else 0,
                    "",
                    "cleanup failed",
                )

        with tempfile.TemporaryDirectory() as temporary:
            trial_root = Path(temporary)
            runner = CleanupRunner()
            primary = experiment.ExperimentError("primary trial failure")
            with self.assertRaisesRegex(
                experiment.ExperimentError,
                "primary trial failure.*cleanup failed",
            ):
                experiment.cleanup_gate_h_resources(
                    runner,
                    trial_root=trial_root,
                    trial=1,
                    containers=(
                        "aster-mesh-0123abcd-t01-gate-a",
                        "aster-mesh-0123abcd-t01-gate-b",
                        "aster-mesh-0123abcd-t01-gate-c",
                    ),
                    networks=(
                        "aster-mesh-0123abcd-t01-live-ab",
                        "aster-mesh-0123abcd-t01-live-bc",
                    ),
                    primary_error=primary,
                )
            receipt = json.loads(
                (trial_root / "cleanup.json").read_text(encoding="utf-8")
            )
            self.assertFalse(receipt["passed"])
            self.assertEqual(receipt["primary_error"]["error"], str(primary))
            self.assertEqual(len(receipt["commands"]), 5)

    def test_gate_h_cleanup_does_not_replace_a_controlled_interruption(self):
        class InterruptCleanupRunner:
            def __init__(self):
                self.commands = []

            def run(self, command, **_kwargs):
                self.commands.append(command)
                return experiment.subprocess.CompletedProcess(
                    command,
                    1 if command[-1].endswith("gate-b") else 0,
                    "",
                    "cleanup failed",
                )

        with tempfile.TemporaryDirectory() as temporary:
            trial_root = Path(temporary)
            runner = InterruptCleanupRunner()
            interruption = KeyboardInterrupt()
            experiment.cleanup_gate_h_resources(
                runner,
                trial_root=trial_root,
                trial=1,
                containers=(
                    "aster-mesh-0123abcd-t01-gate-a",
                    "aster-mesh-0123abcd-t01-gate-b",
                    "aster-mesh-0123abcd-t01-gate-c",
                ),
                networks=(
                    "aster-mesh-0123abcd-t01-live-ab",
                    "aster-mesh-0123abcd-t01-live-bc",
                ),
                primary_error=interruption,
            )
            receipt = json.loads(
                (trial_root / "cleanup.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(receipt["commands"]), 5)
            self.assertFalse(receipt["passed"])
            self.assertEqual(receipt["primary_error"]["error_type"], "KeyboardInterrupt")

    def test_gate_h_cohort_requires_ten_strict_successes(self):
        experiment.require_clean_gate_h_cohort([{"passed": True}] * 10)
        for cohort in (
            [{"passed": True}] * 9,
            [{"passed": True}] * 9 + [{"passed": False}],
            [{"passed": True}] * 9 + [{"passed": 1}],
        ):
            with self.assertRaisesRegex(experiment.ExperimentError, "10/10"):
                experiment.require_clean_gate_h_cohort(cohort)

    def test_arm_network_ranges_are_disjoint(self):
        ranges = {
            arm: {
                experiment.network_spec(arm, trial, phase)[0]
                for trial in range(1, 31)
                for phase in ("ab", "bc")
            }
            for arm in experiment.ARMS
        }
        self.assertEqual(len(ranges["native"]), 60)
        self.assertEqual(len(ranges["iroh"]), 60)
        self.assertEqual(len(ranges["libp2p"]), 60)
        self.assertFalse(ranges["native"] & ranges["iroh"])
        self.assertFalse(ranges["native"] & ranges["libp2p"])
        self.assertFalse(ranges["iroh"] & ranges["libp2p"])

    def test_live_relay_uses_two_distinct_internal_segments(self):
        for arm in experiment.ARMS:
            live_ab = experiment.network_spec(arm, 1, "live-ab")[0]
            live_bc = experiment.network_spec(arm, 1, "live-bc")[0]
            self.assertNotEqual(live_ab, live_bc)
            self.assertTrue(live_ab.startswith("10.250."))
            self.assertTrue(live_bc.startswith("10.250."))

    def test_parser_accepts_the_live_relay_scenario(self):
        parsed = experiment.parser().parse_args(
            [
                "--arm",
                "native",
                "--scenario",
                "live-relay",
                "--binary",
                "/tmp/aster-lab",
                "--root",
                "/tmp/aster-evidence",
            ]
        )
        self.assertEqual(parsed.scenario, "live-relay")

    def test_parser_accepts_the_receive_only_scenario(self):
        parsed = experiment.parser().parse_args(
            [
                "--arm",
                "native",
                "--scenario",
                "receive-only",
                "--binary",
                "/tmp/aster-lab",
                "--root",
                "/tmp/aster-evidence",
            ]
        )
        self.assertEqual(parsed.scenario, "receive-only")

    def test_parser_accepts_only_native_gate_h(self):
        parsed = experiment.parser().parse_args(
            [
                "--arm",
                "native",
                "--scenario",
                "gate-h",
                "--binary",
                "/tmp/aster-lab",
                "--root",
                "/tmp/aster-evidence",
            ]
        )
        self.assertEqual(parsed.scenario, "gate-h")

    def test_network_counter_sums_every_non_loopback_interface(self):
        value = [
            {
                "ifname": "lo",
                "stats64": {"rx": {"bytes": 1000}, "tx": {"bytes": 1000}},
            },
            {
                "ifname": "eth0",
                "stats64": {"rx": {"bytes": 10}, "tx": {"bytes": 20}},
            },
            {
                "ifname": "eth1",
                "stats64": {"rx": {"bytes": 30}, "tx": {"bytes": 40}},
            },
        ]
        self.assertEqual(experiment.sum_non_loopback_network_bytes(value), 100)

    def test_inventory_fanout_is_bound_to_the_authenticated_source_contact(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            events = [
                {"event": "authenticated", "contact": 7, "peer": "a" * 64},
                {
                    "event": "admission_committed",
                    "contact": 7,
                    "peer": "a" * 64,
                },
                {
                    "event": "inventory_changed",
                    "contact": 7,
                    "contacts_planned": 1,
                },
                {
                    "event": "inventory_fanout_queued",
                    "contact": 7,
                    "contacts_queued": 1,
                },
            ]
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            self.assertEqual(
                experiment.inventory_fanout_from_peer(path, "a" * 64),
                {
                    "contact": 7,
                    "source_peer": "a" * 64,
                    "contacts_planned": 1,
                    "contacts_queued": 1,
                },
            )
            self.assertIsNone(
                experiment.inventory_fanout_from_peer(path, "b" * 64)
            )

            with path.open("a", encoding="utf-8") as stream:
                stream.write('{"event":"inventory_changed"')
            self.assertIsNotNone(
                experiment.inventory_fanout_from_peer(path, "a" * 64)
            )

            archived_events = json.loads(json.dumps(events))
            archived_events[1]["event"] = "admitted"
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in archived_events),
                encoding="utf-8",
            )
            self.assertIsNotNone(
                experiment.inventory_fanout_from_peer(path, "a" * 64)
            )

            path.write_text(
                "".join(
                    json.dumps(event) + "\n"
                    for event in events
                    if event.get("event")
                    not in ("admission_committed", "admitted")
                ),
                encoding="utf-8",
            )
            self.assertIsNone(
                experiment.inventory_fanout_from_peer(path, "a" * 64)
            )

    def test_admitted_contact_ids_accept_common_and_archived_events(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            events = [
                {
                    "event": "admission_committed",
                    "contact": 7,
                    "peer": "a" * 64,
                },
                {"event": "admitted", "contact": 9, "peer": "a" * 64},
                {"event": "admission_prepared", "contact": 11, "peer": "a" * 64},
                {
                    "event": "admission_committed",
                    "contact": 13,
                    "peer": "b" * 64,
                },
            ]
            path.write_text(
                "".join(json.dumps(event) + "\n" for event in events),
                encoding="utf-8",
            )
            self.assertEqual(
                experiment.admitted_contacts_from_peer(path, "a" * 64),
                {7, 9},
            )

    def test_upstream_pairs_require_exact_authentication_and_admission(self):
        first = {
            "identity": "a" * 64,
            "authenticated_peers": ["b" * 64],
            "admitted_peers": ["b" * 64],
            "unauthorized_peers": [],
            "candidates_discovered": 1,
        }
        second = {
            "identity": "b" * 64,
            "authenticated_peers": ["a" * 64],
            "admitted_peers": ["a" * 64],
            "unauthorized_peers": [],
            "candidates_discovered": 0,
        }
        experiment.validate_pair(
            first=first,
            second=second,
            expected_first="a" * 64,
            expected_second="b" * 64,
            arm="libp2p",
        )

        missing_admission = dict(first, admitted_peers=[])
        with self.assertRaises(experiment.ExperimentError):
            experiment.validate_pair(
                first=missing_admission,
                second=second,
                expected_first="a" * 64,
                expected_second="b" * 64,
                arm="libp2p",
            )
        with self.assertRaises(experiment.ExperimentError):
            experiment.validate_pair(
                first=missing_admission,
                second=second,
                expected_first="a" * 64,
                expected_second="b" * 64,
                arm="iroh",
            )

        relay_expected = {"a" * 64, "c" * 64}
        self.assertTrue(
            experiment.receipt_has_exact_peer_evidence(
                {
                    "authenticated_peers": sorted(relay_expected),
                    "admitted_peers": sorted(relay_expected),
                },
                relay_expected,
                arm="libp2p",
            )
        )
        self.assertFalse(
            experiment.receipt_has_exact_peer_evidence(
                {
                    "authenticated_peers": sorted(relay_expected),
                    "admitted_peers": ["a" * 64],
                },
                relay_expected,
                arm="libp2p",
            )
        )
        self.assertFalse(
            experiment.receipt_has_exact_peer_evidence(
                {
                    "authenticated_peers": sorted(relay_expected),
                    "admitted_peers": ["a" * 64],
                },
                relay_expected,
                arm="iroh",
            )
        )
        self.assertFalse(
            experiment.receipt_has_exact_peer_evidence(
                {"authenticated_peers": sorted(relay_expected)},
                relay_expected,
                arm="native",
            )
        )

    def test_native_shared_node_profile_is_fail_closed(self):
        receipt = native_shared_node_receipt()
        experiment.validate_provider_profile(
            receipt, arm="native", discovery_source=None
        )
        for field, value in {
            "durable_authority_open_count": 2,
            "sqlite_node_open_count": 2,
            "admitted_peers": ["invalid"],
            "node_resource_rejected_claims": -1,
        }.items():
            with self.subTest(field=field):
                with self.assertRaises(experiment.ExperimentError):
                    experiment.validate_provider_profile(
                        dict(receipt, **{field: value}),
                        arm="native",
                        discovery_source=None,
                    )

        invalid_order = json.loads(json.dumps(receipt))
        invalid_order["node_resource_high_water"]["frames"] = (
            invalid_order["node_resource_limits"]["frames"] + 1
        )
        with self.assertRaisesRegex(experiment.ExperimentError, "frames"):
            experiment.validate_provider_profile(
                invalid_order, arm="native", discovery_source=None
            )

        wrong_bytes = json.loads(json.dumps(receipt))
        wrong_bytes["node_resource_limits"]["inbound_bytes"] *= 2
        with self.assertRaisesRegex(experiment.ExperimentError, "byte ceilings"):
            experiment.validate_provider_profile(
                wrong_bytes, arm="native", discovery_source=None
            )

        inconsistent_rejections = json.loads(json.dumps(receipt))
        inconsistent_rejections["node_resource_rejections"]["frames"] = 1
        with self.assertRaisesRegex(experiment.ExperimentError, "per-category"):
            experiment.validate_provider_profile(
                inconsistent_rejections, arm="native", discovery_source=None
            )

        invalid_alias = json.loads(json.dumps(receipt))
        invalid_alias["frames_received"] += 1
        with self.assertRaisesRegex(experiment.ExperimentError, "aliases"):
            experiment.validate_provider_profile(
                invalid_alias, arm="native", discovery_source=None
            )

        no_generation_check = json.loads(json.dumps(receipt))
        no_generation_check["authorization_generation_checks"] = 0
        with self.assertRaisesRegex(experiment.ExperimentError, "no authorization"):
            experiment.validate_provider_profile(
                no_generation_check, arm="native", discovery_source=None
            )

    def test_native_live_status_allows_zero_checks_only_before_admission(self):
        def empty_live_status():
            value = json.loads(json.dumps(native_shared_node_receipt()))
            value["authorization_generation_checks"] = 0
            value["authenticated_peers"] = []
            value["admitted_peers"] = []
            value["admitted_contact_high_water"] = 0
            value["node_resource_current"]["admitted_contacts"] = 0
            value["node_resource_high_water"]["admitted_contacts"] = 0
            return value

        with tempfile.TemporaryDirectory() as temporary:
            trial_root = Path(temporary)
            role_root = trial_root / "a"
            role_root.mkdir()
            status_path = role_root / "native-mesh-pre-status.json"
            status = empty_live_status()
            status_path.write_text(json.dumps(status), encoding="utf-8")
            self.assertEqual(
                experiment.read_status_receipt(
                    trial_root, "a", "native", "pre"
                ),
                status,
            )

            tamper_cases = {
                "authenticated": ("authenticated_peers", ["b" * 64]),
                "admitted": ("admitted_peers", ["b" * 64]),
                "admitted-high-water": ("admitted_contact_high_water", 1),
            }
            for label, (field, value) in tamper_cases.items():
                with self.subTest(label=label):
                    invalid = empty_live_status()
                    invalid[field] = value
                    status_path.write_text(json.dumps(invalid), encoding="utf-8")
                    with self.assertRaisesRegex(
                        experiment.ExperimentError, "no authorization"
                    ):
                        experiment.read_status_receipt(
                            trial_root, "a", "native", "pre"
                        )

            for label, resource_field in (
                ("current-admission", "node_resource_current"),
                ("high-water-admission", "node_resource_high_water"),
            ):
                with self.subTest(label=label):
                    invalid = empty_live_status()
                    invalid[resource_field]["admitted_contacts"] = 1
                    if resource_field == "node_resource_current":
                        invalid["node_resource_high_water"][
                            "admitted_contacts"
                        ] = 1
                    status_path.write_text(json.dumps(invalid), encoding="utf-8")
                    with self.assertRaisesRegex(
                        experiment.ExperimentError, "no authorization"
                    ):
                        experiment.read_status_receipt(
                            trial_root, "a", "native", "pre"
                        )

            final_path = role_root / "native-mesh-pre-final.json"
            final_path.write_text(
                json.dumps(empty_live_status()), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                experiment.ExperimentError, "no authorization"
            ):
                experiment.read_final_receipt(
                    trial_root, "a", "native", "pre"
                )

    def test_exact_peer_polling_progresses_past_empty_live_status(self):
        identity = "a" * 64
        peer = "b" * 64
        empty = json.loads(json.dumps(native_shared_node_receipt()))
        empty.update(
            {
                "identity": identity,
                "authorization_generation_checks": 0,
                "authenticated_peers": [],
                "admitted_peers": [],
                "admitted_contact_high_water": 0,
            }
        )
        empty["node_resource_current"]["admitted_contacts"] = 0
        empty["node_resource_high_water"]["admitted_contacts"] = 0
        exact = json.loads(json.dumps(native_shared_node_receipt()))
        exact.update(
            {
                "identity": identity,
                "authenticated_peers": [peer],
                "admitted_peers": [peer],
            }
        )
        process = mock.Mock()
        process.poll.return_value = None
        with (
            mock.patch.object(
                experiment,
                "read_status_receipt",
                side_effect=[empty, exact],
            ) as read_status,
            mock.patch.object(experiment.time, "sleep"),
        ):
            elapsed = experiment.wait_for_exact_peer_sets(
                trial_root=Path("/unused"),
                arm="native",
                invocation="pre",
                identities={"a": identity},
                expected={"a": {peer}},
                processes={"a": process},
                timeout=1.0,
            )
        self.assertGreaterEqual(elapsed, 0)
        self.assertEqual(read_status.call_count, 2)

    def test_gate_h_native_receipt_requires_exact_clean_resource_accounting(self):
        receipt = native_shared_node_receipt()
        experiment.validate_gate_h_native_receipt(
            receipt, label="Gate-H test", expected_item_id="d" * 64
        )

        tamper_cases = (
            ("limit", "wrong exact", "node_resource_limits", "descriptors", 2),
            ("base", "provider base", "node_resource_current", "frames", 5_631),
            (
                "contact",
                "admitted-contact",
                "node_resource_high_water",
                "outbound_bytes",
                2 * 1_024 * 1_024 - 1,
            ),
        )
        for name, message, object_field, resource_field, value in tamper_cases:
            with self.subTest(name=name):
                invalid = json.loads(json.dumps(receipt))
                invalid[object_field][resource_field] = value
                with self.assertRaisesRegex(experiment.ExperimentError, message):
                    experiment.validate_gate_h_native_receipt(
                        invalid,
                        label="Gate-H test",
                        expected_item_id="d" * 64,
                    )

        dirty = json.loads(json.dumps(receipt))
        dirty["contact_failures"] = 1
        with self.assertRaisesRegex(experiment.ExperimentError, "not clean"):
            experiment.validate_gate_h_native_receipt(
                dirty, label="Gate-H test", expected_item_id="d" * 64
            )

        wrong_probe = json.loads(json.dumps(receipt))
        wrong_probe["durable_item_probe_id"] = "e" * 64
        with self.assertRaisesRegex(experiment.ExperimentError, "wrong durable ItemID"):
            experiment.validate_gate_h_native_receipt(
                wrong_probe, label="Gate-H test", expected_item_id="d" * 64
            )

        absent_probe = json.loads(json.dumps(receipt))
        absent_probe["durable_item_present"] = False
        with self.assertRaisesRegex(experiment.ExperimentError, "did not observe"):
            experiment.validate_gate_h_native_receipt(
                absent_probe, label="Gate-H test", expected_item_id="d" * 64
            )

    def test_native_live_durable_item_probe_is_exact_and_typed(self):
        item_id = bytes.fromhex("d" * 64)
        self.assertIsNone(
            experiment.native_status_durable_item_present(
                None, item_id, label="Gate-H live test"
            )
        )
        receipt = {
            "durable_item_probe_id": item_id.hex(),
            "durable_item_present": False,
        }
        self.assertFalse(
            experiment.native_status_durable_item_present(
                receipt, item_id, label="Gate-H live test"
            )
        )

        wrong = dict(receipt, durable_item_probe_id="e" * 64)
        with self.assertRaisesRegex(experiment.ExperimentError, "wrong durable ItemID"):
            experiment.native_status_durable_item_present(
                wrong, item_id, label="Gate-H live test"
            )
        untyped = dict(receipt, durable_item_present=None)
        with self.assertRaisesRegex(experiment.ExperimentError, "no typed"):
            experiment.native_status_durable_item_present(
                untyped, item_id, label="Gate-H live test"
            )

    def test_gate_h_prepared_control_is_bound_to_exact_private_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            control_bytes = b"signed authorization control"
            digest = experiment.hashlib.sha256(control_bytes).hexdigest()
            path = root / "b" / "gate-h-authorization-control.bin"
            path.parent.mkdir()
            path.write_bytes(control_bytes)
            path.chmod(0o600)
            prepare = {
                "authorization_control_id": digest,
                "authorization_control_subject": "9" * 64,
                "authorization_control_sha256": digest,
                "authorization_control_bytes": len(control_bytes),
            }
            identities = {"a": "a" * 64, "b": "b" * 64, "c": "c" * 64}
            self.assertEqual(
                experiment.prepared_gate_h_authorization_control(
                    prepare, root, identities
                ),
                prepare,
            )

            mismatched_id = dict(prepare, authorization_control_id="8" * 64)
            with self.assertRaisesRegex(experiment.ExperimentError, "control ID"):
                experiment.prepared_gate_h_authorization_control(
                    mismatched_id, root, identities
                )
            path.chmod(0o644)
            with self.assertRaisesRegex(experiment.ExperimentError, "mode 0600"):
                experiment.prepared_gate_h_authorization_control(
                    prepare, root, identities
                )

    def test_libp2p_provider_profiles_are_fail_closed_and_separate(self):
        provider_digest = "f" * 64
        protected = {
            "schema": experiment.LIBP2P_SHARED_NODE_SCHEMA,
            "provider_binary_sha256": provider_digest,
            "candidate_source": "aster-protected",
            "bounded_candidate_source": True,
            "protected_source_compiled_without_mdns": True,
            "libp2p_mdns": False,
            "libp2p_mdns_enabled": False,
            "mdns_rustsec_blocker": None,
            "provider_mdns_announcement_count_observable": False,
        }
        experiment.validate_provider_profile(
            protected,
            arm="libp2p",
            discovery_source="aster-protected",
            provider_binary_sha256=provider_digest,
        )
        invalid_protected_values = {
            "bounded_candidate_source": False,
            "protected_source_compiled_without_mdns": False,
            "libp2p_mdns": True,
            "libp2p_mdns_enabled": True,
            "mdns_rustsec_blocker": "RUSTSEC-2026-0119",
            "provider_mdns_announcement_count_observable": True,
        }
        for field, value in invalid_protected_values.items():
            with self.subTest(profile="aster-protected", field=field):
                invalid = dict(protected, **{field: value})
                with self.assertRaises(experiment.ExperimentError):
                    experiment.validate_provider_profile(
                        invalid,
                        arm="libp2p",
                        discovery_source="aster-protected",
                        provider_binary_sha256=provider_digest,
                    )
        with self.assertRaises(experiment.ExperimentError):
            experiment.validate_provider_profile(
                dict(protected, bounded_candidate_source=1),
                arm="libp2p",
                discovery_source="aster-protected",
                provider_binary_sha256=provider_digest,
            )

        provider_mdns = {
            "schema": experiment.LIBP2P_SHARED_NODE_SCHEMA,
            "provider_binary_sha256": provider_digest,
            "candidate_source": "provider-mdns",
            "bounded_candidate_source": False,
            "protected_source_compiled_without_mdns": False,
            "libp2p_mdns": True,
            "libp2p_mdns_enabled": True,
            "mdns_rustsec_blocker": "RUSTSEC-2026-0119",
            "provider_mdns_announcement_count_observable": False,
        }
        experiment.validate_provider_profile(
            provider_mdns,
            arm="libp2p",
            discovery_source="provider-mdns",
            provider_binary_sha256=provider_digest,
        )
        for field, value in {
            "bounded_candidate_source": True,
            "protected_source_compiled_without_mdns": True,
            "libp2p_mdns": False,
            "libp2p_mdns_enabled": None,
            "mdns_rustsec_blocker": None,
            "provider_mdns_announcement_count_observable": True,
        }.items():
            with self.subTest(profile="provider-mdns", field=field):
                invalid = dict(provider_mdns, **{field: value})
                with self.assertRaises(experiment.ExperimentError):
                    experiment.validate_provider_profile(
                        invalid,
                        arm="libp2p",
                        discovery_source="provider-mdns",
                        provider_binary_sha256=provider_digest,
                    )
        with self.assertRaises(experiment.ExperimentError):
            experiment.validate_provider_profile(
                provider_mdns,
                arm="libp2p",
                discovery_source="aster-protected",
                provider_binary_sha256=provider_digest,
            )

        for invalid in (
            dict(protected, schema="aster-lab-libp2p-mesh-node/v2"),
            dict(protected, provider_binary_sha256="0" * 64),
            dict(protected, provider_binary_sha256="not-a-digest"),
        ):
            with self.assertRaises(experiment.ExperimentError):
                experiment.validate_provider_profile(
                    invalid,
                    arm="libp2p",
                    discovery_source="aster-protected",
                    provider_binary_sha256=provider_digest,
                )

    def test_libp2p_status_and_final_receipts_bind_the_frozen_provider(self):
        provider_digest = "f" * 64
        receipt = {
            "schema": experiment.LIBP2P_SHARED_NODE_SCHEMA,
            "provider_binary_sha256": provider_digest,
            "candidate_source": "aster-protected",
            "bounded_candidate_source": True,
            "protected_source_compiled_without_mdns": True,
            "libp2p_mdns": False,
            "libp2p_mdns_enabled": False,
            "mdns_rustsec_blocker": None,
            "provider_mdns_announcement_count_observable": False,
        }
        with tempfile.TemporaryDirectory() as temporary:
            trial_root = Path(temporary) / "trial-01"
            node_root = trial_root / "a"
            node_root.mkdir(parents=True)
            prefix = node_root / "libp2p-mesh-t01-final-binding"
            (prefix.with_name(prefix.name + "-status.json")).write_text(
                json.dumps(receipt), encoding="utf-8"
            )
            (prefix.with_name(prefix.name + "-final.json")).write_text(
                json.dumps(receipt), encoding="utf-8"
            )
            self.assertEqual(
                experiment.read_status_receipt(
                    trial_root,
                    "a",
                    "libp2p",
                    "t01-final-binding",
                    discovery_source="aster-protected",
                    provider_binary_sha256=provider_digest,
                ),
                receipt,
            )
            self.assertEqual(
                experiment.read_final_receipt(
                    trial_root,
                    "a",
                    "libp2p",
                    "t01-final-binding",
                    discovery_source="aster-protected",
                    provider_binary_sha256=provider_digest,
                ),
                receipt,
            )
            with self.assertRaisesRegex(
                experiment.ExperimentError, "frozen provider"
            ):
                experiment.read_status_receipt(
                    trial_root,
                    "a",
                    "libp2p",
                    "t01-final-binding",
                    discovery_source="aster-protected",
                    provider_binary_sha256="0" * 64,
                )

    def test_iroh_provider_profiles_are_fail_closed_and_separate(self):
        protected = {
            "schema": "aster-lab-iroh-mesh-node/v2",
            "candidate_source": "aster-protected",
            "public_defaults": False,
            "pre_incoming_boundedness_blocker": experiment.IROH_PRE_INCOMING_BLOCKER,
            "phase1_scale_eligible": False,
            "iroh_mdns": False,
            "iroh_mdns_compiled": False,
            "mdns_boundedness_blocker": None,
            "requirements_eligible_discovery": True,
            "discovery_announcement_count_observable": True,
            "path_events_integrated": False,
        }
        experiment.validate_provider_profile(
            protected, arm="iroh", discovery_source="aster-protected"
        )
        for field, value in {
            "public_defaults": True,
            "pre_incoming_boundedness_blocker": "missing",
            "phase1_scale_eligible": True,
            "iroh_mdns": True,
            "iroh_mdns_compiled": True,
            "mdns_boundedness_blocker": (
                "uncapped-pre-host-iroh-mdns-address-cache-and-callback-tasks"
            ),
            "requirements_eligible_discovery": False,
            "discovery_announcement_count_observable": False,
            "path_events_integrated": None,
        }.items():
            with self.subTest(profile="aster-protected", field=field):
                invalid = dict(protected, **{field: value})
                with self.assertRaises(experiment.ExperimentError):
                    experiment.validate_provider_profile(
                        invalid,
                        arm="iroh",
                        discovery_source="aster-protected",
                    )

        provider_mdns = {
            "schema": "aster-lab-iroh-mesh-node/v2",
            "candidate_source": "provider-mdns",
            "public_defaults": False,
            "pre_incoming_boundedness_blocker": experiment.IROH_PRE_INCOMING_BLOCKER,
            "phase1_scale_eligible": False,
            "iroh_mdns": True,
            "iroh_mdns_compiled": True,
            "mdns_boundedness_blocker": (
                "uncapped-pre-host-iroh-mdns-address-cache-and-callback-tasks"
            ),
            "requirements_eligible_discovery": False,
            "discovery_announcement_count_observable": False,
            "path_events_integrated": False,
        }
        experiment.validate_provider_profile(
            provider_mdns, arm="iroh", discovery_source="provider-mdns"
        )
        for field, value in {
            "public_defaults": True,
            "pre_incoming_boundedness_blocker": "missing",
            "phase1_scale_eligible": True,
            "iroh_mdns": False,
            "iroh_mdns_compiled": False,
            "mdns_boundedness_blocker": None,
            "requirements_eligible_discovery": True,
            "discovery_announcement_count_observable": True,
            "path_events_integrated": None,
        }.items():
            with self.subTest(profile="provider-mdns", field=field):
                invalid = dict(provider_mdns, **{field: value})
                with self.assertRaises(experiment.ExperimentError):
                    experiment.validate_provider_profile(
                        invalid,
                        arm="iroh",
                        discovery_source="provider-mdns",
                    )
        with self.assertRaises(experiment.ExperimentError):
            experiment.validate_provider_profile(
                provider_mdns,
                arm="iroh",
                discovery_source="aster-protected",
            )

    def test_real_libp2p_pair_requires_exact_carrier_locator_coalescing(self):
        first = {
            "carrier_locator_aliases_coalesced": 1,
            "contact_failures": 0,
        }
        second = {
            "carrier_locator_aliases_coalesced": 0,
            "contact_failures": 0,
        }
        experiment.validate_libp2p_protected_alias_pair(first, second)

        with self.assertRaises(experiment.ExperimentError):
            experiment.validate_libp2p_protected_alias_pair(
                {
                    "carrier_locator_aliases_coalesced": 0,
                    "contact_failures": 0,
                },
                second,
            )
        with self.assertRaises(experiment.ExperimentError):
            experiment.validate_libp2p_protected_alias_pair(
                first,
                {
                    "carrier_locator_aliases_coalesced": 0,
                    "contact_failures": 1,
                },
            )

    def test_resource_names_are_run_and_trial_scoped(self):
        name = experiment.resource_name("0123abcd", 30, "bc", "c")
        self.assertEqual(name, "aster-mesh-0123abcd-t30-bc-c")
        self.assertRegex(name, experiment.RESOURCE)

    def test_candidate_process_drops_every_linux_capability(self):
        args = argparse.Namespace(
            arm="iroh",
            duration_ms=6_000,
            discovery_source="aster-protected",
        )
        command = experiment.node_exec_command(
            args=args,
            container="aster-mesh-0123abcd-t01-ab-a",
            invocation="t01_ab",
            expected_peer="a" * 64,
            broadcast="10.253.12.255",
        )
        self.assertIn("--bounding-set=-all", command)
        self.assertIn("--nnp", command)
        self.assertIn("--discovery-token", command)

    def test_iroh_command_uses_native_discovery_policy_and_explicit_bind(self):
        args = argparse.Namespace(
            arm="iroh",
            duration_ms=6_000,
            discovery_source="aster-protected",
        )
        endpoint_id = "a" * 52
        command = experiment.node_exec_command(
            args=args,
            container="aster-mesh-0123abcd-t01-ab-a",
            invocation="t01_ab",
            expected_peer="b" * 64,
            broadcast="10.253.12.255",
            discovery_enabled=False,
            manual_peers=f"{endpoint_id}@10.253.12.11:47101",
        )
        self.assertIn("--bind", command)
        self.assertEqual(command[command.index("--bind") + 1], "0.0.0.0:47101")
        self.assertEqual(
            command[command.index("--discovery-bind") + 1], "0.0.0.0:47102"
        )
        self.assertEqual(
            command[command.index("--discovery-target") + 1],
            "10.253.12.255:47102",
        )
        self.assertEqual(
            command[command.index("--discovery-source") + 1], "aster-protected"
        )
        self.assertIn("--discovery-enabled", command)
        self.assertIn("false", command)
        self.assertIn("--emission-mode", command)
        self.assertIn("normal", command)
        self.assertIn("--manual-peers", command)
        self.assertIn(endpoint_id, " ".join(command))
        self.assertIn("/lab/node/discovery.token", command)

    def test_iroh_literal_cohort_selects_only_provider_mdns(self):
        args = argparse.Namespace(
            arm="iroh",
            duration_ms=6_000,
            discovery_source="provider-mdns",
        )
        command = experiment.node_exec_command(
            args=args,
            container="aster-mesh-0123abcd-t01-ab-a",
            invocation="t01_ab",
            expected_peer="b" * 64,
            broadcast="10.253.12.255",
        )
        self.assertEqual(
            command[command.index("--discovery-source") + 1], "provider-mdns"
        )
        self.assertNotIn("aster-protected", command)
        self.assertNotIn("--discovery-token", command)
        self.assertNotIn("--discovery-bind", command)
        self.assertNotIn("--discovery-target", command)

    def test_native_command_uses_local_token_and_broadcast_only(self):
        args = argparse.Namespace(arm="native", duration_ms=6_000)
        command = experiment.node_exec_command(
            args=args,
            container="aster-mesh-0123abcd-t01-ab-a",
            invocation="t01_ab",
            expected_peer="b" * 64,
            broadcast="10.253.12.255",
        )
        self.assertIn("/lab/node/discovery.token", command)
        self.assertIn("10.253.12.255:47101", command)
        self.assertNotIn("10.253.12.10", command)
        self.assertNotIn("10.253.12.11", command)

    def test_native_manual_peer_keeps_data_emission_and_suppresses_discovery(self):
        args = argparse.Namespace(arm="native", duration_ms=6_000)
        peer = "b" * 64
        command = experiment.node_exec_command(
            args=args,
            container="aster-mesh-0123abcd-t01-manual-a",
            invocation="t01_manual",
            expected_peer=peer,
            broadcast="10.253.12.255",
            discovery_enabled=False,
            manual_peers=f"{peer}@10.253.12.11:47101",
        )
        self.assertEqual(command[command.index("--discovery-enabled") + 1], "false")
        self.assertEqual(command[command.index("--emission-mode") + 1], "normal")
        self.assertIn("--manual-peers", command)

    def test_libp2p_command_uses_protected_discovery_and_emission_policy(self):
        args = argparse.Namespace(
            arm="libp2p",
            duration_ms=6_000,
            discovery_source="aster-protected",
        )
        command = experiment.node_exec_command(
            args=args,
            container="aster-mesh-0123abcd-t01-ab-a",
            invocation="t01_ab",
            expected_peer="b" * 64,
            broadcast="10.253.12.255",
            discovery_enabled=False,
        )
        self.assertIn("/lab/node/discovery.token", command)
        self.assertIn("10.253.12.255:47101", command)
        self.assertIn("--emission-mode", command)
        self.assertIn("constrained", command)
        self.assertIn("--discovery-enabled", command)
        self.assertIn("false", command)
        self.assertEqual(
            command[command.index("--discovery-source") + 1], "aster-protected"
        )

    def test_libp2p_literal_cohort_selects_only_provider_mdns(self):
        args = argparse.Namespace(
            arm="libp2p",
            duration_ms=6_000,
            discovery_source="provider-mdns",
        )
        command = experiment.node_exec_command(
            args=args,
            container="aster-mesh-0123abcd-t01-ab-a",
            invocation="t01_ab",
            expected_peer="b" * 64,
            broadcast="10.253.12.255",
        )
        self.assertEqual(
            command[command.index("--discovery-source") + 1], "provider-mdns"
        )
        self.assertNotIn("aster-protected", command)
        self.assertNotIn("--discovery-token", command)
        self.assertNotIn("--discovery-target", command)

    def test_libp2p_manual_peer_disables_discovery_without_constraining_data(self):
        args = argparse.Namespace(
            arm="libp2p",
            duration_ms=6_000,
            discovery_source="aster-protected",
        )
        command = experiment.node_exec_command(
            args=args,
            container="aster-mesh-0123abcd-t01-manual-a",
            invocation="t01_manual",
            expected_peer="b" * 64,
            broadcast="10.253.12.255",
            discovery_enabled=False,
            manual_peers=f"{'b' * 64}@10.253.12.11:47101",
        )
        self.assertEqual(command[command.index("--discovery-enabled") + 1], "false")
        self.assertEqual(command[command.index("--emission-mode") + 1], "normal")
        self.assertIn("--manual-peers", command)

    def test_receive_only_command_suppresses_discovery_and_dial_policy(self):
        args = argparse.Namespace(
            arm="libp2p",
            duration_ms=6_000,
            discovery_source="aster-protected",
        )
        command = experiment.node_exec_command(
            args=args,
            container="aster-mesh-0123abcd-t01-receive-b",
            invocation="t01_receive",
            expected_peer="a" * 64,
            broadcast="10.253.12.255",
            discovery_enabled=False,
            manual_peers=f"{'a' * 64}@10.253.12.10:47101",
            emission_mode="receive-only",
        )
        self.assertEqual(command[command.index("--discovery-enabled") + 1], "false")
        self.assertEqual(command[command.index("--emission-mode") + 1], "receive-only")
        self.assertIn("--manual-peers", command)

    def test_receive_only_accepts_each_protected_discovery_counter_schema(self):
        self.assertEqual(
            experiment.protected_discovery_announcement_count(
                {"discovery_announcements": 0}
            ),
            0,
        )
        self.assertEqual(
            experiment.protected_discovery_announcement_count(
                {"protected_announcement_events_observed": 0}
            ),
            0,
        )
        with self.assertRaisesRegex(
            experiment.ExperimentError, "omits a protected-discovery"
        ):
            experiment.protected_discovery_announcement_count({})
        with self.assertRaisesRegex(experiment.ExperimentError, "malformed"):
            experiment.protected_discovery_announcement_count(
                {"protected_announcement_events_observed": False}
            )

    def test_unknown_emission_mode_is_rejected(self):
        args = argparse.Namespace(arm="native", duration_ms=6_000)
        with self.assertRaises(experiment.ExperimentError):
            experiment.node_exec_command(
                args=args,
                container="aster-mesh-0123abcd-t01-a",
                invocation="t01_invalid",
                expected_peer="b" * 64,
                broadcast="10.253.12.255",
                emission_mode="silent-ish",
            )

    def test_node_command_accepts_a_phase_duration_override(self):
        args = argparse.Namespace(arm="native", duration_ms=60_000)
        command = experiment.node_exec_command(
            args=args,
            container="aster-mesh-0123abcd-t01-a",
            invocation="t01_gate_pre",
            expected_peer="b" * 64,
            broadcast="10.250.12.255",
            duration_ms=6_000,
        )
        duration_index = command.index("--duration-ms")
        self.assertEqual(command[duration_index + 1], "6000")

    def test_gate_h_commands_keep_c_alive_across_b_restart(self):
        duration_ms = 6_000
        durations = experiment.gate_h_process_durations(duration_ms)
        self.assertEqual(
            durations,
            {
                "a_pre": 6_000,
                "b_pre": 6_000,
                "c_continuous": 17_000,
                "b_post": 6_000,
            },
        )
        identities = {"a": "a" * 64, "c": "c" * 64}
        addresses = {"a": "10.250.12.10", "c": "10.250.13.11"}
        relay_manual_peers = experiment.gate_h_relay_manual_peers(
            identities, addresses
        )
        self.assertEqual(
            relay_manual_peers,
            f"{'a' * 64}@10.250.12.10:47101,{'c' * 64}@10.250.13.11:47101",
        )
        args = argparse.Namespace(arm="native", duration_ms=duration_ms)
        commands = {
            phase: experiment.node_exec_command(
                args=args,
                container=f"aster-mesh-0123abcd-t01-gate-{phase}",
                invocation="t01_gate",
                expected_peer="b" * 64,
                broadcast="10.250.12.255",
                duration_ms=value,
            )
            for phase, value in durations.items()
        }
        self.assertEqual(
            {
                phase: int(command[command.index("--duration-ms") + 1])
                for phase, command in commands.items()
            },
            durations,
        )
        relay_command = experiment.node_exec_command(
            args=args,
            container="aster-mesh-0123abcd-t01-gate-b",
            invocation="t01_gate_pre",
            expected_peer=f"{'a' * 64},{'c' * 64}",
            broadcast="10.250.12.255",
            discovery_enabled=False,
            manual_peers=relay_manual_peers,
            emission_mode="flash-only",
            duration_ms=durations["b_pre"],
            gate_h_control=experiment.GATE_H_CONTROL_PATH,
            gate_h_stale_target_peer="c" * 64,
            durable_item_probe="d" * 64,
        )
        self.assertEqual(
            relay_command[relay_command.index("--manual-peers") + 1],
            relay_manual_peers,
        )
        self.assertEqual(
            relay_command[relay_command.index("--emission-mode") + 1],
            "flash-only",
        )
        self.assertEqual(
            relay_command[relay_command.index("--gate-h-control") + 1],
            experiment.GATE_H_CONTROL_PATH,
        )
        self.assertEqual(
            relay_command[relay_command.index("--durable-item-probe") + 1],
            "d" * 64,
        )
        with self.assertRaisesRegex(experiment.ExperimentError, "reserved"):
            experiment.node_exec_command(
                args=args,
                container="aster-mesh-0123abcd-t01-gate-b",
                invocation="t01_gate_pre",
                expected_peer=f"{'a' * 64},{'c' * 64}",
                broadcast="10.250.12.255",
                emission_mode="flash-only",
            )

    def test_libp2p_nodes_mount_and_execute_the_frozen_provider_binary(self):
        class RecordingRunner:
            def __init__(self):
                self.commands = []

            def run(self, command, **_kwargs):
                self.commands.append(command)
                return None

        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common = base / "candidate-aster-lab"
            provider = base / "candidate-aster-libp2p-node"
            common.write_bytes(b"common")
            provider.write_bytes(b"provider")
            runner = RecordingRunner()
            args = argparse.Namespace(
                arm="libp2p",
                binary=common,
                provider_binary=provider,
                capture=False,
                image="aster-lab:validation",
                duration_ms=6_000,
                discovery_source="aster-protected",
            )
            name = experiment.create_node_container(
                runner,
                args=args,
                run_id="0123abcd",
                trial=1,
                phase="manual",
                role="a",
                node_root=base / "a",
                bundle=base / "a.bundle",
                network="aster-mesh-0123abcd-t01-manual",
                address="10.253.152.10",
                gateway="10.253.152.1",
            )
            create_command = runner.commands[0]
            self.assertEqual(
                create_command.count(
                    f"type=bind,src={common.resolve()},dst=/experiment/aster-lab,readonly"
                ),
                1,
            )
            self.assertEqual(
                create_command.count(
                    f"type=bind,src={provider.resolve()},"
                    "dst=/experiment/aster-libp2p-node,readonly"
                ),
                1,
            )
            self.assertEqual(
                create_command[create_command.index("--entrypoint") + 1],
                "/usr/bin/sleep",
            )
            libp2p_command = experiment.node_exec_command(
                args=args,
                container=name,
                invocation="t01_manual",
                expected_peer="b" * 64,
                broadcast="10.253.152.255",
            )
            self.assertIn("/experiment/aster-libp2p-node", libp2p_command)
            self.assertNotIn("/experiment/aster-lab", libp2p_command)
            native_command = experiment.node_exec_command(
                args=argparse.Namespace(arm="native", duration_ms=6_000),
                container=name,
                invocation="t01_manual",
                expected_peer="b" * 64,
                broadcast="10.253.12.255",
            )
            self.assertIn("/experiment/aster-lab", native_command)
            self.assertNotIn("/experiment/aster-libp2p-node", native_command)

    def test_input_rejects_an_existing_evidence_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "aster-lab"
            binary.write_bytes(b"binary")
            args = argparse.Namespace(
                root=root,
                binary=binary,
                trials=1,
                duration_ms=6_000,
            )
            with self.assertRaises(experiment.ExperimentError):
                experiment.validate_input(args)

    def test_payload_validation_accepts_one_mib_and_rejects_larger_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binary = base / "aster-lab"
            binary.write_bytes(b"binary")
            args = argparse.Namespace(
                root=base / "new-evidence",
                binary=binary,
                trials=1,
                payload_bytes=1_048_576,
                scenario="primary",
                arm="native",
                duration_ms=6_000,
                settle_ms=1_000,
            )
            experiment.validate_input(args)
            args.payload_bytes = 1_048_577
            with self.assertRaises(experiment.ExperimentError):
                experiment.validate_input(args)

    def test_gate_h_requires_native_and_a_full_phase_window(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binary = base / "aster-lab"
            binary.write_bytes(b"binary")
            fault_receipt = base / "fault.json"
            fault_receipt.write_text("{}", encoding="utf-8")
            args = argparse.Namespace(
                root=base / "new-evidence",
                binary=binary,
                trials=10,
                payload_bytes=1_048_576,
                scenario="gate-h",
                arm="native",
                duration_ms=6_000,
                settle_ms=1_000,
                discovery_source=None,
                gate_h_fault_receipt=fault_receipt,
                execute=False,
                image="aster-lab:validation",
                build_command=None,
                docker_binary=Path("/bin/echo"),
                docker_buildx_binary=Path("/bin/echo"),
                git_binary=Path("/usr/bin/git"),
                ssh_keygen_binary=Path("/usr/bin/ssh-keygen"),
                ssh_binary=Path("/usr/bin/ssh"),
                allowed_signers=base / "allowed-signers",
                signer_principal="test@example",
                docker_host="unix:///tmp/gate-h-test.sock",
            )
            args.allowed_signers.write_text(
                "test@example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest\n",
                encoding="utf-8",
            )
            experiment.validate_input(args)
            args.execute = True
            args.build_command = experiment.gate_h_build_command(args.image)
            experiment.validate_input(args)
            args.build_command = "cargo build --release -p aster-lab"
            with self.assertRaisesRegex(experiment.ExperimentError, "allowlisted"):
                experiment.validate_input(args)
            args.execute = False
            args.build_command = None
            args.arm = "libp2p"
            args.discovery_source = "aster-protected"
            with self.assertRaisesRegex(experiment.ExperimentError, "provider-free"):
                experiment.validate_input(args)
            args.arm = "native"
            args.discovery_source = None
            args.duration_ms = 5_999
            with self.assertRaisesRegex(experiment.ExperimentError, "at least 6000"):
                experiment.validate_input(args)

    def test_dual_binary_inputs_are_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            common = base / "aster-lab"
            provider = base / "aster-libp2p-node"
            common.write_bytes(b"common")
            provider.write_bytes(b"provider")
            args = argparse.Namespace(
                root=base / "new-evidence",
                binary=common,
                provider_binary=provider,
                provider_build_command="cargo build --release -p aster-libp2p-node",
                build_command="cargo build --release -p aster-lab",
                execute=True,
                trials=1,
                payload_bytes=1_024,
                scenario="primary",
                arm="libp2p",
                duration_ms=6_000,
                settle_ms=1_000,
                discovery_source="aster-protected",
                gate_h_fault_receipt=None,
            )
            experiment.validate_input(args)

            args.provider_binary = None
            with self.assertRaisesRegex(experiment.ExperimentError, "provider-binary"):
                experiment.validate_input(args)
            args.provider_binary = common
            with self.assertRaisesRegex(experiment.ExperimentError, "distinct"):
                experiment.validate_input(args)
            args.provider_binary = provider
            args.provider_build_command = " "
            with self.assertRaisesRegex(
                experiment.ExperimentError, "provider-build-command"
            ):
                experiment.validate_input(args)
            args.provider_build_command = None
            args.execute = False
            args.arm = "native"
            args.discovery_source = None
            with self.assertRaisesRegex(experiment.ExperimentError, "only to --arm"):
                experiment.validate_input(args)

    def test_upstream_validation_requires_one_explicit_discovery_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            binary = base / "aster-lab"
            binary.write_bytes(b"binary")
            provider_binary = base / "aster-libp2p-node"
            provider_binary.write_bytes(b"provider")
            args = argparse.Namespace(
                root=base / "new-evidence",
                binary=binary,
                trials=1,
                payload_bytes=1_024,
                scenario="primary",
                arm="libp2p",
                duration_ms=6_000,
                settle_ms=1_000,
                discovery_source=None,
            )
            for arm in ("iroh", "libp2p"):
                args.arm = arm
                args.provider_binary = provider_binary if arm == "libp2p" else None
                args.provider_build_command = None
                args.execute = False
                args.discovery_source = None
                with self.assertRaises(experiment.ExperimentError):
                    experiment.validate_input(args)
                args.discovery_source = "provider-mdns"
                experiment.validate_input(args)
                args.discovery_source = "aster-protected"
                experiment.validate_input(args)

    def test_durable_probe_matches_only_the_exact_item_id(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state.sqlite"
            connection = sqlite3.connect(database)
            connection.execute("CREATE TABLE items (item_id BLOB PRIMARY KEY)")
            expected = bytes(range(32))
            connection.execute("INSERT INTO items(item_id) VALUES (?)", (expected,))
            connection.commit()
            connection.close()
            self.assertTrue(experiment.durable_item_present(database, expected))
            self.assertFalse(experiment.durable_item_present(database, bytes(reversed(expected))))


if __name__ == "__main__":
    unittest.main()
