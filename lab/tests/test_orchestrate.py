import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).resolve().parents[1] / "orchestrate.py"
SPEC = importlib.util.spec_from_file_location("aster_lab_orchestrate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
orchestrate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = orchestrate
SPEC.loader.exec_module(orchestrate)


class ControllerTests(unittest.TestCase):
    def context(self, root: Path):
        return orchestrate.RunContext(
            label="test",
            run_id="0123456789abcdef",
            run_dir=root,
            resources=[],
            runner=orchestrate.CommandRunner(root),
            image_id="sha256:" + "a" * 64,
        )

    def test_fixed_networks_are_disjoint_and_namespaced(self):
        specs = orchestrate.network_specs(
            [orchestrate.DIRECT_SPEC, *orchestrate.NAT_NETWORKS.values()]
        )
        self.assertEqual(len(specs), 4)
        self.assertTrue(all(spec.name.startswith("aster-lab-") for spec in specs))

    def test_transfer_can_disable_restart_but_blob_cannot(self):
        transfer = orchestrate.parser().parse_args(
            ["self-contained", "transfer", "--restart-after-frames", "0"]
        )
        self.assertEqual(transfer.restart_after_frames, 0)
        blob = orchestrate.parser().parse_args(
            ["self-contained", "blob-recovery", "--restart-after-frames", "0"]
        )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.run_self_contained(blob)

    def test_run_command_is_pull_never_and_minimum_capability(self):
        with tempfile.TemporaryDirectory() as temporary:
            args = orchestrate.container_run_args(
                self.context(Path(temporary)),
                name="aster-lab-transfer",
                role="transfer",
                command=["transfer", "--root", "/output/run"],
            )
        self.assertIn("--pull=never", args)
        self.assertIn("--cap-drop=ALL", args)
        self.assertIn("--security-opt=no-new-privileges", args)
        self.assertNotIn("--privileged", args)
        self.assertNotIn("--cap-add", args)
        self.assertIn("sha256:" + "a" * 64, args)
        self.assertNotIn(orchestrate.IMAGE, args)

    def test_cleanup_rejects_name_outside_exact_allowlist(self):
        resource = orchestrate.PlannedResource(
            "container", "aster-lab-not-allowlisted", "test"
        )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_cleanup_resource(resource, "0123456789abcdef")

    def test_cleanup_accepts_exact_resource_and_run_id(self):
        resource = orchestrate.PlannedResource(
            "network", orchestrate.DIRECT_NETWORK, "direct"
        )
        orchestrate.validate_cleanup_resource(resource, "0123456789abcdef")

    def test_restrictive_nat_rules_allow_only_wan_infrastructure(self):
        rules = orchestrate.nft_rules(
            profile="restrictive",
            lan_if="eth0",
            wan_if="eth1",
            lan_subnet="10.250.1.0/24",
            node_ip="10.250.1.10",
            external_ip="10.250.0.11",
        )
        self.assertIn("10.250.0.20 udp dport 4476 counter accept", rules)
        self.assertIn("10.250.0.20 tcp dport 4477 counter accept", rules)
        self.assertNotIn("dnat to", rules)

    def test_both_dockerignore_files_are_identical_deny_all_policies(self):
        workspace = MODULE_PATH.parents[1]
        self.assertEqual(
            (workspace / ".dockerignore").read_text(encoding="utf-8"),
            orchestrate.EXPECTED_DOCKERIGNORE,
        )
        self.assertEqual(
            (workspace / "lab" / "Dockerfile.dockerignore").read_text(encoding="utf-8"),
            orchestrate.EXPECTED_DOCKERIGNORE,
        )

    def test_runtime_package_inventory_is_exact_and_canonical(self):
        value = """tcpdump\t4.99.3-1
procps\t2:4.0.2-3
nftables\t1.0.6-2
iputils-ping\t3:20221126-1
iproute2\t6.1.0-3
"""
        self.assertEqual(
            orchestrate.canonical_runtime_package_inventory(value),
            """iproute2\t6.1.0-3
iputils-ping\t3:20221126-1
nftables\t1.0.6-2
procps\t2:4.0.2-3
tcpdump\t4.99.3-1
""",
        )

    def test_runtime_package_inventory_rejects_missing_or_unadmitted_rows(self):
        with self.assertRaises(orchestrate.LabError):
            orchestrate.canonical_runtime_package_inventory(
                "iproute2\t6.1.0-3\niputils-ping\t3:20221126-1\n"
            )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.canonical_runtime_package_inventory(
                """iproute2\t6.1.0-3
iputils-ping\t3:20221126-1
nftables\t1.0.6-2
procps\t2:4.0.2-3
tcpdump\t4.99.3-1
curl\t8.0
"""
            )

    def test_public_provision_manifest_parser_never_requires_secret_paths(self):
        manifest = """ASTER_LAB_NODE_MANIFEST\tversion=1\ttopic=lab.live-ip\tscope=lab/live-ip\tnodes=2
index\tserial\tnode_id
0\t1\taaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
1\t2\tbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.tsv"
            path.write_text(manifest, encoding="utf-8")
            records = orchestrate.parse_provision_manifest(path, 2)
        self.assertEqual(records[0]["identity"], "a" * 64)
        self.assertNotIn("credential", records[0])

    def test_reopened_runner_continues_command_sequence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "commands.jsonl").write_text(
                '{"sequence":1}\n{"sequence":7}\n', encoding="utf-8"
            )
            (root / "command-0009.stdout").write_text("orphan", encoding="utf-8")
            runner = orchestrate.CommandRunner(root)
        self.assertEqual(runner.sequence, 9)

    def test_role_mounts_never_expose_run_root_or_peer_bundle(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            node_output = orchestrate.create_output_directory(context, "node-a")
            private = root / "outputs" / "provision" / "private"
            private.mkdir(parents=True, mode=0o700)
            own_bundle = private / "node-0000.bundle"
            peer_bundle = private / "node-0001.bundle"
            own_bundle.write_bytes(b"own")
            peer_bundle.write_bytes(b"peer")
            own_bundle.chmod(0o600)
            peer_bundle.chmod(0o600)
            arguments = orchestrate.container_run_args(
                context,
                name="aster-lab-node-a",
                role="node-a",
                command=["node-udp", "--root", "/output"],
                output_dir=node_output,
                read_only_mounts=[(own_bundle, "/run/secrets/node.bundle")],
            )
        mounts = [
            arguments[index + 1]
            for index, value in enumerate(arguments[:-1])
            if value == "--mount"
        ]
        self.assertEqual(len(mounts), 2)
        self.assertIn(f"src={node_output.resolve()},dst=/output", mounts[0])
        self.assertIn(f"src={own_bundle.resolve()},dst=/run/secrets/node.bundle,readonly", mounts[1])
        self.assertNotIn(str(peer_bundle.resolve()), "\n".join(mounts))
        self.assertNotIn(f"src={root.resolve()},", "\n".join(mounts))

    def test_mount_confinement_rejects_run_root_and_outside(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            with self.assertRaises(orchestrate.LabError):
                orchestrate.confined_run_path(context, root)
            with self.assertRaises(orchestrate.LabError):
                orchestrate.confined_run_path(context, root.parent / "outside")

    def test_container_requires_preflight_immutable_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            context.image_id = None
            with self.assertRaises(orchestrate.LabError):
                orchestrate.container_run_args(
                    context,
                    name="aster-lab-transfer",
                    role="transfer",
                    command=["transfer", "--root", "/output/run"],
                )

    def test_timeout_preserves_partial_streams_and_sequence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = orchestrate.CommandRunner(root)
            timeout = subprocess.TimeoutExpired(
                cmd=["program"], timeout=1, output="partial-out", stderr="partial-err"
            )
            with mock.patch.object(orchestrate.subprocess, "run", side_effect=timeout):
                with self.assertRaises(orchestrate.LabError):
                    runner.run(["program"], timeout=1)
            self.assertEqual((root / "command-0001.stdout").read_text(), "partial-out")
            self.assertEqual((root / "command-0001.stderr").read_text(), "partial-err")
            receipt = json.loads((root / "commands.jsonl").read_text().strip())
            self.assertTrue(receipt["timed_out"])
            self.assertEqual(receipt["sequence"], 1)

    def test_async_command_records_ordered_start_and_completion(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = orchestrate.CommandRunner(root)
            process = mock.Mock()
            process.poll.return_value = 0
            process.wait.return_value = 0
            process.returncode = 0
            with mock.patch.object(orchestrate.subprocess, "Popen", return_value=process):
                running = runner.start(["docker", "exec", "aster-lab-resource", "workload"])
                self.assertEqual(running.finish(), 0)
            receipts = [
                json.loads(line)
                for line in (root / "commands.jsonl").read_text().splitlines()
            ]
        self.assertEqual([item["phase"] for item in receipts], ["started", "completed"])
        self.assertEqual({item["sequence"] for item in receipts}, {1})

    def test_terminal_resource_sample_does_not_require_process_rss(self):
        sample = {
            "memory.current": "1",
            "memory.max": str(64 * 1024 * 1024),
            "memory.peak": "2",
            "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0",
            "memory.stat": "anon 1",
            "memory.swap.current": "0",
            "memory.swap.max": "0",
            "cpu.stat": "usage_usec 1",
            "cpu.pressure_available": True,
            "cpu.pressure": "some avg10=0.00 avg60=0.00 avg300=0.00 total=0",
            "io.stat": "8:0 rbytes=1 wbytes=2",
            "pids.current": "1",
            "pids.events": "max 0",
            "docker_stats": {"MemUsage": "1MiB / 64MiB"},
        }
        orchestrate.validate_resource_sample(
            sample, 64 * 1024 * 1024, require_process=False
        )

    def test_metrics_cross_check_is_type_strict(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            metrics_root = root / "outputs" / "scale" / "run"
            metrics_root.mkdir(parents=True)
            (metrics_root / "metrics.json").write_text(
                json.dumps(
                    {
                        "schema": "aster-lab-metrics/v1",
                        "converged": True,
                        "nodes": True,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(orchestrate.LabError):
                orchestrate.scenario_metrics(
                    self.context(root), "outputs/scale/run", {"nodes": 1}
                )

    def test_resource_sample_rejects_oom_and_accepts_complete_values(self):
        sample = {
            "memory.current": "1",
            "memory.max": str(64 * 1024 * 1024),
            "memory.peak": "2",
            "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0",
            "memory.stat": "anon 1",
            "memory.swap.current": "0",
            "memory.swap.max": "0",
            "cpu.stat": "usage_usec 1",
            "cpu.pressure_available": True,
            "cpu.pressure": "some avg10=0.00 avg60=0.00 avg300=0.00 total=0",
            "io.stat": "8:0 rbytes=1 wbytes=2 rios=1 wios=1",
            "pids.current": "1",
            "pids.events": "max 0",
            "smaps_rollup": "Rss: 1 kB",
            "status": "Name:\taster-lab",
            "docker_stats": {"MemUsage": "1MiB / 64MiB"},
        }
        orchestrate.validate_resource_sample(sample, 64 * 1024 * 1024)
        sample["memory.events"] = "oom 1\noom_kill 0"
        with self.assertRaises(orchestrate.LabError):
            orchestrate.validate_resource_sample(sample, 64 * 1024 * 1024)

    def test_resource_sample_accepts_explicitly_unavailable_cpu_pressure(self):
        sample = {
            "memory.current": "1",
            "memory.max": str(64 * 1024 * 1024),
            "memory.peak": "2",
            "memory.events": "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0",
            "memory.stat": "anon 1",
            "memory.swap.current": "0",
            "memory.swap.max": "0",
            "cpu.stat": "usage_usec 1",
            "cpu.pressure_available": False,
            "cpu.pressure": None,
            "io.stat": "8:0 rbytes=1 wbytes=2 rios=1 wios=1",
            "pids.current": "1",
            "pids.events": "max 0",
            "smaps_rollup": "Rss: 1 kB",
            "status": "Name:\taster-lab",
            "docker_stats": {"MemUsage": "1MiB / 64MiB"},
        }
        orchestrate.validate_resource_sample(sample, 64 * 1024 * 1024)

    def test_resource_sample_rejects_empty_io_stat(self):
        with self.assertRaises(orchestrate.LabError):
            orchestrate.parse_io_stat("")

    def test_qdisc_validation_binds_requested_netem_parameters(self):
        value = json.dumps(
            [
                {
                    "kind": "netem",
                    "options": {
                        "limit": 64,
                        "rate": 375,
                        "seed": 424242,
                        "loss-random": {"probability": 0.5},
                    },
                }
            ]
        )
        orchestrate.verify_qdisc_json(
            value,
            expected_bps=3000,
            expected_loss_percent=50,
            expected_limit=64,
            expected_seed=424242,
        )
        with self.assertRaises(orchestrate.LabError):
            orchestrate.verify_qdisc_json(
                value,
                expected_bps=4000,
                expected_loss_percent=50,
                expected_limit=64,
                expected_seed=424242,
            )
        unseeded = json.dumps(
            [
                {
                    "kind": "netem",
                    "options": {
                        "limit": 64,
                        "rate": 375,
                        "loss-random": {"probability": 0.5},
                    },
                }
            ]
        )
        orchestrate.verify_qdisc_json(
            unseeded,
            expected_bps=3000,
            expected_loss_percent=50,
            expected_limit=64,
            expected_seed=None,
        )
        self.assertEqual(orchestrate.tc_rate_bits(375), 3000)

    def test_build_input_receipt_includes_deny_all_policy(self):
        inputs = orchestrate.collect_build_inputs()
        paths = {item.relative_path for item in inputs}
        self.assertIn(".dockerignore", paths)
        self.assertIn("LICENSE", paths)
        self.assertIn("THIRD_PARTY_NOTICES.md", paths)
        self.assertIn("lab/Dockerfile", paths)
        self.assertRegex(orchestrate.build_input_digest(inputs), r"^[0-9a-f]{64}$")

    def test_build_boundary_seals_only_hashed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            sealed, digest = orchestrate.verify_build_boundary(context)
            receipt = json.loads((root / "build-inputs.json").read_text())
            sealed_paths = {
                str(path.relative_to(sealed))
                for path in sealed.rglob("*")
                if path.is_file()
            }
        self.assertEqual(sealed_paths, {item["path"] for item in receipt["files"]})
        self.assertEqual(receipt["aggregate_sha256"], digest)
        self.assertNotIn("lab/orchestrate.py", sealed_paths)
        self.assertNotIn(".git", {path.split("/", 1)[0] for path in sealed_paths})

    def test_pcap_validation_requires_a_complete_known_header(self):
        with tempfile.TemporaryDirectory() as temporary:
            valid = Path(temporary) / "capture.pcap"
            valid.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 20)
            self.assertEqual(orchestrate.validate_pcap(valid), 24)
            invalid = Path(temporary) / "invalid.pcap"
            invalid.write_bytes(b"not-a-pcap" + b"\x00" * 20)
            with self.assertRaises(orchestrate.LabError):
                orchestrate.validate_pcap(invalid)

    def test_cleanup_presence_probe_failure_is_not_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            context.runner = mock.Mock()
            context.runner.run.side_effect = orchestrate.LabError("daemon unavailable")
            with mock.patch.object(orchestrate, "require_docker", return_value="docker"):
                with self.assertRaises(orchestrate.LabError):
                    orchestrate.docker_resource_present(
                        context, "container", "aster-lab-node-a"
                    )

    def test_normal_nat_cleanup_refuses_missing_runtime_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            context.label = "nat"
            context.resources = [
                orchestrate.PlannedResource(
                    "container", orchestrate.FIXED_CONTAINER_NAMES["nat-a"], "nat-a"
                )
            ]
            with mock.patch.object(orchestrate, "verify_orbstack", return_value=("docker", {})):
                with self.assertRaisesRegex(
                    orchestrate.LabError, "resources were retained"
                ):
                    orchestrate.cleanup_context(context, tolerate_errors=False)

    def test_image_resolution_requires_provenance_and_sets_digest(self):
        with tempfile.TemporaryDirectory() as temporary:
            context = self.context(Path(temporary))
            context.image_id = None
            context.daemon_architecture = "arm64"
            digest = orchestrate.build_input_digest(orchestrate.collect_build_inputs())
            identity = "sha256:" + "b" * 64
            record = {
                "id": identity,
                "repo_digests": [],
                "architecture": "arm64",
                "labels": {
                    orchestrate.MANAGED_LABEL: "true",
                    orchestrate.RUN_LABEL: "fedcba9876543210",
                    orchestrate.IMAGE_SCHEMA_LABEL: orchestrate.IMAGE_SCHEMA,
                    orchestrate.IMAGE_INPUT_LABEL: digest,
                    orchestrate.IMAGE_BASE_LABEL: orchestrate.LAB_BASE_IMAGE,
                },
            }
            context.runner = mock.Mock()
            context.runner.run.return_value = subprocess.CompletedProcess(
                ["docker"], 0, json.dumps(record), ""
            )
            with mock.patch.object(orchestrate, "require_docker", return_value="docker"):
                observed = orchestrate.resolve_lab_image(context)
        self.assertEqual(observed, identity)
        self.assertEqual(context.image_id, identity)

    def test_existing_nat_finalization_binds_all_terminal_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            context = self.context(root)
            qdisc = json.dumps(
                [
                    {
                        "kind": "netem",
                        "options": {
                            "limit": 64,
                            "rate": 375,
                            "seed": 424242,
                            "loss": {"probability": 0.5},
                        },
                    }
                ]
            )
            nft = json.dumps({"nftables": []})
            infra = "ASTER_LAB_INFRA_READY\tversion=1\n"
            terminal = {}
            for role in ["nat-a", "nat-b"]:
                qdisc_name = f"{role}-qdisc-final-command-0001.json"
                nft_name = f"{role}-nft-final-command-0002.json"
                (root / qdisc_name).write_text(qdisc, encoding="utf-8")
                (root / nft_name).write_text(nft, encoding="utf-8")
                capture = root / "outputs" / role / f"{role}-wan.pcap"
                capture.parent.mkdir(parents=True)
                capture.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 20)
                terminal[role] = {
                    "role": role,
                    "qdisc_receipt": qdisc_name,
                    "qdisc_receipt_sha256": orchestrate.sha256_file(root / qdisc_name),
                    "nft_receipt": nft_name,
                    "nft_receipt_sha256": orchestrate.sha256_file(root / nft_name),
                    "capture": f"outputs/{role}/{role}-wan.pcap",
                    "capture_bytes": 24,
                    "capture_sha256": orchestrate.sha256_file(capture),
                }
            infra_name = "nat-infra-final-command-0003.log"
            (root / infra_name).write_text(infra, encoding="utf-8")
            runtime = {
                "schema": orchestrate.SCHEMA,
                "profile": "restrictive",
                "shape_bps": 3000,
                "loss_percent": 50,
                "netem_limit": 64,
                "netem_seed_requested": 424242,
                "netem_seed_status": "applied",
                "netem_seed": 424242,
                "infra": orchestrate.FIXED_CONTAINER_NAMES["infra"],
                "routers": [{"role": "nat-a"}, {"role": "nat-b"}],
            }
            final = {
                "schema": orchestrate.SCHEMA,
                "run_id": context.run_id,
                "infra_log_receipt": infra_name,
                "infra_log_receipt_sha256": orchestrate.sha256_file(root / infra_name),
                "routers": [terminal["nat-a"], terminal["nat-b"]],
            }
            (root / "nat-runtime.json").write_text(json.dumps(runtime), encoding="utf-8")
            (root / "nat-finalization.json").write_text(json.dumps(final), encoding="utf-8")
            orchestrate.finalize_nat(context)
            (root / terminal["nat-a"]["nft_receipt"]).write_text(
                '{"nftables":["changed"]}', encoding="utf-8"
            )
            with self.assertRaises(orchestrate.LabError):
                orchestrate.finalize_nat(context)


if __name__ == "__main__":
    unittest.main()
