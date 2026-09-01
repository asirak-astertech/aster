#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Pure focused tests for the generated Docker Compose LAN scale controller."""

from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("aster_lan_scale_compose.py")
SPEC = importlib.util.spec_from_file_location("aster_lan_scale_compose", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def event_document(events: list[MODULE.ExpectedEvent]) -> str:
    return json.dumps(
        {
            "events": [
                {
                    "id": item.event_id,
                    "logicalKey": base64.b64encode(item.logical_key.encode()).decode(),
                    "payload": base64.b64encode(item.payload.encode()).decode(),
                }
                for item in events
            ],
            "hasMore": False,
            "scannedThrough": str(len(events)),
        }
    )


class GeneratedModelTests(unittest.TestCase):
    def test_only_exact_scale_counts_are_accepted(self) -> None:
        for value in (8, 16, 32):
            self.assertEqual(MODULE.validate_node_count(value), value)
        for value in (0, 7, 9, 31, 33, 100):
            with self.assertRaisesRegex(MODULE.ScaleError, "one of"):
                MODULE.validate_node_count(value)

    def test_service_names_match_init_contract(self) -> None:
        self.assertEqual(MODULE.authorized_services(8)[0], "n000")
        self.assertEqual(MODULE.authorized_services(8)[-1], "n007")
        self.assertEqual(MODULE.outsider_services(), ("o000",))
        services = MODULE.all_services(32)
        self.assertEqual(len(services), 33)
        self.assertEqual(services[-2:], ("n031", "o000"))

    def test_generated_model_is_isolated_hardened_and_bounded(self) -> None:
        for nodes in (8, 16, 32):
            with self.subTest(nodes=nodes):
                model = MODULE.compose_model(nodes)
                services = model["services"]
                expected = set(MODULE.all_services(nodes))
                self.assertEqual(set(services) - {"init"}, expected)
                self.assertEqual(
                    set(model["volumes"]), {f"{item}-state" for item in expected}
                )
                init = services["init"]
                self.assertEqual(init["network_mode"], "none")
                self.assertEqual(init["command"], [MODULE.INIT_HELPER])
                self.assertEqual(init["environment"]["ASTER_SCALE_NODES"], str(nodes))
                self.assertEqual(init["environment"]["ASTER_SCALE_OUTSIDERS"], "1")
                self.assertEqual(
                    set(init["volumes"]),
                    {f"{item}-state:/nodes/{item}" for item in expected},
                )
                for service in expected:
                    node = services[service]
                    self.assertEqual(node["user"], "10001:10001")
                    self.assertTrue(node["read_only"])
                    self.assertEqual(node["cap_drop"], ["ALL"])
                    self.assertIn("no-new-privileges:true", node["security_opt"])
                    self.assertNotIn("ports", node)
                    self.assertNotIn("healthcheck", node)
                    self.assertEqual(
                        node["environment"]["ASTER_SYNC_MS"],
                        str(MODULE.DEFAULT_SYNC_MS[nodes]),
                    )
                    self.assertEqual(node["environment"]["TOKIO_WORKER_THREADS"], "1")
                    self.assertEqual(node["volumes"], [f"{service}-state:/state"])

    def test_generated_model_is_owner_only_and_exclusive(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = MODULE.write_compose_model(Path(directory), 8)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            parsed = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(len(parsed["volumes"]), 9)
            with self.assertRaisesRegex(MODULE.ScaleError, "could not create"):
                MODULE.write_compose_model(Path(directory), 8)

    def test_payload_is_unique_and_exactly_one_kibibyte(self) -> None:
        payloads = {MODULE.event_payload(item) for item in MODULE.authorized_services(32)}
        self.assertEqual(len(payloads), 32)
        self.assertTrue(all(len(item.encode("utf-8")) == 1024 for item in payloads))
        self.assertEqual(MODULE.event_logical_key("n031"), "scale/n031/event/1")
        with self.assertRaises(MODULE.ScaleError):
            MODULE.event_payload("o000")


class ReceiptAndInventoryTests(unittest.TestCase):
    def test_convergence_retries_transient_query_failure_without_hiding_exit(self) -> None:
        item = MODULE.ExpectedEvent(base64.b64encode(bytes(32)).decode(), "key", "payload")
        expected = {item.event_id: item}

        class FakeCompose:
            def __init__(self) -> None:
                self.attempts: dict[str, int] = {}

            def helper(
                self, service: str, _arguments: tuple[str, ...], *, timeout: float
            ) -> str:
                self.attempts[service] = self.attempts.get(service, 0) + 1
                if service == "n000" and self.attempts[service] == 1:
                    raise MODULE.ScaleError("transient")
                return event_document([] if service == "o000" else [item])

            def ps(
                self, services: tuple[str, ...], *, all_states: bool
            ) -> list[dict[str, object]]:
                self.assert_false(all_states)
                return [
                    {"Service": service, "State": "running", "ID": f"{index + 1:064x}"}
                    for index, service in enumerate(services)
                ]

            @staticmethod
            def assert_false(value: bool) -> None:
                if value:
                    raise AssertionError("expected running-only ps")

        compose = FakeCompose()
        completed, errors, all_exact = MODULE.wait_for_full_convergence(
            compose,
            ("n000",),
            ("o000",),
            expected,
            MODULE.time.monotonic(),
            5,
        )
        self.assertEqual(set(completed), {"n000"})
        self.assertEqual(errors, 1)
        self.assertGreaterEqual(all_exact, max(completed.values()))

    def test_convergence_requires_one_current_exact_batch(self) -> None:
        item = MODULE.ExpectedEvent(base64.b64encode(bytes(32)).decode(), "key", "payload")
        expected = {item.event_id: item}

        class FakeCompose:
            def __init__(self) -> None:
                self.attempts: dict[str, int] = {}

            def helper(
                self, service: str, _arguments: tuple[str, ...], *, timeout: float
            ) -> str:
                self.attempts[service] = self.attempts.get(service, 0) + 1
                attempt = self.attempts[service]
                if service == "o000":
                    return event_document([])
                if service == "n000" and attempt == 2:
                    raise MODULE.ScaleError("transient")
                complete = attempt == 3 or (service == "n000" and attempt == 1) or (
                    service == "n001" and attempt == 2
                )
                return event_document([item] if complete else [])

            def ps(
                self, services: tuple[str, ...], *, all_states: bool
            ) -> list[dict[str, object]]:
                return [
                    {"Service": service, "State": "running", "ID": f"{index + 1:064x}"}
                    for index, service in enumerate(services)
                ]

        compose = FakeCompose()
        with mock.patch.object(MODULE.time, "sleep"):
            completed, errors, all_exact = MODULE.wait_for_full_convergence(
                compose,
                ("n000", "n001"),
                ("o000",),
                expected,
                MODULE.time.monotonic(),
                5,
            )
        self.assertEqual(set(completed), {"n000", "n001"})
        self.assertEqual(compose.attempts["n000"], 3)
        self.assertEqual(compose.attempts["n001"], 3)
        self.assertEqual(errors, 1)
        self.assertGreaterEqual(all_exact, max(completed.values()))

    def test_convergence_rejects_successful_inventory_regression(self) -> None:
        item = MODULE.ExpectedEvent(base64.b64encode(bytes(32)).decode(), "key", "payload")
        expected = {item.event_id: item}

        class FakeCompose:
            def __init__(self) -> None:
                self.attempts: dict[str, int] = {}

            def helper(
                self, service: str, _arguments: tuple[str, ...], *, timeout: float
            ) -> str:
                self.attempts[service] = self.attempts.get(service, 0) + 1
                attempt = self.attempts[service]
                if service == "o000":
                    return event_document([])
                complete = (service == "n000" and attempt == 1) or (
                    service == "n001" and attempt == 2
                )
                return event_document([item] if complete else [])

        with mock.patch.object(MODULE.time, "sleep"):
            with self.assertRaisesRegex(MODULE.ScaleError, "inventory regressed"):
                MODULE.wait_for_full_convergence(
                    FakeCompose(),
                    ("n000", "n001"),
                    ("o000",),
                    expected,
                    MODULE.time.monotonic(),
                    5,
                )

    def test_convergence_cannot_finish_after_deadline(self) -> None:
        item = MODULE.ExpectedEvent(base64.b64encode(bytes(32)).decode(), "key", "payload")
        expected = {item.event_id: item}

        class FakeCompose:
            @staticmethod
            def helper(
                service: str, _arguments: tuple[str, ...], *, timeout: float
            ) -> str:
                return event_document([] if service == "o000" else [item])

        with mock.patch.object(MODULE.time, "monotonic", side_effect=(0.0, 1.1)):
            with self.assertRaisesRegex(MODULE.ScaleError, "before the deadline"):
                MODULE.wait_for_full_convergence(
                    FakeCompose(),
                    ("n000",),
                    ("o000",),
                    expected,
                    0.0,
                    1.0,
                )

    def test_ready_identity_uses_actual_runtime_discovery_value(self) -> None:
        logs = (
            "node | READY selected=true carrier_id=carrier mission_id=mission "
            "mission_authority=authority nearby_discovery=active-evaluation\n"
        )
        identity = MODULE.parse_ready_identity(logs, "n000")
        self.assertEqual(identity.nearby, "active-evaluation")

    def test_identity_cohort_requires_unique_nodes_and_authority_partition(self) -> None:
        identities = {
            "n000": MODULE.ReadyIdentity("c0", "m0", "shared", "active-evaluation"),
            "n001": MODULE.ReadyIdentity("c1", "m1", "shared", "active-evaluation"),
            "o000": MODULE.ReadyIdentity("co", "mo", "other", "active-evaluation"),
        }
        MODULE.validate_identity_cohort(
            identities, ("n000", "n001"), ("o000",), discovery=True
        )
        identities["o000"] = MODULE.ReadyIdentity(
            "co", "mo", "shared", "active-evaluation"
        )
        with self.assertRaisesRegex(MODULE.ScaleError, "not distinct"):
            MODULE.validate_identity_cohort(
                identities, ("n000", "n001"), ("o000",), discovery=True
            )

    def test_inventory_accepts_exact_partial_then_complete_set(self) -> None:
        first = MODULE.ExpectedEvent(base64.b64encode(bytes(32)).decode(), "key/0", "one")
        second = MODULE.ExpectedEvent(
            base64.b64encode(bytes(range(32))).decode(), "key/1", "two"
        )
        expected = {first.event_id: first, second.event_id: second}
        self.assertFalse(
            MODULE.validate_inventory(
                event_document([first]), expected, "partial", require_complete=False
            )
        )
        self.assertTrue(
            MODULE.validate_inventory(
                event_document([second, first]), expected, "complete", require_complete=True
            )
        )

    def test_inventory_rejects_duplicates_extras_changes_and_pagination(self) -> None:
        item = MODULE.ExpectedEvent(base64.b64encode(bytes(32)).decode(), "key", "payload")
        expected = {item.event_id: item}
        with self.assertRaisesRegex(MODULE.ScaleError, "duplicate"):
            MODULE.validate_inventory(
                event_document([item, item]), expected, "duplicate", require_complete=True
            )
        extra = MODULE.ExpectedEvent(
            base64.b64encode(bytes(range(32))).decode(), "other", "payload"
        )
        with self.assertRaisesRegex(MODULE.ScaleError, "unexpected"):
            MODULE.validate_inventory(
                event_document([extra]), expected, "extra", require_complete=True
            )
        changed = json.loads(event_document([item]))
        changed["events"][0]["payload"] = base64.b64encode(b"changed").decode()
        with self.assertRaisesRegex(MODULE.ScaleError, "changed"):
            MODULE.validate_inventory(
                json.dumps(changed), expected, "changed", require_complete=True
            )
        paged = json.loads(event_document([item]))
        paged["hasMore"] = True
        with self.assertRaisesRegex(MODULE.ScaleError, "incomplete"):
            MODULE.validate_inventory(
                json.dumps(paged), expected, "paged", require_complete=True
            )

    def test_event_id_validation_is_exact(self) -> None:
        value = base64.b64encode(bytes(range(32))).decode()
        self.assertEqual(MODULE.canonical_event_id(value), value)
        for malformed in ("", value.rstrip("="), base64.b64encode(bytes(31)).decode()):
            with self.assertRaises(MODULE.ScaleError):
                MODULE.canonical_event_id(malformed)


class ComposeAndMetricParsingTests(unittest.TestCase):
    def test_ps_accepts_array_and_ndjson_and_checks_exact_state(self) -> None:
        records = [
            {"Service": "n000", "State": "running", "ID": "a" * 64},
            {"Service": "o000", "State": "running", "ID": "b" * 64},
        ]
        for raw in (
            json.dumps(records),
            "\n".join(json.dumps(record) for record in records),
        ):
            parsed = MODULE.parse_ps_records(raw)
            self.assertEqual(
                MODULE.validate_service_records(
                    parsed, ("n000", "o000"), expected_state="running"
                ),
                {"n000": "a" * 64, "o000": "b" * 64},
            )
        records[1]["State"] = "exited"
        with self.assertRaisesRegex(MODULE.ScaleError, "expected running"):
            MODULE.validate_service_records(
                records, ("n000", "o000"), expected_state="running"
            )

    def test_docker_size_and_io_parsing_supports_si_and_iec(self) -> None:
        self.assertEqual(MODULE.parse_docker_size("1kB"), 1000)
        self.assertEqual(MODULE.parse_docker_size("1.5MiB"), 1572864)
        self.assertEqual(MODULE.parse_io_pair("2kB / 3KiB"), (2000, 3072))
        with self.assertRaises(MODULE.ScaleError):
            MODULE.parse_docker_size("12 bananas")

    def test_resource_accumulator_requires_owned_complete_samples(self) -> None:
        accumulator = MODULE.ResourceAccumulator(
            {"a" * 64: "n000", "b" * 64: "o000"}
        )

        def sample(cpu: tuple[str, str]) -> str:
            records = []
            for container_id, percent in zip(("a" * 64, "b" * 64), cpu):
                records.append(
                    json.dumps(
                        {
                            "ID": container_id,
                            "CPUPerc": percent,
                            "MemUsage": "2MiB / 1GiB",
                            "NetIO": "1kB / 2kB",
                            "BlockIO": "3kB / 4kB",
                            "PIDs": "4",
                        }
                    )
                )
            return "\n".join(records)

        accumulator.add("convergence", sample(("1.5%", "2.5%")))
        accumulator.add("steady", sample(("0.5%", "0.25%")))
        summary = accumulator.summary()
        self.assertEqual(summary["samples"], {"convergence": 1, "steady": 1})
        self.assertEqual(summary["aggregateFinalIo"]["networkTxBytes"], 4000)
        self.assertEqual(
            summary["aggregatePeaks"]["convergence"]["cpuPercent"], 4.0
        )

    def test_start_time_parser_produces_exact_skew_inputs(self) -> None:
        values = MODULE.parse_started_at(
            "2026-08-31T12:00:00.000000000Z\n"
            "2026-08-31T12:00:01.250000000Z\n"
        )
        self.assertEqual((max(values) - min(values)).total_seconds(), 1.25)


class ContactGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identities = {
            "n000": MODULE.ReadyIdentity("c0", "m0", "shared", "active-evaluation"),
            "n001": MODULE.ReadyIdentity("c1", "m1", "shared", "active-evaluation"),
            "o000": MODULE.ReadyIdentity("co", "mo", "other", "active-evaluation"),
        }

    def test_graph_requires_connected_authorized_edges_and_outsider_rejection(self) -> None:
        logs = {
            "n000": (
                "DISCOVERY status=candidate carrier_peer=c1\n"
                "CONTACT direction=out carrier_peer=c1 status=pass fetched=1 inserted=1\n"
                "CONTACT direction=out carrier_peer=co status=error "
                "error=mission%20authentication:%20foreign\n"
            ),
            "n001": (
                "DISCOVERY status=candidate carrier_peer=c0\n"
                "CONTACT direction=in carrier_peer=c0 status=pass fetched=0 inserted=0 "
                "remaining=0 control_remaining=0 mutable_remaining=0 blob_remaining=0\n"
            ),
            "o000": "DISCOVERY status=candidate carrier_peer=c0\n",
        }
        summary = MODULE.contact_graph_summary(
            logs, self.identities, ("n000", "n001"), ("o000",)
        )
        self.assertTrue(summary["connected"])
        self.assertTrue(summary["outsiderMissionRejection"])
        self.assertEqual(summary["undirectedAuthenticatedEdges"], 1)
        self.assertEqual(summary["transferContacts"], 1)
        self.assertEqual(summary["zeroDifferenceContacts"], 1)

    def test_graph_rejects_outsider_pass_and_candidate_overflow(self) -> None:
        outsider_pass = {
            "n000": "CONTACT direction=out carrier_peer=co status=pass",
            "n001": "",
            "o000": "",
        }
        with self.assertRaisesRegex(MODULE.ScaleError, "Outsider|outsider"):
            MODULE.contact_graph_summary(
                outsider_pass, self.identities, ("n000", "n001"), ("o000",)
            )
        dropped = {
            "n000": "DISCOVERY status=dropped reason=candidate-limit carrier_peer=c1",
            "n001": "",
            "o000": "",
        }
        with self.assertRaisesRegex(MODULE.ScaleError, "candidate bound"):
            MODULE.contact_graph_summary(
                dropped, self.identities, ("n000", "n001"), ("o000",)
            )

    def test_graph_does_not_credit_uncorrelated_outsider_error(self) -> None:
        logs = {
            "n000": "CONTACT carrier_peer=c1 status=pass remaining=0",
            "n001": "CONTACT carrier_peer=c0 status=pass remaining=0",
            "o000": (
                "CONTACT carrier_peer=unknown status=error "
                "error=mission%20authentication:%20uncorrelated\n"
            ),
        }
        with self.assertRaisesRegex(MODULE.ScaleError, "correlated mission rejection"):
            MODULE.contact_graph_summary(
                logs, self.identities, ("n000", "n001"), ("o000",)
            )


class BoundedControlTests(unittest.TestCase):
    def test_sampler_abort_does_not_require_completed_phase_metrics(self) -> None:
        class NeverCalledDocker:
            def run(self, *_args: object, **_kwargs: object) -> str:
                raise AssertionError("sampler should stop before its delayed first call")

        sampler = MODULE.StatsSampler(
            NeverCalledDocker(), {"a" * 64: "n000"}, interval=10.0
        )
        sampler._stop.set()
        sampler.start()
        sampler.abort()

    def test_parallel_worker_failure_is_sanitized(self) -> None:
        def operation(service: str) -> str:
            if service == "n001":
                raise ValueError("internal detail")
            return service

        with self.assertRaisesRegex(MODULE.ScaleError, "worker failed") as raised:
            MODULE.run_parallel(("n000", "n001"), operation, "test")
        self.assertNotIn("internal detail", str(raised.exception))

    def test_percentile_is_nearest_rank(self) -> None:
        values = [1.0, 2.0, 3.0, 4.0]
        self.assertEqual(MODULE.percentile(values, 0.50), 2.0)
        self.assertEqual(MODULE.percentile(values, 0.95), 4.0)

    def test_cleanup_audit_uses_only_exact_project_filters(self) -> None:
        class FakeDocker:
            def __init__(self) -> None:
                self.calls: list[tuple[str, ...]] = []

            def run(self, arguments: tuple[str, ...], *, timeout: float) -> str:
                self.calls.append(arguments)
                return ""

        docker = FakeDocker()
        MODULE.audit_cleanup(
            docker,
            "aster-lan-scale-1234-0123abcd",
            "aster-lan-scale-1234-0123abcd:local",
        )
        self.assertEqual(len(docker.calls), 4)
        for call in docker.calls[:3]:
            self.assertIn(
                "label=com.docker.compose.project=aster-lan-scale-1234-0123abcd",
                call,
            )


if __name__ == "__main__":
    unittest.main()
