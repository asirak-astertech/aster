#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Focused unit tests for the generated hierarchy-scale controller."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("aster_hierarchy_scale_compose.py")
SPEC = importlib.util.spec_from_file_location("aster_hierarchy_scale_compose", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def identifier(value: int) -> str:
    return f"{value:064x}"


def source_logs(publishers_per_leaf: int) -> dict[str, str]:
    result: dict[str, str] = {}
    for index, role in enumerate(MODULE.publisher_services(publishers_per_leaf)):
        lines = []
        for offset, (case, topic) in enumerate(
            (("allowed", MODULE.ALLOWED_TOPIC), ("denied", MODULE.DENIED_TOPIC))
        ):
            digest = MODULE._payload_digest(role, case)
            lines.append(
                "HIERARCHY_SCALE_SOURCE "
                f"status=published role={role} case={case} "
                f"source_id={identifier(2 * index + offset + 1)} "
                f"topic={topic} priority=immediate payload_sha256={digest}"
            )
        result[role] = "\n".join(lines)
    return result


def parsed_sources(
    publishers_per_leaf: int,
) -> dict[str, dict[str, MODULE.SourceFixture]]:
    return MODULE.validate_source_receipts(
        source_logs(publishers_per_leaf), publishers_per_leaf
    )


def ready_identities(publishers_per_leaf: int) -> dict[str, MODULE.ReadyIdentity]:
    return {
        service: MODULE.ReadyIdentity(
            carrier=f"carrier-{service}",
            mission=f"mission-{service}",
            authority=("foreign-authority" if service == "outsider" else "authority"),
            nearby="active-evaluation",
        )
        for service in MODULE.live_services(publishers_per_leaf)
    }


def contact_logs(
    publishers_per_leaf: int,
    identities: dict[str, MODULE.ReadyIdentity],
) -> dict[str, str]:
    logs = {service: [] for service in MODULE.live_services(publishers_per_leaf)}
    for _segment, members in MODULE.segment_members(publishers_per_leaf).items():
        mission_members = [service for service in members if service != "outsider"]
        center = mission_members[-1]
        for remote in mission_members[:-1]:
            carrier = identities[remote].carrier
            logs[center].append(
                f"DISCOVERY status=candidate carrier_peer={carrier} retained_candidates=1"
            )
            logs[center].append(
                "CONTACT direction=out "
                f"carrier_peer={carrier} bridge_offered=0 bridge_applied=0 "
                "bridge_delivered=0 status=pass"
            )
    outsider_carrier = identities["outsider"].carrier
    root_carrier = identities["root-consumer"].carrier
    logs["root-consumer"].append(
        f"DISCOVERY status=candidate carrier_peer={outsider_carrier} retained_candidates=1"
    )
    logs["outsider"].append(
        f"DISCOVERY status=candidate carrier_peer={root_carrier} retained_candidates=1"
    )
    logs["outsider"].append(
        "CONTACT direction=out "
        f"carrier_peer={root_carrier} status=error "
        "error=mission%20authentication%20failed"
    )
    return {service: "\n".join(lines) for service, lines in logs.items()}


def bridge_logs(
    publishers_per_leaf: int,
    sources: dict[str, dict[str, MODULE.SourceFixture]],
) -> dict[str, str]:
    result: dict[str, str] = {}
    counter = 10_000
    for service in (*MODULE.leaf_services(), *MODULE.region_services()):
        expected, hops, current_scope = MODULE._expected_bridge_sources(
            service, sources, publishers_per_leaf
        )
        lines = []
        for fixture in expected.values():
            leaf = MODULE.leaf_for_publisher(fixture.role, publishers_per_leaf)
            current_epoch = (
                MODULE.LEAF_COUNT + MODULE.region_for_leaf(leaf) + 1
                if service in MODULE.leaf_services()
                else MODULE.ROOT_SCOPE_EPOCH
            )
            lines.append(
                "BRIDGE status=forwarded "
                f"source_id={fixture.source_id} route_id={identifier(counter)} "
                f"wrapper_id={identifier(counter + 1)} hops={hops} "
                f"origin_scope=demo/leaf{leaf:02d} origin_epoch={MODULE.LEAF_SCOPE_EPOCH} "
                f"current_scope={current_scope} current_epoch={current_epoch} "
                "disposition=promoted payload_opened=false "
                "payload_plaintext_logged=false"
            )
            counter += 2
        result[service] = "\n".join(lines)
    return result


def delivery_logs(
    publishers_per_leaf: int,
    sources: dict[str, dict[str, MODULE.SourceFixture]],
    *,
    status: str,
) -> tuple[str, dict[str, str]]:
    lines = []
    routes: dict[str, str] = {}
    for index, fixtures in enumerate(sources.values()):
        fixture = fixtures["allowed"]
        leaf = MODULE.leaf_for_publisher(fixture.role, publishers_per_leaf)
        route = identifier(30_000 + index * 2)
        wrapper = identifier(30_001 + index * 2)
        routes[fixture.source_id] = route
        lines.append(
            f"BRIDGE_DELIVERY status={status} source_id={fixture.source_id} "
            f"route_id={route} wrapper_id={wrapper} publisher={identifier(1)} "
            f"hops=2 origin_scope=demo/leaf{leaf:02d} "
            f"origin_epoch={MODULE.LEAF_SCOPE_EPOCH} current_scope=demo/root "
            f"current_epoch={MODULE.ROOT_SCOPE_EPOCH} topic=mesh.allowed "
            f"priority=immediate event_sequence=1 payload_len=42 "
            f"payload_sha256={fixture.payload_sha256} payload_opened=true "
            "payload_plaintext_logged=false"
        )
    return "\n".join(lines), routes


class GeneratedTopologyTests(unittest.TestCase):
    def test_tier_counts_and_exact_service_names(self) -> None:
        for per_leaf, publishers, live in ((1, 8, 20), (4, 32, 44), (8, 64, 76)):
            self.assertEqual(len(MODULE.publisher_services(per_leaf)), publishers)
            self.assertEqual(len(MODULE.live_services(per_leaf)), live)
            self.assertEqual(len(MODULE.compose_model(per_leaf)["services"]), live + 1)
        self.assertEqual(MODULE.publisher_services(1)[-1], "p007")
        self.assertEqual(MODULE.publisher_services(8)[-1], "p063")

    def test_exact_eleven_segment_hierarchy_and_addresses(self) -> None:
        members = MODULE.segment_members(8)
        self.assertEqual(len(members), 11)
        self.assertEqual(len(members["leaf00"]), 9)
        self.assertEqual(set(members["region00"]), {"l00", "l01", "l02", "l03", "r00"})
        self.assertEqual(set(members["root"]), {"r00", "r01", "root-consumer", "outsider"})
        interfaces = MODULE.service_interfaces(8)
        self.assertEqual(interfaces["p000"], {"leaf00": "10.231.0.10"})
        self.assertEqual(
            interfaces["l07"],
            {"leaf07": "10.231.7.200", "region01": "10.231.9.13"},
        )
        self.assertEqual(len({ip for item in interfaces.values() for ip in item.values()}), 86)

    def test_generated_model_is_hardened_and_capacity_bounded(self) -> None:
        model = MODULE.compose_model(8)
        MODULE.validate_compose_model(model, 8)
        services = model["services"]
        self.assertEqual(services["init"]["network_mode"], "none")
        self.assertEqual(services["init"]["user"], "0:0")
        self.assertEqual(services["init"]["cap_drop"], ["ALL"])
        self.assertEqual(services["init"]["cap_add"], ["CHOWN"])
        self.assertEqual(len(services["init"]["volumes"]), 76)
        node = services["l00"]
        self.assertTrue(node["read_only"])
        self.assertEqual(node["cap_drop"], ["ALL"])
        self.assertEqual(node["environment"]["TOKIO_WORKER_THREADS"], "1")
        self.assertNotIn("ports", node)
        self.assertNotIn("extra_hosts", node)
        self.assertEqual(MODULE.capacity_summary(8)["maxLocalPeers"]["selected"], 12)
        self.assertEqual(MODULE.capacity_summary(8)["rootRoutes"]["selected"], 64)

    def test_topology_and_hardening_mutations_fail_closed(self) -> None:
        model = MODULE.compose_model(1)
        changed = copy.deepcopy(model)
        changed["services"]["p000"]["ports"] = ["4433:4433"]
        with self.assertRaises(MODULE.ScaleError):
            MODULE.validate_compose_model(changed, 1)
        changed = copy.deepcopy(model)
        changed["services"]["l00"]["networks"].pop("region00")
        with self.assertRaises(MODULE.ScaleError):
            MODULE.validate_compose_model(changed, 1)
        changed = copy.deepcopy(model)
        changed["services"]["init"]["cap_add"] = ["CHOWN", "NET_ADMIN"]
        with self.assertRaises(MODULE.ScaleError):
            MODULE.validate_compose_model(changed, 1)

    def test_owner_only_compose_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = MODULE.write_compose_model(Path(directory), 1)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(Path(directory).stat().st_mode), 0o700)
            document = json.loads(path.read_text(encoding="utf-8"))
            MODULE.validate_compose_model(document, 1)


class ReceiptValidationTests(unittest.TestCase):
    def test_initializer_and_all_exact_sources(self) -> None:
        line = (
            "HIERARCHY_SCALE_INIT status=pass disposition=created publishers=8 "
            "nodes=20 authorities=2 edges=10 leaf_scopes=8 regional_scopes=2 "
            "provisioning=unprotected-reference"
        )
        self.assertEqual(MODULE.validate_init_receipt(line, 1)["disposition"], "created")
        sources = parsed_sources(1)
        self.assertEqual(len(sources), 8)
        self.assertEqual(
            len({fixture.source_id for cases in sources.values() for fixture in cases.values()}),
            16,
        )

    def test_source_digest_and_uniqueness_fail_closed(self) -> None:
        logs = source_logs(1)
        logs["p000"] = logs["p000"].replace(
            MODULE._payload_digest("p000", "allowed"), identifier(999), 1
        )
        with self.assertRaises(MODULE.ScaleError):
            MODULE.validate_source_receipts(logs, 1)
        logs = source_logs(1)
        first = identifier(1)
        logs["p001"] = logs["p001"].replace(identifier(3), first, 1)
        with self.assertRaises(MODULE.ScaleError):
            MODULE.validate_source_receipts(logs, 1)

    def test_exact_root_delivery_and_unknown_inventory_rejection(self) -> None:
        sources = parsed_sources(1)
        logs, routes = delivery_logs(1, sources, status="delivered")
        self.assertEqual(
            MODULE.validate_root_deliveries(
                logs, sources, 1, status="delivered", require_complete=True
            ),
            routes,
        )
        unknown = logs + "\n" + logs.splitlines()[0].replace(
            next(iter(routes)), identifier(999_999)
        )
        with self.assertRaises(MODULE.ScaleError):
            MODULE.validate_root_deliveries(
                unknown, sources, 1, status="delivered", require_complete=True
            )

    def test_denied_source_delivery_is_rejected(self) -> None:
        sources = parsed_sources(1)
        logs, _routes = delivery_logs(1, sources, status="delivered")
        denied = sources["p000"]["denied"].source_id
        bad = logs + "\n" + logs.splitlines()[0].replace(
            sources["p000"]["allowed"].source_id, denied
        )
        with self.assertRaises(MODULE.ScaleError):
            MODULE.validate_root_deliveries(
                bad, sources, 1, status="delivered", require_complete=True
            )

    def test_leaf_and_regional_forwards_exceed_contact_batch(self) -> None:
        sources = parsed_sources(8)
        logs = bridge_logs(8, sources)
        summary = MODULE.validate_bridge_forwards(logs, sources, 8)
        self.assertTrue(summary["beyondEightRouteContactBatch"])
        self.assertEqual(summary["regionalRoutesEach"], 32)
        self.assertEqual(summary["uniqueForwardedByBridge"]["r00"], 32)

    def test_not_selected_offer_is_counted_but_not_a_forward(self) -> None:
        sources = parsed_sources(1)
        logs = bridge_logs(1, sources)
        extra = logs["l00"].splitlines()[0]
        extra = extra.replace("status=forwarded", "status=not-selected").replace(
            "disposition=promoted", "disposition=not-selected"
        )
        logs["l00"] += "\n" + extra
        summary = MODULE.validate_bridge_forwards(logs, sources, 1)
        self.assertEqual(summary["uniqueForwardedByBridge"]["l00"], 1)
        self.assertEqual(summary["dispositions"]["not-selected"], 1)

    def test_payload_sentinel_in_route_only_log_is_rejected(self) -> None:
        sources = parsed_sources(1)
        logs = bridge_logs(1, sources)
        logs["r00"] += "\n" + MODULE.PAYLOAD_SENTINEL_PREFIX
        with self.assertRaises(MODULE.ScaleError):
            MODULE.validate_payload_blind_logs(logs)

    def test_all_exact_routes_recover_and_missing_route_fails(self) -> None:
        sources = parsed_sources(1)
        recovered_logs, routes = delivery_logs(1, sources, status="recovered")
        restore_lines = []
        wrappers = {}
        for index, (source_id, route_id) in enumerate(routes.items()):
            wrapper = identifier(50_000 + index)
            wrappers[source_id] = wrapper
            restore_lines.append(
                "BRIDGE_RESTORE status=pass "
                f"source_id={source_id} route_id={route_id} wrapper_id={wrapper} "
                "active=true payload_plaintext_logged=false"
            )
        logs = "\n".join((*restore_lines, recovered_logs))
        self.assertEqual(MODULE.validate_route_recovery(logs, sources, 1, routes), routes)
        with self.assertRaises(MODULE.ScaleError):
            MODULE.validate_route_recovery(
                "\n".join((*restore_lines[:-1], recovered_logs)), sources, 1, routes
            )


class GraphAndBoundTests(unittest.TestCase):
    def test_exact_segment_graph_and_outsider_rejection(self) -> None:
        identities = ready_identities(1)
        logs = contact_logs(1, identities)
        summary = MODULE.contact_graph_summary(logs, identities, 1)
        self.assertTrue(summary["connected"])
        self.assertEqual(len(summary["segments"]), 11)
        self.assertEqual(summary["outsiderAuthenticatedPasses"], 0)
        self.assertTrue(summary["outsiderMissionRejection"])

    def test_disconnected_segment_fails(self) -> None:
        identities = ready_identities(1)
        logs = contact_logs(1, identities)
        lines = [
            line
            for line in logs["l00"].splitlines()
            if identities["p000"].carrier not in line
        ]
        logs["l00"] = "\n".join(lines)
        with self.assertRaises(MODULE.ScaleError):
            MODULE.contact_graph_summary(logs, identities, 1)

    def test_outsider_pass_candidate_limit_and_capacity_fail(self) -> None:
        identities = ready_identities(1)
        logs = contact_logs(1, identities)
        logs["outsider"] += (
            "\nCONTACT direction=out carrier_peer=carrier-root-consumer status=pass"
        )
        with self.assertRaises(MODULE.ScaleError):
            MODULE.contact_graph_summary(logs, identities, 1)

        logs = contact_logs(1, identities)
        logs["p000"] += "\nDISCOVERY status=dropped reason=candidate-limit"
        with self.assertRaises(MODULE.ScaleError):
            MODULE.contact_graph_summary(logs, identities, 1)

        logs = contact_logs(1, identities)
        logs["p000"] += (
            "\nCONTACT direction=out status=error "
            "error=mission%20admission%20capacity%20reached"
        )
        with self.assertRaises(MODULE.ScaleError):
            MODULE.contact_graph_summary(logs, identities, 1)

    def test_receipt_and_stats_parsers_are_bounded(self) -> None:
        fields = " ".join(f"k{index}=v" for index in range(MODULE.MAX_RECEIPT_FIELDS + 1))
        with self.assertRaises(MODULE.ScaleError):
            MODULE.receipt_fields(f"CONTACT {fields}", "CONTACT")
        with self.assertRaises(MODULE.ScaleError):
            MODULE.receipt_fields("x" * (MODULE.MAX_RECEIPT_LINE_BYTES + 1), "CONTACT")
        stats = json.dumps(
            {
                "ID": identifier(1),
                "CPUPerc": "1.5%",
                "MemUsage": "1MiB / 2MiB",
                "NetIO": "3kB / 4kB",
                "PIDs": "5",
            }
        )
        self.assertEqual(MODULE.parse_stats_records(stats)[0]["PIDs"], "5")
        self.assertEqual(MODULE.parse_io_pair("1MiB / 2MiB"), (1048576, 2097152))

    def test_ps_records_and_cleanup_targets_are_exact(self) -> None:
        raw = json.dumps(
            [
                {"Service": "p000", "State": "running", "ID": "a" * 12},
                {"Service": "l00", "State": "running", "ID": "b" * 12},
            ]
        )
        records = MODULE.parse_ps_records(raw)
        self.assertEqual(
            MODULE.validate_service_records(
                records, ("p000", "l00"), expected_state="running"
            ),
            {"p000": "a" * 12, "l00": "b" * 12},
        )
        project = MODULE.project_name(pid=123, suffix="abcdef12")
        MODULE.validate_cleanup_target(project, f"{project}:local")
        with self.assertRaises(MODULE.ScaleError):
            MODULE.validate_cleanup_target(project, "aster-hierarchy-scale:latest")
        with self.assertRaises(MODULE.ScaleError):
            MODULE.validate_cleanup_target("wrong", "wrong:local")


if __name__ == "__main__":
    unittest.main()
