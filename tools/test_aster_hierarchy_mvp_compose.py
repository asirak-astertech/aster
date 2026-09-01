#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Focused unit tests for the Docker hierarchy MVP controller."""

from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("aster_hierarchy_mvp_compose.py")
SPEC = importlib.util.spec_from_file_location("aster_hierarchy_mvp_compose", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def identifier(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode("ascii")


def source_logs() -> str:
    lines = []
    for index, (case, (topic, priority, payload)) in enumerate(
        MODULE.FIXTURES.items(), start=1
    ):
        lines.append(
            "BRIDGE_SOURCE status=published "
            f"case={case} source_id={identifier(index)} topic={topic} "
            f"priority={priority} payload_sha256={MODULE._payload_digest(payload)}"
        )
    return "\n".join(lines)


def compose_config() -> str:
    services: dict[str, object] = {}
    for service, networks in MODULE.EXPECTED_NETWORKS.items():
        local_interfaces = MODULE.EXPECTED_INTERFACE_ADDRESSES[service]
        services[service] = {
            "environment": {
                "ASTER_HIERARCHY_ROLE": service,
                "ASTER_NEARBY_IPV4_INTERFACES": ",".join(
                    local_interfaces.values()
                ),
            },
            "networks": {
                network: {"ipv4_address": local_interfaces[network]}
                for network in networks
            },
            "depends_on": {"init": {"condition": "service_completed_successfully"}},
            "volumes": [
                {
                    "type": "volume",
                    "source": f"state-{service}",
                    "target": "/state",
                }
            ],
        }
    services["init"] = {
        "network_mode": "none",
        "volumes": [
            {
                "type": "volume",
                "source": f"state-{service}",
                "target": f"/provision/{service}",
            }
            for service in MODULE.SERVICES
        ],
    }
    return json.dumps(
        {
            "services": services,
            "networks": {
                network: {
                    "driver": "bridge",
                    "internal": False,
                    "ipam": {
                        "config": [
                            {"subnet": MODULE.EXPECTED_NETWORK_SUBNETS[network]}
                        ]
                    },
                }
                for network in MODULE.EXPECTED_NETWORK_SUBNETS
            },
        }
    )


class HierarchyComposeControllerTests(unittest.TestCase):
    def test_project_name_and_discovery_environment_are_bounded(self) -> None:
        value = MODULE.project_name(pid=1234, suffix="0123abcd")
        self.assertEqual(value, "aster-hierarchy-mvp-1234-0123abcd")
        self.assertRegex(value, MODULE.PROJECT_RE)
        environment = MODULE.discovery_environment(("publisher", "bridge-alpha"))
        self.assertEqual(environment["ASTER_PUBLISHER_DISCOVER_LAN"], "1")
        self.assertEqual(environment["ASTER_BRIDGE_ALPHA_DISCOVER_LAN"], "1")
        self.assertEqual(environment["ASTER_BRIDGE_BRAVO_DISCOVER_LAN"], "0")
        self.assertEqual(environment["ASTER_CONSUMER_DISCOVER_LAN"], "0")
        self.assertEqual(environment["ASTER_OUTSIDER_DISCOVER_LAN"], "0")
        with self.assertRaisesRegex(MODULE.SmokeError, "unknown hierarchy node"):
            MODULE.discovery_environment(("unknown",))

    def test_compose_prefix_and_exact_segmented_topology(self) -> None:
        controller = MODULE.Compose(
            "/usr/bin/docker", "aster-hierarchy-mvp-1234-0123abcd"
        )
        self.assertEqual(controller.prefix[0:2], ("/usr/bin/docker", "compose"))
        self.assertEqual(
            controller.image,
            "aster-hierarchy-mvp-1234-0123abcd:local",
        )
        MODULE.validate_compose_topology(compose_config())
        document = json.loads(compose_config())
        document["services"]["consumer"]["networks"]["alpha"] = None
        with self.assertRaisesRegex(MODULE.SmokeError, "consumer changed network"):
            MODULE.validate_compose_topology(json.dumps(document))
        document = json.loads(compose_config())
        document["services"]["bridge-alpha"]["environment"][
            "ASTER_NEARBY_IPV4_INTERFACES"
        ] = "172.30.251.11"
        with self.assertRaisesRegex(MODULE.SmokeError, "local discovery interfaces"):
            MODULE.validate_compose_topology(json.dumps(document))
        document = json.loads(compose_config())
        document["services"]["bridge-bravo"]["networks"]["parent"][
            "ipv4_address"
        ] = "172.30.252.99"
        with self.assertRaisesRegex(MODULE.SmokeError, "selection is inconsistent"):
            MODULE.validate_compose_topology(json.dumps(document))
        with self.assertRaisesRegex(MODULE.SmokeError, "absolute path"):
            MODULE.Compose("docker", "aster-hierarchy-mvp-1234-0123abcd")

    def test_receipts_parse_compose_prefix_without_false_prefix_match(self) -> None:
        logs = "\n".join(
            (
                "publisher-1 | READY selected=true role=publisher "
                "carrier_id=carrier mission_authority=shared "
                "nearby_discovery=active-evaluation",
                "publisher-1 | HIERARCHY_READY status=started role=publisher",
                "NOTREADY selected=true role=wrong carrier_id=wrong "
                "mission_authority=wrong",
            )
        )
        self.assertEqual(
            MODULE.ready_identity(
                logs,
                "publisher",
                discovery="enabled",
            ),
            ("carrier", "shared"),
        )
        self.assertEqual(len(MODULE.receipt_fields(logs, "READY")), 1)
        with self.assertRaisesRegex(MODULE.SmokeError, "failed before readiness"):
            MODULE.reject_node_error(
                "node-1 | HIERARCHY_DEMO status=error error=bounded%20failure",
                "node",
            )

    def test_sources_require_exact_policy_hash_and_distinct_canonical_ids(self) -> None:
        sources = MODULE.validate_source_receipts(source_logs())
        self.assertEqual(sources["allowed"]["source_id"], identifier(1))
        self.assertEqual(sources["denied-topic"]["topic"], MODULE.DENIED_TOPIC)
        damaged = source_logs().replace(
            f"payload_sha256={MODULE._payload_digest(MODULE.DENIED_PRIORITY_PAYLOAD)}",
            "payload_sha256=" + "0" * 64,
        )
        with self.assertRaisesRegex(MODULE.SmokeError, "payload hash"):
            MODULE.validate_source_receipts(damaged)

    def test_runtime_hex_identifiers_are_also_canonical(self) -> None:
        self.assertEqual(MODULE._canonical_id("ab" * 32, "id"), "ab" * 32)
        with self.assertRaisesRegex(MODULE.SmokeError, "canonical"):
            MODULE._canonical_id("AB" * 32, "id")

    def test_delivery_denials_and_payload_blind_forwarding_are_correlated(self) -> None:
        sources = MODULE.validate_source_receipts(source_logs())
        allowed = sources["allowed"]
        route_id = identifier(10)
        wrapper_id = identifier(11)
        bridge_alpha = (
            "BRIDGE status=forwarded "
            f"source_id={allowed['source_id']} hops=1 current_scope=demo/parent "
            "payload_opened=false"
        )
        bridge_bravo = (
            "BRIDGE status=forwarded "
            f"source_id={allowed['source_id']} hops=2 current_scope=demo/bravo "
            "payload_opened=false"
        )
        consumer = (
            "BRIDGE_DELIVERY status=delivered "
            f"source_id={allowed['source_id']} route_id={route_id} "
            f"wrapper_id={wrapper_id} hops=2 origin_scope=demo/alpha "
            f"current_scope=demo/bravo topic={MODULE.ALLOWED_TOPIC} "
            f"priority={MODULE.ALLOWED_PRIORITY} "
            f"payload_sha256={allowed['payload_sha256']}"
        )
        MODULE.validate_forward_receipt(
            bridge_alpha,
            service="bridge-alpha",
            source_id=allowed["source_id"],
            hops=1,
            scope="demo/parent",
        )
        MODULE.validate_forward_receipt(
            bridge_bravo,
            service="bridge-bravo",
            source_id=allowed["source_id"],
            hops=2,
            scope="demo/bravo",
        )
        delivery = MODULE.validate_delivery_receipt(
            consumer,
            allowed,
            status="delivered",
            label="consumer",
        )
        self.assertEqual(delivery["route_id"], route_id)
        MODULE.validate_denials(consumer, "", sources)
        denied_delivery = consumer + (
            "\nBRIDGE_DELIVERY status=delivered source_id="
            + sources["denied-topic"]["source_id"]
        )
        with self.assertRaisesRegex(MODULE.SmokeError, "topic- or priority-denied"):
            MODULE.validate_denials(denied_delivery, "", sources)
        with self.assertRaisesRegex(MODULE.SmokeError, "payload-blind"):
            MODULE.validate_forward_receipt(
                bridge_alpha.replace("payload_opened=false", "payload_opened=true"),
                service="bridge-alpha",
                source_id=allowed["source_id"],
                hops=1,
                scope="demo/parent",
            )

    def test_recovered_delivery_requires_same_durable_route(self) -> None:
        allowed = MODULE.validate_source_receipts(source_logs())["allowed"]
        recovered = (
            "BRIDGE_DELIVERY status=recovered "
            f"source_id={allowed['source_id']} route_id={identifier(20)} "
            f"wrapper_id={identifier(21)} hops=2 origin_scope=demo/alpha "
            f"current_scope=demo/bravo topic={MODULE.ALLOWED_TOPIC} "
            f"priority={MODULE.ALLOWED_PRIORITY} "
            f"payload_sha256={allowed['payload_sha256']}"
        )
        MODULE.validate_delivery_receipt(
            recovered,
            allowed,
            status="recovered",
            label="restart",
            expected_route_id=identifier(20),
        )
        with self.assertRaisesRegex(MODULE.SmokeError, "same durable route"):
            MODULE.validate_delivery_receipt(
                recovered,
                allowed,
                status="recovered",
                label="restart",
                expected_route_id=identifier(22),
            )

    def test_authority_partition_and_outsider_rejection_are_carrier_correlated(self) -> None:
        identities = {
            "publisher": ("publisher-carrier", "shared"),
            "bridge-alpha": ("alpha-carrier", "shared"),
            "bridge-bravo": ("bravo-carrier", "shared"),
            "consumer": ("consumer-carrier", "shared"),
            "outsider": ("outsider-carrier", "foreign"),
        }
        MODULE.validate_authority_partition(identities)
        logs = {
            "bridge-alpha": "CONTACT direction=in carrier_peer=outsider-carrier "
            "status=error error=mission%20authentication:%20foreign",
            "bridge-bravo": "",
            "outsider": "",
        }
        self.assertTrue(MODULE.outsider_contact_rejected(logs, identities))
        logs["outsider"] = (
            "CONTACT direction=out carrier_peer=alpha-carrier status=pass"
        )
        with self.assertRaisesRegex(MODULE.SmokeError, "authenticated hierarchy"):
            MODULE.outsider_contact_rejected(logs, identities)

    def test_stopped_services_require_exact_zero_exit_set(self) -> None:
        stopped = [
            {"Service": "publisher", "State": "exited", "ExitCode": 0},
            {"Service": "consumer", "State": "exited", "ExitCode": 0},
        ]
        MODULE.validate_stopped_services(
            "\n".join(json.dumps(record) for record in stopped),
            ("publisher", "consumer"),
        )
        stopped[1]["ExitCode"] = 137
        with self.assertRaisesRegex(MODULE.SmokeError, "did not exit cleanly"):
            MODULE.validate_stopped_services(
                json.dumps(stopped), ("publisher", "consumer")
            )

    def test_cleanup_failure_suppresses_success(self) -> None:
        class FakeCompose:
            def __init__(self) -> None:
                self.calls: list[tuple[str, ...]] = []

            def run(self, arguments: tuple[str, ...], **_kwargs: object) -> str:
                self.calls.append(arguments)
                if arguments[0] == "down":
                    raise MODULE.SmokeError("cleanup failed")
                return ""

        compose = FakeCompose()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with (
            mock.patch.object(MODULE.shutil, "which", return_value="/usr/bin/docker"),
            mock.patch.object(MODULE, "Compose", return_value=compose),
            mock.patch.object(MODULE, "run_smoke", return_value={"status": "pass"}),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(MODULE.main([]), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("cleanup warning", stderr.getvalue())
        down = next(call for call in compose.calls if call[0] == "down")
        self.assertIn("--remove-orphans", down)
        self.assertIn("--volumes", down)
        self.assertIn("--rmi", down)


if __name__ == "__main__":
    unittest.main()
