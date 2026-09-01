#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Focused unit tests for the Docker Compose LAN MVP controller."""

from __future__ import annotations

import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("aster_lan_mvp_compose.py")
SPEC = importlib.util.spec_from_file_location("aster_lan_mvp_compose", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class ComposeControllerTests(unittest.TestCase):
    def test_project_name_is_bounded_and_not_user_selected(self) -> None:
        value = MODULE.project_name(pid=1234, suffix="0123abcd")
        self.assertEqual(value, "aster-lan-mvp-1234-0123abcd")
        self.assertRegex(value, MODULE.PROJECT_RE)

    def test_discovery_environment_is_complete_and_exact(self) -> None:
        value = MODULE.discovery_environment(("a", "c"))
        self.assertEqual(value["ASTER_A_DISCOVER_LAN"], "1")
        self.assertEqual(value["ASTER_B_DISCOVER_LAN"], "0")
        self.assertEqual(value["ASTER_C_DISCOVER_LAN"], "1")
        self.assertEqual(value["ASTER_D_DISCOVER_LAN"], "0")
        with self.assertRaisesRegex(MODULE.SmokeError, "unknown node"):
            MODULE.discovery_environment(("outsider",))

    def test_compose_prefix_is_exact_and_rejects_ambiguous_binary(self) -> None:
        controller = MODULE.Compose(
            "/usr/bin/docker", "aster-lan-mvp-1234-0123abcd"
        )
        self.assertEqual(controller.prefix[0:2], ("/usr/bin/docker", "compose"))
        self.assertIn(str(MODULE.COMPOSE_FILE), controller.prefix)
        self.assertEqual(
            controller.image,
            "aster-lan-mvp-1234-0123abcd:local",
        )
        with self.assertRaisesRegex(MODULE.SmokeError, "absolute path"):
            MODULE.Compose("docker", "aster-lan-mvp-1234-0123abcd")

    def test_event_validation_requires_exact_identity_key_and_payload(self) -> None:
        event_id = base64.b64encode(bytes(range(32))).decode("ascii")
        event = {
            "id": event_id,
            "logicalKey": base64.b64encode(MODULE.LOGICAL_KEY.encode()).decode(),
            "payload": base64.b64encode(MODULE.PAYLOAD.encode()).decode(),
        }
        self.assertEqual(
            MODULE.validate_event(json.dumps(event), event_id, "test")["id"],
            event_id,
        )
        event["payload"] = base64.b64encode(b"wrong").decode()
        with self.assertRaisesRegex(MODULE.SmokeError, "different payload"):
            MODULE.validate_event(json.dumps(event), event_id, "test")

    def test_negative_query_requires_complete_empty_result(self) -> None:
        MODULE.validate_empty_query(
            json.dumps({"events": [], "hasMore": False, "scannedThrough": "0"}),
            "D",
        )
        with self.assertRaisesRegex(MODULE.SmokeError, "unexpectedly returned"):
            MODULE.validate_empty_query(
                json.dumps({"events": [{"id": "x"}], "hasMore": False}), "D"
            )

    def test_receipts_parse_with_and_without_compose_prefix(self) -> None:
        logs = "\n".join(
            (
                "a-1  | READY selected=true carrier_id=aa mission_authority=shared",
                "NOTREADY selected=true carrier_id=wrong mission_authority=wrong",
                "CONTACT direction=out carrier_peer=dd status=error "
                "error=mission%20authentication:%20foreign",
            )
        )
        self.assertEqual(
            MODULE.ready_identity(logs, "A"),
            ("aa", "shared"),
        )
        self.assertEqual(
            MODULE.receipt_fields(logs, "CONTACT")[0]["carrier_peer"],
            "dd",
        )

    def test_outsider_rejection_is_authority_and_carrier_correlated(self) -> None:
        identities = {
            "a": ("aa", "shared"),
            "b": ("bb", "shared"),
            "d": ("dd", "foreign"),
        }
        MODULE.validate_authority_partition(identities)
        logs = {
            "a": "CONTACT direction=out carrier_peer=dd status=error "
            "error=mission%20authentication:%20foreign",
            "b": "CONTACT direction=out carrier_peer=aa status=pass",
            "d": "",
        }
        self.assertTrue(MODULE.outsider_contact_rejected(logs, identities))

        logs["d"] = "CONTACT direction=in carrier_peer=aa status=pass"
        with self.assertRaisesRegex(MODULE.SmokeError, "authenticated contact"):
            MODULE.outsider_contact_rejected(logs, identities)

        mismatched = dict(identities)
        mismatched["d"] = ("dd", "shared")
        with self.assertRaisesRegex(MODULE.SmokeError, "unexpectedly shared"):
            MODULE.validate_authority_partition(mismatched)

    def test_stopped_services_require_exact_zero_exit_set(self) -> None:
        stopped = [
            {"Service": "a", "State": "exited", "ExitCode": 0},
            {"Service": "b", "State": "exited", "ExitCode": 0},
        ]
        MODULE.validate_stopped_services(json.dumps(stopped), ("a", "b"))
        MODULE.validate_stopped_services(
            "\n".join(json.dumps(record) for record in stopped),
            ("a", "b"),
        )
        stopped[1]["ExitCode"] = 137
        with self.assertRaisesRegex(MODULE.SmokeError, "did not exit cleanly"):
            MODULE.validate_stopped_services(json.dumps(stopped), ("a", "b"))

    def test_peer_evidence_must_correlate_to_the_exact_pair(self) -> None:
        class FakeCompose:
            def __init__(self, logs: dict[str, str]):
                self._logs = logs

            def logs(self, services: tuple[str, ...]) -> str:
                return self._logs[services[0]]

        correlated = FakeCompose(
            {
                "a": "DISCOVERY status=candidate carrier_peer=bb",
                "b": "CONTACT direction=in carrier_peer=aa status=pass",
            }
        )
        MODULE.wait_for_peer_evidence(correlated, "a", "b", "aa", "bb", seconds=0)

        stale = FakeCompose(
            {
                "b": "DISCOVERY status=candidate carrier_peer=old",
                "c": "CONTACT direction=in carrier_peer=bb status=pass",
            }
        )
        with self.assertRaisesRegex(MODULE.SmokeError, "correlated"):
            MODULE.wait_for_peer_evidence(stale, "b", "c", "bb", "cc", seconds=0)

    def test_cleanup_failure_suppresses_pass_and_returns_failure(self) -> None:
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
        self.assertIn("--rmi", down)
        self.assertIn("--volumes", down)


if __name__ == "__main__":
    unittest.main()
