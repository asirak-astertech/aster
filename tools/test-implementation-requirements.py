#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Focused regressions for adopter-facing Blob requirement claims."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest


CHECKER_PATH = Path(__file__).with_name("check-implementation-requirements.py")
SPEC = importlib.util.spec_from_file_location("implementation_requirements", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class BlobCapabilityDocumentationTests(unittest.TestCase):
    def test_current_capability_boundary_is_required(self) -> None:
        payload = {
            "schema": 1,
            "surface": "capability_roadmap",
            "local_publish_waits_for_peer": False,
            "rust_agent_asterctl_publish_read": "implemented",
            "blob_status_scope": "receiver_local_durable_state",
            "blob_status_reports_remote_delivery_peer_or_convergence": False,
            "cli_download_resume": "post_merge",
        }
        text = f"""<!-- ASTER-BLOB-CAPABILITY:BEGIN -->
```json
{json.dumps(payload, indent=2)}
```
<!-- ASTER-BLOB-CAPABILITY:RENDERED -->
Local Blob publication commits without waiting for a peer. Rust, the native-gRPC agent, and asterctl implement bounded Blob publication and authenticated reads. blob-status reports receiver-local durable state, not remote delivery, peer status, or convergence. CLI download resume is post-merge work; an interrupted download restarts at byte zero.
<!-- ASTER-BLOB-CAPABILITY:END -->
BLE is not implemented. Three-CM4 validation of this candidate has not yet run.
"""
        CHECKER.validate_blob_capability_documentation(text)
        mutations = (
            ("typed capability", '"cli_download_resume": "post_merge"', '"cli_download_resume": "implemented"'),
            ("rendered capability", "commits without waiting", "waits before committing"),
            ("BLE boundary", "BLE is not implemented", "BLE is implemented"),
            ("CM4 evidence boundary", "has not yet run", "passed"),
        )
        for label, old, new in mutations:
            with self.subTest(label=label), self.assertRaisesRegex(
                ValueError, label
            ):
                CHECKER.validate_blob_capability_documentation(
                    text.replace(old, new, 1)
                )


if __name__ == "__main__":
    unittest.main()
