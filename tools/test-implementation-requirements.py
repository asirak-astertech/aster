#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Focused regressions for adopter-facing Blob requirement claims."""

from __future__ import annotations

import importlib.util
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
        text = """Current Blob capability: native-gRPC agent and asterctl bounded publication and authenticated read are implemented.
Local publication is peer-independent and completes at the local durable commit.
blob-status reports local durable publication state; peer delivery and convergence status remain open.
Node-to-node receiver-checkpoint resume is implemented. Download resume remains post-merge work and asterctl restarts at byte zero.
BLE is not implemented. Three-CM4 validation of this candidate has not yet run.
"""
        CHECKER.validate_blob_capability_documentation(text)
        mutations = (
            ("agent/CLI Blob capability", "are implemented", "are planned"),
            ("peer-independent publication", "peer-independent", "peer-coordinated"),
            ("peer/convergence status", "remain open", "are implemented"),
            ("download resume", "post-merge work", "implemented"),
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
