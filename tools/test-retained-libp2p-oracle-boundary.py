#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the retained libp2p oracle manifest boundary."""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest


CHECKER_PATH = Path(__file__).with_name("check-retained-libp2p-oracle-boundary.py")
SPEC = importlib.util.spec_from_file_location("retained_oracle_boundary", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def dependency(root: Path) -> dict[str, object]:
    return {
        "name": "aster-libp2p-provider",
        "source": None,
        "kind": None,
        "rename": None,
        "optional": True,
        "target": None,
        "path": str(root / "crates" / "aster-libp2p-provider"),
        "features": [],
    }


def baseline(root: Path) -> dict[str, object]:
    provider_id = "path+file:///workspace/provider#aster-libp2p-provider@0.1.0"
    lab_id = "path+file:///workspace/lab#aster-lab@0.1.0"
    host_id = "path+file:///workspace/host#aster-host@0.1.0"
    return {
        "workspace_members": [provider_id, lab_id, host_id],
        "workspace_default_members": [provider_id, lab_id, host_id],
        "packages": [
            {
                "id": provider_id,
                "name": "aster-libp2p-provider",
                "publish": [],
                "manifest_path": str(
                    root / "crates" / "aster-libp2p-provider" / "Cargo.toml"
                ),
                "dependencies": [],
                "features": {},
            },
            {
                "id": lab_id,
                "name": "aster-lab",
                "publish": None,
                "manifest_path": str(root / "crates" / "aster-lab" / "Cargo.toml"),
                "dependencies": [dependency(root)],
                "features": {
                    "default": ["legacy-lab"],
                    "legacy-lab": [],
                    "libp2p-candidate": ["dep:aster-libp2p-provider", "dep:tokio"],
                },
            },
            {
                "id": host_id,
                "name": "aster-host",
                "publish": None,
                "manifest_path": str(root / "crates" / "aster-host" / "Cargo.toml"),
                "dependencies": [],
                "features": {},
            },
        ],
    }


class RetainedOracleBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.document = baseline(self.root)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_current_boundary_passes(self) -> None:
        CHECKER.validate_metadata(self.document, self.root)

    def test_standalone_default_workspace_root_is_allowed(self) -> None:
        provider_id = self.document["packages"][0]["id"]
        self.assertIn(provider_id, self.document["workspace_default_members"])
        CHECKER.validate_metadata(self.document, self.root)

    def test_publishable_provider_fails(self) -> None:
        document = copy.deepcopy(self.document)
        document["packages"][0]["publish"] = None
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "publish = false"):
            CHECKER.validate_metadata(document, self.root)

    def test_required_lab_dependency_fails(self) -> None:
        document = copy.deepcopy(self.document)
        document["packages"][1]["dependencies"][0]["optional"] = False
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "must remain optional"):
            CHECKER.validate_metadata(document, self.root)

    def test_relocated_provider_fails(self) -> None:
        document = copy.deepcopy(self.document)
        document["packages"][0]["manifest_path"] = str(
            self.root / "elsewhere" / "Cargo.toml"
        )
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "moved outside"):
            CHECKER.validate_metadata(document, self.root)

    def test_renamed_lab_dependency_fails(self) -> None:
        document = copy.deepcopy(self.document)
        document["packages"][1]["dependencies"][0]["rename"] = "oracle-provider"
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "unrenamed local path"):
            CHECKER.validate_metadata(document, self.root)

    def test_remote_lab_dependency_fails(self) -> None:
        document = copy.deepcopy(self.document)
        document["packages"][1]["dependencies"][0]["source"] = (
            "registry+https://github.com/rust-lang/crates.io-index"
        )
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "unrenamed local path"):
            CHECKER.validate_metadata(document, self.root)

    def test_targeted_lab_dependency_fails(self) -> None:
        document = copy.deepcopy(self.document)
        document["packages"][1]["dependencies"][0]["target"] = "cfg(unix)"
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "unconditional normal"):
            CHECKER.validate_metadata(document, self.root)

    def test_missing_direct_candidate_activation_fails(self) -> None:
        document = copy.deepcopy(self.document)
        document["packages"][1]["features"]["libp2p-candidate"] = ["dep:tokio"]
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "explicitly activate"):
            CHECKER.validate_metadata(document, self.root)

    def test_shipping_consumer_fails(self) -> None:
        document = copy.deepcopy(self.document)
        document["packages"][2]["dependencies"].append(dependency(self.root))
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "only aster-lab may consume"):
            CHECKER.validate_metadata(document, self.root)

    def test_excluded_intermediary_consumer_fails(self) -> None:
        document = copy.deepcopy(self.document)
        bridge_id = "path+file:///workspace/bridge#excluded-bridge@0.1.0"
        document["packages"].append(
            {
                "id": bridge_id,
                "name": "excluded-bridge",
                "publish": None,
                "manifest_path": str(self.root / "excluded-bridge" / "Cargo.toml"),
                "dependencies": [dependency(self.root)],
                "features": {},
            }
        )
        document["packages"][2]["dependencies"].append(
            {
                "name": "excluded-bridge",
                "source": None,
                "kind": None,
                "rename": None,
                "optional": False,
                "target": None,
                "path": str(self.root / "excluded-bridge"),
                "features": [],
            }
        )
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "excluded-bridge"):
            CHECKER.validate_metadata(document, self.root)

    def test_shipping_consumer_through_lab_feature_fails(self) -> None:
        document = copy.deepcopy(self.document)
        document["packages"][2]["dependencies"].append(
            {
                "name": "aster-lab",
                "source": None,
                "kind": None,
                "rename": None,
                "optional": False,
                "target": None,
                "path": str(self.root / "crates" / "aster-lab"),
                "features": ["libp2p-candidate"],
            }
        )
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "aster-host"):
            CHECKER.validate_metadata(document, self.root)

    def test_default_shipping_feature_route_to_lab_candidate_fails(self) -> None:
        document = copy.deepcopy(self.document)
        document["packages"][2]["dependencies"].append(
            {
                "name": "aster-lab",
                "source": None,
                "kind": None,
                "rename": None,
                "optional": True,
                "target": None,
                "path": str(self.root / "crates" / "aster-lab"),
                "features": [],
            }
        )
        document["packages"][2]["features"]["default"] = [
            "aster-lab/libp2p-candidate"
        ]
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "aster-host"):
            CHECKER.validate_metadata(document, self.root)

    def test_renamed_weak_route_to_lab_candidate_fails(self) -> None:
        document = copy.deepcopy(self.document)
        document["packages"][2]["dependencies"].append(
            {
                "name": "aster-lab",
                "source": None,
                "kind": None,
                "rename": "oracle-lab",
                "optional": True,
                "target": None,
                "path": str(self.root / "crates" / "aster-lab"),
                "features": [],
            }
        )
        document["packages"][2]["features"]["shipping"] = [
            "oracle-lab?/libp2p-candidate"
        ]
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "aster-host"):
            CHECKER.validate_metadata(document, self.root)

    def test_default_feature_reaching_candidate_fails(self) -> None:
        document = copy.deepcopy(self.document)
        document["packages"][1]["features"]["default"] = ["libp2p-candidate"]
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "activating features"):
            CHECKER.validate_metadata(document, self.root)

    def test_feature_alias_reaching_candidate_fails(self) -> None:
        document = copy.deepcopy(self.document)
        document["packages"][1]["features"]["oracle-alias"] = ["libp2p-candidate"]
        with self.assertRaisesRegex(CHECKER.BoundaryViolation, "oracle-alias"):
            CHECKER.validate_metadata(document, self.root)


if __name__ == "__main__":
    unittest.main()
