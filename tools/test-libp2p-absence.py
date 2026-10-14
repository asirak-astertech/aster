#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed regressions for removal of the experimental provider."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

CHECKER_PATH = Path(__file__).with_name("check-libp2p-absence.py")
SPEC = importlib.util.spec_from_file_location("boundary", CHECKER_PATH)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class AbsenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.package = {"id": "lab", "name": "aster-lab", "dependencies": [], "features": {}}
        self.document = {"packages": [self.package], "workspace_members": ["lab"]}

    def test_absence_passes(self):
        CHECKER.validate_metadata(self.document, self.root)

    def test_removed_packages_fail(self):
        for name in ("aster-libp2p-provider", "libp2p", "libp2p-core"):
            with self.subTest(name=name):
                self.package["name"] = name
                with self.assertRaises(CHECKER.BoundaryViolation):
                    CHECKER.validate_metadata(self.document, self.root)

    def test_optional_renamed_dependency_fails(self):
        self.package["dependencies"] = [{"name": "libp2p", "rename": "carrier", "optional": True}]
        with self.assertRaises(CHECKER.BoundaryViolation):
            CHECKER.validate_metadata(self.document, self.root)

    def test_candidate_feature_fails(self):
        self.package["features"] = {"libp2p-candidate": []}
        with self.assertRaises(CHECKER.BoundaryViolation):
            CHECKER.validate_metadata(self.document, self.root)

    def test_provider_directory_fails(self):
        (self.root / "crates/aster-libp2p-provider").mkdir(parents=True)
        with self.assertRaises(CHECKER.BoundaryViolation):
            CHECKER.validate_metadata(self.document, self.root)

    def test_malformed_metadata_fails(self):
        with self.assertRaises(CHECKER.BoundaryViolation):
            CHECKER.validate_metadata({}, self.root)


if __name__ == "__main__":
    unittest.main()
