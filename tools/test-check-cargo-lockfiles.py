# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Exercise real Cargo rejection of stale independent lockfiles without networking."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
GRAPHS = (Path("."), Path("fuzz"), Path("conformance/evaluation-v0/runner"))


class CargoLockfileTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.env = {**os.environ, "CARGO_NET_OFFLINE": "true"}
        shutil.copyfile(ROOT / "rust-toolchain.toml", self.root / "rust-toolchain.toml")
        (self.root / "tools").mkdir()
        shutil.copyfile(ROOT / "tools/check-cargo-lockfiles.sh",
                        self.root / "tools/check-cargo-lockfiles.sh")
        for index, graph in enumerate(GRAPHS):
            directory = self.root / graph
            (directory / "src").mkdir(parents=True)
            (directory / "src/lib.rs").write_text("")
            (directory / "Cargo.toml").write_text(
                f'[package]\nname = "lockfile-fixture-{index}"\n'
                'version = "0.1.0"\nedition = "2024"\n\n[workspace]\n'
            )
            subprocess.run(["cargo", "generate-lockfile", "--offline"],
                           cwd=directory, env=self.env, check=True, capture_output=True)

    def check_graphs(self, failed=()):
        locks = {graph: (self.root / graph / "Cargo.lock").read_bytes()
                 for graph in GRAPHS if (self.root / graph / "Cargo.lock").exists()}
        completed = subprocess.run(
            ["sh", "tools/check-cargo-lockfiles.sh"], cwd=self.root, env=self.env,
            text=True, capture_output=True,
        )
        self.assertEqual(completed.returncode, int(bool(failed)), completed.stderr)
        for graph in GRAPHS:
            manifest = (graph / "Cargo.toml").as_posix()
            self.assertIn(f"Checking committed Cargo lockfile: {manifest}", completed.stdout)
            if graph in failed:
                self.assertIn(f"Lockfile validation failed for {manifest};", completed.stderr)
            lockfile = self.root / graph / "Cargo.lock"
            if graph in locks:
                self.assertEqual(lockfile.read_bytes(), locks[graph])
            else:
                self.assertFalse(lockfile.exists())

    def test_accepts_consistent_but_different_graphs(self):
        self.check_graphs()

    def test_rejects_each_stale_lockfile_without_rewriting_it(self):
        for graph in GRAPHS:
            with self.subTest(graph=graph):
                manifest = self.root / graph / "Cargo.toml"
                original = manifest.read_text()
                manifest.write_text(original.replace('"0.1.0"', '"0.2.0"'))
                try:
                    self.check_graphs(failed=(graph,))
                finally:
                    manifest.write_text(original)

    def test_reports_all_missing_lockfiles_without_creating_them(self):
        for graph in GRAPHS:
            (self.root / graph / "Cargo.lock").unlink()
        self.check_graphs(failed=GRAPHS)


if __name__ == "__main__":
    unittest.main()
