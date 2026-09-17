#!/usr/bin/env python3
"""Fail-closed guards for the trusted Linux Rust compiler cache."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/ci.yml"
MISE = ROOT / "mise.toml"
CI_DOC = ROOT / "docs/validation/ci.md"

ACTION_SHA = "fc920bf0ec8de6ee65d409111f7ec508035751ba"
ACTION_VERSION = "v0.0.11"
SCCACHE_VERSION = "v0.16.0"
CACHE_GENERATION = "aster-linux-x86_64-rust-1.97.1-v1"
TRUST_EXPRESSION = (
    "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' "
    "&& 'write' || 'read' }}"
)
RW_EXPRESSION = (
    "${{ github.event_name == 'push' && github.ref == 'refs/heads/main' "
    "&& 'READ_WRITE' || 'READ_ONLY' }}"
)


def workflow_job(workflow: str, name: str) -> str:
    match = re.search(
        rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [a-zA-Z0-9_-]+:\n|\Z)",
        workflow,
    )
    if match is None:
        raise AssertionError(f"workflow job is missing: {name}")
    return match.group(1)


class CompilerCacheWorkflowTests(unittest.TestCase):
    def test_linux_compile_jobs_share_one_pinned_read_only_pr_cache(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        action = (
            "uses: mozilla-actions/sccache-action@"
            f"{ACTION_SHA} # {ACTION_VERSION}"
        )
        for name in ("quality", "rust-quality"):
            with self.subTest(job=name):
                job = workflow_job(workflow, name)
                self.assertIn(f"cache-mode: {TRUST_EXPRESSION}", job)
                self.assertIn('RUSTC_WRAPPER: "sccache"', job)
                self.assertIn('SCCACHE_GHA_ENABLED: "true"', job)
                self.assertIn(f"SCCACHE_GHA_RW_MODE: {RW_EXPRESSION}", job)
                self.assertIn(f'SCCACHE_GHA_VERSION: "{CACHE_GENERATION}"', job)
                self.assertEqual(job.count(action), 1)
                self.assertIn(f'version: "{SCCACHE_VERSION}"', job)

        self.assertEqual(workflow.count(action), 2)
        self.assertNotRegex(workflow, r"mozilla-actions/sccache-action@v")

    def test_cache_guard_and_public_sources_are_part_of_the_gate(self):
        mise = MISE.read_text(encoding="utf-8")
        self.assertIn(
            '"python3 .github/scripts/test-ci-sccache.py",',
            mise,
        )
        documentation = CI_DOC.read_text(encoding="utf-8")
        self.assertIn("`sccache` v0.16.0", documentation)
        self.assertIn("`sccache-action` v0.0.11", documentation)
        self.assertIn("https://github.com/mozilla/sccache", documentation)
        self.assertIn(
            "https://github.com/mozilla-actions/sccache-action",
            documentation,
        )


if __name__ == "__main__":
    unittest.main()
