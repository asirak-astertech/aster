#!/usr/bin/env python3
"""Tests for the bounded nextest JUnit timing summary."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("summarize-nextest-junit.py")


class TimingSummaryTests(unittest.TestCase):
    def test_reports_total_and_slowest_tests_in_descending_order(self):
        report = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="3" time="4.75">
  <testsuite name="aster-node::runtime" tests="2" time="4.5">
    <testcase classname="aster_node::runtime" name="fast_case" time="0.5" />
    <testcase classname="aster_node::runtime" name="slow|case" time="4.0" />
  </testsuite>
  <testsuite name="aster-core::api" tests="1" time="0.25">
    <testcase classname="aster_core::api" name="middle_case" time="0.25" />
  </testsuite>
</testsuites>
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "junit.xml"
            output = root / "summary.md"
            source.write_text(report, encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--input",
                    str(source),
                    "--output",
                    str(output),
                    "--partition",
                    "1/2",
                    "--limit",
                    "2",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            summary = output.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("## Rust test timing — partition 1/2", summary)
        self.assertIn("Tests recorded: 3", summary)
        self.assertIn("Cumulative test time: 4.750s", summary)
        self.assertLess(summary.index("slow\\|case"), summary.index("fast_case"))
        self.assertNotIn("middle_case", summary)

    def test_rejects_malformed_empty_or_non_finite_reports(self):
        for report in (
            "not XML",
            "<testsuites />",
            '<testsuites><testcase name="invalid" time="nan" /></testsuites>',
            '<testsuites><testcase name="invalid" time="inf" /></testsuites>',
        ):
            with self.subTest(report=report):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    source = root / "junit.xml"
                    output = root / "summary.md"
                    source.write_text(report, encoding="utf-8")
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(SCRIPT),
                            "--input",
                            str(source),
                            "--output",
                            str(output),
                            "--partition",
                            "2/2",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn("nextest timing summary failed", result.stderr)
                self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
