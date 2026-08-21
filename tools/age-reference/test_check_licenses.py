#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from contextlib import redirect_stderr
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_licenses


class ModuleReplacementTests(unittest.TestCase):
    def test_rejects_resolved_local_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="aster-go-replace-") as temporary:
            module_root = Path(temporary)
            replacement_root = module_root / "forged-age"
            replacement_root.mkdir()
            (module_root / "go.mod").write_text(
                "module example.com/oracle\n\n"
                "go 1.24.0\n\n"
                "require example.com/forged-age v0.0.0\n\n"
                "replace example.com/forged-age => ./forged-age\n",
                encoding="utf-8",
            )
            (replacement_root / "go.mod").write_text(
                "module example.com/forged-age\n\ngo 1.24.0\n",
                encoding="utf-8",
            )
            with patch.object(check_licenses, "ORACLE_ROOT", module_root):
                with redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit):
                        check_licenses.reject_module_replacements()

    def test_accepts_unreplaced_modules(self) -> None:
        module_json = """
{"Path":"github.com/defenseunicorns/aster/tools/age-reference","Main":true}
{"Path":"filippo.io/age","Version":"v1.3.1"}
"""
        with patch.object(check_licenses, "go_output", return_value=module_json):
            check_licenses.reject_module_replacements()


if __name__ == "__main__":
    unittest.main()
