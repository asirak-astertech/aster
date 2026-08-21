#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Verify the canonical Go oracle's compiled module-license receipts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ORACLE_ROOT = Path(__file__).resolve().parent
RECEIPTS = ORACLE_ROOT / "dependency-licenses.tsv"
CANONICAL_GOOS = "linux"
CANONICAL_GOARCH = "amd64"
ALLOWED_LICENSES = {
    "Apache-2.0",
    "Apache-2.0 OR MIT",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "MIT",
    "MIT OR Apache-2.0",
}


def fail(message: str) -> None:
    print(f"Go dependency-license policy failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def go_output(*args: str) -> str:
    environment = os.environ.copy()
    environment.update(
        {
            "GOARCH": CANONICAL_GOARCH,
            "GOOS": CANONICAL_GOOS,
            "GOWORK": "off",
            "CGO_ENABLED": "0",
        }
    )
    completed = subprocess.run(
        [environment.get("GO", "go"), *args],
        cwd=ORACLE_ROOT,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        print(completed.stderr, file=sys.stderr, end="")
        fail(f"go {' '.join(args)} exited with {completed.returncode}")
    return completed.stdout


def load_receipts() -> dict[str, tuple[str, str, str]]:
    receipts: dict[str, tuple[str, str, str]] = {}
    for line_number, raw_line in enumerate(
        RECEIPTS.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not raw_line or raw_line.startswith("#"):
            continue
        fields = raw_line.split("\t")
        if len(fields) != 4:
            fail(f"receipt line {line_number} must have four tab-separated fields")
        module, license_expression, license_path, expected_hash = fields
        if module in receipts:
            fail(f"duplicate receipt for {module}")
        if license_expression not in ALLOWED_LICENSES:
            fail(f"{module} uses disallowed license expression {license_expression}")
        if len(expected_hash) != 64 or any(
            character not in "0123456789abcdef" for character in expected_hash
        ):
            fail(f"{module} has a malformed SHA-256 receipt")
        receipts[module] = (license_expression, license_path, expected_hash)
    if not receipts:
        fail("receipt file is empty")
    return receipts


def module_records(output: str) -> list[dict[str, object]]:
    decoder = json.JSONDecoder()
    records: list[dict[str, object]] = []
    position = 0
    while position < len(output):
        while position < len(output) and output[position].isspace():
            position += 1
        if position == len(output):
            break
        try:
            record, position = decoder.raw_decode(output, position)
        except json.JSONDecodeError as error:
            fail(f"Go returned malformed module JSON: {error}")
        if not isinstance(record, dict):
            fail("Go returned a non-object module record")
        records.append(record)
    if not records:
        fail("Go returned no resolved module records")
    return records


def reject_module_replacements() -> None:
    output = go_output("list", "-mod=readonly", "-m", "-json", "all")
    for record in module_records(output):
        replacement = record.get("Replace")
        if replacement is None:
            continue
        path = record.get("Path", "unknown module")
        version = record.get("Version", "unversioned")
        fail(f"resolved module {path}@{version} uses a replacement: {replacement}")


def compiled_modules() -> set[str]:
    package_template = (
        "{{with .Module}}{{if and (not .Main) .Version}}"
        "{{.Path}}@{{.Version}}{{end}}{{end}}"
    )
    return {
        line
        for line in go_output(
            "list", "-mod=readonly", "-deps", "-test", "-f", package_template, "./..."
        ).splitlines()
        if line
    }


def module_directories() -> dict[str, Path]:
    module_template = (
        "{{if and (not .Main) .Version}}"
        "{{.Path}}@{{.Version}}|{{.Dir}}{{end}}"
    )
    directories: dict[str, Path] = {}
    for line in go_output(
        "list", "-mod=readonly", "-m", "-f", module_template, "all"
    ).splitlines():
        if not line:
            continue
        module, separator, directory = line.partition("|")
        if separator != "|":
            fail(f"Go returned a malformed module-directory record: {line}")
        # `go list -m all` can report modules that are present only in a
        # dependency's go.mod graph and therefore have no downloaded source.
        # Only the separately enumerated compiled modules require a directory.
        if not directory:
            continue
        directories[module] = Path(directory).resolve()
    return directories


def main() -> None:
    reject_module_replacements()
    receipts = load_receipts()
    compiled = compiled_modules()
    if compiled != set(receipts):
        missing = sorted(compiled - set(receipts))
        stale = sorted(set(receipts) - compiled)
        fail(f"compiled graph changed; missing receipts={missing}, stale receipts={stale}")

    directories = module_directories()
    for module in sorted(compiled):
        license_expression, relative_path, expected_hash = receipts[module]
        module_root = directories.get(module)
        if module_root is None:
            fail(f"Go omitted the resolved source directory for {module}")
        license_file = (module_root / relative_path).resolve()
        if not license_file.is_relative_to(module_root):
            fail(f"{module} receipt escapes its module directory")
        if not license_file.is_file():
            fail(f"{module} omits recorded license file {relative_path}")
        actual_hash = hashlib.sha256(license_file.read_bytes()).hexdigest()
        if actual_hash != expected_hash:
            fail(
                f"{module} license hash changed: expected {expected_hash}, got {actual_hash}"
            )
        print(
            f"Go license receipt: {module} {license_expression} "
            f"{relative_path} sha256:{actual_hash}"
        )

    print(
        f"Go dependency-license policy passed for {len(compiled)} compiled modules "
        f"on {CANONICAL_GOOS}/{CANONICAL_GOARCH} with CGO disabled"
    )


if __name__ == "__main__":
    main()
