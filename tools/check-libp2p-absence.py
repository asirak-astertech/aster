#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Reject the removed experimental provider in root and fuzz dependency graphs."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[1]


class BoundaryViolation(ValueError):
    """The removed provider or its dependency family was reintroduced."""


def forbidden(name: str) -> bool:
    return name == "aster-libp2p-provider" or name == "libp2p" or name.startswith("libp2p-")


def validate_metadata(document: dict, repository_root: Path) -> None:
    packages = document.get("packages")
    members = document.get("workspace_members")
    if not isinstance(packages, list) or not isinstance(members, list):
        raise BoundaryViolation("cargo metadata omitted packages or workspace_members")
    if (repository_root / "crates/aster-libp2p-provider").exists():
        raise BoundaryViolation("removed provider directory exists")
    ids = set()
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str):
            raise BoundaryViolation("malformed package metadata")
        if package["id"] in ids:
            raise BoundaryViolation("duplicate package metadata")
        ids.add(package["id"])
        name = package.get("name")
        if not isinstance(name, str) or forbidden(name):
            raise BoundaryViolation(f"removed or malformed package: {name}")
        dependencies = package.get("dependencies")
        features = package.get("features")
        if not isinstance(dependencies, list) or not isinstance(features, dict):
            raise BoundaryViolation("malformed dependencies or features")
        for dependency in dependencies:
            if not isinstance(dependency, dict) or not isinstance(dependency.get("name"), str):
                raise BoundaryViolation("malformed dependency")
            if forbidden(dependency["name"]):
                raise BoundaryViolation(f"removed dependency in {name}: {dependency['name']}")
        if "libp2p-candidate" in features:
            raise BoundaryViolation("removed lab candidate feature exists")
    if any(not isinstance(member, str) or member not in ids for member in members):
        raise BoundaryViolation("unknown workspace member")


def main() -> None:
    cargo = shlex.split(os.environ.get("CARGO", "cargo"))
    if not cargo:
        raise BoundaryViolation("CARGO resolved to an empty command")
    for directory in (ROOT, ROOT / "fuzz"):
        result = subprocess.run(
            [*cargo, "metadata", "--locked", "--offline", "--all-features",
             "--format-version", "1", "--manifest-path", str(directory / "Cargo.toml")],
            cwd=ROOT, check=True, capture_output=True, text=True,
        )
        validate_metadata(json.loads(result.stdout), ROOT)
        with (directory / "Cargo.lock").open("rb") as source:
            for package in tomllib.load(source)["package"]:
                if forbidden(package["name"]):
                    raise BoundaryViolation(f"removed package in {directory}/Cargo.lock: {package['name']}")
    print("libp2p absence passed: provider, candidate feature and dependency family absent from root and fuzz")


if __name__ == "__main__":
    try:
        main()
    except (BoundaryViolation, subprocess.CalledProcessError, ValueError) as error:
        print(f"libp2p absence failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        raise SystemExit(1) from error
