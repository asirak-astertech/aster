#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Keep the rejected libp2p provider inside its retained test-oracle boundary.

The provider remains directly buildable as a standalone workspace root. This policy
guards publication and dependency consumption; it does not hide the retained oracle
from explicit or workspace-wide validation.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from typing import Any


PROVIDER = "aster-libp2p-provider"
LAB = "aster-lab"
CANDIDATE_FEATURE = "libp2p-candidate"
ROOT = Path(__file__).resolve().parents[1]


class BoundaryViolation(ValueError):
    """The retained provider escaped its approved manifest boundary."""


def fail(message: str) -> None:
    raise BoundaryViolation(message)


def package_records(
    document: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    packages = document.get("packages")
    members = document.get("workspace_members")
    if not isinstance(packages, list) or not isinstance(members, list):
        fail("cargo metadata omitted packages or workspace_members")

    by_id: dict[str, dict[str, Any]] = {}
    all_packages = []
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str):
            fail("cargo metadata returned a malformed package record")
        if package["id"] in by_id:
            fail(f"cargo metadata returned duplicate package id {package['id']}")
        by_id[package["id"]] = package
        all_packages.append(package)

    try:
        workspace_packages = [by_id[member] for member in members]
    except (KeyError, TypeError) as error:
        fail(f"cargo metadata returned an unknown workspace member: {error}")
    return all_packages, workspace_packages


def one_package(packages: list[dict[str, Any]], name: str) -> dict[str, Any]:
    matches = [package for package in packages if package.get("name") == name]
    if len(matches) != 1:
        fail(f"expected exactly one workspace package named {name}, found {len(matches)}")
    return matches[0]


def dependency_activating_features(
    features: dict[str, list[str]], dependency: str
) -> set[str]:
    direct = set()
    for feature, entries in features.items():
        for entry in entries:
            if entry == f"dep:{dependency}" or entry.startswith(f"{dependency}/"):
                direct.add(feature)

    activating = set(direct)
    changed = True
    while changed:
        changed = False
        for feature, entries in features.items():
            if feature not in activating and any(entry in activating for entry in entries):
                activating.add(feature)
                changed = True
    return activating


def normalized_features(package: dict[str, Any]) -> dict[str, list[str]]:
    name = package.get("name", "<unknown>")
    raw_features = package.get("features")
    if not isinstance(raw_features, dict):
        fail(f"{name} has malformed feature metadata")
    features: dict[str, list[str]] = {}
    for feature, entries in raw_features.items():
        if not isinstance(feature, str) or not isinstance(entries, list) or not all(
            isinstance(entry, str) for entry in entries
        ):
            fail(f"{name} has malformed feature metadata")
        features[feature] = entries
    return features


def dependency_requests_feature(
    package: dict[str, Any], dependency: dict[str, Any], requested_feature: str
) -> bool:
    requested = dependency.get("features")
    if not isinstance(requested, list) or not all(
        isinstance(feature, str) for feature in requested
    ):
        fail(f"{package.get('name', '<unknown>')} has malformed dependency features")
    if requested_feature in requested:
        return True

    dependency_key = dependency.get("rename") or dependency.get("name")
    if not isinstance(dependency_key, str):
        fail(f"{package.get('name', '<unknown>')} has a malformed dependency name")
    strong = f"{dependency_key}/{requested_feature}"
    weak = f"{dependency_key}?/{requested_feature}"
    return any(
        entry == strong or entry == weak
        for entries in normalized_features(package).values()
        for entry in entries
    )


def validate_metadata(document: dict[str, Any], repository_root: Path) -> None:
    packages, workspace_packages = package_records(document)
    provider = one_package(workspace_packages, PROVIDER)
    lab = one_package(workspace_packages, LAB)

    default_members = document.get("workspace_default_members")
    if not isinstance(default_members, list) or not all(
        isinstance(member, str) for member in default_members
    ):
        fail("cargo metadata omitted or malformed workspace_default_members")
    workspace_ids = {package["id"] for package in workspace_packages}
    unknown_defaults = sorted(set(default_members) - workspace_ids)
    if unknown_defaults:
        fail(f"cargo metadata returned unknown default workspace members {unknown_defaults}")

    if provider.get("publish") != []:
        fail(f"{PROVIDER} must declare publish = false")

    provider_manifest = provider.get("manifest_path")
    if not isinstance(provider_manifest, str):
        fail(f"{PROVIDER} omitted its manifest path")
    expected_manifest = repository_root / "crates" / PROVIDER / "Cargo.toml"
    if Path(provider_manifest).resolve() != expected_manifest.resolve():
        fail(f"{PROVIDER} moved outside crates/{PROVIDER}")
    provider_path = expected_manifest.parent.resolve()

    consumers: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for package in packages:
        dependencies = package.get("dependencies")
        if not isinstance(dependencies, list):
            fail(f"{package.get('name', '<unknown>')} has malformed dependency metadata")
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                fail(f"{package.get('name', '<unknown>')} has a malformed dependency")
            if dependency.get("name") == PROVIDER:
                consumers.append((package, dependency))

    if len(consumers) != 1 or consumers[0][0].get("name") != LAB:
        names = sorted(str(package.get("name")) for package, _ in consumers)
        fail(f"only {LAB} may consume {PROVIDER}; found consumers {names}")

    consumer, dependency = consumers[0]
    if consumer is not lab:
        fail(f"only the canonical {LAB} package may consume {PROVIDER}")
    if dependency.get("optional") is not True:
        fail(f"{LAB}'s {PROVIDER} dependency must remain optional")
    if dependency.get("kind") is not None or dependency.get("target") is not None:
        fail(f"{LAB}'s {PROVIDER} dependency must be an unconditional normal dependency")
    if dependency.get("rename") is not None or dependency.get("source") is not None:
        fail(f"{LAB}'s {PROVIDER} dependency must remain an unrenamed local path")
    dependency_path = dependency.get("path")
    if not isinstance(dependency_path, str) or Path(dependency_path).resolve() != provider_path:
        fail(f"{LAB}'s {PROVIDER} dependency must point to crates/{PROVIDER}")

    features = normalized_features(lab)

    candidate_entries = features.get(CANDIDATE_FEATURE)
    if candidate_entries is None or f"dep:{PROVIDER}" not in candidate_entries:
        fail(f"{CANDIDATE_FEATURE} must explicitly activate dep:{PROVIDER}")

    activating = dependency_activating_features(features, PROVIDER)
    if activating != {CANDIDATE_FEATURE}:
        fail(
            f"only {LAB}/{CANDIDATE_FEATURE} may activate {PROVIDER}; "
            f"found activating features {sorted(activating)}"
        )

    external_activators = []
    for package in packages:
        if package is lab:
            continue
        for package_dependency in package["dependencies"]:
            if package_dependency.get("name") == LAB and dependency_requests_feature(
                package, package_dependency, CANDIDATE_FEATURE
            ):
                external_activators.append(str(package.get("name")))
    if external_activators:
        fail(
            f"workspace packages outside {LAB} may not enable {CANDIDATE_FEATURE}; "
            f"found {sorted(external_activators)}"
        )


def load_metadata(repository_root: Path) -> dict[str, Any]:
    cargo = shlex.split(os.environ.get("CARGO", "cargo"))
    if not cargo:
        fail("CARGO resolved to an empty command")
    completed = subprocess.run(
        [
            *cargo,
            "metadata",
            "--locked",
            "--offline",
            "--all-features",
            "--format-version",
            "1",
            "--manifest-path",
            str(repository_root / "Cargo.toml"),
        ],
        cwd=repository_root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if completed.returncode != 0:
        print(completed.stderr, file=sys.stderr, end="")
        fail(f"cargo metadata exited with {completed.returncode}")
    try:
        document = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        fail(f"cargo metadata returned invalid JSON: {error}")
    if not isinstance(document, dict):
        fail("cargo metadata returned a non-object document")
    return document


def main() -> None:
    try:
        validate_metadata(load_metadata(ROOT), ROOT)
    except BoundaryViolation as error:
        print(f"retained-libp2p-oracle boundary failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print(
        "retained-libp2p-oracle boundary passed: provider is unpublished; standalone "
        "workspace-root builds remain allowed; only optional "
        "aster-lab/libp2p-candidate may consume it"
    )


if __name__ == "__main__":
    main()
