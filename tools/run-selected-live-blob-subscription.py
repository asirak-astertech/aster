#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Create one exclusive raw root for selected live Blob-delivery acceptance.

This launcher reuses the hardened raw-artifact implementation used by selected
live Event acceptance.  The delegated support is loaded from exact source bytes
without creating or trusting Python bytecode, is itself part of the signed
admitted-source set, and is checked against that set before the acceptance run.

The Blob depot contains content-derived directory and chunk names.  This runner
records their bounded owner-only metadata but deliberately leaves validation of
their exact semantic shape, names, counts, and sizes to the receipt checker.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import types


SUPPORT_PATH = Path(__file__).with_name("run-selected-live-event.py")


def _read_source_without_bytecode(path: Path) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > 4 * 1024 * 1024
    ):
        raise RuntimeError(f"unsafe runner support source {path}")
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise RuntimeError(f"runner support changed while opening {path}")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise RuntimeError(f"runner support truncated while reading {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError(f"runner support grew while reading {path}")
        final = os.fstat(descriptor)
        terminal = path.lstat()
        if (final.st_dev, final.st_ino, final.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) or (terminal.st_dev, terminal.st_ino, terminal.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise RuntimeError(f"runner support changed while reading {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load_source_module(path: Path, name: str) -> types.ModuleType:
    source = _read_source_without_bytecode(path)
    module = types.ModuleType(name)
    module.__file__ = os.fspath(path)
    module.__package__ = ""
    module.__loaded_source_sha256__ = hashlib.sha256(source).hexdigest()
    sys.modules[name] = module
    try:
        code = compile(source, os.fspath(path), "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


SUPPORT = _load_source_module(
    SUPPORT_PATH, "selected_live_blob_subscription_runner_support"
)

RAW_SCHEMA = "aster-selected-live-blob-subscription-raw/v1"
CLAIM = (
    "selected-live-blob-subscription-one-host-peerless-exact-publication-"
    "shared-content-forced-receiver-process-termination-durable-redelivery-"
    "reopen-acceptance"
)
BINARY_NAME = "aster-live-blob-subscription-acceptance"
EXAMPLE_NAME = "live_blob_subscription_acceptance"
TRANSCRIPT_PREFIX = b"LIVE_BLOB_SUBSCRIPTION\t"
TRANSCRIPT_RECORDS = 35
PARTICIPANTS = ("node",)
RUN_TIMEOUT_SECONDS = 240
BUILD_ARGV = [
    "cargo",
    "build",
    "--release",
    "--locked",
    "-p",
    "aster-node",
    "--example",
    EXAMPLE_NAME,
]

PRODUCER_PATH = "crates/aster-node/examples/live_blob_subscription_acceptance.rs"
RUNNER_PATH = "tools/run-selected-live-blob-subscription.py"
CHECKER_PATH = "tools/check-selected-live-blob-subscription-receipt.py"
TEST_PATH = "tools/test-selected-live-blob-subscription-receipt.py"
RUNNER_SUPPORT_PATH = "tools/run-selected-live-event.py"
CHECKER_SUPPORT_PATH = "tools/check-selected-live-event-receipt.py"

ADMITTED_PATHS = tuple(
    sorted(
        {
            "Cargo.lock",
            "Cargo.toml",
            "mise.toml",
            "crates/aster-core/Cargo.toml",
            "crates/aster-core/src/blob.rs",
            "crates/aster-core/src/causal.rs",
            "crates/aster-core/src/crypto/reference.rs",
            "crates/aster-core/src/lib.rs",
            "crates/aster-core/src/provisioning.rs",
            "crates/aster-core/src/source_blob.rs",
            "crates/aster-core/src/store.rs",
            "crates/aster-iroh/Cargo.toml",
            "crates/aster-iroh/src/lib.rs",
            "crates/aster-node/Cargo.toml",
            "crates/aster-node/src/application.rs",
            "crates/aster-node/src/application/blob.rs",
            "crates/aster-node/src/frame.rs",
            "crates/aster-node/src/identity.rs",
            "crates/aster-node/src/lib.rs",
            "crates/aster-node/src/mission.rs",
            "crates/aster-node/src/runtime.rs",
            "crates/aster-redb-store/Cargo.toml",
            "crates/aster-redb-store/src/blob.rs",
            "crates/aster-redb-store/src/blob/depot.rs",
            "crates/aster-redb-store/src/blob_subscription.rs",
            "crates/aster-redb-store/src/lib.rs",
            PRODUCER_PATH,
            RUNNER_PATH,
            CHECKER_PATH,
            TEST_PATH,
            RUNNER_SUPPORT_PATH,
            CHECKER_SUPPORT_PATH,
        }
    )
)
TOOL_PATHS = {
    "producer": PRODUCER_PATH,
    "runner": RUNNER_PATH,
    "checker": CHECKER_PATH,
    "test": TEST_PATH,
}

FIXED_EXPECTED_DIRECTORIES = {
    "",
    "binary",
    "participants",
    "participants/node",
    "participants/node/state",
    "participants/node/state/blob-depot-v1",
}
FIXED_PUBLIC_FILES = {
    f"binary/{BINARY_NAME}": 0o700,
    "stdout.log": 0o600,
    "stderr.log": 0o600,
    "transcript.tsv": 0o600,
}
FIXED_PARTICIPANT_SECRET_FILES = {
    "participants/node/mission.bundle": 0o600,
    "participants/node/state/identity.key": 0o600,
    "participants/node/state/mesh.redb": 0o600,
}
DEPOT_RELATIVE = "participants/node/state/blob-depot-v1"


def _configure_support() -> None:
    values = {
        "RAW_SCHEMA": RAW_SCHEMA,
        "CLAIM": CLAIM,
        "BINARY_NAME": BINARY_NAME,
        "EXAMPLE_NAME": EXAMPLE_NAME,
        "TRANSCRIPT_PREFIX": TRANSCRIPT_PREFIX,
        "TRANSCRIPT_RECORDS": TRANSCRIPT_RECORDS,
        "PARTICIPANTS": PARTICIPANTS,
        "RUN_TIMEOUT_SECONDS": RUN_TIMEOUT_SECONDS,
        "BUILD_ARGV": BUILD_ARGV,
        "ADMITTED_PATHS": ADMITTED_PATHS,
        "TOOL_PATHS": TOOL_PATHS,
    }
    for name, value in values.items():
        setattr(SUPPORT, name, value)
    SUPPORT.EXPECTED_DIRECTORIES = set(FIXED_EXPECTED_DIRECTORIES)
    SUPPORT.PUBLIC_FILES = dict(FIXED_PUBLIC_FILES)
    SUPPORT.PARTICIPANT_SECRET_FILES = dict(FIXED_PARTICIPANT_SECRET_FILES)


_configure_support()
_STRICT_INSPECT_INVENTORY = SUPPORT.inspect_inventory


def _require_private_directory(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise SUPPORT.RunnerFailure()


def _require_private_file(metadata: os.stat_result) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
    ):
        raise SUPPORT.RunnerFailure()


def _register_depot_inventory(raw_root: Path) -> None:
    """Admit bounded depot metadata while deferring its exact shape to the checker."""

    SUPPORT.EXPECTED_DIRECTORIES = set(FIXED_EXPECTED_DIRECTORIES)
    SUPPORT.PARTICIPANT_SECRET_FILES = dict(FIXED_PARTICIPANT_SECRET_FILES)
    depot = raw_root / DEPOT_RELATIVE
    directory_flags = (
        os.O_RDONLY
        | os.O_DIRECTORY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    depot_descriptor = os.open(depot, directory_flags)
    try:
        _require_private_directory(os.fstat(depot_descriptor))
        names = sorted(os.listdir(depot_descriptor))
        if len(names) > 32:
            raise SUPPORT.RunnerFailure()
        for name in names:
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                raise SUPPORT.RunnerFailure()
            relative = f"{DEPOT_RELATIVE}/{name}"
            before = os.stat(name, dir_fd=depot_descriptor, follow_symlinks=False)
            if stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode):
                _require_private_file(before)
                SUPPORT.PARTICIPANT_SECRET_FILES[relative] = 0o600
                continue
            if not stat.S_ISDIR(before.st_mode):
                raise SUPPORT.RunnerFailure()
            variant_descriptor = os.open(name, directory_flags, dir_fd=depot_descriptor)
            try:
                opened = os.fstat(variant_descriptor)
                if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                    raise SUPPORT.RunnerFailure()
                _require_private_directory(opened)
                SUPPORT.EXPECTED_DIRECTORIES.add(relative)
                chunk_names = sorted(os.listdir(variant_descriptor))
                if len(chunk_names) > 32:
                    raise SUPPORT.RunnerFailure()
                for chunk_name in chunk_names:
                    if (
                        not chunk_name
                        or chunk_name in {".", ".."}
                        or "/" in chunk_name
                        or "\x00" in chunk_name
                    ):
                        raise SUPPORT.RunnerFailure()
                    chunk = os.stat(
                        chunk_name,
                        dir_fd=variant_descriptor,
                        follow_symlinks=False,
                    )
                    _require_private_file(chunk)
                    SUPPORT.PARTICIPANT_SECRET_FILES[
                        f"{relative}/{chunk_name}"
                    ] = 0o600
            finally:
                os.close(variant_descriptor)
    finally:
        os.close(depot_descriptor)


def inspect_inventory(raw_root: Path):
    _register_depot_inventory(raw_root)
    return _STRICT_INSPECT_INVENTORY(raw_root)


SUPPORT.inspect_inventory = inspect_inventory

# Public aliases make the security-sensitive primitives directly testable.
RunnerFailure = SUPPORT.RunnerFailure
canonical_json = SUPPORT.canonical_json
extract_transcript = SUPPORT.extract_transcript
safe_git_environment = SUPPORT.safe_git_environment
source_snapshot = SUPPORT.source_snapshot


def main() -> None:
    try:
        arguments = SUPPORT.parse_arguments()
        source = Path(arguments.source)
        if not source.is_absolute():
            raise RunnerFailure()
        source = source.resolve(strict=True)
        for observed, relative in (
            (Path(__file__), RUNNER_PATH),
            (SUPPORT_PATH, RUNNER_SUPPORT_PATH),
        ):
            if not os.path.samefile(observed, source / relative):
                raise RunnerFailure()
        git_executable, trusted_options = SUPPORT.reviewer_signature_options()
        authority = SUPPORT.source_snapshot(source, git_executable, trusted_options)
        admitted = {item["path"]: item for item in authority["admitted"]}
        if admitted[RUNNER_SUPPORT_PATH]["sha256"] != SUPPORT.__loaded_source_sha256__:
            raise RunnerFailure()
        SUPPORT.main()
    except (OSError, ValueError, RunnerFailure, subprocess.SubprocessError):
        print("selected live Blob subscription runner failed", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
