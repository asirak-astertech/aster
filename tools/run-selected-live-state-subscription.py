#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Create one exclusive raw root for selected live State-subscription acceptance.

This runner deliberately reuses the hardened raw-artifact implementation used
by selected live Event acceptance.  The support module is itself part of the
signed admitted-source set, so that reuse does not create an unhashed execution
dependency.
"""

from __future__ import annotations

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
    sys.modules[name] = module
    try:
        code = compile(source, os.fspath(path), "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


SUPPORT = _load_source_module(
    SUPPORT_PATH, "selected_live_state_subscription_runner_support"
)

RAW_SCHEMA = "aster-selected-live-state-subscription-raw/v1"
CLAIM = (
    "selected-live-state-subscription-one-host-direct-iroh-positive-current-version-"
    "selector-withholding-forced-receiver-process-termination-durable-redelivery-"
    "tombstone-acceptance"
)
BINARY_NAME = "aster-live-state-subscription-acceptance"
EXAMPLE_NAME = "live_state_subscription_acceptance"
TRANSCRIPT_PREFIX = b"LIVE_STATE_SUBSCRIPTION\t"
TRANSCRIPT_RECORDS = 70
PARTICIPANTS = ("publisher", "receiver")
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

PRODUCER_PATH = "crates/aster-node/examples/live_state_subscription_acceptance.rs"
RUNNER_PATH = "tools/run-selected-live-state-subscription.py"
CHECKER_PATH = "tools/check-selected-live-state-subscription-receipt.py"
TEST_PATH = "tools/test-selected-live-state-subscription-receipt.py"
RUNNER_SUPPORT_PATH = "tools/run-selected-live-event.py"
CHECKER_SUPPORT_PATH = "tools/check-selected-live-event-receipt.py"

ADMITTED_PATHS = tuple(
    sorted(
        {
            "Cargo.lock",
            "Cargo.toml",
            "mise.toml",
            "crates/aster-core/Cargo.toml",
            "crates/aster-core/src/causal.rs",
            "crates/aster-core/src/crypto/reference.rs",
            "crates/aster-core/src/lib.rs",
            "crates/aster-core/src/provisioning.rs",
            "crates/aster-core/src/source_state.rs",
            "crates/aster-iroh/Cargo.toml",
            "crates/aster-iroh/src/lib.rs",
            "crates/aster-node/Cargo.toml",
            "crates/aster-node/src/application.rs",
            "crates/aster-node/src/application/state.rs",
            "crates/aster-node/src/frame.rs",
            "crates/aster-node/src/identity.rs",
            "crates/aster-node/src/lib.rs",
            "crates/aster-node/src/mission.rs",
            "crates/aster-node/src/runtime.rs",
            "crates/aster-redb-store/Cargo.toml",
            "crates/aster-redb-store/src/lib.rs",
            "crates/aster-redb-store/src/state_subscription.rs",
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
    SUPPORT.EXPECTED_DIRECTORIES = {
        "",
        "binary",
        "participants",
        "participants/publisher",
        "participants/publisher/state",
        "participants/receiver",
        "participants/receiver/state",
    }
    SUPPORT.PUBLIC_FILES = {
        f"binary/{BINARY_NAME}": 0o700,
        "stdout.log": 0o600,
        "stderr.log": 0o600,
        "transcript.tsv": 0o600,
    }
    SUPPORT.PARTICIPANT_SECRET_FILES = {
        f"participants/{participant}/{relative}": 0o600
        for participant in PARTICIPANTS
        for relative in ("mission.bundle", "state/identity.key", "state/mesh.redb")
    }


_configure_support()

# Public aliases make the security-sensitive primitives directly testable.
RunnerFailure = SUPPORT.RunnerFailure
canonical_json = SUPPORT.canonical_json
extract_transcript = SUPPORT.extract_transcript
inspect_inventory = SUPPORT.inspect_inventory
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
        SUPPORT.main()
    except (OSError, ValueError, RunnerFailure, subprocess.SubprocessError):
        print("selected live State subscription runner failed", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
