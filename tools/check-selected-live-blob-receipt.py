#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Project or validate one retained selected live Blob receipt.

The raw root is an owner-only, exact-inventory acceptance artifact.  This
validator reads only the public transcript, terminal captures, run metadata,
and copied release executable. Participant mission bundles, identity keys, redb
databases, depot owner markers, and encrypted chunk files are inspected by metadata only:
their contents are never opened, read, or hashed.

The result is a compact, canonical JSON receipt.  It intentionally makes no
physical-host, NAT, relay, BTLE, independent-implementation, scale, resource
threshold, reproducible-build, or cryptographic source-to-execution claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import pwd
import re
import shutil
import stat
import subprocess
import sys
from typing import Any, Iterable, Sequence


SCHEMA = "aster-selected-live-blob-receipt/v1"
RAW_SCHEMA = "aster-selected-live-blob-raw/v1"
TRANSCRIPT_SCHEMA = "aster-selected-live-blob-transcript/v1"
CLAIM = "selected-live-blob-one-host-direct-iroh-peerless-publish-transfer-read-restart-acceptance"
RECEIPT_NAME = "selected-live-blob-receipt.json"
RECEIPT_MAX_BYTES = 16 * 1024
RUN_JSON_MAX_BYTES = 64 * 1024
TRANSCRIPT_MAX_BYTES = 64 * 1024
STDOUT_MAX_BYTES = 8 * 1024 * 1024
STDERR_MAX_BYTES = 16 * 1024
BINARY_MAX_BYTES = 128 * 1024 * 1024
MISSION_MAX_BYTES = 1024 * 1024
STORE_MAX_BYTES = 1024 * 1024 * 1024
OWNER_MARKER_BYTES = 72
TRANSCRIPT_RECORDS = 31

HEX_32 = re.compile(r"[0-9a-f]{64}\Z")
GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
RUN_ID = re.compile(r"[0-9a-f]{16}\Z")
FIELD_NAME = re.compile(r"[a-z][a-z0-9_]*\Z")
SIGNER_FINGERPRINT = re.compile(
    r"(?:[0-9A-F]{40,64}|SHA256:[A-Za-z0-9+/]{43})\Z"
)

PRODUCER_PATH = "crates/aster-node/examples/live_blob_acceptance.rs"
RUNNER_PATH = "tools/run-selected-live-blob.py"
CHECKER_PATH = "tools/check-selected-live-blob-receipt.py"
TEST_PATH = "tools/test-selected-live-blob-receipt.py"
ADMITTED_SOURCE_PATHS = tuple(
    sorted(
        (
            "Cargo.toml",
            "Cargo.lock",
            "mise.toml",
            "crates/aster-core/Cargo.toml",
            "crates/aster-core/src/blob.rs",
            "crates/aster-core/src/source_blob.rs",
            "crates/aster-core/src/store.rs",
            "crates/aster-core/src/crypto/reference.rs",
            "crates/aster-redb-store/Cargo.toml",
            "crates/aster-redb-store/src/blob.rs",
            "crates/aster-redb-store/src/blob/depot.rs",
            "crates/aster-redb-store/src/lib.rs",
            "crates/aster-node/Cargo.toml",
            "crates/aster-node/src/application.rs",
            "crates/aster-node/src/application/blob.rs",
            "crates/aster-node/src/frame.rs",
            "crates/aster-node/src/lib.rs",
            "crates/aster-node/src/runtime.rs",
            PRODUCER_PATH,
            RUNNER_PATH,
            CHECKER_PATH,
            TEST_PATH,
        )
    )
)
TOOL_PATHS = {
    "producer": PRODUCER_PATH,
    "runner": RUNNER_PATH,
    "checker": CHECKER_PATH,
    "test": TEST_PATH,
}
EXPECTED_BUILD_ARGV = [
    "cargo",
    "build",
    "--release",
    "--locked",
    "-p",
    "aster-node",
    "--example",
    "live_blob_acceptance",
]

EXPECTED_BASE_DIRECTORIES = {
    "",
    "binary",
    "participants",
    "participants/publisher",
    "participants/publisher/state",
    "participants/publisher/state/blob-depot-v1",
    "participants/receiver",
    "participants/receiver/state",
    "participants/receiver/state/blob-depot-v1",
}
EXPECTED_BASE_FILES = {
    "run.json": 0o600,
    "stdout.log": 0o600,
    "stderr.log": 0o600,
    "transcript.tsv": 0o600,
    "binary/aster-live-blob-acceptance": 0o700,
    "participants/publisher/mission.bundle": 0o600,
    "participants/publisher/state/identity.key": 0o600,
    "participants/publisher/state/mesh.redb": 0o600,
    "participants/publisher/state/blob-depot-v1/.aster-store-owner-v1": 0o600,
    "participants/receiver/mission.bundle": 0o600,
    "participants/receiver/state/identity.key": 0o600,
    "participants/receiver/state/mesh.redb": 0o600,
    "participants/receiver/state/blob-depot-v1/.aster-store-owner-v1": 0o600,
}
VARIANT_DIRECTORY = re.compile(r"[0-9a-f]{64}\Z")
CHUNK_FILE = re.compile(r"0000000000000000000([01])[.]chunk\Z")

RUN_KEYS = (
    "schema",
    "claim",
    "participants",
    "actor_lifetimes",
    "maximum_concurrent_actors",
    "topic",
    "scope",
    "payload_len",
    "payload_sha256",
    "page_limit",
    "expected_pages",
)
PARTICIPANT_KEYS = (
    "participant",
    "carrier_id",
    "mission_id",
    "mission_authority",
    "expected_carrier_peer",
    "expected_mission_peer",
)
HANDLE_KEYS = (
    "phase",
    "participant",
    "blob_identity",
    "blob_authority",
)
PUBLICATION_KEYS = (
    "phase",
    "participant",
    "id",
    "publisher",
    "counter",
    "priority",
    "total_len",
    "media_type",
    "schema_id_sha256",
    "acceptance_marker",
    "inserted",
    "payload_sha256",
)
RETRY_KEYS = (
    "phase",
    "participant",
    "original_id",
    "retry_id",
    "publisher",
    "counter",
    "priority",
    "total_len",
    "media_type",
    "schema_id_sha256",
    "acceptance_marker",
    "inserted",
    "exact_match",
)
CONFLICT_KEYS = (
    "phase",
    "participant",
    "original_id",
    "original_payload_sha256",
    "changed_payload_sha256",
    "error_kind",
    "operation",
    "publication_preserved",
)
PAGE_KEYS = (
    "phase",
    "participant",
    "page_index",
    "id",
    "publisher",
    "counter",
    "priority",
    "total_len",
    "media_type",
    "schema_id_sha256",
    "acceptance_marker",
    "offset",
    "max_bytes",
    "page_len",
    "next_offset",
    "complete",
    "page_sha256",
)
READ_KEYS = (
    "phase",
    "participant",
    "id",
    "publisher",
    "counter",
    "priority",
    "total_len",
    "media_type",
    "schema_id_sha256",
    "acceptance_marker",
    "pages",
    "max_page_bytes",
    "payload_sha256",
)
SHUTDOWN_KEYS = (
    "phase",
    "participant",
    "contacts",
    "contact_errors",
    "direct_contacts",
    "relay_contacts",
    "unknown_path_contacts",
    "carrier_path_transitions",
    "carrier_path_transition_saturations",
    "items",
    "acceptance_markers",
    "events",
    "event_acceptance_markers",
    "route_cached_events",
    "controls",
    "applied_controls",
    "pending_controls",
    "control_highwater",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "blob_remaining",
    "blob_deferred",
    "blobs",
    "blob_acceptance_markers",
    "blob_last_acceptance_marker",
    "blob_sealed_bytes",
    "blob_operations",
    "blob_operation_bytes",
    "blob_variants",
    "blob_finalized_variants",
    "blob_committed_chunks",
    "blob_committed_file_bytes",
    "blob_reserved_file_bytes",
    "pending_blobs",
    "blob_carrier_prefixes",
    "blob_carrier_fetch_cursors",
    "blob_network_staging_bytes",
)
CLOSED_HANDLE_KEYS = ("phase", "participant", "error_kind", "operation")
SOURCE_REMOVED_KEYS = (
    "participant",
    "status",
    "bytes",
    "sha256",
)
BIND_KEYS = ("participant", "status")
RESULT_KEYS = (
    "status",
    "secret_values_emitted",
    "payload_representation",
    "records",
    "actor_lifetimes",
    "maximum_concurrent_actors",
    "graceful_shutdowns",
    "retained_handles",
    "closed_handles",
    "bind_reacquisitions",
    "source_removed",
)

READY_KEYS = (
    "selected",
    "pid",
    "carrier_id",
    "mission_id",
    "mission_authority",
    "sockets",
    "state",
    "peers",
    "application",
    "carrier_route",
    "controlled_relay_url",
    "controlled_relay_trust",
    "controlled_relay_readiness",
    "public_relay_fallback",
    "hosted_discovery",
    "nat_traversal",
    "path_observation",
    "mission_auth",
    "provisioning",
    "semantics",
    "reconciliation_classes",
    "controls",
    "commit_before_activate",
    "content_admission",
)
CONTACT_KEYS = (
    "direction",
    "carrier_peer",
    "mission_peer",
    "rounds",
    "control_offered",
    "control_fetched",
    "control_retained",
    "control_duplicates",
    "control_activated",
    "control_remaining",
    "offered",
    "fetched",
    "inserted",
    "duplicates",
    "remaining",
    "deferred_event_lanes",
    "mutable_remaining",
    "deferred_mutable_lanes",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "blob_remaining",
    "blob_deferred",
    "handshake_frames",
    "handshake_bytes",
    "protected_frames",
    "protected_bytes",
    "carrier_path",
    "carrier_path_transitions",
    "carrier_path_transitions_saturated",
    "path_observation",
    "mission_auth",
    "semantics",
    "reconciliation_classes",
    "controls",
    "content_admission",
    "status",
)
CONTACT_BLOB_FIELDS = (
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "blob_remaining",
    "blob_deferred",
)
CONTACT_EXCLUDED_ZERO_FIELDS = (
    "control_offered",
    "control_fetched",
    "control_retained",
    "control_duplicates",
    "control_activated",
    "control_remaining",
    "duplicates",
    "remaining",
    "deferred_event_lanes",
    "deferred_mutable_lanes",
)
STOP_KEYS = (
    "lifecycle",
    "sync_status",
    "carrier_id",
    "mission_id",
    "contacts",
    "contact_errors",
    "direct_contacts",
    "relay_contacts",
    "unknown_path_contacts",
    "carrier_path_transitions",
    "carrier_path_transition_saturations",
    "path_observation",
    "opaque_items",
    "opaque_acceptance_markers",
    "events",
    "event_acceptance_markers",
    "route_cached_events",
    "controls",
    "applied_controls",
    "pending_controls",
    "control_highwater",
    "blobs",
    "blob_acceptance_markers",
    "blob_last_acceptance_marker",
    "blob_sealed_bytes",
    "blob_operations",
    "blob_operation_bytes",
    "blob_variants",
    "blob_finalized_variants",
    "blob_committed_chunks",
    "blob_committed_file_bytes",
    "blob_reserved_file_bytes",
    "pending_blobs",
    "blob_carrier_prefixes",
    "blob_carrier_fetch_cursors",
    "blob_network_staging_bytes",
    "blob_ranges_fetched",
    "blob_bytes_fetched",
    "blob_remaining",
    "blob_deferred",
    "mission_auth",
    "provisioning",
    "semantics",
    "reconciliation_classes",
    "controls_semantics",
)
LOOPBACK_SOCKET = re.compile(r"127[.]0[.]0[.]1:([1-9][0-9]{0,4})\Z")

EXPECTED_SEQUENCE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("RUN", RUN_KEYS),
    ("PARTICIPANT", PARTICIPANT_KEYS),
    ("PARTICIPANT", PARTICIPANT_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("BLOB_PUBLICATION", PUBLICATION_KEYS),
    ("BLOB_RETRY", RETRY_KEYS),
    ("BLOB_CONFLICT", CONFLICT_KEYS),
    ("PAGE", PAGE_KEYS),
    ("PAGE", PAGE_KEYS),
    ("READ", READ_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("SOURCE_REMOVED", SOURCE_REMOVED_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("PAGE", PAGE_KEYS),
    ("PAGE", PAGE_KEYS),
    ("READ", READ_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("HANDLE", HANDLE_KEYS),
    ("PAGE", PAGE_KEYS),
    ("PAGE", PAGE_KEYS),
    ("READ", READ_KEYS),
    ("SHUTDOWN", SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", CLOSED_HANDLE_KEYS),
    ("BIND_REACQUIRED", BIND_KEYS),
    ("BIND_REACQUIRED", BIND_KEYS),
    ("RESULT", RESULT_KEYS),
)

PAYLOAD_LEN = 65_747
PAGE_LIMIT = 65_536
CHUNK_FILE_OVERHEAD = 169
COMMITTED_CIPHERTEXT_BYTES = PAYLOAD_LEN + 2 * CHUNK_FILE_OVERHEAD
PAYLOAD_SHA256 = "52d2759ceaccc2ac63ab528f40edbe80ddd3abda8f4b5d894fb034881fcda9cf"
CHANGED_PAYLOAD_SHA256 = "b3da9883cd3819a8e6fe834e65e0f65bcfc3903f2da14bd28eb2a42c2680619c"
SCHEMA_ID_SHA256 = "2a538df7b419268fda25ef2f0e358db63a764ee3b55db19e0a4ef00c8a942be2"
PAGE_FACTS = (
    (0, 0, 65_536, 65_536, "false", "1047ab624c89856e2a3c2dea5cea7a299c2d0ba0a9bcbf1cb951a6d54927239a"),
    (1, 65_536, 211, 65_747, "true", "2740c403e3254a595863ffffbb94bfb26d5cedaa94566c57c6683ba61bf672a7"),
)
MEDIA_TYPE = "application/x-aster-live-blob-acceptance"

# The participant authorities, redb stores, depot owner markers, and encrypted
# chunk files are deliberately metadata-only.  They must never be opened,
# read, or hashed by this projector.
LIMITATIONS = [
    "operator-attested-source-binary-execution-link-not-cryptographically-proven",
    "selected-admitted-source-list-is-not-a-complete-reproducible-build-closure",
    "one-host-loopback-same-implementation-observation",
    "participant-secret-and-ciphertext-artifacts-validated-by-metadata-only",
    "restart-is-graceful-same-process-actor-store-and-provider-reopen",
    "transcript-timing-and-source-removal-order-are-producer-attested",
]
NONCLAIMS = [
    "distinct-physical-hosts",
    "nat-or-internet-path",
    "controlled-or-public-relay",
    "btle-carrier",
    "independent-implementation-interoperability",
    "scale-beyond-two-participants",
    "resource-thresholds-or-long-duration-soak",
    "event-state-or-record-live-application-acceptance",
    "reproducible-build-or-cryptographic-source-to-execution-provenance",
    "process-crash-or-power-loss-recovery",
    "physical-source-media-sanitization-or-secure-erasure",
    "long-offline-recovery-or-partial-transfer-resume",
]



class ReceiptViolation(ValueError):
    """The retained run or supplied receipt failed the selected contract."""


def fail(message: str) -> None:
    raise ReceiptViolation(message)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def exact_string(
    value: Any,
    label: str,
    *,
    expected: str | None = None,
    pattern: re.Pattern[str] | None = None,
    maximum: int = 4096,
) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        fail(f"{label} is not one bounded string")
    if not value.isascii() or any(ord(character) < 0x20 for character in value):
        fail(f"{label} is not canonical printable ASCII")
    if expected is not None and value != expected:
        fail(f"{label} differs from its exact value")
    if pattern is not None and pattern.fullmatch(value) is None:
        fail(f"{label} has a noncanonical encoding")
    return value


def exact_uint(
    value: Any,
    label: str,
    *,
    expected: int | None = None,
    minimum: int = 0,
    maximum: int = (1 << 63) - 1,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        fail(f"{label} is not one bounded unsigned integer")
    if expected is not None and value != expected:
        fail(f"{label} differs from its exact value")
    return value


def exact_bool(value: Any, label: str, *, expected: bool | None = None) -> bool:
    if type(value) is not bool:
        fail(f"{label} is not one Boolean")
    if expected is not None and value is not expected:
        fail(f"{label} differs from its exact value")
    return value


def exact_object(value: Any, keys: Iterable[str], label: str) -> dict[str, Any]:
    expected = set(keys)
    if not isinstance(value, dict) or set(value) != expected:
        fail(f"{label} has missing, extra, or duplicate fields")
    return value


def exact_array(value: Any, label: str, *, length: int | None = None) -> list[Any]:
    if not isinstance(value, list) or (length is not None and len(value) != length):
        fail(f"{label} is not the exact bounded array")
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"
    ).encode("ascii")


def load_canonical_json(data: bytes, label: str, maximum: int) -> dict[str, Any]:
    if not data or len(data) > maximum or not data.endswith(b"\n"):
        fail(f"{label} is empty, truncated, or exceeds its byte cap")
    if b"\x00" in data or b"\r" in data:
        fail(f"{label} contains a forbidden control encoding")

    def pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{label} contains a duplicate JSON field")
            result[key] = value
        return result

    try:
        text = data.decode("ascii", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=pairs_hook,
            parse_constant=lambda _value: fail(f"{label} contains a non-finite number"),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not canonical JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} top level is not one object")
    if canonical_json_bytes(value) != data:
        fail(f"{label} is not compact canonical JSON")
    return value


DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
FILE_FLAGS = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _validate_directory(metadata: os.stat_result, label: str) -> None:
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail(f"{label} is not one plain directory")
    if metadata.st_uid != os.getuid():
        fail(f"{label} is not owned by the current validator user")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail(f"{label} does not have exact owner-only mode 0700")


def open_raw_root(root: Path) -> tuple[int, os.stat_result]:
    root_text = os.fspath(root)
    candidate = PurePosixPath(root_text)
    if not root_text.startswith("/") or str(candidate) != root_text:
        fail("raw root is not one canonical absolute path")
    try:
        descriptor = os.open("/", DIRECTORY_FLAGS)
    except OSError:
        fail("raw root filesystem anchor could not be opened")
    try:
        for index, part in enumerate(candidate.parts[1:]):
            label = "raw root" if index == len(candidate.parts[1:]) - 1 else "raw root parent"
            try:
                before = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                following = os.open(part, DIRECTORY_FLAGS, dir_fd=descriptor)
            except OSError:
                fail(f"{label} could not be opened without following links")
            opened = os.fstat(following)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                os.close(following)
                fail(f"{label} changed identity while opening")
            os.close(descriptor)
            descriptor = following
        metadata = os.fstat(descriptor)
        _validate_directory(metadata, "raw root")
        try:
            final = os.lstat(root)
        except OSError:
            fail("raw root path vanished while opening")
        if (final.st_dev, final.st_ino) != (metadata.st_dev, metadata.st_ino):
            fail("raw root path differs from its opened identity")
        return descriptor, metadata
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _open_directory_at(root_descriptor: int, relative: str, label: str) -> int:
    parts = PurePosixPath(relative).parts if relative else ()
    if any(part in {"", ".", ".."} for part in parts):
        fail(f"{label} has a noncanonical relative path")
    current = os.dup(root_descriptor)
    try:
        for part in parts:
            try:
                before = os.stat(part, dir_fd=current, follow_symlinks=False)
                following = os.open(part, DIRECTORY_FLAGS, dir_fd=current)
            except OSError:
                fail(f"{label} parent could not be opened without following links")
            opened = os.fstat(following)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                os.close(following)
                fail(f"{label} changed identity while opening")
            _validate_directory(opened, label)
            os.close(current)
            current = following
        return current
    except BaseException:
        try:
            os.close(current)
        except OSError:
            pass
        raise


def read_public_file(
    root_descriptor: int,
    relative: str,
    label: str,
    maximum: int,
) -> tuple[bytes, os.stat_result]:
    path = PurePosixPath(relative)
    parent = _open_directory_at(root_descriptor, str(path.parent) if str(path.parent) != "." else "", label)
    descriptor: int | None = None
    try:
        before = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            fail(f"{label} is not one plain regular file")
        if before.st_uid != os.getuid() or before.st_nlink != 1:
            fail(f"{label} has unsafe owner or link metadata")
        if before.st_size > maximum:
            fail(f"{label} exceeds its evidence byte cap")
        descriptor = os.open(path.name, FILE_FLAGS, dir_fd=parent)
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            fail(f"{label} changed identity while opening")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum or len(data) != opened.st_size:
            fail(f"{label} changed size or exceeds its evidence byte cap")
        final = os.fstat(descriptor)
        path_final = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (final.st_dev, final.st_ino, final.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) or (path_final.st_dev, path_final.st_ino, path_final.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            fail(f"{label} changed while being read")
        return data, opened
    except OSError:
        fail(f"{label} could not be read safely")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def stat_witness(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def validate_inventory(root_descriptor: int) -> dict[str, Any]:
    observed_directories: set[str] = set()
    directory_metadata: dict[str, os.stat_result] = {}
    observed_files: dict[str, os.stat_result] = {}
    identities: list[tuple[int, int]] = []
    variants: dict[str, str] = {}

    def admitted_directory(relative: str) -> bool:
        if relative in EXPECTED_BASE_DIRECTORIES:
            return True
        parent, separator, name = relative.rpartition("/")
        if (
            separator
            and parent
            in {
                "participants/publisher/state/blob-depot-v1",
                "participants/receiver/state/blob-depot-v1",
            }
            and VARIANT_DIRECTORY.fullmatch(name) is not None
        ):
            participant = parent.split("/")[1]
            if participant in variants:
                fail(f"{participant} depot contains more than one variant directory")
            variants[participant] = name
            return True
        return False

    def expected_file_mode(relative: str) -> int | None:
        fixed = EXPECTED_BASE_FILES.get(relative)
        if fixed is not None:
            return fixed
        path = PurePosixPath(relative)
        if (
            len(path.parts) == 6
            and path.parts[0] == "participants"
            and path.parts[1] in {"publisher", "receiver"}
            and path.parts[2:4] == ("state", "blob-depot-v1")
            and VARIANT_DIRECTORY.fullmatch(path.parts[4]) is not None
            and CHUNK_FILE.fullmatch(path.parts[5]) is not None
        ):
            return 0o600
        return None

    def walk(descriptor: int, relative: str) -> None:
        metadata = os.fstat(descriptor)
        _validate_directory(metadata, f"raw directory {relative or '.'}")
        observed_directories.add(relative)
        directory_metadata[relative] = metadata
        identities.append((metadata.st_dev, metadata.st_ino))
        try:
            names = sorted(os.listdir(descriptor))
        except OSError:
            fail(f"raw directory {relative or '.'} could not be enumerated")
        if len(names) > 64:
            fail(f"raw directory {relative or '.'} exceeds its inventory bound")
        for name in names:
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                fail("raw inventory contains a noncanonical name")
            child_relative = f"{relative}/{name}" if relative else name
            try:
                before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError:
                fail(f"raw inventory entry {child_relative} could not be inspected")
            if stat.S_ISDIR(before.st_mode):
                if not admitted_directory(child_relative):
                    fail(f"raw inventory contains unexpected directory {child_relative}")
                try:
                    child = os.open(name, DIRECTORY_FLAGS, dir_fd=descriptor)
                except OSError:
                    fail(f"raw directory {child_relative} could not be opened safely")
                try:
                    opened = os.fstat(child)
                    if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
                        fail(f"raw directory {child_relative} changed while opening")
                    walk(child, child_relative)
                finally:
                    os.close(child)
            elif stat.S_ISREG(before.st_mode) and not stat.S_ISLNK(before.st_mode):
                expected_mode = expected_file_mode(child_relative)
                if expected_mode is None:
                    fail(f"raw inventory contains unexpected file {child_relative}")
                if before.st_uid != os.getuid():
                    fail(f"raw file {child_relative} is not owned by the current user")
                if stat.S_IMODE(before.st_mode) != expected_mode:
                    fail(f"raw file {child_relative} has an unexpected mode")
                if before.st_nlink != 1:
                    fail(f"raw file {child_relative} has an unsafe hard-link count")
                observed_files[child_relative] = before
                identities.append((before.st_dev, before.st_ino))
            else:
                fail(f"raw inventory entry {child_relative} has an unsafe type")

    walk(root_descriptor, "")
    if set(variants) != {"publisher", "receiver"} or len(set(variants.values())) != 1:
        fail("participant depots do not contain one matching canonical variant directory each")
    expected_directories = EXPECTED_BASE_DIRECTORIES | {
        f"participants/{participant}/state/blob-depot-v1/{variants[participant]}"
        for participant in ("publisher", "receiver")
    }
    expected_files = set(EXPECTED_BASE_FILES)
    for participant in ("publisher", "receiver"):
        expected_files.update(
            f"participants/{participant}/state/blob-depot-v1/{variants[participant]}/{index:020}.chunk"
            for index in range(2)
        )
    if observed_directories != expected_directories:
        fail("raw inventory has missing or extra directories")
    if set(observed_files) != expected_files:
        fail("raw inventory has missing or extra files")
    if len(set(identities)) != len(identities):
        fail("raw inventory contains aliased directory or file identities")

    chunk_totals: dict[str, int] = {}
    for participant in ("publisher", "receiver"):
        mission = observed_files[f"participants/{participant}/mission.bundle"]
        identity = observed_files[f"participants/{participant}/state/identity.key"]
        store = observed_files[f"participants/{participant}/state/mesh.redb"]
        marker = observed_files[
            f"participants/{participant}/state/blob-depot-v1/.aster-store-owner-v1"
        ]
        if not 0 < mission.st_size <= MISSION_MAX_BYTES:
            fail(f"{participant} mission artifact violates its metadata-only size bound")
        if not 0 < identity.st_size <= STORE_MAX_BYTES:
            fail(f"{participant} identity key violates its metadata-only size bound")
        if not 0 < store.st_size <= STORE_MAX_BYTES:
            fail(f"{participant} mesh database violates its metadata-only size bound")
        if marker.st_size != OWNER_MARKER_BYTES:
            fail(f"{participant} depot owner marker has the wrong metadata-only byte count")
        chunks = [
            observed_files[
                f"participants/{participant}/state/blob-depot-v1/"
                f"{variants[participant]}/{index:020}.chunk"
            ]
            for index in range(2)
        ]
        for index, (chunk, page) in enumerate(zip(chunks, PAGE_FACTS, strict=True)):
            expected_size = page[2] + CHUNK_FILE_OVERHEAD
            if chunk.st_size != expected_size:
                fail(
                    f"{participant} ciphertext chunk {index} has the wrong "
                    "metadata-only byte count"
                )
        chunk_totals[participant] = sum(chunk.st_size for chunk in chunks)
    return {
        "directories": directory_metadata,
        "files": observed_files,
        "variants": variants,
        "chunk_totals": chunk_totals,
    }
def require_same_inventory(
    initial: dict[str, dict[str, os.stat_result]],
    final: dict[str, dict[str, os.stat_result]],
) -> None:
    for kind in ("directories", "files"):
        if set(initial[kind]) != set(final[kind]):
            fail(f"raw {kind} inventory changed during validation")
        for relative in initial[kind]:
            if stat_witness(initial[kind][relative]) != stat_witness(final[kind][relative]):
                fail(f"raw inventory metadata changed during validation: {relative or '.'}")


def parse_uint(value: str, label: str, *, positive: bool = False) -> int:
    if not value or not value.isdigit() or (len(value) > 1 and value.startswith("0")):
        fail(f"{label} is not one canonical unsigned decimal integer")
    parsed = int(value)
    if parsed > (1 << 63) - 1 or (positive and parsed == 0):
        fail(f"{label} is outside its evidence bound")
    return parsed


def parse_record(
    line: str,
    expected_type: str,
    expected_keys: tuple[str, ...],
    index: int,
) -> dict[str, str]:
    parts = line.split("\t")
    label = f"transcript record {index + 1}"
    if len(parts) != len(expected_keys) + 2 or parts[:2] != ["LIVE_BLOB", expected_type]:
        fail(f"{label} has an unexpected type, delimiter, or field count")
    record: dict[str, str] = {}
    ordered: list[str] = []
    for token in parts[2:]:
        key, separator, value = token.partition("=")
        if separator != "=" or FIELD_NAME.fullmatch(key) is None or not value:
            fail(f"{label} contains a malformed field")
        if key in record:
            fail(f"{label} contains a duplicate field")
        if not value.isascii() or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
            fail(f"{label} contains a noncanonical field value")
        ordered.append(key)
        record[key] = value
    if tuple(ordered) != expected_keys:
        fail(f"{label} has missing, extra, or reordered fields")
    return record


def parse_terminal_record(
    line: str,
    expected_prefix: str,
    expected_keys: tuple[str, ...],
    label: str,
) -> dict[str, str]:
    parts = line.split(" ")
    if len(parts) != len(expected_keys) + 1 or parts[0] != expected_prefix or any(not part for part in parts):
        fail(f"{label} has an unexpected prefix, delimiter, or field count")
    record: dict[str, str] = {}
    ordered: list[str] = []
    for token in parts[1:]:
        key, separator, value = token.partition("=")
        if separator != "=" or FIELD_NAME.fullmatch(key) is None or not value:
            fail(f"{label} contains a malformed field")
        if key in record:
            fail(f"{label} contains a duplicate field")
        if not value.isascii() or any(ord(character) < 0x21 or ord(character) > 0x7E for character in value):
            fail(f"{label} contains a noncanonical field value")
        ordered.append(key)
        record[key] = value
    if tuple(ordered) != expected_keys:
        fail(f"{label} has missing, extra, or reordered fields")
    return record


def encoded_path(value: Path) -> str:
    output: list[str] = []
    for byte in os.fsencode(value):
        character = chr(byte)
        if character.isascii() and (character.isalnum() or character in "-_./:"):
            output.append(character)
        else:
            output.append(f"%{byte:02X}")
    return "".join(output)


def require_id(value: str, label: str) -> str:
    if HEX_32.fullmatch(value) is None:
        fail(f"{label} is not one canonical 32-byte identifier")
    return value


def require_fixed(record: dict[str, str], expected: dict[str, str], label: str) -> None:
    for key, value in expected.items():
        if record[key] != value:
            fail(f"{label}.{key} differs from its exact value")


def sorted_pair(first: str, second: str) -> str:
    return ",".join(sorted((first, second)))


def validate_item(
    record: dict[str, str],
    prefix: str,
    expected: dict[str, str],
    label: str,
) -> None:
    require_id(record[f"{prefix}_id"], f"{label}.{prefix}_id")
    require_id(record[f"{prefix}_publisher"], f"{label}.{prefix}_publisher")
    parse_uint(record[f"{prefix}_counter"], f"{label}.{prefix}_counter", positive=True)
    require_id(record[f"{prefix}_payload_sha256"], f"{label}.{prefix}_payload_sha256")
    for suffix in ("id", "publisher", "counter", "payload_sha256"):
        if record[f"{prefix}_{suffix}"] != expected[suffix]:
            fail(f"{label} has inconsistent {prefix}_{suffix}")


def validate_transcript(data: bytes) -> dict[str, Any]:
    if not data or len(data) > TRANSCRIPT_MAX_BYTES or not data.endswith(b"\n"):
        fail("transcript is empty, truncated, or exceeds its byte cap")
    if b"\x00" in data or b"\r" in data:
        fail("transcript contains a forbidden control encoding")
    try:
        text = data.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        fail("transcript is not canonical ASCII")
    lines = text.splitlines()
    if len(lines) != TRANSCRIPT_RECORDS:
        fail("transcript does not contain exactly 31 records")
    if any(not line or len(line.encode("ascii")) > 16 * 1024 for line in lines):
        fail("transcript contains an empty or overlong record")
    records = [
        parse_record(lines[index], expected_type, keys, index)
        for index, (expected_type, keys) in enumerate(EXPECTED_SEQUENCE)
    ]

    require_fixed(
        records[0],
        {
            "schema": TRANSCRIPT_SCHEMA,
            "claim": CLAIM,
            "participants": "2",
            "actor_lifetimes": "4",
            "maximum_concurrent_actors": "2",
            "topic": "opaque",
            "scope": "test/runtime-contact",
            "payload_len": str(PAYLOAD_LEN),
            "payload_sha256": PAYLOAD_SHA256,
            "page_limit": str(PAGE_LIMIT),
            "expected_pages": "2",
        },
        "RUN",
    )

    participants: dict[str, dict[str, str]] = {}
    for index, expected_name in zip((1, 2), ("publisher", "receiver"), strict=True):
        record = records[index]
        require_fixed(record, {"participant": expected_name}, f"PARTICIPANT {expected_name}")
        for field in (
            "carrier_id",
            "mission_id",
            "mission_authority",
            "expected_carrier_peer",
            "expected_mission_peer",
        ):
            require_id(record[field], f"PARTICIPANT {expected_name}.{field}")
        participants[expected_name] = record
    publisher = participants["publisher"]
    receiver = participants["receiver"]
    identity_domain = {
        publisher["carrier_id"],
        receiver["carrier_id"],
        publisher["mission_id"],
        receiver["mission_id"],
    }
    if len(identity_domain) != 4:
        fail("participant carrier and mission identity domains overlap")
    if publisher["mission_authority"] != receiver["mission_authority"]:
        fail("participants do not share exactly one mission authority")
    if publisher["mission_authority"] in identity_domain:
        fail("mission authority overlaps a carrier or participant identity")
    if (
        publisher["expected_carrier_peer"] != receiver["carrier_id"]
        or receiver["expected_carrier_peer"] != publisher["carrier_id"]
        or publisher["expected_mission_peer"] != receiver["mission_id"]
        or receiver["expected_mission_peer"] != publisher["mission_id"]
    ):
        fail("participant expected carrier or mission peer binding is not reciprocal")

    handle_expectations = (
        (3, "peerless_source", "publisher"),
        (13, "connected_transfer", "publisher"),
        (14, "connected_transfer", "receiver"),
        (22, "restart_receiver", "receiver"),
    )
    for index, phase, participant in handle_expectations:
        expected = participants[participant]
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": participant,
                "blob_identity": expected["mission_id"],
                "blob_authority": expected["mission_authority"],
            },
            f"HANDLE {phase} {participant}",
        )

    publication = records[4]
    require_fixed(
        publication,
        {
            "phase": "peerless_source",
            "participant": "publisher",
            "publisher": publisher["mission_id"],
            "counter": "1",
            "priority": "priority",
            "total_len": str(PAYLOAD_LEN),
            "media_type": MEDIA_TYPE,
            "schema_id_sha256": SCHEMA_ID_SHA256,
            "acceptance_marker": "1",
            "inserted": "true",
            "payload_sha256": PAYLOAD_SHA256,
        },
        "BLOB_PUBLICATION",
    )
    blob_id = require_id(publication["id"], "BLOB_PUBLICATION.id")
    retry = records[5]
    require_fixed(
        retry,
        {
            "phase": "peerless_source",
            "participant": "publisher",
            "original_id": blob_id,
            "retry_id": blob_id,
            "publisher": publication["publisher"],
            "counter": publication["counter"],
            "priority": publication["priority"],
            "total_len": publication["total_len"],
            "media_type": publication["media_type"],
            "schema_id_sha256": publication["schema_id_sha256"],
            "acceptance_marker": publication["acceptance_marker"],
            "inserted": "false",
            "exact_match": "true",
        },
        "BLOB_RETRY",
    )
    require_fixed(
        records[6],
        {
            "phase": "peerless_source",
            "participant": "publisher",
            "original_id": blob_id,
            "original_payload_sha256": PAYLOAD_SHA256,
            "changed_payload_sha256": CHANGED_PAYLOAD_SHA256,
            "error_kind": "conflict",
            "operation": "blob_publish",
            "publication_preserved": "true",
        },
        "BLOB_CONFLICT",
    )

    selected_metadata = {
        "id": blob_id,
        "publisher": publication["publisher"],
        "counter": publication["counter"],
        "priority": publication["priority"],
        "total_len": publication["total_len"],
        "media_type": publication["media_type"],
        "schema_id_sha256": publication["schema_id_sha256"],
        "acceptance_marker": publication["acceptance_marker"],
    }

    def validate_pages(first_index: int, phase: str, participant: str) -> None:
        for offset_index, expected_page in enumerate(PAGE_FACTS):
            page = records[first_index + offset_index]
            page_index, offset, page_len, next_offset, complete, page_hash = expected_page
            require_fixed(
                page,
                {
                    "phase": phase,
                    "participant": participant,
                    "page_index": str(page_index),
                    **selected_metadata,
                    "offset": str(offset),
                    "max_bytes": str(PAGE_LIMIT),
                    "page_len": str(page_len),
                    "next_offset": str(next_offset),
                    "complete": complete,
                    "page_sha256": page_hash,
                },
                f"PAGE {phase} {participant} {page_index}",
            )

    def validate_read(index: int, phase: str, participant: str) -> None:
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": participant,
                **selected_metadata,
                "pages": "2",
                "max_page_bytes": str(PAGE_LIMIT),
                "payload_sha256": PAYLOAD_SHA256,
            },
            f"READ {phase} {participant}",
        )

    validate_pages(7, "peerless_source", "publisher")
    validate_read(9, "peerless_source", "publisher")
    validate_pages(15, "connected_receiver", "receiver")
    validate_read(17, "connected_receiver", "receiver")
    validate_pages(23, "restart_receiver", "receiver")
    validate_read(25, "restart_receiver", "receiver")

    shutdown_records: dict[str, dict[str, str]] = {}
    shutdown_expectations = (
        (10, "peerless_source", "publisher"),
        (18, "connected_transfer", "publisher"),
        (19, "connected_transfer", "receiver"),
        (26, "restart_receiver", "receiver"),
    )
    non_blob_zero = (
        "items",
        "acceptance_markers",
        "events",
        "event_acceptance_markers",
        "route_cached_events",
        "controls",
        "applied_controls",
        "pending_controls",
        "control_highwater",
    )
    for index, phase, participant in shutdown_expectations:
        record = records[index]
        require_fixed(record, {"phase": phase, "participant": participant}, f"SHUTDOWN {phase} {participant}")
        numeric = {
            field: parse_uint(record[field], f"SHUTDOWN {phase} {participant}.{field}")
            for field in SHUTDOWN_KEYS[2:]
        }
        if any(numeric[field] != 0 for field in non_blob_zero):
            fail(f"SHUTDOWN {phase} {participant} contains excluded durable item, Event, or control state")
        if any(
            numeric[field] != 0
            for field in (
                "contact_errors",
                "relay_contacts",
                "unknown_path_contacts",
                "carrier_path_transitions",
                "carrier_path_transition_saturations",
                "pending_blobs",
                "blob_carrier_prefixes",
                "blob_network_staging_bytes",
            )
        ):
            fail(f"SHUTDOWN {phase} {participant} contains an error, non-direct path, transition, or pending Blob state")
        require_fixed(
            record,
            {
                "blobs": "1",
                "blob_acceptance_markers": "1",
                "blob_last_acceptance_marker": "1",
                "blob_variants": "1",
                "blob_finalized_variants": "1",
                "blob_committed_chunks": "2",
            },
            f"SHUTDOWN {phase} {participant}",
        )
        if numeric["blob_sealed_bytes"] <= 0:
            fail(f"SHUTDOWN {phase} {participant} has no sealed Blob bytes")
        if (
            numeric["blob_committed_file_bytes"] != COMMITTED_CIPHERTEXT_BYTES
            or numeric["blob_reserved_file_bytes"] != COMMITTED_CIPHERTEXT_BYTES
        ):
            fail(f"SHUTDOWN {phase} {participant} has inconsistent committed and reserved ciphertext bytes")
        if phase in {"peerless_source", "restart_receiver"}:
            for field in (
                "contacts",
                "direct_contacts",
                "blob_ranges_fetched",
                "blob_bytes_fetched",
                "blob_remaining",
                "blob_deferred",
            ):
                if numeric[field] != 0:
                    fail(f"SHUTDOWN {phase} {participant}.{field} is not an exact peerless zero")
        else:
            if numeric["contacts"] <= 0 or numeric["direct_contacts"] != numeric["contacts"]:
                fail(f"SHUTDOWN {phase} {participant} is not positive direct-only contact evidence")
            if numeric["blob_deferred"] != 0:
                fail(f"SHUTDOWN {phase} {participant} retains deferred Blob work")
        if participant == "publisher":
            if numeric["blob_operations"] != 1 or numeric["blob_operation_bytes"] <= 0:
                fail(f"SHUTDOWN {phase} publisher does not retain exactly one positive source operation")
            if numeric["blob_ranges_fetched"] != 0 or numeric["blob_bytes_fetched"] != 0:
                fail(f"SHUTDOWN {phase} publisher reports receiving Blob content")
        else:
            if numeric["blob_operations"] != 0 or numeric["blob_operation_bytes"] != 0:
                fail(f"SHUTDOWN {phase} receiver reports a local source operation")
            if phase == "connected_transfer" and (
                numeric["blob_ranges_fetched"] <= 0 or numeric["blob_bytes_fetched"] <= 0
            ):
                fail("connected receiver has no positive Blob range and byte transfer")
        expected_cursor = (
            {0, 1}
            if phase == "connected_transfer"
            else {0}
        )
        if numeric["blob_carrier_fetch_cursors"] not in expected_cursor:
            fail(f"SHUTDOWN {phase} {participant} has an inadmissible Blob fetch cursor count")
        shutdown_records[f"{phase}:{participant}"] = record

    peerless = shutdown_records["peerless_source:publisher"]
    connected_publisher = shutdown_records["connected_transfer:publisher"]
    connected_receiver = shutdown_records["connected_transfer:receiver"]
    restart_receiver = shutdown_records["restart_receiver:receiver"]
    durable_fields = (
        "blobs",
        "blob_acceptance_markers",
        "blob_last_acceptance_marker",
        "blob_sealed_bytes",
        "blob_variants",
        "blob_finalized_variants",
        "blob_committed_chunks",
        "blob_committed_file_bytes",
        "blob_reserved_file_bytes",
    )
    for field in durable_fields:
        if connected_publisher[field] != peerless[field]:
            fail(f"connected publisher durable Blob field {field} changed from peerless shutdown")
        if connected_receiver[field] != connected_publisher[field]:
            fail(f"connected receiver durable Blob field {field} differs from publisher")
        if restart_receiver[field] != connected_receiver[field]:
            fail(f"restart receiver durable Blob field {field} changed after reopen")
    if connected_publisher["contacts"] != connected_receiver["contacts"]:
        fail("connected participant contact counts are not paired exactly")

    closed_expectations = (
        (11, "peerless_source", "publisher"),
        (20, "connected_transfer", "publisher"),
        (21, "connected_transfer", "receiver"),
        (27, "restart_receiver", "receiver"),
    )
    for index, phase, participant in closed_expectations:
        require_fixed(
            records[index],
            {
                "phase": phase,
                "participant": participant,
                "error_kind": "state_unavailable",
                "operation": "blob_read_page",
            },
            f"CLOSED_HANDLE {phase} {participant}",
        )
    require_fixed(
        records[12],
        {
            "participant": "publisher",
            "status": "removed-and-parent-synced",
            "bytes": str(PAYLOAD_LEN),
            "sha256": PAYLOAD_SHA256,
        },
        "SOURCE_REMOVED",
    )
    for index, participant in zip((28, 29), ("publisher", "receiver"), strict=True):
        require_fixed(
            records[index],
            {"participant": participant, "status": "reacquired"},
            f"BIND_REACQUIRED {participant}",
        )
    require_fixed(
        records[30],
        {
            "status": "pass",
            "secret_values_emitted": "false",
            "payload_representation": "sha256_only",
            "records": "31",
            "actor_lifetimes": "4",
            "maximum_concurrent_actors": "2",
            "graceful_shutdowns": "4",
            "retained_handles": "4",
            "closed_handles": "4",
            "bind_reacquisitions": "2",
            "source_removed": "true",
        },
        "RESULT",
    )

    connected_contacts = parse_uint(
        connected_publisher["contacts"], "connected publisher contacts", positive=True
    )
    return {
        "records": TRANSCRIPT_RECORDS,
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "participants": 2,
        "actor_lifetimes": 4,
        "maximum_concurrent_actors": 2,
        "connected_contacts": connected_contacts * 2,
        "blob_publications": 1,
        "publication_retries": 1,
        "publication_conflicts": 1,
        "page_reads": 6,
        "whole_reads": 3,
        "shutdowns": 4,
        "closed_handles": 4,
        "bind_reacquisitions": 2,
        "source_removed": True,
        "_participants": participants,
        "_shutdowns": shutdown_records,
        "_application_ids": [blob_id],
    }
def validate_terminal_stdout(
    stdout: bytes,
    transcript: bytes,
    root: Path,
    transcript_facts: dict[str, Any],
) -> dict[str, Any]:
    if not stdout or len(stdout) > STDOUT_MAX_BYTES or not stdout.endswith(b"\n"):
        fail("captured stdout is empty, truncated, or exceeds its byte cap")
    if b"\x00" in stdout or b"\r" in stdout:
        fail("captured stdout contains a forbidden control encoding")
    try:
        text = stdout.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        fail("captured stdout is not canonical ASCII")
    lines = text.splitlines()
    if not lines or len(lines) > 8192:
        fail("captured stdout has an invalid line count")
    if any(not line or len(line.encode("ascii")) > 32 * 1024 for line in lines):
        fail("captured stdout contains an empty or overlong line")
    extracted = b"".join(
        (line + "\n").encode("ascii")
        for line in lines
        if line.startswith("LIVE_BLOB\t")
    )
    if extracted != transcript:
        fail("transcript is not the exact ordered LIVE_BLOB extraction from stdout")

    participants: dict[str, dict[str, str]] = transcript_facts["_participants"]
    by_carrier = {record["carrier_id"]: name for name, record in participants.items()}
    by_mission = {record["mission_id"]: name for name, record in participants.items()}
    phase_order = {
        "publisher": ("peerless_source", "connected_transfer"),
        "receiver": ("connected_transfer", "restart_receiver"),
    }
    ready_count = {participant: 0 for participant in participants}
    stop_count = {participant: 0 for participant in participants}
    active: dict[str, str] = {}
    contact_count = {participant: 0 for participant in participants}
    blob_contact_totals = {
        participant: {field: 0 for field in CONTACT_BLOB_FIELDS}
        for participant in participants
    }
    connected_blob_totals: dict[str, dict[str, int]] = {}
    connected_sockets: set[str] = set()
    pids: set[int] = set()
    sockets: set[str] = set()
    ports: set[int] = set()
    ready_records = 0
    contact_records = 0
    stop_records = 0

    contact_numeric_fields = (
        "rounds",
        "control_offered",
        "control_fetched",
        "control_retained",
        "control_duplicates",
        "control_activated",
        "control_remaining",
        "offered",
        "fetched",
        "inserted",
        "duplicates",
        "remaining",
        "deferred_event_lanes",
        "mutable_remaining",
        "deferred_mutable_lanes",
        "blob_ranges_fetched",
        "blob_bytes_fetched",
        "blob_remaining",
        "blob_deferred",
        "handshake_frames",
        "handshake_bytes",
        "protected_frames",
        "protected_bytes",
        "carrier_path_transitions",
    )

    for line_number, line in enumerate(lines, start=1):
        label = f"captured stdout line {line_number}"
        if line.startswith("LIVE_BLOB\t"):
            continue
        if line.startswith("READY "):
            record = parse_terminal_record(line, "READY", READY_KEYS, label)
            carrier_participant = by_carrier.get(record["carrier_id"])
            mission_participant = by_mission.get(record["mission_id"])
            if carrier_participant is None or carrier_participant != mission_participant:
                fail(f"{label} does not bind one transcript participant")
            participant = carrier_participant
            if participant in active or ready_count[participant] >= len(phase_order[participant]):
                fail(f"{label} starts an overlapping or extra participant lifetime")
            phase = phase_order[participant][ready_count[participant]]
            if phase == "connected_transfer" and stop_count["publisher"] != 1:
                fail(f"{label} starts connected transfer before the peerless publisher stopped")
            if phase == "restart_receiver" and (
                active
                or stop_count["publisher"] != 2
                or stop_count["receiver"] != 1
            ):
                fail(f"{label} starts restart before both connected actors stopped")
            expected = participants[participant]
            require_fixed(
                record,
                {
                    "selected": "true",
                    "carrier_id": expected["carrier_id"],
                    "mission_id": expected["mission_id"],
                    "mission_authority": expected["mission_authority"],
                    "state": encoded_path(root / "participants" / participant / "state"),
                    "peers": "1" if phase == "connected_transfer" else "0",
                    "application": "relay",
                    "carrier_route": "direct",
                    "controlled_relay_url": "none",
                    "controlled_relay_trust": "none",
                    "controlled_relay_readiness": "not-applicable",
                    "public_relay_fallback": "false",
                    "hosted_discovery": "false",
                    "nat_traversal": "not-claimed",
                    "path_observation": "not-authorization",
                    "mission_auth": "hybrid-pq",
                    "provisioning": "unprotected-reference",
                    "semantics": "source-authenticated-event",
                    "reconciliation_classes": "event,state,record,blob-v5-opt-in",
                    "controls": "source-authenticated-flash",
                    "commit_before_activate": "true",
                    "content_admission": "capability-gated",
                },
                label,
            )
            pid = parse_uint(record["pid"], f"{label}.pid", positive=True)
            pids.add(pid)
            socket_match = LOOPBACK_SOCKET.fullmatch(record["sockets"])
            if socket_match is None or int(socket_match.group(1)) > 65535:
                fail(f"{label}.sockets is not one bounded loopback socket")
            sockets.add(record["sockets"])
            ports.add(int(socket_match.group(1)))
            if phase == "connected_transfer":
                if record["sockets"] in connected_sockets:
                    fail(f"{label}.sockets aliases another concurrent actor bind")
                connected_sockets.add(record["sockets"])
            active[participant] = phase
            ready_count[participant] += 1
            ready_records += 1
            continue
        if line.startswith("CONTACT "):
            record = parse_terminal_record(line, "CONTACT", CONTACT_KEYS, label)
            remote_by_carrier = by_carrier.get(record["carrier_peer"])
            remote_by_mission = by_mission.get(record["mission_peer"])
            if remote_by_carrier is None or remote_by_carrier != remote_by_mission:
                fail(f"{label} does not bind one reciprocal expected peer")
            remote = remote_by_carrier
            local = "receiver" if remote == "publisher" else "publisher"
            if (
                active.get(local) != "connected_transfer"
                or active.get(remote) != "connected_transfer"
            ):
                fail(f"{label} occurs outside both active connected lifetimes")
            require_fixed(
                record,
                {
                    "carrier_peer": participants[remote]["carrier_id"],
                    "mission_peer": participants[remote]["mission_id"],
                    "carrier_path": "direct",
                    "carrier_path_transitions": "0",
                    "carrier_path_transitions_saturated": "false",
                    "path_observation": "not-authorization",
                    "mission_auth": "hybrid-pq",
                    "semantics": "source-authenticated-event",
                    "reconciliation_classes": "event,state,record,blob",
                    "controls": "source-authenticated-flash",
                    "content_admission": "capability-gated",
                },
                label,
            )
            if record["direction"] not in {"in", "out"}:
                fail(f"{label}.direction is not an admitted contact direction")
            expected_direction = (
                "out"
                if participants[local]["carrier_id"] < participants[remote]["carrier_id"]
                else "in"
            )
            if record["direction"] != expected_direction:
                fail(f"{label}.direction contradicts deterministic carrier initiation")
            numeric = {
                field: parse_uint(
                    record[field], f"{label}.{field}", positive=field == "rounds"
                )
                for field in contact_numeric_fields
            }
            for field in CONTACT_EXCLUDED_ZERO_FIELDS:
                if numeric[field] != 0:
                    fail(f"{label}.{field} is a nonzero excluded Event, State/Record, or control counter")
            first_contact = contact_count[local] == 0
            if local == "publisher":
                if (
                    numeric["offered"] != (2 if first_contact else 1)
                    or numeric["fetched"] != 0
                    or numeric["inserted"] != 0
                    or numeric["mutable_remaining"] != 0
                ):
                    fail(f"{label} does not match publisher Blob reconciliation accounting")
            elif (
                numeric["offered"] != 0
                or numeric["fetched"] != (1 if first_contact else 0)
                or numeric["inserted"] != (1 if first_contact else 0)
                or numeric["mutable_remaining"] not in {0, 1}
                or bool(numeric["mutable_remaining"])
                != bool(numeric["blob_remaining"])
            ):
                fail(f"{label} does not match receiver Blob reconciliation accounting")
            expected_status = (
                "partial"
                if numeric["mutable_remaining"] or numeric["blob_remaining"]
                else "pass"
            )
            if record["status"] != expected_status:
                fail(f"{label}.status differs from the exact remaining-work state")
            for field in (
                "handshake_frames",
                "handshake_bytes",
                "protected_frames",
                "protected_bytes",
            ):
                if numeric[field] == 0:
                    fail(f"{label} has no authenticated or protected protocol traffic")
            for field in CONTACT_BLOB_FIELDS:
                blob_contact_totals[local][field] += numeric[field]
            contact_count[local] += 1
            contact_records += 1
            continue
        if line.startswith("STOP "):
            record = parse_terminal_record(line, "STOP", STOP_KEYS, label)
            carrier_participant = by_carrier.get(record["carrier_id"])
            mission_participant = by_mission.get(record["mission_id"])
            if carrier_participant is None or carrier_participant != mission_participant:
                fail(f"{label} does not bind one transcript participant")
            participant = carrier_participant
            phase = active.get(participant)
            if phase is None or phase != phase_order[participant][stop_count[participant]]:
                fail(f"{label} closes an absent or misordered participant lifetime")
            transcript_shutdown = transcript_facts["_shutdowns"][f"{phase}:{participant}"]
            require_fixed(
                record,
                {
                    "lifecycle": "complete",
                    "sync_status": (
                        "contacts_observed"
                        if phase == "connected_transfer"
                        else "no_successful_contact"
                    ),
                    "carrier_id": participants[participant]["carrier_id"],
                    "mission_id": participants[participant]["mission_id"],
                    "path_observation": "not-authorization",
                    "mission_auth": "hybrid-pq",
                    "provisioning": "unprotected-reference",
                    "semantics": "source-authenticated-event",
                    "reconciliation_classes": "event,state,record,blob-v5",
                    "controls_semantics": "source-authenticated-flash",
                },
                label,
            )
            transcript_to_stop = {
                "contacts": "contacts",
                "contact_errors": "contact_errors",
                "direct_contacts": "direct_contacts",
                "relay_contacts": "relay_contacts",
                "unknown_path_contacts": "unknown_path_contacts",
                "carrier_path_transitions": "carrier_path_transitions",
                "carrier_path_transition_saturations": "carrier_path_transition_saturations",
                "items": "opaque_items",
                "acceptance_markers": "opaque_acceptance_markers",
                "events": "events",
                "event_acceptance_markers": "event_acceptance_markers",
                "route_cached_events": "route_cached_events",
                "controls": "controls",
                "applied_controls": "applied_controls",
                "pending_controls": "pending_controls",
                "control_highwater": "control_highwater",
                "blob_ranges_fetched": "blob_ranges_fetched",
                "blob_bytes_fetched": "blob_bytes_fetched",
                "blob_remaining": "blob_remaining",
                "blob_deferred": "blob_deferred",
                "blobs": "blobs",
                "blob_acceptance_markers": "blob_acceptance_markers",
                "blob_last_acceptance_marker": "blob_last_acceptance_marker",
                "blob_sealed_bytes": "blob_sealed_bytes",
                "blob_operations": "blob_operations",
                "blob_operation_bytes": "blob_operation_bytes",
                "blob_variants": "blob_variants",
                "blob_finalized_variants": "blob_finalized_variants",
                "blob_committed_chunks": "blob_committed_chunks",
                "blob_committed_file_bytes": "blob_committed_file_bytes",
                "blob_reserved_file_bytes": "blob_reserved_file_bytes",
                "pending_blobs": "pending_blobs",
                "blob_carrier_prefixes": "blob_carrier_prefixes",
                "blob_carrier_fetch_cursors": "blob_carrier_fetch_cursors",
                "blob_network_staging_bytes": "blob_network_staging_bytes",
            }
            for transcript_field, stop_field in transcript_to_stop.items():
                parse_uint(record[stop_field], f"{label}.{stop_field}")
                if record[stop_field] != transcript_shutdown[transcript_field]:
                    fail(f"{label}.{stop_field} differs from the exact SHUTDOWN cross-link")
            expected_contacts = parse_uint(
                transcript_shutdown["contacts"], f"{label}.contacts"
            )
            if contact_count[participant] != expected_contacts:
                fail(f"{label} contact count differs from parsed CONTACT records")
            if phase == "connected_transfer":
                for field in CONTACT_BLOB_FIELDS:
                    if (
                        blob_contact_totals[participant][field]
                        != parse_uint(transcript_shutdown[field], f"{label}.{field}")
                    ):
                        fail(f"{label}.{field} differs from aggregated CONTACT Blob accounting")
                connected_blob_totals[participant] = dict(
                    blob_contact_totals[participant]
                )
            elif any(blob_contact_totals[participant].values()):
                fail(f"{label} has CONTACT Blob accounting in a peerless lifetime")
            contact_count[participant] = 0
            blob_contact_totals[participant] = {
                field: 0 for field in CONTACT_BLOB_FIELDS
            }
            del active[participant]
            stop_count[participant] += 1
            stop_records += 1
            continue
        fail(f"{label} belongs to an unadmitted terminal record family")

    if active or any(value != 2 for value in ready_count.values()) or any(
        value != 2 for value in stop_count.values()
    ):
        fail("captured stdout does not contain exactly two complete lifetimes per participant")
    if ready_records != 4 or stop_records != 4:
        fail("captured stdout does not contain exactly four READY and four STOP records")
    if len(connected_sockets) != 2:
        fail("captured stdout does not bind two distinct concurrent actor sockets")
    if len(pids) != 1:
        fail("captured stdout does not bind all actor receipts to one producer process")
    if contact_records != transcript_facts["connected_contacts"] or contact_records < 2:
        fail("captured stdout CONTACT records differ from connected STOP accounting")
    if set(connected_blob_totals) != {"publisher", "receiver"}:
        fail("captured stdout lacks exact connected Blob accounting for both roles")
    publisher_blob = connected_blob_totals["publisher"]
    receiver_blob = connected_blob_totals["receiver"]
    if (
        publisher_blob["blob_ranges_fetched"] != 0
        or publisher_blob["blob_bytes_fetched"] != 0
        or publisher_blob["blob_deferred"] != 0
    ):
        fail("publisher CONTACT accounting reports receiving or deferring Blob content")
    if (
        receiver_blob["blob_ranges_fetched"] <= 0
        or receiver_blob["blob_bytes_fetched"] <= 0
        or receiver_blob["blob_deferred"] != 0
    ):
        fail("receiver CONTACT accounting does not prove positive nondeferred Blob transfer")
    return {
        "lines": len(lines),
        "bytes": len(stdout),
        "sha256": sha256_bytes(stdout),
        "ready_records": ready_records,
        "contact_records": contact_records,
        "stop_records": stop_records,
        "processes": 1,
        "reconciliation": {
            "publisher": {
                field: publisher_blob[field]
                for field in (
                    "blob_ranges_fetched",
                    "blob_bytes_fetched",
                    "blob_deferred",
                )
            },
            "receiver": {
                field: receiver_blob[field]
                for field in (
                    "blob_ranges_fetched",
                    "blob_bytes_fetched",
                    "blob_deferred",
                )
            },
            "remaining_accounting": "validated-exact-not-retained-as-completion-proof",
            "terminal_event_state_record_control_counts": "all-zero",
            "contact_stop_aggregation": "exact",
            "direct_only": True,
        },
        "identifiers_paths_ports_pids": "parsed-cross-bound-excluded",
        "_sensitive_values": sorted(
            {
                *(
                    record[field]
                    for record in participants.values()
                    for field in ("carrier_id", "mission_id", "mission_authority")
                ),
                *transcript_facts["_application_ids"],
                *sockets,
                encoded_path(root),
            }
        ),
        "_sensitive_pids": sorted(pids),
        "_sensitive_ports": sorted(ports),
    }
def validate_artifact_record(
    value: Any,
    label: str,
    *,
    path: str,
    data: bytes,
) -> dict[str, Any]:
    record = exact_object(value, ("path", "bytes", "sha256"), label)
    exact_string(record["path"], f"{label}.path", expected=path)
    exact_uint(record["bytes"], f"{label}.bytes", expected=len(data))
    exact_string(record["sha256"], f"{label}.sha256", expected=sha256_bytes(data), pattern=HEX_32)
    return record


def validate_source_metadata(value: Any, authority: dict[str, Any]) -> list[dict[str, Any]]:
    source = exact_object(value, ("commit", "tree", "signature", "admitted"), "run.source")
    exact_string(source["commit"], "run.source.commit", expected=authority["commit"], pattern=GIT_OBJECT)
    exact_string(source["tree"], "run.source.tree", expected=authority["tree"], pattern=GIT_OBJECT)
    signature = exact_object(
        source["signature"], ("status", "fingerprint"), "run.source.signature"
    )
    exact_string(
        signature["status"],
        "run.source.signature.status",
        expected=authority["signature"]["status"],
    )
    exact_string(
        signature["fingerprint"],
        "run.source.signature.fingerprint",
        expected=authority["signature"]["fingerprint"],
        pattern=SIGNER_FINGERPRINT,
    )
    admitted = exact_array(source["admitted"], "run.source.admitted", length=len(ADMITTED_SOURCE_PATHS))
    normalized: list[dict[str, Any]] = []
    for index, expected_path in enumerate(ADMITTED_SOURCE_PATHS):
        label = f"run.source.admitted[{index}]"
        record = exact_object(admitted[index], ("path", "bytes", "sha256"), label)
        exact_string(record["path"], f"{label}.path", expected=expected_path)
        expected = authority["admitted"][expected_path]
        exact_uint(record["bytes"], f"{label}.bytes", expected=expected["bytes"])
        exact_string(record["sha256"], f"{label}.sha256", expected=expected["sha256"], pattern=HEX_32)
        normalized.append(record)
    return normalized


def validate_run_document(
    document: dict[str, Any],
    root: Path,
    source_authority: dict[str, Any],
    binary: bytes,
    stdout: bytes,
    stderr: bytes,
    transcript: bytes,
) -> dict[str, Any]:
    exact_object(
        document,
        ("schema", "claim", "run_id", "source", "commands", "execution", "artifacts", "tools"),
        "run",
    )
    exact_string(document["schema"], "run.schema", expected=RAW_SCHEMA)
    exact_string(document["claim"], "run.claim", expected=CLAIM)
    run_id = exact_string(document["run_id"], "run.run_id", pattern=RUN_ID)
    if run_id != sha256_bytes(transcript)[:16]:
        fail("run.run_id does not derive from the exact transcript")
    admitted = validate_source_metadata(document["source"], source_authority)

    commands = exact_object(document["commands"], ("build_argv", "run_argv"), "run.commands")
    build_argv = exact_array(commands["build_argv"], "run.commands.build_argv", length=len(EXPECTED_BUILD_ARGV))
    if build_argv != EXPECTED_BUILD_ARGV:
        fail("run.commands.build_argv differs from the exact release build invocation")
    run_argv = exact_array(commands["run_argv"], "run.commands.run_argv", length=2)
    expected_binary = os.fspath(root / "binary" / "aster-live-blob-acceptance")
    if run_argv != [expected_binary, os.fspath(root)]:
        fail("run.commands.run_argv does not bind the copied executable and exact raw root")

    execution = exact_object(
        document["execution"],
        ("exit_code", "worktree_clean_at_run", "source_binary_execution_link"),
        "run.execution",
    )
    exact_uint(execution["exit_code"], "run.execution.exit_code", expected=0)
    exact_bool(execution["worktree_clean_at_run"], "run.execution.worktree_clean_at_run", expected=True)
    exact_string(
        execution["source_binary_execution_link"],
        "run.execution.source_binary_execution_link",
        expected="operator-attested-not-cryptographically-proven",
    )

    artifacts = exact_object(document["artifacts"], ("binary", "stdout", "stderr", "transcript"), "run.artifacts")
    validated_artifacts = {
        "binary": validate_artifact_record(
            artifacts["binary"],
            "run.artifacts.binary",
            path="binary/aster-live-blob-acceptance",
            data=binary,
        ),
        "stdout": validate_artifact_record(artifacts["stdout"], "run.artifacts.stdout", path="stdout.log", data=stdout),
        "stderr": validate_artifact_record(artifacts["stderr"], "run.artifacts.stderr", path="stderr.log", data=stderr),
        "transcript": validate_artifact_record(
            artifacts["transcript"], "run.artifacts.transcript", path="transcript.tsv", data=transcript
        ),
    }

    tools = exact_object(document["tools"], ("producer", "runner", "checker", "test"), "run.tools")
    admitted_by_path = {record["path"]: record for record in admitted}
    normalized_tools: dict[str, dict[str, Any]] = {}
    for role, path in TOOL_PATHS.items():
        label = f"run.tools.{role}"
        record = exact_object(tools[role], ("path", "bytes", "sha256"), label)
        exact_string(record["path"], f"{label}.path", expected=path)
        if record != admitted_by_path[path]:
            fail(f"{label} differs from the signed admitted-source record")
        normalized_tools[role] = record
    return {
        "run_id": run_id,
        "source": document["source"],
        "build_argv": build_argv,
        "run_argv": run_argv,
        "artifacts": validated_artifacts,
        "tools": normalized_tools,
    }


def validate_raw_root(root: Path, source_authority: dict[str, Any]) -> dict[str, Any]:
    root_descriptor, opened_root = open_raw_root(root)
    try:
        inventory = validate_inventory(root_descriptor)
        run_data, run_metadata = read_public_file(root_descriptor, "run.json", "run metadata", RUN_JSON_MAX_BYTES)
        stdout, stdout_metadata = read_public_file(root_descriptor, "stdout.log", "captured stdout", STDOUT_MAX_BYTES)
        stderr, stderr_metadata = read_public_file(root_descriptor, "stderr.log", "captured stderr", STDERR_MAX_BYTES)
        transcript, transcript_metadata = read_public_file(
            root_descriptor, "transcript.tsv", "selected transcript", TRANSCRIPT_MAX_BYTES
        )
        binary, binary_metadata = read_public_file(
            root_descriptor,
            "binary/aster-live-blob-acceptance",
            "copied release executable",
            BINARY_MAX_BYTES,
        )
        public_metadata = {
            "run.json": run_metadata,
            "stdout.log": stdout_metadata,
            "stderr.log": stderr_metadata,
            "transcript.tsv": transcript_metadata,
            "binary/aster-live-blob-acceptance": binary_metadata,
        }
        for relative, metadata in public_metadata.items():
            observed = inventory["files"][relative]
            if (metadata.st_dev, metadata.st_ino, metadata.st_size) != (
                observed.st_dev,
                observed.st_ino,
                observed.st_size,
            ):
                fail(f"public artifact {relative} changed after inventory inspection")
        if not binary:
            fail("copied release executable is empty")
        if stderr != b"":
            fail("captured stderr is nonempty and has no selected acceptance classification")
        transcript_facts = validate_transcript(transcript)
        for participant, phases in {
            "publisher": ("peerless_source", "connected_transfer"),
            "receiver": ("connected_transfer", "restart_receiver"),
        }.items():
            expected_total = inventory["chunk_totals"][participant]
            for phase in phases:
                shutdown_total = parse_uint(
                    transcript_facts["_shutdowns"][f"{phase}:{participant}"][
                        "blob_committed_file_bytes"
                    ],
                    f"SHUTDOWN {phase} {participant}.blob_committed_file_bytes",
                )
                if shutdown_total != expected_total:
                    fail(
                        f"{participant} depot ciphertext metadata does not cross-bind "
                        f"SHUTDOWN {phase} committed bytes"
                    )
        terminal_facts = validate_terminal_stdout(stdout, transcript, root, transcript_facts)
        terminal_facts["_sensitive_values"].extend(inventory["variants"].values())
        terminal_facts["_sensitive_values"] = sorted(
            set(terminal_facts["_sensitive_values"])
        )
        document = load_canonical_json(run_data, "run metadata", RUN_JSON_MAX_BYTES)
        run_facts = validate_run_document(
            document,
            root,
            source_authority,
            binary,
            stdout,
            stderr,
            transcript,
        )
        final_inventory = validate_inventory(root_descriptor)
        require_same_inventory(inventory, final_inventory)
        final_public = {
            "run.json": read_public_file(
                root_descriptor, "run.json", "terminal run metadata", RUN_JSON_MAX_BYTES
            )[0],
            "stdout.log": read_public_file(
                root_descriptor, "stdout.log", "terminal captured stdout", STDOUT_MAX_BYTES
            )[0],
            "stderr.log": read_public_file(
                root_descriptor, "stderr.log", "terminal captured stderr", STDERR_MAX_BYTES
            )[0],
            "transcript.tsv": read_public_file(
                root_descriptor,
                "transcript.tsv",
                "terminal selected transcript",
                TRANSCRIPT_MAX_BYTES,
            )[0],
            "binary/aster-live-blob-acceptance": read_public_file(
                root_descriptor,
                "binary/aster-live-blob-acceptance",
                "terminal copied release executable",
                BINARY_MAX_BYTES,
            )[0],
        }
        initial_public = {
            "run.json": run_data,
            "stdout.log": stdout,
            "stderr.log": stderr,
            "transcript.tsv": transcript,
            "binary/aster-live-blob-acceptance": binary,
        }
        for relative, initial_data in initial_public.items():
            if final_public[relative] != initial_data:
                fail(f"public artifact changed after semantic validation: {relative}")
        terminal_inventory = validate_inventory(root_descriptor)
        require_same_inventory(final_inventory, terminal_inventory)
        final_root = os.fstat(root_descriptor)
        _validate_directory(final_root, "raw root")
        if (final_root.st_dev, final_root.st_ino) != (opened_root.st_dev, opened_root.st_ino):
            fail("raw root changed identity during validation")
        try:
            path_final = os.lstat(root)
        except OSError:
            fail("raw root path vanished during terminal validation")
        if (path_final.st_dev, path_final.st_ino) != (final_root.st_dev, final_root.st_ino):
            fail("raw root path changed identity during validation")
        return {
            "run": run_facts,
            "transcript": transcript_facts,
            "terminal": terminal_facts,
            "retention": {
                "root_mode": "0700",
                "directories": len(EXPECTED_BASE_DIRECTORIES) + 2,
                "files": len(EXPECTED_BASE_FILES) + 4,
                "participant_directories": 2,
                "mission_artifacts": 2,
                "identity_keys": 2,
                "mesh_databases": 2,
                "depot_owner_markers": 2,
                "blob_variants": 2,
                "ciphertext_chunks": 4,
                "chunks_per_participant": 2,
                "ciphertext_bytes_per_participant": COMMITTED_CIPHERTEXT_BYTES,
                "secret_and_ciphertext_contents": "metadata-only-not-opened-read-or-hashed",
                "file_links": "all-one",
                "inventory_aliases": "none",
            },
        }
    finally:
        os.close(root_descriptor)


def reviewer_home_directory() -> str:
    try:
        home = pwd.getpwuid(os.getuid()).pw_dir
    except (KeyError, OSError):
        fail("reviewer account home authority is unavailable")
    if not os.path.isabs(home) or os.path.realpath(home) != home:
        fail("reviewer account home is symbolic or noncanonical")
    try:
        metadata = os.lstat(home)
    except OSError:
        fail("reviewer account home is unavailable")
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        fail("reviewer account home metadata is unsafe")
    return home


def _clean_git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    for key in list(environment):
        if key in {
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_COMMON_DIR",
            "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES",
            "GIT_INDEX_FILE",
            "GIT_NAMESPACE",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_SYSTEM",
            "GIT_CONFIG_GLOBAL",
        } or key.startswith("GIT_CONFIG_KEY_") or key.startswith("GIT_CONFIG_VALUE_"):
            environment.pop(key, None)
    environment.pop("GIT_CONFIG_COUNT", None)
    environment.pop("GNUPGHOME", None)
    environment.pop("GPG_TTY", None)
    reviewer_home = reviewer_home_directory()
    environment.update(
        {
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "HOME": reviewer_home,
        }
    )
    return environment


def trusted_executable(path: str, label: str) -> str:
    if not os.path.isabs(path) or os.path.realpath(path) != path:
        fail(f"{label} executable path is not absolute and canonical")
    try:
        metadata = os.lstat(path)
    except OSError:
        fail(f"{label} executable is unavailable")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid not in {0, os.getuid()}
        or metadata.st_nlink < 1
        or (metadata.st_uid != 0 and metadata.st_nlink != 1)
        or metadata.st_size <= 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
    ):
        fail(f"{label} executable metadata is unsafe")
    return path


def system_executable(name: str) -> str:
    search_path = os.confstr("CS_PATH") or "/bin:/usr/bin"
    resolved = shutil.which(name, path=search_path)
    if resolved is None:
        fail(f"system {name} executable is unavailable")
    return trusted_executable(os.path.realpath(resolved), f"system {name}")


def reviewer_signature_options(git: str) -> list[str]:
    reviewer_home = reviewer_home_directory()
    reviewer_global = os.path.abspath(os.path.join(reviewer_home, ".gitconfig"))
    if os.path.realpath(reviewer_global) != reviewer_global:
        fail("reviewer global Git configuration is symbolic or noncanonical")
    try:
        global_metadata = os.lstat(reviewer_global)
    except OSError:
        fail("reviewer global Git configuration is unavailable")
    if (
        not stat.S_ISREG(global_metadata.st_mode)
        or stat.S_ISLNK(global_metadata.st_mode)
        or global_metadata.st_uid != os.getuid()
        or global_metadata.st_nlink != 1
        or global_metadata.st_size <= 0
        or global_metadata.st_size > 1024 * 1024
        or stat.S_IMODE(global_metadata.st_mode) & 0o022
    ):
        fail("reviewer global Git configuration metadata is unsafe")
    environment = _clean_git_environment()
    environment["GIT_CONFIG_GLOBAL"] = reviewer_global

    def global_value(arguments: Sequence[str], label: str) -> str:
        try:
            completed = subprocess.run(
                [git, "config", "--global", *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                shell=False,
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            fail(f"reviewer signature {label} could not be read")
        if completed.returncode != 0 or completed.stderr or len(completed.stdout) > 4096:
            fail(f"reviewer signature {label} is unavailable")
        try:
            value = completed.stdout.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError:
            fail(f"reviewer signature {label} is not UTF-8")
        if not value or "\n" in value or "\x00" in value:
            fail(f"reviewer signature {label} is malformed")
        return value

    signature_format = global_value(["--get", "gpg.format"], "format")
    if signature_format == "ssh":
        allowed = global_value(
            ["--path", "--get", "gpg.ssh.allowedSignersFile"], "allowed signers"
        )
        if allowed.startswith("~/"):
            allowed_path = os.path.join(reviewer_home, allowed[2:])
        elif os.path.isabs(allowed):
            allowed_path = allowed
        else:
            fail("reviewer SSH allowed-signers path is not absolute")
        allowed_path = os.path.abspath(allowed_path)
        if os.path.realpath(allowed_path) != allowed_path:
            fail("reviewer SSH allowed-signers path is symbolic or noncanonical")
        try:
            allowed_metadata = os.lstat(allowed_path)
        except OSError:
            fail("reviewer SSH allowed-signers file is unavailable")
        if (
            not stat.S_ISREG(allowed_metadata.st_mode)
            or stat.S_ISLNK(allowed_metadata.st_mode)
            or allowed_metadata.st_uid != os.getuid()
            or allowed_metadata.st_nlink != 1
            or allowed_metadata.st_size <= 0
            or allowed_metadata.st_size > 1024 * 1024
            or stat.S_IMODE(allowed_metadata.st_mode) & 0o022
        ):
            fail("reviewer SSH allowed-signers file metadata is unsafe")
        ssh_keygen = system_executable("ssh-keygen")
        return [
            "-c",
            "gpg.format=ssh",
            "-c",
            f"gpg.ssh.allowedSignersFile={allowed_path}",
            "-c",
            f"gpg.ssh.program={ssh_keygen}",
            "-c",
            "gpg.minTrustLevel=fully",
        ]
    if signature_format == "openpgp":
        configured_gpg = global_value(["--path", "--get", "gpg.program"], "gpg program")
        gpg = trusted_executable(configured_gpg, "reviewer gpg")
        return [
            "-c",
            "gpg.format=openpgp",
            "-c",
            f"gpg.program={gpg}",
            "-c",
            f"gpg.openpgp.program={gpg}",
            "-c",
            "gpg.minTrustLevel=fully",
        ]
    fail("reviewer signature format is unsupported")


def run_git(
    source: Path,
    arguments: Sequence[str],
    label: str,
    maximum: int = 64 * 1024 * 1024,
    *,
    git: str | None = None,
    trusted_options: Sequence[str] = (),
) -> bytes:
    git = git or system_executable("git")
    if not os.path.isabs(git):
        fail("git is unavailable for independent source validation")
    try:
        completed = subprocess.run(
            [
                git,
                "--no-replace-objects",
                *trusted_options,
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.hooksPath=/dev/null",
                "-C",
                os.fspath(source),
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_clean_git_environment(),
            shell=False,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        fail(f"source {label} could not be completed")
    if len(completed.stdout) > maximum or len(completed.stderr) > 1024 * 1024:
        fail(f"source {label} exceeded its output bound")
    if completed.returncode != 0:
        fail(f"source {label} failed")
    return completed.stdout


def parse_signature_authority(data: bytes) -> dict[str, str]:
    if len(data) > 4096 or not data.endswith(b"\n") or data.count(b"\x00") != 1:
        fail("source signature status and fingerprint record is malformed")
    raw_status, raw_fingerprint = data[:-1].split(b"\x00", 1)
    try:
        status = raw_status.decode("ascii", errors="strict")
        fingerprint = raw_fingerprint.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        fail("source signature authority is not canonical ASCII")
    if status != "G":
        fail("source signature status is not exactly good and trusted")
    if SIGNER_FINGERPRINT.fullmatch(fingerprint) is None:
        fail("source signer fingerprint is empty or noncanonical")
    return {"status": "good", "fingerprint": fingerprint}


def validate_source(source: Path, raw_root: Path) -> dict[str, Any]:
    source_text = os.path.abspath(os.fspath(source))
    if os.path.realpath(source_text) != source_text:
        fail("source root is symbolic or noncanonical")
    try:
        metadata = os.lstat(source_text)
    except OSError:
        fail("source root is unavailable")
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        fail("source root is not one plain directory")
    git = system_executable("git")
    trusted_options = reviewer_signature_options(git)

    def source_git(
        arguments: Sequence[str], label: str, maximum: int = 64 * 1024 * 1024
    ) -> bytes:
        return run_git(
            source,
            arguments,
            label,
            maximum,
            git=git,
            trusted_options=trusted_options,
        )

    top = source_git(["rev-parse", "--show-toplevel"], "root discovery", 4096)
    try:
        top_path = Path(os.fsdecode(top.rstrip(b"\n")))
        if not os.path.samefile(source, top_path):
            fail("source root is not the repository top level")
    except (OSError, UnicodeDecodeError):
        fail("source root identity could not be validated")
    head = source_git(["rev-parse", "--verify", "HEAD"], "HEAD validation", 128).decode("ascii", errors="strict").strip()
    if GIT_OBJECT.fullmatch(head) is None:
        fail("source HEAD is not one canonical commit identifier")
    tree = source_git(["show", "-s", "--format=%T", head], "tree validation", 128).decode("ascii", errors="strict").strip()
    if GIT_OBJECT.fullmatch(tree) is None:
        fail("source tree is not one canonical tree identifier")
    source_git(["verify-commit", head], "commit signature validation", 1024 * 1024)
    signature = parse_signature_authority(
        source_git(
            ["show", "-s", "--format=%G?%x00%GF", head],
            "commit signer fingerprint validation",
            4096,
        )
    )
    status = source_git(["status", "--porcelain=v1", "--untracked-files=all"], "worktree validation", 4 * 1024 * 1024)
    try:
        raw_relative = raw_root.relative_to(source)
    except ValueError:
        raw_relative = None
    if raw_relative is not None:
        fail("raw root must be outside the source checkout")
    if status:
        fail("source worktree is not clean at independent validation time")
    admitted: dict[str, dict[str, Any]] = {}
    for relative in ADMITTED_SOURCE_PATHS:
        content = source_git(["show", f"{head}:{relative}"], f"admitted blob {relative}")
        if not content or len(content) > 16 * 1024 * 1024:
            fail(f"signed admitted source file is empty or exceeds its bound: {relative}")
        working = source / relative
        try:
            working_metadata = os.lstat(working)
        except OSError:
            fail(f"working admitted source file is missing: {relative}")
        if (
            not stat.S_ISREG(working_metadata.st_mode)
            or stat.S_ISLNK(working_metadata.st_mode)
            or working_metadata.st_nlink != 1
            or working_metadata.st_size != len(content)
        ):
            fail(f"working admitted source file has unsafe metadata: {relative}")
        try:
            working_content = working.read_bytes()
        except OSError:
            fail(f"working admitted source file could not be read: {relative}")
        if working_content != content:
            fail(f"working admitted source differs from signed commit: {relative}")
        admitted[relative] = {"bytes": len(content), "sha256": sha256_bytes(content)}
    terminal_status = source_git(
        ["status", "--porcelain=v1", "--untracked-files=all"],
        "terminal worktree validation",
        4 * 1024 * 1024,
    )
    if terminal_status:
        fail("source worktree changed during independent validation")
    return {"commit": head, "tree": tree, "signature": signature, "admitted": admitted}


def build_receipt(source: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    run = evidence["run"]
    transcript = evidence["transcript"]
    binary = run["artifacts"]["binary"]
    terminal = evidence["terminal"]
    admitted = [
        {
            "path": path,
            "bytes": source["admitted"][path]["bytes"],
            "sha256": source["admitted"][path]["sha256"],
        }
        for path in ADMITTED_SOURCE_PATHS
    ]
    tools = {
        role: {
            "bytes": source["admitted"][path]["bytes"],
            "sha256": source["admitted"][path]["sha256"],
        }
        for role, path in TOOL_PATHS.items()
    }
    exact_run_argv_sha256 = sha256_bytes(canonical_json_bytes(run["run_argv"]))
    return {
        "schema": SCHEMA,
        "status": "pass",
        "claim": CLAIM,
        "source": {
            "commit": source["commit"],
            "tree": source["tree"],
            "signature": source["signature"],
            "admitted": admitted,
        },
        "build": {
            "argv": EXPECTED_BUILD_ARGV,
            "profile": "release",
            "executable": {"bytes": binary["bytes"], "sha256": binary["sha256"]},
            "source_binary_execution_link": "operator-attested-not-cryptographically-proven",
        },
        "run": {
            "id": run["run_id"],
            "argv_redacted": ["<raw-root>/binary/aster-live-blob-acceptance", "<raw-root>"],
            "exact_argv_sha256": exact_run_argv_sha256,
            "exit_code": 0,
            "stdout": {
                "bytes": run["artifacts"]["stdout"]["bytes"],
                "sha256": run["artifacts"]["stdout"]["sha256"],
                "lines": terminal["lines"],
                "ready_records": terminal["ready_records"],
                "contact_records": terminal["contact_records"],
                "stop_records": terminal["stop_records"],
                "identifiers_paths_ports_pids": terminal[
                    "identifiers_paths_ports_pids"
                ],
            },
            "stderr": {
                "bytes": run["artifacts"]["stderr"]["bytes"],
                "sha256": run["artifacts"]["stderr"]["sha256"],
                "classification": "exact-empty",
            },
            "transcript": {
                "records": transcript["records"],
                "bytes": transcript["bytes"],
                "sha256": transcript["sha256"],
                "identifiers": "excluded",
                "payloads": "sha256-only",
            },
        },
        "acceptance": {
            "participants": 2,
            "actor_lifetimes": 4,
            "maximum_concurrent_actors": 2,
            "distinct_carrier_ids": 2,
            "distinct_mission_ids": 2,
            "common_disjoint_mission_authority": True,
            "reciprocal_expected_peer_binding": "verified",
            "live_handle_identity_binding": "verified",
            "runtime_ready_stop_identity_binding": "verified",
            "blob": {
                "publications": transcript["blob_publications"],
                "payload": {
                    "bytes": PAYLOAD_LEN,
                    "sha256": PAYLOAD_SHA256,
                    "media_type": MEDIA_TYPE,
                    "schema_id_sha256": SCHEMA_ID_SHA256,
                    "priority": "priority",
                    "counter": 1,
                    "acceptance_marker": 1,
                },
                "pages": [
                    {
                        "index": page[0],
                        "offset": page[1],
                        "bytes": page[2],
                        "next_offset": page[3],
                        "complete": page[4] == "true",
                        "sha256": page[5],
                    }
                    for page in PAGE_FACTS
                ],
                "page_limit": PAGE_LIMIT,
                "exact_page_reads": transcript["page_reads"],
                "whole_reads": transcript["whole_reads"],
                "read_phases": [
                    "peerless-source",
                    "connected-receiver",
                    "restart-receiver",
                ],
                "exact_noninserting_retries": transcript["publication_retries"],
                "changed_payload_conflicts": transcript["publication_conflicts"],
                "conflict_preserves_publication": True,
                "source_removed_and_parent_synced_before_transfer": transcript[
                    "source_removed"
                ],
            },
            "connected_path": "positive-direct-only-zero-errors",
            "connected_contacts": transcript["connected_contacts"],
            "connected_reconciliation": terminal["reconciliation"],
            "publisher_fetched_ranges_and_bytes": "exact-zero",
            "receiver_fetched_ranges_and_bytes": "positive",
            "durable_shape": {
                "publications": 1,
                "acceptance_markers": 1,
                "last_acceptance_marker": 1,
                "variants": 1,
                "finalized_variants": 1,
                "committed_chunks": 2,
                "committed_file_bytes": COMMITTED_CIPHERTEXT_BYTES,
                "reserved_file_bytes": COMMITTED_CIPHERTEXT_BYTES,
            },
            "peerless_and_restart_contacts": 0,
            "graceful_shutdowns": transcript["shutdowns"],
            "closed_retained_handles": transcript["closed_handles"],
            "bind_reacquisitions": transcript["bind_reacquisitions"],
        },
        "retention": evidence["retention"],
        "tools": tools,
        "limitations": LIMITATIONS,
        "nonclaims": NONCLAIMS,
    }
def receipt_forbidden_values(
    evidence: dict[str, Any], raw_root: Path, source: Path | None = None
) -> list[str]:
    values = set(evidence["terminal"]["_sensitive_values"])
    values.add(encoded_path(raw_root))
    if source is not None:
        values.add(encoded_path(source))
    return sorted(value for value in values if value)


def receipt_forbidden_pids(evidence: dict[str, Any]) -> list[int]:
    return list(evidence["terminal"]["_sensitive_pids"])


def receipt_forbidden_ports(evidence: dict[str, Any]) -> list[int]:
    return list(evidence["terminal"]["_sensitive_ports"])


def contains_exact_scalar(value: Any, forbidden_strings: set[str], forbidden_ints: set[int]) -> bool:
    if type(value) is int:
        return value in forbidden_ints
    if isinstance(value, str):
        return value in forbidden_strings
    if isinstance(value, list):
        return any(contains_exact_scalar(item, forbidden_strings, forbidden_ints) for item in value)
    if isinstance(value, dict):
        return any(
            contains_exact_scalar(item, forbidden_strings, forbidden_ints)
            for item in value.values()
        )
    return False


def render_receipt(
    document: dict[str, Any],
    *,
    forbidden_values: Iterable[str] = (),
    forbidden_pids: Iterable[int] = (),
    forbidden_ports: Iterable[int] = (),
) -> bytes:
    pid_values = set(forbidden_pids)
    if contains_exact_scalar(document, {str(pid) for pid in pid_values}, pid_values):
        fail("sanitized receipt contains an exact process identifier scalar")
    port_values = set(forbidden_ports)
    if contains_exact_scalar(document, {str(port) for port in port_values}, port_values):
        fail("sanitized receipt contains an exact network port scalar")
    encoded = canonical_json_bytes(document)
    if len(encoded) > RECEIPT_MAX_BYTES:
        fail("sanitized receipt exceeds the 16 KiB output cap")
    forbidden = (b"/private/", b"/Users/", b"127.0.0.1:", b'"pid"', b'"port"')
    if any(token in encoded for token in forbidden):
        fail("sanitized receipt contains a forbidden path, port, or process field")
    for value in forbidden_values:
        raw = value.encode("ascii", errors="strict")
        if raw and raw in encoded:
            fail("sanitized receipt contains a parsed identifier, path, port, or process value")
    return encoded


def read_supplied_receipt(path: Path) -> bytes:
    try:
        metadata = os.lstat(path)
    except OSError:
        fail("supplied receipt is missing or unreadable")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) not in {0o600, 0o644}
        or metadata.st_size > RECEIPT_MAX_BYTES
    ):
        fail("supplied receipt has unsafe metadata or exceeds its cap")
    flags = FILE_FLAGS
    try:
        descriptor = os.open(path, flags)
    except OSError:
        fail("supplied receipt could not be opened without following links")
    try:
        opened = os.fstat(descriptor)
        if stat_witness(opened) != stat_witness(metadata):
            fail("supplied receipt changed metadata while opening")
        data = os.read(descriptor, RECEIPT_MAX_BYTES + 1)
        if len(data) != opened.st_size:
            fail("supplied receipt changed size while reading")
        final_opened = os.fstat(descriptor)
        try:
            final_path = os.lstat(path)
        except OSError:
            fail("supplied receipt path disappeared while reading")
        if (
            stat_witness(final_opened) != stat_witness(opened)
            or stat_witness(final_path) != stat_witness(metadata)
        ):
            fail("supplied receipt changed metadata or path identity while reading")
        return data
    finally:
        os.close(descriptor)


def validate_supplied_receipt(data: bytes, expected: bytes) -> None:
    load_canonical_json(data, "supplied receipt", RECEIPT_MAX_BYTES)
    if data != expected:
        fail("supplied receipt differs byte-for-byte from the canonical projection")


def write_receipt(path: Path | None, data: bytes) -> None:
    if path is None:
        sys.stdout.buffer.write(data)
        return
    if path.name != RECEIPT_NAME:
        fail(f"receipt output must use the exact filename {RECEIPT_NAME}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        created = os.fstat(descriptor)
        if (
            not stat.S_ISREG(created.st_mode)
            or created.st_uid != os.getuid()
            or created.st_nlink != 1
            or stat.S_IMODE(created.st_mode) != 0o600
        ):
            fail("receipt output was not created as one owner-only regular file")
        written = 0
        while written < len(data):
            count = os.write(descriptor, data[written:])
            if count <= 0:
                fail("receipt output could not be completed")
            written += count
        os.fsync(descriptor)
        final_opened = os.fstat(descriptor)
        try:
            final_path = os.lstat(path)
        except OSError:
            fail("receipt output path disappeared while writing")
        if (
            (final_opened.st_dev, final_opened.st_ino)
            != (created.st_dev, created.st_ino)
            or final_opened.st_size != len(data)
            or stat.S_IMODE(final_opened.st_mode) != 0o600
            or stat_witness(final_path) != stat_witness(final_opened)
        ):
            fail("receipt output changed metadata or path identity while writing")
    except FileExistsError:
        fail("receipt output already exists; refusing to overwrite it")
    except OSError:
        fail("receipt output could not be created safely")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def parse_args(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "receipt",
        nargs="?",
        default="-",
        help="existing receipt to validate byte-for-byte, or '-' to project",
    )
    parser.add_argument("--raw-root", required=True, type=Path, help="owner-only retained raw root")
    parser.add_argument("--source", required=True, type=Path, help="exact signed source checkout")
    parser.add_argument(
        "--output",
        type=Path,
        help=f"exclusive projected output named {RECEIPT_NAME}; projection defaults to stdout",
    )
    options = parser.parse_args(arguments)
    if options.receipt != "-" and options.output is not None:
        parser.error("--output cannot be combined with an existing receipt")
    return options


def main(arguments: list[str] | None = None) -> None:
    options = parse_args(arguments)
    try:
        raw_root = Path(os.path.abspath(os.fspath(options.raw_root)))
        source = Path(os.path.abspath(os.fspath(options.source)))
        source_authority = validate_source(source, raw_root)
        evidence = validate_raw_root(raw_root, source_authority)
        terminal_source_authority = validate_source(source, raw_root)
        if terminal_source_authority != source_authority:
            fail("signed source authority changed during raw evidence validation")
        encoded = render_receipt(
            build_receipt(source_authority, evidence),
            forbidden_values=receipt_forbidden_values(evidence, raw_root, source),
            forbidden_pids=receipt_forbidden_pids(evidence),
            forbidden_ports=receipt_forbidden_ports(evidence),
        )
        if options.receipt == "-":
            write_receipt(options.output, encoded)
        else:
            supplied = read_supplied_receipt(Path(options.receipt))
            validate_supplied_receipt(supplied, encoded)
    except ReceiptViolation as error:
        print("selected live Blob receipt validation failed", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
