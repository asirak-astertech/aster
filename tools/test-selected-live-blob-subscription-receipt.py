#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Adversarial tests for the retained peerless Blob-subscription receipt."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock


def _read_source(path: Path) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or not 0 < before.st_size <= 4 * 1024 * 1024
    ):
        raise RuntimeError(f"unsafe test subject source {path}")
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
            raise RuntimeError(f"test subject changed while opening {path}")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise RuntimeError(f"test subject truncated while reading {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RuntimeError(f"test subject grew while reading {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _load() -> types.ModuleType:
    path = Path(__file__).with_name(
        "check-selected-live-blob-subscription-receipt.py"
    )
    source = _read_source(path)
    module = types.ModuleType("selected_live_blob_subscription_checker_test_subject")
    module.__file__ = os.fspath(path)
    module.__package__ = ""
    sys.modules[module.__name__] = module
    try:
        exec(
            compile(source, os.fspath(path), "exec", dont_inherit=True, optimize=0),
            module.__dict__,
        )
    except BaseException:
        sys.modules.pop(module.__name__, None)
        raise
    return module


CHECKER = _load()


def identifier(number: int) -> str:
    return f"{number:064x}"


def record(kind: str, keys: tuple[str, ...], values: dict[str, object]) -> str:
    missing = set(keys) - set(values)
    extra = set(values) - set(keys)
    if missing or extra:
        raise AssertionError(f"fixture {kind} fields differ: missing={missing}, extra={extra}")
    return "\t".join(
        [CHECKER.TRANSCRIPT_PREFIX, kind.lower()]
        + [f"{key}={values[key]}" for key in keys]
    )


def terminal_record(prefix: str, keys: tuple[str, ...], values: dict[str, object]) -> str:
    missing = set(keys) - set(values)
    extra = set(values) - set(keys)
    if missing or extra:
        raise AssertionError(f"terminal {prefix} fields differ: missing={missing}, extra={extra}")
    return " ".join([prefix] + [f"{key}={values[key]}" for key in keys])


def child_record(kind: str, keys: tuple[str, ...], values: dict[str, object]) -> str:
    missing = set(keys) - set(values)
    extra = set(values) - set(keys)
    if missing or extra:
        raise AssertionError(f"child {kind} fields differ: missing={missing}, extra={extra}")
    return "\t".join(
        [CHECKER.CHILD_PREFIX, kind] + [f"{key}={values[key]}" for key in keys]
    )


def receipt_values(phase: str) -> dict[str, str]:
    values = {key: "0" for key in CHECKER.RECEIPT_KEYS}
    values.update(
        {
            "phase": phase,
            "participant": "node",
            "blobs": "2",
            "blob_acceptance_markers": "2",
            "blob_last_acceptance_marker": "2",
            "blob_operations": "2",
            "blob_variants": "1",
            "blob_finalized_variants": "1",
            "blob_committed_chunks": "1",
            "blob_committed_file_bytes": str(CHECKER.COMMITTED_CIPHERTEXT_BYTES),
            "blob_reserved_file_bytes": str(CHECKER.COMMITTED_CIPHERTEXT_BYTES),
        }
    )
    return values


class TranscriptFixture:
    def __init__(self) -> None:
        self.carrier = identifier(1)
        self.mission = identifier(2)
        self.authority = identifier(3)
        self.subscription = identifier(4)
        self.blob = identifier(5)
        self.publication_a = identifier(6)
        self.publication_b = identifier(7)
        self.token_one = identifier(8)
        self.token_two = identifier(9)
        self.token_b = identifier(10)
        self.entries: list[tuple[str, tuple[str, ...], dict[str, object]]] = []
        self._build()

    def add(self, kind: str, values: dict[str, object]) -> None:
        expected_kind, keys = CHECKER.EXPECTED_SEQUENCE[len(self.entries)]
        if expected_kind != kind:
            raise AssertionError(f"fixture kind {kind} != {expected_kind}")
        self.entries.append((kind, keys, values))

    def phase(self, number: int, name: str, actors: str, outcome: str) -> None:
        self.add(
            "PHASE",
            {"phase": number, "name": name, "actors": actors, "outcome": outcome},
        )

    def subscription_record(self, phase: str, inserted: bool) -> None:
        self.add(
            "SUBSCRIPTION",
            {
                "phase": phase,
                "participant": "node",
                "id": self.subscription,
                "inserted": str(inserted).lower(),
                "topic": CHECKER.TOPIC,
                "scope": CHECKER.ROOT_SCOPE,
                "include_descendant_scopes": "false",
            },
        )

    def status(self, phase: str, counts: tuple[int, int, int, int, int]) -> None:
        subscriptions, pending, acknowledged, cursors, generation = counts
        self.add(
            "STATUS",
            {
                "phase": phase,
                "participant": "node",
                "subscriptions": subscriptions,
                "pending_deliveries": pending,
                "acknowledged_deliveries": acknowledged,
                "delivery_cursors": cursors,
                "selector_generation": generation,
            },
        )

    def publication(
        self,
        label: str,
        counter: int,
        topic: str,
        scope: str,
        priority: str,
    ) -> None:
        self.add(
            "PUBLICATION",
            {
                "phase": "initial_peerless",
                "participant": "node",
                "label": label,
                "blob_id": self.blob,
                "publisher": self.mission,
                "counter": counter,
                "topic": topic,
                "scope": scope,
                "priority": priority,
                "total_len": CHECKER.PAYLOAD_BYTES,
                "media_type": CHECKER.MEDIA_TYPE,
                "schema_sha256": CHECKER.SCHEMA_SHA256,
                "payload_sha256": CHECKER.PAYLOAD_SHA256,
                "acceptance_marker": counter,
                "inserted": "true",
            },
        )

    def delivery(
        self,
        phase: str,
        label: str,
        publication: str,
        counter: int,
        priority: str,
        attempt: int,
        token: str,
        has_more: bool,
    ) -> None:
        self.add(
            "DELIVERY",
            {
                "phase": phase,
                "participant": "node",
                "label": label,
                "subscription_id": self.subscription,
                "publication_id": publication,
                "blob_id": self.blob,
                "publisher": self.mission,
                "counter": counter,
                "topic": CHECKER.TOPIC,
                "scope": CHECKER.ROOT_SCOPE,
                "priority": priority,
                "total_len": CHECKER.PAYLOAD_BYTES,
                "media_type": CHECKER.MEDIA_TYPE,
                "schema_sha256": CHECKER.SCHEMA_SHA256,
                "acceptance_marker": counter,
                "attempt": attempt,
                "token_sha256": token,
                "delivery_limit": CHECKER.DELIVERY_LIMIT,
                "scan_limit": CHECKER.SCAN_LIMIT,
                "has_more": str(has_more).lower(),
                "metadata_only": "true",
                "acknowledged": "false",
            },
        )

    def _build(self) -> None:
        self.add(
            "RUN",
            {
                "schema": CHECKER.TRANSCRIPT_SCHEMA,
                "claim": CHECKER.CLAIM,
                "participants": 1,
                "processes": 3,
                "actor_lifetimes": 4,
                "maximum_concurrent_processes": 2,
                "maximum_concurrent_actors": 1,
                "phases": 4,
                "topic": CHECKER.TOPIC,
                "root_scope": CHECKER.ROOT_SCOPE,
                "delivery_limit": CHECKER.DELIVERY_LIMIT,
                "scan_limit": CHECKER.SCAN_LIMIT,
                "token_bytes": CHECKER.TOKEN_BYTES,
            },
        )
        self.add(
            "PARTICIPANT",
            {
                "participant": "node",
                "carrier_id": self.carrier,
                "mission_id": self.mission,
                "mission_authority": self.authority,
                "provisioning": "one-node-bundle",
            },
        )
        self.phase(1, "initial_peerless", "parent", "published-and-durable")
        self.subscription_record("initial_peerless", True)
        self.subscription_record("initial_peerless", False)
        self.add(
            "SUBSCRIPTION_CONFLICT",
            {
                "phase": "initial_peerless",
                "participant": "node",
                "kind": "conflict",
                "operation": "blob_subscribe",
                "changed_descendants": "true",
                "rejected": "true",
            },
        )
        self.publication("matching-a", 1, CHECKER.TOPIC, CHECKER.ROOT_SCOPE, "priority")
        self.publication("matching-b", 2, CHECKER.TOPIC, CHECKER.ROOT_SCOPE, "immediate")
        self.status("initial_peerless", (1, 0, 0, 0, 1))
        self.add("RECEIPT", receipt_values("initial_peerless"))
        self.phase(2, "forced_delivery_attempt", "attempt-one-child", "force-terminated")
        self.subscription_record("forced_delivery_attempt", False)
        self.delivery(
            "forced_delivery_attempt", "matching-a", self.publication_a, 1,
            "priority", 1, self.token_one, True,
        )
        self.status("forced_delivery_attempt", (1, 1, 0, 1, 1))
        self.add(
            "PROCESS_TERMINATION",
            {
                "phase": "forced_delivery_attempt",
                "participant": "node",
                "mechanism": "parent-child-kill",
                "signal": "sigkill",
                "distinct_process": "true",
                "after_flushed_poll": "true",
                "graceful": "false",
                "stop_record_observed": "false",
                "acknowledged": "false",
                "token_persisted": "true",
                "token_artifact_mode": "0600",
                "token_artifact_fsynced": "true",
            },
        )
        self.phase(3, "peerless_redelivery", "attempt-two-child", "acknowledged-and-empty")
        self.subscription_record("peerless_redelivery", False)
        self.delivery(
            "peerless_redelivery", "matching-a-retry", self.publication_a, 1,
            "priority", 2, self.token_two, True,
        )
        self.add(
            "TOKEN_CHECKS",
            {
                "phase": "peerless_redelivery",
                "label": "retry",
                "token_bytes": CHECKER.TOKEN_BYTES,
                "attempt_tokens_distinct": "true",
                "previous_token_restored": "true",
                "malformed_token_rejected": "true",
                "wrong_publication_token_rejected": "false",
                "token_artifact_removed": "false",
            },
        )
        self.add(
            "ACKNOWLEDGEMENT",
            {
                "phase": "peerless_redelivery",
                "participant": "node",
                "label": "matching-a",
                "publication_id": self.publication_a,
                "ack": "acknowledged",
                "reack": "already_acknowledged",
                "ack_token_attempt": 1,
                "reack_token_attempt": 2,
            },
        )
        self.delivery(
            "peerless_redelivery", "matching-b", self.publication_b, 2,
            "immediate", 1, self.token_b, False,
        )
        self.add(
            "TOKEN_CHECKS",
            {
                "phase": "peerless_redelivery",
                "label": "binding",
                "token_bytes": CHECKER.TOKEN_BYTES,
                "attempt_tokens_distinct": "true",
                "previous_token_restored": "true",
                "malformed_token_rejected": "true",
                "wrong_publication_token_rejected": "true",
                "token_artifact_removed": "true",
            },
        )
        self.add(
            "ACKNOWLEDGEMENT",
            {
                "phase": "peerless_redelivery",
                "participant": "node",
                "label": "matching-b",
                "publication_id": self.publication_b,
                "ack": "acknowledged",
                "reack": "already_acknowledged",
                "ack_token_attempt": 1,
                "reack_token_attempt": 1,
            },
        )
        self.add(
            "EMPTY_POLL",
            {
                "phase": "peerless_redelivery",
                "participant": "node",
                "label": "post-acknowledgement",
                "deliveries": 0,
                "has_more": "false",
            },
        )
        self.status("peerless_redelivery", (1, 0, 2, 2, 1))
        self.add("RECEIPT", receipt_values("peerless_redelivery"))
        self.phase(4, "final_peerless_reopen", "parent", "durable-empty")
        self.subscription_record("final_peerless_reopen", False)
        self.add(
            "EMPTY_POLL",
            {
                "phase": "final_peerless_reopen",
                "participant": "node",
                "label": "durable-empty",
                "deliveries": 0,
                "has_more": "false",
            },
        )
        self.status("final_peerless_reopen", (1, 0, 2, 2, 1))
        self.add("RECEIPT", receipt_values("final_peerless_reopen"))
        self.add(
            "INSPECTION",
            {
                "participant": "node",
                "blob_publications": 2,
                "blob_acceptance_markers": 2,
                "blob_operations": 2,
                "blob_variants": 1,
                "blob_finalized_variants": 1,
                "blob_committed_chunks": 1,
                "blob_committed_file_bytes": CHECKER.COMMITTED_CIPHERTEXT_BYTES,
                "blob_reserved_file_bytes": CHECKER.COMMITTED_CIPHERTEXT_BYTES,
                "subscriptions": 1,
                "pending_deliveries": 0,
                "acknowledged_deliveries": 2,
                "delivery_cursors": 2,
                "selector_generation": 1,
                "other_namespaces_empty": "true",
                "pending_blobs": 0,
                "carrier_prefixes": 0,
                "network_staging_bytes": 0,
            },
        )
        self.add(
            "CLOSED_HANDLE",
            {
                "phase": "final_peerless_reopen",
                "participant": "node",
                "operation": "blob_delivery_status",
                "kind": "state_unavailable",
            },
        )
        self.add("BIND", {"participant": "node", "reacquired": "true"})
        self.add(
            "RESULT",
            dict(
                zip(
                    CHECKER.RESULT_KEYS,
                    """pass 35 4 1 3 4 2 1 3 1 2 2 0 2 3 5 2 2 1 4 2 2 4 1
                    sha256-only sha256-only false false false false false false false""".split(),
                    strict=True,
                )
            ),
        )
        if len(self.entries) != 35:
            raise AssertionError(f"fixture has {len(self.entries)} records")

    def data(self) -> bytes:
        return (
            "\n".join(record(kind, keys, values) for kind, keys, values in self.entries)
            + "\n"
        ).encode("ascii")

    def mutated(self, index: int, key: str, value: object) -> bytes:
        clone = copy.deepcopy(self)
        clone.entries[index][2][key] = value
        return clone.data()


class RawRootFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve() / "raw"
        self.variant = identifier(90)
        self.chunk = (
            self.root
            / "participants/node/state/blob-depot-v1"
            / self.variant
            / CHECKER.CHUNK_FILE
        )
        for relative in (
            "binary",
            "participants/node/state/blob-depot-v1",
            f"participants/node/state/blob-depot-v1/{self.variant}",
        ):
            path = self.root / relative
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(path, 0o700)
        os.chmod(self.root, 0o700)
        for path in self.root.rglob("*"):
            if path.is_dir():
                os.chmod(path, 0o700)
        files = {
            "run.json": b"{}\n",
            "stdout.log": b"x\n",
            "stderr.log": b"",
            "transcript.tsv": b"x\n",
            f"binary/{CHECKER.BINARY_NAME}": b"binary",
            "participants/node/mission.bundle": b"mission",
            "participants/node/state/identity.key": b"i" * 32,
            "participants/node/state/mesh.redb": b"database",
            "participants/node/state/blob-depot-v1/.aster-store-owner-v1": b"o" * 72,
            f"participants/node/state/blob-depot-v1/{self.variant}/{CHECKER.CHUNK_FILE}": (
                b"c" * CHECKER.COMMITTED_CIPHERTEXT_BYTES
            ),
        }
        for relative, data in files.items():
            path = self.root / relative
            path.write_bytes(data)
            os.chmod(path, 0o700 if relative.startswith("binary/") else 0o600)

    def close(self) -> None:
        self.temporary.cleanup()

    def inventory(self):
        descriptor, _ = CHECKER.SUPPORT.open_raw_root(self.root)
        try:
            return CHECKER.validate_inventory(descriptor)
        finally:
            os.close(descriptor)


def ready_values(fixture: TranscriptFixture, root: Path, pid: int, port: int) -> dict[str, str]:
    return {
        "selected": "true",
        "pid": str(pid),
        "carrier_id": fixture.carrier,
        "mission_id": fixture.mission,
        "mission_authority": fixture.authority,
        "sockets": f"127.0.0.1:{port}",
        "state": CHECKER.encoded_path(root / "participants/node/state"),
        "peers": "0",
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
    }


def stop_values(fixture: TranscriptFixture) -> dict[str, str]:
    values = {key: "0" for key in CHECKER.SUPPORT.STOP_KEYS}
    values.update(
        {
            "lifecycle": "complete",
            "sync_status": "no_successful_contact",
            "carrier_id": fixture.carrier,
            "mission_id": fixture.mission,
            "path_observation": "not-authorization",
            "blobs": "2",
            "blob_acceptance_markers": "2",
            "blob_last_acceptance_marker": "2",
            "blob_sealed_bytes": str(CHECKER.SEALED_SOURCE_BYTES),
            "blob_operations": "2",
            "blob_operation_bytes": "147",
            "blob_variants": "1",
            "blob_finalized_variants": "1",
            "blob_committed_chunks": "1",
            "blob_committed_file_bytes": str(CHECKER.COMMITTED_CIPHERTEXT_BYTES),
            "blob_reserved_file_bytes": str(CHECKER.COMMITTED_CIPHERTEXT_BYTES),
            "mission_auth": "hybrid-pq",
            "provisioning": "unprotected-reference",
            "semantics": "source-authenticated-event",
            "reconciliation_classes": "event,state,record,blob-v5",
            "controls_semantics": "source-authenticated-flash",
        }
    )
    return values


def terminal_fixture(fixture: TranscriptFixture, root: Path) -> bytes:
    facts = CHECKER.validate_transcript(fixture.data())
    attempt_one = {
        key: "0" for key in CHECKER.ATTEMPT_ONE_CHILD_KEYS
    }
    attempt_one.update(
        {
            "participant": "node",
            "identity": fixture.mission,
            "subscription_id": fixture.subscription,
            "subscription_inserted": "false",
            **CHECKER._delivery_child_expected(facts["_attempt_one"]),
            "delivery_limit": str(CHECKER.DELIVERY_LIMIT),
            "scan_limit": str(CHECKER.SCAN_LIMIT),
            "has_more": "true",
            "metadata_only": "true",
            "acknowledged": "false",
            "token_persisted": "true",
            "subscriptions": "1",
            "pending_deliveries": "1",
            "acknowledged_deliveries": "0",
            "delivery_cursors": "1",
            "selector_generation": "1",
        }
    )
    attempt_two = {key: "0" for key in CHECKER.ATTEMPT_TWO_CHILD_KEYS}
    attempt_two.update(
        {
            "participant": "node",
            "identity": fixture.mission,
            "subscription_id": fixture.subscription,
            "subscription_inserted": "false",
            **CHECKER._delivery_child_expected(facts["_retry"], "retry_"),
            "previous_token_sha256": fixture.token_one,
            "tokens_distinct": "true",
            "previous_token_restored": "true",
            "malformed_token_rejected": "true",
            "first_ack": "acknowledged",
            "first_reack": "already_acknowledged",
            "first_ack_token_attempt": "1",
            "first_reack_token_attempt": "2",
            **CHECKER._delivery_child_expected(facts["_matching_b"], "second_"),
            "same_blob_id": "true",
            "distinct_publications": "true",
            "wrong_publication_token_rejected": "true",
            "second_ack": "acknowledged",
            "second_reack": "already_acknowledged",
            "second_ack_token_attempt": "1",
            "second_reack_token_attempt": "1",
            "empty_poll": "true",
            "token_artifact_removed": "true",
            "subscriptions": "1",
            "pending_deliveries": "0",
            "acknowledged_deliveries": "2",
            "delivery_cursors": "2",
            "selector_generation": "1",
            "closed_kind": "state_unavailable",
            "closed_operation": "blob_delivery_status",
        }
    )
    receipt = receipt_values("peerless_redelivery")
    for key in CHECKER.RECEIPT_KEYS[2:]:
        attempt_two[f"shutdown_{key}"] = receipt[key]
    runtime = [
        terminal_record("READY", CHECKER.SUPPORT.READY_KEYS, ready_values(fixture, root, 101, 41001)),
        terminal_record("STOP", CHECKER.SUPPORT.STOP_KEYS, stop_values(fixture)),
        terminal_record("READY", CHECKER.SUPPORT.READY_KEYS, ready_values(fixture, root, 102, 41002)),
        child_record("ATTEMPT1_READY", CHECKER.ATTEMPT_ONE_CHILD_KEYS, attempt_one),
        terminal_record("READY", CHECKER.SUPPORT.READY_KEYS, ready_values(fixture, root, 103, 41003)),
        terminal_record("STOP", CHECKER.SUPPORT.STOP_KEYS, stop_values(fixture)),
        child_record("ATTEMPT2_DONE", CHECKER.ATTEMPT_TWO_CHILD_KEYS, attempt_two),
        terminal_record("READY", CHECKER.SUPPORT.READY_KEYS, ready_values(fixture, root, 101, 41001)),
        terminal_record("STOP", CHECKER.SUPPORT.STOP_KEYS, stop_values(fixture)),
    ]
    return ("\n".join(runtime) + "\n").encode("ascii") + fixture.data()


def authority() -> dict[str, object]:
    admitted = {
        path: {
            "path": path,
            "bytes": index + 1,
            "sha256": hashlib.sha256(path.encode("ascii")).hexdigest(),
        }
        for index, path in enumerate(CHECKER.ADMITTED_SOURCE_PATHS)
    }
    return {
        "commit": "a" * 40,
        "tree": "b" * 40,
        "signature": {"status": "verified", "fingerprint": "A" * 40},
        "admitted": admitted,
    }


def inventory_document(inventory: dict[str, object]) -> dict[str, object]:
    directories = inventory["directories"]
    files = inventory["files"]
    return {
        "directories": [
            {
                "path": relative or ".",
                "mode": stat.S_IMODE(directories[relative].st_mode),
                "owner": directories[relative].st_uid,
            }
            for relative in sorted(directories)
        ],
        "public": [
            {
                "path": relative,
                "bytes": files[relative].st_size,
                "mode": stat.S_IMODE(files[relative].st_mode),
                "hard_links": files[relative].st_nlink,
                "owner": files[relative].st_uid,
            }
            for relative in sorted(
                set(CHECKER.SUPPORT.EXPECTED_FILES)
                - set(CHECKER.SUPPORT.SECRET_FILES)
                - {"run.json"}
            )
        ],
        "participant_secret": [
            {
                "path": relative,
                "bytes": files[relative].st_size,
                "mode": stat.S_IMODE(files[relative].st_mode),
                "hard_links": files[relative].st_nlink,
                "owner": files[relative].st_uid,
            }
            for relative in sorted(CHECKER.SUPPORT.SECRET_FILES)
        ],
    }


def run_document(
    raw: RawRootFixture,
    inventory: dict[str, object],
    transcript: bytes,
    stdout: bytes,
) -> tuple[dict[str, object], dict[str, object], bytes]:
    source = authority()
    binary = b"release-binary"

    def artifact(path: str, data: bytes) -> dict[str, object]:
        return {
            "path": path,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    admitted = [source["admitted"][path] for path in CHECKER.ADMITTED_SOURCE_PATHS]
    document = {
        "schema": CHECKER.RAW_SCHEMA,
        "claim": CHECKER.CLAIM,
        "run_id": hashlib.sha256(transcript).hexdigest()[:16],
        "source": {
            "commit": source["commit"],
            "tree": source["tree"],
            "signature": source["signature"],
            "admitted": admitted,
        },
        "commands": {
            "build_argv": CHECKER.EXPECTED_BUILD_ARGV,
            "run_argv": [
                os.fspath(raw.root / "binary" / CHECKER.BINARY_NAME),
                os.fspath(raw.root),
            ],
        },
        "execution": {
            "exit_code": 0,
            "timeout_seconds": CHECKER.RUN_TIMEOUT_SECONDS,
            "worktree_clean_at_run": True,
            "source_binary_execution_link": "operator-attested-not-cryptographically-proven",
        },
        "artifacts": {
            "binary": artifact(f"binary/{CHECKER.BINARY_NAME}", binary),
            "stdout": artifact("stdout.log", stdout),
            "stderr": artifact("stderr.log", b""),
            "transcript": artifact("transcript.tsv", transcript),
        },
        "inventory": inventory_document(inventory),
        "tools": {
            role: source["admitted"][path]
            for role, path in CHECKER.TOOL_PATHS.items()
        },
    }
    return document, source, binary


class TranscriptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = TranscriptFixture()

    def rejected(self, data: bytes) -> None:
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.validate_transcript(data)

    def test_accepts_exact_contract(self) -> None:
        facts = CHECKER.validate_transcript(self.fixture.data())
        self.assertEqual(facts["records"], CHECKER.TRANSCRIPT_RECORDS)
        self.assertEqual(facts["unique_deliveries"], 2)

    def test_rejects_record_and_field_shape_mutations(self) -> None:
        original = self.fixture.data()
        lines = original.decode("ascii").splitlines()
        cases = {
            "missing": ("\n".join(lines[:-1]) + "\n").encode("ascii"),
            "duplicate": ("\n".join(lines + [lines[-1]]) + "\n").encode("ascii"),
            "reordered-record": (
                "\n".join(lines[:6] + [lines[7], lines[6]] + lines[8:]) + "\n"
            ).encode("ascii"),
            "reordered-field": (
                "\n".join(
                    ["\t".join(lines[0].split("\t")[:2] + list(reversed(lines[0].split("\t")[2:])))]
                    + lines[1:]
                )
                + "\n"
            ).encode("ascii"),
            "extra-field": (lines[0] + "\textra=true\n" + "\n".join(lines[1:]) + "\n").encode("ascii"),
            "carriage-return": original.replace(b"\n", b"\r\n", 1),
            "nul": original.replace(b"claim=", b"claim=\x00", 1),
            "uppercase-kind": original.replace(b"\trun\t", b"\tRUN\t", 1),
        }
        for label, data in cases.items():
            with self.subTest(label=label):
                self.rejected(data)

    def test_rejects_semantic_and_cross_binding_mutations(self) -> None:
        mutations = (
            (0, "claim", "overclaim"),
            (1, "mission_id", self.fixture.carrier),
            (3, "inserted", "false"),
            (5, "rejected", "false"),
            (7, "blob_id", identifier(100)),
            (7, "payload_sha256", identifier(101)),
            (7, "scope", CHECKER.DESCENDANT_SCOPE),
            (8, "pending_deliveries", 1),
            (9, "contacts", 1),
            (12, "publication_id", self.fixture.publication_b),
            (12, "has_more", "false"),
            (13, "pending_deliveries", 0),
            (14, "stop_record_observed", "true"),
            (17, "publication_id", identifier(102)),
            (17, "token_sha256", self.fixture.token_one),
            (18, "previous_token_restored", "false"),
            (19, "ack_token_attempt", 2),
            (20, "publication_id", self.fixture.publication_a),
            (21, "wrong_publication_token_rejected", "false"),
            (23, "deliveries", 1),
            (24, "acknowledged_deliveries", 1),
            (31, "blob_variants", 2),
            (32, "kind", "integrity"),
            (34, "network_contact_claimed", "true"),
            (34, "peer_status_claimed", "true"),
            (34, "selector_withholding_claimed", "true"),
            (34, "network_interest_separation_claimed", "true"),
            (34, "long_retention_claimed", "true"),
        )
        for index, key, value in mutations:
            with self.subTest(index=index, key=key):
                self.rejected(self.fixture.mutated(index, key, value))


class TerminalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = TranscriptFixture()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "raw"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate(self, stdout: bytes) -> dict[str, object]:
        transcript = self.fixture.data()
        return CHECKER.validate_terminal_stdout(
            stdout,
            transcript,
            self.root,
            CHECKER.validate_transcript(transcript),
        )

    def test_accepts_exact_runtime_lifetime_order(self) -> None:
        facts = self.validate(terminal_fixture(self.fixture, self.root))
        self.assertEqual(facts["ready_records"], 4)
        self.assertEqual(facts["stop_records"], 3)
        self.assertEqual(facts["contact_records"], 0)

    def test_rejects_runtime_order_and_child_binding_mutations(self) -> None:
        stdout = terminal_fixture(self.fixture, self.root)
        lines = stdout.decode("ascii").splitlines()
        cases = {
            "stop-after-kill": "\n".join(lines[:4] + [lines[1]] + lines[4:]) + "\n",
            "missing-stop": "\n".join(lines[:5] + lines[6:]) + "\n",
            "contact": "\n".join(["CONTACT x=y"] + lines) + "\n",
            "runtime-after-transcript": "\n".join(
                lines[:8] + lines[9:] + [lines[8]]
            ) + "\n",
            "wrong-prior-token": "\n".join(
                line.replace(
                    f"previous_token_sha256={self.fixture.token_one}",
                    f"previous_token_sha256={identifier(111)}",
                )
                for line in lines
            ) + "\n",
            "wrong-parent-pid": "\n".join(
                line.replace("pid=101", "pid=104") if index == 7 else line
                for index, line in enumerate(lines)
            ) + "\n",
            "network-stop-counter": "\n".join(
                line.replace("contacts=0", "contacts=1", 1)
                if line.startswith("STOP ") else line
                for line in lines
            ) + "\n",
            "wrong-sealed-source-bytes": "\n".join(
                line.replace(
                    f"blob_sealed_bytes={CHECKER.SEALED_SOURCE_BYTES}",
                    f"blob_sealed_bytes={CHECKER.PAYLOAD_BYTES}",
                    1,
                )
                if line.startswith("STOP ") else line
                for line in lines
            ) + "\n",
        }
        for label, value in cases.items():
            with self.subTest(label=label):
                with self.assertRaises(CHECKER.ReceiptViolation):
                    self.validate(value.encode("ascii"))


class InventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = RawRootFixture()

    def tearDown(self) -> None:
        self.raw.close()

    def rejected(self) -> None:
        with self.assertRaises(CHECKER.ReceiptViolation):
            self.raw.inventory()

    def test_accepts_exact_dynamic_single_variant_shape(self) -> None:
        inventory = self.raw.inventory()
        self.assertEqual(inventory["variants"], {"node": self.raw.variant})
        self.assertEqual(
            inventory["chunk_totals"]["node"], CHECKER.COMMITTED_CIPHERTEXT_BYTES
        )

    def test_rejects_missing_extra_noncanonical_and_wrong_size_entries(self) -> None:
        mutations = []

        def missing() -> None:
            self.raw.chunk.unlink()

        mutations.append(("missing", missing))

        def extra() -> None:
            path = self.raw.root / "unexpected"
            path.write_bytes(b"x")
            os.chmod(path, 0o600)

        mutations.append(("extra", extra))

        def size() -> None:
            self.raw.chunk.write_bytes(b"x")

        mutations.append(("size", size))

        def mode() -> None:
            os.chmod(self.raw.chunk, 0o644)

        mutations.append(("mode", mode))

        def owner_marker() -> None:
            (self.raw.root / "participants/node/state/blob-depot-v1/.aster-store-owner-v1").write_bytes(b"x")

        mutations.append(("owner-marker", owner_marker))

        def variant_name() -> None:
            source = self.raw.chunk.parent
            source.rename(source.parent / "not-a-canonical-variant")

        mutations.append(("variant-name", variant_name))

        for label, mutation in mutations:
            with self.subTest(label=label):
                self.raw.close()
                self.raw = RawRootFixture()
                mutation()
                self.rejected()

    def test_rejects_symlink_hardlink_and_second_variant(self) -> None:
        self.raw.chunk.unlink()
        self.raw.chunk.symlink_to(self.raw.root / "stdout.log")
        self.rejected()

        self.raw.close()
        self.raw = RawRootFixture()
        transcript = self.raw.root / "transcript.tsv"
        transcript.unlink()
        os.link(self.raw.root / "stdout.log", transcript)
        self.rejected()

        self.raw.close()
        self.raw = RawRootFixture()
        second = self.raw.root / "participants/node/state/blob-depot-v1" / identifier(91)
        second.mkdir(mode=0o700)
        path = second / CHECKER.CHUNK_FILE
        path.write_bytes(b"x" * CHECKER.COMMITTED_CIPHERTEXT_BYTES)
        os.chmod(path, 0o600)
        self.rejected()

    def test_inventory_never_opens_secret_or_ciphertext_files(self) -> None:
        original_open = os.open

        def guarded(path, *args, **kwargs):
            value = os.fspath(path)
            if value.endswith(("mission.bundle", "identity.key", "mesh.redb", ".chunk", ".aster-store-owner-v1")):
                raise AssertionError(f"secret/ciphertext opened: {value}")
            return original_open(path, *args, **kwargs)

        with mock.patch.object(os, "open", side_effect=guarded):
            self.raw.inventory()


class BindingAndProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = TranscriptFixture()
        self.raw = RawRootFixture()
        self.inventory = self.raw.inventory()
        self.transcript = self.fixture.data()
        self.stdout = terminal_fixture(self.fixture, self.raw.root)
        self.document, self.source, self.binary = run_document(
            self.raw, self.inventory, self.transcript, self.stdout
        )

    def tearDown(self) -> None:
        self.raw.close()

    def validate_run(self, document: dict[str, object]) -> dict[str, object]:
        return CHECKER.SUPPORT.validate_run_document(
            document,
            self.raw.root,
            self.inventory,
            self.source,
            self.binary,
            self.stdout,
            b"",
            self.transcript,
        )

    def test_accepts_exact_source_build_run_inventory_and_tool_binding(self) -> None:
        facts = self.validate_run(self.document)
        self.assertEqual(facts["build_argv"], CHECKER.EXPECTED_BUILD_ARGV)

    def test_rejects_source_build_run_artifact_inventory_and_tool_mutations(self) -> None:
        mutations = (
            ("source-tree", lambda d: d["source"].__setitem__("tree", "c" * 40)),
            ("build-argv", lambda d: d["commands"]["build_argv"].append("--quiet")),
            ("run-root", lambda d: d["commands"]["run_argv"].__setitem__(1, "/tmp/wrong")),
            ("timeout", lambda d: d["execution"].__setitem__("timeout_seconds", 1)),
            ("artifact", lambda d: d["artifacts"]["transcript"].__setitem__("sha256", identifier(120))),
            ("inventory", lambda d: d["inventory"]["participant_secret"][0].__setitem__("bytes", 0)),
            ("tool", lambda d: d["tools"]["checker"].__setitem__("sha256", identifier(121))),
        )
        for label, mutation in mutations:
            with self.subTest(label=label):
                value = copy.deepcopy(self.document)
                mutation(value)
                with self.assertRaises(CHECKER.ReceiptViolation):
                    self.validate_run(value)

    def test_projection_is_canonical_sanitized_and_preserves_nonclaims(self) -> None:
        transcript_facts = CHECKER.validate_transcript(self.transcript)
        terminal_facts = CHECKER.validate_terminal_stdout(
            self.stdout, self.transcript, self.raw.root, transcript_facts
        )
        run_facts = self.validate_run(self.document)
        evidence = {
            "run": run_facts,
            "transcript": transcript_facts,
            "terminal": terminal_facts,
            "retention": {
                "root_mode": "0700",
                "directories": 7,
                "files": 10,
                "participant_directories": 1,
                "mission_artifacts": 1,
                "identity_keys": 1,
                "mesh_databases": 1,
                "depot_owner_markers": 1,
                "blob_variants": 1,
                "ciphertext_chunks": 1,
                "ciphertext_bytes": CHECKER.COMMITTED_CIPHERTEXT_BYTES,
                "secret_and_ciphertext_contents": "metadata-only-not-opened-read-or-hashed",
                "file_links": "all-one",
                "inventory_aliases": "none",
            },
        }
        projected = CHECKER.build_receipt(self.source, evidence)
        self.assertEqual(projected["limitations"], CHECKER.LIMITATIONS)
        self.assertEqual(projected["nonclaims"], CHECKER.NONCLAIMS)
        encoded = CHECKER.render_receipt(
            projected,
            forbidden_values=terminal_facts["_sensitive_values"],
        )
        self.assertEqual(encoded, CHECKER.canonical_json_bytes(json.loads(encoded)))
        for value in (
            self.fixture.subscription,
            self.fixture.publication_a,
            self.fixture.token_one,
        ):
            self.assertNotIn(value.encode("ascii"), encoded)
        self.assertIn(b'"status_scope":"local-ledger-only"', encoded)
        self.assertIn(b'"network-contact-transfer-synchronization-convergence-or-peer-status"', encoded)

    def test_loaded_support_digest_mismatch_is_rejected(self) -> None:
        signed = copy.deepcopy(self.source)
        signed["admitted"][CHECKER.CHECKER_SUPPORT_PATH]["sha256"] = identifier(122)
        with self.assertRaises(CHECKER.ReceiptViolation):
            CHECKER.validate_loaded_support(signed)


if __name__ == "__main__":
    unittest.main()
