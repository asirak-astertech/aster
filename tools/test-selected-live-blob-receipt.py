#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Independent-oracle adversarial tests for the selected live Blob receipt."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


TEST_TEMP_PARENT = os.path.realpath(tempfile.gettempdir())


CHECKER_PATH = Path(__file__).with_name("check-selected-live-blob-receipt.py")
SPEC = importlib.util.spec_from_file_location("selected_live_blob_receipt", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)

ORACLE_RECEIPT_SCHEMA = "aster-selected-live-blob-receipt/v1"
ORACLE_RAW_SCHEMA = "aster-selected-live-blob-raw/v1"
ORACLE_TRANSCRIPT_SCHEMA = "aster-selected-live-blob-transcript/v1"
ORACLE_CLAIM = (
    "selected-live-blob-one-host-direct-iroh-peerless-publish-transfer-read-"
    "restart-acceptance"
)
ORACLE_BUILD_ARGV = (
    "cargo",
    "build",
    "--release",
    "--locked",
    "-p",
    "aster-node",
    "--example",
    "live_blob_acceptance",
)
ORACLE_ADMITTED_PATHS = tuple(
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
            "crates/aster-node/examples/live_blob_acceptance.rs",
            "tools/check-selected-live-blob-receipt.py",
            "tools/run-selected-live-blob.py",
            "tools/test-selected-live-blob-receipt.py",
        )
    )
)
ORACLE_LIMITATIONS = (
    "operator-attested-source-binary-execution-link-not-cryptographically-proven",
    "selected-admitted-source-list-is-not-a-complete-reproducible-build-closure",
    "one-host-loopback-same-implementation-observation",
    "participant-secret-and-ciphertext-artifacts-validated-by-metadata-only",
    "restart-is-graceful-same-process-actor-store-and-provider-reopen",
    "transcript-timing-and-source-removal-order-are-producer-attested",
)
ORACLE_NONCLAIMS = (
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
)

ORACLE_PAYLOAD_LEN = 65_747
ORACLE_PAGE_LIMIT = 65_536
ORACLE_PAYLOAD_SHA256 = (
    "52d2759ceaccc2ac63ab528f40edbe80ddd3abda8f4b5d894fb034881fcda9cf"
)
ORACLE_CHANGED_PAYLOAD_SHA256 = (
    "b3da9883cd3819a8e6fe834e65e0f65bcfc3903f2da14bd28eb2a42c2680619c"
)
ORACLE_SCHEMA_ID_SHA256 = (
    "2a538df7b419268fda25ef2f0e358db63a764ee3b55db19e0a4ef00c8a942be2"
)
ORACLE_MEDIA_TYPE = "application/x-aster-live-blob-acceptance"
ORACLE_PAGE_FACTS = (
    (
        0,
        0,
        65_536,
        65_536,
        "false",
        "1047ab624c89856e2a3c2dea5cea7a299c2d0ba0a9bcbf1cb951a6d54927239a",
    ),
    (
        1,
        65_536,
        211,
        65_747,
        "true",
        "2740c403e3254a595863ffffbb94bfb26d5cedaa94566c57c6683ba61bf672a7",
    ),
)
ORACLE_CHUNK_SIZES = (65_705, 380)
ORACLE_CHUNK_TOTAL = sum(ORACLE_CHUNK_SIZES)
ORACLE_TRANSFER_BYTES = ORACLE_PAYLOAD_LEN + 32

ORACLE_RUN_KEYS = (
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
ORACLE_PARTICIPANT_KEYS = (
    "participant",
    "carrier_id",
    "mission_id",
    "mission_authority",
    "expected_carrier_peer",
    "expected_mission_peer",
)
ORACLE_HANDLE_KEYS = (
    "phase",
    "participant",
    "blob_identity",
    "blob_authority",
)
ORACLE_PUBLICATION_KEYS = (
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
ORACLE_RETRY_KEYS = (
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
ORACLE_CONFLICT_KEYS = (
    "phase",
    "participant",
    "original_id",
    "original_payload_sha256",
    "changed_payload_sha256",
    "error_kind",
    "operation",
    "publication_preserved",
)
ORACLE_PAGE_KEYS = (
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
ORACLE_READ_KEYS = (
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
ORACLE_SHUTDOWN_KEYS = (
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
ORACLE_CLOSED_HANDLE_KEYS = ("phase", "participant", "error_kind", "operation")
ORACLE_SOURCE_REMOVED_KEYS = (
    "participant",
    "status",
    "bytes",
    "sha256",
)
ORACLE_BIND_KEYS = ("participant", "status")
ORACLE_RESULT_KEYS = (
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
ORACLE_EXPECTED_SEQUENCE = (
    ("RUN", ORACLE_RUN_KEYS),
    ("PARTICIPANT", ORACLE_PARTICIPANT_KEYS),
    ("PARTICIPANT", ORACLE_PARTICIPANT_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("BLOB_PUBLICATION", ORACLE_PUBLICATION_KEYS),
    ("BLOB_RETRY", ORACLE_RETRY_KEYS),
    ("BLOB_CONFLICT", ORACLE_CONFLICT_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("READ", ORACLE_READ_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("SOURCE_REMOVED", ORACLE_SOURCE_REMOVED_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("READ", ORACLE_READ_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("HANDLE", ORACLE_HANDLE_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("PAGE", ORACLE_PAGE_KEYS),
    ("READ", ORACLE_READ_KEYS),
    ("SHUTDOWN", ORACLE_SHUTDOWN_KEYS),
    ("CLOSED_HANDLE", ORACLE_CLOSED_HANDLE_KEYS),
    ("BIND_REACQUIRED", ORACLE_BIND_KEYS),
    ("BIND_REACQUIRED", ORACLE_BIND_KEYS),
    ("RESULT", ORACLE_RESULT_KEYS),
)

ORACLE_READY_KEYS = (
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
ORACLE_CONTACT_KEYS = (
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
ORACLE_STOP_KEYS = (
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


def identifier(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def tsv(record_type: str, keys: tuple[str, ...], values: dict[str, str]) -> str:
    if set(values) != set(keys):
        raise AssertionError(f"fixture {record_type} keys differ")
    return "\t".join(
        ["LIVE_BLOB", record_type, *(f"{key}={values[key]}" for key in keys)]
    )


def terminal(prefix: str, keys: tuple[str, ...], values: dict[str, str]) -> str:
    if set(values) != set(keys):
        raise AssertionError(f"fixture {prefix} keys differ")
    return " ".join([prefix, *(f"{key}={values[key]}" for key in keys)])


class Fixture:
    def __init__(self, parent: Path) -> None:
        self.parent = parent
        self.parent.chmod(0o700)
        self.root = parent / "raw"
        self.root.mkdir(mode=0o700)
        self.carriers = {
            "publisher": identifier("carrier-publisher"),
            "receiver": identifier("carrier-receiver"),
        }
        self.missions = {
            "publisher": identifier("mission-publisher"),
            "receiver": identifier("mission-receiver"),
        }
        self.authority = identifier("mission-authority")
        self.blob_id = identifier("selected-blob")
        self.variant_id = identifier("selected-blob-variant")
        self.binary = b"\x7fELFsynthetic-live-blob-release\n"
        self.secret = b"S" * 96
        self.contact_pairs = 1
        self.source = {
            "commit": "1" * 40,
            "tree": "2" * 40,
            "signature": {"status": "good", "fingerprint": "A" * 40},
            "admitted": {
                path: {
                    "bytes": len(f"synthetic:{path}\n".encode("ascii")),
                    "sha256": hashlib.sha256(
                        f"synthetic:{path}\n".encode("ascii")
                    ).hexdigest(),
                }
                for path in ORACLE_ADMITTED_PATHS
            },
        }
        self._create_inventory()
        self.transcript_lines = self._transcript_lines()
        self.runtime_lines = self._runtime_lines()
        self.run_document: dict[str, object] = {}
        self.refresh_public()

    def _mkdir(self, relative: str) -> None:
        path = self.root / relative
        path.mkdir(mode=0o700)
        path.chmod(0o700)

    def _write(self, relative: str, data: bytes, mode: int) -> None:
        path = self.root / relative
        path.write_bytes(data)
        path.chmod(mode)

    def _create_inventory(self) -> None:
        directories = ["binary", "participants"]
        for participant in ("publisher", "receiver"):
            directories.extend(
                (
                    f"participants/{participant}",
                    f"participants/{participant}/state",
                    f"participants/{participant}/state/blob-depot-v1",
                    (
                        f"participants/{participant}/state/blob-depot-v1/"
                        f"{self.variant_id}"
                    ),
                )
            )
        for relative in directories:
            self._mkdir(relative)
        self._write("binary/aster-live-blob-acceptance", self.binary, 0o700)
        for participant in ("publisher", "receiver"):
            prefix = f"participants/{participant}"
            self._write(f"{prefix}/mission.bundle", b"M" * 128, 0o600)
            self._write(f"{prefix}/state/identity.key", self.secret, 0o600)
            self._write(f"{prefix}/state/mesh.redb", b"R" * 256, 0o600)
            depot = f"{prefix}/state/blob-depot-v1"
            self._write(f"{depot}/.aster-store-owner-v1", b"O" * 72, 0o600)
            for index, size in enumerate(ORACLE_CHUNK_SIZES):
                self._write(
                    f"{depot}/{self.variant_id}/{index:020}.chunk",
                    bytes([0xC0 + index]) * size,
                    0o600,
                )

    def participant(self, participant: str) -> dict[str, str]:
        other = "receiver" if participant == "publisher" else "publisher"
        return {
            "participant": participant,
            "carrier_id": self.carriers[participant],
            "mission_id": self.missions[participant],
            "mission_authority": self.authority,
            "expected_carrier_peer": self.carriers[other],
            "expected_mission_peer": self.missions[other],
        }

    def metadata(self) -> dict[str, str]:
        return {
            "id": self.blob_id,
            "publisher": self.missions["publisher"],
            "counter": "1",
            "priority": "priority",
            "total_len": str(ORACLE_PAYLOAD_LEN),
            "media_type": ORACLE_MEDIA_TYPE,
            "schema_id_sha256": ORACLE_SCHEMA_ID_SHA256,
            "acceptance_marker": "1",
        }

    def page(
        self, phase: str, participant: str, page_index: int
    ) -> dict[str, str]:
        index, offset, length, next_offset, complete, page_hash = ORACLE_PAGE_FACTS[
            page_index
        ]
        return {
            "phase": phase,
            "participant": participant,
            "page_index": str(index),
            **self.metadata(),
            "offset": str(offset),
            "max_bytes": str(ORACLE_PAGE_LIMIT),
            "page_len": str(length),
            "next_offset": str(next_offset),
            "complete": complete,
            "page_sha256": page_hash,
        }

    def read(self, phase: str, participant: str) -> dict[str, str]:
        return {
            "phase": phase,
            "participant": participant,
            **self.metadata(),
            "pages": "2",
            "max_page_bytes": str(ORACLE_PAGE_LIMIT),
            "payload_sha256": ORACLE_PAYLOAD_SHA256,
        }

    def shutdown(self, phase: str, participant: str) -> dict[str, str]:
        values = {key: "0" for key in ORACLE_SHUTDOWN_KEYS}
        connected = phase == "connected_transfer"
        values.update(
            {
                "phase": phase,
                "participant": participant,
                "contacts": str(self.contact_pairs) if connected else "0",
                "direct_contacts": str(self.contact_pairs) if connected else "0",
                "blobs": "1",
                "blob_acceptance_markers": "1",
                "blob_last_acceptance_marker": "1",
                "blob_sealed_bytes": "512",
                "blob_operations": "1" if participant == "publisher" else "0",
                "blob_operation_bytes": "256" if participant == "publisher" else "0",
                "blob_variants": "1",
                "blob_finalized_variants": "1",
                "blob_committed_chunks": "2",
                "blob_committed_file_bytes": str(ORACLE_CHUNK_TOTAL),
                "blob_reserved_file_bytes": str(ORACLE_CHUNK_TOTAL),
            }
        )
        if connected and participant == "receiver":
            values.update(
                {
                    "blob_ranges_fetched": str(2 * self.contact_pairs),
                    "blob_bytes_fetched": str(
                        ORACLE_TRANSFER_BYTES * self.contact_pairs
                    ),
                    # This is a per-contact observation, not the visibility proof.
                    "blob_remaining": str(self.contact_pairs),
                }
            )
        return values

    def _transcript_lines(self) -> list[str]:
        records = [
            tsv(
                "RUN",
                ORACLE_RUN_KEYS,
                {
                    "schema": ORACLE_TRANSCRIPT_SCHEMA,
                    "claim": ORACLE_CLAIM,
                    "participants": "2",
                    "actor_lifetimes": "4",
                    "maximum_concurrent_actors": "2",
                    "topic": "opaque",
                    "scope": "test/runtime-contact",
                    "payload_len": str(ORACLE_PAYLOAD_LEN),
                    "payload_sha256": ORACLE_PAYLOAD_SHA256,
                    "page_limit": str(ORACLE_PAGE_LIMIT),
                    "expected_pages": "2",
                },
            ),
            tsv(
                "PARTICIPANT",
                ORACLE_PARTICIPANT_KEYS,
                self.participant("publisher"),
            ),
            tsv(
                "PARTICIPANT",
                ORACLE_PARTICIPANT_KEYS,
                self.participant("receiver"),
            ),
            tsv(
                "HANDLE",
                ORACLE_HANDLE_KEYS,
                {
                    "phase": "peerless_source",
                    "participant": "publisher",
                    "blob_identity": self.missions["publisher"],
                    "blob_authority": self.authority,
                },
            ),
            tsv(
                "BLOB_PUBLICATION",
                ORACLE_PUBLICATION_KEYS,
                {
                    "phase": "peerless_source",
                    "participant": "publisher",
                    **self.metadata(),
                    "inserted": "true",
                    "payload_sha256": ORACLE_PAYLOAD_SHA256,
                },
            ),
            tsv(
                "BLOB_RETRY",
                ORACLE_RETRY_KEYS,
                {
                    "phase": "peerless_source",
                    "participant": "publisher",
                    "original_id": self.blob_id,
                    "retry_id": self.blob_id,
                    **{key: value for key, value in self.metadata().items() if key != "id"},
                    "inserted": "false",
                    "exact_match": "true",
                },
            ),
            tsv(
                "BLOB_CONFLICT",
                ORACLE_CONFLICT_KEYS,
                {
                    "phase": "peerless_source",
                    "participant": "publisher",
                    "original_id": self.blob_id,
                    "original_payload_sha256": ORACLE_PAYLOAD_SHA256,
                    "changed_payload_sha256": ORACLE_CHANGED_PAYLOAD_SHA256,
                    "error_kind": "conflict",
                    "operation": "blob_publish",
                    "publication_preserved": "true",
                },
            ),
            tsv("PAGE", ORACLE_PAGE_KEYS, self.page("peerless_source", "publisher", 0)),
            tsv("PAGE", ORACLE_PAGE_KEYS, self.page("peerless_source", "publisher", 1)),
            tsv("READ", ORACLE_READ_KEYS, self.read("peerless_source", "publisher")),
            tsv(
                "SHUTDOWN",
                ORACLE_SHUTDOWN_KEYS,
                self.shutdown("peerless_source", "publisher"),
            ),
            tsv(
                "CLOSED_HANDLE",
                ORACLE_CLOSED_HANDLE_KEYS,
                {
                    "phase": "peerless_source",
                    "participant": "publisher",
                    "error_kind": "state_unavailable",
                    "operation": "blob_read_page",
                },
            ),
            tsv(
                "SOURCE_REMOVED",
                ORACLE_SOURCE_REMOVED_KEYS,
                {
                    "participant": "publisher",
                    "status": "removed-and-parent-synced",
                    "bytes": str(ORACLE_PAYLOAD_LEN),
                    "sha256": ORACLE_PAYLOAD_SHA256,
                },
            ),
            tsv(
                "HANDLE",
                ORACLE_HANDLE_KEYS,
                {
                    "phase": "connected_transfer",
                    "participant": "publisher",
                    "blob_identity": self.missions["publisher"],
                    "blob_authority": self.authority,
                },
            ),
            tsv(
                "HANDLE",
                ORACLE_HANDLE_KEYS,
                {
                    "phase": "connected_transfer",
                    "participant": "receiver",
                    "blob_identity": self.missions["receiver"],
                    "blob_authority": self.authority,
                },
            ),
            tsv(
                "PAGE",
                ORACLE_PAGE_KEYS,
                self.page("connected_receiver", "receiver", 0),
            ),
            tsv(
                "PAGE",
                ORACLE_PAGE_KEYS,
                self.page("connected_receiver", "receiver", 1),
            ),
            tsv(
                "READ",
                ORACLE_READ_KEYS,
                self.read("connected_receiver", "receiver"),
            ),
            tsv(
                "SHUTDOWN",
                ORACLE_SHUTDOWN_KEYS,
                self.shutdown("connected_transfer", "publisher"),
            ),
            tsv(
                "SHUTDOWN",
                ORACLE_SHUTDOWN_KEYS,
                self.shutdown("connected_transfer", "receiver"),
            ),
            tsv(
                "CLOSED_HANDLE",
                ORACLE_CLOSED_HANDLE_KEYS,
                {
                    "phase": "connected_transfer",
                    "participant": "publisher",
                    "error_kind": "state_unavailable",
                    "operation": "blob_read_page",
                },
            ),
            tsv(
                "CLOSED_HANDLE",
                ORACLE_CLOSED_HANDLE_KEYS,
                {
                    "phase": "connected_transfer",
                    "participant": "receiver",
                    "error_kind": "state_unavailable",
                    "operation": "blob_read_page",
                },
            ),
            tsv(
                "HANDLE",
                ORACLE_HANDLE_KEYS,
                {
                    "phase": "restart_receiver",
                    "participant": "receiver",
                    "blob_identity": self.missions["receiver"],
                    "blob_authority": self.authority,
                },
            ),
            tsv("PAGE", ORACLE_PAGE_KEYS, self.page("restart_receiver", "receiver", 0)),
            tsv("PAGE", ORACLE_PAGE_KEYS, self.page("restart_receiver", "receiver", 1)),
            tsv("READ", ORACLE_READ_KEYS, self.read("restart_receiver", "receiver")),
            tsv(
                "SHUTDOWN",
                ORACLE_SHUTDOWN_KEYS,
                self.shutdown("restart_receiver", "receiver"),
            ),
            tsv(
                "CLOSED_HANDLE",
                ORACLE_CLOSED_HANDLE_KEYS,
                {
                    "phase": "restart_receiver",
                    "participant": "receiver",
                    "error_kind": "state_unavailable",
                    "operation": "blob_read_page",
                },
            ),
            tsv(
                "BIND_REACQUIRED",
                ORACLE_BIND_KEYS,
                {"participant": "publisher", "status": "reacquired"},
            ),
            tsv(
                "BIND_REACQUIRED",
                ORACLE_BIND_KEYS,
                {"participant": "receiver", "status": "reacquired"},
            ),
            tsv(
                "RESULT",
                ORACLE_RESULT_KEYS,
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
            ),
        ]
        if len(records) != 31:
            raise AssertionError("fixture transcript record count differs")
        return records

    def ready(self, participant: str, phase: str, port: int) -> str:
        return terminal(
            "READY",
            ORACLE_READY_KEYS,
            {
                "selected": "true",
                "pid": "4242",
                "carrier_id": self.carriers[participant],
                "mission_id": self.missions[participant],
                "mission_authority": self.authority,
                "sockets": f"127.0.0.1:{port}",
                "state": CHECKER.encoded_path(
                    self.root / "participants" / participant / "state"
                ),
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
        )

    def contact(self, local: str, remote: str, pair_index: int) -> str:
        numeric = {
            key: "0"
            for key in ORACLE_CONTACT_KEYS[3:26] + ORACLE_CONTACT_KEYS[27:28]
        }
        numeric.update(
            {
                "rounds": "1",
                "handshake_frames": "2",
                "handshake_bytes": "128",
                "protected_frames": "2",
                "protected_bytes": "128",
            }
        )
        if local == "publisher":
            numeric["offered"] = "2" if pair_index == 0 else "1"
        else:
            numeric.update(
                {
                    "fetched": "1" if pair_index == 0 else "0",
                    "inserted": "1" if pair_index == 0 else "0",
                    "mutable_remaining": "1",
                    "blob_ranges_fetched": "2",
                    "blob_bytes_fetched": str(ORACLE_TRANSFER_BYTES),
                    "blob_remaining": "1",
                }
            )
        direction = (
            "out" if self.carriers[local] < self.carriers[remote] else "in"
        )
        return terminal(
            "CONTACT",
            ORACLE_CONTACT_KEYS,
            {
                "direction": direction,
                "carrier_peer": self.carriers[remote],
                "mission_peer": self.missions[remote],
                **numeric,
                "carrier_path": "direct",
                "carrier_path_transitions_saturated": "false",
                "path_observation": "not-authorization",
                "mission_auth": "hybrid-pq",
                "semantics": "source-authenticated-event",
                "reconciliation_classes": "event,state,record,blob",
                "controls": "source-authenticated-flash",
                "content_admission": "capability-gated",
                "status": "partial" if local == "receiver" else "pass",
            },
        )

    def stop(self, participant: str, phase: str) -> str:
        shutdown = self.shutdown(phase, participant)
        return terminal(
            "STOP",
            ORACLE_STOP_KEYS,
            {
                "lifecycle": "complete",
                "sync_status": (
                    "contacts_observed"
                    if phase == "connected_transfer"
                    else "no_successful_contact"
                ),
                "carrier_id": self.carriers[participant],
                "mission_id": self.missions[participant],
                "contacts": shutdown["contacts"],
                "contact_errors": shutdown["contact_errors"],
                "direct_contacts": shutdown["direct_contacts"],
                "relay_contacts": shutdown["relay_contacts"],
                "unknown_path_contacts": shutdown["unknown_path_contacts"],
                "carrier_path_transitions": shutdown["carrier_path_transitions"],
                "carrier_path_transition_saturations": shutdown[
                    "carrier_path_transition_saturations"
                ],
                "path_observation": "not-authorization",
                "opaque_items": shutdown["items"],
                "opaque_acceptance_markers": shutdown["acceptance_markers"],
                "events": shutdown["events"],
                "event_acceptance_markers": shutdown["event_acceptance_markers"],
                "route_cached_events": shutdown["route_cached_events"],
                "controls": shutdown["controls"],
                "applied_controls": shutdown["applied_controls"],
                "pending_controls": shutdown["pending_controls"],
                "control_highwater": shutdown["control_highwater"],
                "blobs": shutdown["blobs"],
                "blob_acceptance_markers": shutdown["blob_acceptance_markers"],
                "blob_last_acceptance_marker": shutdown[
                    "blob_last_acceptance_marker"
                ],
                "blob_sealed_bytes": shutdown["blob_sealed_bytes"],
                "blob_operations": shutdown["blob_operations"],
                "blob_operation_bytes": shutdown["blob_operation_bytes"],
                "blob_variants": shutdown["blob_variants"],
                "blob_finalized_variants": shutdown["blob_finalized_variants"],
                "blob_committed_chunks": shutdown["blob_committed_chunks"],
                "blob_committed_file_bytes": shutdown[
                    "blob_committed_file_bytes"
                ],
                "blob_reserved_file_bytes": shutdown[
                    "blob_reserved_file_bytes"
                ],
                "pending_blobs": shutdown["pending_blobs"],
                "blob_carrier_prefixes": shutdown["blob_carrier_prefixes"],
                "blob_carrier_fetch_cursors": shutdown[
                    "blob_carrier_fetch_cursors"
                ],
                "blob_network_staging_bytes": shutdown[
                    "blob_network_staging_bytes"
                ],
                "blob_ranges_fetched": shutdown["blob_ranges_fetched"],
                "blob_bytes_fetched": shutdown["blob_bytes_fetched"],
                "blob_remaining": shutdown["blob_remaining"],
                "blob_deferred": shutdown["blob_deferred"],
                "mission_auth": "hybrid-pq",
                "provisioning": "unprotected-reference",
                "semantics": "source-authenticated-event",
                "reconciliation_classes": "event,state,record,blob-v5",
                "controls_semantics": "source-authenticated-flash",
            },
        )

    def _runtime_lines(self) -> list[str]:
        prefix = [
            self.ready("publisher", "peerless_source", 40000),
            self.stop("publisher", "peerless_source"),
            self.ready("publisher", "connected_transfer", 40010),
            self.ready("receiver", "connected_transfer", 40011),
        ]
        contacts = [
            record
            for pair_index in range(self.contact_pairs)
            for record in (
                self.contact("publisher", "receiver", pair_index),
                self.contact("receiver", "publisher", pair_index),
            )
        ]
        suffix = [
            self.stop("publisher", "connected_transfer"),
            self.stop("receiver", "connected_transfer"),
            self.ready("receiver", "restart_receiver", 40020),
            self.stop("receiver", "restart_receiver"),
        ]
        return [*prefix, *contacts, *suffix]

    def set_contact_pairs(self, pairs: int) -> None:
        if pairs <= 0:
            raise AssertionError("fixture requires positive paired contacts")
        self.contact_pairs = pairs
        self.transcript_lines = self._transcript_lines()
        self.runtime_lines = self._runtime_lines()
        self.refresh_public()

    @staticmethod
    def _artifact(relative: str, data: bytes) -> dict[str, object]:
        return {
            "path": relative,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    def refresh_public(self) -> None:
        transcript = ("\n".join(self.transcript_lines) + "\n").encode("ascii")
        stdout = (
            "\n".join([*self.runtime_lines, *self.transcript_lines]) + "\n"
        ).encode("ascii")
        self._write("transcript.tsv", transcript, 0o600)
        self._write("stdout.log", stdout, 0o600)
        self._write("stderr.log", b"", 0o600)
        admitted = [
            {"path": path, **self.source["admitted"][path]}
            for path in ORACLE_ADMITTED_PATHS
        ]
        tools = {
            role: {"path": path, **self.source["admitted"][path]}
            for role, path in {
                "producer": "crates/aster-node/examples/live_blob_acceptance.rs",
                "runner": "tools/run-selected-live-blob.py",
                "checker": "tools/check-selected-live-blob-receipt.py",
                "test": "tools/test-selected-live-blob-receipt.py",
            }.items()
        }
        self.run_document = {
            "schema": ORACLE_RAW_SCHEMA,
            "claim": ORACLE_CLAIM,
            "run_id": hashlib.sha256(transcript).hexdigest()[:16],
            "source": {
                "commit": self.source["commit"],
                "tree": self.source["tree"],
                "signature": dict(self.source["signature"]),
                "admitted": admitted,
            },
            "commands": {
                "build_argv": list(ORACLE_BUILD_ARGV),
                "run_argv": [
                    os.fspath(
                        self.root / "binary" / "aster-live-blob-acceptance"
                    ),
                    os.fspath(self.root),
                ],
            },
            "execution": {
                "exit_code": 0,
                "worktree_clean_at_run": True,
                "source_binary_execution_link": (
                    "operator-attested-not-cryptographically-proven"
                ),
            },
            "artifacts": {
                "binary": self._artifact(
                    "binary/aster-live-blob-acceptance", self.binary
                ),
                "stdout": self._artifact("stdout.log", stdout),
                "stderr": self._artifact("stderr.log", b""),
                "transcript": self._artifact("transcript.tsv", transcript),
            },
            "tools": tools,
        }
        self.write_run_document()

    def write_run_document(self) -> None:
        self._write(
            "run.json", CHECKER.canonical_json_bytes(self.run_document), 0o600
        )

    def mutate_transcript(self, index: int, key: str, value: str) -> None:
        parts = self.transcript_lines[index].split("\t")
        for position in range(2, len(parts)):
            if parts[position].startswith(f"{key}="):
                parts[position] = f"{key}={value}"
                break
        else:
            raise AssertionError(f"missing fixture field {key}")
        self.transcript_lines[index] = "\t".join(parts)
        self.refresh_public()

    def mutate_runtime(self, index: int, key: str, value: str) -> None:
        parts = self.runtime_lines[index].split(" ")
        for position in range(1, len(parts)):
            field, separator, _old = parts[position].partition("=")
            if separator and field == key:
                parts[position] = f"{field}={value}"
                self.runtime_lines[index] = " ".join(parts)
                self.refresh_public()
                return
        raise AssertionError(f"missing runtime fixture field {key}")

    def evidence(self) -> dict[str, object]:
        return CHECKER.validate_raw_root(self.root, self.source)

    def receipt_document(self) -> tuple[dict[str, object], dict[str, object]]:
        evidence = self.evidence()
        return CHECKER.build_receipt(self.source, evidence), evidence

    def receipt(self) -> bytes:
        document, evidence = self.receipt_document()
        return CHECKER.render_receipt(
            document,
            forbidden_values=CHECKER.receipt_forbidden_values(evidence, self.root),
            forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
            forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
        )


class SelectedLiveBlobReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT)
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def assert_rejected(self, pattern: str) -> None:
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, pattern):
            self.fixture.receipt()

    def test_independent_contract_oracles_match_checker(self) -> None:
        self.assertEqual(CHECKER.SCHEMA, ORACLE_RECEIPT_SCHEMA)
        self.assertEqual(CHECKER.RAW_SCHEMA, ORACLE_RAW_SCHEMA)
        self.assertEqual(CHECKER.TRANSCRIPT_SCHEMA, ORACLE_TRANSCRIPT_SCHEMA)
        self.assertEqual(CHECKER.CLAIM, ORACLE_CLAIM)
        self.assertEqual(tuple(CHECKER.EXPECTED_BUILD_ARGV), ORACLE_BUILD_ARGV)
        self.assertEqual(CHECKER.ADMITTED_SOURCE_PATHS, ORACLE_ADMITTED_PATHS)
        self.assertEqual(tuple(CHECKER.EXPECTED_SEQUENCE), ORACLE_EXPECTED_SEQUENCE)
        self.assertEqual(CHECKER.READY_KEYS, ORACLE_READY_KEYS)
        self.assertEqual(CHECKER.CONTACT_KEYS, ORACLE_CONTACT_KEYS)
        self.assertEqual(CHECKER.STOP_KEYS, ORACLE_STOP_KEYS)
        self.assertEqual(CHECKER.PAYLOAD_LEN, ORACLE_PAYLOAD_LEN)
        self.assertEqual(CHECKER.PAGE_LIMIT, ORACLE_PAGE_LIMIT)
        self.assertEqual(CHECKER.PAYLOAD_SHA256, ORACLE_PAYLOAD_SHA256)
        self.assertEqual(CHECKER.PAGE_FACTS, ORACLE_PAGE_FACTS)
        self.assertEqual(tuple(CHECKER.LIMITATIONS), ORACLE_LIMITATIONS)
        self.assertEqual(tuple(CHECKER.NONCLAIMS), ORACLE_NONCLAIMS)

    def test_valid_projection_is_deterministic_bounded_and_sanitized(self) -> None:
        first = self.fixture.receipt()
        second = self.fixture.receipt()
        self.assertEqual(first, second)
        self.assertLessEqual(len(first), 16 * 1024)
        parsed = json.loads(first)
        self.assertEqual(parsed["schema"], ORACLE_RECEIPT_SCHEMA)
        self.assertEqual(parsed["claim"], ORACLE_CLAIM)
        self.assertEqual(parsed["status"], "pass")
        self.assertEqual(parsed["retention"]["identity_keys"], 2)
        self.assertEqual(parsed["retention"]["mesh_databases"], 2)
        self.assertNotIn("identity_databases", parsed["retention"])
        self.assertNotIn("mission_databases", parsed["retention"])
        self.assertEqual(
            parsed["acceptance"]["connected_reconciliation"][
                "terminal_event_state_record_control_counts"
            ],
            "all-zero",
        )
        self.assertNotIn(
            "event_state_record_controls",
            parsed["acceptance"]["connected_reconciliation"],
        )
        self.assertEqual(tuple(parsed["limitations"]), ORACLE_LIMITATIONS)
        self.assertEqual(tuple(parsed["nonclaims"]), ORACLE_NONCLAIMS)
        for forbidden in (
            os.fsencode(self.fixture.root),
            self.fixture.carriers["publisher"].encode("ascii"),
            self.fixture.missions["receiver"].encode("ascii"),
            self.fixture.blob_id.encode("ascii"),
            self.fixture.variant_id.encode("ascii"),
            b"127.0.0.1",
            b"4242",
            self.fixture.secret,
        ):
            self.assertNotIn(forbidden, first)

    def test_supplied_receipt_replay_is_byte_exact(self) -> None:
        receipt = self.fixture.receipt()
        CHECKER.validate_supplied_receipt(receipt, receipt)
        supplied = self.fixture.parent / "supplied.json"
        supplied.write_bytes(receipt)
        for mode in (0o600, 0o644):
            supplied.chmod(mode)
            self.assertEqual(CHECKER.read_supplied_receipt(supplied), receipt)
        mutated = json.loads(receipt)
        mutated["status"] = "fail"
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "byte-for-byte"):
            CHECKER.validate_supplied_receipt(
                CHECKER.canonical_json_bytes(mutated), receipt
            )

    def test_every_record_type_and_key_order_is_exact(self) -> None:
        for index, ((record_type, keys), line) in enumerate(
            zip(ORACLE_EXPECTED_SEQUENCE, self.fixture.transcript_lines, strict=True)
        ):
            with self.subTest(index=index, record_type=record_type):
                parsed = CHECKER.parse_record(line, record_type, keys, index)
                self.assertEqual(tuple(parsed), keys)
                parts = line.split("\t")
                parts[2], parts[3] = parts[3], parts[2]
                with self.assertRaisesRegex(
                    CHECKER.ReceiptViolation, "reordered fields"
                ):
                    CHECKER.parse_record(
                        "\t".join(parts), record_type, keys, index
                    )
                wrong = line.replace(
                    f"LIVE_BLOB\t{record_type}\t",
                    f"LIVE_BLOB\tWRONG_{index}\t",
                    1,
                )
                with self.assertRaisesRegex(
                    CHECKER.ReceiptViolation, "unexpected type"
                ):
                    CHECKER.parse_record(wrong, record_type, keys, index)

    def test_transcript_record_order_and_count_fail_closed(self) -> None:
        self.fixture.transcript_lines[1], self.fixture.transcript_lines[2] = (
            self.fixture.transcript_lines[2],
            self.fixture.transcript_lines[1],
        )
        self.fixture.refresh_public()
        self.assert_rejected("PARTICIPANT publisher")

    def test_page_gap_and_overlap_fail_closed(self) -> None:
        for offset in ("65535", "65537"):
            with self.subTest(offset=offset):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
                    fixture = Fixture(Path(temporary))
                    fixture.mutate_transcript(8, "offset", offset)
                    with self.assertRaisesRegex(
                        CHECKER.ReceiptViolation,
                        "PAGE peerless_source publisher 1",
                    ):
                        fixture.receipt()

    def test_page_size_completion_and_hash_fail_closed(self) -> None:
        cases = (
            (7, "page_len", "65535"),
            (7, "max_bytes", "65535"),
            (7, "complete", "true"),
            (8, "next_offset", "65746"),
            (8, "page_sha256", "0" * 64),
        )
        for index, key, value in cases:
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
                    fixture = Fixture(Path(temporary))
                    fixture.mutate_transcript(index, key, value)
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        fixture.receipt()

    def test_page_metadata_and_whole_read_must_match_publication(self) -> None:
        self.fixture.mutate_transcript(15, "media_type", "application/octet-stream")
        self.assert_rejected("PAGE connected_receiver")

    def test_whole_read_hash_and_page_count_are_exact(self) -> None:
        self.fixture.mutate_transcript(25, "pages", "3")
        self.assert_rejected("READ restart_receiver")

    def test_retry_is_exact_noninserting_and_identity_preserving(self) -> None:
        self.fixture.mutate_transcript(5, "retry_id", identifier("other-blob"))
        self.assert_rejected("BLOB_RETRY")

    def test_conflict_preserves_the_original_publication(self) -> None:
        self.fixture.mutate_transcript(6, "publication_preserved", "false")
        self.assert_rejected("BLOB_CONFLICT")

    def test_source_removal_is_exact_and_directory_synced(self) -> None:
        self.fixture.mutate_transcript(12, "status", "removed")
        self.assert_rejected("SOURCE_REMOVED")

    def test_source_removal_hash_and_size_are_bound(self) -> None:
        self.fixture.mutate_transcript(12, "sha256", "0" * 64)
        self.assert_rejected("SOURCE_REMOVED")

    def test_runtime_ready_identity_and_state_path_are_cross_bound(self) -> None:
        self.fixture.mutate_runtime(
            0, "mission_id", identifier("wrong-ready-mission")
        )
        self.assert_rejected("does not bind one transcript participant")

    def test_runtime_ready_path_mismatch_fails_closed(self) -> None:
        self.fixture.mutate_runtime(2, "state", "/private/tmp/wrong")
        self.assert_rejected("state")

    def test_global_runtime_phase_barriers_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
            fixture = Fixture(Path(temporary))
            receiver_connected = fixture.runtime_lines.pop(3)
            fixture.runtime_lines.insert(1, receiver_connected)
            fixture.refresh_public()
            with self.assertRaisesRegex(
                CHECKER.ReceiptViolation,
                "connected transfer before the peerless publisher stopped",
            ):
                fixture.receipt()

        with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
            fixture = Fixture(Path(temporary))
            publisher_stop, receiver_stop, restart_ready = fixture.runtime_lines[6:9]
            fixture.runtime_lines[6:9] = [
                receiver_stop,
                restart_ready,
                publisher_stop,
            ]
            fixture.refresh_public()
            with self.assertRaisesRegex(
                CHECKER.ReceiptViolation,
                "restart before both connected actors stopped",
            ):
                fixture.receipt()

    def test_runtime_contact_identity_path_and_direction_are_exact(self) -> None:
        self.fixture.mutate_runtime(4, "carrier_path", "relay")
        self.assert_rejected("carrier_path")

    def test_runtime_contact_blob_reconciliation_accounting_is_exact(self) -> None:
        self.fixture.mutate_runtime(4, "offered", "0")
        self.assert_rejected("publisher Blob reconciliation accounting")

    def test_runtime_contact_stop_counter_mismatch_fails_closed(self) -> None:
        self.fixture.mutate_runtime(7, "blob_ranges_fetched", "1")
        self.assert_rejected("CONTACT|STOP|range")

    def test_runtime_stop_identity_mismatch_fails_closed(self) -> None:
        self.fixture.mutate_runtime(6, "carrier_id", identifier("wrong-stop-carrier"))
        self.assert_rejected("does not bind one transcript participant")

    def test_variable_direct_contact_lines_aggregate_exactly(self) -> None:
        self.fixture.set_contact_pairs(2)
        receipt = json.loads(self.fixture.receipt())
        self.assertEqual(receipt["run"]["stdout"]["contact_records"], 4)

    def test_receiver_transfer_is_positive_and_publisher_transfer_is_zero(self) -> None:
        self.fixture.mutate_runtime(4, "blob_ranges_fetched", "1")
        self.assert_rejected("publisher|Blob")

    def test_final_blob_rows_pending_prefix_and_staging_are_exact(self) -> None:
        cases = (
            ("blobs", "0"),
            ("pending_blobs", "1"),
            ("blob_carrier_prefixes", "1"),
            ("blob_network_staging_bytes", "1"),
        )
        for field, value in cases:
            with self.subTest(field=field):
                with tempfile.TemporaryDirectory(dir=TEST_TEMP_PARENT) as temporary:
                    fixture = Fixture(Path(temporary))
                    fixture.mutate_transcript(19, field, value)
                    with self.assertRaises(CHECKER.ReceiptViolation):
                        fixture.receipt()

    def test_connected_remaining_is_not_used_as_completion_proof(self) -> None:
        # The fixture deliberately retains blob_remaining=1 at the receiver's
        # connected STOP while proving visibility with exact durable rows/pages.
        receipt = self.fixture.receipt()
        self.assertNotIn(b'"blob_remaining"', receipt)

    def test_restart_shutdown_is_peerless_and_durable(self) -> None:
        self.fixture.mutate_transcript(26, "blob_ranges_fetched", "1")
        self.assert_rejected("restart_receiver")

    def test_closure_and_bind_reacquisition_counts_are_exact(self) -> None:
        self.fixture.mutate_transcript(30, "closed_handles", "3")
        self.assert_rejected("RESULT")

    def test_bind_reacquisition_status_is_exact(self) -> None:
        self.fixture.mutate_transcript(29, "status", "failed")
        self.assert_rejected("BIND_REACQUIRED")

    def test_closed_handle_operation_is_exact(self) -> None:
        self.fixture.mutate_transcript(27, "operation", "blob_publish")
        self.assert_rejected("CLOSED_HANDLE")

    def test_source_signature_tree_and_admitted_records_are_bound(self) -> None:
        self.fixture.run_document["source"]["tree"] = "3" * 40
        self.fixture.write_run_document()
        self.assert_rejected("source.tree")

    def test_source_signer_fingerprint_is_bound(self) -> None:
        self.fixture.run_document["source"]["signature"]["fingerprint"] = "B" * 40
        self.fixture.write_run_document()
        self.assert_rejected("signature.fingerprint")

    def test_admitted_source_hash_is_bound(self) -> None:
        self.fixture.run_document["source"]["admitted"][0]["sha256"] = "0" * 64
        self.fixture.write_run_document()
        self.assert_rejected("admitted")

    def test_tool_record_must_equal_the_admitted_source_record(self) -> None:
        self.fixture.run_document["tools"]["checker"]["sha256"] = "0" * 64
        self.fixture.write_run_document()
        self.assert_rejected("tools.checker")

    def test_binary_and_artifact_hashes_are_bound(self) -> None:
        self.fixture.run_document["artifacts"]["binary"]["sha256"] = "0" * 64
        self.fixture.write_run_document()
        self.assert_rejected("artifacts.binary.sha256")

    def test_copied_binary_content_tamper_is_detected(self) -> None:
        binary = self.fixture.root / "binary/aster-live-blob-acceptance"
        binary.write_bytes(self.fixture.binary + b"tamper")
        binary.chmod(0o700)
        self.assert_rejected("artifacts.binary")

    def test_build_and_run_argv_are_exact(self) -> None:
        self.fixture.run_document["commands"]["build_argv"][0] = "rustc"
        self.fixture.write_run_document()
        self.assert_rejected("release build invocation")

    def test_stdout_artifact_tamper_is_detected(self) -> None:
        self.fixture.run_document["artifacts"]["stdout"]["bytes"] += 1
        self.fixture.write_run_document()
        self.assert_rejected("artifacts.stdout.bytes")

    def test_run_document_must_be_compact_canonical_json(self) -> None:
        path = self.fixture.root / "run.json"
        document = json.loads(path.read_bytes())
        path.write_text(json.dumps(document, indent=2) + "\n", encoding="ascii")
        path.chmod(0o600)
        self.assert_rejected("compact canonical JSON")

    def test_duplicate_run_json_field_fails_closed(self) -> None:
        path = self.fixture.root / "run.json"
        data = path.read_bytes()
        path.write_bytes(
            data.replace(b'{"artifacts":', b'{"schema":"duplicate","artifacts":', 1)
        )
        path.chmod(0o600)
        self.assert_rejected("duplicate JSON field")

    def test_inventory_mode_and_extra_entry_fail_closed(self) -> None:
        chunk = (
            self.fixture.root
            / "participants/publisher/state/blob-depot-v1"
            / self.fixture.variant_id
            / "00000000000000000000.chunk"
        )
        chunk.chmod(0o644)
        self.assert_rejected("unexpected mode")

    def test_inventory_symlink_and_unsafe_type_fail_closed(self) -> None:
        transcript = self.fixture.root / "transcript.tsv"
        transcript.unlink()
        os.symlink(self.fixture.root / "stdout.log", transcript)
        self.assert_rejected("unsafe type|missing or extra")

    def test_inventory_hardlink_alias_fails_closed(self) -> None:
        first = (
            self.fixture.root
            / "participants/publisher/state/blob-depot-v1"
            / self.fixture.variant_id
            / "00000000000000000000.chunk"
        )
        second = (
            self.fixture.root
            / "participants/receiver/state/blob-depot-v1"
            / self.fixture.variant_id
            / "00000000000000000000.chunk"
        )
        second.unlink()
        os.link(first, second)
        self.assert_rejected("hard-link|aliased")

    def test_inventory_extra_file_fails_closed(self) -> None:
        extra = self.fixture.root / "unexpected"
        extra.write_bytes(b"unexpected\n")
        extra.chmod(0o600)
        self.assert_rejected("unexpected file")

    def test_ciphertext_chunk_size_bounds_are_metadata_only(self) -> None:
        chunk = (
            self.fixture.root
            / "participants/receiver/state/blob-depot-v1"
            / self.fixture.variant_id
            / "00000000000000000001.chunk"
        )
        chunk.write_bytes(b"C" * 211)
        chunk.chmod(0o600)
        self.assert_rejected("ciphertext chunk 1")

    def test_secret_and_ciphertext_contents_do_not_affect_projection(self) -> None:
        first = self.fixture.receipt()
        private_files = [
            self.fixture.root / "participants/publisher/mission.bundle",
            self.fixture.root / "participants/receiver/state/identity.key",
            self.fixture.root / "participants/publisher/state/mesh.redb",
            (
                self.fixture.root
                / "participants/receiver/state/blob-depot-v1"
                / ".aster-store-owner-v1"
            ),
            (
                self.fixture.root
                / "participants/publisher/state/blob-depot-v1"
                / self.fixture.variant_id
                / "00000000000000000000.chunk"
            ),
        ]
        for index, path in enumerate(private_files, start=1):
            path.write_bytes(bytes([index]) * path.stat().st_size)
            path.chmod(0o600)
        second = self.fixture.receipt()
        self.assertEqual(first, second)

    def test_secret_and_ciphertext_files_are_never_opened(self) -> None:
        original_open = os.open
        private_names = {
            "mission.bundle",
            "identity.key",
            "mesh.redb",
            ".aster-store-owner-v1",
            "00000000000000000000.chunk",
            "00000000000000000001.chunk",
        }

        def guarded_open(path, flags, mode=0o777, *, dir_fd=None):
            if os.path.basename(os.fsdecode(path)) in private_names:
                raise AssertionError(f"private artifact was opened: {path}")
            if dir_fd is None:
                return original_open(path, flags, mode)
            return original_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(CHECKER.os, "open", side_effect=guarded_open):
            self.fixture.receipt()

    def test_identifier_path_port_pid_and_payload_leakage_fail_closed(self) -> None:
        document, evidence = self.fixture.receipt_document()
        forbidden_values = CHECKER.receipt_forbidden_values(
            evidence, self.fixture.root
        )
        for value, pattern in (
            (self.fixture.blob_id, "parsed identifier"),
            (os.fspath(self.fixture.root), "path"),
            (4242, "process identifier"),
            (40010, "network port"),
        ):
            with self.subTest(value=value):
                mutated = dict(document)
                mutated["status"] = value
                with self.assertRaisesRegex(CHECKER.ReceiptViolation, pattern):
                    CHECKER.render_receipt(
                        mutated,
                        forbidden_values=forbidden_values,
                        forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
                        forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
                    )
        payload = "synthetic-plaintext-payload"
        mutated = dict(document)
        mutated["status"] = payload
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "parsed identifier"):
            CHECKER.render_receipt(
                mutated,
                forbidden_values=[*forbidden_values, payload],
                forbidden_pids=CHECKER.receipt_forbidden_pids(evidence),
                forbidden_ports=CHECKER.receipt_forbidden_ports(evidence),
            )

    def test_receipt_output_is_exclusive_and_collision_safe(self) -> None:
        output = self.fixture.parent / CHECKER.RECEIPT_NAME
        output.write_bytes(b"preexisting\n")
        output.chmod(0o600)
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "already exists"):
            CHECKER.write_receipt(output, self.fixture.receipt())
        self.assertEqual(output.read_bytes(), b"preexisting\n")
        with self.assertRaisesRegex(CHECKER.ReceiptViolation, "exact filename"):
            CHECKER.write_receipt(
                self.fixture.parent / "wrong.json", self.fixture.receipt()
            )

    def test_receipt_output_mode_is_exact_under_hostile_umask(self) -> None:
        output = self.fixture.parent / CHECKER.RECEIPT_NAME
        prior_umask = os.umask(0o777)
        try:
            CHECKER.write_receipt(output, self.fixture.receipt())
        finally:
            os.umask(prior_umask)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

    def test_cli_failure_is_generic_while_internal_detail_remains_available(self) -> None:
        chunk = (
            self.fixture.root
            / "participants/publisher/state/blob-depot-v1"
            / self.fixture.variant_id
            / "00000000000000000000.chunk"
        )
        chunk.chmod(0o644)
        with self.assertRaises(CHECKER.ReceiptViolation) as raised:
            self.fixture.receipt()
        internal_detail = str(raised.exception)
        self.assertIn(self.fixture.variant_id, internal_detail)
        self.assertIn("participants/publisher/state/blob-depot-v1", internal_detail)
        chunk.chmod(0o600)

        private_detail = (
            f"{internal_detail}; raw={self.fixture.root}; "
            "sentinel=private-diagnostic-detail"
        )
        stderr = io.StringIO()
        with (
            mock.patch.object(
                CHECKER, "validate_source", return_value=self.fixture.source
            ),
            mock.patch.object(
                CHECKER,
                "validate_raw_root",
                side_effect=CHECKER.ReceiptViolation(private_detail),
            ),
            mock.patch.object(CHECKER.sys, "stderr", stderr),
            self.assertRaises(SystemExit) as exited,
        ):
            CHECKER.main(
                [
                    "--raw-root",
                    os.fspath(self.fixture.root),
                    "--source",
                    os.fspath(self.fixture.parent / "source"),
                ]
            )
        self.assertEqual(exited.exception.code, 1)
        self.assertEqual(
            stderr.getvalue(), "selected live Blob receipt validation failed\n"
        )
        self.assertNotIn(self.fixture.variant_id, stderr.getvalue())
        self.assertNotIn(os.fspath(self.fixture.root), stderr.getvalue())
        self.assertNotIn("private-diagnostic-detail", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
