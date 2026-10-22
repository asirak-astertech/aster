#!/usr/bin/env python3
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the semantic protocol-version contract."""

from __future__ import annotations

import importlib.util
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest


CHECKER_PATH = Path(__file__).with_name("check-protocol-version-contract.py")
SPEC = importlib.util.spec_from_file_location("protocol_version_contract", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)
ORACLE_PATH = CHECKER_PATH.parents[1] / "conformance/blob_stream_oracle.py"
ORACLE_SPEC = importlib.util.spec_from_file_location("blob_stream_oracle", ORACLE_PATH)
if ORACLE_SPEC is None or ORACLE_SPEC.loader is None:
    raise RuntimeError(f"cannot load {ORACLE_PATH}")
ORACLE = importlib.util.module_from_spec(ORACLE_SPEC)
ORACLE_SPEC.loader.exec_module(ORACLE)


DOCUMENTATION_CAPABILITIES = {
    "node_api": {
        "schema": 1,
        "surface": "node_api",
        "semantic_v7_v8_profile": "4:BlobRangesStreamV1",
        "semantic_v9_profile": "5:BlobStreamV1",
        "map_unit": "65536-byte canonical plaintext chunk",
        "record": "ASTRBT01, at most 66215 bytes",
        "extent": "ABX1, at most 1048576 bytes",
    },
    "transports": {
        "schema": 1,
        "surface": "transports",
        "semantic_v7_v8_profile": "4:BlobRangesStreamV1",
        "semantic_v9_profile": "5:BlobStreamV1",
        "map_unit": "65536-byte canonical plaintext chunk",
        "record": "ASTRBT01, at most 66215 bytes",
        "extent": "ABX1, at most 1048576 bytes",
    },
    "recipes": {
        "schema": 1,
        "surface": "recipes",
        "semantic_v7_v8_profile": "4:BlobRangesStreamV1",
        "semantic_v9_profile": "5:BlobStreamV1",
        "map_unit": "65536-byte canonical plaintext chunk",
        "record": "ASTRBT01, at most 66215 bytes",
        "extent": "ABX1, at most 1048576 bytes",
    },
    "runbook": {
        "schema": 1,
        "surface": "runbook",
        "settlement_order": [
            "authenticated_finish_and_content_verification",
            "canonical_apply_promotion",
            "result",
            "ack",
            "receipt_cleanup",
        ],
        "available_before_settlement_cleanup": True,
        "receipt_key": ["receiving_mission_authority", "canonical_source"],
        "receipt_persists_attempt_nonce": False,
        "sender_hard_deadline_basis": "exact_canonical_wire_length",
        "receiver_initial_hard_deadline_basis": "profile_wire_ceiling_before_authenticated_open",
        "authenticated_progress_timeout_seconds": 120,
        "plaintext_chunk_bytes": 65_536,
        "encoded_record_max_bytes": 66_215,
        "extent_max_bytes": 1_048_576,
        "checkpoint_batch_max_bytes": 134_217_728,
        "pre_profile5_canonical_blob_profile5_eligible": True,
        "capacity_authority": "configured_blob_depot_limits",
    },
    "public_api": {
        "schema": 1,
        "surface": "public_api",
        "local_publish_waits_for_peer": False,
        "rust_agent_asterctl_publish_read": "implemented",
        "blob_status_scope": "receiver_local_durable_state",
        "blob_status_reports_remote_delivery_peer_or_convergence": False,
        "cli_download_resume": "post_merge",
    },
    "performance": {
        "schema": 1,
        "surface": "performance",
        "legacy_2026_10_20_format": "ASTRBS02_1MiB_semantic_segments",
        "legacy_2026_10_20_supports_current_candidate": False,
        "current_map_unit": "65536-byte canonical plaintext chunk",
        "current_record": "ASTRBT01",
        "current_extent": "ABX1, at most 1048576 bytes",
        "current_cm4_qualification": "pending_task_13",
    },
}


def capability_block(surface: str, *, value=None) -> str:
    payload = DOCUMENTATION_CAPABILITIES[surface] if value is None else value
    return (
        "<!-- ASTER-BLOB-CAPABILITY:BEGIN -->\n"
        "```json\n"
        f"{json.dumps(payload, indent=2)}\n"
        "```\n"
        "<!-- ASTER-BLOB-CAPABILITY:END -->\n"
    )


def core_contract() -> str:
    constants = "\n".join(
        f"pub(crate) const SEMANTIC_PROTOCOL_V{version}: u16 = {version};"
        for version in range(1, 10)
    )
    offered = ",\n    ".join(
        f"SEMANTIC_PROTOCOL_V{version}" for version in range(9, 0, -1)
    )
    return f"""{constants}
pub(crate) const SUPPORTED_SEMANTIC_PROTOCOL_VERSIONS: &[u16] = &[
    {offered},
];
"""


def protocol_contract() -> str:
    return """The default and highest-supported semantic-version surfaces report `9`.
The default semantic offer is `[9, 8, 7, 6, 5, 4, 3, 2, 1]`.
The default descending offer is `[9, 8, 7, 6, 5, 4, 3, 2, 1]`.
The default initiator offers semantic versions `[9, 8, 7, 6, 5, 4, 3, 2, 1]`.
The current handshake negotiates semantic versions `9`, `8`, `7`, `6`, `5`, `4`, `3`, `2`, and `1` and the complete suite `0x0001`.

| Semantic version | Inherits | Additional mechanics |
| --- | --- | --- |
| `1` | — | stable Event and Blob-chunk transfer |
| `2` | v1 | compact batch and bridge objects |
| `3` | v2 | session custody record |
| `4` | v3 | State and Record reconciliation |
| `5` | v4 | historical direct Blob frame allocation |
| `6` | v5 ordinary lanes byte-for-byte | Event bridge transfer |
| `7` | v6 byte-for-byte | per-lane profiles, receipt-free Event pages, and durable Blob range streams |
| `8` | v7 byte-for-byte except the lane AAD domain and Blob custody fields | authenticated finite Blob custody over `BlobRangesStreamV1` |
| `9` | v8 fixed lanes byte-for-byte except the Blob transfer profile and Blob chunk kind | independently authenticated Blob streams over `BlobStreamV1` |

Blob profile registry: semantic v7/v8 select profile 4; semantic v9 selects profile 5.
Profile 4 limits: 67,108,864 object bytes; 1,024 canonical chunks; 1,048,576 authenticated-source bytes.
Profile 5 limits: 8,589,934,592 object bytes; 131,072 canonical chunks; 16,777,216 authenticated-source bytes.
Profile 5 size classes: 65,536 plaintext chunk bytes; 66,215 encrypted carrier bytes; 1,048,576 ABX1 extent bytes; 134,217,728 checkpoint bytes; 2,097,152 Iroh frame bytes.
Profile 5 order: PLAN -> OPEN -> SOURCE -> ACCEPT -> ABX1 DATA -> CHECKPOINT -> FINISH -> RESULT -> ACK.
Profile 5 exact empty transfer: OPEN -> SOURCE -> ACCEPT -> FINISH(final_offset=0) -> RESULT -> ACK, with no DATA or CHECKPOINT.
"""


def envelope_contract() -> str:
    return """- Negotiated semantic versions: default/highest `9`, compatibility `8`, `7`, `6`, `5`, `4`, `3`, `2`, and `1`
The default semantic-version list is `[9, 8, 7, 6, 5, 4, 3, 2, 1]`.
selected_semantic_version       u16 = 1, 2, 3, 4, 5, 6, 7, 8, or 9
"""


def cddl_contract() -> str:
    return """semantic-v1-object-kind = 1 / 2
semantic-v2-object-kind = semantic-v1-object-kind / 3 / 4 / 5
semantic-v3-object-kind = semantic-v2-object-kind
semantic-v4-object-kind = semantic-v3-object-kind
semantic-v5-object-kind = semantic-v4-object-kind
semantic-v6-object-kind = semantic-v5-object-kind
semantic-v7-object-kind = semantic-v6-object-kind
semantic-v8-object-kind = semantic-v7-object-kind
semantic-v9-object-kind = 1 / 3 / 4 / 5

; stream-profile-v5 is fixed binary, not deterministic CBOR.
stream-profile-v5 = stream-open-v1 / stream-source-v1 / stream-accept-v1 / stream-data-v1 / stream-checkpoint-v1 / stream-finish-v1 / stream-result-v1 / stream-result-ack-v1
stream-data-v1 = "ASM\\x01\\xd8" attempt-tuple offset-u64 extent-len-u32 abx1-extent
abx1-extent = "ABX1" first-chunk-index-u64 carrier-count-u32 1*(carrier-len-u32 canonical-carrier)
"""


class ProtocolVersionContractTests(unittest.TestCase):
    def validate(
        self,
        *,
        core: str | None = None,
        protocol: str | None = None,
        envelope: str | None = None,
        cddl: str | None = None,
    ) -> None:
        CHECKER.validate_contract_texts(
            core if core is not None else core_contract(),
            protocol if protocol is not None else protocol_contract(),
            envelope if envelope is not None else envelope_contract(),
            cddl if cddl is not None else cddl_contract(),
        )

    def test_blob_documentation_contract_is_structured_and_single_authority(self) -> None:
        documents = {
            surface: capability_block(surface) for surface in DOCUMENTATION_CAPABILITIES
        }
        CHECKER.validate_blob_documentation_contract(documents)

        duplicate = dict(documents)
        duplicate["node_api"] += capability_block("node_api")
        with self.assertRaisesRegex(
            CHECKER.ContractViolation, "node_api.*exactly one structured capability block"
        ):
            CHECKER.validate_blob_documentation_contract(duplicate)

        competing = dict(documents)
        competing["transports"] += capability_block("node_api")
        with self.assertRaisesRegex(
            CHECKER.ContractViolation,
            "transports.*exactly one structured capability block",
        ):
            CHECKER.validate_blob_documentation_contract(competing)

        malformed = dict(documents)
        malformed["runbook"] = malformed["runbook"].replace(
            '"authenticated_progress_timeout_seconds": 120',
            '"authenticated_progress_timeout_seconds": "two minutes"',
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "runbook.*fields"):
            CHECKER.validate_blob_documentation_contract(malformed)

        extra_field = dict(documents)
        extra_payload = dict(DOCUMENTATION_CAPABILITIES["performance"])
        extra_payload["current_throughput_mib_s"] = 99
        extra_field["performance"] = capability_block(
            "performance", value=extra_payload
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "performance.*fields"):
            CHECKER.validate_blob_documentation_contract(extra_field)

        missing_field = dict(documents)
        missing_payload = dict(DOCUMENTATION_CAPABILITIES["public_api"])
        del missing_payload["cli_download_resume"]
        missing_field["public_api"] = capability_block(
            "public_api", value=missing_payload
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "public_api.*fields"):
            CHECKER.validate_blob_documentation_contract(missing_field)

        malformed_json = dict(documents)
        malformed_json["recipes"] = malformed_json["recipes"].replace(
            '"schema": 1', '"schema":', 1
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "recipes.*JSON"):
            CHECKER.validate_blob_documentation_contract(malformed_json)

        contradictions = (
            (
                "node_api",
                "node_api contradiction",
                "Each 1 MiB segment carries its own authentication tag.",
            ),
            (
                "transports",
                "transports contradiction",
                "Each segment of 1 MiB is authenticated on its own.",
            ),
            (
                "recipes",
                "recipes contradiction",
                "Profile 5 separately authenticates every 1 MiB segment.",
            ),
            (
                "runbook",
                "receiver settlement contradiction",
                "RESULT and ACK complete prior to canonical promotion.",
            ),
            (
                "runbook",
                "receipt attempt contradiction",
                "The durable receipt retains the fresh attempt nonce.",
            ),
            (
                "runbook",
                "receiver timeout contradiction",
                "For incoming transfers, the exact content length determines the absolute deadline.",
            ),
            (
                "performance",
                "legacy performance contradiction",
                "Legacy CM4 measurements confirm the current ABX1 batching policy.",
            ),
        )
        for surface, label, contradiction in contradictions:
            damaged = dict(documents)
            damaged[surface] += contradiction
            with self.subTest(contradiction=label), self.assertRaisesRegex(
                CHECKER.ContractViolation, label
            ):
                CHECKER.validate_blob_documentation_contract(damaged)

        valid_distinctions = dict(documents)
        valid_distinctions["node_api"] += (
            "A 1 MiB segment is independently encrypted, while every 64 KiB "
            "chunk is authenticated."
        )
        valid_distinctions["runbook"] += (
            "Canonical promotion happens before RESULT and ACK, rather than "
            "after RESULT and ACK. The durable receipt stores plan data, not "
            "the fresh attempt nonce."
        )
        valid_distinctions["performance"] += (
            "Legacy CM4 results support the historical ASTRBS02 candidate, "
            "not the current ABX1 candidate."
        )
        CHECKER.validate_blob_documentation_contract(valid_distinctions)

    def test_blob_documentation_contract_rejects_each_capability_drift(self) -> None:
        documents = {
            "runbook": """Blob profile negotiation: semantic v7/v8 select profile 4; semantic v9 selects profile 5.
Profile 5 size terms: 65,536-byte canonical plaintext chunk; 66,215-byte maximum encoded canonical chunk record; 1,048,576-byte maximum ABX1 batched extent.
Profile 5 checkpoint maximum: 134,217,728 bytes (128 MiB).
Canonical legacy eligibility: every pre-profile-5 canonical Blob remains eligible for profile 5 after upgrade.
Unified capacity: provisional uploads, pending network receipts, and completed canonical variants share the configured Blob depot limits.
""",
            "public_api": """Current Blob API capability: the Rust API, native-gRPC agent, and asterctl support bounded local publication and authenticated reads.
Status boundary: local publication success is a durable local commit; blob-status is receiver-local durable state, not remote delivery, peer status, or convergence status.
Download resume: post-merge work; interrupted asterctl downloads currently restart at byte zero.
""",
            "node_api": """Semantic v9 selects profile 5 BlobStreamV1; semantic v7/v8 retain compatibility profile 4 BlobRangesStreamV1.
Profile 5 batches canonical 64-KiB plaintext chunks as complete ASTRBT01 records in ABX1 extents of at most 1 MiB.
""",
            "transports": """Semantic v9 selects profile 5 BlobStreamV1; semantic v7/v8 retain compatibility profile 4 BlobRangesStreamV1.
Profile 5 batches canonical 64-KiB plaintext chunks as complete ASTRBT01 records in ABX1 extents of at most 1 MiB.
""",
            "recipes": """Semantic v9 selects profile 5 BlobStreamV1; semantic v7/v8 retain compatibility profile 4 BlobRangesStreamV1.
Profile 5 batches canonical 64-KiB plaintext chunks as complete ASTRBT01 records in ABX1 extents of at most 1 MiB.
""",
            "performance": """Legacy 2026-10-20 ASTRBS02 completed-pack evidence used 1-MiB semantic segments and does not validate the current canonical-authority candidate.
Current qualification must measure 64-KiB canonical plaintext chunks carried as ASTRBT01 records in at-most-1-MiB ABX1 extents.
""",
        }
        documents = {
            surface: capability_block(surface) + text
            for surface, text in documents.items()
        }
        CHECKER.validate_blob_documentation_contract(documents)

        coexistence_mutations = (
            (
                "node_api",
                "node_api contradiction",
                "Profile 5 uses independently authenticated 1-MiB segments.",
            ),
            (
                "transports",
                "transports contradiction",
                "Profile 5 uses independently authenticated 1-MiB segments.",
            ),
            (
                "recipes",
                "recipes contradiction",
                "Profile 5 uses independently authenticated 1-MiB segments.",
            ),
            (
                "runbook",
                "receiver settlement contradiction",
                "The receiver sends RESULT and receives ACK before canonical promotion.",
            ),
            (
                "runbook",
                "receipt attempt contradiction",
                "The durable receipt persists the fresh attempt nonce.",
            ),
            (
                "runbook",
                "receiver timeout contradiction",
                "The receiver derives its hard deadline from exact content bytes after OPEN.",
            ),
            (
                "performance",
                "legacy performance contradiction",
                "The legacy 2026-10-20 CM4 result validates the current ABX1 batching policy.",
            ),
        )
        for surface, label, contradiction in coexistence_mutations:
            damaged = dict(documents)
            damaged[surface] += contradiction
            with self.subTest(coexistence=label), self.assertRaisesRegex(
                CHECKER.ContractViolation, label
            ):
                CHECKER.validate_blob_documentation_contract(damaged)

        paraphrase_mutations = (
            (
                "node_api",
                "node_api contradiction",
                "Each 1-MiB segment is independently authenticated.",
            ),
            (
                "transports",
                "transports contradiction",
                "Profile 5 authenticates each 1 MiB segment independently.",
            ),
            (
                "recipes",
                "recipes contradiction",
                "Profile 5 consists of independent, authenticated 1-MiB segments.",
            ),
            (
                "runbook",
                "receiver settlement contradiction",
                "Canonical promotion follows RESULT and ACK.",
            ),
            (
                "runbook",
                "receipt attempt contradiction",
                "The durable receipt stores the fresh attempt nonce.",
            ),
            (
                "runbook",
                "receiver timeout contradiction",
                "Incoming transfers calculate their hard deadline from exact content bytes after OPEN.",
            ),
            (
                "performance",
                "legacy performance contradiction",
                "These legacy CM4 measurements prove the retained ABX1 batching policy for the current candidate.",
            ),
        )
        for surface, label, contradiction in paraphrase_mutations:
            damaged = dict(documents)
            damaged[surface] += contradiction
            with self.subTest(paraphrase=label), self.assertRaisesRegex(
                CHECKER.ContractViolation, label
            ):
                CHECKER.validate_blob_documentation_contract(damaged)

        allowed = dict(documents)
        allowed["node_api"] += (
            "Profile 5 does not use independently authenticated 1-MiB segments."
        )
        allowed["runbook"] += (
            "Canonical promotion does not follow RESULT and ACK. "
            "The durable receipt stores plan data but does not store the fresh "
            "attempt nonce. Incoming transfers do not calculate their hard "
            "deadline from exact content bytes."
        )
        allowed["performance"] += (
            "The legacy CM4 measurements validate only the historical ASTRBS02 "
            "candidate and do not validate the current ABX1 candidate."
        )
        CHECKER.validate_blob_documentation_contract(allowed)

    def test_v1_through_v9_contract_passes(self) -> None:
        self.validate()

    def test_each_missing_implementation_version_fails(self) -> None:
        for version in range(1, 10):
            with self.subTest(version=version):
                damaged = core_contract().replace(
                    f"pub(crate) const SEMANTIC_PROTOCOL_V{version}: u16 = {version};\n",
                    "",
                )
                with self.assertRaisesRegex(
                    CHECKER.ContractViolation, f"implementation versions.*{version}"
                ):
                    self.validate(core=damaged)

    def test_noncanonical_default_offer_fails(self) -> None:
        damaged = core_contract().replace(
            "SEMANTIC_PROTOCOL_V9,\n    SEMANTIC_PROTOCOL_V8",
            "SEMANTIC_PROTOCOL_V8,\n    SEMANTIC_PROTOCOL_V9",
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "default offer"):
            self.validate(core=damaged)

    def test_each_missing_protocol_registry_row_fails(self) -> None:
        for version in range(1, 10):
            with self.subTest(version=version):
                rows = protocol_contract().splitlines()
                damaged = "\n".join(
                    row for row in rows if not row.startswith(f"| `{version}` |")
                )
                with self.assertRaisesRegex(
                    CHECKER.ContractViolation, f"protocol registry.*{version}"
                ):
                    self.validate(protocol=damaged)

    def test_each_protocol_default_offer_declaration_is_checked(self) -> None:
        declarations = (
            "default semantic offer is `[9, 8, 7, 6, 5, 4, 3, 2, 1]`",
            "default descending offer is `[9, 8, 7, 6, 5, 4, 3, 2, 1]`",
            "default initiator offers semantic versions `[9, 8, 7, 6, 5, 4, 3, 2, 1]`",
        )
        for declaration in declarations:
            with self.subTest(declaration=declaration):
                damaged = protocol_contract().replace(
                    declaration, declaration.replace("9, ", ""), 1
                )
                with self.assertRaisesRegex(
                    CHECKER.ContractViolation, "protocol default offer"
                ):
                    self.validate(protocol=damaged)

    def test_protocol_negotiated_version_declaration_is_checked(self) -> None:
        damaged = protocol_contract().replace(
            "`9`, `8`, `7`, `6`, `5`, `4`, `3`, `2`, and `1`",
            "`8`, `7`, `6`, `5`, `4`, `3`, `2`, and `1`",
        )
        with self.assertRaisesRegex(
            CHECKER.ContractViolation, "protocol negotiated versions"
        ):
            self.validate(protocol=damaged)

    def test_protocol_highest_supported_surface_is_checked(self) -> None:
        damaged = protocol_contract().replace(
            "highest-supported semantic-version surfaces report `9`",
            "highest-supported semantic-version surfaces report `8`",
        )
        with self.assertRaisesRegex(
            CHECKER.ContractViolation, "protocol highest-supported version"
        ):
            self.validate(protocol=damaged)

    def test_v6_must_inherit_v5_ordinary_lanes_byte_for_byte(self) -> None:
        damaged = protocol_contract().replace(
            "v5 ordinary lanes byte-for-byte", "v5"
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "v6 inheritance"):
            self.validate(protocol=damaged)

    def test_v7_must_inherit_v6_byte_for_byte(self) -> None:
        damaged = protocol_contract().replace("v6 byte-for-byte", "v6")
        with self.assertRaisesRegex(CHECKER.ContractViolation, "v7 inheritance"):
            self.validate(protocol=damaged)

    def test_v8_must_inherit_v7_except_its_allocated_surfaces(self) -> None:
        damaged = protocol_contract().replace(
            "v7 byte-for-byte except the lane AAD domain and Blob custody fields", "v7"
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "v8 inheritance"):
            self.validate(protocol=damaged)

    def test_v9_must_replace_only_the_blob_profile_and_chunk_kind(self) -> None:
        damaged = protocol_contract().replace(
            "v8 fixed lanes byte-for-byte except the Blob transfer profile and Blob chunk kind",
            "v8",
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "v9 inheritance"):
            self.validate(protocol=damaged)

    def test_blob_profile_registry_is_version_scoped(self) -> None:
        damaged = protocol_contract().replace(
            "semantic v7/v8 select profile 4; semantic v9 selects profile 5",
            "semantic v7/v8/v9 select profile 4",
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "Blob profile registry"):
            self.validate(protocol=damaged)

    def test_profile_size_classes_and_checkpoint_limit_are_distinct(self) -> None:
        replacements = {
            "65,536 plaintext chunk bytes": "1,048,576 plaintext chunk bytes",
            "66,215 encrypted carrier bytes": "65,536 encrypted carrier bytes",
            "1,048,576 ABX1 extent bytes": "66,215 ABX1 extent bytes",
            "134,217,728 checkpoint bytes": "8,388,608 checkpoint bytes",
        }
        for original, replacement in replacements.items():
            with self.subTest(original=original):
                damaged = protocol_contract().replace(original, replacement)
                with self.assertRaisesRegex(CHECKER.ContractViolation, "profile 5 limits"):
                    self.validate(protocol=damaged)

    def test_profile_object_source_and_chunk_limits_are_versioned(self) -> None:
        replacements = {
            "67,108,864 object bytes": "8,589,934,592 object bytes",
            "1,024 canonical chunks": "131,072 canonical chunks",
            "1,048,576 authenticated-source bytes": "16,777,216 authenticated-source bytes",
            "8,589,934,592 object bytes": "67,108,864 object bytes",
            "131,072 canonical chunks": "1,024 canonical chunks",
            "16,777,216 authenticated-source bytes": "1,048,576 authenticated-source bytes",
        }
        for original, replacement in replacements.items():
            with self.subTest(original=original):
                damaged = protocol_contract().replace(original, replacement, 1)
                with self.assertRaisesRegex(CHECKER.ContractViolation, "profile [45] limits"):
                    self.validate(protocol=damaged)

    def test_profile_five_pipeline_and_empty_terminal_order_are_checked(self) -> None:
        for original, replacement in (
            ("PLAN -> OPEN -> SOURCE -> ACCEPT -> ABX1 DATA -> CHECKPOINT -> FINISH -> RESULT -> ACK",
             "PLAN -> OPEN -> ACCEPT -> DATA -> FINISH"),
            ("OPEN -> SOURCE -> ACCEPT -> FINISH(final_offset=0) -> RESULT -> ACK, with no DATA or CHECKPOINT",
             "OPEN -> ACCEPT -> RESULT"),
        ):
            with self.subTest(original=original):
                damaged = protocol_contract().replace(original, replacement)
                with self.assertRaisesRegex(CHECKER.ContractViolation, "profile 5 grammar"):
                    self.validate(protocol=damaged)

    def test_truncated_envelope_selection_registry_fails(self) -> None:
        damaged = envelope_contract().replace(", 7, 8, or 9", "")
        with self.assertRaisesRegex(CHECKER.ContractViolation, "envelope selection"):
            self.validate(envelope=damaged)

    def test_truncated_envelope_default_offer_fails(self) -> None:
        damaged = envelope_contract().replace(
            "[9, 8, 7, 6, 5, 4, 3, 2, 1]", "[8, 7, 6, 5, 4, 3, 2, 1]"
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "envelope default offer"):
            self.validate(envelope=damaged)

    def test_envelope_version_summary_is_checked(self) -> None:
        damaged = envelope_contract().replace(
            "default/highest `9`, compatibility `8`, `7`, `6`, `5`, `4`, `3`, `2`, and `1`",
            "default/highest `8`, compatibility `7`, `6`, `5`, `4`, `3`, `2`, and `1`",
        )
        with self.assertRaisesRegex(
            CHECKER.ContractViolation, "envelope version summary"
        ):
            self.validate(envelope=damaged)

    def test_each_missing_cddl_alias_fails(self) -> None:
        for version in range(1, 10):
            with self.subTest(version=version):
                rows = cddl_contract().splitlines()
                damaged = "\n".join(
                    row
                    for row in rows
                    if not row.startswith(f"semantic-v{version}-object-kind =")
                )
                with self.assertRaisesRegex(
                    CHECKER.ContractViolation, f"CDDL object-kind aliases.*{version}"
                ):
                    self.validate(cddl=damaged)

    def test_cddl_v6_must_inherit_v5_object_kinds(self) -> None:
        damaged = cddl_contract().replace(
            "semantic-v6-object-kind = semantic-v5-object-kind",
            "semantic-v6-object-kind = semantic-v4-object-kind",
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "CDDL v6 inheritance"):
            self.validate(cddl=damaged)

    def test_cddl_v7_must_inherit_v6_object_kinds(self) -> None:
        damaged = cddl_contract().replace(
            "semantic-v7-object-kind = semantic-v6-object-kind",
            "semantic-v7-object-kind = semantic-v5-object-kind",
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "CDDL v7 inheritance"):
            self.validate(cddl=damaged)

    def test_cddl_v8_must_inherit_v7_object_kinds(self) -> None:
        damaged = cddl_contract().replace(
            "semantic-v8-object-kind = semantic-v7-object-kind",
            "semantic-v8-object-kind = semantic-v6-object-kind",
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "CDDL v8 inheritance"):
            self.validate(cddl=damaged)

    def test_cddl_v9_must_exclude_legacy_blob_chunks(self) -> None:
        damaged = cddl_contract().replace(
            "semantic-v9-object-kind = 1 / 3 / 4 / 5",
            "semantic-v9-object-kind = semantic-v8-object-kind",
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "CDDL v9"):
            self.validate(cddl=damaged)

    def test_cddl_declares_profile_five_fixed_binary_grammar(self) -> None:
        damaged = cddl_contract().replace(
            'stream-data-v1 = "ASM\\x01\\xd8" attempt-tuple offset-u64 extent-len-u32 abx1-extent\n',
            "",
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "CDDL profile 5 grammar"):
            self.validate(cddl=damaged)

    def test_profile_five_schema_mutations_fail(self) -> None:
        root = CHECKER_PATH.parents[1]
        schema = json.loads((root / "conformance/profile5-wire-schema.json").read_text())
        rust = (root / "crates/aster-node/src/stream_transfer.rs").read_text()
        mutations = []
        for key, value in (("semantic_version", 8), ("profile_id", 4), ("byte_order", "little-endian")):
            changed = copy.deepcopy(schema)
            changed[key] = value
            mutations.append((key, changed))
        for index, record in enumerate(schema["records"]):
            changed = copy.deepcopy(schema)
            changed["records"][index]["tag"] ^= 1
            mutations.append((f"{record['name']} tag", changed))
            changed = copy.deepcopy(schema)
            changed["records"][index]["fields"] = list(reversed(changed["records"][index]["fields"]))
            mutations.append((f"{record['name']} fields", changed))
            for field_index, field in enumerate(record["fields"]):
                changed = copy.deepcopy(schema)
                changed["records"][index]["fields"][field_index][1] = "u8"
                mutations.append((f"{record['name']} {field[0]} width/bound", changed))
        for path, value in (("ABX1 bound", 1_048_577), ("composite bound", 1_050_631)):
            changed = copy.deepcopy(schema)
            changed["abx1" if path.startswith("ABX1") else "composite"]["max_encoded_bytes"] = value
            mutations.append((path, changed))
        changed = copy.deepcopy(schema)
        next(record for record in changed["records"] if record["name"] == "RESULT")["fields"][-2][1] = "u8-enum:1,2"
        mutations.append(("result code", changed))
        changed = copy.deepcopy(schema)
        next(record for record in changed["records"] if record["name"] == "OPEN")["fields"][10][1] = "u64<=8589934592"
        mutations.append(("OPEN plaintext instead of canonical wire bound", changed))
        for section in ("attempt_fields",):
            changed = copy.deepcopy(schema)
            changed[section] = list(reversed(changed[section]))
            mutations.append((f"{section} order", changed))
            for index, field in enumerate(schema[section]):
                changed = copy.deepcopy(schema)
                changed[section][index][1] = "u8"
                mutations.append((f"{section} {field[0]} width/bound", changed))
        for section in ("abx1", "composite"):
            changed = copy.deepcopy(schema)
            changed[section]["magic"] = "00000000"
            mutations.append((f"{section} magic", changed))
            changed = copy.deepcopy(schema)
            changed[section]["fields"] = list(reversed(changed[section]["fields"]))
            mutations.append((f"{section} field order", changed))
            for index, field in enumerate(schema[section]["fields"]):
                changed = copy.deepcopy(schema)
                changed[section]["fields"][index][1] = "u8"
                mutations.append((f"{section} {field[0]} width/bound", changed))
        for flow in ("empty", "nonempty"):
            changed = copy.deepcopy(schema)
            changed["flow"][flow] = list(reversed(changed["flow"][flow]))
            mutations.append((f"{flow} flow", changed))
        for name, changed in mutations:
            with self.subTest(name=name), self.assertRaises(CHECKER.ContractViolation):
                CHECKER.validate_profile5_schema(changed, rust)

    def test_profile_five_decoder_and_validator_drift_fail(self) -> None:
        root = CHECKER_PATH.parents[1]
        schema = json.loads((root / "conformance/profile5-wire-schema.json").read_text())
        rust = (root / "crates/aster-node/src/stream_transfer.rs").read_text()
        mutations = {
            "OPEN decoder width": rust.replace("let total_len = r.u64()?;", "let total_len = r.u32()?;", 1),
            "attempt decoder order": rust.replace(
                "let id = self.array()?;\n        let n = self.array()?;",
                "let n = self.array()?;\n        let id = self.array()?;",
                1,
            ),
            "OPEN executable wire bound": rust.replace(
                "bytes <= aster_mesh::PROFILE5_MAX_CANONICAL_WIRE_BYTES",
                "bytes <= aster_mesh::MAX_BLOB_CHUNKS",
                1,
            ),
            "OPEN authenticated source bound": rust.replace(
                "length > MAX_STREAM_AUTHENTICATED_OPEN_BYTES",
                "length > PROFILE5_SOURCE_CHUNK_BYTES",
            ),
            "OPEN custody presence enum": rust.replace(
                "1 => Some(r.array()?)",
                "2 => Some(r.array()?)",
                1,
            ),
            "ABX1 carrier bound": rust.replace(
                "length > PROFILE5_CANONICAL_CARRIER_RECORD_BYTES",
                "length > PROFILE5_CANONICAL_EXTENT_BYTES",
            ),
            "ABX1 magic": rust.replace('b"ABX1"', 'b"ABX2"', 1),
            "ABX1 aggregate bound": rust.replace(
                "bytes.len() > PROFILE5_CANONICAL_EXTENT_BYTES",
                "bytes.len() > MAX_STREAM_AUTHENTICATED_OPEN_BYTES",
                1,
            ),
            "ABX1 count bound": rust.replace("if count == 0", "if count == 1", 1),
            "ABX1 index bound": rust.replace(
                "end > aster_mesh::MAX_BLOB_CHUNKS",
                "end >= aster_mesh::MAX_BLOB_CHUNKS",
            ),
            "ABX1 trailing bound": rust.replace(
                "if offset != bytes.len()",
                "if offset > bytes.len()",
                1,
            ),
            "ASD1 protected-header bound": rust.replace(
                "protected_len > MAX_PROTECTED_STREAM_DATA_HEADER_BYTES",
                "protected_len > MAX_STREAM_EXTENT_BYTES",
            ),
            "ASD1 magic": rust.replace('b"ASD1"', 'b"ASD2"', 1),
            "ASD1 zero-header bound": rust.replace(
                "protected_len == 0", "protected_len == 1", 1
            ),
            "SOURCE encoder chunk bound": rust.replace(
                "x.bytes.len() > PROFILE5_SOURCE_CHUNK_BYTES",
                "x.bytes.len() > MAX_STREAM_AUTHENTICATED_OPEN_BYTES",
                1,
            ),
            "SOURCE decoder chunk bound": rust.replace(
                "chunk_len > PROFILE5_SOURCE_CHUNK_BYTES",
                "chunk_len > MAX_STREAM_AUTHENTICATED_OPEN_BYTES",
                1,
            ),
            "ACCEPT encoder checkpoint bound": rust.replace(
                "x.checkpoint_batch_bytes > MAX_STREAM_CHECKPOINT_BATCH_BYTES",
                "x.checkpoint_batch_bytes > u32::MAX",
                1,
            ),
            "ACCEPT decoder checkpoint bound": rust.replace(
                "x.checkpoint_batch_bytes > MAX_STREAM_CHECKPOINT_BATCH_BYTES",
                "x.checkpoint_batch_bytes > u32::MAX",
                2,
            ),
            "RESULT wire mapping": rust.replace(
                "1 => Ok(Self::Promoted)",
                "1 => Ok(Self::IntegrityFailure)",
                1,
            ),
            "terminal flow predicate": rust.replace(
                "phase == Phase::Terminal",
                "phase == Phase::Result",
                1,
            ),
            "attempt nonce validator": rust.replace(
                "v.iter().all(|b| *b == 0)",
                "v.iter().all(|b| *b == 1)",
                1,
            ),
            "extent shared validator": rust.replace(
                "v as usize > MAX_STREAM_EXTENT_BYTES",
                "v as usize > MAX_STREAM_AUTHENTICATED_OPEN_BYTES",
                1,
            ),
            "FINISH shared validator": rust.replace(
                "bytes.len() > max_bytes",
                "bytes.len() >= max_bytes",
                1,
            ),
            "FINISH decoder commitment bound": rust.replace(
                "commitment_len > MAX_STREAM_SEMANTIC_COMMITMENT_BYTES",
                "commitment_len > MAX_STREAM_AUTHENTICATED_OPEN_BYTES",
                1,
            ),
            "CHECKPOINT encoder credit relation": rust.replace(
                "x.absolute_receive_limit < x.durable_offset",
                "x.absolute_receive_limit > x.durable_offset",
                1,
            ),
            "CHECKPOINT decoder credit relation": rust.replace(
                "x.absolute_receive_limit < x.durable_offset",
                "x.absolute_receive_limit > x.durable_offset",
                2,
            ),
            "DATA encoder offset overflow": rust.replace(
                "x.offset\n                    .checked_add(l.into())",
                "x.offset\n                    .checked_sub(l.into())",
                1,
            ),
            "DATA decoder offset overflow": rust.replace(
                "offset\n            .checked_add(extent_len.into())",
                "offset\n            .checked_sub(extent_len.into())",
                1,
            ),
            "record trailing-byte validator": rust.replace(
                "self.o == self.b.len()",
                "self.o <= self.b.len()",
                1,
            ),
            "class wire mapping": rust.replace("Blob = 1", "Blob = 2", 1),
            "direction wire mapping": rust.replace(
                "ToSessionResponder = 2", "ToSessionResponder = 3", 1
            ),
        }
        for name, changed in mutations.items():
            self.assertNotEqual(changed, rust, name)
            with self.subTest(name=name), self.assertRaises(CHECKER.ContractViolation):
                CHECKER.validate_profile5_schema(schema, changed)

    def test_profile_five_encoder_enum_and_minimum_drift_fail(self) -> None:
        root = CHECKER_PATH.parents[1]
        schema = json.loads((root / "conformance/profile5-wire-schema.json").read_text())
        rust = (root / "crates/aster-node/src/stream_transfer.rs").read_text()
        mutations = (
            (
                "OPEN custody encoder discriminant",
                rust.replace("None => o.push(0)", "None => o.push(2)", 1),
                r"OPEN encoder validator differs at None => o\.push\(0\)",
            ),
            (
                "OPEN custody-present encoder discriminant",
                rust.replace(
                    "o.push(1);\n                        o.extend(d)",
                    "o.push(2);\n                        o.extend(d)",
                    1,
                ),
                r"OPEN encoder validator differs at Some\(d\) => \{ o\.push\(1\)",
            ),
            (
                "ABX1 nonempty carrier encoder predicate",
                rust.replace("if self.carriers.is_empty()", "if false", 1),
                r"ABX1 validator differs at self\.carriers\.is_empty\(\)",
            ),
            (
                "ABX1 nonempty carrier-record encoder predicate",
                rust.replace("if carrier.is_empty()", "if false", 1),
                r"ABX1 validator differs at carrier\.is_empty\(\)",
            ),
            (
                "ASD1 nonempty protected-header encoder predicate",
                rust.replace("if protected_header.is_empty()", "if false", 1),
                r"ASD1 validator differs at protected_header\.is_empty\(\)",
            ),
        )
        for name, changed, reason in mutations:
            self.assertNotEqual(changed, rust, name)
            with self.subTest(name=name), self.assertRaisesRegex(
                CHECKER.ContractViolation, reason
            ):
                CHECKER.validate_profile5_schema(schema, changed)

    def test_profile_five_executable_wire_ceiling_drift_fails(self) -> None:
        root = CHECKER_PATH.parents[1]
        paths = [
            "crates/aster-core/src/transfer_profile.rs",
            "crates/aster-node/src/application/blob.rs",
            "crates/aster-core/src/blob.rs",
            "crates/aster-core/src/blob_stream.rs",
            "crates/aster-node/src/stream_transfer.rs",
            "crates/aster-iroh/src/lib.rs",
            "crates/aster-node/src/runtime/blob_stream.rs",
        ]
        sources = [(root / path).read_text() for path in paths]
        damaged = list(sources)
        damaged[3] = damaged[3].replace(
            "pub const PROFILE5_MAX_CANONICAL_WIRE_BYTES: u64 = MAX_BLOB_CHUNKS",
            "pub const PROFILE5_MAX_CANONICAL_WIRE_BYTES: u64 = 8_589_934_592 + 0 * MAX_BLOB_CHUNKS",
            1,
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "executable profile 5 limits"):
            CHECKER.validate_executable_profile_contract(*damaged)
        damaged = list(sources)
        damaged[6] = damaged[6].replace(
            "let profile_ceiling = aster_mesh::PROFILE5_MAX_CANONICAL_WIRE_BYTES;",
            "let profile_ceiling = 8u64 * 1024 * 1024 * 1024;",
            1,
        )
        with self.assertRaisesRegex(CHECKER.ContractViolation, "receiver ceiling"):
            CHECKER.validate_executable_profile_contract(*damaged)

    def test_every_profile_five_fuzz_seed_is_an_actual_decodable_record(self) -> None:
        seed_root = CHECKER_PATH.parents[1] / "fuzz/corpus/stream_transfer_decode"
        seeds = sorted(seed_root.iterdir())
        self.assertGreaterEqual(len(seeds), 8)
        observed = set()
        transcripts = set()
        for seed in seeds:
            payload = seed.read_bytes()
            if payload.startswith(b"HEX:"):
                wire = bytes.fromhex(payload[4:].strip().decode("ascii"))
                observed.add(ORACLE.decode_stream_record(wire))
            elif payload.startswith(b"ASD1"):
                protected_len = int.from_bytes(payload[4:8], "big")
                self.assertTrue(payload[8:8 + protected_len].startswith(b"ASTRFR01"))
                self.assertTrue(payload[8 + protected_len:].startswith(b"ABX1"))
                self.assertLessEqual(len(payload), 1_050_632)
            else:
                self.assertTrue(payload.startswith(b"AST1"), seed)
                self.assertIn(payload[4], (0, 1))
                accepted = payload[4] == 1
                count = payload[5]
                offset = 6
                tags = []
                for _ in range(count):
                    length = int.from_bytes(payload[offset:offset + 4], "big")
                    offset += 4
                    tags.append(ORACLE.decode_stream_record(payload[offset:offset + length]))
                    offset += length
                self.assertEqual(offset, len(payload))
                transcripts.add((accepted, tuple(tags)))
        self.assertEqual(observed, set(range(0xd6, 0xde)))
        self.assertIn((True, (0xd6, 0xdd, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc)), transcripts)
        self.assertIn((True, (0xd6, 0xdd, 0xd7, 0xda, 0xdb, 0xdc)), transcripts)
        self.assertEqual(sum(not accepted for accepted, _ in transcripts), 4)

    def test_profile_five_schema_flow_is_bound_to_checked_in_transcripts(self) -> None:
        root = CHECKER_PATH.parents[1]
        schema = json.loads((root / "conformance/profile5-wire-schema.json").read_text())
        rust = (root / "crates/aster-node/src/stream_transfer.rs").read_text()
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            target = scratch / "fuzz/corpus/stream_transfer_decode"
            shutil.copytree(root / "fuzz/corpus/stream_transfer_decode", target)
            seed = target / "profile5-transcript-empty.bin"
            payload = bytearray(seed.read_bytes())
            payload[4] = 0
            seed.write_bytes(payload)
            with self.assertRaisesRegex(CHECKER.ContractViolation, "flow differs"):
                CHECKER.validate_profile5_schema(schema, rust, scratch)

    def test_profile_five_oracle_and_vector_drift_fail(self) -> None:
        root = CHECKER_PATH.parents[1]
        for drift in ("vector", "oracle"):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as directory:
                scratch = Path(directory)
                shutil.copytree(root / "conformance", scratch / "conformance")
                shutil.copytree(root / "fuzz/corpus", scratch / "fuzz/corpus")
                if drift == "vector":
                    vector = scratch / "conformance/vectors/profile5-transcripts-v1.tsv"
                    vector.write_text(vector.read_text() + "\n")
                else:
                    oracle = scratch / "conformance/blob_stream_oracle.py"
                    oracle.write_text(oracle.read_text().replace(
                        "semantic=9\\tprofile=5", "semantic=10\\tprofile=5", 1
                    ))
                with self.assertRaisesRegex(
                    CHECKER.ContractViolation, "oracle/vectors drifted"
                ):
                    CHECKER.validate_profile5_oracle(scratch)


if __name__ == "__main__":
    unittest.main()
