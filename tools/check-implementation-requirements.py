#!/usr/bin/env python3
"""Generate and validate the exhaustive production requirements trace.

Selected-production status, retained semantic implementation, research, and
external gates are independent dimensions. None silently grants another.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "data-mesh-requirements.md"
MATRIX = ROOT / "docs/evaluations/0005/requirements-matrix.csv"
TRACE = ROOT / "docs/implementation/requirements-implementation.csv"
LEDGER = ROOT / "docs/implementation/requirements-status.md"
EXPECTED_REQUIREMENTS_SHA256 = (
    "e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987"
)
EXPECTED_MATRIX_SHA256 = (
    "57518c2aaeb7341f0d2ef7169a30a1666e337def2bb6a34f9225fad6e438e5b2"
)

FIELDS = (
    "id",
    "level",
    "phase",
    "requirement_class",
    "final_stack_invariant",
    "selected_status",
    "selected_owner",
    "selected_evidence",
    "semantic_source",
    "semantic_evidence",
    "semantic_equivalence_gate",
    "relevant_artifact",
    "research_disposition",
    "research_evidence",
    "disposition",
    "gate_kind",
    "gate_owner",
    "remaining_gap",
)
VALID_SELECTED_STATES = frozenset(
    {"observed-bounded", "implemented-uncredited", "open"}
)

RECEIPT = "docs/implementation/requirements-status.md#reproducible-receipt"
MISSION_RECEIPT = (
    "docs/implementation/requirements-status.md#mission-authenticated-runtime-validation"
)
CONTROL_RECEIPT = (
    "docs/implementation/requirements-status.md#mission-control-revocation-and-rekey-receipt"
)
ZEROIZATION_RECEIPT = (
    "docs/implementation/requirements-status.md#local-software-zeroization-receipt"
)
N32_RECEIPT = (
    "docs/implementation/requirements-status.md#selected-n32-retained-receipt"
)
DEPENDENCY_GATE = (
    "docs/implementation/requirements-status.md#dependency-admission-gate"
)
EVENT_SLICE = (
    "crates/aster-core/src/source_event.rs; crates/aster-redb-store/src/lib.rs; "
    "crates/aster-node/src/runtime.rs; crates/aster-node/src/application.rs; "
    "crates/aster-node/examples/event_application.rs; "
    "docs/quickstart/selected-event-api.md; crates/aster-node/tests/mesh_cli.rs"
)
EVENT_SUBSCRIPTION_SLICE = (
    "crates/aster-redb-store/src/lib.rs; crates/aster-node/src/frame.rs; "
    "crates/aster-node/src/runtime.rs; crates/aster-node/src/application.rs; "
    "crates/aster-node/examples/event_application.rs"
)
EVENT_LIVE_SLICE = (
    "crates/aster-node/src/application.rs; crates/aster-node/src/runtime.rs; "
    "crates/aster-node/src/lib.rs; "
    "crates/aster-node/examples/live_event_application.rs; "
    "crates/aster-node/tests/mesh_cli.rs::"
    "offline_publish_later_real_process_sync_poll_ack_and_restart; "
    "docs/quickstart/selected-event-api.md"
)
CUSTODY_SLICE = (
    "crates/aster-core/src/custody.rs; crates/aster-core/src/source_event.rs; "
    "crates/aster-core/src/crypto/reference.rs; "
    "crates/aster-redb-store/src/custody.rs; crates/aster-redb-store/src/lib.rs; "
    "crates/aster-iroh/src/lib.rs; crates/aster-node/src/frame.rs; "
    "crates/aster-node/src/runtime.rs; crates/aster-node/src/application.rs; "
    "crates/aster-node/examples/custody_application.rs; "
    "docs/quickstart/selected-custody-api.md"
)
AGENT_SLICE = (
    "proto/aster/application/v1alpha1/aster.proto; crates/aster-agent/src/lib.rs; "
    "crates/aster-agent/src/main.rs; crates/aster-agent/tests/real_node_connect.rs; "
    "examples/connect_agent.sh; docs/quickstart/connect-agent.md; "
    "docs/decisions/0030-event-first-local-connect-agent.md"
)
STATE_LOCAL_SLICE = (
    "crates/aster-core/src/source_state.rs; crates/aster-redb-store/src/lib.rs; "
    "crates/aster-node/src/application/state.rs; "
    "crates/aster-node/examples/state_application.rs; "
    "docs/quickstart/selected-state-api.md"
)
RECORD_LOCAL_SLICE = (
    "crates/aster-core/src/source_record.rs; crates/aster-redb-store/src/lib.rs; "
    "crates/aster-node/src/application/record.rs; "
    "crates/aster-node/examples/record_application.rs; "
    "docs/quickstart/selected-record-api.md"
)
MUTABLE_NETWORK_SLICE = (
    "crates/aster-core/src/source_state.rs; crates/aster-core/src/source_record.rs; "
    "crates/aster-redb-store/src/lib.rs; crates/aster-node/src/frame.rs; "
    "crates/aster-node/src/runtime.rs; crates/aster-node/src/main.rs; "
    "fuzz/fuzz_targets/selected_frame_decode.rs; "
    "crates/aster-node/src/frame.rs::tests::"
    "mutable_fetch_result_codec_binds_tag_class_direction_id_and_disposition; "
    "crates/aster-node/src/runtime.rs::tests::"
    "mutable_v4_gate_budget_and_status_are_class_separated; "
    "crates/aster-node/src/runtime.rs::tests::"
    "mutable_fetch_result_requires_exact_pending_tuple_and_echoes_disposition; "
    "crates/aster-node/src/runtime.rs::tests::"
    "real_iroh_mutable_capacity_defers_both_directions_then_progresses_after_reopen; "
    "crates/aster-node/src/runtime.rs::tests::"
    "real_iroh_mutable_cursors_prevent_offer_and_fetch_starvation_across_reopen; "
    "crates/aster-node/src/runtime.rs::tests::"
    "same_epoch_rekey_restart_withholds_historical_lineage_and_contact_continues; "
    "crates/aster-redb-store/src/lib.rs::tests::"
    "state_and_record_frontier_capacity_errors_are_typed_and_transactional; "
    "crates/aster-redb-store/src/lib.rs::tests::"
    "mutable_transfer_cursor_cas_reconcile_reopen_and_terminal_preservation; "
    "crates/aster-node/src/runtime.rs::tests::"
    "real_iroh_contact_converges_state_and_disconnected_record_siblings; "
    "docs/protocol.md#91-selected-semantic-v4-state-and-record-reconciliation; "
    "docs/quickstart/selected-state-api.md; "
    "docs/quickstart/selected-record-api.md"
)
BLOB_LOCAL_SLICE = (
    "crates/aster-core/src/blob.rs; crates/aster-core/src/source_blob.rs; "
    "crates/aster-redb-store/src/blob.rs; "
    "crates/aster-redb-store/src/blob/depot.rs; "
    "crates/aster-node/src/application/blob.rs; "
    "crates/aster-node/examples/blob_application.rs; "
    "docs/quickstart/selected-blob-api.md"
)
BLOB_NETWORK_SLICE = (
    "crates/aster-core/src/blob.rs; crates/aster-core/src/source_blob.rs; "
    "crates/aster-core/src/crypto/reference.rs; crates/aster-core/src/store.rs; "
    "crates/aster-redb-store/src/blob.rs; "
    "crates/aster-redb-store/src/blob/depot.rs; "
    "crates/aster-redb-store/src/lib.rs; crates/aster-node/src/frame.rs; "
    "crates/aster-node/src/runtime.rs; "
    "fuzz/fuzz_targets/selected_frame_decode.rs; "
    "crates/aster-core/src/source_blob.rs::tests::"
    "blob_peer_content_proof_is_exact_current_and_identity_bound; "
    "crates/aster-core/src/store.rs::tests::"
    "schema_v14_migrates_and_v5_provenance_survives_restart; "
    "crates/aster-node/src/frame.rs::tests::"
    "blob_source_class_and_chunk_object_id_are_exactly_typed; "
    "crates/aster-node/src/frame.rs::tests::"
    "blob_interest_is_exact_canonical_and_proof_bound; "
    "crates/aster-node/src/frame.rs::tests::"
    "blob_range_fetch_and_data_enforce_exact_bounded_ranges; "
    "crates/aster-node/src/frame.rs::tests::"
    "blob_range_result_and_ack_bind_exact_canonical_outcome; "
    "crates/aster-node/src/frame.rs::tests::"
    "blob_carrier_finish_remaining_is_bounded_and_exact; "
    "crates/aster-redb-store/src/blob.rs::tests::"
    "network_blob_stages_transfers_promotes_serves_and_reopens; "
    "crates/aster-redb-store/src/blob.rs::tests::"
    "network_blob_reservation_deduplicates_and_terminal_abort_reclaims; "
    "crates/aster-redb-store/src/blob.rs::tests::"
    "network_blob_same_epoch_physical_lineage_requires_epoch_advance; "
    "crates/aster-redb-store/src/blob.rs::tests::"
    "network_blob_promotion_capacity_failure_keeps_retryable_pending_state; "
    "crates/aster-redb-store/src/blob.rs::tests::"
    "network_blob_promotion_frontier_capacity_is_typed_and_transactional; "
    "crates/aster-redb-store/src/blob.rs::tests::"
    "predecessor_nine_table_blob_schema_migrates_network_additively_with_owner_tokens; "
    "crates/aster-redb-store/src/blob.rs::tests::"
    "pending_blob_audit_binds_exact_manifest_route_and_carriers_on_all_open_paths; "
    "crates/aster-redb-store/src/blob.rs::tests::"
    "pending_blob_audit_rejects_self_consistent_missing_depot_plan_without_repair; "
    "crates/aster-redb-store/src/blob.rs::tests::"
    "pending_and_completed_blob_namespaces_are_exclusive_without_repair; "
    "crates/aster-node/src/runtime.rs::tests::"
    "blob_source_carrier_reopen_resumes_exact_complement_from_different_peer; "
    "crates/aster-node/src/runtime.rs::tests::"
    "stale_pending_blob_cleanup_reclaims_exact_cache_and_depot_state; "
    "crates/aster-node/src/runtime.rs::tests::"
    "pending_blob_abort_reconciles_concurrent_exact_restage_without_restart; "
    "crates/aster-node/src/runtime.rs::tests::"
    "blob_lifecycle_lock_serializes_delayed_projection_insert_and_abort; "
    "crates/aster-node/src/runtime.rs::tests::"
    "terminal_blob_poison_advances_scheduler_past_source_to_later_candidate; "
    "docs/protocol.md#92-selected-semantic-v5-direct-blob-transfer; "
    "docs/quickstart/selected-blob-api.md"
)
CONTROLLED_RELAY_SLICE = (
    "crates/aster-iroh/src/lib.rs; crates/aster-node/src/runtime.rs; "
    "crates/aster-node/src/main.rs; crates/aster-node/tests/mesh_cli.rs; "
    "crates/aster-iroh/src/lib.rs::tests::"
    "controlled_route_and_trust_bounds_are_exact; "
    "crates/aster-iroh/src/lib.rs::tests::"
    "relay_only_exact_peer_succeeds_with_pinned_tls_trust; "
    "crates/aster-iroh/src/lib.rs::tests::"
    "relay_tls_rejects_a_valid_but_unrelated_ca_without_fallback; "
    "crates/aster-iroh/src/lib.rs::tests::"
    "usable_exact_direct_candidate_becomes_selected; "
    "crates/aster-iroh/src/lib.rs::tests::"
    "dead_pinned_relay_still_allows_the_exact_direct_candidate; "
    "crates/aster-iroh/src/lib.rs::tests::"
    "controlled_route_rejects_the_wrong_authenticated_identity; "
    "crates/aster-iroh/src/lib.rs::tests::"
    "relay_loss_is_bounded_and_has_no_public_relay_substitution; "
    "crates/aster-node/src/main.rs::tests::"
    "controlled_relay_flags_are_inseparable_and_trust_is_explicit; "
    "crates/aster-node/src/main.rs::tests::"
    "relay_only_switch_rejects_duplicate_ambiguity; "
    "crates/aster-node/src/main.rs::tests::"
    "controlled_relay_value_duplicates_are_rejected_without_echoing_values; "
    "crates/aster-node/src/main.rs::tests::"
    "help_advertises_bounded_controlled_relay_without_authority_claims; "
    "crates/aster-node/src/runtime.rs::tests::"
    "right_carrier_with_wrong_expected_mission_fails_before_inventory; "
    "crates/aster-node/tests/mesh_cli.rs::"
    "controlled_relay_selected_when_direct_candidate_unusable_then_noops; "
    "crates/aster-node/tests/mesh_cli.rs::"
    "unavailable_controlled_relay_does_not_block_exact_direct_sync; "
    "crates/aster-node/tests/mesh_cli.rs::"
    "manual_node_rejects_partial_controlled_relay_before_state_or_mission_access; "
    "crates/aster-node/tests/mesh_cli.rs::"
    "manual_node_rejects_malformed_relay_root_before_state_or_mission_access; "
    "crates/aster-node/tests/mesh_cli.rs::"
    "manual_node_redacts_duplicate_token_bearing_relay_url_before_state_access"
)
CONTROL_SLICE = (
    "crates/aster-core/src/source_control.rs; crates/aster-redb-store/src/lib.rs; "
    "crates/aster-node/src/frame.rs; crates/aster-node/src/runtime.rs; "
    "crates/aster-node/src/main.rs; crates/aster-node/src/control_admin.rs; "
    "crates/aster-node/tests/mesh_cli.rs"
)
PROVISIONING_ADMIN_SLICE = (
    "crates/aster-core/src/provisioning.rs; crates/aster-node/src/mission.rs; "
    "crates/aster-node/src/application.rs; crates/aster-node/src/control_admin.rs; "
    "docs/decisions/0013-protected-provisioning-boundary.md"
)
PROTECTED_RUNTIME_SLICE = (
    f"{PROVISIONING_ADMIN_SLICE}; crates/aster-node/src/runtime.rs; "
    "crates/aster-node/src/lib.rs; crates/aster-node/tests/protected_runtime.rs"
)
LIVE_CONTROL_ADMIN_SLICE = (
    f"{CONTROL_SLICE}; crates/aster-node/src/lib.rs; "
    "crates/aster-node/src/control_admin.rs::tests::"
    "closed_live_control_channel_returns_only_sanitized_state_unavailable; "
    "crates/aster-node/src/runtime.rs::tests::"
    "protected_live_controls_refresh_policy_retry_exactly_and_close_on_shutdown; "
    "crates/aster-node/src/runtime.rs::tests::"
    "live_control_pending_gap_returns_policy_unsettled_and_preserves_exact_retry; "
    "crates/aster-node/src/runtime.rs::tests::"
    "saturated_cloned_live_control_retries_do_not_starve_event_status_or_publish; "
    "crates/aster-node/src/runtime.rs::tests::"
    "cancelled_enqueued_live_control_remains_actor_owned_and_exactly_retryable; "
    "crates/aster-node/src/runtime.rs::tests::"
    "live_self_revocation_returns_receipt_before_actor_teardown"
)

# Exact tracked requirement maps. A path appears only when the file names an ID
# directly or uses an explicit same-family slash/range shorthand for that ID.
RESEARCH_MAPS = (
    "docs/evaluations/0005/requirement-maps/carrier.csv",
    "docs/evaluations/0005/requirement-maps/blob.csv",
    "docs/evaluations/0005/requirement-maps/discovery.csv",
    "docs/evaluations/0005/requirement-maps/selected-stack.json",
    "docs/evaluations/0005/requirement-maps/p2panda.csv",
    "docs/evaluations/0005/requirement-maps/product-assurance.csv",
    "docs/evaluations/0005/requirement-maps/security-profile.json",
    "docs/evaluations/0005/requirement-maps/willow.csv",
)
REQUIREMENT_ID = re.compile(r"DM-\d+(?:\.\d+)?-\d+[A-Z]?")
REQUIREMENT_SHORTHAND = re.compile(
    r"DM-(?P<family>\d+(?:\.\d+)?)-\d+[A-Z]?(?P<suffixes>(?:/\d+[A-Z]?)+)"
)
REQUIREMENT_RANGE = re.compile(
    r"DM-(?P<family>\d+(?:\.\d+)?)-(?P<start>\d+)\s+through\s+"
    r"DM-(?P=family)-(?P<end>\d+)"
)

NON_GOAL_IDS = frozenset(
    {"DM-2-08", "DM-2-10", "DM-2-11", "DM-2-12", "DM-2-13"}
)
EXPLICIT_EXTERNAL_GATES = {
    "DM-2-05": ("physical-btle-hardware", "transport owner; test owner"),
    "DM-5.8-11": ("physical-btle-hardware", "transport owner; test owner"),
    "DM-6-27": ("validated-crypto-module", "security owner; compliance owner"),
    "DM-8-05": (
        "dependency-license-admission",
        "dependency-policy owner; legal/license owner; release owner",
    ),
    "DM-8-18": (
        "independent-implementation",
        "conformance owner; independent implementation owner",
    ),
    "DM-11-04": ("physical-btle-hardware", "transport owner; test owner"),
    "DM-12-01": ("physical-cross-transport", "transport owner; test owner"),
    "DM-12-09": ("physical-nat-network", "transport owner; test owner"),
    "DM-12-10": ("packet-capture-environment", "security owner; test owner"),
    "DM-12-11": (
        "independent-implementation",
        "conformance owner; independent implementation owner",
    ),
    "DM-13-05": ("physical-btle-hardware", "transport owner; release owner"),
}


def selected_claim(
    status: str,
    owner: str,
    evidence: str,
    gap: str,
) -> dict[str, str]:
    return {
        "selected_status": status,
        "selected_owner": owner,
        "selected_evidence": evidence,
        "remaining_gap": gap,
    }


PROFILE_EVIDENCE = (
    "crates/aster-profile/src/item.rs; requirements-owned reconciliation key "
    "and canonical inventory mechanics; Event transfer identity enters this "
    "adapter only through an explicit exact-digest conversion"
)

# Exact selected-lane mappings supported by current code or bounded receipts.
# An entry is not a full requirement pass; each remaining gap preserves the
# untested predicates. DM-8-05 intentionally remains open.
SELECTED_OVERRIDES: dict[str, dict[str, str]] = {
    "DM-1-03": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{RECEIPT}; direct Iroh contacts moved exact source-sealed Events between mission-authenticated peers",
        "The receipt covers one Event application and one scope on one-host loopback; State, Record, Blob, physical, mixed-implementation, generalized policy, and scale evidence remain open.",
    ),
    "DM-1-04": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{RECEIPT}; isolated per-edge cohorts let a payload-blind route-authorized intermediate retain and exact-forward one pre-existing Ping or Pong difference while the publisher process was absent",
        "Verify generalized application/policy behavior, finite custody duration, physical contacts, alternate carriers, and non-line topologies.",
    ),
    "DM-1-05": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{RECEIPT}; stopped and restarted processes reconciled exact source-sealed Event inventories and reused durable reaction operations",
        "Verify the stakeholder-set extended or day-scale disconnection interval, all data classes, physical systems, generalized policy, and requirement scale.",
    ),
    "DM-2-14": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{PROTECTED_RUNTIME_SLICE}; {LIVE_CONTROL_ADMIN_SLICE}; stopped SelectedControlAdmin and actor-owned SelectedControlHandle accept typed bounded revocation and recipient-filtered rekey requests, serialize mutation under the selected policy-write authority, refresh live policy before response, and return sanitized exact durable publication receipts",
        "This is one Rust control family, not generalized key-policy governance: no production SecretStore/protection backend, protected stock CLI or bindings, cross-process admin IPC, registry/credential issuance, automatic or atomic revoke-plus-rekey workflow, recovery policy, or additional key-management mechanism is shipped.",
    ),
    "DM-3-11": selected_claim(
        "open",
        "deployment owner + aster-core + aster-node",
        f"{PROTECTED_RUNTIME_SLICE}; caller-provided Rust NodeConfig validates bounded options and terminal state before one provider/loader call and state creation, accepts a protected artifact or opaque provider reference, and binds recovered credentials to the checked absolute lexical state pathname; stopped Event/admin opens accept the same sources",
        "The mechanism is not an operational pre-mission provisioning window. The stock CLI still requires an unprotected-reference bundle, and no production provider or SecretStore backend, identity/key issuance ceremony, unattended-start policy, backup/recovery procedure, inode/symlink/rename/rollback binding, selected-node binding, or retained operational receipt is delivered.",
    ),
    "DM-3-12": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{CONTROL_RECEIPT}; {LIVE_CONTROL_ADMIN_SLICE}; a four-node real-process line durably revoked the captured leaf, denied two later contact attempts, withheld epoch-two content, and accepted no stale publication at an eligible peer; current code rejects fresh already-revoked rekey recipients and post-revocation legacy recipient-less controls, while live authority automation commits under the actor lease, returns a self-revocation receipt before teardown, and recovers a cancelled enqueued self-revocation through stopped exact retry",
        "The retained receipt covers one captured leaf on one-host direct loopback; the live cancellation/teardown cases are current-code automation only. Revocation and rekey remain separate operator transactions with no automatic or atomic affected-scope workflow; physical capture, larger/non-line topologies, authority recovery, all data classes, and independent implementations remain open.",
    ),
    "DM-5.1-01": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{STATE_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; the stopped SelectedStateNode source-seals and durably publishes bounded State versions, queries one exact topic/scope/logical-key projection without exposing sealed representations or provider internals, and a separately running node reconciles already durable State under semantic-v4/v5 class/direction lanes with exact outcome acknowledgement, exact remaining, typed capacity deferral, current-lineage filtering, and durable fair rotation",
        "The application State surface remains stopped/exclusive, with no live commands, durable subscription, language binding, selected relay cache, finite TTL, physical carrier, mixed-implementation, or release evidence. Selected finite State TTL is structurally rejected. Current same-implementation direct-Iroh automation is not a retained receipt and does not close those gaps.",
    ),
    "DM-5.1-02": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{STATE_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; authenticated State dots and causal context share the selected Event publisher frontier, the store retains causal maxima and dominated versions, the facade independently recomputes the exact-key projection, one durable version reaches an interested independent store over real Iroh, and class/frontier saturation defers transactionally without pruning",
        "Current tests cover local causal projection, same-epoch old-lineage withholding from ordinary current projection/query and network inventory/transfer with exact same-operation recovery only through strict cached/projection/historical verification, one same-implementation transfer, and capacity/fairness progress. Divergent State convergence, multi-hop/partition behavior, independent interoperability, scale, and retained acceptance remain open.",
    ),
    "DM-5.1-04": selected_claim(
        "observed-bounded", "aster-core + aster-redb-store + aster-node",
        f"{RECEIPT}; {EVENT_SLICE}; {EVENT_LIVE_SLICE}; the built-in sample and high-level live handle publish, source-seal, store, transfer, freshly verify, query, and durably deliver Event objects",
        "The retained receipt covers the built-in Event sample; the generalized live-handle later-sync path has current-code automated loopback evidence only. Other data classes and independent wire interoperability remain open.",
    ),
    "DM-5.1-08": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; the stopped SelectedRecordNode source-seals and durably publishes bounded Record revisions, queries one exact-key current/concurrent/superseded projection, accepts only exact-sibling guarded application resolution, and a separately running node reconciles already durable revisions under semantic-v4/v5 class/direction lanes with exact outcome acknowledgement, exact remaining, typed capacity deferral, current-lineage filtering, and durable fair rotation",
        "The application Record surface remains stopped/exclusive, with no live commands, durable subscription, language binding, automatic registered-policy merge, selected relay cache, finite TTL/GC, physical carrier, mixed-implementation, or retained release evidence. Selected finite Record TTL is structurally rejected.",
    ),
    "DM-5.1-09": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; independently source-authenticated publishers create revisions on separate stores while disconnected, one real-Iroh contact reconciles both exact inventories, both stores retain the same two causal heads without running merge code, and repeated bounded contacts rotate capacity-deferred offer/fetch work across reopen",
        "This current-code automation has no retained execution receipt and remains same-implementation and one-host, with no long partition, comprehensive crash sweep, relay, automatic merge, mixed implementation, scale, physical system, or release acceptance.",
    ),
    "DM-5.1-10": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; {BLOB_NETWORK_SLICE}; the stopped SelectedBlobNode prepares a manifest-bounded digest set, commits encrypted chunks under the fixed 64-KiB profile outside redb, source-seals one canonical manifest, and streams verified plaintext into a caller-owned writer; semantic v5 stages the exact authenticated source before canonical carrier ranges and grants ordinary publication visibility only after exact depot, full-content, and current-lineage completion",
        "The selected Blob application surface remains stopped and the network slice is direct content-capable-peer only. No live handle/subscription, route-only relay/custody, Blob TTL/GC, language binding, physical/resource acceptance, mixed-implementation evidence, or retained release receipt exists. The network case is one 96-KiB same-process, one-host fixture, not maximum-size acceptance.",
    ),
    "DM-5.1-11": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; {BLOB_NETWORK_SLICE}; BlobId commits exact plaintext bytes, the canonical chunk profile, and media/schema identity metadata; source-authenticated manifest records and the epoch-specific encrypted depot variant are immutable once committed, and semantic-v5 remote staging remains invisible until exact immutable content verification and atomic publication",
        "The ID is metadata-bound object identity, not a separate pure whole-byte content ID. Metadata-independent deduplication, route-only relay/custody, independent interoperability, scale, physical/resource evidence, and retained acceptance remain open.",
    ),
    "DM-5.1-12": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_NETWORK_SLICE}; semantic v5 authenticates and atomically stages the exact source envelope and manifest before strict kind-2 carrier work, transfers canonical carriers through contiguous ranges no larger than 16 KiB, and verifies carrier identity, every AEAD/chunk digest, and the whole BlobId before publication",
        "Current evidence is one 96-KiB same-process, one-host direct-Iroh case. There is no 100+ MiB/RSS or physical/resource acceptance, route-only relay/custody, mixed implementation, live Blob handle/subscription, retained execution root, or release authorization.",
    ),
    "DM-5.1-13": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_NETWORK_SLICE}; exact source plans and contiguous carrier prefixes are durable under source/carrier identity rather than peer or session, survive runtime/store/provider-cache teardown and reopen, resume only the exact missing complement from another eligible content peer, and remain nonpublic until full verified promotion",
        "The bounded case uses one 96-KiB Blob on one host and one immediate modeled later contact. Route-only relay/custody, long-delay and crash/power-loss acceptance, 100+ MiB/RSS or physical evidence, mixed implementations, live Blob access, retained evidence, and release acceptance remain open.",
    ),
    "DM-5.2-19": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_NETWORK_SLICE}; an authenticated pending source plus peer-neutral contiguous carrier prefix survives interruption and reopen, and the scheduler requests the exact source/carrier complement without discarding already accepted bytes",
        "This is one 96-KiB same-process, one-host direct-Iroh case, not long-partition, 100+ MiB/RSS, physical/resource, mixed-implementation, retained-receipt, or release evidence. Route-only relay/custody and live Blob application delivery remain open.",
    ),
    "DM-5.2-20": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_NETWORK_SLICE}; A sends C the authenticated source plus one bounded durable range, then C's runtime, store, and provider cache tear down and reopen with that exact partial progress retained and nonpublic",
        "The brief-contact checkpoint is one controlled 96-KiB same-process, one-host case. OS-process/power-loss, long-duration, 100+ MiB/RSS, physical/resource, route-only, mixed-implementation, retained-receipt, and release acceptance remain open.",
    ),
    "DM-5.2-21": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_NETWORK_SLICE}; after reopen the receiver continues at the first missing carrier byte and creates exactly one ordinary publication only after canonical carrier, depot completion, freshly streamed full-content verification, and current-lineage proof all agree",
        "Later contact is immediate within one 96-KiB same-process, one-host test. Long offline intervals, OS-process/power-loss, route-only custody, 100+ MiB/RSS or physical evidence, mixed implementations, retained evidence, live Blob delivery, and release authorization remain open.",
    ),
    "DM-5.2-22": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_NETWORK_SLICE}; A completes B, partially stages C, and is removed; fresh eligible content peer B then sends C no source retransmission and only the exact missing carrier complement while every inventory/source/range service rechecks peer content proof, route, revocation, and current route/physical lineage",
        "Eligibility deliberately excludes route-only peers. This is one 96-KiB same-process, one-host direct-Iroh case without a retained execution root, live Blob application handle/subscription, TTL/GC, pure-byte deduplication, 100+ MiB/RSS or physical/resource acceptance, mixed implementation, or release authorization.",
    ),
    "DM-5.1-05": selected_claim(
        "implemented-uncredited", "aster-redb-store",
        f"{EVENT_SLICE}; exact transfer and semantic indexes reject conflicting Event representations or dot reuse",
        "Publish independent interoperability and broader mutation/adversarial evidence before claiming complete Event immutability.",
    ),
    "DM-5.1-06": selected_claim(
        "implemented-uncredited", "aster-redb-store",
        f"{EVENT_SLICE}; accepted Events carry authenticated nonzero publisher sequence and durable per-publisher/topic/scope positions",
        "Verify ordering through durable cross-process consumer delivery, independent interoperability, and at requirement scale.",
    ),
    "DM-5.1-07": selected_claim(
        "implemented-uncredited", "aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {EVENT_LIVE_SLICE}; the public Event gap query bounds one exact publisher/topic/scope stream, freshly source/content verifies every observed anchor, and race-rechecks the policy-bound plan before returning half-open gaps",
        "Gap absence is limited to verified positions already observed by the local mission-bound store; verify actual missing-position detection through a cross-process consumer and independent implementation without implying publisher completeness or convergence.",
    ),
    "DM-5.1-17": selected_claim(
        "implemented-uncredited", "aster-core + aster-node", EVENT_SLICE,
        f"The selected live and stopped application boundaries publish, query, subscribe to, poll, acknowledge, unsubscribe from, and inspect Event through {EVENT_SUBSCRIPTION_SLICE} and {EVENT_LIVE_SLICE}. State, Record, and Blob have stopped typed boundaries, but live handles and selected-node language bindings remain open.",
    ),
    "DM-5.1-18": selected_claim(
        "implemented-uncredited", "aster-core + aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; Event, State, Record, and Blob topics are source-authenticated and content-granted; Event has durable Consume/Carry delivery selectors, semantic-v4/v5 State/Record have explicit class-separated interests, and each v5 exact Blob selector carries a current peer-bound content proof",
        "Repeated dynamic selector lifecycle, durable State/Record/Blob application delivery, route-only Blob custody, and independent interoperability remain open.",
    ),
    "DM-5.1-19": selected_claim(
        "implemented-uncredited", "aster-core + aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; Event, State, Record, and Blob scope/epoch are source-authenticated; current route grants and current source lineage filter inventory/transfer, while every v5 Blob inventory/source/range send additionally requires the authenticated peer's current exact topic/scope/epoch content proof and current physical lineage",
        "Repeated dynamic multi-scope lifecycle, route-only Blob custody, physical peers, and independent interoperability remain open. Same-epoch replacement withholds old proofs and rows; a bounded non-public unfinished physical-lineage fence preserves the numeric-epoch-advance rule across cleanup.",
    ),
    "DM-5.1-20": selected_claim(
        "implemented-uncredited", "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; selected Event priority is source-authenticated, persisted, used by bounded v3/v4/v5 scheduling/retry, and participates in the explicit Event/RouteEvent pressure order; AtLeast remains an Event-only threshold and does not suppress semantic-v4/v5 State/Record or v5 Blob work",
        "State, Record, and Blob remain outside selected custody priority scheduling and eviction; mutable/Blob continuation is not priority or cross-class eviction credit, and no physical-link, independent, or release acceptance credit is claimed.",
    ),
    "DM-5.1-21": selected_claim(
        "implemented-uncredited", "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; selected Event TTL is source-authenticated, semantic-v3/v4/v5 custody carries checked cumulative age, Linux publication may choose a positive finite TTL, ttl=None remains durable, and selected State/Record/Blob finite TTL is structurally rejected",
        "Finite selected Event publication fails closed on non-Linux targets; State/Record/Blob forwarding age, expiry, and GC, powered-off elapsed-time recovery, physical systems, independent interoperability, and release acceptance remain open.",
    ),
    "DM-5.1-22": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {EVENT_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; retained Ping/Pong plus current-code direct State/Record and v5 Blob contacts authenticate authority-provisioned source identities independently at each endpoint; Blob range service additionally binds the authenticated claimant peer to the current content grant",
        "Only Event has a retained receipt. State/Record/Blob evidence is same-implementation current-code direct-Iroh automation; the Blob case is one-host and 96 KiB. Route-only Blob custody, independent interoperability, physical systems, scale, and release authorization remain open.",
    ),
    "DM-5.2-01": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; retained three- and eight-node loopback lines converged Event transfers, while current-code real-Iroh contacts converged one State inventory, two disconnected Record revisions, and one bounded v5 Blob resumed from a different eligible content peer",
        "Only Event has retained evidence. State/Record/Blob are same-implementation direct-contact automation, not an all-reachable-node result; the Blob is 96 KiB on one host. Multiple-scope lifecycle, route-only Blob custody, long partitions, mixed implementations, physical links, requirement scale, and release authorization remain open.",
    ),
    "DM-5.2-02": selected_claim(
        "implemented-uncredited",
        "aster-redb-store + aster-node",
        f"{EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; durable Event Consume/Carry selectors, explicit semantic-v4/v5 class-separated State/Record interests, and v5 exact Blob topic/scope/epoch selectors with peer-bound current content proofs become mission-protected receiver interests; current-code real-Iroh tests deliver selected objects, while ReceiveOnly and legacy semantic versions expose no inapplicable lane",
        "The tests observe same-implementation bounded flows, not all reachable subscribed nodes or global convergence. No retained multi-class receipt exists; repeated multi-scope lifecycle, route-only Blob custody, long partitions, physical peers, scale, and mixed implementations remain open.",
    ),
    "DM-5.2-06": selected_claim(
        "implemented-uncredited",
        "aster-redb-store + aster-node",
        f"{RECEIPT}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; the live facade durably prepares bounded Event delivery, freshly re-verifies source/content authorization, and commits an attempt before returning it; current-code real processes poll and acknowledge an Event after later synchronization",
        "The retained receipt covers the built-in Event reaction, while generalized live delivery has current-code automated evidence only. Verify unacknowledged real-process crash retry, every other data class, bindings, and independent interoperability.",
    ),
    "DM-5.2-07": selected_claim(
        "implemented-uncredited", "aster-redb-store + aster-node",
        f"{RECEIPT}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; exact transfer replay reuses durable acceptance, the pending ledger repeats an unacknowledged Event by semantic ID, and a current-code real-process receiver restart observes no delivery after acknowledgement",
        "Verify duplicate suppression across live network cycles, unacknowledged crash retry, cyclic topologies, every other data class, bindings, and independent interoperability.",
    ),
    "DM-5.2-08": selected_claim(
        "observed-bounded",
        "aster-redb-store + aster-node",
        f"{RECEIPT}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; peerless cohorts commit under durable operation keys; tests cover subscription replay/conflict, attempt persistence, idempotent acknowledgement, selector removal/replacement, verified gap plans, stale-policy rejection, and receiver restart",
        "The retained receipt still covers only the built-in Event reaction; the generalized live actor has current-code automated evidence but no retained PR-C receipt. Crash injection at every external boundary, other data classes, bindings, and independent implementations remain open.",
    ),
    "DM-5.2-09": selected_claim(
        "observed-bounded", "aster-core + aster-redb-store + aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; an isolated peerless destination publishes causally observing Pong, the durable store rejects dot equivocation, and disconnected Record publishers remain two causal heads after both exact revisions reconcile",
        "Verify broader sequential/concurrent State/Record network projections, Blob causal-convergence acceptance, long partitions, independent interoperability, and scale.",
    ),
    "DM-5.2-10": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-negentropy + aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; Event, State, and Record counters/context are authoritative while class-specific exact transfer IDs reconcile with Negentropy timestamp zero",
        "Verify tombstone propagation, a future State/Record finite-TTL forwarding-age design (currently rejected), long partitions, and long-running operation without trustworthy time.",
    ),
    "DM-5.2-13": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-negentropy",
        f"{EVENT_SLICE}; {MUTABLE_NETWORK_SLICE}; exact Event, State, and Record transfer IDs reconcile with Negentropy timestamp zero while causality uses authenticated counters/context",
        "Verify the wall-clock boundary for Blob, long-running custody, and independent implementations.",
    ),
    "DM-5.2-14": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-negentropy + aster-node",
        f"{EVENT_SLICE}; {MUTABLE_NETWORK_SLICE}; Event order plus State/Record causal projection use authenticated counters/context, not the Negentropy timestamp field",
        "Broader tombstone/conflict cases, Blob, long partitions, and complete independent wire behavior remain to be verified.",
    ),
    "DM-5.2-18": selected_claim(
        "implemented-uncredited",
        "aster-negentropy + aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; bounded identifier-set reconciliation computes differences over class-specific exact Event, State, Record, and semantic-v5 Blob source identities; State/Record use durable peer/class/local-mode strict-successor rotation, Blob requests only an exact missing contiguous carrier complement, and retained Event evidence shows equal inventory transfers nothing",
        "Publish total-size-versus-difference cost evidence across all four classes at requirement scale, physical links, and mixed implementations.",
    ),
    "DM-5.3-01": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{STATE_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; an active version whose authenticated context observes another version's dot dominates it, causal maxima remain active, exact-key query returns the deterministic current, and remote ingest retains the same authenticated causal facts",
        "State crosses same-implementation direct contacts and capacity-deferred work later progresses, but divergent/concurrent State network convergence, expiry/garbage collection, independent interoperability, scale, and retained acceptance remain open.",
    ),
    "DM-5.3-02": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{STATE_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; when active State maxima are concurrent, the greatest complete source-authenticated semantic State ID is current and the other maxima remain explicitly Concurrent; network ingest preserves the same immutable facts and a current tombstone remains visible",
        "The deterministic concurrent tie-break still has current-code local tests only. No delete-wins rule is inferred, and mixed-implementation, divergent cross-node, adversarial-scale, and retained acceptance evidence remain open.",
    ),
    "DM-5.3-06": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; all active causal Record maxima are retained when no automatic merge executes; a real-Iroh contact between two disconnected publishers leaves the same two heads on both independent stores",
        "The selected slice deliberately executes no registered merge policy, and same-implementation direct-contact automation has no retained execution receipt. Add a convergent registered-policy design separately, then verify longer partitions, relays, retention/GC interaction, mixed implementations, scale, and release acceptance.",
    ),
    "DM-5.3-07": selected_claim(
        "implemented-uncredited",
        "aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; exact-key query returns an explicit RecordConflict whenever more than one active causal head exists, with every sorted sibling semantic ID and an opaque exact projection guard; network ingest retains the two-head structure",
        "Conflict annotation is still exposed only through the stopped Rust facade. Live application delivery, language bindings, independent interoperability, and retained acceptance remain open.",
    ),
    "DM-5.3-08": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{RECORD_LOCAL_SLICE}; the high-level RecordProjection exposes Current, Concurrent, optional Superseded, and RecordConflict application fields while omitting sealed bytes, exact transfer identities, causal vectors, provider internals, and store plan tokens",
        "Only the exclusive stopped Rust facade exposes this API. Live Record, selected-node C/Go/Python bindings, independent usability evidence, and retained acceptance remain open.",
    ),
    "DM-5.3-09": selected_claim(
        "implemented-uncredited",
        "aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; ordinary publish fails atomically across multiple heads, guarded resolution must observe the exact complete sibling set, and a real-Iroh contact preserves both disconnected revisions on both stores without merge execution",
        "The one same-implementation direct-contact test has no retained execution receipt. Verify crashes at external boundaries, longer partitions and relays, automatic merge if later added, mixed implementations, adversarial scale, and release acceptance.",
    ),
    "DM-5.3-10": selected_claim(
        "implemented-uncredited",
        "aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; causally dominated active Record revisions remain durably retained and are returned in the optional Superseded lane after fresh verification; guarded resolution turns every inspected head into recoverable history and network ingest never executes merge code",
        "The slice rejects at its per-key bound rather than silently evicting, but explicit-policy garbage collection is not implemented. Add retention/GC policy and verify networked superseded history, restart, expiry, scale, and acceptance.",
    ),
    "DM-5.3-04": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; {BLOB_NETWORK_SLICE}; immutable Blob bytes and identity metadata never enter the State/Record causal merge reducers, multiple signed source publications can reference one exact completed content variant without changing it, and semantic-v5 remote source/carrier staging remains outside ordinary publication indexes until exact atomic completion",
        "The network mechanism is one small same-implementation direct case. Route-only relay/custody, adversarial multi-writer interoperability, retention/GC policy, pure-byte identity, scale/resource/physical evidence, mixed implementations, and acceptance remain open.",
    ),
    "DM-5.4-01": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{PROFILE_EVIDENCE}; {CUSTODY_SLICE}; the fixed Routine/Priority/Immediate/Flash ordinals are source authenticated and used by the selected Event scheduler",
        "The exact count and names remain provisional pending stakeholder and service-doctrine approval; State, Record, Blob, and generic cross-class pressure remain outside selected custody.",
    ),
    "DM-5.4-05": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; EventPublishRequest requires the publisher to choose one priority and the source envelope authenticates it through storage and forwarding",
        "Selected evidence is Event/RouteEvent-only and same-implementation; stakeholder priority-name governance, other classes, bindings, and acceptance remain open.",
    ),
    "DM-5.4-09": selected_claim(
        "implemented-uncredited",
        "aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; one bounded bulk scheduler orders eligible semantic-v3/v4/v5 Event/RouteEvent custody by source priority, remaining TTL, acceptance order, and exact identity before leasing and final send rechecks",
        "Evidence is selected Event-only and loopback automated testing; v1/v2 deterministic partial behavior, physical links, many-node scale, mixed implementations, and other classes remain open.",
    ),
    "DM-5.4-10": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; retry_delay_ms and the bounded retry ledger give higher authenticated Event priority an earlier deterministic retry cadence while exact leases and acknowledgements suppress duplicate work",
        "This is selected Event/RouteEvent mechanism evidence, not physical-loss, long-disconnection, many-peer, cross-class, or retained acceptance evidence.",
    ),
    "DM-5.4-12": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; priority and optional TTL are independent source-authenticated Event fields and neither the scheduler nor custody merge derives or rewrites one from the other",
        "The mechanism is Event-only; State, Record, Blob, bindings, physical systems, mixed implementations, and release acceptance remain open.",
    ),
    "DM-5.4-13": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; for non-tombstone finite-TTL Event/RouteEvent data, age greater than or equal to source TTL is withheld in inventory, load, lease, carrier-adjacent final checks, and final application query/poll/gap exposure",
        "Finite Event custody is Linux-only and requires semantic v3, v4, or v5; selected clock-domain loss is sticky and requires an application-specific replacement or new source revision. Selected State/Record/Blob finite TTL is rejected; physical links, other classes, and retained acceptance remain open.",
    ),
    "DM-5.4-14": selected_claim(
        "implemented-uncredited",
        "aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; bounded maintenance marks known-expired Event/RouteEvent custody unavailable, drains protected leases safely, removes exact payload bytes, and retains permanent receiver fences with audited restart state",
        "Collection is selected Event/RouteEvent-only. State, Record, Blob, physical allocation, long-duration evidence, and release acceptance remain open.",
    ),
    "DM-5.4-15": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; SelectedForwardingConfig and the live RunningNode policy expose Normal, AtLeast, and ReceiveOnly with revision checks at object send and receive-commit boundaries; Normal/AtLeast run v4/v5 State/Record and may run v5 Blob because AtLeast is Event-only, while ReceiveOnly exposes neither mutable nor Blob work",
        "AtLeast does not create State/Record/Blob custody priority. Physical RF silence, carrier-wide policy, route-only Blob custody, bindings, and operational acceptance remain open.",
    ),
    "DM-5.4-16": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; EventEmissionPolicy::AtLeast applies one explicit source-priority floor to every selected Event offer with carrier-adjacent live revision closure; configured contacts, required protocol/control work, semantic-v4/v5 State/Record lanes, and eligible v5 Blob work continue",
        "No topic default, integrator priority rewrite/cap, State/Record/Blob custody priority, policy-driven discovery control, physical proof, language binding, or retained acceptance is claimed.",
    ),
    "DM-5.4-17": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; ReceiveOnly cannot initiate contacts and emits no discovery, local Event inventory/object, control object, State/Record interest/inventory/ID/object, or Blob interest/inventory/source/range/staging/promotion/accounting; protected empty Event inventory replies and bounded authenticated v3/v4/v5 Event offer acknowledgements/results remain permitted",
        "ReceiveOnly may emit mandatory connection authentication and Event acknowledgements/apply results; it is not physical radio silence and has no packet-capture, BTLE, platform, or independent acceptance evidence.",
    ),
    "DM-5.4-18": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; a real semantic-v3/v4/v5 loopback test gives the ReceiveOnly responder an empty disclosed Event inventory while it accepts authenticated finite priority Event offers within interest, route, TTL, and quota policy; semantic-v4/v5 mutable classes and semantic-v5 Blob work are skipped",
        "Evidence is one-host same-implementation automation, not physical, impaired-link, mixed-implementation, long-running, or release acceptance.",
    ),
    "DM-5.4-19": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; selected Rust startup and live-node APIs ship the MVP emission-policy hooks without changing existing NodeConfig literals, and the semantic-v4/v5 mutable plus v5 Blob mode boundaries are fixed beneath that Event-facing enum",
        "Selected-node C/Go/Python live-node bindings, physical/radio acceptance, route-only Blob custody, richer post-MVP policy, and release authorization remain open.",
    ),
    "DM-5.4-21": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{CUSTODY_SLICE}; constrained operation is one three-form emission enum plus source priority, optional TTL, aggregate limits, and exact-scope quota, all with fail-closed validation",
        "The qualitative simplicity claim lacks adopter usability evidence, stakeholder approval, language bindings, physical operation, and release acceptance.",
    ),
    "DM-5.4-22": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; the selected Event matrix is fixed priority, optional positive TTL, and Normal/AtLeast/ReceiveOnly emission, with aggregate and exact-scope bounds rather than an open-ended policy language; v4/v5 State/Record and v5 Blob are durable-only, continue under AtLeast, and are absent under ReceiveOnly",
        "Priority count/names remain provisional; optional defaults/caps/overrides, richer post-MVP policy, State/Record/Blob custody/TTL, bindings, physical evidence, and release acceptance remain open.",
    ),
    "DM-5.5-01": selected_claim(
        "implemented-uncredited", "aster-core + aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {EVENT_SUBSCRIPTION_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; Event, State, Record, and Blob topic/scope are distinct authenticated fields and durable index dimensions; Event uses canonical Consume/Carry selectors, mutable classes use explicit canonical interests, and v5 Blob selectors bind exact topic/scope/epoch plus current peer content proof",
        "Repeated multiple-scope selector lifecycle, bridges, route-only Blob custody, and independent interoperability remain open.",
    ),
    "DM-5.5-02": selected_claim(
        "implemented-uncredited", "aster-redb-store + aster-node",
        f"{EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; bounded canonical Event selectors, explicit State/Record interest sets, and exact v5 Blob selectors carrying peer-bound current content proof become mission-protected receiver interests; empty means receive-none; current-code direct contacts synchronize selected objects",
        "State/Record/Blob interests are runtime configuration rather than durable live application subscriptions. No retained multi-class receipt exists; repeated multi-scope replacement lifecycle, route-only Blob custody, physical peers, scale, and mixed-implementation acceptance remain open.",
    ),
    "DM-5.5-03": selected_claim(
        "implemented-uncredited", "aster-node",
        f"{MISSION_RECEIPT}; {CONTROL_RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; per-contact Event, State, Record, and Blob inventory/transfer are filtered by the authenticated peer's current authority-signed scope/epoch route grant; Blob additionally requires a current claimant-bound content proof and nonrevocation at every send",
        "Verify repeated join/leave and membership churn across multiple scopes, route-only Blob custody policy, physical peers, and independent implementations.",
    ),
    "DM-5.5-05": selected_claim(
        "observed-bounded", "aster-core + aster-redb-store + aster-node",
        f"{RECEIPT}; the intermediate had route access but no topic-content grant, retained exact sealed bytes, and semantically accepted zero Events",
        "The observation covers one Event topic/scope and line topology; generalized relay policy and all other data classes remain open.",
    ),
    "DM-5.5-06": selected_claim(
        "implemented-uncredited", "aster-node",
        f"{MISSION_RECEIPT}; {CONTROL_RECEIPT}; {BLOB_NETWORK_SLICE}; peers without the current authenticated Event scope/epoch route grant learn no matching Event inventory ID; v5 Blob also withholds inventory/source/ranges from peers lacking the exact current route plus claimant-bound content proof",
        "Verify repeated dynamic membership changes, multiple scopes, physical peers, route-only Blob relay/custody policy, and independent implementations.",
    ),
    "DM-5.5-07": selected_claim(
        "implemented-uncredited",
        "aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {CUSTODY_SLICE}; SelectedForwardingConfig installs aggregate StoreLimits and exact-scope CustodyQuota values before readiness; route-only and accepted Event custody share audited ordinary usage and bounded pressure",
        "Logical row/source-byte limits do not measure redb/filesystem allocation. State/Record have fixed 4,096-row/16-MiB per-class fail-closed admission and durable cursor metadata but no custody eviction; Blob network staging is bounded at 10,000 rows/64 MiB but has no TTL/custody pressure or complete physical accounting. Physical sustained-pressure, scale, mixed-implementation, and retained acceptance evidence remain open.",
    ),
    "DM-5.6-01": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; same-implementation nodes synchronized source-sealed Event, State, Record, and one bounded v5 Blob over direct one-host Iroh; the Blob resumed from a different eligible content peer after receiver reopen",
        "Add independent conformance, broader partitions, route-only Blob relay/custody, physical transport, large/resource evidence, and broader network acceptance. Only Event has a retained receipt.",
    ),
    "DM-5.6-02": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{RECEIPT}; direct endpoints ran with relays, discovery, and port mapping disabled",
        "Verify infrastructure-free operation across physical systems and required transports.",
    ),
    "DM-5.6-03": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{RECEIPT}; a three-node line used isolated per-edge cohorts to exact-forward one pre-existing protected Ping or Pong difference through a route-only relay while the publisher process was absent",
        "Verify generalized relay policy, finite custody duration, physical contacts, alternate carriers, and larger/non-line topologies.",
    ),
    "DM-5.6-05": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{RECEIPT}; exact Event duplicate acceptance and durable application operations were reused, and a separate equal-inventory contact transferred nothing",
        "Verify duplicate delivery, cyclic and broadcast loop suppression, and bounded routing over the network.",
    ),
    "DM-5.7-02": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{RECEIPT}; exact CARRIER_ID@IP:PORT=MISSION_NODE_ID peers completed mission-authenticated direct contacts",
        "Add protected operational provisioning, physical systems, and configuration lifecycle evidence.",
    ),
    "DM-5.7-03": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{CUSTODY_SLICE}; the selected direct-Iroh endpoint disables hosted discovery in every emission mode, and ReceiveOnly additionally forbids contact initiation while accepting bounded authenticated inbound v3/v4/v5 Event work and disclosing zero mutable/Blob work",
        "AtLeast still initiates configured contacts, and discovery is not dynamically controlled by its threshold. This is not physical RF silence, packet-capture evidence, BTLE behavior, mixed implementations, or release acceptance.",
    ),
    "DM-5.8-06": selected_claim(
        "implemented-uncredited",
        "aster-iroh + aster-node",
        f"{CONTROLLED_RELAY_SLICE}; the selected Iroh carrier binds direct UDP/QUIC, authenticates the exact endpoint identity, accepts bounded operator-supplied initial IP locators, and current-code real processes complete exact direct contacts while the sole configured controlled relay is unavailable",
        "This is source plus same-implementation one-host loopback automation, not a supported or released IP-adapter acceptance result. Representative physical IP networks, NAT operation, supported-target packaging, mixed implementations, dependency/license admission, retained acceptance, and release authorization remain open.",
    ),
    "DM-5.8-09": selected_claim(
        "implemented-uncredited",
        "aster-iroh + aster-node",
        f"{CONTROLLED_RELAY_SLICE}; one current-code real-process test uses exactly one operator-pinned HTTPS relay with explicit DER trust, gives the initiator an unusable initial direct candidate, disables responder IP, observes Relay at both authenticated endpoints, synchronizes one Event, and repeats as an exact no-op; a separate focused runtime test rejects the wrong expected mission before inventory construction",
        "This is one same-implementation localhost fixture, not representative NAT failure, physical relay service, or a temporal direct-first fallback: Iroh may probe initial paths in parallel and may derive authenticated direct paths later. NAT direct/traversal acceptance, public/default relay operation, mobility/outage recovery, State/Record/Blob-over-relay acceptance, mixed implementations, a retained receipt, and release authorization remain open.",
    ),
    "DM-5.8-10": selected_claim(
        "observed-bounded",
        "aster-iroh",
        f"{RECEIPT}; local direct operation completed with relays, discovery, and port mapping disabled",
        "Verify local and mesh operation on physical systems and all required carriers.",
    ),
    "DM-6-01": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; Event, State, Record, and Blob content remain source-sealed independently of the Iroh carrier session; Blob range service requires current claimant-bound content proof, while retained evidence separately shows an Event route-only relay cannot open content",
        "Only Event has a retained receipt. State/Record/Blob are current-code direct contacts with no Blob route-only relay/custody or packet capture. Complete carrier variants, provisioning, physical/mixed acceptance, and independent review.",
    ),
    "DM-6-02": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{MISSION_RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; exact source-sealed Event, State, Record, and Blob bytes are freshly verified before inventory serving and remote admission; Blob publication additionally requires every canonical carrier plus fresh streamed full-content and current-lineage completion, while Event is reverified before application reaction",
        "Only Event has retained evidence. Complete live State/Record/Blob application delivery, route-only Blob custody, hostile physical-network acceptance, independent interoperability, and cryptographic review.",
    ),
    "DM-6-03": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; destinations authenticate authority-provisioned Event, State, Record, and Blob publishers independently of carrier and session identities; Blob service also binds the authenticated claimant peer to the current content grant",
        "Only Event has retained evidence. Complete generalized live publication, route-only Blob custody, protected provisioning, platform-complete zeroization assurance, broader control lifecycle, physical/mixed acceptance, and independent review.",
    ),
    "DM-6-04": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; isolated Event cohorts, disconnected State/Record test publishers, and the v5 Blob publisher source-seal objects before the corresponding contact; Blob source verification completes before any carrier range",
        "Only Event has retained evidence. State/Record/Blob are same-implementation current-code direct-contact automation. Generalized live publication, route-only Blob custody, key lifecycle beyond one bounded rekey, physical/mixed acceptance, and independent review remain open.",
    ),
    "DM-6-05": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; Event, State, Record, and Blob objects carry authenticated source identities and signed semantic headers; Blob transfer additionally binds the exact manifest, canonical carrier IDs, and current route/physical lineages",
        "Only Event has retained evidence. State/Record/Blob are bounded same-implementation current-code direct-contact automation; generalized publication, route-only Blob custody, physical/mixed evidence, and independent interoperability remain open.",
    ),
    "DM-6-06": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; Event applications react only to content-verified payloads, State/Record remote admission requires exact content verification and never executes application merge code, and partial Blob staging remains nonpublic until fresh full-content verification and atomic promotion",
        "State/Record/Blob have no live application delivery path. Route-only Blob custody, bindings, physical peers, mixed implementations, and independent interoperability remain open.",
    ),
    "DM-6-07": selected_claim(
        "observed-bounded", "aster-core + aster-redb-store + aster-node",
        f"{RECEIPT}; the relay exact-forwarded two source-sealed Events with content_access=denied and semantic_acceptance=none",
        "Verify generalized policies, finite custody, all data classes, physical links, and independent review.",
    ),
    "DM-6-09": selected_claim(
        "implemented-uncredited", "aster-core + aster-node",
        f"{EVENT_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; Event, State, Record, and Blob topic/scope/epoch/causal/routing metadata are inside protected source envelopes; mutable and Blob interest/source/range mechanics, including the opaque peer content proof, are mission-session protected",
        "Publish packet-capture evidence across supported carriers, define route-only Blob custody metadata exposure, and complete physical/mixed interoperability and independent review.",
    ),
    "DM-6-10": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {CONTROL_RECEIPT}; an authenticated route-only relay verified protected Event scope/epoch metadata and forwarded exact epoch-one and epoch-two bytes without content access",
        "Generalize route policy and repeated multi-scope lifecycle across all data classes, bridges, and physical carriers.",
    ),
    "DM-6-11": selected_claim(
        "implemented-uncredited", "aster-core + aster-node",
        f"{EVENT_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; Event, State, Record, and Blob forwarding metadata is source-envelope protected and later mechanics frames are mission-session protected; Blob inventory/source/range service rechecks current peer content proof, route, nonrevocation, and lineages",
        "Complete route-only Blob relay/custody design, packet-capture acceptance, all supported carriers, metadata-length analysis, mixed interoperability, and independent cryptographic review.",
    ),
    "DM-6-12": selected_claim(
        "implemented-uncredited", "aster-core + aster-node",
        f"{EVENT_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; Event, State, Record, and Blob source envelopes plus mission-protected mechanics leave carrier necessities outside their protection boundary; Blob carrier IDs and exact ranges are protected application frames rather than raw grant/key exposure",
        "Define and verify the exact unavoidable-plaintext profile with packet captures across all supported carriers, including any future route-only Blob custody path.",
    ),
    "DM-6-13": selected_claim(
        "observed-bounded",
        "aster-core + aster-node",
        f"{MISSION_RECEIPT}; {CONTROL_RECEIPT}; {PROTECTED_RUNTIME_SLICE}; the runtime checks expected mission NodeId independently from Iroh EndpointId before inventory and rejects a durably revoked mission principal; current live Rust NodeConfig/start_node and stopped Event/admin facades accept protected artifacts or opaque secret references",
        "The retained runtime receipt still uses an unprotected-reference bundle, and the protected live path has current-code automation only. Add a production SecretStore/protection backend, protected stock CLI and bindings, operational identity issuance/recovery, non-Unix and physical zeroization assurance, authority/signer recovery, and independent security acceptance; carrier identity remains deliberately separate.",
    ),
    "DM-6-14": selected_claim(
        "observed-bounded",
        "aster-core + aster-node",
        f"{MISSION_RECEIPT}; {PROTECTED_RUNTIME_SLICE}; the retained runtime requires a bounded owner-only unprotected-reference bundle before state or sockets; current Rust NodeConfig additionally validates options and terminal state before exactly one protected-artifact/provider-reference load, binds one absolute lexical state pathname, and emits only a coarse non-identifying provisioning origin",
        "The observed retained runtime path remains unprotected-reference; protected live startup is current fixture automation only, and the lexical witness is not inode, parent-directory, symlink/rename, or rollback binding. Deliver an admitted production backend, protected stock CLI and bindings, persistent custody plus install/coordinated-destroy workflow, platform-complete zeroization assurance, rollback handling, and operational recovery.",
    ),
    "DM-6-18": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {CONTROL_RECEIPT}; {LIVE_CONTROL_ADMIN_SLICE}; only included members opened epoch-two Ping/Pong while the route-only relay and omitted captured node could not; current recipient-package construction authenticates the registry and canonical recipients before key generation, and a live epoch-two rekey refreshes runtime policy before post-rekey Event publication succeeds",
        "Verify repeated rekeys across multiple topics/scopes, generalized subscriptions, automatic affected-scope remediation, all data classes, and independent security review.",
    ),
    "DM-6-19": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{MISSION_RECEIPT}; {CONTROL_RECEIPT}; {LIVE_CONTROL_ADMIN_SLICE}; a node without the current scope route grant learns no Event ID, a route-only node lacks content access, and the captured node learned no epoch-two data; current code refuses fresh already-revoked rekey recipients and post-revocation legacy recipient-less controls, preserves exact same-signer historical recovery, and refreshes bounded live recipient policy before responding",
        "Complete repeated dynamic multi-scope lifecycle, automatic/atomic revocation remediation, broader compromise cases, all data classes, and independent review.",
    ),
    "DM-6-20": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{CONTROL_RECEIPT}; {CONTROL_SLICE}; the authority process and node were absent while a payload-blind relay forwarded the exact revocation/rekey suffix to a surviving member; current code durably fences authenticated poison descendants and recovers only exact historical locally signed publication receipts",
        "The receipt covers two controls crossing one relay on one-host loopback; the rejection fence and historical-retry behavior have focused current-code automation only. Longer partitions, loss/bandwidth impairment, multiple relays/carriers, broader crash injection, physical systems, and independent implementations remain open.",
    ),
    "DM-6-21": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{CONTROL_RECEIPT}; {LIVE_CONTROL_ADMIN_SLICE}; an authority process committed a recipient-filtered scope transition from epoch one to two and the omitted captured node learned no fresh content; current typed rekey requests bind registry generation, scope, epoch, unique recipients and topic grants, reject an already-revoked fresh recipient, and let the live actor recover the exact receipt after canonical recipient reordering plus a higher minimum-generation witness",
        "One scope advanced once for three exact recipients on loopback; the live actor path has current-code automation only. Revocation and rekey are separate calls with no automatic affected-scope discovery or atomic remediation fence; repeated/multi-scope churn, authority recovery, protected registry administration, physical field evidence, and independent implementations remain open.",
    ),
    "DM-6-22": selected_claim(
        "observed-bounded",
        "aster-node + aster-redb-store + platform security owner",
        f"{ZEROIZATION_RECEIPT}; {PROVISIONING_ADMIN_SLICE}; a same-UID Unix CLI triggered a live child node to drain, terminally lock state, and overwrite/synchronize/truncate two retained inodes; the provider-neutral SecretStore contract separately validates operation/reference-bound logical destroy receipts without claiming physical erasure",
        "The retained receipt covers only the Unix unprotected-reference file path. No production SecretStore backend or coordinated selected-node drain-plus-provider-destroy workflow exists; neither a backend tombstone nor software overwrite proves inode deletion, physical/copy-on-write/snapshot/swap/backup sanitization, redb rollback resistance, remote triggering, non-Unix behavior, or independent platform assurance.",
    ),
    "DM-6-23": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{MISSION_RECEIPT}; {CONTROL_RECEIPT}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {LIVE_CONTROL_ADMIN_SLICE}; protected-frame replay/plaintext, control rollback/fork, stale epoch and revoked-source traffic fail closed; current code fences authenticated rejected-sequence descendants, while live control returns PolicyUnsettled for a pending gap without killing the actor, recovers exact historical receipt through that gap, and retains actor ownership after post-enqueue caller cancellation",
        "The control rejection-fence, pending-gap, historical-retry, and one caller-cancellation boundary have focused current-code automation only. Verify process/power interruption, captured replay across physical sessions, every data class, other live command/contact boundaries, long retention/eviction boundaries, and independent implementations.",
    ),
    "DM-6-25": selected_claim(
        "observed-bounded",
        "aster-node::mission",
        f"{MISSION_RECEIPT}; the runtime completes the existing hybrid four-flight key establishment over real Iroh before inventory",
        "Complete protected provisioning, admitted-module, algorithm-policy, and independent-review gates.",
    ),
    "DM-6-26": selected_claim(
        "observed-bounded",
        "aster-node::mission",
        f"{MISSION_RECEIPT}; the existing hybrid-authenticated session and source-authenticated Event envelopes are used unchanged, and cross-mission credentials fail closed",
        "Complete all data classes, protected provisioning, algorithm-policy/admitted-module gates, and independent review.",
    ),
    "DM-7-09": selected_claim(
        "implemented-uncredited",
        "aster-agent",
        f"{AGENT_SLICE}; a separate process owns the running selected node and serves its live Event authority through an authenticated loopback application listener",
        "This is an alpha same-host agent without protected mission provisioning, credential rotation/reload, OS socket identity, supported-target packaging, production deployment acceptance, or live State/Record/Blob operations.",
    ),
    "DM-7-10": selected_claim(
        "implemented-uncredited",
        "aster-agent",
        f"{AGENT_SLICE}; the repository-owned v1alpha1 Protobuf service accepts Connect, gRPC, and gRPC-Web calls without requiring the Buf Schema Registry",
        "Only same-implementation Connect client evidence exists. Independent gRPC/gRPC-Web clients, supported-target packaging, protected provisioning, and production local-IPC acceptance remain open.",
    ),
    "DM-7-11": selected_claim(
        "implemented-uncredited",
        "aster-node::application + aster-agent",
        f"{EVENT_LIVE_SLICE}; {AGENT_SLICE}; SelectedEventHandle and the authenticated agent expose typed publish, query, subscribe, poll/stream, acknowledge, unsubscribe, authenticated gaps, sync status, and peer status with sanitized errors",
        "This is an Event-only partial boundary. State/Record/Blob, conflict annotations, control/provisioning administration, selected-node bindings, and the complete adopter-facing API remain open.",
    ),
    "DM-7-14": selected_claim(
        "implemented-uncredited",
        "aster-node::application",
        f"{EVENT_LIVE_SLICE}; {AGENT_SLICE}; SelectedEventHandle and agent operations/results contain no carrier type, endpoint, address, path choice, or transport selection",
        "Node startup still requires separate direct-Iroh configuration, and the complete multi-class API, bindings, and future multi-carrier composition require the same boundary audit.",
    ),
    "DM-7-15": selected_claim(
        "implemented-uncredited",
        "aster-node::application",
        f"{EVENT_LIVE_SLICE}; {AGENT_SLICE}; the live Event and agent surfaces return application items, delivery attempts, verified gap intervals, and high-level last-contact status without exposing inventories, exact transfer IDs, Negentropy state, or contact protocol frames",
        "Complete and audit the same abstraction across State/Record/Blob, conflict workflows, bindings, and control administration.",
    ),
    "DM-7-16": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{CONTROL_RECEIPT}; {EVENT_SLICE}; {EVENT_LIVE_SLICE}; after epoch-two control convergence one retained cohort published Ping with peers=0 and contacts=0, and the generalized live handle publishes arbitrary authorized Events while no peer is configured",
        "The generalized live path has current-code automated evidence only. Compose every data class, stakeholder-set offline intervals, and selected-node bindings.",
    ),
    "DM-7-17": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{RECEIPT}; {EVENT_LIVE_SLICE}; the retained built-in flow published while peerless and synchronized later; a separate current-code process test publishes through SelectedEventHandle with no peer, restarts the publisher for contact, and polls/acks at the receiver",
        "The generalized live path has no retained PR-C receipt. Stakeholder-set offline duration, other classes, physical systems, no-loss acceptance, and independent interoperability remain open.",
    ),
    "DM-7-18": selected_claim(
        "implemented-uncredited",
        "aster-node + aster-agent + shipped documentation",
        f"{EVENT_LIVE_SLICE}; {AGENT_SLICE}; docs ship runnable embedded and 35-line local-agent examples, complete high-level Event paths, conservative delivery/gap/status semantics, and focused real-node tests",
        "Compilation and automated tests are not an independent developer-usability study; other data classes, selected-node bindings, operational provisioning, production packaging, and the complete integration surface remain open.",
    ),
    "DM-7-20": selected_claim(
        "observed-bounded",
        "aster-node + aster-agent",
        f"docs/quickstart/mesh-cli.md; {EVENT_LIVE_SLICE}; {CUSTODY_SLICE}; {AGENT_SLICE}; the shipped CLI runs bounded source-authenticated Event Ping/Pong, compiled examples exercise high-level Event publication, delivery, custody configuration, quota, and live emission-policy revision, and the 35-line agent sample performs status, subscribe, offline publish, poll, and acknowledge",
        "The retained observation predates the agent sample. Add an independent usability exercise, live/running-node State/Record and Blob samples over their existing network lanes, selected-node bindings, operational provisioning, Linux/physical custody execution, and physical multi-system instructions/evidence.",
    ),
    "DM-8-01": selected_claim(
        "observed-bounded",
        "selected Rust workspace",
        "cargo +1.91.0 check --locked --offline --workspace --all-targets --all-features and selected control/Event/runtime tests passed; the locked/offline Darwin-arm64 Mach-O is 8776928 bytes with SHA-256 c905ffadb6481b2fa947c88ba60141b8117094b0836271a05a23fc07ab4a0a65",
        "Repeat static-build and target acceptance for every supported release target after the full semantic migration; artifact identity is not release authorization.",
    ),
    "DM-8-02": selected_claim(
        "observed-bounded",
        "selected Rust workspace",
        "Cargo.toml designates the selected crates as Rust; cargo +1.91.0 check --locked --offline --workspace --all-targets --all-features passed",
        "Retain Rust as the core-framework language through full semantic migration and release packaging.",
    ),
    "DM-8-05": selected_claim(
        "open",
        "dependency-policy owner",
        f"{DEPENDENCY_GATE}; exact CDLA trust-root packages remain unadmitted and browser-WASM target policy is unresolved",
        "Obtain exact package/version legal-policy disposition and supported-target decision, or implement an approved trust-root path; no exception has been added.",
    ),
    "DM-9-13": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; {BLOB_NETWORK_SLICE}; read_into freshly verifies the selected publication and completed depot variant, then streams independently authenticated plaintext chunks into a caller-owned writer; semantic-v5 transport accepts canonical carrier data only in contiguous ranges no larger than 16 KiB and verifies the complete Blob before publication",
        "The application reader remains stopped and synchronous. The network case is only 96 KiB and does not establish live delivery, route-only custody, large/RSS behavior, carrier switching, physical-disk acceptance, platform breadth, mixed implementations, or retained resource evidence.",
    ),
    "DM-9-14": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; {BLOB_NETWORK_SLICE}; preparation uses one bounded zeroizing plaintext chunk buffer and a one-MiB-manifest-bounded digest vector; the core streaming engine reports its peak chunk-buffer capacity, store adapters are independently chunk-bounded, and semantic-v5 transfer bounds each accepted range at 16 KiB without granting visibility until freshly streamed whole-content verification",
        "The public metric is the core reader's buffer, not whole-operation peak memory; adapters and runtime may hold other bounded buffers. Current evidence uses modest local fixtures and one 96-KiB network case. Add bracketed process RSS on supported targets, 100+ MiB network transfer, physical storage/resource accounting, mixed implementations, and retained acceptance before crediting the full resource target.",
    ),
    "DM-9-21A": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{N32_RECEIPT}; an operator-attested Cargo release-profile binary run for the signed current-tree source completed the selected one-host direct-loopback Event line at N=32 with 32 distinct mission identities and stores, 65 exact cohorts, 158 exact-named executions with distinct READY PIDs, 30 payload-blind intermediates, and 32 distinct log-observed READY PIDs in the final zero-difference no-op",
        "This is one same-build, same-implementation, one-scope/authority/topic, line-topology observation on one macOS arm64 host. It is not the bracketed at-least-100-node target, a full 2-through-32 range sweep, distributed or physical scale, NAT/relay/BTLE/cross-transport evidence, independent interoperability, or resource-threshold/release acceptance.",
    ),
    "DM-9-24": selected_claim(
        "implemented-uncredited",
        "aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; StoreLimits bound accounted aggregate namespaces while custody quotas, table caps, schedulers, retry/receipt/lease caps, authority reserve, and permanent-fence reserve fail closed at selected Event boundaries; State/Record cap objects at 1 MiB and each class at 4,096 rows/16 MiB, while v5 Blob network admission is 64 MiB/1,024 chunks and pending staging is 10,000 rows/64 MiB with 16-KiB range service",
        "Accepted-dot, aggregate causal-frontier domains, and Event-position/high-water ledgers lack a complete retirement bound. State/Record/Blob have no complete GC/custody pressure or physical allocation accounting. Hostile unrelated files, snapshots/backups/swap, long pressure, scale, mixed implementations, and release acceptance remain open.",
    ),
    "DM-9-25": selected_claim(
        "implemented-uncredited",
        "aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; SelectedForwardingConfig accepts validated aggregate StoreLimits and deterministic exact-scope CustodyQuota replacements before readiness",
        "Not every hard safety cap is operator-tunable, and there is no selected binding, live administrative quota mutation, physical-capacity accounting, or release evidence.",
    ),
    "DM-11-02": selected_claim(
        "implemented-uncredited",
        "aster-iroh + aster-node",
        f"{CONTROLLED_RELAY_SLICE}; the selected Rust composition and CLI integrate exact authenticated direct IP contacts plus an explicit singleton controlled-relay option, with current-code real-process direct and relay path evidence",
        "The IP mechanism exists, but the complete MVP does not. NAT operation, BTLE, physical and supported-target acceptance, bindings, protected operational provisioning, dependency/license admission, mixed implementations, resource evidence, retained acceptance, and release authorization remain open.",
    ),
    "DM-11-15": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; the selected Event MVP surface includes positive source-authenticated TTL publication, cumulative semantic-v3/v4/v5 custody, exact expiry withholding, collection, and permanent replay fences; selected State/Record/Blob finite TTL is rejected",
        "Finite TTL is Linux-only and Event/RouteEvent-only; State/Record/Blob forwarding age, expiry, custody, and GC, the complete MVP, other platforms/classes, physical acceptance, bindings, protected provisioning, and release gates remain open.",
    ),
    "DM-11-17": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; the selected Event MVP surface includes ReceiveOnly startup/live policy, no initiation or local object disclosure, bounded authenticated semantic-v3/v4/v5 Event inbound ingestion, and zero semantic-v4/v5 State/Record or semantic-v5 Blob interest/inventory/source/object/range/staging/promotion/accounting",
        "This is protocol object-emission control, not physical radio silence; platform/carrier packet-capture, bindings, mixed implementations, and the complete MVP/release gates remain open.",
    ),
    "DM-11-18": selected_claim(
        "open",
        "deployment owner + aster-node",
        f"{MISSION_RECEIPT}; {PROTECTED_RUNTIME_SLICE}; unique mission identities exist and current caller-provided Rust NodeConfig/start_node plus stopped Event/admin facades can authenticate protected or provider-referenced provisioning",
        "The complete MVP, identity issuance and recovery workflow, protected stock CLI and selected-node bindings, production backend, operational receipt, and release gates remain absent; current protected live startup is fixture automation only.",
    ),
    "DM-11-19": selected_claim(
        "open",
        "deployment owner + aster-core + aster-node",
        f"{PROTECTED_RUNTIME_SLICE}; caller-provided live Rust NodeConfig and stopped Event/admin facades can ingest protected or provider-referenced scope/content/control key material through bounded capabilities",
        "The complete MVP, production SecretStore/protection backend, stock CLI and binding composition, unattended-start and recovery policy, coordinated destruction, FIPS/admitted-module decision, retained operational receipt, and release gates remain absent.",
    ),
    "DM-11-20": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{CONTROL_RECEIPT}; {LIVE_CONTROL_ADMIN_SLICE}; durable revocation is present through typed live and stopped Rust administration; current live tests return self-revocation receipt before teardown, retain enqueued work after caller cancellation, and recover exactly through stopped retry",
        "Revocation is present, but the live additions have current-code automation only and the complete MVP, production provisioning/custody backend, protected stock CLI/bindings, cross-process admin IPC, automatic or atomic revoke-plus-rekey remediation, platform-complete zeroization assurance, generalized policy administration, and release gates remain incomplete.",
    ),
    "DM-12-08": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{CONTROL_RECEIPT}; {LIVE_CONTROL_ADMIN_SLICE}; one four-node equivalent scenario revoked a leaf, propagated the exact control suffix without the authority online, rekeyed the affected scope, exchanged epoch-two Events among eligible nodes, and denied two captured-node contacts; current code separately rejects fresh already-revoked recipients and post-revocation legacy recipient-less controls and covers live policy refresh, exact retry, and self-revocation teardown ordering",
        "The observed receipt remains the older one-host direct-Iroh scenario; the live admin seam is current-code automation only. Revocation and rekey are two explicit transactions, not an automatic or atomic remediation workflow; target/physical devices, real partition/loss, operational provisioning/custody, independent implementation/review, and release authorization remain open.",
    ),
    "DM-13-04": selected_claim(
        "implemented-uncredited",
        "aster-iroh + aster-node",
        f"{CONTROLLED_RELAY_SLICE}; aster-iroh exposes bounded direct and singleton controlled-relay IP endpoints, and aster-node composes them into NodeConfig and the selected CLI with exact carrier/mission peer binding and no hosted lookup, public relay fallback, or port mapping",
        "Tracked source and current tests exist, but this is not a versioned production release artifact. Supported-target packaging and stability, physical IP and NAT acceptance, mixed implementation, dependency/license admission and SBOM disposition, retained acceptance, and release authorization remain open.",
    ),
}


RELEVANT_ARTIFACTS = {
    "DM-2-01": "docs/protocol.md; docs/wire.cddl; docs/envelope.md",
    "DM-2-03": "bindings/c; bindings/go; bindings/python",
    "DM-2-04": "docs/bindings/pattern.md",
    "DM-2-07": "docs/conformance.md; crates/aster-conformance; conformance",
    "DM-2-08": "data-mesh-requirements.md",
    "DM-2-09": "data-mesh-requirements.md",
    "DM-2-10": "data-mesh-requirements.md",
    "DM-2-11": "data-mesh-requirements.md",
    "DM-2-12": "data-mesh-requirements.md",
    "DM-2-13": "data-mesh-requirements.md",
    "DM-7-02": "bindings/c",
    "DM-7-03": "docs/bindings/pattern.md",
    "DM-7-04": "docs/bindings/pattern.md; bindings/c; bindings/go; bindings/python",
    "DM-7-09": "crates/aster-agent; docs/quickstart/connect-agent.md",
    "DM-7-10": "proto/aster/application/v1alpha1/aster.proto; crates/aster-agent",
    "DM-7-11": "crates/aster-node/src/application.rs; docs/decisions/0009-public-api-boundary.md",
    "DM-7-14": "crates/aster-node/src/application.rs; docs/decisions/0009-public-api-boundary.md",
    "DM-7-15": "crates/aster-node/src/application.rs; docs/decisions/0009-public-api-boundary.md",
    "DM-7-18": "docs/quickstart/selected-event-api.md; docs/quickstart/connect-agent.md; crates/aster-node/src/application.rs; crates/aster-agent",
    "DM-7-20": "docs/quickstart/mesh-cli.md; docs/quickstart/selected-event-api.md; docs/quickstart/selected-custody-api.md; crates/aster-node/src/application.rs; examples/connect_agent.sh",
    "DM-8-01": "Cargo.toml; Cargo.lock",
    "DM-8-02": "Cargo.toml; Cargo.lock",
    "DM-8-05": "deny.toml; tools/check-dependency-exception-scope.sh",
    "DM-8-16": "docs/decisions/0025-requirements-first-foss-architecture-evaluation.md",
    "DM-8-17": "docs/protocol.md; docs/wire.cddl; docs/conformance.md",
    "DM-8-19": "docs/protocol.md; docs/wire.cddl",
    "DM-10-01": "docs/protocol.md; docs/conformance.md",
    "DM-10-02": "docs/protocol.md; docs/conformance.md",
    "DM-10-03": "docs/protocol.md; docs/conformance.md",
    "DM-10-04": "docs/protocol.md; docs/deprecation-policy.md",
    "DM-10-05": "docs/protocol.md; docs/deprecation-policy.md",
    "DM-10-06": "docs/deprecation-policy.md",
    "DM-13-01": "docs/protocol.md; docs/wire.cddl; docs/envelope.md",
    "DM-13-02": "crates/aster-core; crates/aster-host",
    "DM-13-03": "crates/aster-ffi; bindings/c",
    "DM-13-04": "crates/aster-iroh; crates/aster-node",
    "DM-13-05": "crates/aster-host; crates/aster-ble",
    "DM-13-06": "crates/aster-ffi; bindings/c; bindings/go; bindings/python",
    "DM-13-07": "docs/bindings/pattern.md",
    "DM-13-08": "docs/conformance.md; crates/aster-conformance; conformance",
    "DM-13-09": "docs/quickstart; docs/application-recipes.md",
    "DM-13-10": "examples; docs/quickstart",
    "DM-13-11": "deny.toml; docs/decisions; docs/evaluations/0005",
    "DM-14-20": "docs/evaluations/0005; docs/decisions/0025-requirements-first-foss-architecture-evaluation.md",
    "DM-14-21": "docs/evaluations/0005/responsibility-map.md; docs/decisions/0025-requirements-first-foss-architecture-evaluation.md",
}

PROVEN_SEMANTIC_SOURCES: dict[str, str] = {
    "DM-2-02": "crates/aster-core; crates/aster-host",
    "DM-2-03": "crates/aster-ffi",
    "DM-2-05": "crates/aster-host; crates/aster-ip; crates/aster-ble",
    "DM-2-06": "crates/aster-host",
    "DM-2-14": "crates/aster-core",
    "DM-7-01": "crates/aster-core",
    "DM-7-02": "crates/aster-ffi",
    "DM-7-05": "crates/aster-ffi; bindings/go; bindings/python",
    "DM-7-08": "crates/aster-core",
    "DM-13-02": "crates/aster-core; crates/aster-host",
    "DM-13-03": "crates/aster-ffi",
    "DM-13-04": "crates/aster-host; crates/aster-ip",
    "DM-13-05": "crates/aster-host; crates/aster-ble",
    "DM-13-06": "crates/aster-ffi; bindings/go; bindings/python",
}


def map_semantic_family(
    family: str, numbers: range | tuple[int, ...], source: str
) -> None:
    for number in numbers:
        requirement_id = f"DM-{family}-{number:02d}"
        previous = PROVEN_SEMANTIC_SOURCES.setdefault(requirement_id, source)
        if previous != source:
            raise ValueError(
                f"conflicting proven semantic sources for {requirement_id}: "
                f"{previous!r} versus {source!r}"
            )


# Exact families called out by the retained semantic implementation and its
# tests. These are migration/equivalence sources only, never selected credit.
map_semantic_family(
    "5.1", (1, 2, *range(4, 23)), "crates/aster-core"
)
map_semantic_family("5.2", (8, 9, 10, 13, 14, 15, 16, 17), "crates/aster-core")
map_semantic_family("5.3", range(1, 13), "crates/aster-core")
map_semantic_family("5.4", range(1, 23), "crates/aster-core; crates/aster-host")
map_semantic_family("5.5", range(1, 15), "crates/aster-core; crates/aster-host")
map_semantic_family("5.6", range(1, 7), "crates/aster-core; crates/aster-host")
map_semantic_family("5.7", range(1, 5), "crates/aster-host; crates/aster-ip; crates/aster-ble")
map_semantic_family("5.8", range(1, 12), "crates/aster-host; crates/aster-ip; crates/aster-ble")
map_semantic_family("5.8", (15, 16, 17, 18), "crates/aster-host; crates/aster-ip; crates/aster-ble")
map_semantic_family("6", range(1, 24), "crates/aster-core")
map_semantic_family("6", (25, 26, 29, 30), "crates/aster-core")
map_semantic_family("7", range(11, 19), "crates/aster-core; crates/aster-ffi")


def verify_authority_hashes() -> None:
    for path, expected in (
        (REQUIREMENTS, EXPECTED_REQUIREMENTS_SHA256),
        (MATRIX, EXPECTED_MATRIX_SHA256),
    ):
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise ValueError(
                f"authority hash mismatch for {path.relative_to(ROOT)}: "
                f"expected {expected}, got {actual}; regenerate and review the matrix/ledger"
            )
    ledger = LEDGER.read_text(encoding="utf-8")
    for label, expected in (
        ("Requirements SHA-256", EXPECTED_REQUIREMENTS_SHA256),
        ("Matrix SHA-256", EXPECTED_MATRIX_SHA256),
    ):
        expected_line = f"- {label}: `{expected}`"
        if expected_line not in ledger:
            try:
                ledger_name = str(LEDGER.relative_to(ROOT))
            except ValueError:
                ledger_name = str(LEDGER)
            raise ValueError(
                f"{ledger_name} does not record the bound {label} "
                f"value {expected}"
            )


def verify_mapped_source_paths() -> None:
    tracked_result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    tracked_paths = {
        path
        for path in tracked_result.stdout.decode("utf-8").split("\0")
        if path
    }

    for mapping_name, mapping in (
        ("proven semantic source", PROVEN_SEMANTIC_SOURCES),
        ("relevant artifact", RELEVANT_ARTIFACTS),
    ):
        for requirement_id, sources in mapping.items():
            for source in sources.split("; "):
                if not (ROOT / source).exists():
                    raise ValueError(
                        f"{mapping_name} path for {requirement_id} is missing: {source}"
                    )
                tracked = source in tracked_paths or any(
                    path.startswith(source.rstrip("/") + "/")
                    for path in tracked_paths
                )
                if not tracked:
                    raise ValueError(
                        f"{mapping_name} path for {requirement_id} is not tracked: {source}"
                    )


def read_matrix() -> list[dict[str, str]]:
    with MATRIX.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or "id" not in reader.fieldnames:
            raise ValueError(f"{MATRIX}: missing id column")
        rows = list(reader)
    ids = [row["id"].strip() for row in rows]
    duplicates = sorted(item for item, count in Counter(ids).items() if count > 1)
    if duplicates:
        raise ValueError(f"{MATRIX}: duplicate requirement IDs: {', '.join(duplicates)}")
    if any(not item for item in ids):
        raise ValueError(f"{MATRIX}: blank requirement ID")
    return rows


def read_research_evidence(matrix_ids: set[str]) -> dict[str, str]:
    pointers: dict[str, list[str]] = {requirement_id: [] for requirement_id in matrix_ids}
    unknown_ids: set[str] = set()
    for relative_path in RESEARCH_MAPS:
        path = ROOT / relative_path
        if not path.is_file():
            raise ValueError(f"tracked research requirements map is missing: {relative_path}")
        text = path.read_text(encoding="utf-8")
        mentioned = set(REQUIREMENT_ID.findall(text))
        for shorthand in REQUIREMENT_SHORTHAND.finditer(text):
            family = shorthand.group("family")
            for suffix in shorthand.group("suffixes").split("/"):
                if suffix:
                    mentioned.add(f"DM-{family}-{suffix}")
        for requirement_range in REQUIREMENT_RANGE.finditer(text):
            family = requirement_range.group("family")
            start = int(requirement_range.group("start"))
            end = int(requirement_range.group("end"))
            if end < start:
                raise ValueError(
                    f"descending requirement range in {relative_path}: "
                    f"{requirement_range.group(0)}"
                )
            width = len(requirement_range.group("start"))
            for number in range(start, end + 1):
                mentioned.add(f"DM-{family}-{number:0{width}d}")
        unknown_ids.update(mentioned - matrix_ids)
        for requirement_id in sorted(mentioned & matrix_ids):
            pointers[requirement_id].append(relative_path)
    if unknown_ids:
        raise ValueError(
            "research requirements maps reference IDs absent from matrix: "
            + ", ".join(sorted(unknown_ids))
        )
    return {
        requirement_id: "; ".join(paths) if paths else "none"
        for requirement_id, paths in pointers.items()
    }


def is_provisional(matrix_row: dict[str, str]) -> bool:
    return (
        matrix_row["class"] == "provisional_target"
        or matrix_row["level"] == "provisional"
    )


def semantic_source(matrix_row: dict[str, str]) -> str:
    return PROVEN_SEMANTIC_SOURCES.get(matrix_row["id"], "not-yet-mapped")


def relevant_artifact(matrix_row: dict[str, str]) -> str:
    return RELEVANT_ARTIFACTS.get(matrix_row["id"], "none")


def semantic_evidence(semantic: str) -> str:
    if semantic == "not-yet-mapped":
        return "none"
    evidence: list[str] = []
    for source in semantic.split("; "):
        mapped = {
            "crates/aster-core": "crates/aster-core/src/causal.rs; crates/aster-core/src/engine.rs; crates/aster-core/src/source_event.rs; crates/aster-core/src/crypto/reference.rs; aster-core source tests",
            "crates/aster-host": "crates/aster-host/src; aster-host source tests",
            "crates/aster-ip": "crates/aster-ip/src; aster-ip source tests",
            "crates/aster-ble": "crates/aster-ble/src; aster-ble source tests",
            "crates/aster-ffi": "crates/aster-ffi/src; aster-ffi source tests",
            "bindings/go": "bindings/go; Go binding tests",
            "bindings/python": "bindings/python; Python binding tests",
        }.get(source)
        if mapped is None:
            raise ValueError(f"no semantic evidence mapping for proven source {source!r}")
        evidence.append(mapped)
    return "; ".join(evidence)


def external_gate(matrix_row: dict[str, str]) -> tuple[str, str]:
    requirement_id = matrix_row["id"]
    if requirement_id in EXPLICIT_EXTERNAL_GATES:
        return EXPLICIT_EXTERNAL_GATES[requirement_id]
    if is_provisional(matrix_row):
        return "stakeholder-provisional-target", "stakeholder; requirements owner"
    if matrix_row["phase"] == "governance":
        if requirement_id in {"DM-14-20", "DM-14-21"}:
            return "existing-decision-artifact-review", "architecture owner; stakeholder"
        if requirement_id in {"DM-14-22", "DM-14-23"}:
            return "validated-crypto-module", "security owner; compliance owner"
        if requirement_id in {"DM-7-07", "DM-14-19"}:
            return "stakeholder-binding-selection", "stakeholder; API owner"
        return "stakeholder-governance-decision", "stakeholder; requirements owner"
    return "none", "none"


def semantic_gate(matrix_row: dict[str, str], semantic: str) -> str:
    if matrix_row["id"] in NON_GOAL_IDS:
        return "No implementation-equivalence claim applies to this retained non-goal."
    if matrix_row["id"] in {"DM-14-20", "DM-14-21"}:
        return "No implementation-equivalence claim is inferred from the decision artifacts."
    if semantic == "not-yet-mapped":
        return "No proven retained semantic source is mapped; define implementation and acceptance evidence."
    return "Retain the named proven source until the selected replacement passes equivalent source tests."


def base_row(matrix_row: dict[str, str], research: str) -> dict[str, str]:
    statement = matrix_row["statement"].strip()
    semantic = semantic_source(matrix_row)
    artifact = relevant_artifact(matrix_row)
    gate_kind, gate_owner = external_gate(matrix_row)
    row = {
        "id": matrix_row["id"],
        "level": matrix_row["level"],
        "phase": matrix_row["phase"],
        "requirement_class": matrix_row["class"],
        "final_stack_invariant": matrix_row["final_stack_invariant"],
        "selected_status": "open",
        "selected_owner": "unassigned",
        "selected_evidence": "No selected-production-lane evidence is mapped.",
        "semantic_source": semantic,
        "semantic_evidence": semantic_evidence(semantic),
        "semantic_equivalence_gate": semantic_gate(matrix_row, semantic),
        "relevant_artifact": artifact,
        "research_disposition": (
            "pointer-only-no-production-credit" if research != "none" else "none"
        ),
        "research_evidence": research,
        "disposition": "build-and-verify",
        "gate_kind": gate_kind,
        "gate_owner": gate_owner,
        "remaining_gap": "Implement and verify in the selected production lane: " + statement,
    }

    if matrix_row["id"] in NON_GOAL_IDS:
        row.update(
            {
                "selected_owner": "architecture owner; release owner",
                "disposition": "retained-scope-boundary",
                "remaining_gap": "Retain and verify this non-goal; it is not an affirmative implementation action: " + statement,
            }
        )
    elif matrix_row["phase"] == "future" or matrix_row["level"] == "future":
        row.update(
            {
                "selected_owner": "architecture owner",
                "disposition": "deferred-future-extension-seam",
                "remaining_gap": "Preserve the extension seam without pulling this work into MVP: " + statement,
            }
        )
    elif matrix_row["phase"] == "post-mvp":
        row.update(
            {
                "selected_owner": "product owner",
                "disposition": "deferred-post-mvp",
                "remaining_gap": "Retain as explicit post-MVP work and preserve its extension seam: " + statement,
            }
        )
    elif gate_kind != "none":
        if matrix_row["id"] in {"DM-14-20", "DM-14-21"}:
            row.update(
                {
                    "selected_owner": gate_owner,
                    "disposition": "review-existing-decision-artifact",
                    "remaining_gap": "Review, adopt, or update the named existing decision artifacts against the selected production composition: " + statement,
                }
            )
        elif matrix_row["phase"] == "governance":
            row.update(
                {
                    "selected_owner": gate_owner,
                    "disposition": "stakeholder-governance-gate",
                    "remaining_gap": "The named gate owner must decide or validate this governance obligation; record the disposition before release: " + statement,
                }
            )
        else:
            row.update(
                {
                    "selected_owner": gate_owner,
                    "disposition": "external-gate-and-implementation",
                    "remaining_gap": "Complete the named external gate and any selected implementation work; then verify: " + statement,
                }
            )
    elif semantic != "not-yet-mapped":
        row.update(
            {
                "disposition": "migrate-and-verify",
                "remaining_gap": "Migrate equivalent behavior from the named source, integrate it with the selected composition, and pass equivalent tests: " + statement,
            }
        )
    elif artifact != "none":
        row.update(
            {
                "disposition": "retain-artifact-and-build",
                "remaining_gap": "Retain the named non-credit artifact as authority, product input, or prior work; complete and verify the selected obligation: " + statement,
            }
        )
    elif research != "none":
        row.update(
            {
                "disposition": "research-informed-build-and-verify",
                "remaining_gap": "Use the named research only as non-credit input; implement and verify in the selected production lane: " + statement,
            }
        )
    return row


def expected_rows(matrix_rows: list[dict[str, str]]) -> list[dict[str, str]]:
    matrix_ids = {row["id"] for row in matrix_rows}
    mapped_ids = (
        set(SELECTED_OVERRIDES)
        | set(PROVEN_SEMANTIC_SOURCES)
        | set(RELEVANT_ARTIFACTS)
    )
    unknown = sorted(mapped_ids - matrix_ids)
    if unknown:
        raise ValueError("mapped IDs absent from matrix: " + ", ".join(unknown))
    research_by_id = read_research_evidence(matrix_ids)
    rows: list[dict[str, str]] = []
    for matrix_row in matrix_rows:
        row = base_row(matrix_row, research_by_id[matrix_row["id"]])
        override = SELECTED_OVERRIDES.get(matrix_row["id"])
        if override is not None:
            row.update(override)
            if row["selected_status"] != "open":
                row["disposition"] = "continue-selected-implementation"
            elif matrix_row["id"] == "DM-8-05":
                row["disposition"] = "dependency-admission-block"
        rows.append(row)
    return rows


def write_trace(rows: list[dict[str, str]]) -> None:
    TRACE.parent.mkdir(parents=True, exist_ok=True)
    with TRACE.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def validate_trace(expected: list[dict[str, str]]) -> list[str]:
    if not TRACE.is_file():
        return [f"missing trace: {TRACE}"]
    with TRACE.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        actual_fields = tuple(reader.fieldnames or ())
        actual = list(reader)
    errors: list[str] = []
    if actual_fields != FIELDS:
        return [f"unexpected columns: got {actual_fields!r}, expected {FIELDS!r}"]

    actual_ids = [row["id"].strip() for row in actual]
    duplicates = sorted(item for item, count in Counter(actual_ids).items() if count > 1)
    if duplicates:
        errors.append("duplicate trace IDs: " + ", ".join(duplicates))
    expected_ids = {row["id"] for row in expected}
    actual_id_set = set(actual_ids)
    missing = sorted(expected_ids - actual_id_set)
    extra = sorted(actual_id_set - expected_ids)
    if missing:
        errors.append("missing trace IDs: " + ", ".join(missing))
    if extra:
        errors.append("extra trace IDs: " + ", ".join(extra))

    selected_non_open_ids: set[str] = set()
    for row_number, row in enumerate(actual, start=2):
        if row["selected_status"] not in VALID_SELECTED_STATES:
            errors.append(f"row {row_number} {row['id']!r}: invalid selected state {row['selected_status']!r}")
        if row["selected_status"] != "open":
            selected_non_open_ids.add(row["id"])
        blank_fields = [field for field in FIELDS if not row[field].strip()]
        if blank_fields:
            errors.append(f"row {row_number} {row['id']!r}: blank fields {', '.join(blank_fields)}")

    expected_non_open_ids = {
        requirement_id
        for requirement_id, override in SELECTED_OVERRIDES.items()
        if override["selected_status"] != "open"
    }
    if selected_non_open_ids != expected_non_open_ids:
        errors.append(
            "selected non-open status escaped the exact mapped set; "
            f"missing={sorted(expected_non_open_ids - selected_non_open_ids)!r} "
            f"extra={sorted(selected_non_open_ids - expected_non_open_ids)!r}"
        )

    if not duplicates and not missing and not extra:
        expected_by_id = {row["id"]: row for row in expected}
        for row in actual:
            expected_row = expected_by_id[row["id"]]
            for field in FIELDS[1:]:
                if row[field] != expected_row[field]:
                    errors.append(
                        f"{row['id']} {field}: trace differs from conservative generated value; update the mapping and regenerate"
                    )
    return errors


def print_counts(rows: list[dict[str, str]]) -> None:
    statuses = Counter(row["selected_status"] for row in rows)
    dispositions = Counter(row["disposition"] for row in rows)
    semantic_mapped = sum(row["semantic_source"] != "not-yet-mapped" for row in rows)
    artifact_mapped = sum(row["relevant_artifact"] != "none" for row in rows)
    research_mapped = sum(row["research_evidence"] != "none" for row in rows)
    research_pointers = sum(
        len(row["research_evidence"].split("; "))
        for row in rows
        if row["research_evidence"] != "none"
    )
    gated = sum(row["gate_kind"] != "none" for row in rows)
    print(f"requirements trace valid: {len(rows)} matrix IDs, {len(SELECTED_OVERRIDES)} exact selected mappings")
    print("selected_status: " + ", ".join(f"{key}={statuses[key]}" for key in sorted(statuses)))
    print(
        f"source coverage: proven-semantic={semantic_mapped}, semantic-unmapped={len(rows) - semantic_mapped}, "
        f"relevant-artifact={artifact_mapped}, "
        f"research-mapped={research_mapped}, research-none={len(rows) - research_mapped}, "
        f"research-pointers={research_pointers}, external-gated={gated}"
    )
    print("disposition: " + ", ".join(f"{key}={dispositions[key]}" for key in sorted(dispositions)))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="regenerate before validating")
    args = parser.parse_args()
    try:
        verify_authority_hashes()
        verify_mapped_source_paths()
        expected = expected_rows(read_matrix())
        if args.write:
            write_trace(expected)
        errors = validate_trace(expected)
    except (OSError, csv.Error, ValueError) as error:
        print(f"requirements trace validation failed: {error}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"requirements trace validation failed: {error}", file=sys.stderr)
        return 1
    print_counts(expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
