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
NAT_RECEIPT = (
    "docs/implementation/requirements-status.md#selected-iroh-nat-retained-receipt"
)
LIVE_EVENT_RECEIPT = (
    "docs/implementation/requirements-status.md#selected-live-event-retained-receipt"
)
LIVE_STATE_SUBSCRIPTION_RECEIPT = (
    "docs/implementation/requirements-status.md#selected-live-state-subscription-retained-receipt"
)
LIVE_RECORD_SUBSCRIPTION_RECEIPT = (
    "docs/implementation/requirements-status.md#selected-live-record-subscription-retained-receipt"
)
LIVE_MUTABLE_RECEIPT = (
    "docs/implementation/requirements-status.md#selected-live-state-and-record-retained-receipt"
)
LIVE_BLOB_RECEIPT = (
    "docs/implementation/requirements-status.md#selected-live-blob-retained-receipt"
)
LINUX_CUSTODY_RECEIPT = (
    "docs/implementation/requirements-status.md#selected-linux-event-custody-retained-receipt"
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
STATE_SUBSCRIPTION_SLICE = (
    "crates/aster-redb-store/src/state_subscription.rs; "
    "crates/aster-redb-store/src/lib.rs; "
    "crates/aster-node/src/application.rs; "
    "crates/aster-node/src/application/state.rs; "
    "crates/aster-node/src/runtime.rs; "
    "docs/quickstart/selected-state-api.md"
)
RECORD_SUBSCRIPTION_SLICE = (
    "crates/aster-redb-store/src/record_subscription.rs; "
    "crates/aster-redb-store/src/lib.rs; "
    "crates/aster-node/src/application.rs; "
    "crates/aster-node/src/application/record.rs; "
    "crates/aster-node/src/runtime.rs; "
    "crates/aster-node/src/lib.rs; "
    "docs/quickstart/selected-record-api.md"
)
EVENT_LIVE_SLICE = (
    "crates/aster-node/src/application.rs; crates/aster-node/src/runtime.rs; "
    "crates/aster-node/src/lib.rs; "
    "crates/aster-node/examples/live_event_application.rs; "
    "crates/aster-node/tests/mesh_cli.rs::"
    "offline_publish_later_real_process_sync_poll_ack_and_restart; "
    "docs/quickstart/selected-event-api.md"
)
LIVE_EVENT_ACCEPTANCE_SLICE = (
    "crates/aster-node/examples/live_event_acceptance.rs; "
    "tools/run-selected-live-event.py; "
    "tools/check-selected-live-event-receipt.py; "
    "tools/test-selected-live-event-receipt.py; "
    "docs/implementation/evidence/selected-live-event-c464129.json"
)
LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE = (
    "crates/aster-node/examples/live_state_subscription_acceptance.rs; "
    "tools/run-selected-live-state-subscription.py; "
    "tools/check-selected-live-state-subscription-receipt.py; "
    "tools/test-selected-live-state-subscription-receipt.py; "
    "docs/implementation/evidence/selected-live-state-subscription-8912fc3.json"
)
LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE = (
    "crates/aster-node/examples/live_record_subscription_acceptance.rs; "
    "tools/run-selected-live-record-subscription.py; "
    "tools/check-selected-live-record-subscription-receipt.py; "
    "tools/test-selected-live-record-subscription-receipt.py; "
    "docs/implementation/evidence/selected-live-record-subscription-0c11344.json"
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
LINUX_CUSTODY_ACCEPTANCE_SLICE = (
    "crates/aster-node/examples/linux_event_custody_acceptance.rs; "
    "tools/run-selected-linux-event-custody.py; "
    "tools/check-selected-linux-event-custody-receipt.py; "
    "tools/test-selected-linux-event-custody-receipt.py; "
    "docs/implementation/evidence/selected-linux-event-custody-ade6ee1.json"
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
LIVE_MUTABLE_SLICE = (
    "crates/aster-node/src/application.rs; "
    "crates/aster-node/src/application/state.rs; "
    "crates/aster-node/src/application/record.rs; "
    "crates/aster-node/src/runtime.rs; crates/aster-node/src/lib.rs; "
    "crates/aster-node/examples/live_mutable_acceptance.rs; "
    "tools/run-selected-live-mutable.py; "
    "tools/check-selected-live-mutable-receipt.py; "
    "tools/test-selected-live-mutable-receipt.py; "
    "docs/implementation/evidence/selected-live-mutable-6cabb4c.json; "
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
    "network_blob_reservation_deduplicates_and_terminal_abort_retains_bounded_staging; "
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
    "stale_pending_blob_cleanup_removes_visibility_but_retains_reserved_staging; "
    "crates/aster-node/src/runtime.rs::tests::"
    "pending_blob_abort_reconciles_concurrent_exact_restage_without_restart; "
    "crates/aster-node/src/runtime.rs::tests::"
    "blob_lifecycle_lock_serializes_delayed_projection_insert_and_abort; "
    "crates/aster-node/src/runtime.rs::tests::"
    "terminal_blob_poison_advances_scheduler_past_source_to_later_candidate; "
    "docs/protocol.md#92-selected-semantic-v5-direct-blob-transfer; "
    "docs/quickstart/selected-blob-api.md"
)
BLOB_LIVE_SLICE = (
    "crates/aster-node/src/application.rs; "
    "crates/aster-node/src/application/blob.rs; "
    "crates/aster-node/src/runtime.rs; crates/aster-node/src/lib.rs; "
    "crates/aster-node/src/application/blob.rs::tests::"
    "live_blob_page_is_bounded_exact_and_rejects_invalid_ranges; "
    "crates/aster-node/src/application/blob.rs::tests::"
    "live_blob_commands_reject_exactly_when_closed_or_saturated; "
    "crates/aster-node/src/application/blob.rs::tests::"
    "live_blob_handle_rejects_oversized_request_before_enqueuing_file; "
    "crates/aster-node/src/application/blob.rs::tests::"
    "live_blob_file_requires_zero_cursor_and_growth_cannot_cross_ceiling; "
    "crates/aster-node/src/application/blob.rs::tests::"
    "live_blob_second_pass_change_leaves_only_bounded_unfinalized_staging; "
    "crates/aster-node/src/runtime.rs::tests::"
    "live_selected_blob_is_bounded_durable_idempotent_and_closes_admission; "
    "crates/aster-node/src/runtime.rs::tests::"
    "live_selected_blob_rekey_retry_lineage_and_restart_are_exact; "
    "crates/aster-node/src/runtime.rs::tests::"
    "live_selected_blob_converges_over_direct_iroh_and_restarts_peerless; "
    "crates/aster-node/src/runtime.rs::tests::"
    "live_blob_page_withholds_plaintext_when_rekey_linearizes_mid_operation; "
    "crates/aster-node/src/runtime.rs::tests::"
    "live_zeroization_closes_every_application_admission_before_erasure"
)
LIVE_BLOB_ACCEPTANCE_SLICE = (
    "crates/aster-node/examples/live_blob_acceptance.rs; "
    "tools/run-selected-live-blob.py; "
    "tools/check-selected-live-blob-receipt.py; "
    "tools/test-selected-live-blob-receipt.py; "
    "docs/implementation/evidence/selected-live-blob-044d90f.json; "
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
SELECTED_NAT_SLICE = (
    "crates/aster-iroh/src/lib.rs; crates/aster-node/src/runtime.rs; "
    "crates/aster-node/src/main.rs; crates/aster-lab/src/selected_nat_main.rs; "
    "crates/aster-lab/src/selected_relay_main.rs; lab/Dockerfile.selected-nat; "
    "lab/orchestrate.py; tools/check-selected-iroh-nat-receipt.py"
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
        f"{RECEIPT}; {LIVE_BLOB_RECEIPT}; direct Iroh contacts moved exact source-sealed Events between mission-authenticated peers, and a separate retained live Blob run seeded one completed two-chunk authenticated Blob, interrupted a second receiver after one range, preserved that progress across reopen, and completed it from the distinct seeded peer",
        "The retained observations are small same-implementation one-host loopback cases. State and Record retain separate bounded evidence; route-only Blob custody, physical systems, mixed implementations, generalized policy, and scale remain open.",
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
        f"{RECEIPT}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {LIVE_BLOB_RECEIPT}; stopped and restarted processes reconciled exact source-sealed Event inventories and reused durable reaction operations; two live peers separately published concurrent State and Record versions while peerless, then eight positive direct-only contacts transferred seven exact mutable items and converged both actors on one State tombstone over three superseded predecessors plus one resolved Record over two superseded siblings before one immediate peerless restart reproduced both exact projections; a separate live Blob publisher committed while peerless, seeded a replica, and a receiver retained one-range progress across graceful reopen before the distinct replica supplied the exact remaining complement and the final peerless reopen reproduced the authenticated pages",
        "The mutable causal observation/publication order is producer-attested, and its restart covers one immediate graceful peerless reopen rather than an extended retention interval, OS-process crash, power loss, compaction, or garbage collection. Verify the stakeholder-set extended or day-scale disconnection interval, route-only or arbitrary-peer custody, physical systems, generalized policy, mixed implementations, and requirement scale.",
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
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{STATE_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; SelectedStateNode and the actor-owned cloneable SelectedStateHandle source-seal and durably publish bounded State versions, query one exact topic/scope/logical-key projection without exposing sealed representations or provider internals, reconcile explicit interests under semantic-v4/v5 class/direction lanes, and durably subscribe, poll, acknowledge, and unsubscribe positive Current projections; the retained State-subscription run exercised peerless concurrent origins, direct reconciliation, a causally observing successor, an authenticated empty tombstone, forced receiver-process termination after a flushed unacknowledged poll, exact attempt-two fresh-process redelivery, idempotent acknowledgement, final empty delivery state, and one immediate peerless reopen",
        "The retained State runs are same-implementation, one-host, two-participant observations; causal observation/publication order is producer-attested, and restart covers one immediate peerless reopen rather than indefinite tombstone retention, compaction, or garbage collection. Application subscriptions are intentionally separate from configured network interests and deliver positive Current versions rather than Current-to-None withdrawal. Blob delivery, language bindings, selected relay cache, finite State TTL, physical carriers, mixed implementations, scale, and release acceptance remain open. Selected finite State TTL remains structurally rejected.",
    ),
    "DM-5.1-02": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{STATE_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; authenticated State dots and causal context share the selected Event publisher frontier, and the retained run first kept two peerless publications as exact Current/Concurrent maxima, then projected node-a's counter-four successor as Current with both observed initial versions Superseded on both actors, and finally projected node-b's counter-three empty tombstone as Current with the successor and both originals Superseded on both actors and after one immediate peerless restart",
        "This is one exact four-version, same-implementation, one-host, two-participant direct-Iroh schedule. The causal observation/query-before-publication order is producer-attested rather than independently reconstructed from public causal vectors, and restart covers one immediate graceful peerless reopen rather than an extended retention, compaction, or garbage-collection interval. Multi-hop and longer partitions, competing successors or tombstones, independent interoperability, physical systems, scale, and release acceptance remain open.",
    ),
    "DM-5.1-04": selected_claim(
        "observed-bounded", "aster-core + aster-redb-store + aster-node",
        f"{RECEIPT}; {EVENT_SLICE}; {EVENT_LIVE_SLICE}; the built-in sample and high-level live handle publish, source-seal, store, transfer, freshly verify, query, and durably deliver Event objects",
        "The retained receipt covers the built-in Event sample; the generalized live-handle later-sync path has current-code automated loopback evidence only. Other data classes and independent wire interoperability remain open.",
    ),
    "DM-5.1-08": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; SelectedRecordNode and the actor-owned cloneable SelectedRecordHandle source-seal and durably publish bounded revisions, query current/concurrent/superseded projections, expose exact conflicts, reject ordinary publication across multiple heads, accept only exact-sibling guarded application resolution, and durably subscribe, poll, acknowledge, and unsubscribe whole-key active-head projections; the retained Record-subscription run delivered a peerless Current tombstone, later delivered one complete two-head edit/tombstone conflict at delivery_limit=1, preserved its projection identity across forced SIGKILL and fresh-process attempt-two replay while rotating the 89-byte token, accepted exact acknowledgement and reacknowledgement, rejected malformed and cross-binding tokens, required a fresh query-only guard for exact resolution, delivered the successor under a new projection, kept both superseded siblings query-only, and retained the subscription plus empty acknowledged state through a final peerless reopen",
        "This is one same-implementation, one-host, two-participant direct-loopback observation with three processes and one forced SIGKILL after a flushed poll; it is not power-loss or filesystem-crash recovery. Source-to-binary execution linkage, Record causal observation/publication order, and secret custody retain the receipt's operator-attested or metadata-only limits. The run proves one immediate reopen, not finite TTL, long retention, compaction, or garbage collection; hidden conflict IDs do not disclose or authorize hidden lineage. Language bindings, automatic registered-policy merge, selected relay cache, physical carriers, NAT/relay/BTLE, mixed implementations, scale/resource/soak brackets, and release acceptance remain open. Selected finite Record TTL remains structurally rejected.",
    ),
    "DM-5.1-09": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; two independently authenticated live publishers created revisions on separate stores with zero peerless contacts, then four positive direct-only error-free contact receipts reconciled both revisions and both live projections retained the same two annotated causal heads without merge execution",
        "The retained partition is brief and the run remains same-implementation, one-host, and two-participant, with no comprehensive crash sweep, relay, automatic registered-policy merge, mixed implementation, scale, physical system, long-duration soak, or release acceptance.",
    ),
    "DM-5.1-10": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; {BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; SelectedBlobNode and the cloneable actor-owned SelectedBlobHandle prepare a manifest-bounded digest set, commit encrypted chunks under the fixed 64-KiB profile outside redb, source-seal one canonical manifest, and expose synchronous stopped streaming or bounded live zeroize-on-drop plaintext pages; the retained live run published and read one 98,304-byte two-chunk Blob while peerless, seeded a replica, retained exact nonpublic interrupted progress across receiver reopen, resumed from that distinct replica, and read the authenticated result before and after a final peerless receiver reopen",
        "The retained run is one same-implementation, one-host, three-participant, small two-chunk observation with an operator-attested source/binary/execution link. Blob subscription or class-specific status, route-only relay/custody, Blob TTL/GC, language bindings, crash or power-loss recovery, long-offline recovery, physical/resource acceptance, mixed implementations, large-Blob/RSS evidence, and release authorization remain open.",
    ),
    "DM-5.1-11": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; {BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; BlobId commits exact plaintext bytes, the canonical chunk profile, and media/schema identity metadata; the retained live run returned the original publication on one exact noninserting retry, rejected one changed-payload reuse as a conflict, preserved the original publication, and reproduced all exact page and whole-payload commitments at the peerless publisher, seeded replica, resumed receiver, and final peerless receiver reopen",
        "The ID is metadata-bound object identity, not a separate pure whole-byte content ID. The retained case is one publisher and does not establish adversarial multi-writer behavior. Blob subscription/status, metadata-independent deduplication, route-only relay/custody, independent interoperability, scale, large-RSS, physical/resource evidence, and release authorization remain open.",
    ),
    "DM-5.1-12": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; semantic v5 authenticates and atomically stages the exact source envelope and manifest before strict kind-2 carrier work, transfers canonical carriers through contiguous ranges no larger than 16 KiB, and verifies carrier identity, every AEAD/chunk digest, and the whole BlobId before publication; the retained direct run accounted eight positive ranges and 98,638 fetched carrier bytes at both the seeded replica and across the receiver partial/resume/finish lifetimes, retained exactly two committed ciphertext chunks per participant, and returned the 98,304-byte plaintext as exact 65,536-byte and 32,768-byte pages",
        "The retained network observation is one small same-implementation, one-host direct-Iroh case with graceful same-process interruption and reopen. Blob subscription/status, 100+ MiB/RSS or physical/resource acceptance, route-only relay/custody, crash or power-loss recovery, long-offline recovery, mixed implementation, and release authorization remain open.",
    ),
    "DM-5.1-13": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; exact source plans and contiguous carrier prefixes are durable under source/carrier identity rather than peer or session, survive runtime/store/provider-cache teardown and reopen, resume only the exact missing complement from another eligible content peer, and remain nonpublic until full verified promotion; the retained run interrupted a 98,638-byte authenticated carrier transfer after one 16,384-byte range, preserved that exact nonpublic prefix across a peerless receiver reopen, advanced it by exactly 16,384 bytes from the seeded replica without source refetch, fetched only the 65,870-byte remaining complement, promoted once, and served the exact 98,304-byte plaintext again after a final peerless reopen",
        "The retained interruption and restart are graceful same-process actor, Store, and provider-cache reopen on one same-implementation loopback host. OS-process crash, power loss, long offline intervals, route-only custody, arbitrary peers, Blob subscription/status, TTL/GC, 100+ MiB and RSS brackets, physical systems, mixed implementations, scale, and release authorization remain open.",
    ),
    "DM-5.2-19": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; an authenticated pending source plus peer-neutral contiguous carrier prefix survives interruption and reopen, and the scheduler requests the exact source/carrier complement without discarding already accepted bytes; the retained run binds a 16,384-byte durable prefix to typed Store inspection, preserves it exactly across a peerless reopen, advances it by the exact next 16,384-byte complement from a different eligible peer, and reconstructs all 98,638 authenticated carrier bytes without discarding accepted work",
        "This is one small same-implementation, one-host direct-Iroh graceful interruption and reopen. Long partitions, OS-process crash or power loss, route-only relay or custody, arbitrary-peer continuation, physical and resource brackets, mixed implementations, Blob subscription/status, TTL/GC, scale, and release evidence remain open.",
    ),
    "DM-5.2-20": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; A sends C the authenticated source plus one bounded durable range, then C's runtime, Store, and provider cache tear down and reopen with that exact partial progress retained and nonpublic; the retained run limits the initial receiver encounter to exactly one successful direct contact, records one 16,384-byte nonpublic durable prefix, shuts the actor down, reopens peerless, and proves the source ID, Blob ID, staging fingerprint, prefix object, index, length, total, next complement, and carrier totals are unchanged",
        "The brief contact and reopen are controlled on one host and do not model an OS-process crash, power loss, long offline duration, physical carrier, route-only custody, mixed implementation, 100+ MiB or RSS target, subscription/status, TTL/GC, scale, or release acceptance.",
    ),
    "DM-5.2-21": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; after reopen the receiver continues at the first missing carrier byte and creates exactly one ordinary publication only after canonical carrier, depot completion, freshly streamed full-content verification, and current-lineage proof all agree; the retained run makes a later exactly-one-contact encounter with the seeded replica advance the receiver from 16,384 to 32,768 durable carrier bytes with zero source refetch, then fetches exactly the remaining 65,870 bytes and exposes plaintext only after verified promotion",
        "The later contact is immediate and the restart is graceful and same-process on one same-implementation loopback host. Long offline recovery, OS-process crash or power loss, route-only custody, arbitrary peers, physical and resource acceptance, mixed implementations, Blob subscription/status, TTL/GC, scale, and release authorization remain open.",
    ),
    "DM-5.2-22": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; A completes B, partially stages C, and is removed; fresh eligible content peer B then sends C no source retransmission and only the exact missing carrier complement while every inventory/source/range service rechecks peer content proof, route, revocation, and current route/physical lineage; the retained run first completes publisher-to-replica seeding, removes the publisher actor from the receiver phases, preserves the receiver partial across reopen, and has the distinct eligible replica continue the exact complement with zero source refetch before final verified promotion and peerless reread",
        "Eligibility remains the configured directly authenticated content-capable peer and explicitly excludes arbitrary or route-only peers. The observation is one-host, same-implementation, graceful same-process reopen and does not cover crash or power loss, long offline periods, physical or resource brackets, mixed implementations, Blob subscription/status, TTL/GC, scale, or release authorization.",
    ),
    "DM-5.1-05": selected_claim(
        "observed-bounded", "aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {EVENT_LIVE_SLICE}; {LIVE_EVENT_ACCEPTANCE_SLICE}; {LIVE_EVENT_RECEIPT}; the retained live run durably published four peerless Events, returned the original immutable publication on one exact noninserting retry, rejected changed-intent operation reuse while preserving the original, and retained the same three exact transferred alpha publications through final receiver peerless reopen",
        "The observation is one same-implementation, one-host, two-participant run with one changed-intent conflict. Broader mutation/equivocation cases, independent interoperability, physical systems, scale, resource evidence, and release acceptance remain open.",
    ),
    "DM-5.1-06": selected_claim(
        "observed-bounded", "aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {EVENT_LIVE_SLICE}; {LIVE_EVENT_ACCEPTANCE_SLICE}; {LIVE_EVENT_RECEIPT}; three authenticated alpha Events retained exact publisher sequences one through three across peerless publication, priority-threshold transfer, a forced receiver-process termination, fresh-process redelivery, normal-policy gap closure, and final peerless query; priority scheduling withheld sequence two without changing its canonical publisher position",
        "This is one three-item stream from one publisher on one same-implementation loopback host. It does not establish long streams, multiple concurrent publishers, independent interoperability, physical systems, requirement scale, or release acceptance.",
    ),
    "DM-5.1-07": selected_claim(
        "observed-bounded", "aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {EVENT_LIVE_SLICE}; {LIVE_EVENT_ACCEPTANCE_SLICE}; {LIVE_EVENT_RECEIPT}; the retained receiver reported the authenticated half-open alpha gap [2,3) after priority policy transferred sequences one and three while withholding routine sequence two, then reported closed-through-three after one normal-policy transfer and again after final peerless reopen",
        "Gap absence remains limited to verified positions observed by the local mission-bound store and does not prove publisher completeness or global convergence. This is one bounded same-implementation stream without independent interoperability, long partitions, physical systems, or scale evidence.",
    ),
    "DM-5.1-17": selected_claim(
        "implemented-uncredited", "aster-core + aster-node",
        f"{EVENT_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {BLOB_LIVE_SLICE}; {STATE_SUBSCRIPTION_SLICE}; {RECORD_SUBSCRIPTION_SLICE}; selected live and stopped boundaries publish and query Event, State, Record, and Blob through high-level typed operations; Event, State, and Record additionally expose subscribe/poll/acknowledge/unsubscribe, State delivers freshly verified positive Current versions, Record delivers whole-key active-head projections and exposes conflict annotation plus exact-guard resolution, and Blob exposes bounded zeroize-on-drop page reads",
        "Blob has no durable delivery subscription. State has no contact/status or materialized-view/Current-to-None delivery, Blob has no class-specific status operation, the agent remains Event-only, and selected-node language bindings remain open.",
    ),
    "DM-5.1-18": selected_claim(
        "implemented-uncredited", "aster-core + aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {STATE_SUBSCRIPTION_SLICE}; Event, State, Record, and Blob topics are source-authenticated and content-granted; Event has durable Consume/Carry delivery selectors, State has a durable exact topic/scope positive-current-version application selector separate from configured network interests, semantic-v4/v5 State/Record have explicit class-separated network interests, and each v5 exact Blob selector carries a current peer-bound content proof",
        "Repeated and multi-scope State/Record application-selector lifecycle, Blob application delivery, dynamic network-interest administration, route-only Blob custody, and independent interoperability remain open.",
    ),
    "DM-5.1-19": selected_claim(
        "implemented-uncredited", "aster-core + aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; Event, State, Record, and Blob scope/epoch are source-authenticated; current route grants and current source lineage filter inventory/transfer, while every v5 Blob inventory/source/range send additionally requires the authenticated peer's current exact topic/scope/epoch content proof and current physical lineage",
        "Repeated dynamic multi-scope lifecycle, route-only Blob custody, physical peers, and independent interoperability remain open. Same-epoch replacement withholds old proofs and rows; cleanup deliberately retains bounded quota-charged depot expected/committed staging, backing files/chunks where present, reserved-byte authority, and the non-public retained physical-lineage fence until an explicit GC protocol.",
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
        f"{RECEIPT}; {LIVE_MUTABLE_RECEIPT}; {LIVE_BLOB_RECEIPT}; {EVENT_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; retained Ping/Pong, live State/Record, and live Blob runs authenticate authority-provisioned source identities independently at each endpoint; the Blob receipt binds one exact publisher through peerless publication, direct transfer, receiver read, and graceful receiver reopen while v5 range service separately binds the authenticated claimant peer to the current content grant",
        "The live receipts are same-implementation, one-host, direct-only observations with at most three participants. Route-only Blob custody, arbitrary-peer continuation, independent interoperability, physical systems, scale, and release authorization remain open.",
    ),
    "DM-5.2-01": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{RECEIPT}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {LIVE_BLOB_RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; retained Event lines converged exact transfers; the retained live mutable run used eight positive direct-only zero-error contacts to transfer seven exact items and converge both actors on the same four-version State projection with an authenticated tombstone Current and three predecessors Superseded plus the same three-version Record projection with the guarded resolution Current and two siblings Superseded, then reproduced both projections after one immediate peerless restart; the retained live Blob run transferred one peerless-published two-chunk object through a seeded replica, retained a receiver prefix across graceful reopen, resumed the exact complement from that distinct eligible content peer, and reproduced authenticated pages after final reopen",
        "The retained observations are same-implementation, one-host, at-most-three-participant, brief cases and are not all-reachable-node or long-partition results. Mutable causal observation/publication order is producer-attested, and its restart is one immediate graceful peerless reopen rather than crash, power-loss, or indefinite retention evidence. Multiple-scope lifecycle, route-only Blob custody, arbitrary-peer continuation, mixed implementations, physical links, requirement scale, and release authorization remain open.",
    ),
    "DM-5.2-02": selected_claim(
        "observed-bounded",
        "aster-redb-store + aster-node",
        f"{EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; durable Event Consume/Carry selectors, durable State/Record topic/scope application selectors, explicit semantic-v4/v5 class-separated State/Record network interests, and v5 exact Blob topic/scope/epoch selectors with peer-bound current content proofs become mission-protected receiver interests; retained State and Record runs kept application subscriptions durable across forced process replacement and final reopen while proving they neither expanded nor mutated separately configured network interests; the Record run retained network-interested application-unmatched beta without delivery and withheld application-matched network-uninterested gamma",
        "The retained State/Record flows are same-implementation, one-host, and two-participant, not all reachable subscribed nodes or global convergence. Their application selectors are separate static surfaces rather than dynamic network-interest administration, and a local application selector alone does not prove replication. No retained four-class subscription receipt exists; repeated multi-scope lifecycle, Blob application subscriptions, route-only Blob custody, long partitions, physical peers, scale, and mixed implementations remain open.",
    ),
    "DM-5.2-06": selected_claim(
        "observed-bounded",
        "aster-redb-store + aster-node",
        f"{RECEIPT}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {LIVE_EVENT_ACCEPTANCE_SLICE}; {LIVE_EVENT_RECEIPT}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; retained Event and State receivers replayed flushed unacknowledged attempts after forced process termination; independently, the retained Record receiver flushed attempt one for one complete two-head conflict projection, was killed by SIGKILL without graceful shutdown or acknowledgement, and a fresh process replayed the same projection at attempt two with a distinct token before acknowledgement",
        "Each retained fault is one controlled forced receiver termination after a flushed poll, not crash injection at every external boundary, power-loss or filesystem-crash recovery, or failed-contact recovery. Blob delivery, bindings, independent interoperability, physical systems, scale, and release acceptance remain open.",
    ),
    "DM-5.2-07": selected_claim(
        "observed-bounded", "aster-redb-store + aster-node",
        f"{RECEIPT}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {LIVE_EVENT_ACCEPTANCE_SLICE}; {LIVE_EVENT_RECEIPT}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; retained Event and State runs inserted exact network objects with zero transfer duplicates and replayed only unacknowledged attempts; the retained Record run inserted three network publications with zero duplicates, delivered the complete sorted two-head conflict once per unacknowledged attempt even at delivery_limit=1, acknowledged and reacknowledged exact work idempotently, retired that head set after guarded resolution, delivered the successor under a new projection, and retained empty post-ack polls through final peerless reopen",
        "The retained observations are direct, same-implementation, one-host, two-participant schedules. They do not cover cycles, broadcast, every external crash point, Blob delivery, bindings, independent implementations, physical systems, scale, or release acceptance.",
    ),
    "DM-5.2-08": selected_claim(
        "observed-bounded",
        "aster-redb-store + aster-node",
        f"{RECEIPT}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {LIVE_EVENT_ACCEPTANCE_SLICE}; {LIVE_EVENT_RECEIPT}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; retained Event and State runs bind publication, durable replay, redelivery, acknowledgement, selector lifecycle, and policy status; the retained Record run binds its 89-byte acknowledgement tokens to subscription incarnation, whole-projection identity, complete sorted active-head set, tenure, and attempt, rotates the token between forced-crash attempts while restoring the prior token from durable storage, accepts exact acknowledgement and reacknowledgement including the already-acknowledged conflict after successor delivery, and rejects malformed, wrong-subscription, wrong-projection, and retired-singleton tokens",
        "Each retained process fault is one forced receiver termination after a flushed poll, not crash injection at every external boundary or power-loss recovery. Blob delivery, bindings, independent implementations, physical systems, scale, and release acceptance remain open.",
    ),
    "DM-5.2-09": selected_claim(
        "observed-bounded", "aster-core + aster-redb-store + aster-node",
        f"{RECEIPT}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {MUTABLE_NETWORK_SLICE}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; an isolated peerless destination publishes causally observing Pong and the durable store rejects dot equivocation; retained State evidence distinguishes concurrent maxima from causally dominant successors; retained Record evidence binds one complete sorted edit/tombstone active-head set into a stable whole-projection identity across attempt-one SIGKILL and fresh-process attempt two, then requires a fresh exact query guard before resolution and emits the causally observing successor under a new projection while keeping the retired siblings query-only",
        "These are exact, producer-attested causal schedules; public receipt fields do not expose full causal vectors. The Record case checks one two-head conflict and one successor across one immediate peerless reopen, not arbitrary ordering, competing successors, long or multi-hop partitions, independent interoperability, physical systems, or scale.",
    ),
    "DM-5.2-10": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-negentropy + aster-node",
        f"{RECEIPT}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {MUTABLE_NETWORK_SLICE}; Event, State, and Record authenticated counters/context are authoritative while class-specific exact transfer IDs reconcile with Negentropy timestamp zero; the retained run projected initial concurrent State, a causally observing successor, and a causally observing tombstone from authenticated counter/context and semantic-ID facts rather than wall-clock order",
        "The retained run does not inject clock skew or independently reconstruct its producer-attested causal observation/publication order. Verify adversarial clock behavior, a future State/Record finite-TTL forwarding-age design (currently rejected), long partitions, and long-running operation without trustworthy time.",
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
    "DM-5.2-15": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{STATE_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; retained State evidence propagated, delivered, acknowledged, and immediately reopened one authenticated Current tombstone; independently, the retained Record run delivered and left unacknowledged a peerless Current tombstone, later retained that tombstone as one complete conflict head beside an edit, then explicitly resolved both heads and kept them query-only as Superseded through final peerless reopen",
        "This proves bounded direct propagation/delivery and immediate peerless-restart observation on one same-implementation host with two participants. Causal observation/publication order is producer-attested, and restart does not establish tombstone retention duration, compaction, garbage collection, power-loss recovery, Current-to-None withdrawal, or a delete-wins rule. Broader concurrent deletion/update races, multi-hop and long partitions, physical systems, mixed implementations, scale, and release acceptance remain open.",
    ),
    "DM-5.2-18": selected_claim(
        "implemented-uncredited",
        "aster-negentropy + aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; bounded identifier-set reconciliation computes differences over class-specific exact Event, State, Record, and semantic-v5 Blob source identities; State/Record use durable peer/class/local-mode strict-successor rotation, Blob requests only an exact missing contiguous carrier complement, and retained Event evidence shows equal inventory transfers nothing",
        "Publish total-size-versus-difference cost evidence across all four classes at requirement scale, physical links, and mixed implementations.",
    ),
    "DM-5.3-01": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{STATE_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; an active version whose authenticated context observes another version's dot dominates it; after both actors first retained two concurrent maxima, node-a's counter-four successor observed both and became Current with both originals Superseded, then node-b's counter-three tombstone observed the successor as its one active head and all three prior versions and became Current with all three Superseded on both actors and after one immediate peerless restart",
        "This is one exact four-version, same-implementation, one-host, two-participant direct-Iroh schedule. Its query/causal-observation/publication order is producer-attested, and restart covers only one immediate graceful peerless reopen, not tombstone retention duration, expiry, compaction, or garbage collection. Competing successors or deletion races, multi-hop and longer partitions, independent interoperability, physical systems, scale, and release acceptance remain open.",
    ),
    "DM-5.3-02": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{STATE_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; two peerless live publishers created concurrent State maxima and both initial connected views selected the greatest complete authenticated semantic State ID as Current with the other maximum explicitly Concurrent; the later exact successor and tombstone phases instead superseded every causally observed predecessor, separating the concurrent semantic-ID tie-break from causal dominance",
        "This is one two-value, same-implementation, one-host direct-Iroh tie-break. The later causal observation/publication order is producer-attested, and only the final tombstone projection receives one immediate graceful peerless-restart check. No delete-wins rule, larger concurrent set, mixed-implementation, relay, physical, adversarial-scale, long-duration, or release acceptance is established.",
    ),
    "DM-5.3-06": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; retained direct-Iroh runs left two authenticated causal Record heads present without executing a merge policy; the retained delivery run projected its complete edit/tombstone active-head set as one unit even at delivery_limit=1, preserved the same sorted sibling set and projection identity across forced SIGKILL and fresh-process replay, exposed neither superseded plaintext nor a resolution guard, and never split the conflict across pages",
        "The retained conflicts are same-implementation, one-host, direct-only, and two-participant. The selected implementation deliberately executes no registered merge policy; hidden sibling identifiers neither disclose nor authorize hidden lineage. Add a convergent registered-policy design separately, then verify longer partitions, relays, retention/GC interaction, mixed implementations, scale, physical systems, and release acceptance.",
    ),
    "DM-5.3-07": selected_claim(
        "observed-bounded",
        "aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; retained exact-key queries returned RecordConflict with both sorted sibling IDs and an opaque exact projection guard; independently, retained durable delivery returned the same complete sorted sibling IDs as a non-authorizing whole-key annotation, including opaque IDs whose lineage withholds plaintext, deliberately omitted the query-only resolution guard, and preserved that annotation across fresh-process replay",
        "The retained annotation evidence covers embedded Rust live handles in bounded direct-Iroh runs. Sibling identifiers do not disclose or authorize hidden lineage. Language bindings, independent interoperability, larger retained conflicts, relays, physical systems, and release acceptance remain open.",
    ),
    "DM-5.3-08": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{RECORD_LOCAL_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; the actor-owned SelectedRecordHandle exposes Current, Concurrent, optional query-only Superseded, and RecordConflict application fields, accepts an exact query guard for application-reviewed resolution, and exposes durable whole-projection subscribe, poll, acknowledge, and unsubscribe; the retained delivery run returned projection identity, attempt, visible active heads, non-authorizing sibling IDs, and an opaque token without sealed bytes, transfer identities, causal vectors, provider internals, store plan tokens, Superseded history, or a resolution guard",
        "The retained evidence covers only the embedded Rust live handle in bounded same-host runs. Selected-node C/Go/Python bindings, independent usability evidence, larger retained conflicts, physical systems, and release acceptance remain open.",
    ),
    "DM-5.3-09": selected_claim(
        "observed-bounded",
        "aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; retained runs rejected ordinary publication across two heads, required an exact fresh query guard, and inserted one guarded successor with an exact noninserting retry; retained polling verified every candidate and emitted the complete sorted two-head projection as one delivery at delivery_limit=1 and scan_limit=16 with has_more=false, then emitted the successor only under a new projection after resolution",
        "The retained evidence is one same-implementation direct-contact conflict and one forced-process boundary. Verify crashes at other external boundaries, longer partitions and relays, automatic merge if later added, mixed implementations, adversarial scale, physical systems, and release acceptance.",
    ),
    "DM-5.3-10": selected_claim(
        "observed-bounded",
        "aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; guarded live resolution turned both inspected heads into recoverable Superseded originals; the retained delivery run emitted the resolution successor under a new projection, deliberately kept the two originals out of delivery, returned both only through the explicit include-superseded query, and reproduced the current successor plus both query-only originals after final peerless reopen",
        "The bounded runs retain history because no explicit-policy garbage collection exists; the immediate reopen establishes no retention horizon. Verify expiry/GC, longer partitions, relays, mixed implementations, adversarial scale, physical systems, and release acceptance.",
    ),
    "DM-5.3-04": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; {BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_RECEIPT}; immutable Blob bytes and identity metadata never enter the State/Record causal merge reducers, multiple stopped or live signed source publications can reference one exact completed content variant without changing it, live reads select only a freshly authenticated current immutable publication, and semantic-v5 remote source/carrier staging remains outside ordinary publication indexes until exact atomic completion; the retained one-publisher run rejected changed-payload operation reuse and preserved the original publication",
        "The retained conflict is operation-key immutability for one publisher, not adversarial multi-writer merge behavior. Blob subscription/status, route-only relay/custody, adversarial multi-writer interoperability, retention/GC policy, pure-byte identity, scale/large-RSS/resource/physical evidence, mixed implementations, and release authorization remain open.",
    ),
    "DM-5.4-01": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{PROFILE_EVIDENCE}; {CUSTODY_SLICE}; the fixed Routine/Priority/Immediate/Flash ordinals are source authenticated and used by the selected Event scheduler",
        "The exact count and names remain provisional pending stakeholder and service-doctrine approval; State, Record, Blob, and generic cross-class pressure remain outside selected custody.",
    ),
    "DM-5.4-05": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; the retained origin assigned and authenticated one priority on each of six Events, four exact Events with preserved priorities reached route custody, and the two surviving receiver deliveries preserved Flash and Immediate",
        "The receipt is one same-implementation Linux-container loopback observation for Event/RouteEvent only. Stakeholder priority-name governance, other classes, bindings, physical systems, mixed implementations, scale, and release authorization remain open.",
    ),
    "DM-5.4-09": selected_claim(
        "observed-bounded",
        "aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; after finite expiry and one explicit pressure retirement, the retained relay offered exactly the surviving Flash and Immediate Events and the receiver returned those two deliveries in that priority order",
        "This observes one two-item current selected Event/RouteEvent order after a deliberately staged quota transition. It does not observe retry cadence, older-version deterministic partial behavior, cross-class ordering, physical or impaired links, many-node scale, mixed implementations, or release authorization.",
    ),
    "DM-5.4-10": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; retry_delay_ms and the bounded retry ledger give higher authenticated Event priority an earlier deterministic retry cadence while exact leases and acknowledgements suppress duplicate work",
        "This is selected Event/RouteEvent mechanism evidence, not physical-loss, long-disconnection, many-peer, cross-class, or retained acceptance evidence.",
    ),
    "DM-5.4-12": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; the retained origin authenticated two finite Flash Events with distinct expiry horizons plus durable Flash, Immediate, Priority, and Routine Events, preserving TTL as independent from priority through custody",
        "The observation is Event/RouteEvent-only in one same-implementation Linux container. State, Record, Blob, non-Linux finite TTL, bindings, physical systems, mixed implementations, scale, and release authorization remain open.",
    ),
    "DM-5.4-13": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; Linux CLOCK_BOOTTIME withheld one Event already expired before the first contact and expired a second retained route Event on relay reopen before the receiver contact, with neither Event delivered",
        "Finite Event custody is Linux-only and semantic-v3-format behavior inherited by v4/v5. The receipt is one short one-kernel loopback run without suspend injection; selected clock-domain replacement, non-Linux behavior, State/Record/Blob TTL, physical links, mixed implementations, scale, and release authorization remain open.",
    ),
    "DM-5.4-14": selected_claim(
        "observed-bounded",
        "aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; bounded Linux maintenance collected the already-expired origin Event and the relay-expired route Event, and the retained inspection verified the retirement fence persisted through reopen and forwarding",
        "Collection is observed only for two selected Event/RouteEvent items in one short same-implementation Linux-container run. State, Record, Blob, physical allocation reclamation, long-duration pressure, crash/power-loss points, mixed implementations, scale, and release authorization remain open.",
    ),
    "DM-5.4-15": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; the retained origin used AtLeast(Priority), both downstream actors used ReceiveOnly while accepting inbound Event custody, and the relay later used Normal to forward only the two surviving route Events",
        "This is a same-implementation loopback exercise of the selected Event policy hooks, not physical RF silence or carrier-wide policy. AtLeast does not create State/Record/Blob custody priority; route-only Blob custody, bindings, broader platform/transport evidence, scale, and release authorization remain open.",
    ),
    "DM-5.4-16": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; the retained AtLeast(Priority) contact transferred exactly four unexpired Events at or above Priority while withholding the authenticated Routine Event below the configured floor",
        "The receipt covers one explicit Event floor and one direct loopback contact. It does not establish topic defaults, integrator rewrites/caps, State/Record/Blob custody priority, policy-driven discovery control, physical or impaired-link behavior, language bindings, mixed implementations, scale, or release authorization.",
    ),
    "DM-5.4-17": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; ReceiveOnly cannot initiate contacts and emits no discovery, local Event inventory/object, control object, State/Record interest/inventory/ID/object, or Blob interest/inventory/source/range/staging/promotion/accounting; protected empty Event inventory replies and bounded authenticated v3/v4/v5 Event offer acknowledgements/results remain permitted",
        "ReceiveOnly may emit mandatory connection authentication and Event acknowledgements/apply results; it is not physical radio silence and has no packet-capture, BTLE, platform, or independent acceptance evidence.",
    ),
    "DM-5.4-18": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; while operating in ReceiveOnly, the retained relay initiated zero contacts and disclosed zero local Event, State, Record, Blob, or control objects while ingesting four authenticated route Events; the ReceiveOnly receiver likewise ingested the two surviving Events",
        "Evidence is one-host same-implementation direct-loopback execution, not physical RF silence, an impaired link, a long-running partition, mixed implementations, broader class custody, scale, or release authorization.",
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
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {LIVE_MUTABLE_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; one retained run exercised the fixed four Event priorities, finite-or-durable TTL, AtLeast/Normal/ReceiveOnly emission, and exact-scope quota bounds without an open-ended policy language",
        "The receipt covers one deliberately small same-implementation Event/RouteEvent matrix. Priority count/names remain provisional; defaults/caps/overrides, richer post-MVP policy, State/Record/Blob custody/TTL, bindings, physical systems, mixed implementations, scale, and release authorization remain open.",
    ),
    "DM-5.5-01": selected_claim(
        "implemented-uncredited", "aster-core + aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {EVENT_SUBSCRIPTION_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; Event, State, Record, and Blob topic/scope are distinct authenticated fields and durable index dimensions; Event uses canonical Consume/Carry selectors, mutable classes use explicit canonical interests, and v5 Blob selectors bind exact topic/scope/epoch plus current peer content proof",
        "Repeated multiple-scope selector lifecycle, bridges, route-only Blob custody, and independent interoperability remain open.",
    ),
    "DM-5.5-02": selected_claim(
        "observed-bounded", "aster-redb-store + aster-node",
        f"{EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {LIVE_EVENT_ACCEPTANCE_SLICE}; {LIVE_EVENT_RECEIPT}; {LIVE_MUTABLE_RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; retained Event, State, and Record receivers bound delivery to explicit application selectors; the Record run proved network-interested application-unmatched beta remained retained without delivery, application-matched network-uninterested gamma remained absent, and subscription creation/replay never mutated the separately configured network interest",
        "The retained application selectors are separate static surfaces, not dynamic network-interest administration, and a local application selector alone does not prove replication. Blob application subscriptions, repeated multi-scope lifecycle, route-only Blob custody, physical peers, scale, mixed implementations, and release acceptance remain open.",
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
        "observed-bounded",
        "aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {CUSTODY_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; the retained route-only relay admitted exactly four Events under an exact-scope four-item quota, expired one, retired exactly one lower-priority RouteEvent under explicit stopped-store pressure, persisted a two-item quota, and reopened with exactly two route items",
        "The quota transition was deliberately staged by stopped-store pressure followed by quota lowering; it is not automatic startup down-sizing or sustained physical-capacity pressure. Logical row/source-byte limits do not measure redb/filesystem allocation; other classes lack equivalent custody eviction and complete physical accounting. Scale, mixed implementations, long pressure, and release authorization remain open.",
    ),
    "DM-5.6-01": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{RECEIPT}; {LIVE_MUTABLE_RECEIPT}; {LIVE_BLOB_RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; same-implementation nodes synchronized source-sealed Event, State, and Record in retained direct one-host runs; the retained v2 Blob run additionally seeds one complete replica, preserves a receiver partial across graceful reopen, and resumes the exact complement from that distinct eligible content peer",
        "The requirement applies to conformant nodes generally, while all retained data-class observations are same-implementation. Add independent conformance, broader and long partitions, crash or power-loss recovery, route-only Blob relay/custody, arbitrary-peer continuation, physical transport, large/resource evidence, and broader network acceptance.",
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
        "This is source plus same-implementation one-host loopback automation, not a supported or released IP-adapter acceptance result. Representative physical IP networks, dynamic or representative NATs, physical NAT hardware or paths, supported-target packaging, mixed implementations, dependency/license admission, retained supported-target acceptance, and release authorization remain open.",
    ),
    "DM-5.8-07": selected_claim(
        "observed-bounded",
        "aster-iroh + aster-node + aster-lab",
        f"{NAT_RECEIPT}; {SELECTED_NAT_SLICE}; the retained cone cell ran two selected endpoints behind distinct Linux software-NAT namespaces with operator-known static full-cone mappings, observed Direct at both endpoints, transferred and acknowledged one exact Event, repeated as an exact no-op, and bound 978 cross-NAT UDP packet observations to complementary nft DNAT/SNAT and exact directional forwarding counters without a relay, hosted discovery, public/default relay, or port mapping",
        "This is one same-build, same-implementation, one-host Docker namespace observation with static operator-known mappings. It does not prove endpoint discovery or punching, dynamic or representative NATs, physical NAT hardware or paths, public Internet operation, mixed implementations, supported-target packaging, resource thresholds, or release authorization.",
    ),
    "DM-5.8-09": selected_claim(
        "observed-bounded",
        "aster-iroh + aster-node + aster-lab",
        f"{NAT_RECEIPT}; {CONTROLLED_RELAY_SLICE}; {SELECTED_NAT_SLICE}; the retained restrictive cell blocked direct cross-NAT traffic, recorded three direct-drop packets and zero direct WAN observations, observed Relay at both authenticated endpoints through one explicitly DER-pinned HTTPS origin, accepted two exact allowlisted sessions, bound 2,052 controlled-relay HTTPS packet observations, transferred and acknowledged one exact Event, and repeated as an exact no-op",
        "The bounded result proves relay-assisted connectivity under one same-host restrictive software-NAT policy, not a temporal direct-first fallback sequence: Iroh may probe paths in parallel and learn later authenticated direct paths. Physical or independently operated relay service, public/default relay operation, mobility/outage recovery, State/Record/Blob-over-relay acceptance, mixed implementations, supported-target packaging, and release authorization remain open.",
    ),
    "DM-5.8-10": selected_claim(
        "observed-bounded",
        "aster-iroh",
        f"{RECEIPT}; local direct operation completed with relays, discovery, and port mapping disabled",
        "Verify local and mesh operation on physical systems and all required carriers.",
    ),
    "DM-6-01": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {LIVE_MUTABLE_RECEIPT}; {LIVE_BLOB_RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; Event, State, Record, and Blob content remain source-sealed independently of the Iroh carrier session; retained State/Record and Blob contacts bind source and carrier identities separately, Blob range service requires current claimant-bound content proof, and retained Event evidence separately shows a route-only relay cannot open content",
        "State/Record/Blob evidence is one same-host direct-Iroh implementation; the Blob receipt has no route-only relay/custody or packet capture. Complete carrier variants, provisioning, physical/mixed acceptance, and independent review remain open.",
    ),
    "DM-6-02": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{MISSION_RECEIPT}; {LIVE_MUTABLE_RECEIPT}; {LIVE_BLOB_RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; exact source-sealed Event, State, Record, and Blob bytes are freshly verified before inventory serving and remote admission; retained State/Record projections and State/Record deliveries follow that verification, with the Record run verifying the complete retained candidate set and current authorization before exposing one whole projection, while Blob publication requires every carrier plus fresh full-content/current-lineage completion and Event is reverified before reaction",
        "The Record receipt is one same-implementation direct-loopback case and its source-to-execution link is operator-attested, not cryptographically proven. Blob has no durable application subscription; State has no class-specific contact/status or Current-to-None delivery, and Blob has no class-specific sync/peer status. Route-only Blob custody, hostile physical-network acceptance, independent interoperability, and cryptographic review remain open.",
    ),
    "DM-6-03": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {LIVE_MUTABLE_RECEIPT}; {LIVE_BLOB_RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; destinations authenticate authority-provisioned Event, State, Record, and Blob publishers independently of carrier/session identities; retained live State/Record and Blob publication exercise that separation, the Blob publisher commits while peerless and a later receiver serves only freshly authorized pages, and Blob network service separately binds the claimant peer to the current content grant",
        "Blob subscription/status, route-only Blob custody, protected operational provisioning, platform-complete zeroization assurance, broader control lifecycle, physical/mixed acceptance, and independent review remain open.",
    ),
    "DM-6-04": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {LIVE_MUTABLE_RECEIPT}; {LIVE_BLOB_RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; isolated Event cohorts and retained disconnected live State/Record/Blob publishers source-seal objects before contact; the Blob receipt records peerless durable publication before a later v5 direct contact completes source verification and carrier transfer",
        "State/Record/Blob retention is same-implementation, one-host, and direct-only. Blob subscription/status, route-only Blob custody, key lifecycle beyond one bounded rekey, physical/mixed acceptance, and independent review remain open.",
    ),
    "DM-6-05": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {LIVE_MUTABLE_RECEIPT}; {LIVE_BLOB_RECEIPT}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; Event, State, Record, and Blob objects carry authenticated source identities and signed semantic headers; retained live State/Record/Blob projections preserve those identities, the live Blob handle publishes and reads only the authenticated current publication, and Blob transfer additionally binds the exact manifest, carrier IDs, and current route/physical lineages",
        "State/Record/Blob retention is bounded same-implementation direct-Iroh evidence. Blob subscription/status, route-only Blob custody, physical/mixed evidence, and independent interoperability remain open.",
    ),
    "DM-6-06": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {LIVE_EVENT_RECEIPT}; {LIVE_MUTABLE_RECEIPT}; {LIVE_BLOB_RECEIPT}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {LIVE_EVENT_ACCEPTANCE_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; Event, State, and Record polls freshly verify source/content authorization before committing durable attempts; the retained Record run verified the bounded candidate set, current policy and selector generation, visible active heads, and complete opaque conflict plan before atomically advancing one whole-projection attempt, rejected cross-subscription/projection and stale tokens, kept network-interest and application-subscription authority separate, and required a fresh query-only guard before resolution",
        "The observed delivery receipts are same-implementation direct-loopback cases without independent packet capture or cryptographic review. A Record application selector cannot expand network or mission authority, and conflict sibling IDs neither disclose nor authorize hidden lineage. Blob delivery/status, route-only Blob custody, bindings, physical peers, mixed implementations, and independent interoperability remain open.",
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
        f"{EVENT_LIVE_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; {AGENT_SLICE}; the actor-owned Event, State, Record, and Blob handles expose typed high-level publication/query or bounded page-read operations with sanitized errors; Event, State, and Record add durable subscribe/poll/acknowledge/unsubscribe operations, and retained State/Record acceptance runs exercise their distinct positive-Current or whole-key delivery contracts through those Rust handles; Record delivery exposes non-authorizing conflict sibling IDs while exact query separately supplies the resolution guard",
        "Blob has no durable subscription or class-specific sync/peer status operation. State has no Current-to-None withdrawal signal, the agent remains Event-only, and selected-node bindings, operational provisioning, independent usability, and the complete adopter-facing API remain open; the retained Record acceptance harness is not a binding or usability study.",
    ),
    "DM-7-14": selected_claim(
        "implemented-uncredited",
        "aster-node::application",
        f"{EVENT_LIVE_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; {AGENT_SLICE}; SelectedEventHandle, SelectedStateHandle, SelectedRecordHandle, SelectedBlobHandle, and agent operations/results contain no carrier type, endpoint, address, path choice, or transport selection; State and Record subscription, polling, acknowledgement, and unsubscribe remain high-level application operations, while their separate retained harnesses configure direct-Iroh actors and gather acceptance-only coordination records outside those handles",
        "Node startup and acceptance topology still require separate Iroh configuration, and retained harnesses use topology coordination and typed Store inspection outside the adopter API. The agent remains Event-only, and selected-node bindings plus future physical/multicarrier composition require the same boundary audit; the retained Record receipt is not release acceptance.",
    ),
    "DM-7-15": selected_claim(
        "implemented-uncredited",
        "aster-node::application",
        f"{EVENT_LIVE_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; {AGENT_SLICE}; live Event/State/Record/Blob surfaces return application items, verified projections, query-only Record conflict guards, non-authorizing Record-delivery sibling annotations, bounded authenticated plaintext pages, delivery attempts, and high-level Event status without exposing inventories, exact transfer IDs, Negentropy state, carrier ranges, depot capabilities, or contact protocol frames; retained Record delivery confirms that whole-conflict polling exposes application projection data and opaque acknowledgement tokens while superseded history and the resolution guard remain query-only",
        "Complete Blob subscription/status, State Current-to-None withdrawal semantics, selected-node bindings, the Event-only agent, and broader control-administration exposure without leaking synchronization internals; keep acceptance-only topology coordination and Store inspection clearly outside the adopter-facing surface. The retained Record harness does not complete these adopter-facing or release gates.",
    ),
    "DM-7-16": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{CONTROL_RECEIPT}; {EVENT_SLICE}; {EVENT_LIVE_SLICE}; {LIVE_EVENT_ACCEPTANCE_SLICE}; {LIVE_EVENT_RECEIPT}; {LIVE_MUTABLE_RECEIPT}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; retained Event, State, Record, and Blob publishers commit durably while peerless; the Record-subscription run created/replayed its application selector, delivered a peerless singleton tombstone, retained selector and acknowledgement state through forced process replacement, and reopened peerless with the resolved Current successor plus query-only history and an empty delivery queue",
        "The retained offline publications are same-implementation, one-host, and brief; they establish no stakeholder-set offline duration. Mutable/Record causal order plus Blob source-removal timing are producer-attested. Verify longer offline intervals, Blob delivery/status, selected-node bindings, physical systems, independent interoperability, scale, and release acceptance.",
    ),
    "DM-7-17": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{RECEIPT}; {EVENT_LIVE_SLICE}; {LIVE_EVENT_ACCEPTANCE_SLICE}; {LIVE_EVENT_RECEIPT}; {LIVE_MUTABLE_RECEIPT}; {LIVE_BLOB_RECEIPT}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; retained Event, State, Record, and Blob publishers commit peerless and synchronize later; the Record-subscription run inserted three exact network publications with zero duplicates over its connected phase, delivered the complete two-head conflict, replayed it after forced receiver termination, resolved it under a fresh guard, delivered the successor, and retained empty acknowledged state after final peerless reopen",
        "The retained observations are brief same-implementation one-host schedules, not stakeholder-set long-offline or power-loss results. State/Record application subscriptions and network interests remain separate static surfaces. Blob delivery, route-only or arbitrary-peer Blob custody, physical systems, scale, independent interoperability, and release acceptance remain open.",
    ),
    "DM-7-18": selected_claim(
        "implemented-uncredited",
        "aster-node + aster-agent + shipped documentation",
        f"{EVENT_LIVE_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {BLOB_LOCAL_SLICE}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; {STATE_SUBSCRIPTION_SLICE}; {LIVE_STATE_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_STATE_SUBSCRIPTION_RECEIPT}; {RECORD_SUBSCRIPTION_SLICE}; {LIVE_RECORD_SUBSCRIPTION_ACCEPTANCE_SLICE}; {LIVE_RECORD_SUBSCRIPTION_RECEIPT}; {AGENT_SLICE}; docs ship runnable embedded Event/State/Record and stopped Blob examples plus a local-agent example; State and Record quickstarts document live subscribe/poll/acknowledge/unsubscribe with explicit network-interest separation, query-only Record resolution guards, and bounded delivery semantics, while separate compiled retained acceptance producers exercise both State and Record delivery mechanisms",
        "The compiled State, Record, and Blob acceptance producers are acceptance harnesses, not minimal documentation-only integration samples, binding examples, or independent developer-usability studies. Blob delivery/status, selected-node bindings, operational provisioning, production packaging, and the complete integration surface remain open; no release credit follows from the Record receipt.",
    ),
    "DM-7-20": selected_claim(
        "observed-bounded",
        "aster-node + aster-agent",
        f"docs/quickstart/mesh-cli.md; {EVENT_LIVE_SLICE}; {LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; {BLOB_LOCAL_SLICE}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_ACCEPTANCE_SLICE}; {LIVE_BLOB_RECEIPT}; {CUSTODY_SLICE}; {AGENT_SLICE}; shipped and compiled examples exercise high-level Event/State/Record publication and query, Record conflict resolution, stopped Blob streaming, Event delivery/custody/quota/policy, and the Event-only agent sample; the Blob quickstart supplies a live publish/page-read/later-sync guide and a retained acceptance producer exercises that handle",
        "The retained live Blob producer is an acceptance harness, not a minimal developer sample. Add compiled minimal live State/Record delivery and Blob samples, make Blob subscription/status boundaries explicit, add selected-node bindings, and retain independent usability, operational provisioning, Linux/physical custody, and physical multi-system evidence.",
    ),
    "DM-8-01": selected_claim(
        "observed-bounded",
        "selected Rust workspace",
        f"{LIVE_MUTABLE_RECEIPT}; {LIVE_BLOB_RECEIPT}; cargo +1.91.0 check --locked --offline --workspace --all-targets --all-features and selected control/Event/runtime tests passed; retained live-mutable and live-Blob runs used Cargo release-profile Rust executables, with the current live-Blob executable exactly 12246960 bytes and SHA-256 e057c2046754de2fb0485b288b383031c49bbd05b96d34247bb72cefbdbcddb8",
        "The retained executables are operator-attested rather than reproducible or cryptographically source-bound builds, and neither is a product release. Repeat static-build and target acceptance for every supported release target after the full semantic migration.",
    ),
    "DM-8-02": selected_claim(
        "observed-bounded",
        "selected Rust workspace",
        f"{LIVE_MUTABLE_RECEIPT}; {LIVE_BLOB_RECEIPT}; Cargo.toml designates the selected crates as Rust; retained live-mutable and live-Blob executables were built with exact cargo build --release --locked aster-node example commands and passed their bounded runs",
        "Retain Rust as the core-framework language through full semantic migration, supported-target acceptance, and release packaging; neither retained binary is release authorization.",
    ),
    "DM-8-05": selected_claim(
        "open",
        "dependency-policy owner",
        f"{DEPENDENCY_GATE}; Decision 0028 records stakeholder-approved exact-package deviations, and deny.toml pins CDLA-Permissive-2.0 exceptions to webpki-roots 1.0.9 and webpki-root-certs 1.0.9 plus Unlicense exceptions to async_io_stream 0.3.3, pharos 0.5.3, and ws_stream_wasm 0.7.5; neither license enters the general allowlist and coordinate drift fails closed",
        "The frozen requirement literally requires OSI-approved licenses only, so the two CDLA data-package deviations are not counted as normative DM-8-05 compliance. The requirement owner must expressly revise or disposition that rule, or the implementation must use an approved alternative; supported-target, SBOM, packaging, and release admission remain open.",
    ),
    "DM-9-13": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; {BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_RECEIPT}; stopped read_into freshly verifies the selected publication and completed depot variant before streaming independently authenticated plaintext chunks into a caller-owned writer; live read_page repeats current-policy, projection, depot-capability, chunk, and final-lifecycle checks and returns at most one 64-KiB zeroize-on-drop plaintext page; the retained live run returned eight exact pages across peerless publisher, seeded replica, resumed receiver, and final peerless receiver reopen for one 98,304-byte payload",
        "The retained fixture is only 98,304 bytes and does not establish large-Blob storage streaming, Blob subscription/status, route-only custody, 100+ MiB or process-RSS behavior, carrier switching, physical-disk acceptance, platform breadth, mixed implementations, or retained resource evidence.",
    ),
    "DM-9-14": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; {BLOB_NETWORK_SLICE}; {BLOB_LIVE_SLICE}; {LIVE_BLOB_RECEIPT}; preparation uses one bounded zeroizing plaintext chunk buffer and a one-MiB-manifest-bounded digest vector; the core streaming engine reports its peak chunk-buffer capacity, store adapters are independently chunk-bounded, the live worker is joined and capacity-one, live plaintext pages are capped at 64 KiB spanning at most two canonical chunks and are zeroized on drop, and the retained run exercises only one 98,304-byte two-page fixture",
        "These component bounds and the retained small fixture are not a whole-process peak-memory measurement; adapters, the actor, filesystem, and caller custody may hold other bounded buffers. Add bracketed process RSS on supported targets, 100+ MiB network transfer, physical storage/resource accounting, mixed implementations, and retained resource acceptance before crediting the full target.",
    ),
    "DM-9-21A": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{N32_RECEIPT}; an operator-attested Cargo release-profile binary run for the signed current-tree source completed the selected one-host direct-loopback Event line at N=32 with 32 distinct mission identities and stores, 65 exact cohorts, 158 exact-named executions with distinct READY PIDs, 30 payload-blind intermediates, and 32 distinct log-observed READY PIDs in the final zero-difference no-op",
        "This is one same-build, same-implementation, one-scope/authority/topic, line-topology observation on one macOS arm64 host. It is not the bracketed at-least-100-node target, a full 2-through-32 range sweep, distributed or physical scale, NAT/relay/BTLE/cross-transport evidence, independent interoperability, or resource-threshold/release acceptance.",
    ),
    "DM-9-24": selected_claim(
        "observed-bounded",
        "aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; one retained route-only scope stayed within a four-item bound, then bounded maintenance plus explicit pressure reduced it to exactly two retained items with zero legacy, State, Record, Blob, or control namespace content",
        "This observes one logical Event/RouteEvent item bound, not complete local-storage or physical-allocation accounting. Accepted-dot, causal-frontier, Event-position/high-water, State/Record/Blob GC/custody, hostile unrelated files, snapshots/backups/swap, sustained pressure, scale, mixed implementations, and release authorization remain open.",
    ),
    "DM-9-25": selected_claim(
        "observed-bounded",
        "aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; the retained relay ran under explicit exact-scope four-item and one-MiB bounds, then persisted an explicit two-item replacement before reopen and forwarded within that configured bound",
        "The run exercises one stopped exact-scope Event quota transition. Not every hard safety cap is operator-tunable, and there is no selected binding, live administrative mutation, physical-capacity accounting, mixed-implementation evidence, scale result, or release authorization.",
    ),
    "DM-11-02": selected_claim(
        "implemented-uncredited",
        "aster-iroh + aster-node",
        f"{CONTROLLED_RELAY_SLICE}; the selected Rust composition and CLI integrate exact authenticated direct IP contacts plus an explicit singleton controlled-relay option, with current-code real-process direct and relay path evidence",
        "The IP mechanism exists, but the complete MVP does not. Dynamic, representative, or physical NAT operation, BTLE, physical and supported-target acceptance, bindings, protected operational provisioning, dependency/license admission, mixed implementations, resource evidence, complete-MVP acceptance, and release authorization remain open.",
    ),
    "DM-11-03": selected_claim(
        "implemented-uncredited",
        "aster-iroh + aster-node + aster-lab",
        f"{NAT_RECEIPT}; {SELECTED_NAT_SLICE}; the selected composition now includes direct Event operation across two isolated software-NAT namespaces and controlled-relay operation under a separate restrictive namespace policy",
        "The NAT mechanism is implemented and has one retained one-host namespace observation, but the complete MVP is not shipped. Physical and representative NATs, endpoint discovery/punching, BTLE, supported-target packaging, bindings, protected operational provisioning, dependency/license admission, mixed implementations, resource evidence, and release authorization remain open.",
    ),
    "DM-11-06": selected_claim(
        "implemented-uncredited",
        "aster-redb-store + aster-node",
        f"{LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; the selected MVP composition detects multiple active Record heads through an explicit live RecordConflict, rejects ordinary publication without insertion, and accepts only an exact-sibling guarded application resolution",
        "The conflict mechanism is present and bounded evidence exists, but the complete MVP is not shipped: live Blob has no subscription/status, bindings and the local agent lack Record operations, automatic registered-policy merge is absent, and physical/mixed/release gates remain open. The retained Blob receipt is unrelated to Record conflict detection and does not complete the MVP.",
    ),
    "DM-11-07": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{LIVE_MUTABLE_SLICE}; {LIVE_MUTABLE_RECEIPT}; SelectedRecordHandle surfaces an application-level RecordConflict containing every sorted sibling semantic ID and an opaque exact projection guard, then returns current and superseded annotations after resolution",
        "The annotation exists only in the embedded Rust application surface; the complete MVP, selected-node language bindings, agent RPC support, independent usability, physical/mixed acceptance, and release authorization remain open.",
    ),
    "DM-11-13": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; the selected Event composition includes the fixed Routine, Priority, Immediate, and Flash set; the retained run published Events at all four levels, withheld Routine below the threshold, retired Priority under pressure, and delivered Flash plus Immediate",
        "The fixed set exists and has one bounded retained observation, but the exact count and names remain provisional and the complete MVP is not shipped. Stakeholder approval, bindings, supported-target packaging, physical/mixed acceptance, and release authorization remain open.",
    ),
    "DM-11-15": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; the selected Event MVP surface includes positive source-authenticated TTL publication, cumulative semantic-v3/v4/v5 custody, exact expiry withholding, collection, and permanent replay fences; selected State/Record/Blob finite TTL is rejected",
        "Finite TTL is Linux-only and Event/RouteEvent-only; State/Record/Blob forwarding age, expiry, custody, and GC, the complete MVP, other platforms/classes, physical acceptance, bindings, protected provisioning, and release gates remain open.",
    ),
    "DM-11-16": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{CUSTODY_SLICE}; {MUTABLE_NETWORK_SLICE}; {BLOB_NETWORK_SLICE}; {LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; the selected Rust composition includes Normal, AtLeast(priority), and ReceiveOnly startup/live emission-policy hooks, and the retained run exercised all three forms across two contacts",
        "The hooks exist and have one bounded retained Event observation, but the complete MVP is not shipped. Selected-node bindings, protected operational provisioning, supported-target packaging, physical/mixed acceptance, broader class custody, and release authorization remain open.",
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
    "DM-12-04": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{LIVE_MUTABLE_RECEIPT}; two independently authenticated live publishers edited the same Record key while peerless, four positive direct-only contacts reconciled both revisions, both actors exposed the same two annotated sibling IDs without silent loss, ordinary publication inserted nothing, exact-guard resolution observed both siblings, and both peerless restart views retained the successor plus both superseded originals",
        "This passes one equivalent scenario on one host with one Rust implementation, two participants, a brief partition, direct Iroh, and no injected process crash. It is not physical, mixed-implementation, long-duration, relay/NAT/BTLE, adversarial-scale, product-release, or release-authorization evidence.",
    ),
    "DM-12-06": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; one equivalent bounded scenario withheld an already-expired Flash Event before the first contact, expired a second Flash route Event before the next contact, then delivered exactly the surviving Flash Event before the surviving Immediate Event",
        "This is one same-implementation Linux-container direct-loopback equivalent scenario with staged quota pressure, not a physical constrained link. Impairment/loss, long disconnection, suspend injection, other classes, mixed implementations, target hardware, scale, product-release, and release-authorization evidence remain open.",
    ),
    "DM-12-07": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{LINUX_CUSTODY_ACCEPTANCE_SLICE}; {LINUX_CUSTODY_RECEIPT}; one equivalent bounded scenario used AtLeast(Priority) to withhold exactly one Routine Event while transferring four eligible Events into a ReceiveOnly route relay, then transferred the two surviving route Events into a ReceiveOnly receiver; while operating in ReceiveOnly, both actors initiated zero contacts and disclosed zero local data/control objects",
        "This is one same-implementation Linux-container direct-loopback equivalent scenario, not physical RF silence, a constrained carrier, long-running operation, mixed implementations, broader-class custody, target hardware, scale, product-release, or release authorization.",
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
    "DM-7-11": "crates/aster-node/src/application.rs; crates/aster-node/src/application/blob.rs; docs/decisions/0009-public-api-boundary.md",
    "DM-7-14": "crates/aster-node/src/application.rs; crates/aster-node/src/application/blob.rs; docs/decisions/0009-public-api-boundary.md",
    "DM-7-15": "crates/aster-node/src/application.rs; crates/aster-node/src/application/blob.rs; docs/decisions/0009-public-api-boundary.md",
    "DM-7-18": "docs/quickstart/selected-event-api.md; docs/quickstart/selected-blob-api.md; docs/quickstart/connect-agent.md; crates/aster-node/src/application.rs; crates/aster-node/src/application/blob.rs; crates/aster-agent",
    "DM-7-20": "docs/quickstart/mesh-cli.md; docs/quickstart/selected-event-api.md; docs/quickstart/selected-custody-api.md; docs/quickstart/selected-blob-api.md; crates/aster-node/src/application.rs; crates/aster-node/src/application/blob.rs; examples/connect_agent.sh",
    "DM-8-01": "Cargo.toml; Cargo.lock",
    "DM-8-02": "Cargo.toml; Cargo.lock",
    "DM-8-05": "docs/decisions/0028-selected-stack-implementation-boundary.md; deny.toml; THIRD_PARTY_NOTICES.md; tools/check-dependency-exception-scope.sh",
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
