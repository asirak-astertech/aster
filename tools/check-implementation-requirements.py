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
    "crates/aster-redb-store/src/lib.rs; crates/aster-node/src/frame.rs; "
    "crates/aster-node/src/runtime.rs; crates/aster-node/src/main.rs; "
    "crates/aster-node/src/runtime.rs::tests::"
    "real_iroh_contact_converges_state_and_disconnected_record_siblings; "
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
CONTROL_SLICE = (
    "crates/aster-core/src/source_control.rs; crates/aster-redb-store/src/lib.rs; "
    "crates/aster-node/src/frame.rs; crates/aster-node/src/runtime.rs; "
    "crates/aster-node/src/main.rs; crates/aster-node/tests/mesh_cli.rs"
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
        f"{CONTROL_SLICE}; authority CLI inputs set the revoked subject/generation and the exact route-only/member recipient policy for a source-authenticated scope rekey",
        "Policy is currently expressed through bounded authority CLI inputs over one reference bundle/registry and one control family; protected operator provisioning, a generalized adopter-facing management API, policy governance, and additional key-management mechanisms remain open.",
    ),
    "DM-3-12": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{CONTROL_RECEIPT}; a four-node real-process line durably revoked the captured leaf, denied two later contact attempts, withheld epoch-two content, and accepted no stale publication at an eligible peer",
        "One captured leaf was excluded on one-host direct loopback; physical capture, larger and non-line topologies, authority/signer handoff and recovery, all data classes, and independent implementations remain open.",
    ),
    "DM-5.1-01": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{STATE_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; the stopped SelectedStateNode source-seals and durably publishes bounded State versions, queries one exact topic/scope/logical-key projection without exposing sealed representations or provider internals, and a separately running node reconciles already durable State under explicit interests",
        "The application State surface remains stopped/exclusive, with no live commands, durable subscription, language binding, selected relay cache, finite TTL, physical carrier, mixed-implementation, or release evidence. One same-implementation two-node real-Iroh transfer does not close those gaps.",
    ),
    "DM-5.1-02": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{STATE_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; authenticated State dots and causal context share the selected Event publisher frontier, the store retains causal maxima and dominated versions, the facade independently recomputes the exact-key projection, and one durable version reaches an interested independent store over real Iroh",
        "Current tests cover local causal projection plus one same-implementation two-node transfer. Divergent State convergence, multi-hop/partition behavior, independent interoperability, scale, and retained acceptance remain open.",
    ),
    "DM-5.1-04": selected_claim(
        "observed-bounded", "aster-core + aster-redb-store + aster-node",
        f"{RECEIPT}; {EVENT_SLICE}; {EVENT_LIVE_SLICE}; the built-in sample and high-level live handle publish, source-seal, store, transfer, freshly verify, query, and durably deliver Event objects",
        "The retained receipt covers the built-in Event sample; the generalized live-handle later-sync path has current-code automated loopback evidence only. Other data classes and independent wire interoperability remain open.",
    ),
    "DM-5.1-08": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; the stopped SelectedRecordNode source-seals and durably publishes bounded Record revisions, queries one exact-key current/concurrent/superseded projection, accepts only exact-sibling guarded application resolution, and a separately running node reconciles already durable revisions under explicit interests",
        "The application Record surface remains stopped/exclusive, with no live commands, durable subscription, language binding, automatic registered-policy merge, selected relay cache, finite TTL/GC, physical carrier, mixed-implementation, or retained release evidence.",
    ),
    "DM-5.1-09": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; independently source-authenticated publishers create revisions on separate stores while disconnected, one real-Iroh contact reconciles both exact inventories, and both stores retain the same two causal heads without running merge code",
        "This observation is one same-implementation, one-host, two-node contact with no long partition, crash sweep, relay, automatic merge, mixed implementation, scale, physical system, or retained release receipt.",
    ),
    "DM-5.1-10": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; the stopped SelectedBlobNode prepares a manifest-bounded digest set, commits encrypted chunks under the fixed 64-KiB profile outside redb, source-seals one canonical manifest, and streams verified plaintext into a caller-owned writer",
        "This is a stopped/local selected Blob surface. Blob has no live/runtime reconciliation, remote chunk transfer, any-peer resume, language binding, physical acceptance, mixed-implementation evidence, or retained release receipt. The selected integration tests are modest multi-chunk fixtures, not maximum-size acceptance.",
    ),
    "DM-5.1-11": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; BlobId commits exact plaintext bytes, the canonical chunk profile, and media/schema identity metadata; source-authenticated manifest records and the epoch-specific encrypted depot variant are immutable once committed",
        "The ID is metadata-bound object identity, not a separate pure whole-byte content ID. Metadata-independent deduplication, selected network transfer, independent interoperability, scale, and retained acceptance remain open.",
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
        f"{EVENT_SLICE}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {MUTABLE_NETWORK_SLICE}; Event, State, and Record topics are source-authenticated and content-granted; Event has durable Consume/Carry delivery selectors while State/Record have explicit network interests",
        "Repeated dynamic selector lifecycle, durable State/Record application delivery, Blob networking, and independent interoperability remain open.",
    ),
    "DM-5.1-19": selected_claim(
        "implemented-uncredited", "aster-core + aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {MUTABLE_NETWORK_SLICE}; Event, State, and Record scope/epoch are source-authenticated; canonical interests support exact/descendant matching and current peer route grants filter inventory and Offer",
        "Repeated dynamic multi-scope lifecycle, Blob networking, physical peers, and independent interoperability remain open.",
    ),
    "DM-5.1-20": selected_claim(
        "implemented-uncredited", "aster-core + aster-node", EVENT_SLICE,
        "Event priority is source-authenticated and accepted by the selected publication API, but it is not yet wired into transmission ordering, retransmission, or eviction.",
    ),
    "DM-5.1-21": selected_claim(
        "implemented-uncredited", "aster-core + aster-redb-store + aster-node", EVENT_SLICE,
        "Event TTL is source-authenticated and ttl=None is durable; remote finite TTL fails closed until authenticated forwarding age and custody policy are ported.",
    ),
    "DM-5.1-22": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {EVENT_SLICE}; {MUTABLE_NETWORK_SLICE}; retained Ping/Pong and current-code direct State/Record contact authenticate authority-provisioned source identities independently at each endpoint",
        "State/Record evidence is one same-implementation current-code contact, not a retained receipt. Blob networking and independent interoperability remain open.",
    ),
    "DM-5.2-01": selected_claim(
        "observed-bounded",
        "aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; retained three- and eight-node loopback lines converged Event transfers, while a current-code two-node real-Iroh contact converged one State inventory and two disconnected Record revisions under explicit interests",
        "The State/Record observation is one same-implementation direct contact, not a retained receipt or all-reachable-node result. Multiple-scope lifecycle, Blob, long partitions, mixed implementations, physical links, and requirement scale remain open.",
    ),
    "DM-5.2-02": selected_claim(
        "implemented-uncredited",
        "aster-redb-store + aster-node",
        f"{EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {MUTABLE_NETWORK_SLICE}; durable Event Consume/Carry selectors and explicit class-separated State/Record topic/scope selectors become mission-protected receiver interests; current-code real-Iroh tests deliver selected Event, State, and Record objects",
        "The tests observe same-implementation two-node flows, not all reachable subscribed nodes or global convergence. No retained multi-class receipt exists; repeated multi-scope lifecycle, Blob, long partitions, physical peers, scale, and mixed implementations remain open.",
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
        "Verify broader sequential/concurrent State/Record network projections, Blob, long partitions, independent interoperability, and scale.",
    ),
    "DM-5.2-10": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-negentropy + aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; Event, State, and Record counters/context are authoritative while class-specific exact transfer IDs reconcile with Negentropy timestamp zero",
        "Verify tombstone propagation, finite TTL forwarding age, long partitions, and long-running operation without trustworthy time.",
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
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; bounded identifier-set reconciliation computes differences over class-specific exact Event, State, and Record transfer identities; retained Event evidence shows equal inventory transfers nothing",
        "Publish total-size-versus-difference cost evidence at requirement scale.",
    ),
    "DM-5.3-01": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{STATE_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; an active version whose authenticated context observes another version's dot dominates it, causal maxima remain active, exact-key query returns the deterministic current, and remote ingest retains the same authenticated causal facts",
        "One State crosses a same-implementation two-node contact, but divergent/concurrent State network convergence, expiry/garbage collection, independent interoperability, scale, and retained acceptance remain open.",
    ),
    "DM-5.3-02": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{STATE_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; when active State maxima are concurrent, the greatest complete source-authenticated semantic State ID is current and the other maxima remain explicitly Concurrent; network ingest preserves the same immutable facts and a current tombstone remains visible",
        "The deterministic concurrent tie-break still has current-code local tests only. No delete-wins rule is inferred, and mixed-implementation, divergent cross-node, adversarial-scale, and retained acceptance evidence remain open.",
    ),
    "DM-5.3-06": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; all active causal Record maxima are retained when no automatic merge executes; a real-Iroh contact between two disconnected publishers leaves the same two heads on both independent stores",
        "The selected slice deliberately executes no registered merge policy. The observation is one same-implementation direct contact; add a convergent registered-policy design separately, then verify longer partitions, relays, retention/GC interaction, mixed implementations, scale, and release acceptance.",
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
        "observed-bounded",
        "aster-redb-store + aster-node",
        f"{RECORD_LOCAL_SLICE}; {MUTABLE_NETWORK_SLICE}; ordinary publish fails atomically across multiple heads, guarded resolution must observe the exact complete sibling set, and a real-Iroh contact preserves both disconnected revisions on both stores without merge execution",
        "The network observation is one same-implementation direct contact. Verify crashes at external boundaries, longer partitions and relays, automatic merge if later added, mixed implementations, adversarial scale, and release acceptance.",
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
        f"{BLOB_LOCAL_SLICE}; immutable Blob bytes and identity metadata never enter the State/Record causal merge reducers, while multiple signed source publications can reference one exact completed content variant without changing it",
        "This is local mechanism evidence only. Selected Blob network delivery, adversarial multi-writer interoperability, retention/GC policy, scale, and acceptance remain open.",
    ),
    "DM-5.4-01": selected_claim(
        "implemented-uncredited", "aster-profile", PROFILE_EVIDENCE,
        "Adopt stakeholder-approved names/count and wire priority through authenticated items and scheduling.",
    ),
    "DM-5.5-01": selected_claim(
        "implemented-uncredited", "aster-core + aster-redb-store + aster-node",
        f"{EVENT_SLICE}; {EVENT_SUBSCRIPTION_SLICE}; {MUTABLE_NETWORK_SLICE}; Event, State, and Record topic/scope are distinct authenticated fields and durable index dimensions; Event uses canonical Consume/Carry selectors and mutable classes use explicit canonical interests",
        "Repeated multiple-scope selector lifecycle, bridges, Blob networking, and independent interoperability remain open.",
    ),
    "DM-5.5-02": selected_claim(
        "implemented-uncredited", "aster-redb-store + aster-node",
        f"{EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {MUTABLE_NETWORK_SLICE}; bounded canonical Event selectors and explicit State/Record interest sets become mission-protected receiver interests; empty means receive-none; current-code direct contacts synchronize selected objects",
        "State/Record interests are runtime configuration rather than durable application subscriptions. No retained multi-class receipt exists; Blob, repeated multi-scope replacement lifecycle, physical peers, scale, and mixed-implementation acceptance remain open.",
    ),
    "DM-5.5-03": selected_claim(
        "implemented-uncredited", "aster-node",
        f"{MISSION_RECEIPT}; {CONTROL_RECEIPT}; {MUTABLE_NETWORK_SLICE}; per-contact Event, State, and Record inventory/Offer are filtered by the authenticated peer's current authority-signed scope/epoch route grant",
        "Verify repeated join/leave and membership churn across multiple scopes, Blob, physical peers, and independent implementations.",
    ),
    "DM-5.5-05": selected_claim(
        "observed-bounded", "aster-core + aster-redb-store + aster-node",
        f"{RECEIPT}; the intermediate had route access but no topic-content grant, retained exact sealed bytes, and semantically accepted zero Events",
        "The observation covers one Event topic/scope and line topology; generalized relay policy and all other data classes remain open.",
    ),
    "DM-5.5-06": selected_claim(
        "implemented-uncredited", "aster-node",
        f"{MISSION_RECEIPT}; {CONTROL_RECEIPT}; peers without the current authenticated Event scope/epoch route grant learn no matching inventory ID and cannot fetch or offer it",
        "Verify repeated dynamic membership changes, multiple scopes, physical peers, and all data classes.",
    ),
    "DM-5.5-07": selected_claim(
        "implemented-uncredited", "aster-redb-store",
        f"{EVENT_SLICE}; route-only cache and accepted Event bytes share aggregate store limits, with additional hard route-cache caps",
        "Expose and verify operator-configurable relay quotas, eviction policy, priority interaction, and sustained pressure behavior.",
    ),
    "DM-5.6-01": selected_claim(
        "implemented-uncredited",
        "aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; same-implementation nodes synchronized source-sealed Event, State, and Record objects over direct one-host loopback",
        "Add independent conformance, broader partitions/relays, and networked Blob before physical transport and broader network acceptance.",
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
    "DM-5.8-10": selected_claim(
        "observed-bounded",
        "aster-iroh",
        f"{RECEIPT}; local direct operation completed with relays, discovery, and port mapping disabled",
        "Verify local and mesh operation on physical systems and all required carriers.",
    ),
    "DM-6-01": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; Event, State, and Record content remain source-sealed independently of the Iroh carrier session; retained evidence additionally shows an Event route-only relay cannot open content",
        "State/Record evidence is a current-code direct contact with no relay or packet capture. Complete Blob, carrier variants, provisioning, and independent review.",
    ),
    "DM-6-02": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{MISSION_RECEIPT}; {MUTABLE_NETWORK_SLICE}; exact source-sealed Event, State, and Record bytes are freshly verified before inventory serving and remote admission; Event is also reverified before application reaction",
        "Complete networked Blob, State/Record application delivery, hostile physical-network acceptance, independent interoperability, and cryptographic review.",
    ),
    "DM-6-03": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; destinations authenticate authority-provisioned Event, State, and Record publishers independently of carrier and session identities",
        "Complete networked Blob, generalized publication, protected provisioning, platform-complete zeroization assurance, broader control lifecycle, and independent review.",
    ),
    "DM-6-04": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; isolated Event cohorts and disconnected State/Record test publishers source-seal objects before the corresponding contact",
        "State/Record evidence is one current-code direct contact. Blob, generalized publication, key lifecycle beyond one bounded rekey, and independent review remain open.",
    ),
    "DM-6-05": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {MUTABLE_NETWORK_SLICE}; Event, State, and Record objects carry authenticated source identities and signed semantic headers",
        "The State/Record claim is bounded to one current-code direct contact; Blob, generalized publication, and independent interoperability remain open.",
    ),
    "DM-6-06": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; {MUTABLE_NETWORK_SLICE}; Event applications react only to content-verified payloads, while State/Record remote admission requires exact content verification and never executes application merge code",
        "State/Record have no live application delivery path. Blob, bindings, physical peers, and independent interoperability remain open.",
    ),
    "DM-6-07": selected_claim(
        "observed-bounded", "aster-core + aster-redb-store + aster-node",
        f"{RECEIPT}; the relay exact-forwarded two source-sealed Events with content_access=denied and semantic_acceptance=none",
        "Verify generalized policies, finite custody, all data classes, physical links, and independent review.",
    ),
    "DM-6-09": selected_claim(
        "implemented-uncredited", "aster-core + aster-node",
        f"{EVENT_SLICE}; {MUTABLE_NETWORK_SLICE}; Event, State, and Record topic/scope/priority/TTL/causal/routing metadata are inside protected source envelopes and mechanics frames are session protected",
        "Publish packet-capture evidence across supported carriers and complete networked Blob and independent review.",
    ),
    "DM-6-10": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {CONTROL_RECEIPT}; an authenticated route-only relay verified protected Event scope/epoch metadata and forwarded exact epoch-one and epoch-two bytes without content access",
        "Generalize route policy and repeated multi-scope lifecycle across all data classes, bridges, and physical carriers.",
    ),
    "DM-6-11": selected_claim(
        "implemented-uncredited", "aster-core + aster-node",
        f"{EVENT_SLICE}; {MUTABLE_NETWORK_SLICE}; Event, State, and Record forwarding metadata is source-envelope protected and later mechanics frames are mission-session protected",
        "Complete networked Blob, packet-capture acceptance, all supported carriers, metadata-length analysis, and independent cryptographic review.",
    ),
    "DM-6-12": selected_claim(
        "implemented-uncredited", "aster-core + aster-node",
        f"{EVENT_SLICE}; {MUTABLE_NETWORK_SLICE}; Event, State, and Record source envelopes plus mission-protected mechanics leave carrier necessities outside their protection boundary",
        "Define and verify the exact unavoidable-plaintext profile with packet captures across all supported carriers.",
    ),
    "DM-6-13": selected_claim(
        "observed-bounded",
        "aster-node::mission",
        f"{MISSION_RECEIPT}; {CONTROL_RECEIPT}; the runtime checks expected mission NodeId independently from Iroh EndpointId before inventory and rejects a durably revoked mission principal",
        "Add protected operational provisioning, non-Unix and physical zeroization assurance, authority/signer handoff and recovery, and independent security acceptance; carrier identity remains deliberately separate.",
    ),
    "DM-6-14": selected_claim(
        "observed-bounded",
        "aster-node::mission",
        f"{MISSION_RECEIPT}; the runtime requires and loads a bounded owner-only unprotected-reference bundle before state or sockets",
        "Deliver an admitted protected-at-rest provisioning workflow, persistent secret custody, platform-complete zeroization assurance, and operational recovery.",
    ),
    "DM-6-18": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{RECEIPT}; {CONTROL_RECEIPT}; only included members opened epoch-two Ping/Pong while the route-only relay and omitted captured node could not",
        "Verify repeated rekeys across multiple topics/scopes, generalized subscriptions, all data classes, and independent security review.",
    ),
    "DM-6-19": selected_claim(
        "observed-bounded", "aster-core + aster-node",
        f"{MISSION_RECEIPT}; {CONTROL_RECEIPT}; a node without the current scope route grant learns no Event ID, a route-only node lacks content access, and the captured node learned no epoch-two data",
        "Complete repeated dynamic multi-scope lifecycle, broader compromise cases, all data classes, and independent review.",
    ),
    "DM-6-20": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{CONTROL_RECEIPT}; the authority process and node were absent while a payload-blind relay forwarded the exact revocation/rekey suffix to a surviving member; a separate no-peer cohort then published epoch-two Ping before a later Event-transfer cohort, and the survivor denied the revoked leaf",
        "The receipt covers two controls crossing one relay on one-host loopback; longer partitions, loss/bandwidth impairment, multiple relays/carriers, crash points, physical systems, and independent implementations remain open.",
    ),
    "DM-6-21": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{CONTROL_RECEIPT}; an authority process committed a recipient-filtered scope transition from epoch one to two; after control convergence, an included member published epoch-two Ping with no peer or contact, a separate cohort moved it into the route-only cache, and four later barriers delivered Ping, committed causal Pong with no contact, cached Pong, and returned it while the omitted captured node learned no fresh content",
        "One scope advanced once for three exact recipients on loopback; repeated/multi-scope rekey, membership churn, authority recovery, protected registry administration, physical field evidence, and independent implementations remain open.",
    ),
    "DM-6-22": selected_claim(
        "observed-bounded",
        "aster-node + aster-redb-store + platform security owner",
        f"{ZEROIZATION_RECEIPT}; a same-UID Unix CLI triggered a live child node to drain, commit a terminal redb intent, invalidate in-process secret holders, and overwrite, synchronize, and truncate the exact retained mission-bundle and carrier-identity inodes; data rows survived, restored credentials could not reopen the retained Complete database, idempotent replay preserved the external restoration, and a separate real child resumed cleanup after abrupt exit immediately after the marker",
        "The hook is Unix-only bounded software erasure of two owner-only, uniquely linked files. It preserves data rows and zero-length pathnames and does not prove inode deletion, physical flash or copy-on-write sanitization, snapshot/swap/backup destruction, protection against redb rollback or replacement, remote triggering, deterministic teardown of a mid-flight stream, protected operational provisioning, or independent platform assurance.",
    ),
    "DM-6-23": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{MISSION_RECEIPT}; {CONTROL_RECEIPT}; {EVENT_SUBSCRIPTION_SLICE}; {EVENT_LIVE_SLICE}; protected-frame replay/plaintext, control rollback/fork, stale epoch and revoked-source traffic fail closed; Event publication, selector insert/remove, delivery attempts, acknowledgement, live admission closure, and receiver restart are durable, idempotent, or fail closed",
        "Verify captured replay across physical sessions, every data class, abrupt interruption at each live command/contact boundary, long retention/eviction boundaries, and independent implementations.",
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
    "DM-7-11": selected_claim(
        "implemented-uncredited",
        "aster-node::application",
        f"{EVENT_LIVE_SLICE}; SelectedEventHandle exposes typed publish, query, subscribe, poll, acknowledge, unsubscribe, authenticated gaps, sync status, and peer status with sanitized errors",
        "This is an Event-only partial boundary. State/Record/Blob, conflict annotations, control/provisioning administration, selected-node bindings, and the complete adopter-facing API remain open.",
    ),
    "DM-7-14": selected_claim(
        "implemented-uncredited",
        "aster-node::application",
        f"{EVENT_LIVE_SLICE}; SelectedEventHandle operations and results contain no carrier type, endpoint, address, path choice, or transport selection",
        "Node startup still requires separate direct-Iroh configuration, and the complete multi-class API, bindings, local-agent decision, and future multi-carrier composition require the same boundary audit.",
    ),
    "DM-7-15": selected_claim(
        "implemented-uncredited",
        "aster-node::application",
        f"{EVENT_LIVE_SLICE}; the live Event surface returns application items, delivery attempts, verified gap intervals, and high-level last-contact status without exposing inventories, exact transfer IDs, Negentropy state, or contact protocol frames",
        "Complete and audit the same abstraction across State/Record/Blob, conflict workflows, bindings, control administration, and any optional local agent.",
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
        "aster-node + shipped documentation",
        f"{EVENT_LIVE_SLICE}; docs ship a runnable live example, a complete high-level code path, conservative gap/status semantics, and the focused offline-publish/later-sync test command",
        "Compilation and automated tests are not an independent developer-usability study; other data classes, selected-node bindings, operational provisioning, and the complete integration surface remain open.",
    ),
    "DM-7-20": selected_claim(
        "observed-bounded",
        "aster-node",
        f"docs/quickstart/mesh-cli.md; {EVENT_LIVE_SLICE}; the shipped CLI runs bounded source-authenticated Event Ping/Pong, and compiled stopped/live examples exercise high-level Event publication, query, durable delivery, unsubscribe, gaps, and status",
        "Add other data classes, selected-node bindings, operational provisioning, and physical multi-system instructions/evidence.",
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
        f"{DEPENDENCY_GATE}; docs/decisions/0028-selected-stack-implementation-boundary.md; deny.toml; THIRD_PARTY_NOTICES.md; the stakeholder approved five exact-coordinate CDLA/Unlicense exceptions with hash-pinned distribution notices, while the CDLA treatment remains a visible deviation from the frozen OSI-only rule",
        "Keep the exact exception and notices fail-closed; define supported release targets and either amend the normative OSI-only rule or replace the CDLA trust-root path before claiming DM-8-05 credit.",
    ),
    "DM-9-13": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; read_into freshly verifies the selected publication and completed depot variant, then reads canonical encrypted chunk files and streams independently authenticated plaintext chunks into a caller-owned writer",
        "The selected reader is stopped/local and synchronous. Remote chunk transport, carrier switching, physical-disk acceptance, maximum-size runs, platform breadth, and retained resource evidence remain open.",
    ),
    "DM-9-14": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{BLOB_LOCAL_SLICE}; preparation uses one bounded zeroizing plaintext chunk buffer and, after its first pass, retains only the one-MiB-manifest-bounded digest vector; the core streaming engine reports its peak chunk-buffer capacity, every store-adapter buffer is independently chunk-bounded, and tests compare multi-chunk output without collecting the complete Blob in the component",
        "The public metric is the core reader's buffer, not whole-operation peak memory; the adapter may hold additional bounded chunk-sized buffers. Current evidence uses modest local fixtures. Add bracketed process resident-memory measurements on supported targets, physical storage/resource accounting, remote transfer, and retained acceptance before crediting the full resource target.",
    ),
    "DM-9-21A": selected_claim(
        "implemented-uncredited",
        "aster-node",
        "docs/implementation/requirements-status.md#bounded-scale-probes; configurable demo accepts 2 through 32 with 2N+1 cohorts and 5N-2 children, and current source-authenticated Event receipts passed at 3 nodes/13 processes and 8 nodes/38 processes",
        "Eight nodes do not prove the bracketed many-node target, the full 2-through-32 range, physical scale, or resource targets.",
    ),
    "DM-11-20": selected_claim(
        "implemented-uncredited",
        "aster-core + aster-redb-store + aster-node",
        f"{CONTROL_RECEIPT}; durable revocation is present in the selected production lane and one real-process captured-leaf scenario passed",
        "Revocation is present, but the complete MVP, protected operational provisioning, platform-complete zeroization assurance, generalized control administration, and release gates remain incomplete.",
    ),
    "DM-12-08": selected_claim(
        "observed-bounded",
        "aster-core + aster-redb-store + aster-node",
        f"{CONTROL_RECEIPT}; one four-node equivalent scenario revoked a leaf, propagated the exact control suffix without the authority online, rekeyed the affected scope, separated no-peer epoch-two Ping and Pong publication from their later route-only transfers through explicit causal barriers, exchanged both Events among eligible nodes, and denied two captured-node contacts",
        "This is one-host direct-Iroh loopback evidence; target and physical devices, real partition/loss, operational provisioning/custody, independent implementation/review, and release authorization remain open.",
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
    "DM-7-11": "crates/aster-node/src/application.rs; docs/decisions/0009-public-api-boundary.md",
    "DM-7-14": "crates/aster-node/src/application.rs; docs/decisions/0009-public-api-boundary.md",
    "DM-7-15": "crates/aster-node/src/application.rs; docs/decisions/0009-public-api-boundary.md",
    "DM-7-18": "docs/quickstart/selected-event-api.md; crates/aster-node/src/application.rs",
    "DM-7-20": "docs/quickstart/mesh-cli.md; docs/quickstart/selected-event-api.md",
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
    "DM-13-04": "crates/aster-host; crates/aster-ip",
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
                row["disposition"] = "stakeholder-approved-deviation"
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
