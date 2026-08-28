# Capability roadmap

- Status date: 2026-08-28
- Product-intent authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Security-profile applicability:
  [`security-profile-requirements-disposition.md`](security-profile-requirements-disposition.md)
- Evidence authority: [`requirements-status.md`](requirements-status.md)
- Atomic trace: [`requirements-implementation.csv`](requirements-implementation.csv)
- Current release posture: **evaluation-stage; not production-authorized**

## Purpose

This is the planning and review view of the data-mesh requirements. It groups
the draft target state into demonstrable product outcomes so that progress can
be evaluated without treating the 348-row atomic trace as a flat backlog or a
percentage-complete score.

The hash-bound requirements document remains the provenance baseline. Reviewed
decisions may refine a row's current applicability without rewriting that
baseline; the accepted security-profile overlay does so for metadata and
post-quantum policy. This roadmap does not itself waive a requirement or
advance implementation credit. It defines how work is sequenced and reviewed.
For planning purposes,
the aggregate scope in requirements §§11–13 is called the **complete MVP target
product profile**; incremental PRs and explicitly bounded evaluation profiles
may advance toward it without claiming it complete.

The atomic trace remains useful for stable IDs, exact evidence, duplicated
phase obligations, external gates, and future work. A single capability can
move several rows, and several rows can restate the same outcome. Conversely,
the presence of a mechanism can move a row without completing the user-visible
capability. Capability maturity therefore follows the weakest material gap in
the outcome, not an average of row statuses.

## Maturity vocabulary

| Maturity | Planning meaning |
|---|---|
| **Demonstrated — bounded** | The selected composition produced reproducible evidence for the stated environment and claim boundary. This is not general release evidence. |
| **Implemented — evidence pending** | Material mechanisms and automated tests exist, but the end-to-end outcome lacks retained or representative evidence. |
| **Partial** | Useful parts exist, but a material user-visible, operational, or cross-component path is absent. |
| **Open** | The selected composition does not yet provide the outcome. |
| **External decision/gate** | Completion depends on stakeholder policy, target systems, independent work, or an admitted external component rather than only repository implementation. |

These maturity labels summarize outcomes. They do not replace the conservative
`observed-bounded`, `implemented-uncredited`, and `open` values in the atomic
trace.

## How to treat the 348 atomic rows

The source document is still a draft, and atomization is not stakeholder
ratification. Keep every row traceable until it is affirmed, revised, deferred,
or rejected through a reviewed profile or decision record, but do not turn all
rows into engineering tickets:

- core security, correctness, and compatibility invariants constrain any
  capability to which they apply;
- capability statements describe target outcomes and should be planned in
  coherent groups;
- acceptance and deliverable rows often restate those outcomes and define
  evidence, rather than adding separate product features;
- assumptions, non-goals, provisional values, and open stakeholder choices are
  constraints or decisions, not implementation tasks by themselves; and
- Post-MVP and Future rows stay visible without entering the current merge
  queue unless a named profile pulls them forward.

When a requirement is no longer credible, record the decision and applicability
explicitly; do not manufacture implementation work merely to close its row.

## Adopted security-profile direction

[Decision 0033](../decisions/0033-policy-selected-security-profiles.md) and its
[requirements disposition](security-profile-requirements-disposition.md) make
metadata exposure and post-quantum use explicit profile policy:

- source payload encryption/authentication, payload-blind forwarding, Aster
  mission authorization, plaintext minimization, agility, and downgrade
  resistance remain profile-invariant;
- a secure carrier may protect ephemeral contact metadata, while persistent
  forwarding metadata is independently protected where practical and every
  unavoidable exposure is declared;
- complete classical and hybrid-PQ profiles are target capabilities, with
  mission policy setting the minimum and required PQ failing closed; and
- suite/profile `0x0001` keeps all of its hybrid components and wire meanings;
  additive profile `0x0002` now implements a semantic-v1 classical Event/control
  and Iroh-exporter-bound two-node mission path without changing the stock
  selected runtime.

Profile `0x0002` includes provisioned singleton selection, exact mixed-profile
failure, a local durable profile/generation binding, declared metadata exposure,
and same-implementation tests. Runtime/CLI selection, representative capture,
compute/memory/energy evidence, snapshot-resistant rollback, retained receipts,
and release authorization remain open. Existing evidence statuses do not move.

## Current capability outcomes

| Outcome | Current maturity | Demonstrable progress | Next material outcome | Explicitly not claimed |
|---|---|---|---|---|
| **Authenticated offline-first Event exchange** | **Demonstrated — bounded** | Selected nodes publish while disconnected, reconcile source-authenticated Events over direct Iroh contacts, and expose live Rust and local ConnectRPC application paths with durable delivery/custody mechanics. The [9,573-byte signed-source receipt](evidence/selected-live-event-c464129.json) observes three peerless alpha Events plus one authorized beta Event, threshold delivery of alpha sequences 1 and 3 with authenticated gap `[2,3)`, forced receiver-child termination after a flushed unacknowledged poll, fresh-process attempt-2 redelivery with ack/re-ack, and normal sequence-2 gap closure on one same-implementation loopback host. Beta is withheld; a temporary subscription observes `PolicyChangedSinceContact` and is removed without a later contact or delivery. | Turn the bounded Event path into a named supported evaluation profile across declared platforms and network conditions; add positive failed-contact observation and fresh post-policy completion/delivery evidence. | Physical or representative network convergence, NAT/Internet, relay, BTLE, mixed or independent implementations, scale/resource/soak evidence, positive failed-contact propagation, post-policy beta delivery, other-class acceptance, reproducible source-to-execution proof, or production authorization. |
| **Intermittent store-and-forward relay and membership recovery** | **Demonstrated — bounded** | Controlled payload-blind Event relay, temporal custody, mission-authenticated contacts, revocation propagation, explicit rekey, and bounded zeroization have retained or current-code evidence. The [4,377-byte signed-source Linux custody receipt](evidence/selected-linux-event-custody-ade6ee1.json) additionally observes exact route-only Event quota pressure, two Linux-boottime expiries, priority-ordered store-and-forward, and ReceiveOnly ingestion in one loopback container. | Demonstrate the complete operational workflow with representative partitions, protected provisioning, target systems, and declared relay trust. | Automatic/atomic revoke-plus-rekey, route-only custody for every class, platform-complete erasure, physical constrained-link acceptance, mixed implementations, or hostile-field acceptance. |
| **State and Record convergence without silent conflict loss** | **Demonstrated — bounded** | Source-authenticated State and Record objects publish peerless through cloneable live handles and reconcile directly. The [7,752-byte signed-source v2 receipt](evidence/selected-live-mutable-6cabb4c.json) retains exact concurrent State heads, a causally later successor, and an authenticated empty tombstone through one immediate peerless restart, while Record retains explicit siblings through guarded resolution and restart. A separate [9,656-byte signed-source State-delivery receipt](evidence/selected-live-state-subscription-8912fc3.json) observes one durable application subscription across three processes, forced receiver-process replacement, attempt-2 redelivery and acknowledgement, selector withholding, causal ancestor suppression, a current tombstone, and one final peerless reopen. A separate [10,357-byte signed-source Record-delivery receipt](evidence/selected-live-record-subscription-0c11344.json) observes the complete active-head set as one delivery, forced-process attempt-2 redelivery, guarded resolution and a successor projection, selector separation, and final peerless reopen on one same-implementation direct-loopback host. | Broaden the result across representative physical and mixed implementations, partitions, relay paths, and declared resource brackets; then add bindings, finite TTL, retention, expiry, and garbage collection. | Indefinite tombstone retention, garbage collection, delete-wins, materialized State-view convergence, synthetic withdrawal delivery, State contact/status behavior, dynamic network-interest mutation, selected-node bindings, finite-TTL forwarding age, automatic registered-policy merge, temporal relay coverage, physical/mixed acceptance, scale beyond two, resource thresholds, long-partition acceptance, or release authorization. |
| **Authenticated resumable Blob movement** | **Demonstrated — bounded** | The selected composition has authenticated immutable publication, a cloneable actor-owned live Blob handle for bounded regular-file publication and zeroize-on-drop paged reads, a durable metadata-only application-delivery ledger keyed by exact source publication, bounded-memory encrypted depot streaming, and semantic-v5 direct source-before-carrier range transfer with durable resume state. A [signed-source retained transfer receipt](evidence/selected-live-blob-044d90f.json) observes one peerless-published 96-KiB two-chunk Blob, direct seeding to a replica, a 16-KiB non-public receiver prefix retained across graceful same-process reopen, one-contact continuation from that different eligible peer without source refetch, exact reconstruction, authenticated receiver reads, and final graceful reopen on one same-implementation loopback host. A separate [10,269-byte signed-source delivery receipt](evidence/selected-live-blob-subscription-26e0a09.json) observes two exact publications sharing one `BlobId`, finalized depot variant, and committed chunk; a flushed attempt-one poll, forced receiver `SIGKILL`, attempt-two token rotation, earlier same-tenure token acknowledgement/reacknowledgement, and final empty local-ledger status across three processes/four actor lifetimes on one peerless host. | Broaden the peerless delivery/redelivery result into representative networked and selector-separation observations, then demonstrate remote retention, cleanup and failure recovery across process/crash boundaries and longer offline windows. | Network contact/transfer or selector-withholding/network-interest-separation delivery acceptance, peer/convergence or transfer-progress status, process-crash/power-loss or long-offline recovery, arbitrary-peer or route-only Blob resume/custody, full TTL/GC policy, large-target/RSS acceptance, mixed implementations, physical systems, or all-carrier transfer. |
| **Reachability and carrier portability** | **Partial** | Manually admitted direct IP contacts and an explicitly configured controlled HTTPS relay work behind one transport abstraction. | Define and demonstrate the supported IP reachability profile, including NAT behavior and discovery, then add real BTLE and cross-transport acceptance. | Infrastructure-free NAT traversal, default/public relay dependence, automatic discovery, BTLE platform integration, or RF broadcast efficiency. |
| **Mission security and operator lifecycle** | **Partial** | Profile `0x0001` provides the stock hybrid-PQ mission/source/control path. Additive profile `0x0002` provides exact provisioned policy, P-256 semantic-v1 Event/control protection, a distinct Iroh ALPN and TLS-exporter-bound four-flight mission path, raw QUIC application frames, local profile-generation store binding, and same-implementation mismatch tests. No retained evidence status moves. | Integrate profile policy into a named runtime/CLI and protected provisioning workflow; add snapshot-resistant rollback, representative packet capture and compute/memory/bandwidth/idle/energy results; then prove the operational issue/recover/revoke/rekey/zeroize lifecycle. | PQ-free distribution/code-size result, profile `0x0002` State/Record/Blob/batch/bridge/rekey, target resource/energy result, retained or mixed-implementation evidence, FIPS-path closure, hardware custody, physical sanitization, complete metadata-exposure acceptance, or production authority. |
| **Embeddable developer surface** | **Partial** | Event, State, Record, and Blob have cloneable live Rust handles; Event has durable stream delivery, State has retained bounded evidence for durable positive-current-version delivery, Record has retained-bounded durable whole-key active-head delivery, and Blob has retained-bounded peerless metadata-only exact-publication delivery plus bounded file publication and authenticated plaintext pages. Event alone has contact status plus a local ConnectRPC API. All four classes retain stopped facades. The retained State/Record/Blob acceptance producers are outside the adopter API and are not minimal developer samples or usability studies. | Broaden Blob delivery evidence, add Blob peer/convergence status plus minimal compiled developer-facing State/Record delivery and Blob samples, add supported selected-node C ABI/bindings, and measure integration usability. | Complete four-class peer/status/binding set, networked/selector-separated Blob delivery acceptance, State status/materialized-view/withdrawal behavior if required, dynamic State/Record/Blob network-interest mutation, binding template, protected stock agent administration, independent usability, or the provisional one-day integration target. |
| **Protocol, conformance, and release assurance** | **Open** | Versioned selected wire/profile documents, compatibility rules, dependency policy, an SBOM path, and extensive same-implementation tests provide a foundation. | Name a release profile; close its normative specification, conformance, platform, dependency, security-review, resource, and representative acceptance gates. | Independent implementation interoperability, complete MVP conformance, or any production release authorization. |

The Record receipt above is 10,357 bytes, has SHA-256
`ba0e2bf47291f7e87000b85fa280cc957f3710ac800def82a51fb9b4657a1b48`,
and binds Good-signed source commit `0c1134411953f4bb52133b50aff9989cd4ce3930`.
Its bounded run uses two participants, three processes, and seven actor
lifetimes. It retains a complete two-head edit/tombstone conflict as one delivery
at `delivery_limit=1` and `scan_limit=16`, then sends the receiver `SIGKILL`
after its flushed durable unacknowledged attempt-one poll. A fresh process gets
the same projection at attempt two with a rotated 89-byte token. A fresh exact
query guard resolves both heads, a new successor projection is delivered, and
both originals remain query-only superseded history. Beta is
network-interested/application-unmatched and retained without delivery; gamma is
application-matched/network-uninterested and withheld, and the subscription does
not mutate network interest. A final peerless reopen replays the subscription
with an empty acknowledged queue, the resolved current successor, and the two
query-only originals.

Only `DM-5.1-08` moves. `DM-7-11`, `DM-7-14`, `DM-7-15`, and
`DM-7-18` remain implemented-uncredited; `DM-7-20` is unchanged. The receipt
adds no finite-TTL/GC, physical/NAT/relay/BTLE, mixed-implementation,
scale/resource/soak, selected-node bindings, automatic-merge, reproducible
source-to-binary proof, or release credit.

The Blob-delivery receipt above is 10,269 bytes, has SHA-256
`3d0c0b2da629282c56de5ae9dacc8920c9960defba083c6bff856e2c0612a675`,
and binds Good-signed source commit
`26e0a090b9a6f644d96b38cfaa23f4e2139ad8b1`. Its 35-record peerless run uses
one host and participant, three processes, and four actor lifetimes: three stop
gracefully and one receiver child is sent `SIGKILL` after a flushed
unacknowledged poll. Two exact source publications share one immutable
`BlobId`, finalized depot variant, and committed chunk but remain separate
deliveries. Attempt one rotates to attempt two after process replacement; the
restored earlier same-tenure token acknowledges and reacknowledges the pending
publication, the second publication is separately acknowledged/reacknowledged,
and final peerless reopen reports an empty local ledger.

Only `DM-5.3-04` moves, producing 43 implemented-uncredited, 84
observed-bounded, and 221 open rows; the DM-5 roll-up is 21/50/51. The receipt
adds no network contact/transfer/synchronization, selector-withholding or
network-interest-separation, peer status, TTL/GC, plaintext/read, physical or
mixed-system, scale/resource, reproducible-build, or release credit.

## Working delivery sequence

This sequence is an outcome-oriented planning default, not a promise that every
task is serial or that unrelated future/external gates block useful merges.

1. **Stabilize a supported Event/relay evaluation profile.** Name its platforms,
   reachability assumptions, security boundary, APIs, evidence, and exclusions.
2. **Complete the live four-class application path.** Broaden the bounded
   State/Record/Blob delivery and interrupted-resume Blob receipts into
   representative retained usability, network and selector separation, longer
   partitions, failure recovery, and cleanup, then add the required status,
   bindings, and lifecycle coverage.
3. **Operationalize security profiles.** Carry the exact implemented classical
   and hybrid-PQ profile policy through a named runtime/CLI, protected
   provisioning, snapshot-resistant rollback, declared-target resource/capture
   tests, and provisioning-through-destruction workflow.
4. **Broaden reachability and carriers.** Close the chosen IP/NAT/discovery
   profile before adding and proving BTLE and cross-transport behavior.
5. **Productize a named release profile.** Finish only the specification,
   conformance, bindings, platform, resource, and external gates applicable to
   that declared profile; retain the complete MVP target as the broader goal.

## PR review and merge standard

A PR should identify the capability outcome it advances and distinguish a
mechanism from an end-to-end result. Review should answer:

1. Does the change make a coherent, usable, or risk-reducing increment toward
   the named outcome?
2. Are its claims no broader than its code, tests, environment, and retained
   evidence?
3. Does it preserve applicable security, causal, compatibility, and ownership
   invariants?
4. Are regressions and important failure modes tested in proportion to risk?
5. If the evidence boundary changed, are the exact atomic IDs and remaining
   gaps updated conservatively?

A “yes” does not require the PR to close every row associated with the outcome,
or any unrelated target-profile, future, provisional, stakeholder, or external
gate. A PR must not claim the outcome complete merely because a mechanism exists
or a row moved to `implemented-uncredited`.

## Release profiles

Before creating a release candidate, record one profile containing:

- intended users and use case;
- supported platforms, carriers, topology, and operating bounds;
- included capability outcomes and public APIs;
- applicable security/correctness invariants and acceptance scenarios;
- exact permitted security profiles, authenticated minimum and rollback policy,
  metadata-exposure budget, connection-idle behavior, and resource/energy bounds;
- required artifacts, independent evidence, and external approvals; and
- explicit exclusions and upgrade/compatibility expectations.

An **evaluation profile** may intentionally cover a bounded subset and must say
so. A **production profile** requires representative operational evidence and
all gates applicable to its claims. The **complete MVP target product profile**
is the broad target in §§11–13 of the requirements document; it is not the
default gate for every incremental merge or partial evaluation release.

No production release profile is currently authorized.
