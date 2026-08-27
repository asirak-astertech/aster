# Capability roadmap

- Status date: 2026-08-27
- Product-intent authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Evidence authority: [`requirements-status.md`](requirements-status.md)
- Atomic trace: [`requirements-implementation.csv`](requirements-implementation.csv)
- Current release posture: **evaluation-stage; not production-authorized**

## Purpose

This is the planning and review view of the data-mesh requirements. It groups
the draft target state into demonstrable product outcomes so that progress can
be evaluated without treating the 348-row atomic trace as a flat backlog or a
percentage-complete score.

The hash-bound requirements document remains the target-state and provenance
baseline. This roadmap neither waives that target nor advances implementation
credit. It defines how work is sequenced and reviewed. For planning purposes,
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

## Current capability outcomes

| Outcome | Current maturity | Demonstrable progress | Next material outcome | Explicitly not claimed |
|---|---|---|---|---|
| **Authenticated offline-first Event exchange** | **Demonstrated — bounded** | Selected nodes publish while disconnected, reconcile source-authenticated Events over direct Iroh contacts, and expose live Rust and local ConnectRPC application paths with durable delivery/custody mechanics. | Turn the bounded Event path into a named supported evaluation profile across declared platforms and network conditions. | General physical-network convergence, every transport, production authorization, or independent interoperability. |
| **Intermittent store-and-forward relay and membership recovery** | **Demonstrated — bounded** | Controlled payload-blind Event relay, temporal custody, mission-authenticated contacts, revocation propagation, explicit rekey, and bounded zeroization have retained or current-code evidence. | Demonstrate the complete operational workflow with representative partitions, protected provisioning, target systems, and declared relay trust. | Automatic/atomic revoke-plus-rekey, route-only custody for every class, platform-complete erasure, or hostile-field acceptance. |
| **State and Record convergence without silent conflict loss** | **Demonstrated — bounded** | Source-authenticated State and Record objects publish peerless through cloneable live handles, reconcile directly, retain explicit concurrent State versions, and retain explicit Record siblings through guarded resolution and restart. The [signed-source retained receipt](evidence/selected-live-mutable-2ccfba0.json) is one-host, same-implementation loopback evidence. | Broaden the result across representative physical and mixed implementations, partitions, relay paths, and declared resource brackets, then extend subscriptions/bindings, finite TTL, retention, expiry, and garbage collection. | Durable subscriptions, selected-node bindings, finite-TTL forwarding age, automatic registered-policy merge, temporal relay coverage, physical/mixed acceptance, scale beyond two, resource thresholds, or long-partition acceptance. |
| **Authenticated resumable Blob movement** | **Demonstrated — bounded** | The selected composition has authenticated immutable publication, a cloneable actor-owned live Blob handle for bounded regular-file publication and zeroize-on-drop paged reads, bounded-memory encrypted depot streaming, and semantic-v5 direct source-before-carrier range transfer with durable resume state. A [signed-source retained receipt](evidence/selected-live-blob-044d90f.json) observes one peerless-published 96-KiB two-chunk Blob, direct seeding to a replica, a 16-KiB non-public receiver prefix retained across graceful same-process reopen, one-contact continuation from that different eligible peer without source refetch, exact 98,638-carrier-byte reconstruction, authenticated receiver reads, and final graceful reopen on one same-implementation loopback host. | Demonstrate representative remote retention, cleanup and failure recovery across process/crash boundaries, longer offline windows, and the required subscription/status behavior. | Process-crash/power-loss or long-offline recovery, arbitrary-peer or route-only Blob resume/custody, Blob subscription or class-specific status, full TTL/GC policy, large-target/RSS acceptance, mixed implementations, physical systems, or all-carrier transfer. |
| **Reachability and carrier portability** | **Partial** | Manually admitted direct IP contacts and an explicitly configured controlled HTTPS relay work behind one transport abstraction. | Define and demonstrate the supported IP reachability profile, including NAT behavior and discovery, then add real BTLE and cross-transport acceptance. | Infrastructure-free NAT traversal, default/public relay dependence, automatic discovery, BTLE platform integration, or RF broadcast efficiency. |
| **Mission security and operator lifecycle** | **Partial** | Hybrid-PQ mission authentication, source/control authorization, protected-header handling, policy refresh, revocation, recipient-filtered rekey planning, and local software zeroization mechanisms exist. | Select and integrate an admissible production secret/provisioning backend and prove the operational issue/recover/revoke/rekey/zeroize lifecycle. | FIPS-path closure, hardware custody, physical sanitization, complete metadata-privacy acceptance, or production authority. |
| **Embeddable developer surface** | **Partial** | Event, State, Record, and Blob have cloneable live Rust handles; Blob adds bounded file publication and authenticated plaintext pages, while Event alone has durable delivery subscription/contact status and a local ConnectRPC API. All four classes retain stopped facades. The retained live-Blob acceptance producer exercises the high-level handle but is not a minimal developer sample or usability study. | Add required State/Record/Blob subscription and status behavior, a minimal compiled developer-facing live Blob sample, supported selected-node C ABI/bindings, and measured integration usability. | Complete four-class subscription/status/binding set, binding template, protected stock agent administration, independent usability, or the provisional one-day integration target. |
| **Protocol, conformance, and release assurance** | **Open** | Versioned selected wire/profile documents, compatibility rules, dependency policy, an SBOM path, and extensive same-implementation tests provide a foundation. | Name a release profile; close its normative specification, conformance, platform, dependency, security-review, resource, and representative acceptance gates. | Independent implementation interoperability, complete MVP conformance, or any production release authorization. |

## Working delivery sequence

This sequence is an outcome-oriented planning default, not a promise that every
task is serial or that unrelated future/external gates block useful merges.

1. **Stabilize a supported Event/relay evaluation profile.** Name its platforms,
   reachability assumptions, security boundary, APIs, evidence, and exclusions.
2. **Complete the live four-class application path.** Broaden the bounded
   State/Record and interrupted-resume Blob receipts into representative
   retained usability, longer partitions, failure recovery, and cleanup, then
   add the required subscriptions/status, bindings, and lifecycle coverage.
3. **Operationalize the security lifecycle.** Replace fixture/reference custody
   with an admitted backend and exercise provisioning through destruction.
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
- required artifacts, independent evidence, and external approvals; and
- explicit exclusions and upgrade/compatibility expectations.

An **evaluation profile** may intentionally cover a bounded subset and must say
so. A **production profile** requires representative operational evidence and
all gates applicable to its claims. The **complete MVP target product profile**
is the broad target in §§11–13 of the requirements document; it is not the
default gate for every incremental merge or partial evaluation release.

No production release profile is currently authorized.
