# Aster documentation

This documentation is organized around what you are trying to do. You do not
need to understand the wire format or cryptography to embed the application API.

## Start here

1. Run the one-command [capability tour](quickstart/capability-tour.md) for the
   fastest visible result.
2. Read [Core concepts](concepts.md) for the ten-minute mental model and the
   [selected architecture](architecture.md) for its trust boundaries.
3. Run the full [live N-node, multi-process mesh CLI](quickstart/mesh-cli.md),
   exercise the selected live [Event API](quickstart/selected-event-api.md),
   or use the current semantic application API with the [Rust](quickstart/rust.md),
   [Python](quickstart/python.md), [Go](quickstart/go.md), or
   [C](quickstart/c.md) quickstart.
4. Read [Carriers and contacts](transports.md) when you are ready to move data
   between nodes.
5. Review [Security and production gates](security.md) before designing a real
   provisioning or deployment process.

The application quickstarts deliberately begin offline. This is Aster's
foundational contract: publish, query, and subscription behavior must work
without a live peer. The selected carrier/storage quickstart separately proves
real process and contact mechanics, including runtime mission authentication
before inventory disclosure, while the remaining proven semantic behavior is
migrated onto that composition.

## Find a guide by goal

| I want to… | Read… |
|---|---|
| See Aster work as quickly as possible | [Capability tour](quickstart/capability-tour.md) |
| Understand what makes Aster different | [Project overview](../README.md) and [Core concepts](concepts.md) |
| Understand the selected components and trust boundaries | [Selected architecture](architecture.md) |
| Run real node processes and watch Ping/Pong or captured-node control propagation cross the mesh | [Live mesh CLI](quickstart/mesh-cli.md) |
| Publish offline, synchronize later, consume durably, and inspect selected Event gaps/status | [Selected Event API](quickstart/selected-event-api.md) |
| Choose between State, Event, Record, and Blob | [Choosing a data class](concepts.md#choosing-a-data-class) |
| Publish and subscribe from an application | [Language quickstarts](quickstart/README.md) |
| See commented examples for every data class and common operation | [Application recipes](application-recipes.md) |
| Connect nodes over IP or BTLE | [Carriers and contacts](transports.md) |
| Handle conflicts, deletion, priority, or expiry | [Framework mechanisms](concepts.md#framework-mechanisms) |
| Understand relays, scopes, and bridges | [Routing and propagation](concepts.md#routing-and-propagation) |
| Assess security assumptions and deployment blockers | [Security](security.md) and [Conformance](conformance.md) |
| Build or embed a language binding | [Binding pattern](bindings/pattern.md), [C ABI](../bindings/c/README.md), [Go](../bindings/go/README.md), and [Python](../bindings/python/README.md) |
| Implement an independent compatible node | [Protocol](protocol.md), [wire grammar](wire.cddl), and [security objects](envelope.md) |
| Run validation or interpret evidence | [CI](ci.md), [Conformance](conformance.md), [Lab](../lab/README.md), and the test-only [reconciliation bake-off](reconciliation-bakeoff.md) |
| See which source requirements the selected composition has actually reached | [Production implementation requirements status](implementation/requirements-status.md) |

## Documentation types

The distinction matters because Aster has both a framework and an
implementation-independent protocol.

- **Tutorials** get an application developer to a working result.
- **Concept guides** explain the mental model and tradeoffs.
- **Integration guides** describe platform and carrier seams.
- **Reference specifications** define interoperable bytes and normative behavior.
- **Proposals** define bounded, non-normative experiments that may produce a
  later architecture decision.
- **Evidence documents** state what has actually been tested and what remains a
  release or deployment gate.

If a tutorial and a normative specification ever appear to disagree, the
specification is authoritative for interoperability. The high-level API remains
the authority for what application code is expected to touch.

## Current capability boundary

| Surface | Available now | Important boundary |
|---|---|---|
| Selected carrier/storage composition | Exact source-sealed control/Event transfer, a durable ordered Flash-control prefix with atomic policy activation, mission-bound semantic/causal/operation state, durable Consume/Carry selectors, at-least-once application delivery, bounded route-only cache, a durable terminal software-zeroization intent, clock-independent Negentropy difference, direct Iroh exchange, and the `aster` composition/CLI. `SelectedEventHandle` exposes live policy-authorized Event publish/query, durable subscribe/poll/ack, idempotent unsubscribe, freshly verified gap inspection, and bounded authenticated peer/last-contact status through the running actor's sole store authority; stopped `SelectedEventNode` remains available when the actor is absent. Protected per-contact interests drive two receiver-directed Event reconciliation lanes. | Carrier, mission, control/source, receive intent, route, and content authority remain distinct. Status is process-local last-contact evidence, not global convergence; gap absence is bounded to freshly verified positions already observed by the store. Atomic subscription update, State/Record/Blob, generalized control administration, finite-TTL custody, protected provisioning, NAT/hosted relay, BTLE, platform-complete zeroization assurance, and release gates remain open. Empty receive intent is receive-none, never wildcard. The selected node's normal graph contains no SQLite. |
| Selected live CLI | Configurable 2–32-node Ping/Pong line, explicit four-role control scenario, addressed `init`/`inspect`/mission-provisioned `node`, stopped-state authority commands, a same-UID Unix `zeroize` hook, isolated legacy `put`, and built-in relay/Ping/Pong roles | Parent PR-A/pre-subscription N=3/13-process, default N=4/18-process, and N=8/38-process Ping/Pong receipts plus the explicit N=4/23-process control receipt passed. They cover peerless publication, later forwarding, causal return, control convergence, payload-blind relay, captured-node exclusion, and terminal no-op within their stated loopback boundary. A separate live-child receipt exercises the local hook. PR B and PR C add exact current-code tests for receive selectors and the high-level live Event surface; they do not relabel those historical roots. The hook preserves data rows and zero-length artifact pathnames and does not prove non-Unix behavior, inode deletion, physical sanitization, database rollback resistance, physical networking, many-node scale, or production authorization. |
| Current semantic Rust API | Publish, query, durable subscriptions, conflicts, batches, streamed Blobs, emission policy, status, bridges, recipient-filtered rekey, hybrid-PQ handshakes, protected envelopes, and source authentication in `aster-core` | This remains the proven semantic implementation and migration source. The selected node now uses its mission-session, control-envelope/rekey, and Event source-envelope seams; the broader high-level API and other data classes are not composed yet. Event-gap inspection, process-local merge-policy ID registration, and retention-driven garbage collection are Rust-only; automatic Record merge is partial. |
| Protected provisioning | Replaceable, bounded Rust protection boundary with a redacted, zeroizing Aster-owned plaintext container, plus an isolated age-v1 X25519 provider pilot | The pilot is Rust-only, non-production, classical rather than post-quantum, and not FIPS validated or a persistent secret store; upstream age encryption and identity-decoding intermediates are not comprehensively zeroized, and raw fixture/compatibility paths remain in Rust and all language bindings. |
| Current semantic host | Provider-neutral `MeshHost`, `MeshService`, and the tested shared-node supervisor | This code remains a proven migration source. Its persistence/reconciliation authorities are not run beside the selected ones; behavior moves only with equivalent tests. |
| C ABI | High-level offline operations over the current semantic implementation | Not yet connected to the selected node; no event-gap inspection, merge-policy registration, retention-driven garbage collection, sealed objects, cryptographic provider, or carrier configuration |
| Go and Python | First-class wrappers over the current semantic C ABI | Not yet connected to the selected node; the same C ABI boundaries apply |
| Selected Iroh carrier | Exact endpoint identity, manually supplied direct address, bounded request/response, allowlist admission | Carrier identity is not mission, control, or Event-source authorization. `aster-node` enforces mission-before-inventory and control-before-Event admission. Hosted discovery, relays, port mapping, NAT acceptance, other data classes, non-Unix and physical zeroization assurance, and remaining zero-trust lifecycle obligations are open. Dependency admission awaits exact CDLA/Unlicense and supported-target dispositions; no exception was added. |
| Current semantic IP adapter | UDP link with manual peer mapping, protected discovery support, rendezvous helpers, and opaque relay components | A migration source, not the selected carrier. Production NAT, relay/path recovery, and physical-network acceptance remain separate. |
| Current semantic BTLE adapter | MTU-aware `Link` over the `BleRadio` platform seam | A migration source; no platform-specific OS radio implementation ships and it is not wired to the selected node. |

See the [production requirements status](implementation/requirements-status.md),
[Conformance](conformance.md), and [CI](ci.md) for the precise claim boundaries.

## Proposals and experiments

Proposals describe work the project may run to answer an unresolved design
question. They do not change the protocol, admit dependencies, or establish a
capability claim until a later decision and implementation evidence say so.

- [Proposal index and lifecycle](proposals/README.md)
- [0001 — Operational IP mesh vertical-slice experiment](proposals/0001-ip-mesh-vertical-slice.md)
- [0001 result — LAN mesh proven; operational IP profile not selected](proposals/0001-ip-mesh-vertical-slice-results.md)
- [0002 — Provider-neutral mesh host and focused rust-libp2p profile](proposals/0002-provider-neutral-mesh-host.md)
- [0002 result — Host contract retained; rust-libp2p profile not selected](proposals/0002-provider-neutral-mesh-host-results.md)
- [0003 — Idiomatic IP mesh provider comparison](proposals/0003-idiomatic-ip-mesh-provider-comparison.md)
- [0003 result — No provider selected; refactor durable node ownership first](proposals/0003-idiomatic-ip-mesh-provider-results.md)
- [0004 — Shared-node rust-libp2p retest](proposals/0004-shared-node-libp2p-retest.md)
- [0004 result — Provider-free Gate H retained; no provider selected](proposals/0004-shared-node-libp2p-retest-results.md)
- [0005 — Requirements-first FOSS architecture evaluation](proposals/0005-requirements-first-foss-architecture-evaluation.md)
- [0006 — Selected FOSS reference stack build and validation](proposals/0006-selected-foss-reference-stack.md)

## Architecture and design decisions

The protocol and framework specifications define behavior. The architecture
decision records explain why the current design chose its major boundaries:

- [0001 — Standards and provider boundaries](decisions/0001-standards-and-provider-boundaries.md)
- [0002 — Dependency admission](decisions/0002-dependency-admission.md)
- [0003 — FIPS production gate](decisions/0003-fips-production-gate.md)
- [0004 — Radio-silence semantics](decisions/0004-radio-silence-semantics.md)
- [0005 — Deterministic codec](decisions/0005-deterministic-codec.md)
- [0006 — SQLite store](decisions/0006-sqlite-store.md)
- [0007 — IP and BTLE links](decisions/0007-ip-and-btle-links.md)
- [0008 — Local-agent phasing](decisions/0008-local-agent-phasing.md)
- [0009 — Public API boundary](decisions/0009-public-api-boundary.md)
- [0010 — Authenticated Blob transfer](decisions/0010-authenticated-blob-transfer.md)
- [0011 — Recipient-filtered rekey](decisions/0011-recipient-filtered-rekey.md)
- [0012 — Content-committing post-quantum batches](decisions/0012-content-committing-pq-batches.md)
- [0013 — Protected provisioning boundary](decisions/0013-protected-provisioning-boundary.md)
- [0018 — age X25519 provisioning-provider pilot](decisions/0018-age-provisioning-provider.md)
- [0022 — No IP mesh substrate selected from Proposal 0001](decisions/0022-ip-mesh-experiment-no-selection.md)
- [0023 — Retain the mesh-host contract without selecting rust-libp2p](decisions/0023-mesh-host-contract-no-libp2p-selection.md)
- [0024 — Refactor durable node ownership before selecting an IP provider](decisions/0024-refactor-durable-node-ownership-before-ip-provider-selection.md)
- [0025 — Requirements-first FOSS architecture evaluation](decisions/0025-requirements-first-foss-architecture-evaluation.md)
- [0026 — Scope lock-only Hickory advisories](decisions/0026-lock-only-hickory-advisories.md)
- [0027 — Bound the active libp2p pilot dependency exceptions](decisions/0027-libp2p-pilot-dependency-policy.md)
- [0028 — Start the selected-stack implementation behind an isolated profile](decisions/0028-selected-stack-implementation-boundary.md)
- [0029 — Close Proposal 0004 without selecting rust-libp2p](decisions/0029-close-proposal-0004-libp2p-pilot.md)

## All documents

### Tutorials and integration

- [Capability tour](quickstart/capability-tour.md)
- [Selected Event API](quickstart/selected-event-api.md)
- [Live mesh CLI](quickstart/mesh-cli.md)
- [Selected production-lane architecture](architecture.md)
- [Language quickstarts](quickstart/README.md)
- [Application recipes](application-recipes.md)
- [Carriers and contacts](transports.md)
- [Binding design pattern](bindings/pattern.md)
- [C ABI reference](../bindings/c/README.md)
- [Go binding reference](../bindings/go/README.md)
- [Python binding reference](../bindings/python/README.md)
- [Non-production binding fixture](../bindings/testdata/README.md)

### Protocol and security reference

- [Core concepts](concepts.md)
- [Protocol specification](protocol.md)
- [Envelope and security-object specification](envelope.md)
- [Wire grammar](wire.cddl)
- [Security model](security.md)
- [Deprecation policy](deprecation-policy.md)
- [Source requirements](../data-mesh-requirements.md)

### Validation and project evidence

- [Production implementation requirements status](implementation/requirements-status.md)
- [Conformance and acceptance](conformance.md)
- [CI and local validation](ci.md)
- [Fuzzing guide](../fuzz/README.md)
- [Lab guide](../lab/README.md)
- [Reconciliation FOSS bake-off](reconciliation-bakeoff.md)
- [Selected FOSS reference-stack validation](evaluations/0006/README.md)

The design-decision index above covers every ADR included in the public
repository.
