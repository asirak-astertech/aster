# Aster documentation

This documentation is organized around what you are trying to do. You do not
need to understand the wire format or cryptography to embed the application API.

## Start here

1. Read [Core concepts](concepts.md) for the ten-minute mental model.
2. Run one local quickstart:
   [Rust](quickstart/rust.md), [Python](quickstart/python.md),
   [Go](quickstart/go.md), or [C](quickstart/c.md).
3. Read [Carriers and contacts](transports.md) when you are ready to move data
   between nodes.
4. Review [Security and production gates](security.md) before designing a real
   provisioning or deployment process.

The local quickstarts deliberately begin offline. This is Aster's foundational
contract: publish, query, and subscription behavior must work without a live
peer. Networking is a deployment concern layered onto that durable local API.

## Find a guide by goal

| I want to… | Read… |
|---|---|
| Understand what makes Aster different | [Project overview](../README.md) and [Core concepts](concepts.md) |
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
| Rust application API | Publish, query, durable subscriptions, conflicts, batches, streamed Blobs, emission policy, status, bridges, and recipient-filtered rekey | Event-gap inspection, process-local merge-policy ID registration, and retention-driven garbage collection are Rust-only. Policy registration only annotates high-level conflict results; replicated ingestion never executes application policy. Automatic Record merge under requirements §5.3 is partial. The complete authority-side rekey-registry administration workflow is not shipped. |
| Protected provisioning | Replaceable, bounded Rust protection boundary with a redacted, zeroizing Aster-owned plaintext container, plus an isolated age-v1 X25519 provider pilot | The pilot is Rust-only, non-production, classical rather than post-quantum, and not FIPS validated or a persistent secret store; upstream age encryption and identity-decoding intermediates are not comprehensively zeroized, and raw fixture/compatibility paths remain in Rust and all language bindings. |
| Rust composition host | Provider-neutral `MeshHost`, the default-gated legacy `MeshService`, and a Proposal-0004 shared-node supervisor that owns one durable authority across contact sessions | The shared-node experiment baseline passed formal Gate H. The formal `aster-gate-h` build compile-excludes `MeshService` and the legacy CLI; no provider is selected. |
| Live synchronization | The default compatibility build can run application logic in-process through `MeshService`; a separate native three-process Gate-H CLI exists for the shared-node experiment | The shared-node Gate-H cohort passed 10/10, but C, Go, and Python still do not have an in-process networking API. The out-of-process local agent is post-MVP; see [ADR 0008](decisions/0008-local-agent-phasing.md). |
| C ABI | High-level offline application operations | No event-gap inspection, merge-policy registration, retention-driven garbage collection, sealed objects, cryptographic provider, or carrier configuration |
| Go and Python | First-class wrappers over the C ABI | The same C ABI boundaries apply; build and load the matching native library first |
| IP adapter | UDP link with manual peer mapping, protected discovery support, rendezvous helpers, opaque relay components, and the provider-free native Gate-H harness | The formal provider-free Gate-H evidence passed; corrected provider comparison is authorized, but no IP provider is selected. Production NAT, relay/path recovery, and physical-network acceptance remain separate. |
| BTLE adapter | MTU-aware `Link` over the `BleRadio` platform seam | A platform-specific OS radio implementation is not shipped |

See [Conformance](conformance.md) and [CI](ci.md) for the precise evidence behind
these statements.

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

## All documents

### Tutorials and integration

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

- [Conformance and acceptance](conformance.md)
- [CI and local validation](ci.md)
- [Fuzzing guide](../fuzz/README.md)
- [Lab guide](../lab/README.md)
- [Reconciliation FOSS bake-off](reconciliation-bakeoff.md)
- [Selected FOSS reference-stack validation](evaluations/0006/README.md)

The design-decision index above covers every ADR included in the public
repository.
