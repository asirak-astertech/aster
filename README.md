# Aster

**Keep data moving when the network disappears.**

Aster is an offline-first data mesh for applications that cannot depend on a
continuous path to a service. Applications commit data to a local node. Aster
protects it at the source, stores it durably, and exchanges it when an
authenticated contact becomes available.

Direct connections, relays, and central infrastructure can help delivery, but
none is required for the data model to remain correct. Aster is designed for
field teams, vehicles, sensors, and edge systems that move between connected,
constrained, and disconnected operation.

> [!IMPORTANT]
> Aster is an evaluation-stage reference implementation, not a
> production-authorized system. Event, State, Record, and Blob have live Rust
> APIs; Event alone also has a local ConnectRPC API. State, Record, and Blob
> retain stopped-node facades for exclusive use. The live Blob API is limited
> to peerless-capable durable publication and bounded page reads; it is not a
> subscription or convergence-status surface. Review the
> [security gates](docs/security.md) and
> [conformance status](docs/conformance.md) before planning a deployment.

A [retained live State/Record receipt](docs/implementation/evidence/selected-live-mutable-2ccfba0.json)
binds a 5,660-byte canonical projection (SHA-256
`299a3c3b8d1685deb5980ed091797f7d46119562b67c3d853b94d8552c83b67a`)
to signed source commit `2ccfba0`. On one loopback host, two
same-implementation participants completed six actor lifetimes, with at most two
actors concurrent. They published State and conflicting Record revisions while
peerless; four paired direct `CONTACT` records then accounted for 5/5/5 selected
items offered/fetched/inserted, concurrent State max-ID tie-break and restart,
and Record conflict rejection, guarded resolution, superseded originals, exact
retry, and restart. Six graceful shutdowns closed four retained handles, while
Event, control, and Blob counters remained zero.

That receipt is bounded evidence, not a broader acceptance claim. Its
source-to-execution link is operator-attested, not cryptographically proven or
reproducible; secret artifacts were inspected by metadata only. It does not
cover physical hosts, NAT, Internet, relay, BTLE, independent implementations,
scale beyond two participants, resource thresholds, long-duration operation,
or evidence for the newer live Blob mechanism or live Event/Blob application
acceptance. Finite State/Record TTL, durable
subscriptions, selected-node language bindings, representative physical or
mixed-implementation acceptance, and release authorization remain open.

A [retained 10,728-byte v2 live-Blob receipt](docs/implementation/evidence/selected-live-blob-044d90f.json)
(SHA-256
`4fea2ffbd16608862a67167fb1b8fcb6d5d8b4b82c576aa9a6b7e25ee9c55909`)
binds signed source commit `044d90ff07c8e754b3d490cb810d42de3c915e3d`
with `Good` signature status. Its three participants ran 11 actor lifetimes and
32 error-free direct `CONTACT` records: a publisher committed while peerless; a replica
received all 98,638 carrier bytes; a receiver retained an interrupted
exactly-one-contact 16,384-byte prefix, reopened peerless with that exact
progress, resumed exactly 16,384 bytes from the different replica without
refetching the source, fetched the exact remaining 65,870 bytes, reconstructed
all 98,638 carrier bytes, and reopened peerless for a final authenticated read.
Its source-to-execution link remains operator-attested, not cryptographically
proven. This is one-host, same-implementation evidence of graceful same-process
actor/store/provider reopen only. It does not prove process-crash, power-loss,
long-offline, arbitrary-peer, or route-only resume; NAT, Internet, relay, or
BTLE paths; independent-implementation interoperability; scale beyond three
participants; resource thresholds or soak; physical sanitization; or release
authorization.

A [retained two-cell receipt](docs/implementation/requirements-status.md#selected-iroh-nat-retained-receipt)
observes the selected Event path on one Darwin arm64 host through isolated
Docker Linux namespace NATs: one relay-disabled cone cell selected Direct, and
one restrictive direct-blocked cell selected the exact operator-pinned
controlled Iroh connectivity relay. Each cell delivered and acknowledged one
exact 32-byte Event and replayed as an exact no-op. This is one-host software
namespace-NAT evidence only—not discovery or punching, temporal fallback
chronology, representative or physical NAT, public Internet or public/default
relay, independent implementation, BTLE, other-class relay, complete-MVP, or
release evidence.

## See it work

The capability tour starts real processes with independent stores and
identities, publishes while disconnected, reconnects the nodes over direct
Iroh contacts, and verifies that a second pass has nothing left to transfer.

```sh
mise install
mise run tour
```

Two focused tours expose the less familiar boundaries:

```sh
mise run tour-relay    # a relay carries protected data it cannot read
mise run tour-control  # revocation, rekey, and captured-node exclusion
```

The tours retain their working directories for inspection. The
[capability tour](docs/quickstart/capability-tour.md) explains each result and
its limits.

## How Aster moves data

```mermaid
flowchart LR
    A["Producer application"] -->|"commit locally"| B["Local Aster node"]
    B -->|"when contact exists"| C["Authenticated peer or relay"]
    C -->|"possibly much later"| D["Receiving Aster node"]
    D --> E["Consumer application"]
```

- **Offline publication.** Success means the item is durable locally, not that
  a server happened to be reachable.
- **Store-and-forward delivery.** Protected data can cross several intermittent
  contacts, including relays without content access.
- **Source authentication.** Identity and protected semantic metadata survive
  every hop; carrier identity alone never grants data access.
- **Deterministic convergence.** Nodes reconcile without trusting wall clocks
  or assuming one always-online coordinator.

Read [Core concepts](docs/concepts.md) for the ten-minute mental model.

## Choose a data class

The data class defines how an item converges. It is more than a storage label.

| Class | Best for | Convergence behavior |
|---|---|---|
| **State** | Current position, device status, latest setting | Selects one current value per logical key while retaining meaningful concurrent history |
| **Event** | Messages, observations, audit entries | Preserves immutable publisher order and makes sequence gaps detectable |
| **Record** | Plans, forms, annotations, mutable documents | Preserves concurrent versions for explicit, guarded application resolution |
| **Blob** | Imagery, maps, attachments, large binary objects | Identifies immutable chunked content and supports authenticated streaming |

The [data-class guide](docs/concepts.md#choosing-a-data-class) includes a
decision tree and worked examples.

## Integrate an application

For new integrations, start with the local ConnectRPC agent. It exposes the
live Event authority over Connect, gRPC, and gRPC-Web using a checked-in
Protobuf schema and does not require a hosted Buf Schema Registry.

| Integration | Start here | Current boundary |
|---|---|---|
| **Connect, gRPC, or gRPC-Web** | [ConnectRPC agent](docs/quickstart/connect-agent.md) | Live Event and local status; authenticated loopback process |
| **Rust selected node** | [Selected Event API](docs/quickstart/selected-event-api.md) | Live Event publish, query, durable delivery, gaps, and status |
| **State or Record in Rust** | [State](docs/quickstart/selected-state-api.md) and [Record](docs/quickstart/selected-record-api.md) | Cloneable live actor handles plus exclusive stopped-node facades; direct-Iroh reconciliation under explicit interests |
| **Blob in Rust** | [Blob](docs/quickstart/selected-blob-api.md) | Cloneable `RunningNode::selected_blobs()` handle for durable file publication and bounded pages, plus an exclusive stopped streaming facade; already-durable Blob data can transfer directly under semantic v5 |
| **Rust semantic API** | [Rust quickstart](docs/quickstart/rust.md) | Broader proven semantic surface used as the migration source |
| **Python, Go, or C** | [Language quickstarts](docs/quickstart/README.md) | Offline semantic API through the current C ABI, not the selected live node |

The [application recipes](docs/application-recipes.md) show all four data
classes, queries, subscriptions, batches, deletion, conflicts, and emission
policy. Kubernetes, Zarf, and UDS integrations should treat the ConnectRPC
agent as the application boundary; deployment packaging and protected
provisioning remain open work.

## Current implementation boundary

| Surface | Implemented | Still open |
|---|---|---|
| **Event** | Source-authenticated reconciliation over direct Iroh or one operator-pinned controlled Iroh connectivity relay; live Rust and local ConnectRPC APIs; durable consume/carry selectors and at-least-once delivery | Atomic subscription update, hosted discovery/public relay, and broader physical-network acceptance |
| **State** | Source-authenticated live or stopped publication/query, causal projection, direct-Iroh reconciliation under explicit interests, and bounded retained one-host evidence | Durable subscriptions, selected-node bindings, finite TTL, relay acceptance, expiry/garbage collection, and representative physical/mixed evidence |
| **Record** | Live or stopped conflict-preserving query/publication, exact-sibling guarded resolution, direct-Iroh reconciliation, and bounded retained one-host evidence | Durable subscriptions, selected-node bindings, automatic merge execution, finite TTL, relay acceptance, expiry/garbage collection, and representative physical/mixed evidence |
| **Blob** | Authenticated immutable publication through a cloneable live Rust handle or exclusive stopped facade; live reads return at most one zeroize-on-drop 64-KiB page; direct semantic-v5 source/carrier transfer has durable resume state and bounded retained one-host interrupted/reopened/different-peer resume, completion, read, and reopen evidence | Blob subscription or convergence status, route-only relay/custody, arbitrary-peer resume, crash/power-loss/long-offline recovery, large/RSS acceptance, representative physical or mixed-implementation evidence, retention, garbage collection, and release authorization |
| **Operations** | Manually admitted direct addresses, an operator-pinned controlled relay, bounded one-host software namespace-NAT acceptance, reference mission provisioning, and bounded same-UID Unix software zeroization | Protected operational provisioning, discovery, representative/physical NAT, public/default relay selection, BTLE platform integration, physical sanitization, and release authorization |

The [capability roadmap](docs/implementation/capability-roadmap.md) is the
planning and merge-review view. The
[requirements status](docs/implementation/requirements-status.md) remains the
authority for exact evidence and open acceptance gates.

## When Aster fits

Aster is a strong fit when:

- applications must keep publishing without peers or infrastructure online;
- data may cross several intermittent contacts before reaching a consumer;
- links are too constrained to resend an entire dataset;
- conflicts must remain explicit and reproducible without wall-clock ordering;
- relays should forward authorized data without reading it; or
- one application model must survive movement between carriers.

Aster is not a message broker, general-purpose database, VPN, radio manager, or
real-time media transport. If every client can reliably reach one service, a
conventional database or broker will usually be simpler.

## Find the next document

| Goal | Read |
|---|---|
| Understand the model | [Core concepts](docs/concepts.md) |
| Run a working example | [Capability tour](docs/quickstart/capability-tour.md) |
| Build an application | [ConnectRPC agent](docs/quickstart/connect-agent.md) or [language quickstarts](docs/quickstart/README.md) |
| Understand trust and component boundaries | [Selected architecture](docs/architecture.md) |
| Connect nodes or evaluate carriers | [Carriers and contacts](docs/transports.md) |
| Implement compatible protocol bytes | [Protocol](docs/protocol.md), [wire grammar](docs/wire.cddl), and [security objects](docs/envelope.md) |
| Assess progress or readiness | [Capability roadmap](docs/implementation/capability-roadmap.md), [requirements status](docs/implementation/requirements-status.md), [conformance](docs/conformance.md), and [security](docs/security.md) |
| Review development inputs and provenance | [Public development provenance record](docs/provenance/independent-development-record.md) |
| Browse all project records | [Documentation index](docs/README.md) |

## Repository map

| Area | Purpose |
|---|---|
| [`crates`](crates) | Selected node, carrier, persistence, protocol, semantic reference, and conformance implementations |
| [`bindings`](bindings) | C ABI plus Go and Python wrappers |
| [`docs`](docs) | Guides, concepts, specifications, decisions, and evidence |
| [`lab`](lab) | Controlled network and impairment experiments |
| [`fuzz`](fuzz) | Parser and protocol robustness targets |

## Build and verify

```sh
mise install
mise run check
```

See [CI and local validation](docs/ci.md) for narrower checks and the precise
claim attached to each gate.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
Distribution notices for approved dependency exceptions are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
