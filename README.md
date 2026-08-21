# Aster Mesh

**Move important application data when the network is unreliable, untrusted, or
missing altogether.**

Aster is an offline-first data synchronization protocol and embeddable reference
framework. An application publishes to its local Aster node; Aster stores the
item durably, protects it at the source, and exchanges it whenever an
authenticated contact becomes available. A direct connection, relay, or central
server may help delivery, but none is required for correctness.

That makes Aster useful for field teams, vehicles, sensors, and edge systems that
move between IP, Bluetooth Low Energy, tactical radio, SATCOM, and disconnected
operation.

> **Project status:** Aster 0.1 is a reference candidate. It is not a completed
> MVP, production-authorized build, or claim of FIPS 140-3 validation.
> Production use is **blocked** by explicit gates in
> [security](docs/security.md) and
> [conformance and acceptance](docs/conformance.md); read both before planning
> an operational deployment.

## Why Aster exists

Most synchronization systems assume that a client can reach a service. Aster
assumes the opposite: contacts are brief, links are slow, nodes disappear for
days, and every carrier may be observed or manipulated.

```mermaid
flowchart LR
    A["Producer app"] -->|"publish locally"| B["Aster node"]
    B -->|"when contact exists"| C["Authenticated peer or relay"]
    C -->|"later, over any carrier"| D["Consumer's Aster node"]
    D --> E["Consumer app"]
```

Aster is unusual in combining these properties in one application-facing model:

- **Offline publication:** success means the item is durably committed locally,
  not that a remote service happened to be reachable.
- **Store-and-forward delivery:** a relay can carry protected data between nodes
  that never meet directly.
- **Transport-neutral progress:** verified objects and partial large-file ranges
  can resume through a different peer or carrier.
- **Data-aware convergence:** State, Event, Record, and Blob each have explicit
  synchronization and conflict behavior.
- **Constrained-operation controls:** priority, expiry, quotas, and receive-only
  mode make bandwidth, storage, and power deliberate choices.
- **Protected routing:** relays can make authorized forwarding decisions without
  receiving content access; source authentication survives every hop.
- **Scoped sharing:** topics select what data means, scopes bound where it may
  travel, and signed bridge policy controls movement between scopes.

## Choose the right data class

The data class tells every conforming node how an item should converge. It is not
just a label.

| Class | Use it for | What Aster guarantees |
|---|---|---|
| **State** | Current position, device status, latest setting | One current value per logical key, with deterministic handling of concurrent updates |
| **Event** | Chat messages, observations, audit entries | Immutable, ordered events per publisher, with detectable sequence gaps |
| **Record** | Plans, forms, annotations, mutable documents | Concurrent versions are preserved and annotated for explicit application resolution. Registered-policy auto-merge is not currently executed during replication. |
| **Blob** | Imagery, maps, attachments, large binary objects | Immutable, chunked transfer whose ID commits to the plaintext digest and manifest fields, with authenticated streaming and resume |

See [Core concepts](docs/concepts.md) for worked examples and selection guidance.
The [Application recipes](docs/application-recipes.md) show commented code for
all four classes, queries, subscriptions, batches, deletion, conflicts, and
emission policy.

## Get a local publish/subscribe working

The fastest first success uses the checked-in disposable provisioning fixture.
It exercises durable, offline application behavior without pretending to be an
operational deployment.

Operational provisioning is still gated. Rust exposes a replaceable protected-
artifact boundary, but this repository does not yet ship an admitted provider
or persistent secret store; the fixture and current language-binding entry
points ingest the unprotected inner format for tests and compatibility only.

| Your application | Start here |
|---|---|
| Rust | [Rust quickstart](docs/quickstart/rust.md) |
| Python | [Python quickstart](docs/quickstart/python.md) |
| Go | [Go quickstart](docs/quickstart/go.md) |
| C or another native language | [C ABI quickstart](docs/quickstart/c.md) |

Then read [Connect nodes and choose a carrier](docs/transports.md). The
[current capability boundary](docs/README.md#current-capability-boundary) states
which application and live-synchronization paths are available today.

## Know when to use it

Aster is a good fit when:

- publishing must keep working with no peer or infrastructure online;
- data may cross several intermittent contacts before reaching a consumer;
- links are too constrained to resend an entire dataset;
- conflicts must be explicit and reproducible without trusting wall clocks;
- relays should forward data without being able to read it; or
- the same application model must survive a change from IP to a narrow carrier.

Aster is not a message broker, general-purpose database, VPN, radio manager, or
real-time voice/video transport. If every client has reliable access to a
service, a conventional database or broker will usually be simpler.

## How the repository is organized

| Area | Purpose |
|---|---|
| [`crates/aster-core`](crates/aster-core) | Data model, durable store, reducers, security, and synchronization |
| [`crates/aster-host`](crates/aster-host) | High-level node plus authenticated contact and carrier composition |
| [`crates/aster-ip`](crates/aster-ip) | Nonblocking UDP/IP link, discovery, rendezvous, and opaque relay support |
| [`crates/aster-ble`](crates/aster-ble) | BTLE link over a small platform-radio interface |
| [`crates/aster-ffi`](crates/aster-ffi) | Stable C-compatible application boundary |
| [`bindings`](bindings) | C header plus first-class Go and Python bindings |
| [`crates/aster-conformance`](crates/aster-conformance) | Black-box scenarios and interoperability vectors |
| [`lab`](lab) | Controlled network and impairment experiments |
| [`docs`](docs) | Tutorials, concepts, operations, specifications, and evidence |
| [`site`](site) | Self-contained static project landing page |

## Documentation map

- **New to Aster:** [Documentation home](docs/README.md) →
  [Core concepts](docs/concepts.md) → a [language quickstart](docs/quickstart/README.md) →
  [Application recipes](docs/application-recipes.md)
- **Integrating a deployment:** [Carriers and contacts](docs/transports.md) →
  [Security model and production gates](docs/security.md)
- **Implementing the protocol:** [Protocol specification](docs/protocol.md) →
  [wire grammar](docs/wire.cddl) → [fixed security objects](docs/envelope.md)
- **Evaluating readiness:** [Conformance and acceptance](docs/conformance.md) →
  [CI evidence](docs/ci.md) → [security gates](docs/security.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)

## Verify the repository

Install the pinned tools and run the complete local gate:

```sh
mise install
mise run check
```

The narrower commands in each quickstart are better for a first run. The full
gate is intentionally comprehensive.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.
