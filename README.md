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

> **Project status:** Aster 0.1 now has an executable production-implementation
> lane for bounded source-authenticated Event and mission-control meshes over
> direct IP. Iroh carrier authentication remains separate from the ported
> `aster-core` hybrid
> mission session, which completes before inventory. The runtime source-seals
> ordered Flash revocation/rekey controls and Events through the existing
> `aster-core` providers, activates a durable contiguous control prefix before
> Event transfer, keeps exact transfer identity distinct from semantic identity,
> separates content admission from payload-blind routing, and now exchanges
> protected Consume/Carry interests through two receiver-directed Event lanes.
> The selected API now exposes live and stopped-state Event publish/query,
> durable subscribe/poll/ack, idempotent unsubscribe, and authenticated gap
> inspection. Its live handle reports bounded authenticated peer and
> last-contact status without exposing carrier or reconciliation internals. It
> now also has an exclusive stopped-node State surface for source-authenticated
> publication and exact-key causal projection. Current tombstones remain
> visible, while active concurrent and superseded versions are recoverable.
> A parallel stopped-node Record surface preserves and annotates all causal
> heads, rejects ordinary publication across an unresolved conflict, and
> accepts only an explicit application-reviewed successor guarded by the exact
> sibling set inspected. It does not execute registered merge policies during
> ingest. The live runtime now reconciles already durable State and Record
> objects through separate typed Negentropy/fetch lanes under explicit
> receiver topic/scope interests. A real-Iroh two-node test covers State
> delivery and two disconnected Record publishers converging without losing
> either causal head. The application-facing State and Record handles remain
> stopped/exclusive, and network ingest never invokes application merge code.
> An exclusive stopped-node Blob surface now streams immutable,
> metadata-bound objects into a crash-resumable encrypted depot and freshly
> verifies them into caller-owned outputs without exposing provider readers or
> keys. Blob is not yet carried by the live runtime or reconciliation wire.
> Aster is
> still not a completed MVP, production-authorized build, or claim of FIPS
> 140-3 validation. Live State/Record application handles, replicated Blob,
> remote Blob chunk transfer, finite-TTL custody,
> atomic subscription
> update, protected provisioning, generalized control administration, and
> physical/multi-carrier acceptance remain open. A bounded same-UID Unix hook
> now drains a selected node, terminally locks its retained redb state, and
> software-erases its exact
> mission-bundle and carrier-identity file contents. Non-Unix support, physical
> media/copy-on-write/snapshot/swap/backup sanitization, and database
> rollback/replacement resistance remain open. The broader
> `aster-core` implementation is the proven migration source, not legacy to
> discard, and remains until replacements pass equivalent tests. Production
> use is **blocked** by explicit gates in
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

## Try Aster in one command

The fastest tour runs a causal two-node Ping/Pong exchange with real processes,
independent stores, direct Iroh contacts, peerless publication, restart, and a
zero-difference no-op:

```sh
mise install
mise run tour
```

Two follow-on tours make the more unusual boundaries visible:

```sh
mise run tour-relay    # three nodes; middle node stores bytes it cannot read
mise run tour-control  # four roles; revocation, rekey, captured-node exclusion
```

Each command retains its complete root and prints stopped-state inspections.
See the [capability tour](docs/quickstart/capability-tour.md) for what to look
for, the [selected Event API quickstart](docs/quickstart/selected-event-api.md)
to publish offline through the live actor, consume durably, inspect gaps/status,
and run the focused later-sync process test, the
[local ConnectRPC agent quickstart](docs/quickstart/connect-agent.md) to call
that Event authority from Connect, gRPC, or gRPC-Web without the Buf Schema
Registry, the
[selected State API quickstart](docs/quickstart/selected-state-api.md) to see a
local causal latest-value projection and learn the authenticated deletion rule,
the [selected Record API quickstart](docs/quickstart/selected-record-api.md) to
see explicit conflict annotation and guarded application resolution,
the [selected Blob API quickstart](docs/quickstart/selected-blob-api.md) to
stream immutable local content through the encrypted depot,
and the [selected architecture](docs/architecture.md) for the trust and
authority boundaries.

## Run the live mesh slice by hand

The selected implementation starts an N-node, multi-process line with
independent stores and identities. A live node-0 application source-seals and
durably publishes Ping;
route-only intermediates exact-forward it without content access; the origin
process exits; and a live destination atomically publishes a causally correlated
Pong. Restarts reuse both durable operations and equal inventory transfers
nothing:

```sh
ASTER_DEMO_PARENT="$(mktemp -d)"
cargo run --locked -p aster-node --bin aster -- \
  demo --nodes 3 --root "$ASTER_DEMO_PARENT/mesh"
```

The `--root` path must not already exist. The demo uses real Iroh connections,
independent redb stores, persisted random carrier identities, and demo-issued
random mission bundles persisted as unprotected-reference files. Only the
demo-scoped issuing authority seed is ephemeral. Bounded Negentropy reconciles
exact sealed-transfer IDs. Every contact authenticates the expected mission peer
before inventory and protects later mechanics frames. Each Event independently
authenticates its publisher and protected semantic header. This demo command does
**not** validate State/Record/Blob networking, remote Blob chunks, atomic subscription update, finite-TTL
custody, protected provisioning at rest,
NAT/hosted relay operation, BTLE, physical multi-system operation, or any
production security gate. The separate selected Event quickstart and focused
real-process test exercise the live application handle and bounded status; the
demo command itself continues to exercise its built-in Ping/Pong roles. See the
[capability tour](docs/quickstart/capability-tour.md),
the [mesh CLI quickstart](docs/quickstart/mesh-cli.md),
the [local ConnectRPC agent quickstart](docs/quickstart/connect-agent.md),
and the tracked [production requirements status](docs/implementation/requirements-status.md)
for the exact observed result and open work.

Omitting `--scenario` always selects that configurable Ping/Pong path, including
at four nodes. A separate exact four-role control scenario demonstrates one
ordered revocation and one recipient-filtered scope rekey:

```sh
ASTER_CONTROL_PARENT="$(mktemp -d)"
cargo run --locked -p aster-node --bin aster -- \
  demo --nodes 4 --scenario control --root "$ASTER_CONTROL_PARENT/mesh"
```

The authority CLI and authority carrier node are absent while a route-only node
forwards the two-control suffix. The surviving member reaches epoch two, the
captured member is excluded, and eligible members exchange epoch-two Ping/Pong.
This is not local key destruction: the captured node can still create a stale
epoch-one signature, which current eligible peers reject. The demo retains raw,
unprotected reference provisioning material and does not establish a protected
operator workflow.

Separately managed Unix nodes expose a binding local destruction hook:

```sh
target/debug/aster zeroize --state ./aster-state \
  --mission-bundle-unprotected-reference ./mission.unprotected-reference.bundle
```

For a live node the same-UID command uses owner-only local IPC, stops new work,
drains owned contact tasks, closes the Iroh endpoint, and drops derived secret
holders before committing a terminal redb cleanup intent. It then overwrites,
synchronizes, and truncates the exact retained mission-bundle and
`identity.key` inodes. Their owner-only pathnames remain as zero-length
tombstones; application and mesh rows remain for audit. Normal reopen is denied
while that redb terminal marker is retained, including if credential bytes are
later restored. This is bounded software erasure, not inode deletion or a claim
about physical media, filesystem copies, snapshots, swap, backups, or a restored
pre-marker database. There is no network zeroization trigger.

The retained parent PR-A/pre-subscription frozen-tree receipts cover three-node/13-process, default
four-node/18-process, and eight-node/38-process Ping/Pong runs plus the explicit
four-node/23-process control run. The generic line isolates Ping publication,
each forward edge, Pong publication, each return edge, and the final no-op into
`2N+1` cohorts and `5N-2` child processes. Their child logs retain zero, five,
ten, and 109 stderr lines respectively. Every directed generic transfer edge moved
exactly one pre-existing Event with all control counters zero; the N=3, N=4,
and N=8 no-ops completed 36, 62, and 228 passing contacts with all six control
and all five Event counters zero. The control path places a one-process,
zero-contact epoch-two Ping publication after control convergence and before a separate
Event-transfer cohort. After the captured-node denials it similarly separates
pre-existing Ping delivery to node 0, a one-process zero-contact Pong commit,
Pong transfer to the route-only relay, and Pong return to node 2. All 109
control-run stderr lines arose inside the two required captured-node denial
cohorts; every successful cohort retained zero stderr. Corresponding required
contacts and all terminal invariants passed. These are not zero-error, physical,
or scale claims; eight nodes are not many-node scale.
In a separate parent-snapshot live-child receipt, the zeroize CLI completed bounded local
software zeroization in 0.074759 seconds while preserving the audited rows and
terminal redb marker.

## Get the current semantic application API working

The fastest first success uses the checked-in disposable provisioning fixture.
It exercises durable, offline application behavior without pretending to be an
operational deployment.

Operational provisioning is still gated. Rust exposes a replaceable protected-
artifact boundary and an isolated age-v1 X25519 provider pilot. That pilot is
not a production default, post-quantum or FIPS claim, persistent secret store,
or protected language-binding workflow; the fixture and current binding entry
points still ingest the unprotected inner format for tests and compatibility.

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
| [`crates/aster-profile`](crates/aster-profile) | Requirements-owned reconciliation key and stable inventory ordering; exact Event transfer IDs enter by explicit conversion |
| [`crates/aster-redb-store`](crates/aster-redb-store) | Mission-bound atomic ordered-control policy plus Event and local State/Record/Blob semantic, causal, projection/publication, and operation persistence; bounded route-only Event cache; exact Blob depot markers/limits; and disjoint opaque compatibility storage |
| [`crates/aster-negentropy`](crates/aster-negentropy) | Selected bounded, clock-independent inventory set-difference mechanism |
| [`crates/aster-iroh`](crates/aster-iroh) | Selected profile-independent direct-IP carrier; endpoint authentication is not mission or data authorization |
| [`crates/aster-node`](crates/aster-node) | Selected composition root and CLI; enforces mission-before-inventory, control-before-Event, peer route filtering, exact control/Event transfer, live sample applications, and exclusive local State, Record, and Blob facades |
| [`crates/aster-core`](crates/aster-core) | Proven current semantic implementation and migration source for the data model, reducers, mission/source/control security, and synchronization behavior |
| [`crates/aster-host`](crates/aster-host) | Current semantic/reference high-level host and carrier composition |
| [`crates/aster-ip`](crates/aster-ip) | Current semantic/reference UDP/IP, discovery, rendezvous, and opaque-relay mechanisms |
| [`crates/aster-ble`](crates/aster-ble) | Current semantic/reference BTLE seam; no platform radio driver ships |
| [`crates/aster-provisioning-age`](crates/aster-provisioning-age) | Experimental Rust-only age-v1 X25519 provisioning-artifact provider |
| [`crates/aster-ffi`](crates/aster-ffi) | Current semantic/reference C-compatible offline application boundary |
| [`bindings`](bindings) | Current semantic/reference C header plus Go and Python bindings |
| [`crates/aster-conformance`](crates/aster-conformance) | Reference black-box scenarios and interoperability vectors |
| [`lab`](lab) | Research-only controlled network and impairment experiments |
| [`docs`](docs) | Tutorials, concepts, operations, specifications, and evidence |
| [`docs/index.html`](docs/index.html) | Self-contained static project landing page |

## Documentation map

- **New to Aster:** [Documentation home](docs/README.md) →
  [live mesh CLI](docs/quickstart/mesh-cli.md) or a
  [selected State projection](docs/quickstart/selected-state-api.md) or a
  [selected Record conflict projection](docs/quickstart/selected-record-api.md) or a
  [current semantic API language quickstart](docs/quickstart/README.md) →
  [Application recipes](docs/application-recipes.md)
- **Integrating a deployment:** [Carriers and contacts](docs/transports.md) →
  [Security model and production gates](docs/security.md)
- **Implementing the protocol:** [Protocol specification](docs/protocol.md) →
  [wire grammar](docs/wire.cddl) → [fixed security objects](docs/envelope.md)
- **Evaluating readiness:** [Conformance and acceptance](docs/conformance.md) →
  [production requirements status](docs/implementation/requirements-status.md) →
  [CI evidence](docs/ci.md) → [security gates](docs/security.md)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)

## Verify the repository

Install the pinned tools and run the complete local gate:

```sh
mise install
mise run check
GOBIN=/tmp/aster-go-tools go install golang.org/x/vuln/cmd/govulncheck@v1.6.0
GOVULNCHECK=/tmp/aster-go-tools/govulncheck mise run age-reference-audit
mise run age-reference-interop
```

The narrower commands in each quickstart are better for a first run. The
two age-oracle commands keep the separately maintained Go implementation, its
reachable-vulnerability and compiled-module license checks, and the
experimental artifact-provider interoperability evidence explicit. See
[CI evidence](docs/ci.md) for their narrow claim boundary.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`. Exact dependency
license texts that must accompany distributions are in
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
