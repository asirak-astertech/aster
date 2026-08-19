# Aster Mesh

Aster is an implementation-independent synchronization protocol and
embeddable Rust reference framework for intermittent, untrusted, constrained
networks. It moves four classes of data—State, Event, Record, and Blob—directly
or through store-and-forward relays without making a server part of correctness.

> **Security status:** version 0.1 is a reference candidate, not a completed MVP
> or production build. Its
> portable cryptographic provider uses NIST-standard algorithms but is **not a
> claim of FIPS 140-3 validation**. Production authorization is blocked by the
> explicit gates in `docs/security.md` and `docs/conformance.md`.

## What is here

- `docs/protocol.md` — versioned wire and replication authority
- `docs/wire.cddl` — language-neutral data grammar
- `docs/envelope.md` — deterministic security-object profile
- `crates/aster-core` — model, causal reducers, security, persistence, and sync
- `crates/aster-ip` and `crates/aster-ble` — link adapters
- `crates/aster-ffi` — C-compatible library boundary
- `bindings/go` and `bindings/python` — first-class application bindings
- `crates/aster-conformance` — black-box scenarios and wire vectors
- `docs/security.md` — threat model, controls, and production security gates
- `docs/conformance.md` — validation plan and acceptance criteria
- `docs/deprecation-policy.md` — mixed-version and retirement guarantees

## Reproducible verification

Install the pinned toolchain and run the complete local gate:

```sh
mise install
mise run check
```

Basic publish/subscribe examples are in `examples/`. Publishing commits locally
before it reports success, so the same API works without a current peer.

Rust applications use `ApplicationNode`, whose default surface contains bounded
query, publish, streamed Blob staging/read, subscribe/acknowledge, conflict,
policy, status, quota, lifecycle, and high-level authority operations. Protocol,
sealed-object, provider, key, and adapter contracts require the explicit
non-default `adapter-sdk` feature or remain internal; Go and Python expose the
same application boundary through the C ABI.

The reference also implements semantic-version-2 cross-scope bridge
authorization, immutable route rewrapping, bounded status/paging, and unified
query/subscription semantics. C, Go, and Python expose the same high-level
capability workflow without exposing sealed controls, route descriptors, keys,
provider handles, or transport internals. The Rust application host can own and
pump configured `Link` instances; current automated tests use controlled
in-memory links and do not establish behavior on a physical IP or BTLE path.

Rust, C, Go, and Python callers can explicitly publish 2–64 same-publisher/
class/topic/scope/epoch items as one atomic semantic-version-2 batch. The
default retains both compact batch and format-2 singleton representations;
callers may explicitly choose batch-only publication. Each binding also
atomically finalizes 2–64 distinct Blob writers without exposing manifests or
route commitments. Proof, compact items, any required singletons, publisher/
Event ranges, ledgers, and outbox metadata commit together or not at all. This
source/store/application/binding path and local peer runtime are green. Local
tests cover exact v1/v2 representation inventory, proof-first transfer,
compact-first private restart/promotion, and a finalized two-Blob batch through
proof, compact manifests, carriers, and plaintext verification. This is not an
independent-SUT, 3 kbps, or physical live-carrier claim.

The core fixed profile now creates fresh recipient-filtered hybrid rekey packages
and excludes an omitted captured node from the new epoch. A complete high-level
and language-binding **rekey-registry** administration workflow is still absent,
and authority restart requires an independently retained registry-generation
high-water mark.
The core also inventories, ranges, relays, and resumes encrypted Blob chunk
carriers; a reference test reopens partial state and completes it from a different
authenticated peer. Adversarial tests also prove terminal first-peer poisoning
is cleared before a full retry through a different relay, unauthenticated staging
cannot evict committed data, and the high-level/FFI path rejects route-root or
chunk-count substitution. A separate generated 101 MiB local streaming test
passes with bounded component buffers; the different-peer runtime case is
smaller, so a combined 100+ MiB different-peer run with measured process RSS and
a live IP/BTLE carrier remains an open acceptance gap. Zero-byte Blob
publication is unsupported.
The implemented four-flight handshake keeps mission, NodeID, credentials, roles,
and route-grant commitments
out of clear carrier bytes, and a reassembled-flight runtime canary test passes;
captures on every enabled physical carrier remain an external acceptance gate.
Encryption does not hide endpoints, timing, sizes, RF characteristics, or other
traffic-analysis signals. See `docs/security.md`, `docs/protocol.md`, and
`docs/conformance.md` for the complete technical disposition.

## Contributing and CI

See `CONTRIBUTING.md` for contribution requirements and `docs/ci.md` for the
automated validation lanes and local equivalents.
