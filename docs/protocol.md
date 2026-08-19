# Aster Mesh Protocol Specification

- Specification version: 0.1.0-draft.2
- Wire major/minor: 1.0
- Status: reference draft; not production-authorized
- Date: 2026-08-18

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are
normative. The protocol specification, not the Rust representation, is the
interoperability authority.

## 1. Design invariants

1. A transport carries opaque frames and never defines data meaning.
2. Every delivered item is encrypted and authenticated by its source.
3. Relays can inspect only protected routing metadata and cannot read content
   unless independently granted a content key.
4. Causality and conflict resolution never depend on wall-clock order.
5. Reconciliation is exact. Probabilistic hints may optimize but never decide
   convergence.
6. Verified objects and partial Blob ranges are peer- and transport-neutral, so
   later contact continues prior work.
7. Duplicate application is defined to have no further semantic effect.
8. Unknown optional extensions are ignorable; unknown critical extensions fail
   the containing message deterministically.

## 2. Layering

The protocol has five independent layers:

| Layer | Responsibility |
|---|---|
| Carrier | stream/datagram delimiting, opaque fragmentation, MTU adaptation |
| Adjacency | mutual authentication, replay protection, and encrypted pairwise sessions; a future profile must define any protected broadcast capsule |
| Source envelope | immutable source-authenticated route wrapper and end-to-end content ciphertext |
| Replication | exact inventories, offers/wants, resumable data, durable receipts |
| Class reducer | State, Event, Record, Blob, tombstone, conflict, and projection semantics |

IP and BTLE adapter seams move opaque core objects. The Rust application host
owns and pumps configured `Link` instances and wakes the authenticated runtime
when local inventory changes. Current host tests use controlled in-memory links;
the C, Go, and Python application nodes do not configure transports, and
no concrete BTLE controller is claimed. Broadcast support remains an adapter
primitive rather than a complete one-to-many replication profile. A future file
carrier can reuse the same serialized objects.

## 3. Primitive types and encoding

The protocol has two deterministic encodings. Replication messages use the RFC
8949 core deterministic encoding profile:

- definite-length arrays, maps, byte strings, and text only;
- shortest-width integer and length encodings;
- integer map keys in deterministic encoded-key order;
- no duplicate map keys;
- valid UTF-8 and no floating-point values in protocol-owned structures;
- no unregistered tags;
- maximum nesting depth 16, maximum control-message size 1 MiB, and configured
  byte/string/collection bounds before allocation;
- signed bytes MUST already be deterministic; a receiver MUST NOT normalize an
  invalid representation and then verify it.

[`wire.cddl`](wire.cddl) defines those maps. Security objects—credentials, source envelopes,
handshake flights, custody wrappers, controls, and Blob manifests—use the fixed,
length-prefixed binary structures in [envelope.md](envelope.md); the semantic-v2
batch additions use the fixed structures in §6.1. Those readers reject
truncation, trailing bytes, nonzero reserved fields, unknown critical kinds, and
lengths above their field-specific bound before allocation. A security object is
never reinterpreted as a CBOR object or vice versa.

Numeric registries in §19 define meaning. The exact domain prefixes, input-length
words, signature messages, KDF salts, labels, and contexts are normative in
[envelope.md](envelope.md); they MUST NOT be inferred from prose labels.

Security digests and semantic identifiers are 32-byte SHA-256 results. The
replication namespace uses a fixed 33-byte `ObjectID = kind u8 || digest[32]`.
Semantic version 1 permits kind `1` source envelopes and kind `2` Blob chunk
carriers. Semantic version 2 additionally permits kind `3` source-batch proofs,
kind `4` bridge authorizations, and kind `5` bridge-route wrappers. Full typed
identifiers decide ordering and dispatch; a session MAY use dictionary indexes
only after collision-safe binding to the full value.

Topic names are 1–128 bytes from `[A-Za-z0-9._-]`. Scope names use the same set
plus `/` as a hierarchy separator; empty, `.` and `..` segments are invalid.
Human-readable names occur only inside protected metadata. An authority MAY
assign opaque identifiers at provisioning time.

## 4. Identity, dots, and semantic item core

A provisioned identity contains ECDSA P-256 and ML-DSA-65 signing keys, a static
P-256 ECDH key, an ML-KEM-768 key, an authority serial, a mission identifier,
and authorized roles. `NodeID` is the
domain-separated SHA-256 digest of its deterministic credential body, exactly as
specified in [envelope.md](envelope.md) §3.1.

Every publisher has a durable 64-bit counter. A dot is `(NodeID, counter)` and
counter zero is invalid. Reusing a dot for different semantic bytes is publisher
equivocation and produces a security alert; it is never merged silently. The
accepted-dot and Event-sequence ledgers survive item garbage collection.

An identity whose complete durable store is lost MUST NOT resume publishing from
counter one. It must recover an external anti-rollback witness or be
reprovisioned with a new identity. The portable reference does not claim that a
filesystem can detect deletion of itself; this remains a deployment gate.

`ItemCore` contains:

| Order | Field | Constraint |
|---:|---|---|
| 0 | data class | registered `u8` |
| 1 | priority | `0..3` |
| 2 | topic | canonical bounded UTF-8 |
| 3 | origin scope | canonical bounded UTF-8 |
| 4 | publisher NodeID | 32 bytes |
| 5 | counter | nonzero `u64` |
| 6 | causal context | sorted unique `(NodeID, greatest counter)` entries |
| 7 | Event sequence | optional `u64` |
| 8 | logical key/stream | wire maximum 65,536 bytes; profile admission maximum 4,096 |
| 9 | Blob route commitment | tag; BlobID, nonzero chunk count, and Merkle root exactly for Blob |
| 10 | TTL milliseconds | optional `u64`; absent means durable, zero means already expired |
| 11 | declared content length | `u64` |
| 12 | tombstone | canonical boolean byte |
| 13 | content epoch | `u64` |
| 14 | payload | bounded byte string or authenticated Blob manifest |

`ItemID = SHA-256(u64(len("aster/item/v1")) || "aster/item/v1" ||
u64(len(binary-semantic-core)) || binary-semantic-core)` using the exact field
encoding in [envelope.md](envelope.md). The complete core is bounded at 512 MiB.

ItemID is the semantic idempotency key. Applying an already applied ItemID MUST
return the prior result without another logical revision or delivery.

## 5. Source envelope and protected metadata

Two independent key planes exist:

- a scope routing epoch key for members allowed to forward within a scope;
- a content epoch key for principals allowed to read a topic/readership group.

Possessing one key MUST NOT derive the other or any unrelated scope key.

The source computes ItemID, then derives a unique content key and nonce:

```text
ItemKey   = HKDF-SHA256(content_epoch_key,
             label="aster/content-key/v1", context=ItemID)
ItemNonce = HKDF-SHA256(content_epoch_key,
             label="aster/content-nonce/v1", context=ItemID)[0..12]
```

This is descriptive shorthand; the `PKDF` salt and encoded label/context info in
[envelope.md](envelope.md) §5.2 are part of the interoperable result.

It encrypts deterministic `ItemCore` with AES-256-GCM. Associated data binds the
wire version, suite, content epoch, and ItemID.

The protected `RouteDescriptor` repeats only forwarding and verification fields:
the publisher credential, ItemID, class, scope, topic, logical key, priority,
TTL, publisher/counter/context, Event sequence, tombstone state, declared
content length, authenticated Blob route commitment, content group/epoch/nonce,
ciphertext length, and the authentication fields selected by the envelope
format. Format 2 carries the unchanged singleton authentication-manifest
identifier and hybrid source signature. Semantic-v2 format 3 carries the exact
batch reference, Merkle path, and item ECDSA suffix in §6.1. A consumer MUST
reject if a repeated semantic field differs from decrypted ItemCore.

For stable-store wrapping, and for any future broadcast profile, the source
creates a unique opaque route selector.
`RouteKey = HKDF-SHA256(scope_routing_epoch_key,
label="aster/route-key/v1", context=selector)`. The descriptor is encrypted with
AES-256-GCM. Pairwise sessions additionally encrypt the complete replication
message, so the transport sees no descriptor fields.

`EnvelopeID = SHA-256(source-envelope-bytes)`. Relays use EnvelopeID for exact
ciphertext deduplication and resumable byte ranges; consumers recompute ItemID
after content decryption. Custody metadata is deliberately outside those stable
bytes and therefore does not change EnvelopeID.

Clear carrier data is limited to format, opaque session/key selector,
nonce/counter material, fragment position, flags, and length. Stable selectors
permit traffic correlation; encryption does not hide timing, sizes, RF energy,
or protocol presence.

## 6. Source authentication

Semantic-v1 envelope format 2 authenticates each source envelope with both ECDSA P-256/SHA-256 and
ML-DSA-65. Verification is AND: authority credential, both publisher signatures,
publisher/dot commitment, and the ItemID binding MUST pass before application
delivery. Missing or stripped signatures fail.

The fixed envelope includes a singleton authentication-manifest identifier and
both publisher signatures bind the complete canonical semantic header, including
the conditional Blob route commitment. Its bytes and meaning remain unchanged:
semantic-v2 peers MAY still use format 2 for a singleton or urgent fallback, but
no implementation may reinterpret a format-2 byte as compact batch
authentication.

### 6.1 Semantic-v2 content-committing PQ batch profile

This profile amortizes the authority credential and ML-DSA source signature
without removing post-quantum authentication. It is available only after the
authenticated session selects semantic version 2. A batch has `2..64` items
from one publisher with one data class, topic, scope, content-key epoch, and
credential. Causal counters are nonzero and contiguous in item-index order.
Event sequences are also nonzero and contiguous for class `1` Event; every
other class encodes `first_event_sequence = 0` and has no Event sequence.
Overflow, a gap, a mixed field, or reordered/duplicate item index rejects the
batch before publication.

For every domain `D`, this section writes
`H_D(x) = SHA-256(u64(len(D)) || D || u64(len(x)) || x)`, with unsigned
integers in network byte order. The registered domains are:

```text
aster/pq-batch-preamble/v1
aster/pq-batch-leaf/v1
aster/pq-batch-empty/v1
aster/pq-batch-node/v1
aster/pq-batch-id/v1
aster/pq-batch-signature/v1
aster/pq-batch-credential/v1
aster/pq-batch-item-ecdsa/v1
```

#### 6.1.1 Manifest

The canonical preamble has no outer length and encodes these fields in order:

| Field | Exact encoding |
|---|---|
| batch format | `u16 = 1` |
| envelope format | `u16 = 3` |
| semantic protocol | `u16 = 2` |
| complete suite | `u16 = 1` |
| hash algorithm | `u16 = 1` (SHA-256) |
| tree algorithm | `u16 = 1` (complete binary Merkle tree) |
| batch signature algorithm | `u16 = 1` (hybrid AND) |
| item signature algorithm | `u16 = 1` (P-256/SHA-256) |
| data class | registered `u8`, `0..3` |
| credential identifier | 32 bytes |
| publisher NodeID | 32 bytes |
| topic | `u16` byte length, then `1..128` canonical bytes |
| scope | `u16` byte length, then `1..128` canonical bytes |
| content-key epoch | `u64` |
| first causal counter | nonzero `u64` |
| first Event sequence | Event: nonzero `u64`; otherwise zero |
| item count | `u16`, `2..64` |

The batch adapter applies the global Topic and Scope grammar in §3 directly to
these protected strings. UTF-8 validity and byte length alone are insufficient:
a topic containing any byte outside `[A-Za-z0-9._-]`, or a scope containing an
empty, `.` or `..` path segment, is noncanonical and rejects before hashing.

The preamble is exactly `111 + topic_bytes + scope_bytes` bytes. Its commitment
is `H_preamble(exact_preamble)`. The manifest is the exact preamble followed by
the 32-byte Merkle root, so it is `143 + topic_bytes + scope_bytes` bytes.
`BatchID = H_batch-id(exact_manifest)`, and the source's batch hybrid signature
signs `H_batch-signature(exact_manifest)`.

A hybrid signature is exactly `u16(64) || p256_signature[64] || u32(3309) ||
ml_dsa_65_signature[3309]`, for 3,379 bytes. Verification is AND. A credential
with `g` route groups has an exact body length `B(g) = 3264 + 32g`, where
`1 <= g <= 256`. Its batch credential identifier is
`H_credential(exact_credential_body || exact_authority_hybrid_signature)`.
The fixed-binary parser MUST validate both embedded length prefixes; checking
only the 3,379-byte outer length is insufficient. Successful structural parsing
does not authenticate either signature. Length-valid, canonically framed but
cryptographically invalid or unverified signature bytes still fail provider
authentication and MUST NOT authorize a proof or dependent item.

#### 6.1.2 Content-committing leaves and tree

Each real leaf input encodes, in order:

```text
u16 leaf_format = 1
u16 item_index
ItemID[32]
u32 canonical_header_length
canonical envelope header bytes
ContentGroupID[32]
content_nonce[12]
u64 content_ciphertext_length
SHA-256(exact content ciphertext)[32]
```

The real leaf hash is `H_leaf(exact_leaf_input)`. Item indexes are exactly
`0..item_count-1` in order, and duplicate ItemIDs reject the construction. The
tree width is the smallest power of two not less than `item_count`. For every
padding index `j`, the empty leaf is
`H_empty(H_preamble(exact_preamble) || u16(j))`. Each parent is
`H_node(left[32] || right[32])` until one root remains.

An inclusion path contains exactly `ceil(log2(item_count))` sibling hashes,
bottom-up, with no direction bytes. The verifier derives left/right position
from successive bits of `item_index`. A short, long, reordered, superfluous, or
root-mismatching path rejects. Equal-valued sibling hashes are not by themselves
noncanonical; structure and the computed root decide validity.

#### 6.1.3 BatchProof object and compact item suffix

The batch proof is a stable semantic-v2 transfer object with `ObjectKind = 3`.
Its protected route plaintext is exactly:

```text
u8 object_kind = 3
u32 credential_body_length
credential_body[credential_body_length]
authority_hybrid_signature[3379]
manifest[143 + topic_bytes + scope_bytes]
source_batch_hybrid_signature[3379]
```

It is sealed under envelope format 3. The 44-byte public header is
`"ASTRENV3"[8] || u16(3) || u16(2) || u16(1) || u8(3) || u8(0) ||
route_selector[16] || u32(route_ciphertext_length) || u64(0)`. The protected
route ciphertext adds the suite's 16-byte authentication tag and there is no
content ciphertext. Its exact stable `EnvelopeID` is raw SHA-256 of the complete
sealed proof bytes; its typed inventory identity is `3 || EnvelopeID`.
Parsing this plaintext establishes only canonical structure and commitments.
Semantic acceptance additionally requires the provider to validate the exact
credential format and cryptographically authenticate both hybrid signatures.

Every dependent item remains ObjectKind `1` but uses envelope format 3. Its
44-byte public header is `"ASTRENV3"[8] || u16(3) || u16(2) || u16(1) ||
u8(1) || u8(0) || route_selector[16] || u32(route_ciphertext_length) ||
u64(content_ciphertext_length)`. The protected route plaintext ends with this
authentication suffix:

```text
u8 auth_mode = 1
proof_envelope_id[32]
batch_id[32]
u16 item_index
u8 proof_depth                 ; 1..6 and exact for item_count
sibling_hashes[proof_depth][32]
p256_item_signature[64]
```

The suffix is exactly `132 + 32*proof_depth` bytes. The item signature signs
`H_item-ecdsa(BatchID || proof_EnvelopeID || real_leaf_hash)`. Verification
requires the exact canonical header, ItemID, content group, nonce, ciphertext
length, ciphertext SHA-256, path, manifest, credential, authority hybrid
signature, source hybrid signature, and item P-256 signature to agree. The
application never supplies or selects verification keys.

#### 6.1.4 Dependency, version, and representation rules

A proof SHOULD be offered and transferred before its dependent items. An item
that arrives first is bounded, crash-durable unauthenticated staging charged to
the ordinary staging quota and requests the exact proof EnvelopeID. A bare
compact suffix or complete compact item without an authenticated matching proof
is **pending**, not accepted: it MUST NOT enter application state or satisfy the
source-authentication gate. An invalid proof or reference fails closed; a
receiver never silently converts the compact item to format 2.

A semantic-v1 session suppresses kinds `3..5` before inventory construction and
rejects ObjectKind 3, `ASTRENV3`, and compact authentication wherever received.
The receive gate applies to raw bytes: a semantic-v1 deterministic-CBOR decoder
rejects a canonical message containing a kind-3 ObjectID, and a semantic-v1
fixed-envelope decoder rejects an `ASTRENV3` header before route or content
dispatch.
This rule preserves all semantic-v1 format-2 bytes and corpus vectors exactly.
A semantic-v2 session accepts format-2 singleton fallback as well as valid
format-3 proof/item representations. When both representations are published,
they share ItemID but retain distinct EnvelopeIDs, receipts, retry completion,
custody, and garbage-collection references. ItemID deduplication occurs only at
application semantics; it must not collapse stable transfer objects.

The exact proof-envelope overhead is `P(g,s,t) = 10230 + 32g + s + t` bytes.
For `n` items the compact authentication total is
`P + n*(132 + 32*ceil(log2(n)))`. At `n=64`, `s=t=128`, the totals are 39,414
bytes for `g=256` and 31,254 bytes for `g=1`; dual publication with all
format-2 singletons is respectively 1,207,414 and 677,014 bytes. These are
serialized-byte equations, not transport-throughput or independent-
interoperability claims.

The reference exposes an explicit `publish_batch` operation rather than hidden
buffering. It atomically reserves contiguous publisher/Event ranges and commits
the proof, all compact items, accepted ledgers and metadata, plus either the
default retained format-2 singleton set or an explicit batch-only policy. Blob
items use the same source-authenticated route-commitment checks, and Rust/C/Go/
Python can atomically finalize 2–64 distinct Blob writers while keeping them
retryable after rejection. Failure before commit exposes none of the set, and
reopen reauthenticates the proof before proof-backed application reads. This
source/store/application/binding implementation and the local reference peer
runtime are green. Automated reference tests cover exact v1 singleton-only
versus v2 proof/compact inventory, batch-only proof-to-compact replication,
compact-first private restart followed by exact-proof promotion, selected-v1 compact
rejection, and finalized two-Blob proof/compact/carrier transfer with plaintext
verification. Independent interoperability, live-carrier, and 3 kbps acceptance
remain separate gates.

## 7. Causality

A version vector records the greatest accepted counter for each publisher.
Publishing captures the current vector before advancing the publisher's durable
counter. The reference profile does not encode sparse exceptions or parent IDs;
the permanent dot ledger detects counter reuse/equivocation while stored heads
retain exact conflict versions.

For complete clocks `A` and `B`:

- `A < B` when every counter in A is no greater than B and at least one is less;
- `A > B` symmetrically;
- equal clocks are equal;
- otherwise they are concurrent.

Vector entries MUST NOT be pruned while their publisher may return within the
declared retention policy. A future pruning profile requires an authority-signed
retirement and causal-stability proof. Wall-clock values are never consulted.

## 8. Data class reducers

### 8.1 State

Storage retains every causally maximal head and recoverable history. A descendant
projects over its ancestors. Concurrent heads project the lexicographically
greatest full ItemID; losing heads remain queryable and annotated. A resolution
publishes a new revision whose context and parents cover every resolved head.

### 8.2 Event

An Event has `(publisher, stream, sequence)`. Sequence begins at one and
increments by one. Missing sequence intervals surface as gaps. Equal tuple/equal
ItemID is duplicate; equal tuple with different ItemID is equivocation. Events
are immutable.

### 8.3 Record

A Record is a revision DAG. Without a registered policy, every concurrent maximal
revision remains a sibling and the application receives a conflict annotation.
A merge policy is identified by name, semantic version, and conformance-vector
digest. It receives heads sorted by ItemID and MUST produce deterministic bytes.
A merged view never deletes input versions. Explicit resolution publishes a new
revision naming all resolved heads.

Code received over the mesh is never executed.

### 8.4 Blob

A Blob manifest contains total length, media/schema metadata, chunk size, ordered
SHA-256 chunk digests, and a full-content digest. Default chunk size is 16 KiB,
configurable from 4–64 KiB. Chunks use independently derived keys/nonces and are
verified and committed while streaming. A complete blob digest is verified before
delivery. The canonical manifest is at most 1 MiB and is independently
implementable from [envelope.md](envelope.md). The current durable Blob service
can resume local chunk production and reading without whole-Blob RAM growth.

The manifest is the payload of a source-authenticated envelope whose signed
header commits BlobID, nonzero chunk count, and a route Merkle root. Encrypted
chunks travel as canonical `ASTRBT01` objects under kind-`2` typed ObjectIDs and
use ordinary WANT/DATA/RECEIPT ranges; Blob DATA has no custody wrapper. A
route-only relay verifies the source association, ciphertext hash/length, and
Merkle proof without a content key. A content reader additionally matches the
protected manifest record, authenticates/decrypts the chunk, and verifies the
whole digest. A reference runtime test durably interrupts a carrier larger than
64 KiB, reopens SQLite and Blob state with a new driver and sync reducer, then
requests the exact missing complement from a different authenticated route-only
peer and recovers identical plaintext. Its adversarial branch accepts a corrupt
range from an authenticated producer under the genuine ObjectID, detects the
poison only at terminal object authentication, deletes only that typed object's
staging, reopens with no poisoned progress, and completes the retransmission from
byte zero through a different honest route-only relay. This is local
reference-to-reference validation. A separate generated 101 MiB local streaming
test covers interruption/reopen, deduplication, readback, and tamper rejection
with component buffers no larger than 65,552 bytes. The different-peer runtime
case is smaller; a combined 100+ MiB different-peer run with measured process
RSS and live-carrier acceptance remains open.

The high-level and FFI Blob deduplication/read path re-inspects the stored sealed
source envelope and requires the exact authenticated route commitment and exact
manifest bytes; BlobID or manifest equality alone cannot substitute a different
route root or chunk count.

Empty manifests are canonical local objects, but envelope format 2 requires a
nonzero route chunk count, so a zero-byte Blob is not publishable in this network
profile. A manifest has at most 14,543 chunks and 1 MiB of bytes.
The composite per-contact inventory is capped at 100,000 ObjectIDs with source
envelopes inserted before Blob carriers. Content-authorized nodes retain both a
quota-accounted carrier and canonical encrypted chunk; route-only relays retain
the carrier only. Since a transfer digest is not invertible to its route/index,
local enumeration may reconstruct candidate objects from the authenticated route
tree.

### 8.5 Tombstones

A deletion is a signed revision with a dot, causal context, and all known heads
as parents. A dominating tombstone keeps ancestors deleted; a concurrent delete
and edit is a visible conflict. Tombstones and causal fences have separately
configured retention. The deployment baseline is offline tolerance plus margin
(30 days + 15 days). Returning after the configured bound can resurrect data;
bounded retention cannot prevent that indefinitely.

## 9. Exact reconciliation and resumption

For each policy-filtered snapshot selected by the embedding node, the implemented
inventory is an exact sparse nibble-radix Merkle tree keyed by the full 33-byte
typed ObjectID. It therefore has 66 nibble levels. A leaf commits to that full
typed identifier, keeping source envelopes, Blob chunk carriers, and semantic-v2
batch proofs disjoint even if their 32-byte digests collide. Internal hashes
commit to depth, ordered child summaries, and counts. ItemID, singleton/batch
identifiers, proof dependencies, and semantic fields are authenticated inside
the stable objects; they are not separate inventory fields.

The message flow is:

1. `INTEREST`: authorized joined scopes and consume/carry filters.
2. `SUMMARY`: immutable snapshot generation, root, and count.
3. `PROBE` / `NODE`: descend only unequal radix branches.
4. `OFFER`: exact differing typed object identifiers.
5. `WANT`: objects or block ranges accepted under quota/policy.
6. `DATA`: one stable object byte range. Source-envelope DATA may separately
   carry its per-hop custody wrapper; Blob-chunk DATA MUST carry an empty
   forwarding field.
7. `RECEIPT`: durably stored ranges for the typed object.

The canonical first WANT for a Blob carrier has unknown total length, no missing
ranges, and `need_forwarding = false`. After the first DATA establishes total
length, WANT carries the exact sorted missing ranges. Empty ranges with false
forwarding requests no work and is rejected.

A terminal full-object length, identity, route, ciphertext, source-authentication,
or policy failure atomically aborts only that typed ObjectID. Durable extents,
known total, received ranges, pending writes, hop forwarding, and commit-pending
state are cleared, and the peer-neutral request returns to the canonical
unknown-total/empty-range WANT. No inventory entry or successful receipt is
created. Transient Store, I/O, and missing-chunk failures preserve progress.

Equal roots end a partition without an inventory scan. A future optimization
such as an IBLT or Bloom filter MAY be negotiated, but every ambiguity or
overflow must fall back to the exact tree; no such optimization negotiation is
implemented in profile 1.

Every exchange names immutable roots. Verified objects commit immediately.
Outstanding wants are stored by ObjectID/range, not by peer or session. Losing a
contact may restart tree traversal without discarding durably verified ranges.
Delivery is at least once; application acknowledgement state is separate from
protocol receipt state.

The reference driver can initiate an exchange and can answer one through its
responder-with-start path, so its in-memory authenticated flow is bidirectional.
If backend storage rejects a received range, the intent remains queued for a
later attempt. Once authenticated, the driver retains causal protocol work and
uses monotonic deadlines derived from message priority, retry attempt, and the
link's reported retry floor. INTEREST, SUMMARY, PROBE, NODE, WANT, and DATA can
therefore be retried without application polling logic. Authenticated causal
responses retire predecessor work, and RECEIPT ranges retire matching DATA.
The current retry loop is bounded as specified in §18; it is not a general
congestion controller and does not claim progress under permanent or
adversarial loss.

The retained ciphertext and transfer identifier are reused for up to eight
send rounds so fragments from a lossy contact can complete one logical record.
A still-live retry then receives a fresh session record and transfer identifier;
the receiver's replay window remains authoritative. A bounded standalone NODE
response expires after those rounds and is regenerated only by its retained
causal PROBE. The responder's final handshake flight is retained until the next
authenticated session record acknowledges it causally.

Reference tests cover a forced lost SUMMARY, seeded approximately 50% frame
loss in both directions, a 96-byte MTU, and fragmented 4 KiB DATA. It converges
and commits exactly once, then re-acknowledges duplicate committed DATA so a
lost RECEIPT cannot strand the sender. This remains software
reference-to-reference validation, not the required 3 kbps/live-carrier gate.

## 10. TTL and freshness without synchronized clocks

TTL is a signed duration, never an ordering timestamp. A custody wrapper carries
an authenticated nondecreasing age lower bound. Each node persists received age
and adds elapsed local monotonic residence before offer, request, retry, send, or
delivery while that monotonic clock remains continuous. The wrapper contains no
wall-clock timestamp, and profile 1 does not define a cross-node wall-time
adjustment.

If finite-TTL age cannot be bounded across reboot or power loss, the node MUST
mark the item non-forwardable until a trusted time source proves it unexpired; it
MAY retain it locally with an indeterminate-age annotation. Durable items are not
affected. An item known locally to have `age >= TTL` MUST NOT be offered,
requested, retransmitted, or sent and MUST enter garbage collection.

Session counters/windows, full ItemID deduplication, publisher counter ledgers,
mission epochs, and control-chain rollback checks ensure captured traffic is not
accepted as a new logical item. A fresh node without trustworthy time cannot
infer real age from a capture alone; provisioning epochs bound this case.

## 11. Priority, retry, eviction, and emissions

Wire priorities are fixed: 0 ROUTINE, 1 PRIORITY, 2 IMMEDIATE, 3 FLASH. Doctrine
profiles MAY change display names but not ordinals. Publisher priority is capped
before signing by topic/integrator policy. A bridge may locally suppress or
demote scheduling but never rewrite the source-signed priority, reset custody
age, or extend TTL.

When eligible work is queued, higher priority receives earlier initial
transmission, greater in-flight allowance, and later eviction. Within a priority
lane, bounded fairness and expiry urgency prevent a Blob from monopolizing a
link. The authenticated runtime also gives higher priority earlier retry
deadlines and sends due work in priority/queue order while respecting the
adapter's minimum retry interval. At saturation, higher-priority work may
replace only lower-priority expendable NODE, WANT, or DATA retries. Retained
INTEREST, SUMMARY, and PROBE causal work is not silently evicted. Exact queue
and byte ceilings are in §18.

Committed storage pressure evicts expired data, then unconsumed relay data, then
uses ascending priority/nearest expiry/oldest policy order. Current keys,
revocation/control state, and retained tombstone fences use reserved quota.

The reference isolates unauthenticated transfer staging from committed-record
eviction. It reserves one quarter of configured `max_bytes`, capped at 64 MiB
and always leaving at least one byte for committed data; the remainder is the
committed ceiling. Staging is capped at 4 MiB per object,
`min(max_items, 10,000)` objects, 4,095 extents per object, and 65,536 extents
globally. An extent that exceeds a staging bound is rejected transactionally and
evicts neither existing staging nor a committed item. The 4 MiB per-object cap
is also the current runtime transfer admission limit for a source envelope,
even though the fixed envelope format has a larger bound.

Emission modes are:

- `Normal`: all eligible traffic and discovery.
- `AtLeast(p)`: no discovery; application and supporting control traffic below
  `p` is suppressed.
- `ReceiveOnly`: no discovery, inventory, or item transmission; mandatory
  authentication/link acknowledgements may occur to ingest on connection-oriented
  transports.
- `PassiveOnly`: zero framework-originated bytes; receives only unsolicited
  independently protected broadcast/push.

The physical distinction is mandatory in operator presentation and remains a
stakeholder-validation item.

## 12. Scopes, topics, relay, and bridge policy

Consume interest and carry interest are explicit. A node reconciles only their
union within joined scopes; it is never required to hold a global dataset. A
relay can hold routing keys and carry interest without content-read keys.

Scope hierarchy is authority signed and administrative, not implicit key
derivation. Parent membership grants no automatic child access and vice versa.
Cross-boundary propagation requires an explicit authority control containing
the bridge identity, exact directed source/target scopes and route epochs,
allowed topics, four-bit priority mask, and one-to-eight-hop bound. A bridge may
install only a narrower local topic/priority filter. Storage quota and source-
signed TTL/custody rules apply independently and cannot be widened by that local
filter.

The semantic-version-2 bridge path decrypts protected route metadata, evaluates
an authority-issued exact directed-edge policy plus a local narrowing filter,
and creates a destination routing wrapper around the byte-identical format-2
source envelope. ObjectKind 4 authorization controls and ObjectKind 5 wrappers
are suppressed on selected-version-1 sessions. An authorization and each hop
are hybrid authenticated; an eight-hop bound, exact path continuity, and a
no-repeated-scope rule prevent route widening and loops.

The bridge never grants payload access. Query and subscription results preserve
the source-authenticated `origin_scope` and separately expose the wrapper's
`current_scope`; consumption still requires the original scope/topic/content-
epoch grant. Application ItemID/dot/Event semantics and one durable delivery
ledger are shared across direct and bridged arrival, while wrapper routes,
receipts, outboxes, and custody remain representation specific.

The reference implements every dependency arrival order, crash-durable pending
state, restart reauthentication, receipt-aware inventory/serving, deterministic
active-path selection with verified fallback, monotonic custody, dynamic
filter/revocation/epoch checks, and quota/reference-counted lifecycle. The
high-level Rust/C/Go/Python administration surface uses move-only enrollment and
opaque durable 32-byte authorization/route handles; it does not expose sealed
objects or keys. Cross-implementation, scale, physical-carrier, and independent
cryptographic review remain release gates. Future summarization publishes a new
derived item with provenance.

A wrapper adds no trusted tombstone-retention timestamp. The reference therefore
keeps a bridged tombstone fence protected instead of inferring an early-eviction
age; if quota pressure reaches only such protected records, admission fails
closed.

## 13. Authenticated session and downgrade protection

Suite `0x0001` is provisional and complete:

- P-256 ephemeral ECDH + ML-KEM-768;
- ECDSA P-256/SHA-256 + ML-DSA-65;
- HKDF-SHA-256;
- AES-256-GCM with 96-bit nonce and 128-bit tag;
- SHA-256.

There is no classical-only fallback inside the suite. The suite's hybrid KEM
combiner is a pre-production independent-review gate; suite encoding never
changes in place.

The four-flight handshake is `ClientHello`, `ServerHello+ServerAuth`,
`ClientAuth`, `ServerFinished`, with exact bytes in
[envelope.md](envelope.md) §8. Flight 1 contains anonymous public hello material
and a proof under the provisioned common mission control-route key; the responder
verifies that proof before parsing the ML-KEM public key or doing P-256/ML-KEM
work. Responder and initiator credentials are encrypted after the hybrid secret
exists. The final transcript binds the canonical descending semantic-version
offer, the canonical descending complete-suite offer, the responder's selected
semantic version and complete suite, both fresh 256-bit nonces, both P-256
shares, ML-KEM public key/ciphertext, the proof commitment, mission, roles,
route-grant commitments, authority credentials, and both handshake hybrid
signatures.

Both signature algorithms, the server and client empty-plaintext key
confirmations, and the encrypted 32-byte ServerFinished value MUST verify before
DATA or inventory is accepted; wire/profile `1` has no 0-RTT application data.
Clear flights contain no mission, NodeID, credential, role, or route-grant commitment. This
does not hide size/timing or identifiers available to the link or network before
flight 1.

The key schedule uses exact concatenation of the 32-byte P-256 ECDH result and
32-byte ML-KEM result, with the public transcript as HKDF salt and seven distinct
direction/protection/confirmation labels. The stable handshake framing,
credential/envelope encoding, cryptographic profile, and replication wire
profile remain version `1`. Inside that framing, a default initiator offers
semantic versions `[2, 1]`; an honest current responder selects the highest
common value, so current peers select `2` and a v1-only peer selects `1`. The
selected semantic version is bound into the public transcript, key schedule,
key confirmations, and hybrid handshake authentication.

That binding provides on-path transcript downgrade resistance: an attacker who
cannot authenticate as either endpoint cannot strip or reorder the ClientHello
offer or rewrite an honest ServerHello selection. It does not authenticate the
responder's complete capability set. A valid older, modified, or rolled-back
responder using an accepted credential can select `1`, and the initiator cannot
distinguish authorized compatibility from rollback. No production downgrade
claim is permitted until an authority-signed mission minimum semantic version
and durable per-identity high-water state with explicit rollback authorization
are implemented and independently tested. Stateless cookies, resumption,
export keys, and general handshake extensions also remain separate release work.

## 14. Revocation, rekey, and zeroization

Authority control records are dual-signed, FLASH-priority, non-evictable items
containing mission, monotonic control sequence, previous-state hash, revoked
credentials, and key epoch transitions. Lower sequences or a fork from an
accepted state are security failures.

After receiving revocation, a node rejects new sessions and source attestations
from that credential. ScopeEpoch format `0` remains a legacy activation of an
independently pre-provisioned epoch and does not exclude a holder of that key.
Format `1` carries one through 128 sorted recipient packages. The authority
generates a fresh scope route key, fresh per-topic content keys, and a hidden
random salt per recipient grant; each package combines fresh P-256 ECDH and
ML-KEM-768 and is bound to the mission, authority, control-chain link, scope,
epoch, complete package set, recipient credential, and salted topic grant.
Only a durably applied control can activate. A matching nonrevoked recipient
authenticates and decapsulates the complete package before removing any
pre-placed key for that scope/epoch and installing its replacements; an omitted,
credential-mismatched, or locally revoked node removes stale grants and installs
none. The signed recipient set is also the dynamic route authorization set for
that epoch. Applied controls are reauthenticated and their packages
redecapsulated on reopen. Exact bytes and bounds are in
[envelope.md](envelope.md) §6.

The provisioner persists recipient public credentials in a separately signed,
append-only `ASTRRKR1` administrative registry; the mesh does not distribute
that registry. Preventing rollback after complete authority storage replacement
requires the operator to persist the last registry generation independently and
enforce it on import. High-level application and language-binding rekey calls
exist, but complete public-registry import/management is not provided. Old keys
may still decrypt retained history under policy. A captured holder of the old common
control-route key can see the encrypted control's package metadata, recipient
identifiers, and sizes, but an omitted holder cannot recover hidden grant salts,
topic lists, or fresh epoch keys.

Zeroization destroys in-memory identity, package, scope, content, session, DRBG,
and cached-plaintext material, then calls platform keystore/destruction hooks.
Destroying a hardware-backed wrapping key is the preferred persistent mechanism.
Software cannot promise physical erasure from flash and documentation MUST NOT
claim it.

Revocation takes effect at an honest disconnected node only after the record
arrives. It cannot erase keys or plaintext already captured.

## 15. Carrier, fragmentation, broadcast, and loops

On a bound ordered stream, carrier framing is a bounded length plus session
ciphertext. On datagrams, a compact core header contains format/flags, opaque
transfer token, fragment index/count or range, and payload length. The full frame
is authenticated before semantic parsing. Fragmentation and reassembly are owned
by the core runtime; IP and BTLE adapters carry opaque core fragments and MUST
NOT create an incompatible adapter-specific fragmentation protocol. For an MTU
too small for mandatory security overhead, the core uses the link's reported MTU.

Reassembly is bounded globally and per authenticated adjacency. Duplicate
segments are harmless; inconsistent overlap, length overflow, token reuse,
excessive sparse state, and changed counts fail. Blob blocks bound RAM and stream
to disk. The reference adjacency admits at most 16 incomplete logical frames
using at most 4 MiB of aggregate reassembly bytes. Filling that volatile budget
drops only incomplete fragment state so a retained sender can refill it;
inconsistent reuse remains fatal.

After one logical transfer authenticates successfully, the driver retains a
FIFO completion record keyed by adapter route and transfer identifier with the
logical length and SHA-256 digest. The cache is capped at 1,024 entries.
Identical repeats are ignored, while reuse of the same route/identifier for
different completed logical bytes fails closed. Entries are recorded only after
the handshake flight or session record authenticates; this cache is transport
replay defense, not application-level ItemID deduplication.

The adapter contract can report broadcast capability and the simulated BTLE seam
can emit one opaque payload to multiple listeners. The reference does not define
or implement a complete broadcast replication capsule, Trickle suppression,
randomized NACK/repair aggregation, or loop-bounded one-to-many runtime. Those
remain protocol and physical acceptance work; ordinary pairwise reconciliation
must not be treated as broadcast validation.

## 16. Discovery and link profiles

An IP local-discovery advertisement is exactly `type=1 u8 || nonce[16] ||
proof[16]`. The nonce is fresh OS cryptographic randomness. The provisioned
128-bit discovery token is never transmitted. The proof is the 16-byte output
of HKDF-SHA-256 with salt `"aster/ip-discovery-proof/v1"`, IKM equal to
the discovery token, info equal to the 16-byte nonce, and output length 16.
Discovery identifies a
candidate endpoint only; it cannot pass the fresh hybrid handshake. Manual and
provisioned endpoints enter that same authentication path. Constrained modes do
not advertise.

The link contract exposes MTU; ordered/reliable/broadcast capability; estimated
bandwidth/loss/latency; cost; emission footprint; listen/discover/connect;
send/receive. The SDK cannot choose a transport for an item.

The IP adapter prefixes opaque data with `type=0 u8` and accepts UDP datagrams no
larger than 65,507 bytes. Its rendezvous registration is `type=2 ||
pairing_token[32]`; the peer response is `type=3 || pairing_token[32] || address`,
where address is `4 || IPv4[4] || port u16` or `6 || IPv6[16] || port u16`; and a
punch is `type=4 || pairing_token[32]`. The response token MUST match a locally
outstanding token before its address is used. The high-entropy pairing token is
a rendezvous capability, not peer authentication, and is visible to the
rendezvous service. Waiting registrations expire after 120 seconds. Reference
bounds are 4,096 peers, 4,096 discovered addresses, 128 outstanding punch tokens,
and 4,096 rendezvous registrations. Local/direct operation has no infrastructure
dependency; restrictive NAT/firewall pairs may require rendezvous or the
separately deployable opaque ciphertext relay.

For a DATA datagram from an unknown socket address, the IP adapter creates a
process-local 32-byte routing handle for the `Link` interface. It draws a fresh
32-byte seed when the adapter instance opens and computes HKDF-SHA-256 with salt
`"aster/ip-endpoint-handle/v1"`, IKM equal to that seed, info equal to the
canonical address encoding above followed by a one-byte retry counter `0..15`,
and output length 32. It selects the first nonzero value that does not collide
with another address. This NodeID-shaped value is never a wire field or an
authenticated identity and is stable only for that adapter instance. The runtime
may latch it to route later handshake fragments, but authorization and peer
state MUST use only the NodeID yielded by the authenticated core session.

The BTLE crate is a platform-neutral seam for opaque service data, MTU reporting,
L2CAP/GATT capability selection, and advertisement delivery. Its simulation can
exercise those contracts, but no concrete controller driver currently performs
live L2CAP or GATT I/O. Core persisted object progress and the Rust host's link
pump are link neutral; the missing controller and physical run prevent a live
claim that a transfer survives BTLE disconnect or MTU change.

Every replication message is serializable; a future file carrier can exchange
CBOR sequences across separate physical trips without a live call stack.

## 17. Versioning and extensions

Carrier revision, stable replication-wire/profile version, negotiated semantic
version, cryptographic suite ID, and object/data-class registries are separate.
A transport addition changes none of them. `PROTOCOL_VERSION` and the legacy C
`aster_protocol_version()` report stable replication-wire/profile version `1`;
the unambiguous replication-wire surfaces also report `1`, while the default and
highest-supported semantic-version surfaces report `2`.

The current handshake negotiates semantic versions `2` and `1` and the complete
suite `0x0001`. Offers are nonempty, nonzero, duplicate-free canonical descending
lists of at most 16 values. The responder selects the highest common semantic
version and its locally preferred complete common suite; the initiator requires
both selections to have been offered and to be locally supported. Semantic `1`
permits transfer object kinds `1` (source envelope) and `2` (Blob chunk).
Semantic `2` additionally permits the reserved kinds `3` (source-batch proof),
`4` (bridge authorization), and `5` (bridge-route wrapper). A v1 session filters
those extended kinds before inventory-root construction and rejects them in
messages, durable progress, and transfer events rather than silently processing
v2 semantics. Semantic 1 also rejects envelope format 3 and compact batch
authentication. Semantic 2 permits both the unchanged format-2 singleton and
the §6.1 format-3 batch representation; negotiated semantics never rewrite
stored stable bytes.

Durable ranged-transfer progress records the immutable semantic version under
which the object was first admitted. A source object first admitted under v1 may
resume on v1 or v2; a source first admitted under v2 may resume only on v2.
Recognized stable Blob carriers admitted under either version may resume on
either version, while v2-only kinds `3..5` resume only on v2. Migrated progress
without trustworthy origin-version provenance is suppressed rather than guessed.
Eligibility filtering occurs before page limits so incompatible early rows
cannot starve later compatible work.

Deterministic-CBOR map keys `64` and above are ignorable extensions, while
unknown keys `0..63` fail. Fixed-binary registries are closed. The current
source-envelope decoder rejects unknown data classes, so opaque forwarding of a
future class is aspirational rather than implemented behavior. New semantics,
formats, or registry entries MUST allocate new values rather than changing
stable version-1 bytes in place. The authenticated mission floor and peer
high-water gate in §13 is required before negotiated v1 fallback is authorized
for downgrade-sensitive production use.

Before 1.0, the project MUST publish minimum support windows, authority rollback
format, registry allocation policy, and test fixtures. Stored envelopes remain
self-describing and forwardable by a node that cannot consume them.

## 18. Error and resource behavior

All untrusted lengths/counts are checked before allocation and arithmetic is
overflow checked. Invalid data fails the containing object/session without
panicking. Authentication failure reveals one indistinguishable error externally.
Rate, byte, fragment, partial-transfer, peer, and handshake limits are configured.

The reference authenticated adjacency enforces these outbound/replay limits:

| Resource | Bound | Saturation behavior |
|---|---:|---|
| retained retry records | 128 entries | higher priority may replace only lower-priority expendable NODE/WANT/DATA work; otherwise backpressure or deferred WANT |
| one-shot logical outbox | 128 entries | new one-shot work returns explicit backpressure |
| retained handshake flight | 1 entry | a causal authenticated next flight replaces or retires it |
| combined pending logical bytes | 16 MiB | checked before every retry insert/refresh, outbox insert, and handshake replacement |
| logical sends per pump | 128 | remaining due work keeps its monotonic deadline |
| durable/deferred WANTs | 10,000 objects by default | compact metadata remains retryable without retaining ciphertext or payload |
| incomplete fragment transfers | 16 transfers and 4 MiB aggregate | volatile incomplete state resets; authenticated retained senders refill it |
| completed transfer records | 1,024 entries | FIFO eviction; conflicting route/transfer-ID reuse fails closed |
| DATA production per WANT | 16 messages of at most 64 KiB payload each | each backend batch is queued before expanding the next WANT; excess returns backpressure |

The shared 16 MiB counter covers each retained retry's fixed `Message` value,
every owned nested string/vector capacity, any duplicate variable prefix held in
its retry key, and its sealed record, plus every one-shot and handshake record
capacity. Fixed retry/key fields other than `Message`, tree/deque node and spare
container storage, allocator headers, and compact deferred-WANT metadata are not
in that byte counter; their entry counts are bounded separately above. The cap
therefore describes retained logical buffers, not total process RSS.

When retained space is saturated, a durable receiver WANT is never silently
discarded. It remains in peer-neutral sync state with a compact retry marker,
can send a fresh authenticated one-shot WANT while saturated, and is promoted
back to retained retry work when space opens. Non-WANT excess is rejected with
explicit backpressure. This preserves receiver progress without claiming
unbounded buffering or delivery under permanent loss.

The Tier-2 baseline uses bounded queues, paged queries, one storage writer,
streaming blobs, event-driven wakeups, and configurable duty cycles. No protocol
component requires an in-memory mirror of the 10,000-item working set.

Finite storage means convergence is defined over items retained by declared TTL
and visible quota/eviction policy. Evictions and conflicts surface to the app.

## 19. Initial registries

| Registry | Values |
|---|---|
| class | 0 State, 1 Event, 2 Record, 3 Blob; every other value rejected in profile 1 |
| priority | 0 Routine, 1 Priority, 2 Immediate, 3 Flash |
| message | 1 Interest, 2 Summary, 3 Probe, 4 Node, 5 Offer, 6 Want, 7 Data, 8 Receipt |
| transfer object kind | semantic 1: 1 source envelope, 2 Blob chunk; semantic 2 adds 3 source-batch proof, 4 bridge authorization, 5 bridge-route wrapper |
| source envelope format | 2 singleton hybrid authentication; semantic 2 adds 3 content-committing batch authentication |
| batch authentication mode | 1 exact proof reference, Merkle path, and P-256 item signature |
| suite | `0x0001` provisional hybrid reference suite |
| map field | unknown `0..63` critical; unknown `64..2^64-1` optional |

New allocations require specification text, conformance vectors, security and
compatibility analysis, and a unique numeric value. Reusing a withdrawn value is
forbidden. The closed fixed-binary magic, kind, and role registries are in
[envelope.md](envelope.md) §2; the deterministic-CBOR field registry is in
[wire.cddl](wire.cddl).

## 20. Known bounds

- Offline revocation is not instantaneous and cannot revoke already known data.
- NAT traversal cannot always succeed without rendezvous/relay infrastructure.
- Exact elapsed TTL over an unmeasurable powered-off interval is unknowable.
- Bounded tombstones cannot prevent resurrection after their retention bound.
- Encryption does not hide traffic analysis.
- PQ handshakes/signatures remain large; caching/batching reduces frequency only.
- Format 2 carries a full credential and two large signatures per singleton
  source envelope. The semantic-v2 provider and atomic explicit batch
  source/store/application path plus reference peer proof/compact runtime
  amortize transferred verification bytes, but the required 3 kbps end-to-end
  measurement and independent interoperability remain separate gates.
- Link-, network-, rendezvous-, or discovery-layer identifiers observed before
  the first Aster handshake flight can still correlate contacts.
- Recipient-excluding rekey is implemented in the core fixed profile, but its
  public recipient registry requires an independently persisted generation
  high-water mark after authority storage replacement. High-level rekey calls
  are shipped, but complete public-registry import/management is not.
- Typed Blob chunk transfer and different-peer range resume are verified in the
  in-memory reference runtime, and a separate generated 101 MiB local streaming
  case passes with bounded component buffers. A combined 100+ MiB different-peer
  run with measured process RSS and live carrier remains an acceptance gap.
  Zero-byte Blob publication is not supported by envelope format 2.
- A custom hybrid composition needs independent cryptographic review.
- Literal passive silence cannot request, authenticate interactively, or ACK.
- The Rust application host owns and pumps configured link instances, while the
  native language bindings remain transport-neutral local application APIs.
  Current authenticated host/timer-retry tests use controlled in-memory links.
  The bounded retry loop is not a general congestion controller and has no
  permanent-loss or physical live-carrier liveness claim.
- Broadcast is only an adapter primitive; a complete protected one-to-many
  replication and repair protocol is absent.
- An external independent implementation is required before interoperability can
  be claimed; reference-to-reference tests alone are insufficient.
