# Aster Conformance Plan

- Plan version: 0.1.0
- Protocol under test: Aster 1.0 draft

The target conformance program is black-box. A system under test (SUT) would
implement the small local control contract below while synchronization travels
through real Aster wire messages. JSON result documents would include
protocol/suite versions, vector digest, seed, capabilities, exact pass/fail
results, and packet captures where relevant. That scenario harness and SUT
contract are a plan, not a shipped executable feature.

Passing the reference implementation against itself is necessary but is not the
independent-interoperability acceptance claim.

Fixed security-object bytes and bounds come from [envelope.md](envelope.md) and
the semantic-v2 batch profile in [protocol.md](protocol.md) §6.1; replication
CBOR comes from [wire.cddl](wire.cddl). A test harness MUST retain those
namespaces and must not normalize a rejected encoding.

The shipped `aster-conformance` runner provides four stable entry points:

```text
aster-conformance --self-test
aster-conformance --emit-vectors
aster-conformance --emit-batch-vectors
aster-conformance --check-wire-hex HEX
```

The generated corpus is checked in at `conformance/vectors/wire-v1.tsv` so an
independent implementation can consume it without linking the reference core.
`ACCEPT` rows must decode and re-encode byte-for-byte; `REJECT` rows must be
rejected before semantic dispatch. The current corpus has 10 ACCEPT and 21
REJECT rows. The Rust verifier requires every ACCEPT row to raw-decode,
canonical re-encode to identical bytes, and pass typed semantic decoding; every
REJECT row must fail typed decoding. The accepted evolution row retains an
unknown key-64 bounded nested value in the raw-value path even though the typed
version-1 message ignores its semantics. Negative rows cover deterministic-CBOR
form, identifiers, critical extensions, prefix form, range ordering and
coalescing, Blob forwarding, no-work requests, Receipt completeness, empty
DATA, radix counts, and integer bounds.

The separate checked-in
`conformance/vectors/batch-semantic-v2.tsv` corpus covers the fixed-binary
semantic-v2 content-committing batch profile without changing any wire-v1 row.
It intentionally contains no `ACCEPT` disposition because it provides no
provider keys or cryptographic authentication oracle. Its four dispositions
have these exact meanings:

- `CANONICAL-COMPONENT`: a standalone preamble, manifest, or leaf parses and
  re-encodes exactly; this is not application or source-authentication
  acceptance.
- `STRUCTURAL-UNVERIFIED`: a proof-bearing structure has exact canonical
  framing and internally consistent commitments, but every signature remains
  cryptographically unverified and the row MUST NOT release a pending item.
- `PENDING`: a canonical ASTRENV3 header or compact suffix is insufficient
  without an independently authenticated matching proof.
- `REJECT`: canonical or semantic structural decoding must fail before
  provider authentication.

The corpus contains 4 `CANONICAL-COMPONENT`, 8
`STRUCTURAL-UNVERIFIED`, 4 `PENDING`, and 38 `REJECT` rows. Its exact checked-in
SHA-256 is
`46b94199042576fdcbbfd7713f47d60995740e8cbdbb04e6459fef813a364979`.
The Rust verifier explicitly rejects an
`ACCEPT` row, requires proof routes to carry exact
`u16(64) || 64 bytes || u32(3309) || 3309 bytes` hybrid framing, and never
reports a structural row as authenticated.

Six portable `merkle-case` rows cover depths 1 through 6 with `(n,index)` equal
to `(2,1)`, `(3,2)`, `(5,4)`, `(9,8)`, `(17,16)`, and `(33,32)`. Every
non-power-of-two case selects the final real leaf, whose first sibling is the
normative padded empty leaf. `merkle-case` is a conformance-only container, not
a protocol object, encoded as:

```text
"ASTRMCV1"[8]
u32 manifest_length || manifest[manifest_length]
u16 item_count
repeat item_count times:
    u32 leaf_length || leaf[leaf_length]
    u32 ciphertext_length || ciphertext[ciphertext_length]
u16 selected_index
u32 compact_length || compact_authentication[compact_length]
```

The verifier checks every ciphertext commitment, rebuilds the complete ordered
and padded tree from every leaf, compares the root to the manifest, compares the
exact generated path to the compact siblings, and verifies the BatchID, item
index, proof-depth, root, and item-signature digest input end to end. The item
signature bytes remain `STRUCTURAL-UNVERIFIED`. A negative padding-sibling row
must fail that same end-to-end verifier.

Negative rows additionally cover global Topic/Scope grammar and both embedded
hybrid-signature length prefixes, alongside constant/version downgrade,
class/count/sequence/range, truncation, trailing bytes, leaf format, compact
mode/depth, proof kind, credential commitment, ASTRENV3
magic/reserved/kind/length, and proof-content invariants. The self-test injects
raw canonical kind-3 CBOR and raw `ASTRENV3` into semantic-v1 receive decoders,
serializes every `n=2..64` batch at `g=1` and `g=256`, and checks the exact
overhead equations and headline byte totals.

The supersession receipt at
`conformance/vectors/batch-semantic-v2-supersession.ndjson` preserves the exact
hash, byte/line counts, dispositions, and unsafe-acceptance reason for the prior
corpus before recording this replacement. The active runner includes only the
corrected TSV.

This batch corpus is emitted and judged by the reference implementation and
therefore has `oracle=self`. A separately authored implementation must consume
the checked-in bytes and exchange actual proof/item objects with the reference
before the independent-interoperability gate can pass. Reimplementing the
decoder inside this repository, using another language, or passing
reference-to-reference tests does not satisfy that gate.

Beyond the structural corpus, the Rust reference implements the provider and
explicit atomic source/store/application path: 2–64-item validation, contiguous
publisher/Event reservation, retained-dual default, explicit batch-only policy,
Blob batches, all-or-nothing proof/compact/singleton/ledger/outbox commit, and
proof reauthentication before reads after reopen. These are local construction
and durability subgates. C, Go, and Python expose the same retained-dual/
batch-only transaction plus atomic batches of finalized Blob writers; FFI 12/12,
Go 8/8, Python 9/9, and linked C/C++ smoke pass. The reference peer runtime also
passes exact retained-dual/batch-only inventory shaping, batch-only proof-first
replication and receiver restart, compact-first private persistence followed by
exact-proof promotion, selected-v1 compact rejection, and a finalized two-Blob
proof/compact/carrier transfer with plaintext verification. Core 196/196, host
9/9, and strict core/host lint pass. This remains same-team reference evidence,
not independent interoperability, a 3 kbps result, or a physical-carrier claim.

The self-test additionally checks exact Merkle differences, tiny-MTU
out-of-order reassembly, resource bounds, and causal concurrency using the same
reference implementation as producer and oracle. The checked-in corpus is the
deterministic sync-wire corpus only; it is not a complete corpus for every
V-FIXED/V-CRYPTO group below. Scenario, independent-SUT, and hardware claims
remain separate gates.

`conformance/python_wire_oracle.py` is a separate, standard-library-only decoder
and semantic validator which neither imports nor binds the Rust implementation.
It checks canonical re-encoding for every ACCEPT row and rejection of every
negative row. Its result identifies itself as
`same-team-not-independent-python-codepath`, while the corpus and Rust runner
retain `oracle=self`. Because both were authored by the same project team and
the corpus is produced by the reference, this is
code-path and language diversity evidence—not the separately authored SUT
required by A-10.

## Local SUT control contract

An implementation exposes newline-delimited deterministic JSON over stdin/stdout
or a local Unix socket. The control path is test-only and never a mesh transport.

Commands: `reset`, `provision`, `join`, `subscribe`, `carry`, `publish`,
`publish_batch`, `publish_blob`, `publish_blob_batch`, `edit`, `delete`,
`advance_monotonic`, `set_link`, `partition`, `heal`, `set_loss`,
`set_bandwidth`, `set_emission`, `revoke`, `rekey`, `query`, `conflicts`,
`status`, `metrics`, `shutdown`.

Every response has request ID, status, structured result, and implementation
manifest. Secrets are redacted from reports. Test reports bind results to the
implementation version and conformance-vector digest under test.

## Normative vector groups

| ID | Group | Required evidence |
|---|---|---|
| V-WIRE | deterministic CBOR | exact accepted bytes and nonminimal/duplicate/indefinite/oversized rejection |
| V-FIXED | fixed binary security objects | every `envelope.md` object at min/max bounds, including `ASTRPB03`, delegated `ASTRCA02`, and `ASTRBCA2`; truncation, trailing, reserved, length, ordering, credential/signer substitution, and cross-field rejection |
| V-BATCH | semantic-v2 content-committing batch | exact preamble/manifest/BatchID, content leaf, complete tree/padding/path, ObjectKind 3 proof route, format-3 compact suffix, missing-proof pending state, downgrade/mutation rejection, and serialized overhead |
| V-BRIDGE | semantic-v2 cross-scope bridge | exact ObjectKind 4 authorization-format-2 delegated signer authentication and ObjectKind 5 wrapper bytes; signer persistence/liveness, directed-edge/filter/path authentication, v1 suppression, source/Blob dependencies, arrival-order, restart, custody, revocation, fallback, quota, and unified-delivery behavior |
| V-ID | identifiers | exact ItemID, raw-SHA-256 EnvelopeID, 33-byte typed ObjectID including semantic-v2 kind 3, BlobID, Blob transfer-object digest, ManifestDigest, ContentGroupID, NodeID, SingletonBatchID, and content-committing BatchID inputs |
| V-CRYPTO | algorithms | NIST KAT provenance plus exact envelope, root-credentialed delegated-control, custody, Blob, and session vectors from `envelope.md` |
| V-HANDSHAKE | peer authentication | all four exact flights and transcript intermediates; tamper, replay, downgrade, proof, key-confirmation, and either-signature failure |
| V-CAUSAL | dots and clocks | before/after/equal/concurrent/equivocation traces; schema-12 exact-domain isolation, schema-11 sentinel migration/reopen and pointwise maximum, 4,095/4,096/4,097 publisher boundaries with atomic ordinary/bridge rejection, and the explicit A-to-B-to-C non-transitivity trace |
| V-CLASS | reducers | State projection, Event gaps, Record siblings/merge, canonical Blob manifest/chunks and local streaming |
| V-MERKLE | exact anti-entropy | typed 33-byte ObjectIDs, 66-nibble tree roots, probe traces, equal-root wire-descent short circuit with local snapshot accounting, adversarial prefixes, and 100,000/cap-plus-one snapshot behavior for SQLite and custom stores |
| V-FRAG | carrier segments | every supported MTU, order, duplicate, truncation, overlap, bounds |
| V-IP | IP control bytes | discovery proof vectors and nonce freshness; rendezvous token echo/address forms, TTL, source, and capacity rejection; local endpoint-handle collision and non-authorization tests |
| V-EXT | evolution | optional skip/preserve and critical rejection |
| V-FFI | ABI | layouts, ownership, panic containment, repeated lifecycle, invalid pointers/lengths, atomic batch result ordering/rollback, and finalized-Blob writer batches |

## Acceptance scenarios

| ID | Scenario | Pass condition |
|---|---|---|
| A-01 | BTLE then IP | publish over simulated/physical BTLE, disconnect, consume remaining transfer over IP; one ItemID delivered |
| A-02 | 30-day partition | durable items converge after virtual 30 days; expired items do not transmit |
| A-03 | concurrent Record | all heads retained and annotated, or exact registered merge view; no input disappears |
| A-04 | relay path | producer and consumer lack direct path; ciphertext relay delivers; relay key cannot decrypt content |
| A-05 | constrained link | at 3 kbps and seeded 50% loss, higher priority begins first; no expired frame reaches link |
| A-06 | emission | threshold suppresses lower lanes without discarding them; ReceiveOnly/PassiveOnly behavior matches declared physical mode |
| A-07 | revocation/rekey | after control arrival, revoked handshake fails and fresh epoch is unreadable with revoked keys |
| A-08 | NAT | direct UDP path forms through test cone NAT; restrictive case uses separately deployed opaque relay |
| A-09 | capture confidentiality | payload/topic/scope/priority/publisher canaries absent from all carrier captures |
| A-10 | independent implementation | separately authored SUT passes the same corpus against the reference |
| A-11 | blob resume | 100+ MB stream interrupts mid-block set and resumes with another peer without whole-blob RAM growth |
| A-12 | broadcast | one physical advertisement satisfies at least two listeners; duplicate/NACK repair remains bounded |

## Implemented reliability and resource subgates

The authenticated in-memory runtime has a deterministic monotonic retry loop,
not merely initial-send scheduling. One test uses an MTU of 96 bytes, seeded
approximately 50% frame loss in both directions, the forced loss of an entire
changed SUMMARY transfer, and a fragmented 4 KiB DATA record. It converges,
commits exactly once, re-acknowledges a duplicate after a lost Receipt, and
retires the sender's DATA retry. Separate tests verify priority-ordered retry
deadlines, adapter retry floors, causal retirement of retained protocol work,
and return to no runtime wakeup after convergence.

Resource tests saturate the shared 16 MiB pending-logical budget and the 128
retry/128 one-shot entry limits, verify higher-priority replacement of lower
expendable retries, retain durable WANT progress through compact deferred
metadata, and reject hostile maximum WANT-to-DATA fanout with explicit
backpressure. The bounded completed-transfer cache rejects one adapter-route
transfer identifier being reused for different authenticated logical bytes.

Focused inventory-selection regressions exercise the same bound at small test
sizes: the SQLite helper returns exactly the configured cap, requests only cap
plus one rows in its single metadata-only query, and rejects the extra row; the
generic node guard separately rejects an over-limit vector from a custom store.
The production bound is 100,000 metadata objects. Equal roots avoid subsequent
`PROBE` / `NODE` wire descent, but both peers still select and hash the local
snapshot. These tests therefore establish a ceiling and wire short circuit, not
difference-proportional local work. Because source descriptors are inserted
first into the composite inventory, a snapshot containing exactly 100,000
source descriptors leaves no capacity for Blob carrier ObjectIDs; fair or
reserved carrier allocation remains an open scheduling concern.

Schema-12 store regressions cover schema-11 frontier migration into the reserved
`('', '')` sentinel, reopen behavior, exact `(topic, origin scope)` isolation,
pointwise-max loading, and the 4,096-publisher effective-domain boundary. They
also prove that ordinary and authenticated bridge-source overflow rolls back
without accepted-dot or outbox residue, and that a received signed predecessor
vector does not expand the local publication frontier. The last property is a
trust containment rule, not evidence of complete causal propagation: the
A-to-B-to-C trace remains non-transitive, per-key/per-stream domains are absent,
and accepted-dot/Event ledgers plus aggregate frontier domains remain unbounded.
V-CAUSAL and production causality therefore remain incomplete.

These are reference-to-reference software subgates. They do not measure useful
throughput at 3 kbps, Tier-2 RSS or battery use, permanent/adversarial loss, a
live carrier, or physical hardware, and they do not satisfy A-05 or A-10 alone.

The reference also passes a cross-scope bridge software subgate. It verifies
semantic-version-2 authorization and wrapper authentication, selected-version-1
suppression, exact source and Blob dependencies in every arrival order,
multi-hop path continuity and loop rejection, dynamic filter/revocation/epoch
enforcement, monotonic custody, deterministic verified-path fallback, and
reference-counted quota/GC across restart. Direct and bridged arrival share one
ItemID/dot/Event reducer and durable subscription-acknowledgement ledger while
preserving distinct `origin_scope` and `current_scope` views. The Rust/C/Go/
Python surface uses move-only enrollment and opaque 32-byte durable handles.
This remains same-team reference evidence; it does not satisfy the independent
SUT, 1,000-node bridge-scale, packet-capture, or physical-carrier gates.

The core now passes a focused A-07 software subgate: a root-credentialed,
delegated-hybrid-signed chained ScopeEpoch format-1 control distributes freshly
generated route/topic keys in hybrid recipient packages; a captured omitted
node cannot open fresh content; route-only recipients cannot open content; and
tamper, fork, rollback,
out-of-order/reopen, and local-revocation cases do not install unauthorized keys.
This is not the complete black-box administration scenario: the public recipient
registry still needs an independently persisted generation high-water mark after
authority-store replacement, and complete public-registry import/management is
not shipped even though high-level rekey calls exist. Format `0`
pre-provisioning is not evidence for A-07.

The core also passes focused delegated-authority software regressions. They
verify that `ASTRPB03` contains no authority-root signing seed, separately
provisioned ControlAuthority nodes have distinct signing identities, and the
provider rejects legacy root-signed control shapes, missing roles, credential
substitution, and signature tamper. Store tests persist the authenticated signer,
reject a signer/reservation mismatch, apply revocation in contiguous chain
order, reject and remove a revoked signer's pending dependent suffix, and let a
different live signer reissue that suffix on the same stable authority chain.
The bridge path separately checks format-2 delegated authentication, signer
persistence, revoked-signer suffix rejection, and loss of liveness after signer
revocation. Schema-10 stores with existing ordinary or bridge controls fail
closed rather than assigning those rows an inferred signer.

These same-team unit/integration regressions are not a distributed authority
protocol. They do not prove concurrent-writer consensus, automated signer
rotation, root override, total-history recovery, or rollback resistance after
complete control-store replacement. Those would require the separately
specified root-signed epoch/cutover and external chain high-water described in
[security.md](security.md).

The core passes complementary A-11 software subgates. A generated 101 MiB local
streaming case interrupts/reopens, deduplicates, reads back, and rejects tamper
with component buffers no larger than 65,552 bytes. A smaller carrier forces a
durable partial range, drops the first session, reopens SQLite and Blob state
with a brand-new driver and sync reducer, authenticates a different route-only
serving peer, requests exactly the missing complement, retires staging,
finalizes, and recovers identical plaintext. Its adversarial branch accepts a
corrupt range from authenticated producer A under a genuine ObjectID, reaches a
terminal carrier-authentication failure, transactionally clears only that
object's durable and reducer progress, reopens with no poison, issues the
canonical unknown-length/full request to a different honest route-only relay B,
and recovers identical plaintext. Separate regressions prove hostile Blob and
source partials cannot evict a committed Routine item, reducer reset clears
total/ranges/forwarding, and the high-level/FFI path rejects the same manifest
under a wrong route root or chunk count. The targeted cases pass. The combined
100+ MiB different-peer run with measured process RSS and a physical live
carrier remains pending.

A-12 remains failed: the adapter/BTLE simulation exposes a broadcast primitive,
but there is no protected broadcast replication capsule or implemented
suppression, repair aggregation, and loop-bounding protocol. The Rust host can
pump a configured link, but no concrete physical BTLE controller is shipped.

The reference passes A-09's handshake subgate: a runtime capture test reassembles
all four tiny-MTU flights and finds neither peer's mission, credential,
credential body, NodeID, nor route-grant commitment canaries. Full A-09 still
requires captures covering source, custody, protected replication, and each
physical carrier. It excludes correlation already available from
link/network/rendezvous identifiers before the first Aster flight and does not
assert traffic-flow confidentiality.

## Durability and fault scenarios

- Kill/reopen before and after each publish transaction boundary.
- Disk full during envelope, outbox, blob block, manifest, and receipt commit.
- Corrupt ciphertext, index row, block digest, and partial bitmap.
- Counter-store rollback and same-dot/different-content equivocation.
- Unclean reboot with finite TTL and no trustworthy persistent time.
- Tombstone just inside/outside configured retention.
- Quota pressure proving protected control/tombstone reservations.

## Property tests

```text
apply(x, x) = apply(x)
project(a, b) = project(b, a)
join(join(a, b), c) = join(a, join(b, c))
publication_frontier(topic, scope) = pointwise_max(exact_direct_dots, legacy_sentinel)
an accepted signed predecessor claim does not become local direct observation
an inventory snapshot has at most 100000 objects or selection fails without truncation
equal Merkle roots imply no wire descent, not no local snapshot construction
no concurrent head disappears without a dominating explicit revision
eventually connected replicas with the same retention policy converge
fragment/reassembly is invariant to MTU, duplicate, and arrival order
compact batch bytes remain private and semantically unapplied until their exact proof authenticates
selected-v1 inventory and resume expose neither batch proofs nor compact representations
staged source-envelope and Blob-carrier progress survives peer/session change unless terminal whole-object authentication resets only that ObjectID
verified content Blob chunk progress never decreases across process restart
direct and bridged representations of one ItemID share one semantic acceptance and acknowledgement ledger
no active bridge path bypasses its exact authorization/source dependencies after reopen or fallback
eviction never removes a currently protected class
unauthenticated staging exhaustion never evicts a committed item
```

## Fuzz corpus

Targets: deterministic decoder, every fixed object in `envelope.md`, source
envelopes, controls, custody wrappers, handshakes, protected frames, fragments,
overlapping ranges, Merkle probes, dotted contexts, bridge filters, store
authorizations/wrappers/path dependencies, store recovery, and FFI call
sequences.

Seeds include duplicate keys; nonminimum integers; indefinite/oversized/deep
objects; truncated tags/signatures; wrong inclusion proofs; inconsistent fragment
overlap; TTL underflow; old epochs; replayed session counters; malformed public
keys; same-dot/different-item; route-root/chunk-count substitution; poisoned
partial restart; staging exhaustion; zero-length and maximum-length blobs.
Batch seeds additionally include semantic-v1/format-2 downgrade substitution,
mixed batch fields, counter/Event range overflow, reordered leaves, wrong empty
padding, short/long/reordered paths, proof-ID and BatchID substitution, missing
proof, ciphertext length/hash mutation, malformed opaque signature lengths, and
bare compact items that must remain pending.

## Resource gates

On each Tier-2 target, record stripped library/sample binary size; peak and
steady RSS at 10,000 metadata items; single-core convergence CPU; idle wakeups;
3 kbps/50% loss useful delivery; 100-node scope simulation; and 1,000-node
bridged simulation. Blob tests demonstrate constant-memory streaming. Draft target
failure blocks an MVP claim or requires stakeholder-approved target revision.

## Hardware gates

Simulation is not hardware acceptance. BTLE release evidence requires two
physical controllers/devices, negotiated small MTU, disconnect/reconnect, GATT
fallback, and L2CAP where supported. NAT evidence requires controlled cone and
restrictive NAT/firewall topologies. RF emission claims require platform capture.
