# Security Architecture and Threat Model

- Version: 0.1.0
- Status: reference design; production security and integration gates unsatisfied

## Assets and adversary

Protected assets are item plaintext, protected routing metadata, publisher
authenticity, causal history, authorization state, key epochs, provisioning
artifacts, identity/routing/content seeds, backups containing those values, and
availability within declared quotas. The adversary may observe, drop, delay,
duplicate, reorder, replay, modify, and inject traffic on every carrier; run an
untrusted rendezvous/relay; capture old packets; later possess a revoked device;
or obtain a copied local artifact, backup, crash dump, or accidentally committed
file.

The design does not hide protocol presence, timing, packet size, direction, or RF
energy. It cannot stop an authorized reader from disclosing plaintext, a routing
member from observing protected metadata it is entitled to decrypt, or a captured
device from reading data for which it already obtained keys.

## Trust boundaries

```text
provisioning authority
  -> offline authority-root hybrid key signs node credentials and roles
  -> unique ControlAuthority identity keys append delegated controls
  -> one mission control chain keyed by the stable authority root identifier
  -> independent scope routing grants
  -> independent topic/readership content grants

source item
  -> source AES-GCM content encryption
  -> ECDSA + ML-DSA singleton authentication, or exact batch proof + item path
  -> scope routing wrapper
  -> optional authorized target-scope wrapper preserving the source carrier
  -> pairwise protected session
  -> untrusted IP/BTLE/rendezvous/relay carrier
```

The adapter API has a broadcast capability bit, but no complete protected
broadcast replication capsule or repair protocol is implemented.

Relays are not content readers by default. The implemented semantic-version-2
bridge similarly limits a bridge to rule-specific endpoint routing grants and
an authority-signed directed-edge authorization. It rewraps the exact immutable
format-2 source carrier without content access, preserves the source signature
and origin scope, and exposes a distinct authenticated current scope. A target
reader still needs the exact origin scope/topic/content-epoch grant; target
membership, bridge authority, and target content grants cannot substitute for
it. The remaining cross-implementation and physical acceptance gates are in
[conformance.md](conformance.md).

The exact protected bytes, signature messages, KDF inputs, and bounds are
normative in [envelope.md](envelope.md).

## Provisioning artifact and persistent-key custody

`ASTRPB03` is a checksum-protected plaintext inner representation containing
secret material. Separate `ProvisioningProtector` and
`ProvisioningUnprotector` interfaces keep authority-side recipient encryption
apart from node-side identity/private-key decryption. Each top-level protect or
open operation completes local, size, and magic prechecks first: failure makes
zero provider calls, while passing all prechecks makes exactly one protector or
unprotector attempt. Aster neither retries nor falls back internally; a caller
may explicitly start a new operation. The recovered plaintext is bounded to
125,877 bytes and held in a redacted non-cloneable container whose owned
allocation is zeroized on explicit erase and drop.
Protected artifacts are bounded to one MiB. Provider errors retain only safe
typed categories, and failure cannot fall back to interpreting the artifact as
plaintext.

The interface does not itself guarantee encryption. In addition to behavioral
test providers, the repository ships an isolated `aster-provisioning-age` pilot
using exactly pinned Rust `age` 0.11.5 with `default-features = false`. The
configuration accepts only 1–16 classic X25519 recipients or identities; it
does not expose passphrases, SSH identities, plugins, tagged hardware
recipients, or any post-quantum recipient profile. Its
streaming path remains inside Aster's outer and recovered-plaintext bounds and
must authenticate through EOF before plaintext can be returned. A narrow
`age-core` custom-identity wrapper examines age's parsed stanza metadata and
requires 1–16 X25519 stanzas, rejects scrypt and more than one extension stanza,
and does so before attempting any identity unwrap. This bounds peer-controlled
work without implementing a second file parser.

Standard age adds one mandatory GREASE/unknown stanza to non-scrypt files. The
parser does not label it separately, so the wrapper permits one non-scrypt
unknown stanza and cannot prove that it is GREASE rather than another meaningful
extension recipient. The provider never executes or loads such an extension,
and decryption still requires a matching X25519 stanza, but strict byte-level
X25519/GREASE-only classification remains an upstream-API residual.

Memory clearing is best-effort and specifically bounded. The provider clears
the plaintext/ciphertext buffers owned by its Aster wrapper and returns no
partial plaintext after authentication failure. Rust `age` 0.11.5 does not
comprehensively zeroize its internal plaintext encryption buffer or every
intermediate created while decoding an X25519 identity. No claim extends to
those upstream temporaries, allocator/compiler copies, crash dumps, swap, or
complete process-memory erasure. This residual is separate from successful
ciphertext authentication and is another production-review gate.

This is an experimental Rust-only provider, not an operational default. Rust
`age` describes pre-1.0 releases as beta software for testing and its repository
has no detected security-policy file. The plugin feature is disabled, and
0.11.5 includes the plugin-execution fix first released in 0.11.1 for
`GHSA-4fg7-vxc8-qx5w`. Bidirectional interoperability with exact
reference Go age v1.3.1 is a required batch gate, not a mesh-interoperability or
security-audit claim. [Decision 0018](decisions/0018-age-provisioning-provider.md)
records the dependency graph, sources, exception, and exit gates.

The pilot graph also contains build-time `proc-macro-error2` 2.0.1 through
`i18n-embed-fl` 0.9.4. RustSec `RUSTSEC-2026-0173` marks it unmaintained and
lists no patched release; the advisory is informational and reports no
vulnerability. Current Rust separately reports future-incompatibility `E0365`.
The exact advisory is ignored by dependency policy only for this bounded pilot,
with locked checksums and offline validation after dependency acquisition. It
is not a reported runtime vulnerability, but build-time code can influence the
produced binary. It therefore remains an unresolved supply-chain and
compiler-lifecycle risk and independently prohibits production admission.

The profile is X25519 and ChaCha20-Poly1305 based. It provides no post-quantum
artifact-confidentiality or FIPS 140-3 validation claim. The raw
`ApplicationNode::open`, `MeshService::open`, FFI, Go, and Python paths remain
unprotected compatibility/test ingestion. The current host also retains a
zeroizing plaintext bundle copy in process so it can rebuild its backend after
a paused contact.

Persistent custody after ingestion is a separate `SecretStore` problem. A
production backend needs opaque seal/load/destroy handles, platform or hardware
key policy, unattended-start decisions, recovery and backup procedures,
rollback handling, and verified failure behavior. Neither successful provider
destruction nor software zeroization proves physical flash erasure. This model
does not defend secrets against a fully compromised running process or root,
unlocked-memory inspection, swap, DMA, backups, or crash dumps unless the
selected platform and deployment add those controls.

## Mandatory controls

- Canonical ordered semantic-version and complete-suite offers, with selection
  bound into the transcript, KDF, key confirmations, and hybrid authentication;
  there is no algorithm-by-algorithm mixing. The stable framing/profile remains
  `1`, the default semantic offer is `[2, 1]`, and profile 1 has one registered
  complete suite.
- Both classical and PQ signatures verify; failure is indistinguishable on wire.
- A compact semantic-version-2 batch item is never authenticated by its P-256
  suffix alone: the exact proof credential, authority hybrid signature, source
  hybrid root signature, ciphertext commitment, Merkle path, and item signature
  must all verify. Missing proof means bounded pending state, never delivery.
- Durable partial-transfer progress preserves its first-admission semantic
  version. Unknown provenance fails closed, and v2-only objects cannot be
  resumed or served through a selected-v1 session after restart.
- Hybrid ephemeral establishment, transcript binding, explicit key confirmation,
  direction/purpose labels, and no 0-RTT data.
- Anonymous mission proof before responder P-256/ML-KEM work; responder and
  initiator credential contexts protected under hybrid-derived keys.
- AES-GCM keys/nonces are purpose separated; a key/nonce pair is never reused.
- Session replay windows, ItemID idempotency, publisher counters, control-chain
  sequence/hash, and key epochs reject replay as new work.
- `ASTRPB03` field bundles never contain the authority-root signing seed.
  Format-2 controls require a root-signed ControlAuthority credential and the
  delegated identity's hybrid signature; signer identity is persisted and
  checked against the applied revocation state before activation.
- Decode bounds precede allocation. Malformed input cannot panic the safe core.
- Adapter endpoint handles are routing-only local hints; only the authenticated
  session NodeID may authorize peer state, grants, inventory, or DATA.
- Local discovery requires a fresh receiver challenge cryptographically bound to
  the announcement and response role, then locally matched to the apparent
  source socket, before an address becomes a candidate. All discovery packets
  are strict, zero-padded 64-byte records, so a response does not amplify the
  request by payload or ordinary IP/UDP wire size. Discovery does not register a
  DATA route or authenticate a peer.
- UDP DATA from an unregistered source socket is dropped before route
  construction or core delivery. One receive poll processes at most 64
  datagrams before yielding, so ignored traffic cannot monopolize one host pump
  call. Manual provisioning or an explicit embedding decision must register a
  discovery/rendezvous candidate first.
- Adapter routes remain untrusted local routing hints after registration. A
  configured or fully authenticated route is exact, including anonymous versus
  routed delivery; a mismatch is discarded before fragment decoding and neither
  rebinds nor tears down the contact. Before an unknown route is authenticated,
  each of at most 16 incomplete transfers retains its own exact route, so
  cross-route fragments cannot assemble together and one incomplete fragment
  cannot globally pin the contact. Partial route and reassembly state idle for
  ten minutes is evicted together. A successfully verified logical handshake
  flight establishes the candidate route used for the next reply; full session
  authentication commits it. Malformed or inconsistent fragments, conflicting
  completed transfer identifiers, route mismatches, and records that fail
  session authentication are discardable carrier input. One runtime pump
  handles at most 64 such failures before yielding. Authorization and peer state
  derive only from the cryptographically authenticated session identity.
- The runtime handshake receive path validates against the current
  cryptographic state without consuming that state until the flight succeeds. A
  forged or malformed ServerHello, ClientAuth, or ServerFinished is discarded
  while the exact prior state and its bounded retained outbound flight remain
  available for retransmission. `MeshService` retains one zeroizing in-process
  canonical bundle copy for backend rebuilds; the runtime creates no additional
  serialized or persistent recovery copy. Failures after record
  authentication--including wire, synchronization, backend, and internal
  contract errors--remain fatal to the containing contact rather than being
  hidden as carrier noise.
- A Blob source signature binds BlobID, chunk count, and route Merkle root.
  Route-only relays accept `ASTRBT01` carriers only after ciphertext hash,
  source-envelope association, and bounded Merkle-proof verification; readers
  additionally require the protected manifest record and content AEAD. The
  high-level and FFI deduplication/read path re-inspects the sealed source
  envelope and rejects a mismatched route root or chunk count even when BlobID
  and manifest bytes match.
- Unauthenticated partial state is peer-neutral but has per-object and global
  byte/count/extent limits in an isolated staging partition.
- Plaintext payload is not written to the protocol store; blobs stream.
- Secrets use best-effort memory zeroization and platform key-destruction hooks.

## Key access matrix

| Role | Session | Routing | Content | Publish | Bridge | Authority |
|---|---:|---:|---:|---:|---:|---:|
| consumer | yes | joined scopes | granted groups | optional | no | no |
| relay | yes | carried scopes | no by default | no | no | no |
| bridge | yes | authorized edge endpoints | no by default | no source authorship | explicit directed edges | no |
| publisher | yes | origin scopes | required groups | explicit | no | no |
| authority | policy | policy | fresh recipient packages or legacy activation | control records | grants | yes |

Holding one scope or content seed cannot derive another. Parent/child scope names
do not imply key access.

## Authority custody and control continuity

The authority-root signing key remains in the provisioning helper and signs
credentials and the administrative recipient registry. It is not copied into
`ASTRPB03` bundles. Each fielded ControlAuthority receives a unique node identity
seed and a root-signed credential carrying the ControlAuthority role. Ordinary
and scope-epoch controls embed that credential and are signed by the delegated
identity over `ASTRCA02` format-2 bytes. Bridge authorization format `2` uses the
parallel `ASTRBCA2` delegated authentication wrapper. Capturing one authority
node therefore permits forgery as that delegated signer until its revocation is
applied, but it does not reveal the root signing key or the private keys of other
delegated signers.

Both ordinary and bridge stores persist the authenticated signer. Ordinary
controls share one chain head keyed by stable `authority_id`; bridge
authorizations use their own semantic-v2 chain, also keyed by that stable root
identifier. Neither creates a per-signer history. A signer revoked in the
contiguous applied prefix cannot contribute another link. If activation reaches
a staged link signed by an identity revoked earlier in that prefix, the
implementation rejects and removes that link and its entire unapplied dependent
suffix; a live signer must recreate the suffix from the last applied head.
Bridge authorization liveness additionally requires current-process
reauthentication, the applied enabled generation high-water, and no revocation
of the authority root identifier, delegated signer, or bridge identity.

Revocation of the stable `authority_id` is intentionally terminal. The
authority-revocation record itself may apply as the final contiguous ordinary
link while the authority is still live. In that same transaction, every
ordinary and bridge chain is purged from its earliest unapplied row belonging to
that authority, and affected active bridge routes and queued route work are
removed. Subsequent publish reservation, ordinary admission/activation, and
bridge admission/activation reject when either the stable authority or the
delegated signer is revoked. There is no root override, sequence reset, or
in-band recovery after stable-authority revocation in this version.

These chains are single-writer authenticated logs, not consensus. Safe rotation
requires external coordination: provision the replacement signer, give it the
trusted exact current sequence/envelope head, stop the former writer, and append
the handoff/revocation without a concurrent claim. A second valid signer can
recover after loss or compromise only if it knows that exact head. Concurrent
valid signers can create a fork at the same sequence, which fails closed. The
offline root has no implemented in-band override. Total history loss, deliberate
fork replacement, or recovery without a trusted head requires a separately
specified root-signed control epoch and an externally retained chain high-water;
those mechanisms and an operator recovery workflow remain production gates.

Schema 11 adds signer attribution. Migration from schema 10 succeeds only when
both legacy control tables are empty. If either contains rows, open fails closed
with an explicit migration-required error pending a signed cutover/import design
or a fresh store; the implementation will not infer a signer for old controls.

## Revocation meaning

A root-credentialed, delegated-hybrid-signed monotonic control record propagates
through normal durable sync at FLASH priority. After contiguous application, an
honest node rejects the identity. ScopeEpoch
format `1` distributes a fresh route key and fresh topic keys only to one through
128 named recipients. Each recipient package combines a fresh P-256 ECDH share
and ML-KEM-768 encapsulation, binds the full control-chain and package-set
context, and conceals a random per-recipient salt used by the visible topic-grant
commitment. A recipient installs only its matching authenticated package; an
omitted or locally revoked node removes any pre-placed key for that scope/epoch
and installs nothing. Package authentication and decapsulation complete before
that mutation, and only a durably applied control activates. The signed
recipient set also authorizes routing for the new epoch. Route-only recipients
receive no content keys. Exact bytes and bounds are in
[envelope.md](envelope.md) §6.

The signed public recipient registry is an administrative artifact, not a mesh
object. An authority restart preserves append-only behavior after importing it,
but rollback detection after complete authority-store replacement additionally
requires an operator-held registry-generation high-water mark. High-level
application and language-binding rekey calls exist, but public-registry import/
management does not yet constitute a full administration workflow. Legacy
ScopeEpoch format `0` still activates a pre-provisioned key and
does not provide capture exclusion. Disconnected nodes cannot enforce a
revocation they have not received, and no rekey can erase an old captured key or
plaintext. A captured holder of the old common control-route key can observe
format-1 package metadata, recipient identifiers, and sizes. Salted grant
commitments prevent that omitted holder from testing topic dictionaries, and
the hybrid recipient package withholds the fresh epoch keys.

## Causal evidence and bounded state

Schema 12 scopes publication frontiers to exact `(topic, origin scope)` domains.
Only an accepted item's own dot advances the local frontier; its signed
predecessor vector is not imported as local observation. This is a deliberate
trust boundary: source authentication identifies the publisher of a causal
claim but cannot prove that the publisher truthfully or completely observed the
claimed predecessors.

Each domain loads the pointwise maximum of its exact rows and the reserved
SQLite-only legacy sentinel `('', '')`. Empty topic and scope names are invalid
on the protocol, so admitted data cannot occupy that sentinel. Schema-11
node-global observations migrate verbatim into the sentinel, which is then
read-only under normal acceptance. The exact-plus-sentinel union is capped at
4,096 distinct publishers per domain, and a new publisher at the boundary fails
the same transaction that would accept the item. The aggregate number of
domains and frontier rows is not bounded.

This bounds cross-scope pollution but does not establish transitive causality.
For example, after A publishes `A1`, B observes it and publishes `B1`, and C
receives only `B1`, C's next publication includes B's directly observed dot but
not A's dot. Later `A1` can appear concurrent with C's item. The node-global
accepted-dot ledger and the publisher/topic/scope Event-sequence ledger still
survive normal garbage collection, are outside item quota, and have no aggregate
bound or pruning protocol. Per-key or per-stream domains, transitive propagation
with safe trust semantics, and bounded authenticated retirement/checkpointing
remain production security and availability gates. No minimum-context clamp is
claimed or implemented.

## Availability controls

Inventory roots are constant size and exact tree descent is bounded. Control
records, current epochs, and retained tombstone fences have reserved quota.
Priority does not bypass authentication or bounds. An INTEREST is rejected
before backend work if it exceeds 256 topics, 256 scopes, or 4,096
topic-by-scope combinations. An admitted filter causes one metadata-only
inventory query, not a Cartesian series of store queries, and does not
materialize sealed payload or causal/application fields into the Rust
projection. The policy-filtered source snapshot has a 100,000-object ceiling.
SQLite stops at cap plus one and rejects the selection if that row exists; the
generic node facade also rejects an over-limit result from a custom store. Equal
Merkle roots prevent further wire descent but do not avoid this local selection
and hashing step, so local reconciliation work is snapshot-size proportional,
not difference proportional.

For a selected root containing no more than both peers' OFFER limits (256 by
default), the sender can return the complete canonical identifier set. The
receiver requires the current expected root probe, exact advertised count, and
a reconstructed Merkle root equal to the authenticated `SUMMARY` before it
creates wants or retires traversal state. A bounded history recognizes exact
delayed authenticated responses as no-ops; malformed or mismatched responses do
not retire the probe retry. This removes deep wire traversal for small
snapshots, not the O(k) identifier validation or O(N) local snapshot build.
Larger snapshots retain the 66-level exact tree path.

Discovery holds at most 128 recent local announcements, 256 pending challenges,
and 1,024 emitted-response records; each class is pruned at 30 seconds before
lookup or reuse. Pending records use `(exact source socket, announcement)` and
retain a fresh challenge; only a matching response from that socket consumes the
record. Emitted responses use `(exact source socket, announcement, challenge)`.
A replay from another socket therefore cannot collide with or directly consume
the legitimate socket's exact record. Pending and emitted-response admission is
additionally limited to 8 and 32 records, respectively, per canonical source
IP; IPv4 and its IPv4-mapped IPv6 form share one quota. This contains
source-port churn while preserving the global 256/1,024 bounds, but distributed
replay can fill those shared caches and delay legitimate discovery until the
30-second expiry; large shared-NAT populations also contend for the same
per-source limits. It blocks passive replay redirection but not an active,
bidirectional live relay of the challenge and response; only the subsequent
hybrid handshake authenticates the peer.

Advertisement, challenge, and response packets are all strict, zero-padded
64-byte records, so reflected discovery traffic does not exceed the inducing
packet by payload size or ordinary IPv4/IPv6 UDP wire size. Equal sizing does not
prove source ownership. A captured valid announcement—or an announcement made
by a discovery-token holder—with a spoofed source can still consume that
apparent victim's bounded per-source pending quota and the global quota. Public
or hostile-link deployments require source anti-spoofing and ingress rate
controls.

Rendezvous rejects a zero pairing token. Client attempts are bounded at 128,
expire after 120 seconds, and bind the expected server per token. A server peer
response is consumed once; only its selected endpoint may then present the
corresponding punch, except for an endpoint explicitly authorized with
`accept_punch`. Failed registration sends restore prior client state. The server
examines at most 64 datagrams per poll, retains at most 4,096 waiting tokens and
64 per canonical source IP, and maintains those source counts incrementally.
The absolute 120-second waiting lifetime cannot be refreshed by duplicate
registration. Registration is a strict 160-byte packet with 127 zero padding
bytes; the prior 33- and 64-byte forms fail closed. Under a conservative
48-byte IPv6 UDP/IP-header model, the 208-byte registration wire cost exceeds
the largest 181-byte reflected response-plus-punch chain: a 52-byte IPv6 peer
response and 33-byte punch, each with a 48-byte header.

Before sending either reply, the server atomically reserves their exact
combined payload size from one global 4,096-byte bucket refilling at 1,024 bytes
per second and from a 1,024-byte bucket refilling at 256 bytes per second for
each distinct canonical source IP. Endpoints sharing one canonical IP charge
that source once; different sources each pay the full pair. Source-budget state
is capped at 4,096 entries and expires after 120 idle seconds. Missing state is
created only after every required bucket can pay. A denied reservation spends
nothing; a send failure conservatively spends the reservation but preserves
waiting and source-count invariants for retry. These controls bound state,
per-poll work, repeated completed-pair egress, and one canonical source's share
without byte amplification. Shared-NAT clients share a budget. Rotating spoofed
source IPs can still fill the finite source-budget table, and these controls do
not prove a UDP source address was not spoofed; public exposure still requires
deployment anti-spoofing and rate controls. The visible high-entropy token
remains a capability, not peer authentication.

The TCP ciphertext relay defaults to 256 active pairs, 64 accepted sockets per
source IP across validation/waiting/active states, and a 120-second active-pair
idle timeout reset by actual I/O. Client queues are independently bounded in
both directions at 256 frames and 4 MiB. `send` only performs nonblocking local
queue admission; saturation returns `WouldBlock`, while asynchronous write
failure closes the link and makes later sends fail. One pair whose endpoints
share a public NAT normally consumes two source admissions. Operators can raise
that limit for large shared NATs, trading away some per-source denial-of-service
containment while retaining the global active-pair bound. Inbound clients must
complete a four-byte frame header within 120 seconds. A body gets 30 seconds
plus its encoded length at 1,024 bits per second, or 542 seconds for the maximum
65,535-byte frame; expiry closes the link and releases its bounded queue state.
Zero or monotonic-clock-unrepresentable active-pair idle durations fail
configuration, and runtime deadline construction is checked.

These relay bounds are containment, not complete slow-client resistance. Any
successful byte transfer resets the active idle timer, so coordinated sources
can retain the finite global slots by sending periodic traffic; a healthy pair
that is completely quiet for the configured interval is also disconnected and
must be re-established by its embedding. Deployment-layer source controls and
reconnection policy remain release gates.

A stateless pre-response cookie format is not implemented, so amplification
resistance for the large PQ response remains a deployment/release gate.
Discovery and rendezvous rate limits
belong to their carrier profiles and are not provided by the fixed handshake.
The mission proof prevents a party without mission material from creating a new
accepted flight 1, but a captured valid flight 1 remains replayable and can
trigger a fresh bounded response. On an unknown responder it can also pin that
session's candidate adapter route even though flight 1 does not establish the
initiator's full peer identity; rate limiting and contact replacement are still
required.

The reference gives unauthenticated staging a nominal 25% partition of
`max_bytes`, capped at 64 MiB, and reserves the remainder for committed records.
It admits at most 4 MiB per staged object, `min(max_items, 10,000)` staged
objects, 4,095 extents per object, and 65,536 extents globally. Staging
exhaustion rejects the new extent without evicting either prior staging or a
committed item. Thus an authenticated or unauthenticated sender can deny its own
new partial admission but cannot use staged bytes to force committed-data
priority eviction.

Terminal full-object length, identity, source-authentication, ciphertext, route,
or policy failure atomically purges only the offending typed ObjectID and resets
its WANT to unknown length/no ranges. Transient Store, I/O, and missing-chunk
failures retain progress. This distinction prevents a malicious first peer from
persistently poisoning a later honest peer's same-object recovery without using
transient local failures as a staging-erasure oracle.

The runtime retains a failed backend range for another attempt and implements a
bounded monotonic retransmission loop with priority deadlines, causal retirement,
and adapter retry floors. The Rust application host owns and pumps configured
link instances and wakes the runtime on local inventory change. Current tests
use controlled in-memory links; they do not establish general congestion-control
behavior, permanent-loss progress, a concrete BTLE controller, or a physical
live-carrier path.

Flight 1 proves possession of a shared mission proof key anonymously; it is not
a per-credential revocation check. A captured or revoked node that retains that
key can create fresh flight-1 ephemerals, derive the hybrid secret, and decrypt
the responder identity in flight 2. Its own revoked credential is rejected after
encrypted flight 3/backend authorization, and no DATA is accepted. Rejecting a
revoked client before revealing protected flight 2 would require a
per-credential protected flight-1 identifier/proof or rotation of the shared
mission proof key. This residual authorized-member exposure is distinct from the
solved passive-observer credential leak.

## Mesh cryptographic provider status

The reference provider uses `aes-gcm`, `hkdf`, `sha2`, `p256`, `ml-kem`, and
`ml-dsa` at the exact registered versions. This proves neither independent audit
nor FIPS 140-3 validation. The public API cannot select primitives; an internal
provider boundary allows a CMVP-backed module.

Production is blocked until deployment assurance identifies a current CMVP
certificate, exact module/version/operational environment and approved mode,
coverage for all suite operations, self-tests, and an independently reviewed
hybrid combiner.

## Security test gates

Listing a production gate is not evidence that it has passed. Independent NIST
algorithm-vector validation remains required; the checked-in, reference-generated
protocol conformance vectors do not satisfy that gate.

- Bit-level tamper of every envelope/handshake field.
- signature stripping and classical/PQ downgrade attempts.
- direct mutation of an honestly selected semantic `2` to offered semantic `1`;
  the initiator must reject even though membership checks alone would accept it.
- malformed public keys/ciphertexts and implicit-rejection behavior.
- nonce uniqueness across concurrency, crash, rollback, and epoch change.
- replay windows and old control/key epochs.
- packet-capture canary scan for payload and routing fields.
- relay/bridge negative decryption tests.
- The repository ships `wire_decode`, `fragment_decode`, and
  `envelope_inspect` fuzz targets plus allocation-limit tests; an FFI fuzz target
  remains a production gate.
- Aster-owned zeroization hook invocation and post-zeroize handle rejection;
  this does not assert clearing of upstream age internals.
- age-provider ordinary/binary/maximum-size and real-bundle round trips;
  one-to-sixteen recipient/identity bounds, duplicate rejection, sanitized
  configuration errors, redacted secret debug output, and multi-recipient
  recovery; incoming no-X25519, over-16-X25519, scrypt, and multiple-extension
  stanza-set rejection before identity unwrap while accepting standard GREASE;
  wrong-identity, malformed-header,
  stanza/header-MAC/body/final-byte, truncation, and trailing-data rejection;
  bounded output and recovered
  plaintext; randomized ciphertext; and failure without partial plaintext
  release.
- bidirectional outer-file interoperability with exact reference Go age v1.3.1;
  this checks only the classic X25519 age file profile.
- dependency-policy confirmation that the sole ignored advisory is the
  pilot-scoped informational `RUSTSEC-2026-0173`, with no additional advisory
  or vulnerability exception.

The semantic-version tamper gate proves only on-path transcript downgrade
resistance. Client offers are mission-proof bound; honest responder selections
are transcript/KDF/confirmation/authentication bound. The handshake has no
authenticated responder capability ceiling, authority-signed mission minimum,
or durable per-identity semantic high-water. Consequently, a valid older or
modified responder can authenticate semantic `1`. Downgrade-sensitive
production authorization MUST fail closed until the signed floor, high-water,
explicit rollback authorization, and independently authored mixed-version
validation exist.

Packet-capture success means protected payload, topic, scope, priority, and
publisher credential canaries are absent from Aster carrier bytes. It does not
claim resistance to correlation by link/network identifiers established before
the first Aster flight—including IP addresses and a rendezvous pairing token
visible to the rendezvous service—nor does it hide timing, direction, sizes, RF
energy, or protocol presence. Local discovery sends a fresh nonce and truncated
HKDF proof, never the provisioned discovery token itself. Its subsequent
challenge and response are also truncated token-derived proofs; they establish
live reachability at the apparent socket, not identity or resistance to an
active real-time relay.

The reference now has a passing runtime capture subtest that reassembles all
four tiny-MTU handshake flights and verifies that neither peer's mission,
credential, credential body, NodeID, nor route-grant commitments occur in the
clear. This satisfies the handshake portion of the capture gate, not the broader
physical-carrier traffic-analysis boundary.

The canonical batch codec, provider authentication, and explicit atomic
source/store/application path reduce the transferred verification closure for a
semantic-version-2 batch. The default retained-dual policy preserves v1
compatibility at extra signing/storage cost; explicit batch-only cannot reach a
selected-v1 peer. Reference peer proof-first, compact-first pending/restart,
v1-rejection, and Blob-carrier tests pass; the required 3 kbps end-to-end
measurement, physical-carrier validation, and an independent SUT remain open.
Recipient-excluding rekey is implemented in the core fixed profile, with the
external registry high-water and missing administration workflow limitations
above. Typed Blob-carrier relay and different-peer ranged resume are verified in
the in-memory reference runtime, while a separate 101 MiB local streaming case
passes with bounded component buffers. A combined 100+ MiB different-peer run
with measured process RSS and physical live-carrier validation remains open. See
[envelope.md](envelope.md) §§5.4, 6, and 10.

Report vulnerabilities through the private process in `.github/SECURITY.md`.
Do not include mission data or credentials in a public issue.
