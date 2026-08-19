# Security Architecture and Threat Model

- Version: 0.1.0
- Status: reference design; production crypto gate unsatisfied

## Assets and adversary

Protected assets are item plaintext, protected routing metadata, publisher
authenticity, causal history, authorization state, key epochs, and availability
within declared quotas. The adversary may observe, drop, delay, duplicate,
reorder, replay, modify, and inject traffic on every carrier; run an untrusted
rendezvous/relay; capture old packets; and later possess a revoked device.

The design does not hide protocol presence, timing, packet size, direction, or RF
energy. It cannot stop an authorized reader from disclosing plaintext, a routing
member from observing protected metadata it is entitled to decrypt, or a captured
device from reading data for which it already obtained keys.

## Trust boundaries

```text
provisioning authority
  -> dual-key node credential and roles
  -> mission control chain
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
- Decode bounds precede allocation. Malformed input cannot panic the safe core.
- Adapter endpoint handles are routing-only local hints; only the authenticated
  session NodeID may authorize peer state, grants, inventory, or DATA.
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

## Revocation meaning

A dual-signed monotonic control record propagates through normal durable sync at
FLASH priority. After receipt, an honest node rejects the identity. ScopeEpoch
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

## Availability controls

Inventory roots are constant size and exact tree descent is bounded. Control
records, current epochs, and retained tombstone fences have reserved quota.
Priority does not bypass authentication or bounds. A stateless pre-response
cookie format is not implemented, so amplification resistance for the large PQ
response remains a deployment/release gate. Discovery and rendezvous rate limits
belong to their carrier profiles and are not provided by the fixed handshake.
The mission proof prevents a party without mission material from creating a new
accepted flight 1, but a captured valid flight 1 remains replayable and can
trigger a fresh bounded response; rate limiting is still required.

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

## Provider status

The reference provider uses `aes-gcm`, `hkdf`, `sha2`, `p256`, `ml-kem`, and
`ml-dsa` at the exact registered versions. This proves neither independent audit
nor FIPS 140-3 validation. The public API cannot select primitives; an internal
provider boundary allows a CMVP-backed module.

Production is blocked until deployment assurance identifies a current CMVP
certificate, exact module/version/operational environment and approved mode,
coverage for all suite operations, self-tests, and an independently reviewed
hybrid combiner.

## Security test gates

- NIST algorithm vectors plus protocol golden vectors.
- Bit-level tamper of every envelope/handshake field.
- signature stripping and classical/PQ downgrade attempts.
- direct mutation of an honestly selected semantic `2` to offered semantic `1`;
  the initiator must reject even though membership checks alone would accept it.
- malformed public keys/ciphertexts and implicit-rejection behavior.
- nonce uniqueness across concurrency, crash, rollback, and epoch change.
- replay windows and old control/key epochs.
- packet-capture canary scan for payload and routing fields.
- relay/bridge negative decryption tests.
- decoder/fragment/FFI fuzzing and allocation limits.
- zeroization hook invocation and post-zeroize handle rejection.

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
HKDF proof, never the provisioned discovery token itself.

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
