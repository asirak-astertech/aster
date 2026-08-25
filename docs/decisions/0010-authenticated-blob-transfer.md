# Decision 0010: Source-bound encrypted Blob carriers

- Status: accepted for reference; stopped/local selected subset implemented
- Date: 2026-08-18

## Decision

Blob manifests remain ordinary source-encrypted and hybrid-signed items. Their
canonical protected header additionally commits to the BlobID, nonzero chunk
count, and a Merkle root over the ordered encrypted-chunk records. The header is
part of both ItemID semantics and the source-signature message.

Each network chunk is a bounded `ASTRBT01` carrier identified by a full 256-bit
typed ObjectID. It binds the source EnvelopeID, BlobID, index, ciphertext
SHA-256, ciphertext length, and canonical Merkle proof, followed by the
ciphertext. It intentionally omits plaintext digests. A route-authorized relay
can validate and retain the carrier without a content key. A content-authorized
consumer additionally requires the exact authenticated manifest record before
installing a reader-visible chunk.

Transfer staging records the complete 33-byte typed ObjectID and exact byte
ranges in the durable store. A completed staging object is retired only after
authenticated commit; accepted semantic and event replay ledgers remain
separate. Partial ranges are peer-neutral, so a new runtime and a different
authenticated peer can request only their complement.

## Consequences

- Source envelopes are the authorization root for advertising, serving, or
  accepting every Blob carrier; Blob DATA never carries a peer forwarding
  wrapper.
- Route-only relays cannot open the manifest or payload and content consumers
  reject a route-valid carrier that differs from the manifest's exact record.
- Merkle levels are built once and persisted under a bounded cache; carrier
  scans retain one bounded object at a time.
- Unauthenticated transfer staging is isolated from committed-record eviction:
  it receives at most one quarter of the total byte quota (capped at 64 MiB),
  4 MiB per typed object, 10,000 objects, 4,095 extents per object, and 65,536
  extents globally. Exhaustion rejects the new extent without evicting either
  staged or committed data.
- A terminal full-object identity, route, or source-authentication failure
  transactionally deletes only that typed staging object and resets the reducer
  to an unknown-length request. Transient storage, I/O, and missing-chunk
  failures retain progress for another contact.
- The current profile rejects zero-chunk Blobs, caps the manifest near 1 MiB
  (about 14,543 chunks), and caps a composite contact inventory at 100,000
  source-prioritized identifiers.
- Content-capable nodes retain both the forwarding carrier and canonical
  encrypted chunk, charged to quota; this favors store-and-forward availability
  over minimum disk amplification.

The design uses SHA-256, AES-GCM chunk records, and ordinary authenticated
source envelopes already admitted by Decisions 0001–0006. The local depot
owner token uses the workspace's existing pinned `getrandom` package through a
new direct store dependency; it adds no new third-party package/version or
external implementation input.

## Selected local implementation boundary

The selected stopped `SelectedBlobNode` implements the source-authenticated
manifest and encrypted-at-rest chunk boundary without yet implementing the
network carriers described above. Its profile fixes nonempty objects to 64-KiB
chunks and gives `BlobId` its exact meaning: the ID commits plaintext bytes,
canonical chunk profile, and media/schema identity metadata. It is not a
metadata-independent pure byte-content ID.

Signed publication bytes and operation authority live in the mission-bound
redb store. Ciphertext files live in a private sibling depot, partitioned by
Blob ID, content group, and epoch. A file becomes authoritative only after
write/sync/rename/directory-sync and an exact redb committed marker. The source
publication commits only after a private completion proof checks every
authenticated expected and committed manifest record plus the final manifest
digest. A marked missing or corrupt file fails closed; only unmarked remnants
may be reclaimed.

From its first successful Store open, redb persists a domain-separated binding
over a random owner token, canonical database path, and, on Unix, backing
device/inode. The fixed sibling depot’s private marker must carry that exact
binding before any chunk/variant scan or reclaim. The first database to
initialize a parent’s depot wins; a second cannot adopt it. Moving/copying even
an empty bound database to another path fails on reopen. On Unix, a new inode
also fails, moving the depot with the database does not preserve the binding,
and a same-path replacement cannot adopt an existing depot. This slice
deliberately has no supported rebind or backup-restore migration. Non-Unix
keeps the token/path binding but cannot distinguish a copied database restored
over the same path, so equivalent inode/rollback resistance is not claimed.
Legacy owner-token or binding migration is permitted only when the fields are
wholly absent, every Blob row/counter is canonical empty, and the fixed depot
root is absent; partial fields, any logical Blob state, or any fixed depot root
fail closed without repair.

The facade performs synchronous borrowed streaming, so no provider reader or
copied content key can outlive the exclusive stopped handle. Its redb read plan
is structural: every retained publication is freshly source/content verified,
the active deterministic source publication is recomputed, the exact plan is
rechecked, and only then is the selected depot completion verified and read.

Dedicated limits cover committed ciphertext-file bytes, durable chunk-metadata
rows, and import variants. Unfinished imports count against row/variant
admission until an explicit-GC policy is implemented. These limits do not claim
complete filesystem allocation accounting or physical sanitization. The
selected slice has no Blob frame, remote chunk request, any-peer resume, live
handle, subscription, carrier-neutral partial staging, or acceptance result;
the network portion of this decision remains a migration target.
