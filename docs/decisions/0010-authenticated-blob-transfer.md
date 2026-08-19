# Decision 0010: Source-bound encrypted Blob carriers

- Status: accepted for reference
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
source envelopes already admitted by Decisions 0001–0006. No new dependency or
external implementation input was introduced.
