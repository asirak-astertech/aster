# PR 110 Review Remediation Design

Date: 2026-10-21

Status: approved design, pending implementation plan

Supersedes the split-authority parts of:

- `docs/superpowers/specs/2026-10-19-aster-data-mesh-streaming-dag-design.md`
- `docs/superpowers/specs/2026-10-20-blob-operator-ux-design.md`

The pipeline, transport-adapter, progress, status, CLI, and operator-workflow
decisions in those designs remain in force unless this document changes them
explicitly.

## Purpose and claim boundary

PR 110 adds semantic-v9/profile-5 Blob streaming, but its current implementation
creates a second semantic Blob publication authority beside the established
Blob publication, subscription, lifecycle, capacity, and compatibility store.
That split causes the reviewed compatibility, security, causal, recovery, and
resource failures.

This remediation makes profile 5 a bounded, checkpointed transport pipeline
over the existing canonical Blob authority. There will be one semantic Blob
publication model and one durable authority regardless of whether profile 4 or
profile 5 moves its bytes.

The resulting increment must preserve:

- peer-independent local publication;
- semantic-v7/v8 profile-4 wire compatibility;
- upgraded-node access to every existing canonical Blob;
- highest-common-version interoperability between v9 and v7/v8 nodes;
- existing Blob subscriptions, retirement, pressure, quota, and read policy;
- receiver-authoritative network resume;
- bounded memory independent of Blob size; and
- transport-neutral operation so a later ordered reliable adapter such as BTLE
  can use the same pipeline.

This remains evaluation-stage work. It does not add download resume, route-only
Blob custody, peer/convergence status, cross-transport failover within one
attempt, a BTLE implementation, production qualification, or release
authorization.

## Rejected alternatives

### Patch two semantic stores

Keeping `BLOB_STREAM_PUBLICATIONS` as a second publication authority would
require permanent bidirectional projection for subscriptions, lifecycle,
capacity, pressure, causality, reads, and profile-4 compatibility. Atomicity
would cross two representations, completed content would be charged twice or
not at all, and every future Blob feature would need two implementations. This
does not provide a stable correctness boundary.

### Introduce another protocol version

Moving the correction to a later semantic version would leave the unmerged v9
profile internally inconsistent and would not make PR 110 mergeable. Profile 5
is still a draft and may be corrected together with its vectors and normative
specification.

## Architecture

### 1. One canonical semantic Blob authority

The existing Blob publication tables, exact source envelope, manifest, depot,
accepted-dot/frontier authority, acceptance order, subscriptions, lifecycle,
pressure policy, and configured capacity limits remain the sole semantic Blob
authority.

Profile-5 code may retain durable provisional upload and transfer checkpoints,
but those rows are not publications and are never independently readable,
subscribable, enumerable as content, or eligible for network inventory.
`BLOB_STREAM_PUBLICATIONS`, `BLOB_STREAM_VARIANTS`, and the raw shared
`BLOB_STREAM_OPERATIONS` mapping cease to be semantic authorities.

An available publication has exactly one canonical source identity and exactly
one acceptance marker, independent of the transport profile that delivered it.
Promotion must use the existing canonical Blob commit path and atomically
update its accepted dot, causal frontier, operation result, acceptance order,
subscription visibility, lifecycle indexes, and capacity accounting.

### 2. Canonical chunks are the profile-5 map units

Profile 5 transports the source-authenticated canonical Blob representation
already used by profile 4. A profile-5 data extent is a bounded batch of
complete canonical encrypted chunk records, not a second 1-MiB semantic segment
format.

The application and network pipelines use the same stages:

1. admit an authenticated publication or upload reservation;
2. partition into canonical chunk records;
3. map encrypt/verify work across a bounded worker pool;
4. reorder by canonical chunk index;
5. append to canonical depot staging;
6. synchronize data and journal state;
7. project one durable checkpoint; and
8. promote through the canonical Blob transaction.

The transport batch target remains a performance policy. The normative record
defines separate limits for plaintext chunk bytes, encoded canonical chunk
bytes, and the batched profile-5 extent. Implementations may negotiate a
smaller extent or checkpoint batch without changing Blob identity.

The selected implementation initially batches enough canonical chunks to stay
within the current approximately 1-MiB extent ceiling and caps one checkpoint
batch at 128 MiB. Exact constants and encoded overhead are generated from the
canonical chunk codec rather than duplicated in prose.

### 3. Local application upload

`OpenPublishStream` creates or restores a durable provisional upload keyed by
an owner-qualified application operation identity:

```text
(publisher NodeId, operation_key bytes)
```

The reservation persists the immutable request, authenticated publisher,
topic, scope, priority, TTL option, media/schema metadata, declared length,
policy/epoch binding, and exact durable staging checkpoint. Reopening the same
operation restores those bytes; it never reconstructs a new authority from
current state. A conflicting request fails without changing the reservation.

Opening an upload does not allocate a semantic publisher counter or causal
context. Those values are allocated only when all canonical chunks are durable
and final promotion can commit atomically. Therefore a long upload cannot lose
its counter to an unrelated State, Event, Record, or Blob publication, cannot
make later publications depend on an uncommitted dot, and cannot leave a causal
hole when abandoned.

Finalization creates the canonical signed Blob source and commits through the
existing idempotent operation path. Exact retries return the original result.
Cancellation or process loss retains only the bounded provisional upload and
its capacity charge; reopening resumes from its durable canonical chunk
checkpoint.

### 4. Network profile-5 transfer

Profile-5 inventory is derived from canonical Blob publications selected by
the existing topic/scope/epoch, lifecycle, policy, and peer-interest rules.
Consequently every pre-PR canonical Blob is automatically eligible between
upgraded nodes.

`StreamOpenV1` binds:

- the exact authenticated canonical Blob source identity;
- direction and session transcript;
- a fresh attempt nonce;
- total canonical transfer bytes and chunk count;
- receiver-authoritative durable checkpoint generation; and
- the authenticated finite-custody evidence required by the selected semantic
  version.

Network transfers do not use application operation keys. Their durable identity
is the canonical source publication plus the receiving mission/store authority.
Independent publishers using the same application operation bytes therefore
cannot collide at a receiver.

The receiver stages and verifies canonical chunk records through the existing
Blob depot and pending-source authority. A checkpoint becomes visible only
after the depot data and its restart journal are synchronized and the store
projection commits. Final promotion uses the same canonical transaction as
profile 4.

For v9-to-v7/v8 contact, semantic negotiation selects the lower version and
profile 4 moves the same canonical publication. For v9-to-v9 contact, profile 5
moves it. No conversion, dual publication, or content duplication is required.
An active profile-5 attempt is never downgraded in place.

### 5. Resume and terminal settlement

`StreamAcceptV1` returns the receiver's exact durable canonical chunk and byte
checkpoint. The sender starts strictly at that boundary.

If the accepted durable offset already equals the declared transfer length,
the sender sends `StreamFinishV1` immediately. It does not wait for a checkpoint
that can only be emitted after new data. The receiver validates the terminal
commitment against its durable canonical staging and proceeds to promotion and
result settlement.

All other attempts emit cumulative checkpoints after durable progress. A
disconnect after any checkpoint may replay only the uncheckpointed suffix.
Attempt nonces remain fresh; publication and Blob identity remain unchanged.

### 6. Finite lifetime and receiver-local custody

Profile 5 reuses the established authenticated finite-Blob custody model rather
than comparing local clock identities with the publisher's original clock.
The sender authenticates the accumulated lower-bound age and continuity facts
required by the selected version. On acceptance, the receiver anchors that age
to its own custody continuity and persists receiver-local lifecycle state.

Reads, forwarding eligibility, maintenance, and retirement project age from the
receiver-local checkpoint. A different device clock identity is expected and
is not itself expiry. Unknown or discontinuous age remains conservative and
fails closed according to the existing Blob custody rules.

### 7. Authorization and cached reads

Every stream-originated publication becomes an ordinary canonical Blob and uses
the established read plan. Before each nonempty plaintext page is released,
including pages from a cached reader, the actor must freshly check:

- current policy generation;
- current content epoch;
- reader route/content grants;
- publisher nonrevocation; and
- finite lifecycle state.

Revocation, rekey, retirement, shutdown, or terminal zeroization clears the
cached reader and releases no additional plaintext. Unauthorized and absent
content retain the existing sanitized public error boundary.

### 8. Unified capacity and cleanup

Provisional application uploads, pending network receipts, and completed
canonical variants all participate in the configured Blob depot byte, chunk,
variant, and staging limits. There is no independent hard-coded 16-GiB stream
pool.

Reservation accounts for the bounded worst-case canonical staged bytes before
admission. Promotion changes ownership of the same charge rather than removing
it. Abort, retirement, and reclamation release capacity only through the
existing restart-safe lifecycle and physical cleanup protocol.

Capacity status reports the unified counters. A completed profile-5 transfer
must remain charged until its canonical variant is legitimately reclaimed.

### 9. Subscription and public API behavior

Canonical promotion allocates the existing Blob acceptance order and therefore
makes a profile-5-arrived publication visible to existing matching Blob
subscriptions. Poll, attempt rotation, acknowledgement, retirement delivery,
and delivery status use the existing exact-publication ledger unchanged.

The agent and `asterctl` APIs introduced by PR 95 keep their request and output
contracts. Streaming remains an implementation of bounded application I/O, not
a second semantic API. Publication status is projected from the provisional
upload, canonical pending-source, canonical publication, and retained
retirement authorities by exact publication identity.

### 10. Transport abstraction and cancellation

Profile-5 framing, attempt coordination, checkpointing, and ordered pipeline
processing depend only on `StreamTransportAdapter`. Iroh remains the first
adapter. No store or semantic type imports Iroh endpoint, QUIC, IP, or MTU
types.

On transport, framing, verification, durability, lifecycle, or sink failure,
the pipeline stops admission, closes its channels, signals cancellation, joins
every active map worker, drops plaintext buffers, and only then returns. Tests
must establish that at least one worker is active before injecting failure and
must observe that the worker exits before the operation completes.

## Persistence and migration

Canonical databases created before PR 110 retain every Blob and require no
content migration. The writable schema migration adds only provisional upload
and profile-5 checkpoint authority and its audit/accounting indexes.

PR 110 has not shipped or been deployed. Its split stream-publication schema is
experimental and has no compatibility promise. Writable open may remove empty
experimental tables. A database containing nonempty experimental stream-only
publications fails closed with a specific unsupported-development-schema error;
it is never silently discarded or guessed into canonical authority. Test and
development users must export through the reviewed API before changing builds
or reset that unqualified state.

Read-only inspection never mutates or partially migrates a schema. Migration is
atomic and idempotent, and audit rejects partial authority, orphan checkpoints,
unaccounted staging, duplicate owner-qualified operations, or capacity totals
that differ from live state.

## Wire and compatibility contract

Semantic v7/v8 profile 4 remains byte-for-byte unchanged. Semantic v9/profile 5
is updated before merge together with its protocol prose, CDDL, construction
oracle, vectors, decoder, hostile-input bounds, and negotiation tests.

The v9 Blob profile registry explicitly lists profile 5, while the v7/v8 rules
explicitly list profile 4. The highest common semantic version determines the
corresponding exact Blob profile. Unknown critical profile, record, or extent
forms fail closed.

The normative profile-5 limits distinguish:

- canonical plaintext chunk size;
- maximum encoded canonical chunk record;
- maximum batched data extent;
- maximum protected data header;
- maximum checkpoint batch; and
- maximum attempt data/control allocations.

The implementation constants and conformance checks are the executable source
for the numeric values copied into documentation.

## Test design

Every corrected defect receives a deterministic regression that is observed
failing before implementation.

### Store and application tests

- Two publishers may use identical application operation bytes without a
  receiver collision.
- Two simultaneous local uploads plus an unrelated data-class publication
  finalize with unique causal dots and exact retry results.
- Restart restores the exact upload reservation, policy binding, TTL metadata,
  staging checkpoint, and operation ownership.
- Revocation between read pages prevents the next plaintext page, including
  with a cached reader.
- A finite Blob transferred between different clock identities remains readable
  until receiver-local accumulated age reaches TTL and is then retired.
- Profile-5 promotion appears once in an existing Blob subscription and uses
  normal acknowledgement and retirement behavior.
- Provisional, pending, and completed profile-5 bytes remain charged under the
  configured Blob capacity limit across promotion, restart, abort, and cleanup.

### Network and compatibility tests

- A canonical Blob created by the pre-profile-5 API transfers between two v9
  nodes through profile 5.
- A Blob published through the streaming agent transfers over profile 4 in a
  v9-to-v8 contact and over profile 5 in a later v9-to-v9 contact.
- A retry accepted at total durable length sends Finish without waiting for a
  new checkpoint and settles exactly once.
- Partial checkpoints resume on a different eligible peer/adapter instance
  without replaying the durable prefix.
- Real store and API inspection survive a small-MTU adapter interruption and a
  different-adapter resume; tests do not manufacture status snapshots.
- Transport failure is injected only after an active verification worker is
  observed, and return is blocked until that worker exits.

### Fuzz and hostile-input tests

`stream_transfer_decode` is included in `tools/run-fuzz-smoke.sh` with its own
temporary corpus and artifact directory. Every checked-in seed is an actual
encoded profile-5 wire record, or uses the shared explicit `HEX:` corpus format
and is decoded by the harness before the target. Marker strings and accidental
trailing newlines are not structured seeds.

Fuzz smoke covers truncated and oversized batch headers, chunk count/length
overflow, malformed canonical chunk records, attempt binding, checkpoint
rollback, terminal replay, and trailing bytes.

### Verification boundary

Focused store, application, runtime, transport, agent, CLI, protocol-contract,
and documentation tests run after their respective changes. Final verification
includes formatting, strict Clippy, the serial repository test suite, Cargo
lockfile checks, implementation-requirement checks when evidence text changes,
and the bounded fuzz-smoke lane. CM4 performance revalidation follows only
after local correctness gates are green and uses the existing three-device
profile without changing installed production services.

## Documentation corrections

The protocol, roadmap, selected Blob API guide, engineering runbook, performance
record, operator guide, and CLI documentation must describe the unified
authority and its exact claim boundary.

In particular:

- profile 5 appears in the negotiated profile registry;
- v7/v8 profile-4 rules are separate from v9 profile-5 rules;
- plaintext chunk, encoded chunk, and batched extent limits are distinct;
- the normative checkpoint maximum is 128 MiB;
- local publication progress is distinguished from peer/convergence status;
- agent/CLI Blob publication and read are described as current capabilities;
- legacy canonical Blobs remain eligible through profile 5 after upgrade; and
- capacity examples use the configured unified Blob limits rather than the
  removed provisional stream pool.

Historical performance receipts remain historical and keep their original
commit and environment boundaries. New validation must not relabel an earlier
measurement as evidence for the remediated implementation.

## Review-finding traceability

The report's 17 findings are acceptance requirements, not optional follow-up
work:

| Finding | Required disposition |
| --- | --- |
| F1, revoked publisher readability | Revalidate publisher, epoch, grants, and lifecycle before every plaintext page, including cached reads. |
| F2, publication-counter collision | Allocate the semantic counter only in the atomic canonical finalization transaction; provisional uploads retain no counter. |
| F3, final-checkpoint deadlock | Send Finish immediately when the accepted durable offset is already the declared total. |
| F4, cross-device finite TTL | Import authenticated age into receiver-local custody continuity and use the established lifecycle authority. |
| F5, restart reconstruction | Restore the exact durable reservation and immutable request rather than signing a replacement open. |
| F6, operation-key collision | Qualify application operations by publisher and keep network receipt identity separate. |
| R1, old and new Blob synchronization | Derive both profiles from the one canonical publication authority. |
| R2, subscription regression | Promote through the canonical acceptance-order and subscription transaction. |
| R3, storage-budget bypass | Charge provisional, pending, and completed bytes to the configured unified Blob limits. |
| T1, omitted fuzz campaign | Add `stream_transfer_decode` to the CI fuzz-smoke campaign. |
| T2, invalid fuzz seeds | Store valid encoded records or explicitly decoded hexadecimal fixtures. |
| T3, manufactured integration status | Exercise the real store/API and transport-adapter boundary. |
| T4, unproved worker cancellation | Gate failure on an observed active worker and require its exit before return. |
| D1, conflicting transfer-piece limits | Specify plaintext chunk, encoded chunk-record, and batched-extent limits separately. |
| D2, checkpoint-limit mismatch | Make 128 MiB the single normative maximum and test the executable constant. |
| D3, missing profile-5 negotiation | Register v9/profile 5 while preserving the exact v7/v8/profile-4 rules. |
| D4, stale roadmap capability wording | Describe agent/CLI local publication progress separately from peer/convergence status and retain maturity labels. |

## Completion criteria

The remediation is complete only when:

1. every report finding has a focused regression or documentation assertion;
2. there is one canonical semantic Blob publication authority;
3. existing canonical Blobs synchronize between upgraded v9 nodes;
4. new agent/CLI publications remain available through v7/v8 profile 4;
5. subscriptions, lifecycle, revocation, causality, and configured capacity
   behave identically regardless of transfer profile;
6. restart and fully checkpointed resume settle without reconstruction or
   timeout;
7. fuzz CI runs valid profile-5 records;
8. normative documentation matches executable limits and negotiation; and
9. focused and repository gates pass before CM4 performance evidence is
   collected.
