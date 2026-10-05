# Pipelined Durable Event Publication Design

## Status

Approved for implementation on 2026-10-04. This design is based on
`defenseunicorns/aster` main at `2dd022f9c6cb453b6cc22896aecfb3449270be88`.

## Outcome

Increase sustained local Event publication throughput without weakening the
existing offline-first contract: a successful publication result still means
the Event and its idempotency mapping are durable in the node's sole local
authority. Mesh reconciliation remains independent and asynchronous after
that local commit.

The increment combines:

1. opportunistic group commit for already-admitted ordinary `PublishEvent`
   commands; and
2. an additive bidirectional `PublishEvents` RPC so an HTTP/2 telemetry client
   can keep multiple publications in flight and receive one durable outcome
   per input Event.

Unary `PublishEvent` remains compatible. Concurrent unary callers use the same
group-commit path. Browsers, which cannot stream request bodies, retain unary
publication and can pipeline a bounded window of concurrent unary calls.

## Requirements and architectural fit

- `DM-7-16` requires disconnected publication to succeed locally and sync
  later. Publication success therefore stays behind local durable commit, not
  remote delivery.
- The local agent remains an adapter over `SelectedEventHandle`; it gains no
  second store, journal, reconciliation engine, or durable authority.
- The selected-node actor remains the sole mutable owner. It drains only work
  already present in its bounded application lane and never waits for a future
  Event to complete a group.
- The existing explicit cryptographic atomic batch is a different feature.
  Pipelined ordinary Events retain independent operation keys, validation,
  results, and failure outcomes and keep their existing singleton Event wire
  representation.
- This is a local application-protocol addition, not a mesh protocol or
  semantic-version change.

## Public API

Add this method to `AsterApplicationService`:

```proto
rpc PublishEvents(stream PublishEventsRequest)
    returns (stream PublishEventsResponse);
```

`PublishEventsRequest` wraps one unchanged `PublishEventRequest` publication;
the wrapper satisfies the schema naming contract without changing an Event or
its operation key.

Each response contains exactly one of:

- `published`: the existing `PublishEventResponse`, emitted only after its
  local transaction commits; or
- `failure`: one sanitized `PublicErrorDetail` for that input Event.

Responses preserve request order. A valid application-level failure does not
close the stream or poison later inputs. Authentication, malformed stream
framing, message-size enforcement, deadline expiry, or transport loss may
close the stream through the existing transport error contract.

The stream introduces no batch-size, page-size, wait-time, or rate field.
Existing request/message/deadline limits remain unchanged. In particular, the
agent still defaults a stream to 10 seconds and clamps a caller-supplied
deadline to 30 seconds. `PublishEvents` is therefore a sequence of bounded
stream sessions, not one immortal connection. The native SDK and validation
harness rotate a healthy session before the server cap. If a session closes,
the client reconnects and resubmits every sent-but-unanswered request with its
original operation key; durable duplicates resolve to their original result
and uncommitted requests execute normally. This recovery rule is part of the
public client contract and lets a 15--60 second telemetry run span several
sessions without weakening durability. The rotation interval is an
implementation detail, not a protocol field or data-rate limit.

Native HTTP/2 Connect/gRPC clients can use full duplex. Browser transports
cannot stream request bodies; gRPC-Web request-streaming is rejected and the
same Events remain publishable through a bounded window of concurrent unary
calls.

The stream is intentionally ordinary-publication only. Experimental numbered
publication keeps its existing recovery/session API and is not silently mixed
into this path.

## Actor scheduling and backpressure

The application channel remains bounded at 32 commands. One actor turn may
process at most the existing application fairness budget of eight commands.
These are implementation bounds already present in the runtime, not new
protocol constants.

When the pending command is an ordinary non-Flash Event publication, the actor
uses nonblocking reads to collect immediately adjacent ordinary non-Flash
publication commands up to the remaining fairness budget. It stops at the
first other command and retains that command for the next turn. It never skips
over query, State, Record, Blob, control, numbered-publication, or Flash work.

Flash publication remains singleton to avoid adding urgent-path latency.
Singleton publication never waits for another Event.

The RPC handler keeps only a bounded number of publish futures active. Awaiting
the actor's bounded sender and the ordered response stream propagates
backpressure to the client. A client that stops reading or sending cannot
create an unbounded server queue.

## Group construction

One actor group may contain multiple independent commit cohorts. The actor
first collects adjacent ordinary non-Flash commands without filtering them,
then splits that ordered group into contiguous cohorts. A cohort shares:

- publisher identity;
- topic and scope;
- the same settled control-policy snapshot; and
- durable custody or finite-TTL custody mode.

Priority and TTL values may differ inside a compatible cohort. Tombstones are
durable and therefore never enter a finite-TTL cohort. Any incompatible input
ends the current cohort without reordering inputs.

Before sealing, the store derives a contiguous set of optimistic reservations
from one read snapshot. The reservations simulate serialized publication:

- publisher counters advance once for every newly inserted Event;
- per-stream Event sequences advance contiguously;
- every later reservation observes the earlier reserved local dot; and
- reaction predecessors are resolved and added to the exact causal context.

Exact operation-key retries resolve to their original durable result and do
not consume new counters. Conflicting operation-key reuse fails only that
input.

The actor processes cohorts strictly in input order: maintain custody once for
the collected group, then prepare and commit one cohort before reserving the
next. Later reservations therefore observe the durable publisher frontier
created by earlier cohorts rather than becoming stale. Within one cohort,
identical repeated operation keys resolve once without consuming a second
counter or sequence; conflicting reuse fails only that input and ordered
fallback preserves valid siblings.

## Durable group commit

The store prepares every source-authenticated Event before opening the writer.
One immediate-durability redb transaction then applies a compatible cohort in
request order. Each staged Event performs the same policy, authorization,
namespace, causal, operation-ledger, quota, custody, and acceptance checks as
the current singleton path. The transaction updates the ordinary singleton
Event representation and existing reconciliation indexes; it does not create
the separate cryptographic batch representation.

The node runs one bounded `drive_custody_maintenance` pass before processing a
collected actor group, rather than once per Event on the successful group path.
This preserves the current expiry/quota/continuity maintenance boundary while
amortizing its committing garbage-collection transaction. Exceptional
singleton fallback reuses the already-completed group maintenance pass and
replays only the Event publication work through the singleton primitive. Its
diagnostics therefore count that one group maintenance pass plus every actual
fallback Event writer commit.

For each finite-TTL cohort, the node captures one fresh commit-adjacent custody
checkpoint and exact policy revision and passes both explicitly into the store
group-commit API. All members use that same checkpoint/revision. Continuity and
policy checks occur in the same writer boundary as the Events. The existing
terminal continuity/policy transition rules remain authoritative.

When one collected actor group contains several cohorts, each cohort is
prepared and committed before the next cohort is reserved. A group never holds
reservations for a later cohort across an earlier cohort's commit.

Results are released only after `write.commit()` succeeds. A process failure:

- before commit exposes none of the cohort; or
- after commit but before responses exposes all committed rows, recoverable by
  retrying the same operation keys.

No receipt ledger is added because the ordinary operation ledger already
provides exact retry resolution.

## Independent failures

Fast-path group failure rolls back the whole tentative transaction. The actor
then replays that cohort through the existing singleton path, in original
order, to isolate errors. Valid siblings can commit and invalid siblings return
their existing typed failures. This fallback preserves current observable
semantics at the cost of losing the performance benefit for an exceptional
cohort.

Policy/rekey/revocation changes linearize a successful cohort wholly before or
after one exact policy generation. Reservation change retries rebuild and
reseal the cohort from fresh durable state. Exhausted retry follows the current
typed failure path.

## Cancellation, shutdown, and zeroization

Once a request enters the actor channel, caller cancellation does not cancel
the durable operation. A disconnected stream may therefore lose a response;
the caller retries the same operation key and receives the exact committed
result.

Shutdown keeps the existing synchronous actor boundary. Once the actor starts
processing an ordinary publication, the whole adjacent group it collects in
that turn is the executing unit and may finish, including custody maintenance,
sealing, and its sequential cohort commits. Shutdown cannot interleave a
lifecycle check inside that synchronous unit. It closes further admission and
rejects commands left queued beyond the collected group; the lifecycle does
not promise to drain every command previously admitted to the bounded channel.
Forced shutdown and zeroization use the same no-early-success rule. No detached
publication worker owns the store outside the actor.

## Bounded diagnostics

The actor emits one structured `event_publication_group` diagnostic after each
collected group completes. Its bounded numeric fields are `group_sequence`,
`collected`, `cohorts`, `custody_writer_commits`, `event_writer_commits`,
`total_writer_commits`, `accepted_new`, `exact_retries`, `failures`,
`max_cohort_size`, and `singleton_fallbacks`. The sequence starts at one and
increases monotonically for one actor/service invocation. Refactored custody
collection outcomes report every committed maintenance transaction, including
a committed continuity/policy transition followed by retry; Event group and
singleton outcomes report their own commits. `total_writer_commits` is their
checked sum, not timing or an inferred request count.

Group size is bounded by the existing actor fairness budget, so this adds
neither per-Event log spam nor unbounded cardinality; no operation keys,
topics, publishers, payloads, or other sensitive identifiers are logged.
The record uses a dedicated bounded-diagnostic output path that remains enabled
under the customer agent's `CustomerSafe` node-output policy. Legacy node
receipts and errors remain suppressed by that policy.

Unit tests consume the same internal diagnostic value before it is formatted
as a log record. Device receipts pin one systemd invocation and journal cursor
range, verify an unbroken `group_sequence`, and reconcile the sum of `collected`
against every request frame sent by the otherwise-exclusive matrix client,
including reconnect replays. That reconciliation detects a missing first or
final record as well as a middle gap; an incomplete interval is rejected.
This instrumentation is an implementation diagnostic, not a public protocol
field or a durable correctness ledger.

## Validation

Correctness tests cover:

- singleton no-wait behavior and Flash singleton behavior;
- FIFO grouping and fairness around other application commands;
- serialized-equivalent counters, sequences, causal contexts, and reactions;
- exact retry, conflicting reuse, malformed input, and valid-sibling fallback;
- same-group identical and conflicting operation keys without extra counters;
- durable and finite-TTL cohorts, tombstones, expiry, continuity, quota,
  revocation, rekey, reservation retry, shutdown, cancellation, and restart;
- crash boundary: none before commit, exact retry after commit;
- bounded stream send/read backpressure and ordered per-input outcomes;
- native Connect and gRPC HTTP/2 stream interoperability, bounded-session
  reconnect with sent-but-unanswered operation-key replay, and browser
  gRPC-Web streaming rejection plus concurrent-unary fallback;
- exact bounded group diagnostics and receipt completeness; and
- unchanged numbered publication and explicit cryptographic batch behavior.

Performance validation reuses the established two-CM4 telemetry matrix at
`0.2`, `1`, `5`, `10`, and `50` Events/s/device for durable and finite-TTL
Events, after a resource/activity preflight. It records exact commits and
binaries and compares current DU main with the candidate for:

- unary concurrency one, for compatibility/no regression;
- a fixed concurrent-unary window, for isolated group-commit effect; and
- the pipelined stream, for the intended telemetry outcome.

Receipts include accepted, skipped, errors, exactly-once remote delivery,
publication and sync percentiles, CPU, RSS, commits per accepted Event, and
observed group sizes. No performance claim is made unless the pipelined path
materially increases accepted and delivered Events without correctness loss.

The completed [bounded two-CM4 comparison](../../validation/evidence/2026-10-05-pipelined-event-publication-cm4-validation.md)
meets that evidence shape for one exact baseline and candidate. It observes
more admitted and delivered Events only in saturated rows, no delivery loss,
and fewer writer commits when groups form. Mixed latency and synchronization
percentiles plus single-run normalized CPU results remain explicit boundaries
on any broader efficiency claim.

## Documentation and evidence boundary

Update the agent reference, Connect quickstart, protocol description, generated
descriptor/client checks, and capability/requirements descriptions only where
the implemented boundary genuinely changes. Device results remain engineering
evidence unless separately retained and accepted under the repository's
validation process. The PR must distinguish implementation correctness from
physical performance observations and release authorization.

Decision 0012 is amended alongside this feature to clarify that an ordinary
publish remains immediate when it never waits for future work: atomically
grouping only already-admitted commands is an internal transaction optimization
and does not create the explicit cryptographic batch representation or silently
buffer a publish for later submission.
