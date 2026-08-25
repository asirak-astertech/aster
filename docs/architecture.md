# Selected production-lane architecture

This page depicts the bounded control/Event composition that executes today.
It is intentionally narrower than Aster's complete protocol and semantic
reference implementation. The live selected Event API provides publish,
bounded query, durable subscribe/poll/ack, idempotent unsubscribe, authenticated
gap inspection, and bounded peer/last-contact status through the running node's
sole actor. The stopped-state handle provides the same data operations when no
runtime owns the store. State, Record, Blob, atomic subscription update,
finite-TTL custody, protected operational provisioning, additional carriers,
generalized control administration, and release authorization remain outside
this selected lane.

## Components and trust boundaries

```mermaid
flowchart LR
    Operator["Same-UID Unix operator"]
    Authority["Stopped authority CLI"]
    Application["Application"]
    LiveHandle["SelectedEventHandle<br/>publish · query · subscribe · poll · ack<br/>unsubscribe · gaps · status"]
    StoppedApp["Stopped SelectedEventNode<br/>same Event data operations<br/>without live status"]
    BuiltIns["Built-in roles<br/>Ping · Pong · relay"]
    Artifacts["Retained mission bundle<br/>and carrier identity"]

    subgraph Local["Selected aster-node composition"]
        Node["aster-node<br/>ordering and lifecycle"]
        Core["aster-core control/source providers<br/>authority · publisher · protected headers"]
        Session["aster-core mission session<br/>four-flight hybrid authentication"]
        Profile["aster-profile<br/>canonical exact-ID ordering"]
        Diff["aster-negentropy<br/>set difference only"]
        Store["aster-redb-store<br/>durable acceptance/effect authority<br/>Consume/Carry selectors + delivery ledger"]
        Carrier["aster-iroh<br/>direct authenticated carrier"]
    end

    Peer["Peer aster-node<br/>independent identity and store"]

    Application --> LiveHandle -->|"bounded commands"| Node
    Node -->|"sanitized results"| LiveHandle
    BuiltIns -. "run inside actor" .-> Node
    StoppedApp -->|"exclusive stopped-state operations"| Store
    Store -->|"bounded structural candidates and durable receipts"| StoppedApp
    StoppedApp -->|"fresh source/content verification"| Core
    Authority -->|"control input"| Node
    Node -->|"uses control/source providers"| Core
    Node -->|"uses canonical ordering"| Profile
    Node -->|"reconciles exact-ID sets"| Diff
    Node -->|"commits accepted state"| Store
    Node -->|"runs mission session"| Session --> Carrier <--> Peer
    Operator -. "local zeroize" .-> Node
    Artifacts -. "exact retained files" .-> Node
```

`aster-node` is the sole composition root. `aster-iroh` authenticates only the
carrier endpoint and provides bounded direct exchange. The mission `NodeId` is
independent from the Iroh `EndpointId`. `aster-negentropy` computes exact-ID set
difference; it does not transfer objects, establish causality, or make policy.
`aster-redb-store` is the selected durable authority for accepted Events,
ordered control effects, policy/selector snapshots, at-least-once application
delivery, route-only representations, and the terminal zeroization marker.

The live handle does not open a second store. It sends commands over a bounded
channel to the actor that already owns the mission-bound writer. Commands that
insert or remove selectors take the actor's policy write lease; other
application operations and contacts use a policy read lease. Shutdown or
zeroization closes admission and rejects queued commands before the authority
is released. The stopped handle can acquire that authority only after the live
actor has exited.

## Live application command and status flow

```mermaid
sequenceDiagram
    participant A as Application
    participant H as SelectedEventHandle
    participant N as RunningNode actor
    participant L as Policy lease
    participant S as Mission-bound redb
    participant C as Contact task

    A->>H: high-level Event operation
    H->>N: bounded command + one-shot reply
    alt subscribe or unsubscribe
        N->>L: acquire write lease
        N->>S: atomically update selector generation and delivery ledger
        S-->>N: durable selector receipt
    else publish
        N->>L: acquire read lease
        N->>N: validate request and source-seal Event
        N->>S: policy-bound idempotent commit
        S-->>N: durable publication result
    else query, poll, or gaps
        N->>L: acquire read lease
        N->>S: request bounded structural candidates or plan
        S-->>N: untrusted candidate page or plan
        N->>N: freshly verify source; verify content for returned data
        N->>S: recheck exact poll/gap plan when applicable
    else acknowledge or status
        N->>L: acquire read lease
        N->>S: check current policy, delivery ledger, or selector snapshot
        S-->>N: durable acknowledgement or local policy state
    end
    N-->>H: sanitized application result
    H-->>A: typed result

    C->>N: completed authenticated contact receipt
    N->>N: record peer, bounded remainder, and exact contact policy
    A->>H: status()
    H->>N: status command
    N->>S: current control and selector policy
    N-->>H: local last-contact snapshot
    H-->>A: typed status
    Note over A,N: LastContactComplete is not global convergence
```

Gap results follow the same trust rule. The store prepares a bounded structural
plan, the selected node freshly verifies every observed source position, and
the store rechecks the exact policy-bound plan before a half-open gap interval
is exposed. Absence of a returned gap says only that the locally observed,
verified positions in that page are contiguous; it is not publisher
completeness or mesh convergence.

## One authenticated contact

```mermaid
sequenceDiagram
    participant L as Local node
    participant C as Direct Iroh carrier
    participant P as Peer node
    participant S as redb store

    L->>C: exact EndpointId + direct address
    C->>P: authenticated carrier connection
    L->>P: hybrid mission flights 1 and 3
    P->>L: hybrid mission flights 2 and 4
    Note over L,P: independently verify exact mission NodeId
    L->>P: control reconciliation query
    P->>L: source-authenticated control suffix
    L->>S: commit and activate contiguous control prefix
    L->>S: atomically capture policy + selector generation
    L->>P: protected canonical receive interest
    P->>L: protected canonical receive interest
    Note over L,P: empty interest means receive-none
    L->>P: reconcile IDs in peer-receiver universe
    P->>L: independently authorize peer-receiver difference
    L->>P: offer only peer-selected, peer-routable bytes
    P->>L: reconcile IDs in local-receiver universe
    L->>P: independently authorize local-receiver difference
    P->>L: local fetches only locally selected, locally routable bytes
    alt content grant
        L->>S: verify source + admit semantic Event
        L->>L: application reaction may run
    else route-only grant
        L->>S: retain bounded exact bytes only
        Note over L,S: no content open or semantic Event row
    end
```

The ordering is security-relevant: mission authentication precedes inventory;
control reconciliation and durable activation precede protected interest or
Event inventory; each receiver gets an independent filtered reconciliation
universe; and content admission is separate from forwarding authority. Receive
intent never grants access: current source, epoch, revocation, and route policy
are rechecked at inventory, transfer, and commit boundaries.

## Identity and authorization are deliberately separate

| Layer | Proves or decides | Does not imply |
|---|---|---|
| Carrier | Exact direct Iroh endpoint | Mission membership or data access |
| Mission | Hybrid-session possession of the expected mission `NodeId` | Control authority, source authorship, route, or content grant |
| Control | Ordered authority/delegation chain and policy effect | Event source identity or plaintext access |
| Event source | Publisher and protected semantic header | Permission for every peer to route or read it |
| Receive selector | Membership-visible topic/scope intent inside the protected mission session; empty means receive-none | Route or content authority, Event-ID disclosure, or scope-private subscription metadata |
| Route policy | Whether an exact representation may be advertised/carried | Content decryption or semantic admission |
| Content policy | Whether protected bytes may become a semantic Event | Authority to alter source identity or control state |

## Bounded terminal zeroization

```mermaid
stateDiagram-v2
    [*] --> Live
    Live --> CleanupPending: preflight exact unique files<br/>drain/close/drop secret holders<br/>commit durable intent
    CleanupPending --> MissionDestroyed: overwrite + fsync + truncate<br/>mission file descriptor
    MissionDestroyed --> IdentityDestroyed: overwrite + fsync + truncate<br/>carrier-key file descriptor
    IdentityDestroyed --> Complete: durable final receipt
    CleanupPending --> CleanupPending: crash retry on unchanged inode
    MissionDestroyed --> MissionDestroyed: crash retry on unchanged inode
    IdentityDestroyed --> IdentityDestroyed: crash retry on unchanged inode
```

Every non-`Live` phase denies normal opens. Terminal-safe inspection and data
rows remain available. The same-UID Unix operator may enter through owner-only
live IPC or a stopped exclusive-writer path; there is no carrier or mission-
control trigger. Pathnames remain as zero-length tombstones. Physical media,
copy-on-write history, snapshots, swap, backups, database rollback/replacement,
and non-Unix behavior are outside the proof.

## Follow the evidence

- [Capability tour](quickstart/capability-tour.md) — fastest visible behavior.
- [Selected Event API](quickstart/selected-event-api.md) — live publish/query,
  durable delivery, gaps, unsubscribe, and bounded status.
- [Carriers and contacts](transports.md) — selected and migration-source carrier boundaries.
- [Mesh CLI guide](quickstart/mesh-cli.md) — phase-by-phase and retained receipts.
- [Requirements status](implementation/requirements-status.md) — exact credited rows and open gaps.
- [Security model](security.md) — production gates and explicit non-claims.
