# Selected production-lane architecture

This page depicts the bounded control/Event composition that executes today.
It is intentionally narrower than Aster's complete protocol and semantic
reference implementation. State, Record, Blob, generalized applications and
subscriptions, finite-TTL custody, protected operational provisioning,
additional carriers, and release authorization remain outside this selected
lane.

## Components and trust boundaries

```mermaid
flowchart LR
    Operator["Same-UID Unix operator"]
    Authority["Stopped authority CLI"]
    App["Built-in Event application"]
    Artifacts["Retained mission bundle<br/>and carrier identity"]

    subgraph Local["Selected aster-node composition"]
        Node["aster-node<br/>ordering and lifecycle"]
        Core["aster-core control/source providers<br/>authority · publisher · protected headers"]
        Session["aster-core mission session<br/>four-flight hybrid authentication"]
        Profile["aster-profile<br/>canonical exact-ID ordering"]
        Diff["aster-negentropy<br/>set difference only"]
        Store["aster-redb-store<br/>durable acceptance/effect authority"]
        Carrier["aster-iroh<br/>direct authenticated carrier"]
    end

    Peer["Peer aster-node<br/>independent identity and store"]

    App -->|"publication input"| Node
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
ordered control effects, policy snapshots, route-only representations, and the
terminal zeroization marker.

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
    L->>S: capture fresh policy snapshot
    L->>P: Negentropy query over locally route-filtered exact IDs
    P->>L: reply lets local derive one exact set difference
    P->>L: reverse query over peer-filtered exact IDs
    L->>P: reply lets peer derive the reverse difference
    L->>P: protected bytes offered for peer-missing IDs
    P->>L: protected bytes fetched for local-missing IDs
    alt content grant
        L->>S: verify source + admit semantic Event
        L->>L: application reaction may run
    else route-only grant
        L->>S: retain bounded exact bytes only
        Note over L,S: no content open or semantic Event row
    end
```

The ordering is security-relevant: mission authentication precedes inventory;
control reconciliation and durable activation precede Event inventory; a fresh
policy snapshot filters every peer's route visibility; and content admission is
separate from forwarding authority.

## Identity and authorization are deliberately separate

| Layer | Proves or decides | Does not imply |
|---|---|---|
| Carrier | Exact direct Iroh endpoint | Mission membership or data access |
| Mission | Hybrid-session possession of the expected mission `NodeId` | Control authority, source authorship, route, or content grant |
| Control | Ordered authority/delegation chain and policy effect | Event source identity or plaintext access |
| Event source | Publisher and protected semantic header | Permission for every peer to route or read it |
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
- [Carriers and contacts](transports.md) — selected and migration-source carrier boundaries.
- [Mesh CLI guide](quickstart/mesh-cli.md) — phase-by-phase and retained receipts.
- [Requirements status](implementation/requirements-status.md) — exact credited rows and open gaps.
- [Security model](security.md) — production gates and explicit non-claims.
