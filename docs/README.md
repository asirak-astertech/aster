# Aster documentation

Use this page to choose a path through the project. You do not need to
understand Aster's wire format or cryptography before building an application.

## Recommended path

1. Read [Core concepts](concepts.md) for the mental model: items, topics,
   scopes, data classes, and contacts.
2. Run the [capability tour](quickstart/capability-tour.md) to watch real nodes
   publish offline and synchronize later.
3. Choose an integration path. Most applications should begin with the
   [local ConnectRPC agent](quickstart/connect-agent.md); Rust applications can
   use the [selected Event API](quickstart/selected-event-api.md) directly.
4. Read [Selected architecture](architecture.md) and
   [Security](security.md) before designing a deployment.

## Choose a guide by goal

| I want to… | Read… |
|---|---|
| Understand what Aster is and when it fits | [Project overview](../README.md) and [Core concepts](concepts.md) |
| See Aster work quickly | [Capability tour](quickstart/capability-tour.md) |
| Call Aster from Connect, gRPC, or gRPC-Web | [Local ConnectRPC agent](quickstart/connect-agent.md) |
| Use the live Event API from Rust | [Selected Event API](quickstart/selected-event-api.md) |
| Explore current State, Record, or Blob behavior | [State](quickstart/selected-state-api.md), [Record](quickstart/selected-record-api.md), or [Blob](quickstart/selected-blob-api.md) |
| Use the semantic API from Rust, Python, Go, or C | [Language quickstarts](quickstart/README.md) |
| See examples for every data class | [Application recipes](application-recipes.md) |
| Run and inspect a multi-process mesh | [Live mesh CLI](quickstart/mesh-cli.md) |
| Understand component and trust boundaries | [Selected architecture](architecture.md) |
| Connect nodes or add a carrier | [Carriers and contacts](transports.md) |
| Choose between State, Event, Record, and Blob | [Choosing a data class](concepts.md#choosing-a-data-class) |
| Handle conflicts, deletion, priority, or expiry | [Framework mechanisms](concepts.md#framework-mechanisms) |
| Design a binding | [Binding pattern](bindings/pattern.md) |
| Implement an independent compatible node | [Protocol](protocol.md), [wire grammar](wire.cddl), and [security objects](envelope.md) |
| Assess progress, security, or production blockers | [Capability roadmap](implementation/capability-roadmap.md), [Security](security.md), [Conformance](conformance.md), and [requirements status](implementation/requirements-status.md) |
| Review development inputs and public provenance | [Public development provenance record](provenance/independent-development-record.md) and [public source register](provenance/public-source-register.csv) |
| Run validation or interpret evidence | [CI](ci.md), [Conformance](conformance.md), and the [lab guide](../lab/README.md) |

## Know which kind of document you are reading

| Type | Purpose | Authority |
|---|---|---|
| **Quickstart** | Get to a working result | Demonstrates the bounded behavior it names |
| **Concept guide** | Explain the model and tradeoffs | Educational; links to normative details |
| **Integration guide** | Connect Aster to an application, platform, or carrier | Describes supported seams and explicit gaps |
| **Specification** | Define interoperable bytes and behavior | Normative for protocol compatibility |
| **Decision or proposal** | Record why a boundary exists or how an experiment is scoped | Historical design record; proposals are non-normative |
| **Evidence** | State what has been tested and what remains gated | Authority for implementation and release claims |

If a tutorial and a specification appear to disagree, the specification is
authoritative for interoperability. The
[requirements status](implementation/requirements-status.md) is authoritative
for which production requirements the selected composition has reached. The
[capability roadmap](implementation/capability-roadmap.md) groups those details
into outcomes for planning and PR review.

## Capability snapshot

The selected implementation deliberately exposes different maturity levels:

- **Event** has direct-Iroh networking and one operator-pinned controlled Iroh
  connectivity relay, plus live Rust and local ConnectRPC APIs.
- **State and Record** reconcile between selected nodes, while their application
  APIs require exclusive stopped-node access.
- **Blob** supports authenticated local publication, verified streaming, and
  selected direct range transfer with durable resume state; its live API,
  route-only relay/custody, and representative remote evidence remain open.
- The broader semantic Rust implementation and language bindings remain the
  proven migration source for behavior not yet composed into the selected node.

A [retained two-cell receipt](implementation/requirements-status.md#selected-iroh-nat-retained-receipt)
observes exact Event delivery and no-op replay through one cone/direct and one
restrictive/controlled-relay Docker Linux namespace-NAT cell on one Darwin
arm64 host. It is not discovery or punching, temporal fallback chronology,
representative or physical NAT, public Internet or public/default relay,
independent implementation, State/Record/Blob relay, complete-MVP, or release
evidence.

Aster remains an evaluation-stage reference implementation. Do not infer
production authorization from code presence or a passing demo. The
[project overview](../README.md#current-implementation-boundary) gives a compact
boundary; [requirements status](implementation/requirements-status.md),
[Conformance](conformance.md), and [Security](security.md) carry the details.

## Reference collections

- [Reference index](reference-index.md) — primary specifications, integration
  references, validation records, proposals, and architecture decisions.
- [Proposal index](proposals/README.md) — experiment lifecycle and results.
- [Wire grammar](wire.cddl) — compact CDDL definition.
- [Source requirements](../data-mesh-requirements.md) — frozen target-state
  grounding requirements; use the [capability roadmap](implementation/capability-roadmap.md)
  for delivery planning and PR review.
- [Public development provenance record](provenance/independent-development-record.md)
  — review path from product intent and public inputs to decisions,
  implementation, and retained repository history.

## Contributing

Start with [CONTRIBUTING.md](../CONTRIBUTING.md). Follow the project's
project source rules and provenance requirements for every change.
