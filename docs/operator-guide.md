# Aster operator guide

This guide is for an operator who needs to install and use Aster without
building software or writing an application. It uses the packaged
`aster-agent` service and the `asterctl` command to move Events and Blobs
between explicitly provisioned Linux nodes.

> [!IMPORTANT]
> Aster is an evaluation-stage reference implementation, not a
> production-authorized system. The commands below operate the implemented
> evaluation boundary; they do not replace mission authorization, deployment
> approval, target-device qualification, backup policy, or physical
> sanitization procedures.

## What this guide covers

By the end of the Debian-package path, you can:

- install an Aster node and its command-line client;
- install separately issued mission authorization and an application bearer
  token;
- configure one node or two explicit peers;
- check service health and authenticated status;
- publish and inspect Events;
- publish, transfer, and retrieve durable or finite-lifetime Blobs; and
- stop, restart, rotate the application token, and diagnose common failures.

The public agent currently exposes Event operations plus Blob publication and
reading. It does not expose State or Record operations, Blob subscriptions, or
peer/convergence status over the operator API.

## Understand the two credentials

Aster uses two independent forms of authentication. Do not substitute one for
the other.

| Credential | Purpose | Who supplies it |
| --- | --- | --- |
| Mission provisioning bundle and reference | Establish the node's mission identity, authority, and keys and authorize its permitted peers, topics, and scopes | The mission or security authority |
| Application bearer token | Allows a local `asterctl` or application client to call the loopback agent API | The deployment operator or site credential service |

The bearer token does not make a node a mission member. Mission credentials do
not grant a local process access to the agent API. Both must be valid before
normal operation.

## Choose an installation option

| Option | Use it when | Operator boundary |
| --- | --- | --- |
| Ubuntu 24.04 `.deb` | A human needs `asterctl`, systemd service management, and direct local Event/Blob use | Recommended path for this guide; package artifacts are evaluation candidates |
| Docker Compose release bundle | A site already operates Docker and wants the dedicated immutable file-secret profile | Provides deployment, preflight, health, and authenticated generation verification; the current scratch images do not package an interactive `asterctl` client or publish the loopback application port to the host |
| Source checkout | A developer is evaluating or changing Aster | Requires Rust and repository tooling; use the quickstarts instead of this operator guide |

Neither package path is a production release. Obtain artifacts from a reviewed
revision and preserve the artifact checksum, source revision, architecture,
and approval record supplied by the release owner.

## Information required before installation

Obtain the following before changing a node:

1. A reviewed Aster package or Compose release bundle for the host
   architecture.
2. One authorized mission provisioning bundle for this node, delivered by the
   site's protected channel, or a disposable evaluation bundle created as
   described below.
3. The retained install and load operation IDs that belong to that bundle.
4. The topic and scope the node may publish or receive, for example
   `chat.events` and `mission/team/alpha`.
5. For every explicit peer:
   - its 64-hex-character carrier identity;
   - its reachable IP address and UDP port; and
   - its 64-hex-character mission node identity.
6. If the node will receive Blobs, the exact authorized Blob topic and scope
   and approved local depot limits.

Do not invent peer identities or copy another node's state, configuration,
credentials, or operation IDs. Every node needs independent custody.

## Choose how the mission bundle is supplied

Aster separates **issuance** from **installation**. The
`aster-credential-admin install` command and the
`aster-compose-credential-admin create` command consume an existing canonical
`ASTRPB03` mission bundle and place it into their deployment's credential
custody. Despite the Compose command's name, neither command creates a mission,
acts as a mission authority, or grants new access.

| Deployment | Operational bundle source | Repository evaluation option | How the node consumes it |
| --- | --- | --- | --- |
| Ubuntu `.deb` with systemd | The mission authority supplies one node-specific `ASTRPB03` bundle over a protected channel | The packaged `aster playground-init` command creates a disposable 2–32-node mission | Import the selected node's bundle with `aster-credential-admin install`, then install its matching carrier identity |
| Docker Compose | The mission authority supplies one node-specific `ASTRPB03` bundle and the site creates a separate application token | A bundle from a disposable `playground-init` run can be used as the protected input to exercise generation creation | `aster-compose-credential-admin create` produces one immutable credential generation from the bundle and token |
| Source checkout | The mission authority supplies a bundle only when an explicitly approved development integration requires it | Run `playground-init`, or use the checked-in public binding-test fixture for its narrowly documented tests | Development commands may read an owner-only file through `--mission-bundle-unprotected-reference`; this makes no protected-custody claim |

There is currently no supported repository command for production authority-side
bundle issuance. An operational authority must create, retain, recover, and
destroy its issuer state outside these node installation tools. Do not use an
evaluation generator, public fixture, copied node bundle, or node-side
credential administrator as a substitute.

### Create bundles for a Debian evaluation

Create every member of one evaluation mission in a single run on a controlled
host. Running the command independently on two hosts creates unrelated mission
authorities that cannot authenticate each other:

```sh
umask 077
aster playground-init --nodes 2 --root /tmp/aster-evaluation-mission
```

The root must not already exist. The command accepts 2 through 32 nodes and
prints each node's public carrier and mission identifiers. Each `node-N`
directory contains two sensitive files:

| File | Purpose |
| --- | --- |
| `identity.key` | That node's carrier identity |
| `mission.unprotected-reference.bundle` | That node's plaintext canonical `ASTRPB03` mission bundle |

Assign exactly one complete `node-N` directory to each host and transfer it
through an approved protected channel. The generated mission has fixed scope
`demo/playground`, fixed topic `mesh.messages`, epoch 1, and all-member grants.
It is suitable only for disposable interoperability evaluation; it cannot
create an operational role model or authorize the `imagery.maps` Blob examples
later in this guide.

For a complete package example that imports each bundle into systemd protected
credentials, installs the matching carrier identity, configures reciprocal
peers, and removes the plaintext staging material, follow the
[two-Raspberry-Pi package lab](quickstart/two-raspberry-pi-ci-package-lab.md).
Generate and retain distinct install and load operation IDs for every node as
that procedure specifies.

### Supply a bundle to a Compose deployment

Place an authority-issued bundle, or one selected node bundle from the
disposable evaluation above, at the protected input path used by the Compose
procedure:

```sh
export ASTER_BUNDLE_INPUT="$ASTER_DEPLOYMENT_ROOT/input/mission.astpb03"
install -m 0600 \
  /protected/inbox/node.astpb03 "$ASTER_BUNDLE_INPUT"
```

Then follow [Create an immutable generation](release/docker-compose.md#create-an-immutable-generation).
That command reads the bundle on standard input and combines it with a separate
application token. Its output is a deployable credential generation, not a new
mission bundle. Remove the input bundle under site policy after the generation
and deployment have been verified.

### Create or select a source-development bundle

From a source checkout, the same evaluation generator is available through
Cargo:

```sh
umask 077
cargo run --locked -p aster-node --bin aster -- \
  playground-init --nodes 2 --root /tmp/aster-source-mission
```

Use each generated node bundle with the matching generated carrier identity.
For binding tests only, the repository also contains
`bindings/testdata/non-production-provisioning.bundle`; it has public,
disposable credentials and narrowly fixed test grants. The
[development agent example](quickstart/connect-agent.md#exercise-the-repository-development-path)
shows the plaintext compatibility flag. Neither file-based source path
exercises systemd or Compose protected credential custody.

## Install the Ubuntu package

These steps assume Ubuntu 24.04 and a reviewed package named
`aster_VERSION_ARCH.deb` in the current directory.

First verify the checksum supplied by the release owner. The expected value
must come from a separately reviewed manifest or approval record:

```sh
sha256sum ./aster_VERSION_ARCH.deb
```

Install the package and the two standard command-line utilities used below:

```sh
sudo apt install ./aster_VERSION_ARCH.deb curl openssl
```

The package creates these paths but leaves the service stopped and disabled:

| Purpose | Path or identity |
| --- | --- |
| Service | `aster-agent.service` |
| Service account | `aster:aster` |
| Agent | `/usr/bin/aster-agent` |
| Operator client | `/usr/bin/asterctl` |
| Mission credential administrator | `/usr/sbin/aster-credential-admin` |
| Configuration | `/etc/aster/agent.json` |
| Application token | `/etc/aster/agent-credentials/client-token` |
| Mission reference | `/etc/aster/agent-credentials/mission-reference` |
| Durable node state | `/var/lib/aster-agent` |

Do not start the service yet.

## Set up authentication

### Create the local application token

Generate a token without putting its value in the command line, environment,
or terminal output:

```sh
umask 077
ASTER_TOKEN_STAGE="$(mktemp)"
openssl rand -hex 32 > "$ASTER_TOKEN_STAGE"
sudo install -o aster -g aster -m 0600 "$ASTER_TOKEN_STAGE" \
  /etc/aster/agent-credentials/client-token
rm -- "$ASTER_TOKEN_STAGE"
unset ASTER_TOKEN_STAGE
```

The token file may contain only 32–256 ASCII letters, digits, or `-._~`, plus
one trailing line ending. The hexadecimal command above produces an accepted
64-character token. Prefer `--token-file`; passing a literal token through
`--token` can expose it in shell history and process listings.

### Install the mission credential

Mission credential installation is a stopped-service security operation. The
authorized bundle is not generated by `asterctl` and must not be replaced by a
repository test bundle.

1. Keep the service stopped and confirm that no process remains:

   ```sh
   sudo systemctl stop aster-agent.service
   sudo systemctl show aster-agent.service \
     --property=ActiveState,SubState,MainPID,ControlPID
   ```

   Continue only when the service is inactive and both process IDs are zero.

2. If this is the first installation on the host, initialize the systemd host
   credential key once:

   ```sh
   sudo systemd-creds setup
   ```

   Do not replace an existing host key. Loss of an existing key requires the
   documented recovery procedure.

3. Use the exact
   [provider install and reference-handoff procedure](mvp/raspberry-pi-provider-v2-operations.md#operation-1-install-and-hand-off-the-reference).
   That procedure passes the authorized bundle on a protected descriptor,
   invokes `aster-credential-admin install` with the retained install and load
   operation IDs, validates the complete success result, and atomically writes
   the service-readable mission reference.

4. Confirm the resulting service-readable reference has the required ownership and
   mode without printing its contents:

   ```sh
   sudo stat --format='%U:%G %a %n' \
     /etc/aster/agent-credentials/mission-reference
   ```

   The expected result is `aster:aster 600` followed by the path.

Never place provisioning-bundle bytes, bearer-token bytes, or the decoded
mission reference in this guide, a ticket, a log, shell tracing, or command
arguments.

## Configure a packaged node

Edit `/etc/aster/agent.json` as root. This baseline receives no network Blobs
until an exact interest is added. Replace every angle-bracket placeholder
before validation:

```json
{
  "schema_version": 1,
  "state": {
    "directory": "/var/lib/aster-agent"
  },
  "application": {
    "listen": "127.0.0.1:8181"
  },
  "health": {
    "listen": "127.0.0.1:8182"
  },
  "mesh": {
    "bind": "0.0.0.0:8183",
    "emission_policy": "normal",
    "sync_interval_ms": 500,
    "blob_interests": [],
    "peers": []
  },
  "credentials": {
    "client_token_file": "/etc/aster/agent-credentials/client-token",
    "mission_secret_ref_file": "/etc/aster/agent-credentials/mission-reference",
    "mission_load_id": "<LOAD_OPERATION_AS_64_HEX_CHARACTERS>"
  },
  "storage": {
    "max_items": 10000,
    "max_payload_bytes": 67108864,
    "blob_depot": {
      "max_bytes": 67108864,
      "max_chunks": 4096,
      "max_variants": 64
    },
    "operations": {
      "max_records": 1000000,
      "max_logical_bytes": 201326592,
      "emergency_reserve": 10000
    }
  }
}
```

The capacity values are the repository's bounded evaluation values, not a
production sizing recommendation. The load operation must exactly match the
retained operation used when the mission reference was installed.

Set the configuration's ownership and permissions:

```sh
sudo chown root:aster /etc/aster/agent.json
sudo chmod 0640 /etc/aster/agent.json
```

Validate it as the service account:

```sh
sudo -u aster /usr/bin/aster-agent \
  --check-config /etc/aster/agent.json
```

Exit status `0` with no output means the configuration and referenced files
passed static validation. It does not prove that mission loading, networking,
or readiness will succeed.

## Configure two explicit peers

Each node needs the other node's exact descriptor in `mesh.peers`:

```text
CARRIER_ID@IP:PORT=MISSION_NODE_ID_HEX64
```

For example, Node A's configuration points at Node B:

```json
"peers": [
  "<NODE_B_CARRIER_ID>@192.0.2.20:8183=<NODE_B_MISSION_ID>"
]
```

Node B points independently at Node A:

```json
"peers": [
  "<NODE_A_CARRIER_ID>@192.0.2.10:8183=<NODE_A_MISSION_ID>"
]
```

Replace the documentation-only `192.0.2.0/24` addresses with reachable site
addresses. Permit the configured mesh traffic through site firewalls. Keep
the application and health listeners on loopback; never expose their
plaintext ports as remote services. A remote operator should connect to the
host and run `asterctl` locally, or use a separately approved authenticated
tunnel terminating on that host.

Peer configuration only supplies coordinates and expected identities. The
mission credential must independently authorize the peer, topic, scope, and
direction of use.

Configuration changes to peers, emission policy, Blob interests, depot
limits, or mission material require a restart.

## Configure Blob receipt

Local Blob publication and reading work without a mesh receive interest. To
allow Node B to request a specific Blob lane from peers, configure the exact
topic and exact scope on Node B:

```json
"blob_interests": [
  "imagery.maps@mission/team/alpha"
]
```

Keep all three nonzero `storage.blob_depot` limits in the same configuration.
An empty or absent list receives no Blob network work. Wildcards, descendant
scopes, duplicates, and more than 256 selectors are rejected.

The selector is receive policy, not authorization. Mission authorization and
the current epoch and revocation state still decide whether transfer is
allowed. An authenticated peer can observe the exact topic and scope interest
metadata, so enable only reviewed interests.

The `imagery.maps@mission/team/alpha` examples require bundles issued with
that exact Blob authorization. Bundles from `playground-init` authorize only
`mesh.messages@demo/playground`; changing the JSON selector or CLI arguments
does not add authority grants.

`receive_only` is not a way to receive Blobs in the current profile: while
that mode is active, the configured selectors remain stored for a later
normal-mode restart but the node performs no Blob network work.

## Start and verify the service

Start the agent and wait for readiness:

```sh
sudo systemctl start aster-agent.service
curl --fail --silent --output /dev/null \
  http://127.0.0.1:8182/livez
curl --fail --silent --output /dev/null \
  http://127.0.0.1:8182/readyz
```

Both commands must exit successfully. `/livez` only shows that the process is
alive. `/readyz` means the local durable authority and application listener
accept work; it does not mean a peer is reachable or synchronized.

Make the authenticated status call:

```sh
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token status
```

Review at least:

- node and mission identities are present;
- configured and effective emission modes are the intended values;
- peer authorization is active;
- authenticated-contact and failed-contact counters are reasonable;
- storage and publication-operation usage remain below their limits; and
- delivery pressure is not saturated.

After validation, enable start at boot if that matches site policy:

```sh
sudo systemctl enable aster-agent.service
```

## Publish and verify an Event

Run this command on Node A:

```sh
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token \
  publish \
  --topic chat.events \
  --scope mission/team/alpha \
  --priority routine \
  --operation-key operator-check-001 \
  "Node A operator check"
```

`Published locally` means Node A durably committed the Event. It does not mean
Node B received it.

Query Node A's local store:

```sh
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token \
  query --topic chat.events --scope mission/team/alpha
```

After an authenticated contact, run the same query locally on Node B. Seeing
the exact Event in Node B's query is application-level evidence that Node B
stored it. Contact counters or successful publication on Node A are not
substitutes for that check.

### Publish a finite-lifetime Event

The following Event is valid for 60 seconds from its original publication
lifetime:

```sh
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token \
  publish \
  --topic chat.events \
  --scope mission/team/alpha \
  --priority priority \
  --ttl-ms 60000 \
  --operation-key operator-check-ttl-001 \
  "This Event expires"
```

The lifetime does not restart after forwarding or process restart. Once
expired, the Event is withheld from queries, delivery, and forwarding and is
later removed by maintenance.

### Retry an uncertain publication

If a timeout or disconnect leaves the outcome unknown, repeat the identical
request against the same node with the same operation key, payload, and
options. Do not change the key to make the command succeed. An identical retry
returns the already committed result when the first attempt succeeded.

`--operation-key auto` prints a generated key before sending, but human
operators should normally choose and record an explicit key before the first
attempt.

## Create and inspect an Event subscription

Create a persistent subscription:

```sh
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token \
  subscribe \
  --scope mission/team/alpha \
  --operation-key operator-chat-reader-001 \
  chat.events
```

List subscriptions:

```sh
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token subscriptions
```

The CLI can create, list, and delete Event subscriptions. It does not provide
the application delivery poll/stream and acknowledgement workflow; consuming
at-least-once deliveries requires an application client using the agent API.
For a manual transfer check, use `query` on the receiving node.

To delete a subscription, copy its printed ID and run:

```sh
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token \
  unsubscribe '<SUBSCRIPTION_ID>'
```

## Publish, transfer, and retrieve a Blob

Blob publication accepts one nonempty regular file. Keep the file unchanged
until the command finishes. `asterctl` runs as the `aster` account in these
examples, so stage operator-owned files in a protected directory that account
can access. Do not use the Aster state directory as an exchange directory:

```sh
sudo install -d -o aster -g aster -m 0700 /run/aster-operator
sudo install -o aster -g aster -m 0600 \
  /secure/input/map.bin /run/aster-operator/map.bin
```

On Node A, publish a durable Blob:

```sh
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token \
  --timeout 30 \
  blob-publish \
  --file /run/aster-operator/map.bin \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --priority routine \
  --media-type application/octet-stream \
  --operation-key map-001
```

Record the printed Blob ID. Publication streams bounded chunks and does not
load the complete file into memory. The protocol does not define a 64-MiB
maximum, but the current selected backend may reject a file above its
configured implementation limit.

For a Blob that expires after one hour, add:

```text
--ttl-ms 3600000
```

Do not use a new operation key to retry an uncertain result. Retry with the
same file bytes and every original publication option.

If Node B has the exact Blob receive interest, authorization, depot capacity,
and a successful authenticated contact, prepare its protected output directory
and retrieve the Blob locally on Node B:

```sh
sudo install -d -o aster -g aster -m 0700 /run/aster-operator
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token \
  --timeout 30 \
  blob-read \
  --id '<BLOB_ID_FROM_NODE_A>' \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --output /run/aster-operator/received-map.bin
```

The destination must not already exist. On Linux, `asterctl` writes an
anonymous temporary file, verifies the complete authenticated stream, syncs
it, and atomically publishes the requested new path. A failed or incomplete
read leaves no named partial output.

After the read succeeds, record the first hash on Node A and the second hash on
Node B, then compare the two values:

```sh
# Node A
sha256sum /run/aster-operator/map.bin

# Node B
sha256sum /run/aster-operator/received-map.bin
```

Matching hashes plus a successful authenticated read prove equality of those
two files. A successful contact or a local publication receipt alone does not
prove remote Blob availability.

The current agent caps an RPC at 30 seconds even when a longer client timeout
is requested. Operator input and completed output remain outside Aster node
custody; copy the result into approved custody and remove staging files under
site policy when they are no longer needed. Node zeroization does not erase
those external files.

## Use the Docker Compose option

The Compose profile is a separate installation choice, not an alternate
runtime flag for the Debian binary. Follow the
[Compose operator procedure](release/docker-compose.md) for the complete
sequence:

1. select the native `amd64` or `arm64` workflow artifact;
2. verify `SHA256SUMS`, source revision, architecture, and image identities;
3. import the agent and administration image archives;
4. prepare one user-owned state directory and protected input files;
5. create one immutable credential generation from the issued bundle and
   bearer token;
6. review a schema-v2 configuration and record its SHA-256;
7. render and inspect the exact Compose model;
8. run the no-network preflight;
9. force-create the agent; and
10. run the authenticated generation verifier.

Do not scale or replicate the service: one Compose project owns one identity,
credential generation, and state directory. The current Compose images do not
contain `asterctl`, and the application listener remains loopback-only inside
the agent container's network namespace. The packaged interactive Event/Blob
commands in this guide therefore apply to the Debian path. A Compose
application integration needs a separately reviewed client deployment in the
same protected network boundary; the repository does not currently ship that
operator sidecar.

## Routine service operations

### Stop or restart

```sh
sudo systemctl stop aster-agent.service
sudo systemctl restart aster-agent.service
```

A graceful stop first removes readiness and drains bounded accepted work.
Do not delete the state directory to clear an error or reclaim capacity; doing
so destroys durability and restart claims.

### Rotate only the application token

Create the replacement beside the active file, publish it with an atomic
same-directory rename, then reload:

```sh
umask 077
ASTER_TOKEN_STAGE="$(sudo mktemp \
  /etc/aster/agent-credentials/.client-token.XXXXXX)"
openssl rand -hex 32 | sudo tee "$ASTER_TOKEN_STAGE" >/dev/null
sudo chown aster:aster "$ASTER_TOKEN_STAGE"
sudo chmod 0600 "$ASTER_TOKEN_STAGE"
sudo sync -f "$ASTER_TOKEN_STAGE"
sudo mv -T "$ASTER_TOKEN_STAGE" \
  /etc/aster/agent-credentials/client-token
sudo sync -f /etc/aster/agent-credentials
unset ASTER_TOKEN_STAGE
sudo systemctl reload aster-agent.service
```

Confirm the new token works and the prior token no longer works. A failed
reload retains the old token and Ready state. Mission credentials, peers,
emission mode, depot limits, and Blob interests require a restart and their
own approved procedures.

### Back up and recover

Back up durable state and provider material only into the site's approved
encrypted custody. Stop the service first and follow the
[provider backup and recovery procedure](mvp/raspberry-pi-provider-v2-operations.md#5-back-up-and-recover-the-exact-current-generation).
Copying only `/var/lib/aster-agent`, only the mission reference, or only the
encrypted provider file is not a complete recoverable node.

## Troubleshooting

| Observation | Meaning and action |
| --- | --- |
| `--check-config` fails | Correct the named sanitized rule category. Check JSON shape, absolute paths, ownership, permissions, operation ID, peers, Blob interests, and depot limits. Do not loosen file permissions. |
| `/livez` is unavailable or `503` | The service is absent or failed. Keep application traffic stopped and inspect `systemctl status aster-agent.service` and approved sanitized telemetry. |
| `/readyz` is `503` | The node is starting, draining, or failed. Wait for Ready or correct startup/provisioning failure. Peer absence alone does not make an offline-first node unready. |
| `asterctl` reports authentication failure | Use the token file configured for this node, check owner/mode, and confirm a token rotation did not replace it. Do not print the token. |
| Publication outcome is unknown | Retry the identical request on the same node with the same operation key. Do not create a new key. |
| Event is present on Node A but absent on Node B | Check both nodes' status, reciprocal peer coordinates, mission authorization, network reachability, emission mode, expiry, and contact results. Publication on A proves only A's local commit. |
| Blob is absent on Node B | In addition to peer and authorization checks, confirm Node B has the exact `TOPIC@SCOPE` Blob interest, normal emission mode, and available byte/chunk/variant depot capacity, then restart after configuration changes. |
| `blob-read` rejects the destination | Use Linux and a destination filesystem supporting anonymous temporary files and descriptor-relative linking. Choose a path that does not already exist. |
| `OPERATION_CAPACITY_EXHAUSTED` | Stop new publication. Preserve the state directory and existing operation keys; do not retry with new keys or raise limits during the evaluation. |
| Pending deliveries reach the documented boundary | Stop increasing workload and repair or drain the consuming application. Creating a subscription without consuming and acknowledging it can add pressure. |

For exact configuration fields and limits, see the
[schema-v1 reference](reference/aster-agent-config-v1.md). For complete CLI
syntax, run `asterctl --help`, `asterctl COMMAND --help`, or read the packaged
man pages such as `man asterctl-blob-publish`.

## What successful checks do and do not prove

| Check | It proves | It does not prove |
| --- | --- | --- |
| Configuration validation | The document and referenced files satisfy static rules | Mission provider loading or runtime readiness |
| `/readyz` returns `200` | Local durable authority and application listener accept work | Peer connectivity or convergence |
| `asterctl publish` succeeds | The local node durably committed the Event | Any peer received it |
| Authenticated contact counter increases | A mission-authenticated contact occurred | A particular Event or Blob was stored remotely |
| Query on Node B finds the Event | Node B's application view contains that Event | Every eligible node converged |
| Blob read on Node B succeeds | Node B returned a complete authenticated Blob matching the requested identity and metadata | Production transfer performance or arbitrary-peer recovery |

Retain exact receipts, timestamps, package hashes, configuration hashes, and
the devices involved when a result will be used as evaluation evidence.
