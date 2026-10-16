# Aster operator runbook

Use this runbook to install and operate Aster without building software or
writing an application. The Debian package is the complete interactive path.
The Docker Compose profile supports deployment and health verification but not
interactive Event or Blob commands.

> [!IMPORTANT]
> Aster is an evaluation-stage reference implementation, not a
> production-authorized system. Follow site approval, credential custody,
> backup, and device-sanitization policy.

## 1. Before you start

### Choose a deployment

| Option | Use it when | What works |
| --- | --- | --- |
| Ubuntu 24.04 `.deb` | A human operator needs a local CLI | systemd service, health checks, `asterctl`, Event and Blob examples |
| Docker Compose | The site uses Docker and immutable file-backed credential generations | preflight, agent startup, health, authenticated generation verification |
| Source checkout | A developer needs to change or integrate Aster | Use the [quickstarts](quickstart/README.md), not this runbook |

Neither packaged path is a production release. Use a reviewed artifact for the
correct architecture and retain its checksum and source revision.

### Collect these inputs

- One mission bundle issued for this node.
- The approved topic and scope.
- For Debian, the retained install and load operation IDs.
- For each peer: carrier ID, reachable `IP:PORT`, and mission node ID.
- For Blob receipt: the exact approved `TOPIC@SCOPE` selector and depot limits.

Each node needs its own identity, bundle, state, and operation IDs.

### Understand the two credentials

| Credential | Purpose |
| --- | --- |
| Mission bundle | Establishes mission identity and authorizes peers, topics, scopes, and keys |
| Application token | Authorizes a local client to call the agent API |

The token does not grant mission membership. The mission bundle does not grant
local API access.

`aster-credential-admin install` and
`aster-compose-credential-admin create` install an existing bundle; they do
not issue one. Production authority-side issuance is not yet provided. See
[issue #96](https://github.com/defenseunicorns/aster/issues/96).

For a disposable two-node evaluation only, create both nodes in one run:

```sh
umask 077
aster playground-init --nodes 2 --root /tmp/aster-evaluation-mission
```

Each `node-N` directory contains `identity.key` and
`mission.unprotected-reference.bundle`. The generated mission authorizes only
`mesh.messages@demo/playground`; it does not authorize the Event and Blob
examples below. See the
[two-Raspberry-Pi lab](quickstart/two-raspberry-pi-ci-package-lab.md) for the
complete evaluation import procedure.

## 2. Debian package runbook

### Step 1: install the package

Verify the checksum against a separately reviewed value, then install:

```sh
sha256sum ./aster_VERSION_ARCH.deb
sudo apt install ./aster_VERSION_ARCH.deb curl openssl
```

The package leaves `aster-agent.service` stopped and disabled. Do not start it
until authentication and configuration are ready.

### Step 2: create the application token

```sh
umask 077
ASTER_TOKEN_STAGE="$(mktemp)"
openssl rand -hex 32 > "$ASTER_TOKEN_STAGE"
sudo install -o aster -g aster -m 0600 "$ASTER_TOKEN_STAGE" \
  /etc/aster/agent-credentials/client-token
rm -- "$ASTER_TOKEN_STAGE"
unset ASTER_TOKEN_STAGE
```

Always use `--token-file`. Do not put the token in command arguments, logs, or
tickets.

### Step 3: install the mission credential

Keep the service stopped:

```sh
sudo systemctl stop aster-agent.service
sudo systemctl show aster-agent.service \
  --property=ActiveState,SubState,MainPID,ControlPID
```

Continue only when the service is inactive and both process IDs are zero. On a
new host, initialize the systemd credential key once:

```sh
sudo systemd-creds setup
```

Do not replace an existing host key. Follow
[Install and hand off the reference](mvp/raspberry-pi-provider-v2-operations.md#operation-1-install-and-hand-off-the-reference)
using this node's bundle and retained operation IDs. Then confirm the reference
permissions without printing its contents:

```sh
sudo stat --format='%U:%G %a %n' \
  /etc/aster/agent-credentials/mission-reference
```

Expected owner and mode: `aster:aster 600`.

### Step 4: configure the node

Write `/etc/aster/agent.json` and replace the load-operation placeholder:

```json
{
  "schema_version": 1,
  "state": {"directory": "/var/lib/aster-agent"},
  "application": {"listen": "127.0.0.1:8181"},
  "health": {"listen": "127.0.0.1:8182"},
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

The capacity values are evaluation defaults, not production sizing guidance.

Set permissions and validate:

```sh
sudo chown root:aster /etc/aster/agent.json
sudo chmod 0640 /etc/aster/agent.json
sudo -u aster /usr/bin/aster-agent \
  --check-config /etc/aster/agent.json
```

Exit status `0` with no output means static validation passed.

### Step 5: add peers and Blob interests

Each node independently names its peer:

```text
CARRIER_ID@IP:PORT=MISSION_NODE_ID_HEX64
```

Node A example:

```json
"peers": [
  "<NODE_B_CARRIER_ID>@192.0.2.20:8183=<NODE_B_MISSION_ID>"
]
```

Node B uses Node A's values. Replace the documentation IP with a reachable site
address and permit UDP 8183 through the site firewall. Keep application and
health ports on loopback.

To receive a Blob lane, add the exact authorized selector on the receiving
node:

```json
"blob_interests": [
  "imagery.maps@mission/team/alpha"
]
```

The selector requests data; it does not grant authorization. Empty interests
mean no Blob network receipt. Peer, interest, emission-policy, depot, and
mission changes require a restart.

### Step 6: start and verify

```sh
sudo systemctl start aster-agent.service
curl --fail --silent --output /dev/null http://127.0.0.1:8182/livez
curl --fail --silent --output /dev/null http://127.0.0.1:8182/readyz
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token status
```

`readyz` proves local readiness, not peer connectivity. Review identities,
emission mode, peer authorization, contact counters, storage use, and delivery
pressure. Enable boot start only after validation:

```sh
sudo systemctl enable aster-agent.service
```

### Step 7: test an Event

The bundle must authorize `chat.events@mission/team/alpha`.

Publish on Node A:

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

Query locally on Node A, then on Node B after authenticated contact:

```sh
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token \
  query --topic chat.events --scope mission/team/alpha
```

Seeing the Event on Node B proves that Node B stored it. A local publication or
contact counter alone does not.

For a 60-second Event, add:

```text
--ttl-ms 60000
```

If publication times out, retry the identical request on the same node with
the same operation key, payload, and options.

### Step 8: test a Blob

The bundle and receiving interest must authorize
`imagery.maps@mission/team/alpha`.

Stage the input for the `aster` service account:

```sh
sudo install -d -o aster -g aster -m 0700 /run/aster-operator
sudo install -o aster -g aster -m 0600 \
  /secure/input/map.bin /run/aster-operator/map.bin
```

Publish on Node A:

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

Record the Blob ID. For a one-hour Blob, add `--ttl-ms 3600000`.

Read on Node B:

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

The output path must not already exist. Compare the files:

```sh
# Node A
sha256sum /run/aster-operator/map.bin

# Node B
sha256sum /run/aster-operator/received-map.bin
```

Matching hashes prove equality of those two files. Remove staging files under
site policy after moving required output into approved custody.

### Optional: manage Event subscriptions

```sh
sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token \
  subscribe --scope mission/team/alpha \
  --operation-key operator-chat-reader-001 chat.events

sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token subscriptions

sudo -u aster /usr/bin/asterctl \
  --token-file /etc/aster/agent-credentials/client-token \
  unsubscribe '<SUBSCRIPTION_ID>'
```

The CLI manages subscriptions but does not poll or acknowledge deliveries. An
application client is required for the at-least-once delivery workflow.

## 3. Docker Compose runbook

The canonical profile deploys one agent per Compose project. Do not scale it or
share state, credentials, or identity between projects.

### Step 1: verify and import the release

Follow [Download and verify a release bundle](release/docker-compose.md#download-and-verify-a-release-bundle).
That procedure selects `amd64` or `arm64`, verifies checksums and metadata,
loads both images, and produces these immutable values:

```sh
export ASTER_AGENT_IMAGE_DIGEST='sha256:<verified-agent-image-id>'
export ASTER_ADMIN_IMAGE_DIGEST='sha256:<verified-admin-image-id>'
export ASTER_ARTIFACT_DIR='/absolute/path/to/verified-compose-artifact'
export ASTER_COMPOSE_FILE="$ASTER_ARTIFACT_DIR/compose.yaml"
```

The release artifact does not currently include the delivery validator. Keep a
reviewed source tree at the same revision available for Step 4.

### Step 2: prepare one deployment

Run as the same non-root user that will operate Compose:

```sh
export ASTER_UID="$(id -u)" ASTER_GID="$(id -g)"
test "$ASTER_UID" -ne 0
test "$ASTER_GID" -ne 0
export COMPOSE_PROJECT_NAME=aster-site-a
export ASTER_DEPLOYMENT_ROOT="$(pwd -P)/$COMPOSE_PROJECT_NAME"
export ASTER_GENERATION_PARENT="$ASTER_DEPLOYMENT_ROOT/credential-generations"
export ASTER_STATE_DIR="$ASTER_DEPLOYMENT_ROOT/state"
export ASTER_TOKEN_INPUT="$ASTER_DEPLOYMENT_ROOT/input/client-token"
export ASTER_BUNDLE_INPUT="$ASTER_DEPLOYMENT_ROOT/input/mission.astpb03"

install -d -m 0700 "$ASTER_DEPLOYMENT_ROOT" \
  "$ASTER_GENERATION_PARENT" "$ASTER_STATE_DIR" \
  "$ASTER_DEPLOYMENT_ROOT/input"
umask 077
openssl rand -hex 32 > "$ASTER_TOKEN_INPUT"
install -m 0600 /protected/inbox/node.astpb03 "$ASTER_BUNDLE_INPUT"
```

Replace the bundle path with this node's authority-issued bundle.

### Step 3: create a credential generation

```sh
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$ASTER_UID:$ASTER_GID" \
  --mount "type=bind,src=$ASTER_GENERATION_PARENT,dst=/host/generations" \
  --mount "type=bind,src=$ASTER_TOKEN_INPUT,dst=/host/input/client-token,readonly" \
  --interactive "$ASTER_ADMIN_IMAGE_DIGEST" \
  /usr/local/bin/aster-compose-credential-admin create \
  --output-parent /host/generations \
  --token-file /host/input/client-token < "$ASTER_BUNDLE_INPUT"
```

Record the printed generation and select it:

```sh
export ASTER_CREDENTIAL_GENERATION_DIR="$ASTER_GENERATION_PARENT/generation-<64-hex>"
test -d "$ASTER_CREDENTIAL_GENERATION_DIR"
jq . "$ASTER_CREDENTIAL_GENERATION_DIR/manifest.json"
```

Do not print the other generation files. This command installs an existing
bundle; it does not issue one.

### Step 4: configure and start

Copy and edit the packaged schema-v2 example:

```sh
export ASTER_AGENT_CONFIG_FILE="$ASTER_DEPLOYMENT_ROOT/agent.json"
install -m 0644 "$ASTER_ARTIFACT_DIR/agent.example.json" \
  "$ASTER_AGENT_CONFIG_FILE"
sha256sum "$ASTER_AGENT_CONFIG_FILE"
export ASTER_AGENT_CONFIG_SHA256='<reviewed-64-lowercase-hex>'
export ASTER_VALIDATOR='/reviewed/aster-source/tools/aster_compose_delivery.py'
```

Keep the container state and credential paths from the template unchanged.
Add only reviewed peers, Blob interests, and capacity values. Then run:

```sh
python3 "$ASTER_VALIDATOR" "$ASTER_COMPOSE_FILE"
docker compose -f "$ASTER_COMPOSE_FILE" config --format json \
  > /tmp/aster-compose.rendered.json
docker compose -f "$ASTER_COMPOSE_FILE" run --rm preflight
docker compose -f "$ASTER_COMPOSE_FILE" \
  up -d --force-recreate aster-agent
docker compose -f "$ASTER_COMPOSE_FILE" run --rm verify
docker compose -f "$ASTER_COMPOSE_FILE" ps
```

Proceed only when preflight passes, the agent is healthy, and the verifier
prints `VERIFY status=pass`.

### Current Compose limits

- The scratch image has no shell, `curl`, or `asterctl`.
- Application and health listeners are container-loopback-only.
- The canonical model does not publish mesh UDP 8183 to the host.
- Separate projects use separate networks.

Therefore this profile has no supported interactive Event/Blob or multi-project
transfer example. Those require a separately reviewed client and network
integration. Local health and generation verification do not prove transfer.

### Rotate or stop

For rotation, create and select a new generation, repeat validation and
preflight, then force-create and verify. Do not use `docker compose restart`.

```sh
docker compose -f "$ASTER_COMPOSE_FILE" \
  up -d --force-recreate aster-agent
docker compose -f "$ASTER_COMPOSE_FILE" run --rm verify
```

Stop or remove this project's containers and network:

```sh
docker compose -f "$ASTER_COMPOSE_FILE" stop -t 40 aster-agent
docker compose -f "$ASTER_COMPOSE_FILE" down
```

`down` preserves host state and credential generations. Use the
[complete Compose procedure](release/docker-compose.md) for backup, restore,
retention, and authorized cleanup.

## 4. Routine operations

### Debian service

```sh
sudo systemctl status aster-agent.service
sudo systemctl restart aster-agent.service
sudo systemctl stop aster-agent.service
```

For token rotation and protected backup/recovery, follow the
[provider operations runbook](mvp/raspberry-pi-provider-v2-operations.md).
Configuration and mission changes require a restart.

### Check CLI syntax

```sh
asterctl --help
asterctl COMMAND --help
```

The Debian package also installs command-specific man pages, such as
`man asterctl-blob-publish`.

## 5. Troubleshooting

| Symptom | Action |
| --- | --- |
| Configuration validation fails | Correct the reported JSON, path, owner, mode, peer, interest, or capacity rule; do not loosen permissions |
| `/livez` fails | Inspect `systemctl status aster-agent.service` and sanitized logs |
| `/readyz` returns `503` | Wait for startup or correct credential/configuration failure; peer absence alone does not make an offline node unready |
| `asterctl` authentication fails | Confirm the configured token file, ownership, mode, and latest rotation |
| Publication result is unknown | Retry the identical request on the same node with the same operation key |
| Event is absent on Node B | Check readiness, reciprocal peers, mission authorization, UDP reachability, emission mode, expiry, and authenticated contact |
| Blob is absent on Node B | Also check the exact Blob interest and depot byte/chunk/variant capacity |
| `blob-read` rejects output | Use Linux and a new destination path on a filesystem supporting the required atomic operation |
| Compose preflight fails | Keep the agent stopped and correct the reported config, credential, ownership, or mount condition |
| Compose verifier rejects generation | Force-create the agent with the selected generation; do not restart it |
| Operation capacity is exhausted | Stop new publication and preserve state and operation keys; do not retry with new keys |

## 6. What checks prove

| Check | Proves | Does not prove |
| --- | --- | --- |
| Static config validation | Document and referenced files satisfy static rules | Credential loading or runtime readiness |
| `/readyz` succeeds | Local durable authority and API accept work | Peer connectivity or convergence |
| Local publish succeeds | The local node committed the object | A peer received it |
| Authenticated contact increases | A mission-authenticated contact occurred | A specific Event or Blob transferred |
| Node B query finds an Event | Node B stored that Event | Every eligible node converged |
| Node B reads and hashes a Blob | Node B returned the requested complete Blob | Production performance or arbitrary-peer recovery |
| Compose verifier passes | Running agent uses the selected credential generation | Data transfer or host qualification |

Retain exact receipts, timestamps, artifact and configuration hashes, and the
devices involved when a result will be used as evaluation evidence.
