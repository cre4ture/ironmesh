# Manual Rendezvous Relay Test

This is a concrete manual test for the current pre-release stack using:

- `rendezvous-service`
- 2 `server-node` processes
- 1 CLI client

It is designed to validate the path that matters most for the new architecture:

- node discovery through rendezvous
- relay-required node-to-node traffic
- client bootstrap plus enrollment
- signed client requests
- end-to-end object replication across two nodes

This recipe uses plain HTTP rendezvous and `local-edge` nodes on one machine to keep the setup small. It intentionally forces relay for both peer and client traffic by setting `IRONMESH_RELAY_MODE=required`.

Because plain HTTP rendezvous is insecure, the service now refuses to start that way unless you explicitly opt in with `IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP=true`. Use that override only for local development/testing.

## What this proves

At the end of this test you will have verified that:

- both nodes join the same cluster through rendezvous
- peer traffic can work with relay required
- a client can enroll from a bootstrap bundle
- the client can write through node A
- the same client identity can read the replicated object through node B using a second bootstrap bundle

## Current limitation

This flow is manual on purpose. The local cluster helper in [README.md](../README.md) does not yet start `rendezvous-service` for you, so relay-focused testing still needs a separate rendezvous process.

## Prerequisites

- PowerShell
- or Bash on Linux
- Rust toolchain
- `cargo`
- `curl` for the Bash/Linux variant

Build the binaries once:

```powershell
cargo build -p rendezvous-service -p server-node -p cli-client
```

```bash
cargo build -p rendezvous-service -p server-node -p cli-client
```

## Test values

Use one fixed cluster ID and two fixed node IDs so logs are easier to compare.

```powershell
$Root = Join-Path $PWD "data/manual-relay-test"
$ClusterId = "11111111-1111-7111-8111-111111111111"
$NodeA = "00000000-0000-0000-0000-00000000a101"
$NodeB = "00000000-0000-0000-0000-00000000a102"
$AdminToken = "admin-secret"
$RendezvousUrl = "http://127.0.0.1:19090"
$NodeAUrl = "http://127.0.0.1:18081"
$NodeBUrl = "http://127.0.0.1:18082"

New-Item -ItemType Directory -Force -Path $Root | Out-Null
```

```bash
ROOT="$PWD/data/manual-relay-test"
CLUSTER_ID="11111111-1111-7111-8111-111111111111"
NODE_A="00000000-0000-0000-0000-00000000a101"
NODE_B="00000000-0000-0000-0000-00000000a102"
ADMIN_TOKEN="admin-secret"
RENDEZVOUS_URL="http://127.0.0.1:19090"
NODE_A_URL="http://127.0.0.1:18081"
NODE_B_URL="http://127.0.0.1:18082"

mkdir -p "$ROOT"
```

## 1. Start rendezvous-service

Open PowerShell window 1:

```powershell
Set-Location c:\Users\hornu\dev-rust\ironmesh
$env:IRONMESH_RENDEZVOUS_BIND = "127.0.0.1:19090"
$env:IRONMESH_RENDEZVOUS_PUBLIC_URL = "http://127.0.0.1:19090"
$env:IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP = "true"
cargo run -p rendezvous-service
```

Leave that window running.

Alternative on Linux/bash:

```bash
cd /path/to/ironmesh
export IRONMESH_RENDEZVOUS_BIND="127.0.0.1:19090"
export IRONMESH_RENDEZVOUS_PUBLIC_URL="http://127.0.0.1:19090"
export IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP="true"
cargo run -p rendezvous-service
```

## 2. Start node A

Open PowerShell window 2:

```powershell
Set-Location c:\Users\hornu\dev-rust\ironmesh
$env:IRONMESH_NODE_MODE = "local-edge"
$env:IRONMESH_CLUSTER_ID = "11111111-1111-7111-8111-111111111111"
$env:IRONMESH_NODE_ID = "00000000-0000-0000-0000-00000000a101"
$env:IRONMESH_DATA_DIR = "c:\Users\hornu\dev-rust\ironmesh\data\manual-relay-test\node-a"
$env:IRONMESH_SERVER_BIND = "127.0.0.1:18081"
$env:IRONMESH_PUBLIC_URL = "http://127.0.0.1:18081"
$env:IRONMESH_RENDEZVOUS_URLS = "http://127.0.0.1:19090"
$env:IRONMESH_RELAY_MODE = "required"
$env:IRONMESH_PUBLIC_PEER_API_ENABLED = "true"
$env:IRONMESH_REPLICATION_FACTOR = "2"
$env:IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS = "5"
$env:IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS = "5"
$env:IRONMESH_STARTUP_REPAIR_DELAY_SECS = "1"
$env:IRONMESH_ADMIN_TOKEN = "admin-secret"
$env:IRONMESH_REQUIRE_CLIENT_AUTH = "true"
cargo run -p server-node
```

Alternative on Linux/bash:

```bash
cd /path/to/ironmesh
export IRONMESH_NODE_MODE="local-edge"
export IRONMESH_CLUSTER_ID="11111111-1111-7111-8111-111111111111"
export IRONMESH_NODE_ID="00000000-0000-0000-0000-00000000a101"
export IRONMESH_DATA_DIR="$PWD/data/manual-relay-test/node-a"
export IRONMESH_SERVER_BIND="127.0.0.1:18081"
export IRONMESH_PUBLIC_URL="http://127.0.0.1:18081"
export IRONMESH_RENDEZVOUS_URLS="http://127.0.0.1:19090"
export IRONMESH_RELAY_MODE="required"
export IRONMESH_PUBLIC_PEER_API_ENABLED="true"
export IRONMESH_REPLICATION_FACTOR="2"
export IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS="5"
export IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS="5"
export IRONMESH_STARTUP_REPAIR_DELAY_SECS="1"
export IRONMESH_ADMIN_TOKEN="admin-secret"
export IRONMESH_REQUIRE_CLIENT_AUTH="true"
cargo run -p server-node
```

## 3. Start node B

Open PowerShell window 3:

```powershell
Set-Location c:\Users\hornu\dev-rust\ironmesh
$env:IRONMESH_NODE_MODE = "local-edge"
$env:IRONMESH_CLUSTER_ID = "11111111-1111-7111-8111-111111111111"
$env:IRONMESH_NODE_ID = "00000000-0000-0000-0000-00000000a102"
$env:IRONMESH_DATA_DIR = "c:\Users\hornu\dev-rust\ironmesh\data\manual-relay-test\node-b"
$env:IRONMESH_SERVER_BIND = "127.0.0.1:18082"
$env:IRONMESH_PUBLIC_URL = "http://127.0.0.1:18082"
$env:IRONMESH_RENDEZVOUS_URLS = "http://127.0.0.1:19090"
$env:IRONMESH_RELAY_MODE = "required"
$env:IRONMESH_PUBLIC_PEER_API_ENABLED = "true"
$env:IRONMESH_REPLICATION_FACTOR = "2"
$env:IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS = "5"
$env:IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS = "5"
$env:IRONMESH_STARTUP_REPAIR_DELAY_SECS = "1"
$env:IRONMESH_ADMIN_TOKEN = "admin-secret"
$env:IRONMESH_REQUIRE_CLIENT_AUTH = "true"
cargo run -p server-node
```

Alternative on Linux/bash:

```bash
cd /path/to/ironmesh
export IRONMESH_NODE_MODE="local-edge"
export IRONMESH_CLUSTER_ID="11111111-1111-7111-8111-111111111111"
export IRONMESH_NODE_ID="00000000-0000-0000-0000-00000000a102"
export IRONMESH_DATA_DIR="$PWD/data/manual-relay-test/node-b"
export IRONMESH_SERVER_BIND="127.0.0.1:18082"
export IRONMESH_PUBLIC_URL="http://127.0.0.1:18082"
export IRONMESH_RENDEZVOUS_URLS="http://127.0.0.1:19090"
export IRONMESH_RELAY_MODE="required"
export IRONMESH_PUBLIC_PEER_API_ENABLED="true"
export IRONMESH_REPLICATION_FACTOR="2"
export IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS="5"
export IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS="5"
export IRONMESH_STARTUP_REPAIR_DELAY_SECS="1"
export IRONMESH_ADMIN_TOKEN="admin-secret"
export IRONMESH_REQUIRE_CLIENT_AUTH="true"
cargo run -p server-node
```

## 4. Check cluster formation

Open PowerShell window 4 for the client/admin steps:

```powershell
Set-Location c:\Users\hornu\dev-rust\ironmesh
$Root = Join-Path $PWD "data/manual-relay-test"
$ClusterId = "11111111-1111-7111-8111-111111111111"
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:18081/cluster/nodes" | ConvertTo-Json -Depth 8
```

Alternative on Linux/bash:

```bash
cd /path/to/ironmesh
ROOT="$PWD/data/manual-relay-test"
CLUSTER_ID="11111111-1111-7111-8111-111111111111"
curl -s "http://127.0.0.1:18081/cluster/nodes"
```

Wait until you can see both node IDs in the response.

Because both nodes use `IRONMESH_RELAY_MODE=required`, peer traffic is forced through rendezvous relay even though all processes are on localhost.

## 5. Issue a bootstrap bundle from node A

```powershell
$BootstrapAPath = Join-Path $Root "client-bootstrap-node-a.json"
$BootstrapA = Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:18081/auth/bootstrap-bundles/issue" `
  -Headers @{ "x-ironmesh-admin-token" = "admin-secret" } `
  -ContentType "application/json" `
  -Body '{"label":"manual-cli","expires_in_secs":3600}'

$BootstrapA | ConvertTo-Json -Depth 16 | Set-Content $BootstrapAPath
```

Alternative on Linux/bash:

```bash
cd /path/to/ironmesh
ROOT="$PWD/data/manual-relay-test"
BOOTSTRAP_A_PATH="$ROOT/client-bootstrap-node-a.json"
curl -s \
  -X POST \
  -H "x-ironmesh-admin-token: admin-secret" \
  -H "content-type: application/json" \
  -d '{"label":"manual-cli","expires_in_secs":3600}' \
  "http://127.0.0.1:18081/auth/bootstrap-bundles/issue" \
  > "$BOOTSTRAP_A_PATH"
```

## 6. Enroll one client identity

```powershell
$ClientIdentityPath = Join-Path $Root "client-identity.json"

cargo run -p cli-client -- `
  --bootstrap-file $BootstrapAPath `
  --client-identity-file $ClientIdentityPath `
  enroll `
  --label manual-cli
```

Alternative on Linux/bash:

```bash
cd /path/to/ironmesh
ROOT="$PWD/data/manual-relay-test"
BOOTSTRAP_A_PATH="$ROOT/client-bootstrap-node-a.json"
CLIENT_IDENTITY_PATH="$ROOT/client-identity.json"

cargo run -p cli-client -- \
  --bootstrap-file "$BOOTSTRAP_A_PATH" \
  --client-identity-file "$CLIENT_IDENTITY_PATH" \
  enroll \
  --label manual-cli
```

This writes one persisted client identity. Keep it. We will reuse the same identity against node B later.

## 7. Write through node A

```powershell
cargo run -p cli-client -- `
  --bootstrap-file $BootstrapAPath `
  --client-identity-file $ClientIdentityPath `
  put notes/hello.txt "hello through rendezvous relay"
```

Alternative on Linux/bash:

```bash
cd /path/to/ironmesh
ROOT="$PWD/data/manual-relay-test"
BOOTSTRAP_A_PATH="$ROOT/client-bootstrap-node-a.json"
CLIENT_IDENTITY_PATH="$ROOT/client-identity.json"

cargo run -p cli-client -- \
  --bootstrap-file "$BOOTSTRAP_A_PATH" \
  --client-identity-file "$CLIENT_IDENTITY_PATH" \
  put notes/hello.txt "hello through rendezvous relay"
```

Optional check:

```powershell
cargo run -p cli-client -- `
  --bootstrap-file $BootstrapAPath `
  --client-identity-file $ClientIdentityPath `
  get notes/hello.txt
```

```bash
cd /path/to/ironmesh
ROOT="$PWD/data/manual-relay-test"
BOOTSTRAP_A_PATH="$ROOT/client-bootstrap-node-a.json"
CLIENT_IDENTITY_PATH="$ROOT/client-identity.json"

cargo run -p cli-client -- \
  --bootstrap-file "$BOOTSTRAP_A_PATH" \
  --client-identity-file "$CLIENT_IDENTITY_PATH" \
  get notes/hello.txt
```

## 8. Wait for replication

Give the background repair/audit loop a few seconds:

```powershell
Start-Sleep -Seconds 8
```

```bash
sleep 8
```

You can also inspect the plan:

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:18081/cluster/replication/plan" | ConvertTo-Json -Depth 8
```

```bash
curl -s "http://127.0.0.1:18081/cluster/replication/plan"
```

## 9. Issue a second bootstrap bundle from node B

The client identity is cluster-wide, but bootstrap is still the transport seed. To read through node B, ask node B for its own bootstrap bundle and reuse the same client identity.

```powershell
$BootstrapBPath = Join-Path $Root "client-bootstrap-node-b.json"
$BootstrapB = Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:18082/auth/bootstrap-bundles/issue" `
  -Headers @{ "x-ironmesh-admin-token" = "admin-secret" } `
  -ContentType "application/json" `
  -Body '{"label":"manual-cli","expires_in_secs":3600}'

$BootstrapB | ConvertTo-Json -Depth 16 | Set-Content $BootstrapBPath
```

Alternative on Linux/bash:

```bash
cd /path/to/ironmesh
ROOT="$PWD/data/manual-relay-test"
BOOTSTRAP_B_PATH="$ROOT/client-bootstrap-node-b.json"
curl -s \
  -X POST \
  -H "x-ironmesh-admin-token: admin-secret" \
  -H "content-type: application/json" \
  -d '{"label":"manual-cli","expires_in_secs":3600}' \
  "http://127.0.0.1:18082/auth/bootstrap-bundles/issue" \
  > "$BOOTSTRAP_B_PATH"
```

## 10. Read the replicated object through node B

```powershell
cargo run -p cli-client -- `
  --bootstrap-file $BootstrapBPath `
  --client-identity-file $ClientIdentityPath `
  get notes/hello.txt
```

Alternative on Linux/bash:

```bash
cd /path/to/ironmesh
ROOT="$PWD/data/manual-relay-test"
BOOTSTRAP_B_PATH="$ROOT/client-bootstrap-node-b.json"
CLIENT_IDENTITY_PATH="$ROOT/client-identity.json"

cargo run -p cli-client -- \
  --bootstrap-file "$BOOTSTRAP_B_PATH" \
  --client-identity-file "$CLIENT_IDENTITY_PATH" \
  get notes/hello.txt
```

Expected output:

```text
hello through rendezvous relay
```

If that succeeds, the manual relay test is working end to end.

## Useful extra checks

List nodes from either side:

```powershell
cargo run -p cli-client -- `
  --bootstrap-file $BootstrapAPath `
  --client-identity-file $ClientIdentityPath `
  nodes
```

```bash
cd /path/to/ironmesh
ROOT="$PWD/data/manual-relay-test"
BOOTSTRAP_A_PATH="$ROOT/client-bootstrap-node-a.json"
CLIENT_IDENTITY_PATH="$ROOT/client-identity.json"

cargo run -p cli-client -- \
  --bootstrap-file "$BOOTSTRAP_A_PATH" \
  --client-identity-file "$CLIENT_IDENTITY_PATH" \
  nodes
```

Start the embedded web UI through the same transport-aware client:

```powershell
cargo run -p cli-client -- `
  --bootstrap-file $BootstrapAPath `
  --client-identity-file $ClientIdentityPath `
  serve-web `
  --bind 127.0.0.1:8081
```

```bash
cd /path/to/ironmesh
ROOT="$PWD/data/manual-relay-test"
BOOTSTRAP_A_PATH="$ROOT/client-bootstrap-node-a.json"
CLIENT_IDENTITY_PATH="$ROOT/client-identity.json"

cargo run -p cli-client -- \
  --bootstrap-file "$BOOTSTRAP_A_PATH" \
  --client-identity-file "$CLIENT_IDENTITY_PATH" \
  serve-web \
  --bind 127.0.0.1:8081
```

Inspect rendezvous presence directly:

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:19090/control/presence?cluster_id=$ClusterId" | ConvertTo-Json -Depth 8
```

```bash
cd /path/to/ironmesh
CLUSTER_ID="11111111-1111-7111-8111-111111111111"
curl -s "http://127.0.0.1:19090/control/presence?cluster_id=$CLUSTER_ID"
```

## Simplest variant

If you only want a very fast smoke test first:

- set `IRONMESH_REQUIRE_CLIENT_AUTH=false` on both nodes
- skip enrollment
- use `cargo run -p cli-client -- --server-url http://127.0.0.1:18081 put ...`

That is useful for a quick transport check, but the full recipe above is the better manual validation because it exercises bootstrap, enrollment, signed client requests, and relay-required node traffic together.

## Cleanup

- stop the four PowerShell windows with `Ctrl+C`
- remove `data/manual-relay-test`

On Linux/bash:

- stop the four terminal windows with `Ctrl+C`
- run `rm -rf data/manual-relay-test`
