# Manual Embedded Rendezvous Relay Test

This is the recommended manual relay test for the current zero-touch setup path.

It uses:

- 2 `server-node` processes
- 1 CLI client
- the embedded managed rendezvous host created automatically on the first node

It does not require:

- `rendezvous-service`
- `openssl`
- manual CA or certificate creation
- manual node TLS provisioning

## What this guide proves

At the end of this test you will have verified:

- first-run HTTPS setup UI on both nodes
- `Start a new cluster` on node A
- `Join an existing cluster` on node B through join-request plus enrollment import
- embedded managed rendezvous created automatically on node A
- password-backed admin login on the runtime UI
- client bootstrap plus enrollment
- relay-capable client transport using embedded rendezvous
- writing through node A and reading the replicated object through node B

Important scope note:

- this guide proves the current user-friendly embedded rendezvous path and a relay-backed client read path
- on one machine, node-to-node replication may still use direct peer connectivity if it is available
- if you specifically want to force node-to-node relay too, that is a more advanced/operator-style scenario than this guide

## Prerequisites

- PowerShell or Bash
- Rust toolchain
- `cargo`
- a browser

Build the binaries once:

```powershell
cargo build -p server-node -p cli-client
```

```bash
cargo build -p server-node -p cli-client
```

## Test values

```powershell
$Root = Join-Path $PWD "data/manual-relay-test"
$NodeABind = "127.0.0.1:18481"
$NodeBBind = "127.0.0.1:18482"
$NodeAUrl = "https://$NodeABind"
$NodeBUrl = "https://$NodeBBind"
$AdminPassword = "correct horse battery staple"
New-Item -ItemType Directory -Force -Path $Root | Out-Null
```

```bash
ROOT="$PWD/data/manual-relay-test"
NODE_A_BIND="127.0.0.1:18481"
NODE_B_BIND="127.0.0.1:18482"
NODE_A_URL="https://$NODE_A_BIND"
NODE_B_URL="https://$NODE_B_BIND"
ADMIN_PASSWORD="correct horse battery staple"
mkdir -p "$ROOT"
```

## 1. Start node A in zero-touch setup mode

Only a data directory and bind address are needed.

PowerShell:

```powershell
$env:IRONMESH_DATA_DIR = (Join-Path $Root "node-a")
$env:IRONMESH_SERVER_BIND = $NodeABind
cargo run -p server-node
```

```bash
export IRONMESH_DATA_DIR="$ROOT/node-a"
export IRONMESH_SERVER_BIND="$NODE_A_BIND"
cargo run -p server-node
```

Leave that terminal running.

## 2. Create the cluster on node A

Open node A in a browser:

- `https://127.0.0.1:18481/`

Accept the temporary self-signed browser warning. In the setup UI:

1. click `Start a new cluster`
2. use the same public origin as the page URL
3. choose the admin password from the test values above

What happens automatically now:

- a managed cluster CA is created
- node A receives its runtime enrollment package
- managed signer material is persisted locally
- embedded managed rendezvous is configured automatically on node A
- the process transitions into normal runtime

After the transition, node A stays on the same address and the browser should move into the regular runtime UI.

## 3. Start node B in zero-touch setup mode

PowerShell:

```powershell
$env:IRONMESH_DATA_DIR = (Join-Path $Root "node-b")
$env:IRONMESH_SERVER_BIND = $NodeBBind
cargo run -p server-node
```

```bash
export IRONMESH_DATA_DIR="$ROOT/node-b"
export IRONMESH_SERVER_BIND="$NODE_B_BIND"
cargo run -p server-node
```

Open node B in a browser:

- `https://127.0.0.1:18482/`

Accept the temporary self-signed warning there too.

## 4. Generate a join request on node B

In the node B setup UI:

1. click `Generate join request`
2. copy the emitted JSON blob

## 5. Approve node B on node A

In the node A runtime UI:

1. sign in with the admin password if needed
2. go to `Issue Enrollment From Join Request`
3. paste node B's join-request JSON
4. click `Issue enrollment from join request`
5. copy the emitted node enrollment package JSON

## 6. Import the enrollment package on node B

Back in the node B setup UI:

1. paste the node enrollment package JSON
2. choose the local admin password for node B
   For this guide, using the same password as node A is simplest.
3. click `Import node enrollment package`

Node B will transition into normal runtime.

## 7. Verify both nodes are online

The simplest check is in the browser:

- open node A runtime UI
- inspect the node list / cluster status section
- wait until both node IDs are visible

If you prefer a shell check, use the public runtime endpoint:

```powershell
curl.exe --silent --insecure "$NodeAUrl/cluster/nodes"
```

```bash
curl --silent --insecure "$NODE_A_URL/cluster/nodes"
```

## 8. Issue two client bootstrap bundles

You need one bootstrap bundle from each node:

1. on node A, use `Bootstrap bundle` and save the JSON as:
   - PowerShell: `Join-Path $Root "client-bootstrap-node-a.json"`
   - Bash: `"$ROOT/client-bootstrap-node-a.json"`
2. on node B, issue another bootstrap bundle and save it as:
   - PowerShell: `Join-Path $Root "client-bootstrap-node-b.json"`
   - Bash: `"$ROOT/client-bootstrap-node-b.json"`

Node B may ask you to sign in first with the password from step 6 if the session is gone.

## 9. Enroll one client identity using node A's bootstrap

PowerShell:

```powershell
$BootstrapAPath = Join-Path $Root "client-bootstrap-node-a.json"
$ClientIdentityPath = Join-Path $Root "client-identity.json"

cargo run -p cli-client -- `
  --bootstrap-file $BootstrapAPath `
  --client-identity-file $ClientIdentityPath `
  enroll `
  --label manual-cli
```

```bash
BOOTSTRAP_A_PATH="$ROOT/client-bootstrap-node-a.json"
CLIENT_IDENTITY_PATH="$ROOT/client-identity.json"

cargo run -p cli-client -- \
  --bootstrap-file "$BOOTSTRAP_A_PATH" \
  --client-identity-file "$CLIENT_IDENTITY_PATH" \
  enroll \
  --label manual-cli
```

This should create one client identity file that you keep for the rest of the test.

## 10. Write data through node A

PowerShell:

```powershell
cargo run -p cli-client -- `
  --bootstrap-file $BootstrapAPath `
  --client-identity-file $ClientIdentityPath `
  put notes/hello.txt "hello through embedded rendezvous"
```

```bash
cargo run -p cli-client -- \
  --bootstrap-file "$BOOTSTRAP_A_PATH" \
  --client-identity-file "$CLIENT_IDENTITY_PATH" \
  put notes/hello.txt "hello through embedded rendezvous"
```

Optional direct read-back through node A:

```powershell
cargo run -p cli-client -- `
  --bootstrap-file $BootstrapAPath `
  --client-identity-file $ClientIdentityPath `
  get notes/hello.txt
```

```bash
cargo run -p cli-client -- \
  --bootstrap-file "$BOOTSTRAP_A_PATH" \
  --client-identity-file "$CLIENT_IDENTITY_PATH" \
  get notes/hello.txt
```

## 11. Wait for replication

```powershell
Start-Sleep -Seconds 8
```

```bash
sleep 8
```

## 12. Force a relay-backed client read via node B

To make the client prefer rendezvous relay instead of the direct public endpoint, create a copy of node B's bootstrap and replace the public direct endpoint URL with an unreachable address.

PowerShell:

```powershell
$BootstrapBPath = Join-Path $Root "client-bootstrap-node-b.json"
$RelayBootstrapBPath = Join-Path $Root "client-bootstrap-node-b.relay.json"

$bootstrap = Get-Content $BootstrapBPath -Raw | ConvertFrom-Json
foreach ($endpoint in $bootstrap.direct_endpoints) {
  if ($endpoint.usage -eq "public_api") {
    $endpoint.url = "http://127.0.0.1:9"
  }
}
$bootstrap | ConvertTo-Json -Depth 20 | Set-Content $RelayBootstrapBPath
```

```bash
BOOTSTRAP_B_PATH="$ROOT/client-bootstrap-node-b.json"
RELAY_BOOTSTRAP_B_PATH="$ROOT/client-bootstrap-node-b.relay.json"

export BOOTSTRAP_B_PATH
export RELAY_BOOTSTRAP_B_PATH

python3 - <<'PY'
import json
import os
from pathlib import Path

src = Path(os.environ["BOOTSTRAP_B_PATH"])
dst = Path(os.environ["RELAY_BOOTSTRAP_B_PATH"])
data = json.loads(src.read_text())
for endpoint in data.get("direct_endpoints", []):
    if endpoint.get("usage") == "public_api":
        endpoint["url"] = "http://127.0.0.1:9"
dst.write_text(json.dumps(data, indent=2))
PY
```

If your shell does not have `python3`, edit the JSON manually and change only the `public_api` direct endpoint URL to `http://127.0.0.1:9`.

## 13. Read the replicated object through node B using relay

PowerShell:

```powershell
cargo run -p cli-client -- `
  --bootstrap-file $RelayBootstrapBPath `
  --client-identity-file $ClientIdentityPath `
  get notes/hello.txt
```

```bash
cargo run -p cli-client -- \
  --bootstrap-file "$RELAY_BOOTSTRAP_B_PATH" \
  --client-identity-file "$CLIENT_IDENTITY_PATH" \
  get notes/hello.txt
```

Expected output:

```text
hello through embedded rendezvous
```

If that succeeds, then:

- node A and node B were provisioned through the zero-touch path
- embedded managed rendezvous is active
- the client can still reach node B when its direct public endpoint is unusable
- the relay-backed client path is working
- the object replicated successfully to node B

## Optional extra checks

List nodes through the transport-aware client:

```powershell
cargo run -p cli-client -- `
  --bootstrap-file $BootstrapAPath `
  --client-identity-file $ClientIdentityPath `
  nodes
```

```bash
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
cargo run -p cli-client -- \
  --bootstrap-file "$BOOTSTRAP_A_PATH" \
  --client-identity-file "$CLIENT_IDENTITY_PATH" \
  serve-web \
  --bind 127.0.0.1:8081
```

## Current limitation

This guide now follows the normal zero-touch path, but one limitation is still worth calling out:

- the fully automated role-transfer story is not done yet; moving the signer plus embedded rendezvous role to another node still uses the explicit export/import plus restart flow documented in the admin UI

## Cleanup

- stop all terminals with `Ctrl+C`
- remove `data/manual-relay-test`

PowerShell:

```powershell
Remove-Item -Recurse -Force $Root
```

```bash
rm -rf "$ROOT"
```
