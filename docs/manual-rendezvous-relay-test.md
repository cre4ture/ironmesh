# Manual Secure Rendezvous Relay Test

This is the recommended manual relay test for the current pre-release stack using:

- `rendezvous-service`
- 2 `server-node` processes
- 1 CLI client

It validates the secure path that matters for the new architecture:

- rendezvous over HTTPS with mutual TLS
- node authentication at the rendezvous control plane
- relay-required node-to-node traffic
- client bootstrap plus enrollment
- enrolled client relay traffic using issued rendezvous client identity
- end-to-end object replication across two nodes

## What changed

This guide is much simpler than the older version:

- `node B` now uses the first-run HTTPS setup UI and the zero-touch join flow
- regular runtime admin actions can use password login plus an HTTP-only session cookie
- only the rendezvous service and the first cluster node still use the advanced env-driven path

Why the first node is still special:

- the current first-run setup UI does not yet ask for rendezvous URLs or secure rendezvous settings
- for that reason, the first cluster node in this relay recipe still needs explicit rendezvous configuration

So the current best manual flow is:

1. start secure `rendezvous-service`
2. start `node A` with explicit rendezvous config
3. start `node B` with only minimal same-machine overrides and let it use the setup UI
4. use the existing cluster UI on `node A` to approve `node B`
5. use CLI bootstrap/enrollment and normal relay traffic from there

## What this proves

At the end of this test you will have verified that:

- both nodes join the same cluster through an mTLS-protected rendezvous service
- peer traffic works with relay required
- a client can enroll from a bootstrap bundle
- enrollment returns the extra rendezvous client identity needed for secure relay
- the client can write through node A
- the same client identity can read the replicated object through node B

## Prerequisites

- PowerShell or Bash
- Rust toolchain
- `cargo`
- `openssl`
- a browser

Build the binaries once:

```powershell
cargo build -p rendezvous-service -p server-node -p cli-client
```

```bash
cargo build -p rendezvous-service -p server-node -p cli-client
```

## Test values

```powershell
$Root = Join-Path $PWD "data/manual-relay-test"
$AdminToken = "admin-secret"
$NodeAUrl = "http://127.0.0.1:18081"
$NodeBSetupUrl = "https://127.0.0.1:18482"
$RendezvousUrl = "https://127.0.0.1:19090"
New-Item -ItemType Directory -Force -Path $Root | Out-Null
```

```bash
ROOT="$PWD/data/manual-relay-test"
ADMIN_TOKEN="admin-secret"
NODE_A_URL="http://127.0.0.1:18081"
NODE_B_SETUP_URL="https://127.0.0.1:18482"
RENDEZVOUS_URL="https://127.0.0.1:19090"
mkdir -p "$ROOT"
```

## 1. Generate minimal TLS material

For this updated guide, only these manual certificates are needed:

- one shared CA
- one rendezvous server certificate
- one internal mTLS certificate for `node A`

`node B` no longer needs manually created TLS files. It will receive them through the join enrollment package.

PowerShell:

```powershell
$TlsRoot = Join-Path $Root "tls"
$CaDir = Join-Path $TlsRoot "ca"
$RendezvousDir = Join-Path $TlsRoot "rendezvous"
$NodeADir = Join-Path $TlsRoot "node-a"
New-Item -ItemType Directory -Force -Path $CaDir, $RendezvousDir, $NodeADir | Out-Null

@"
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1
"@ | Set-Content (Join-Path $TlsRoot "rendezvous.ext")

@"
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=IP:127.0.0.1,URI:urn:ironmesh:node:node-a
"@ | Set-Content (Join-Path $TlsRoot "node-a.ext")

openssl genrsa -out (Join-Path $CaDir "cluster-ca.key") 2048
openssl req -x509 -new -key (Join-Path $CaDir "cluster-ca.key") -sha256 -days 365 -out (Join-Path $CaDir "cluster-ca.pem") -subj "/CN=ironmesh-manual-ca"

openssl genrsa -out (Join-Path $RendezvousDir "rendezvous.key") 2048
openssl req -new -key (Join-Path $RendezvousDir "rendezvous.key") -out (Join-Path $RendezvousDir "rendezvous.csr") -subj "/CN=ironmesh-rendezvous"
openssl x509 -req -in (Join-Path $RendezvousDir "rendezvous.csr") -CA (Join-Path $CaDir "cluster-ca.pem") -CAkey (Join-Path $CaDir "cluster-ca.key") -CAcreateserial -out (Join-Path $RendezvousDir "rendezvous.pem") -days 365 -sha256 -extfile (Join-Path $TlsRoot "rendezvous.ext")

openssl genrsa -out (Join-Path $NodeADir "node.key") 2048
openssl req -new -key (Join-Path $NodeADir "node.key") -out (Join-Path $NodeADir "node.csr") -subj "/CN=ironmesh-node-a"
openssl x509 -req -in (Join-Path $NodeADir "node.csr") -CA (Join-Path $CaDir "cluster-ca.pem") -CAkey (Join-Path $CaDir "cluster-ca.key") -CAcreateserial -out (Join-Path $NodeADir "node.pem") -days 365 -sha256 -extfile (Join-Path $TlsRoot "node-a.ext")
```

Bash:

```bash
TLS_ROOT="$ROOT/tls"
CA_DIR="$TLS_ROOT/ca"
RENDEZVOUS_DIR="$TLS_ROOT/rendezvous"
NODE_A_DIR="$TLS_ROOT/node-a"
mkdir -p "$CA_DIR" "$RENDEZVOUS_DIR" "$NODE_A_DIR"

cat > "$TLS_ROOT/rendezvous.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=IP:127.0.0.1
EOF

cat > "$TLS_ROOT/node-a.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=IP:127.0.0.1,URI:urn:ironmesh:node:node-a
EOF

openssl genrsa -out "$CA_DIR/cluster-ca.key" 2048
openssl req -x509 -new -key "$CA_DIR/cluster-ca.key" -sha256 -days 365 -out "$CA_DIR/cluster-ca.pem" -subj "/CN=ironmesh-manual-ca"

openssl genrsa -out "$RENDEZVOUS_DIR/rendezvous.key" 2048
openssl req -new -key "$RENDEZVOUS_DIR/rendezvous.key" -out "$RENDEZVOUS_DIR/rendezvous.csr" -subj "/CN=ironmesh-rendezvous"
openssl x509 -req -in "$RENDEZVOUS_DIR/rendezvous.csr" -CA "$CA_DIR/cluster-ca.pem" -CAkey "$CA_DIR/cluster-ca.key" -CAcreateserial -out "$RENDEZVOUS_DIR/rendezvous.pem" -days 365 -sha256 -extfile "$TLS_ROOT/rendezvous.ext"

openssl genrsa -out "$NODE_A_DIR/node.key" 2048
openssl req -new -key "$NODE_A_DIR/node.key" -out "$NODE_A_DIR/node.csr" -subj "/CN=ironmesh-node-a"
openssl x509 -req -in "$NODE_A_DIR/node.csr" -CA "$CA_DIR/cluster-ca.pem" -CAkey "$CA_DIR/cluster-ca.key" -CAcreateserial -out "$NODE_A_DIR/node.pem" -days 365 -sha256 -extfile "$TLS_ROOT/node-a.ext"
```

## 2. Start secure rendezvous-service

PowerShell:

```powershell
$env:IRONMESH_RENDEZVOUS_BIND = "127.0.0.1:19090"
$env:IRONMESH_RENDEZVOUS_PUBLIC_URL = "https://127.0.0.1:19090"
$env:IRONMESH_RENDEZVOUS_CLIENT_CA_CERT = (Join-Path $Root "tls\ca\cluster-ca.pem")
$env:IRONMESH_RENDEZVOUS_TLS_CERT = (Join-Path $Root "tls\rendezvous\rendezvous.pem")
$env:IRONMESH_RENDEZVOUS_TLS_KEY = (Join-Path $Root "tls\rendezvous\rendezvous.key")
cargo run -p rendezvous-service
```

```bash
export IRONMESH_RENDEZVOUS_BIND="127.0.0.1:19090"
export IRONMESH_RENDEZVOUS_PUBLIC_URL="https://127.0.0.1:19090"
export IRONMESH_RENDEZVOUS_CLIENT_CA_CERT="$ROOT/tls/ca/cluster-ca.pem"
export IRONMESH_RENDEZVOUS_TLS_CERT="$ROOT/tls/rendezvous/rendezvous.pem"
export IRONMESH_RENDEZVOUS_TLS_KEY="$ROOT/tls/rendezvous/rendezvous.key"
cargo run -p rendezvous-service
```

Leave that terminal running.

## 3. Start node A with explicit rendezvous config

This is the one remaining advanced node in this guide.

Why:

- the first-run setup UI does not yet ask for rendezvous configuration
- node A needs to seed the cluster with secure rendezvous settings and signer material

PowerShell:

```powershell
$env:IRONMESH_NODE_MODE = "cluster"
$env:IRONMESH_DATA_DIR = (Join-Path $Root "node-a")
$env:IRONMESH_SERVER_BIND = "127.0.0.1:18081"
$env:IRONMESH_PUBLIC_URL = "http://127.0.0.1:18081"
$env:IRONMESH_INTERNAL_BIND = "127.0.0.1:18181"
$env:IRONMESH_INTERNAL_URL = "https://127.0.0.1:18181"
$env:IRONMESH_INTERNAL_TLS_CA_CERT = (Join-Path $Root "tls\ca\cluster-ca.pem")
$env:IRONMESH_INTERNAL_TLS_CA_KEY = (Join-Path $Root "tls\ca\cluster-ca.key")
$env:IRONMESH_INTERNAL_TLS_CERT = (Join-Path $Root "tls\node-a\node.pem")
$env:IRONMESH_INTERNAL_TLS_KEY = (Join-Path $Root "tls\node-a\node.key")
$env:IRONMESH_RENDEZVOUS_URLS = "https://127.0.0.1:19090"
$env:IRONMESH_RENDEZVOUS_CA_CERT = (Join-Path $Root "tls\ca\cluster-ca.pem")
$env:IRONMESH_RENDEZVOUS_MTLS_REQUIRED = "true"
$env:IRONMESH_RELAY_MODE = "required"
$env:IRONMESH_PUBLIC_PEER_API_ENABLED = "false"
$env:IRONMESH_REPLICATION_FACTOR = "2"
$env:IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS = "5"
$env:IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS = "5"
$env:IRONMESH_STARTUP_REPAIR_DELAY_SECS = "1"
$env:IRONMESH_ADMIN_TOKEN = $AdminToken
$env:IRONMESH_REQUIRE_CLIENT_AUTH = "true"
cargo run -p server-node
```

```bash
export IRONMESH_NODE_MODE="cluster"
export IRONMESH_DATA_DIR="$ROOT/node-a"
export IRONMESH_SERVER_BIND="127.0.0.1:18081"
export IRONMESH_PUBLIC_URL="http://127.0.0.1:18081"
export IRONMESH_INTERNAL_BIND="127.0.0.1:18181"
export IRONMESH_INTERNAL_URL="https://127.0.0.1:18181"
export IRONMESH_INTERNAL_TLS_CA_CERT="$ROOT/tls/ca/cluster-ca.pem"
export IRONMESH_INTERNAL_TLS_CA_KEY="$ROOT/tls/ca/cluster-ca.key"
export IRONMESH_INTERNAL_TLS_CERT="$ROOT/tls/node-a/node.pem"
export IRONMESH_INTERNAL_TLS_KEY="$ROOT/tls/node-a/node.key"
export IRONMESH_RENDEZVOUS_URLS="https://127.0.0.1:19090"
export IRONMESH_RENDEZVOUS_CA_CERT="$ROOT/tls/ca/cluster-ca.pem"
export IRONMESH_RENDEZVOUS_MTLS_REQUIRED="true"
export IRONMESH_RELAY_MODE="required"
export IRONMESH_PUBLIC_PEER_API_ENABLED="false"
export IRONMESH_REPLICATION_FACTOR="2"
export IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS="5"
export IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS="5"
export IRONMESH_STARTUP_REPAIR_DELAY_SECS="1"
export IRONMESH_ADMIN_TOKEN="$ADMIN_TOKEN"
export IRONMESH_REQUIRE_CLIENT_AUTH="true"
cargo run -p server-node
```

Open `http://127.0.0.1:18081/` in a browser. The admin sections work there, but because this node came from the advanced env path you should use the `Admin token override (optional)` fields with `admin-secret`.

## 4. Start node B in zero-touch setup mode

On a real second machine you would usually need no overrides at all. For this same-machine test, give node B only:

- its own data directory
- its own bind port

PowerShell:

```powershell
$env:IRONMESH_DATA_DIR = (Join-Path $Root "node-b")
$env:IRONMESH_SERVER_BIND = "127.0.0.1:18482"
cargo run -p server-node
```

```bash
export IRONMESH_DATA_DIR="$ROOT/node-b"
export IRONMESH_SERVER_BIND="127.0.0.1:18482"
cargo run -p server-node
```

Open `https://127.0.0.1:18482/` in a browser and accept the temporary self-signed certificate warning. You should see the first-run setup UI.

## 5. Generate a join request on node B

In the node B setup UI:

1. click `Generate join request`
2. copy the emitted JSON blob

This request already includes node B’s desired public/internal runtime addresses based on the setup UI origin.

## 6. Issue node B enrollment from node A

In the node A runtime UI:

1. go to `Issue Enrollment From Join Request`
2. paste node B’s join-request JSON
3. enter `admin-secret` in the token override field if it is not already there
4. click `Issue enrollment from join request`
5. copy the emitted node enrollment package JSON

## 7. Import the enrollment package on node B

Back in the node B setup UI:

1. paste the node enrollment package JSON
2. choose a local admin password for node B
3. click `Import node enrollment package`

The node will transition into normal runtime. The setup page now automatically logs the browser into node B’s runtime admin session using that password.

## 8. Check cluster formation

You can use either node’s UI, or use a shell:

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:18081/cluster/nodes" | ConvertTo-Json -Depth 8
```

```bash
curl -s "http://127.0.0.1:18081/cluster/nodes"
```

Wait until both nodes appear.

Because node A is running with `IRONMESH_RELAY_MODE=required`, the peer traffic for this recipe is forced through rendezvous relay.

## 9. Issue a client bootstrap bundle from node A

For now, the easiest exact path is:

- use node A’s runtime UI
- in `Bootstrap bundle`, provide the admin token override `admin-secret`
- click `Issue bootstrap bundle`
- paste the resulting JSON into `$Root/client-bootstrap-node-a.json`

The bootstrap should include secure rendezvous trust metadata and `rendezvous_mtls_required=true`.

## 10. Enroll one client identity

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

Keep the resulting client identity file. It should contain the extra rendezvous client identity needed for secure relay.

## 11. Write through node A

```powershell
cargo run -p cli-client -- `
  --bootstrap-file $BootstrapAPath `
  --client-identity-file $ClientIdentityPath `
  put notes/hello.txt "hello through secure rendezvous relay"
```

```bash
cargo run -p cli-client -- \
  --bootstrap-file "$BOOTSTRAP_A_PATH" \
  --client-identity-file "$CLIENT_IDENTITY_PATH" \
  put notes/hello.txt "hello through secure rendezvous relay"
```

Optional immediate read-back through node A:

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

## 12. Wait for replication

```powershell
Start-Sleep -Seconds 8
```

```bash
sleep 8
```

Optional plan check:

```powershell
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:18081/cluster/replication/plan" | ConvertTo-Json -Depth 8
```

```bash
curl -s "http://127.0.0.1:18081/cluster/replication/plan"
```

## 13. Issue a second bootstrap bundle from node B

This is now easier than before because node B is on the zero-touch path:

1. open node B runtime UI at its normal address after setup transition
2. you should already have a local admin session from the setup import step
3. in `Bootstrap bundle`, click `Issue bootstrap bundle`
4. paste the resulting JSON into `$Root/client-bootstrap-node-b.json`

If your session is gone, use the `Admin Access` section on node B and sign in with the password you chose during step 7.

## 14. Read the replicated object through node B

PowerShell:

```powershell
$BootstrapBPath = Join-Path $Root "client-bootstrap-node-b.json"

cargo run -p cli-client -- `
  --bootstrap-file $BootstrapBPath `
  --client-identity-file $ClientIdentityPath `
  get notes/hello.txt
```

```bash
BOOTSTRAP_B_PATH="$ROOT/client-bootstrap-node-b.json"

cargo run -p cli-client -- \
  --bootstrap-file "$BOOTSTRAP_B_PATH" \
  --client-identity-file "$CLIENT_IDENTITY_PATH" \
  get notes/hello.txt
```

Expected output:

```text
hello through secure rendezvous relay
```

If that succeeds, the secure relay path is working end to end.

## Useful extra checks

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

Inspect rendezvous presence directly. This endpoint is node-only under rendezvous mTLS, so use node A’s certificate:

```powershell
curl.exe --silent `
  --cacert "$Root\tls\ca\cluster-ca.pem" `
  --cert "$Root\tls\node-a\node.pem" `
  --key "$Root\tls\node-a\node.key" `
  https://127.0.0.1:19090/control/presence
```

```bash
curl --silent \
  --cacert "$ROOT/tls/ca/cluster-ca.pem" \
  --cert "$ROOT/tls/node-a/node.pem" \
  --key "$ROOT/tls/node-a/node.key" \
  https://127.0.0.1:19090/control/presence
```

## Current zero-touch limitation

This guide is already much friendlier than the old one, but one limitation remains important:

- the first cluster node still needs explicit rendezvous configuration through env vars because the first-run setup UI does not yet collect secure rendezvous settings

Once the setup UI grows rendezvous configuration for the first node, this guide can get shorter again.

## Cleanup

- stop all terminals with `Ctrl+C`
- remove `data/manual-relay-test`

On Linux/bash:

```bash
rm -rf data/manual-relay-test
```
