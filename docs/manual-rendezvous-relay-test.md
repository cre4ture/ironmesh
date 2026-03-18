# Manual Secure Rendezvous Relay Test

This is a concrete manual test for the current pre-release stack using:

- `rendezvous-service`
- 2 `server-node` processes
- 1 CLI client

It validates the secure path that matters for the new architecture:

- rendezvous over HTTPS with mutual TLS
- node authentication at the rendezvous control plane
- relay-required node-to-node traffic
- client bootstrap plus enrollment
- bootstrap trust roots for secure rendezvous
- enrolled client relay traffic using issued rendezvous client identity
- end-to-end object replication across two nodes

To keep the setup manageable on one machine, this recipe leaves the public node API on plain HTTP. The secure part under test here is the rendezvous control plane plus internal node identity. For a production deployment, you would normally secure the public listener too.

## What this proves

At the end of this test you will have verified that:

- both nodes join the same cluster through an mTLS-protected rendezvous service
- peer traffic can work with relay required
- a client can enroll from a bootstrap bundle
- enrollment returns the extra rendezvous client identity needed for secure relay
- the client can write through node A
- the same client identity can read the replicated object through node B using a second bootstrap bundle

## Current limitation

This flow is manual on purpose. The local cluster helper in [README.md](../README.md) does not yet start `rendezvous-service` for you, so relay-focused testing still needs a separate rendezvous process.

## Prerequisites

- PowerShell
- or Bash on Linux
- Rust toolchain
- `cargo`
- `openssl`
- `curl`

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
$RendezvousUrl = "https://127.0.0.1:19090"
$NodeAUrl = "http://127.0.0.1:18081"
$NodeBUrl = "http://127.0.0.1:18082"
$NodeAInternalUrl = "https://127.0.0.1:18181"
$NodeBInternalUrl = "https://127.0.0.1:18182"

New-Item -ItemType Directory -Force -Path $Root | Out-Null
```

```bash
ROOT="$PWD/data/manual-relay-test"
CLUSTER_ID="11111111-1111-7111-8111-111111111111"
NODE_A="00000000-0000-0000-0000-00000000a101"
NODE_B="00000000-0000-0000-0000-00000000a102"
ADMIN_TOKEN="admin-secret"
RENDEZVOUS_URL="https://127.0.0.1:19090"
NODE_A_URL="http://127.0.0.1:18081"
NODE_B_URL="http://127.0.0.1:18082"
NODE_A_INTERNAL_URL="https://127.0.0.1:18181"
NODE_B_INTERNAL_URL="https://127.0.0.1:18182"

mkdir -p "$ROOT"
```

## 1. Generate TLS material

For this local test we use one shared CA for:

- rendezvous server TLS
- node internal mTLS
- issued client rendezvous identities

That keeps the recipe small. It also means both nodes get access to the CA private key so they can issue rendezvous client identities during enrollment. That is acceptable for this local manual test only, not as a production pattern.

PowerShell:

```powershell
Set-Location c:\path\to\ironmesh
$Root = Join-Path $PWD "data/manual-relay-test"
$ClusterId = "11111111-1111-7111-8111-111111111111"
$NodeA = "00000000-0000-0000-0000-00000000a101"
$NodeB = "00000000-0000-0000-0000-00000000a102"

$TlsRoot = Join-Path $Root "tls"
$CaDir = Join-Path $TlsRoot "ca"
$RendezvousDir = Join-Path $TlsRoot "rendezvous"
$NodeADir = Join-Path $TlsRoot "node-a"
$NodeBDir = Join-Path $TlsRoot "node-b"
New-Item -ItemType Directory -Force -Path $CaDir, $RendezvousDir, $NodeADir, $NodeBDir | Out-Null

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
subjectAltName=IP:127.0.0.1,URI:urn:ironmesh:node:$NodeA
"@ | Set-Content (Join-Path $TlsRoot "node-a.ext")

@"
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=IP:127.0.0.1,URI:urn:ironmesh:node:$NodeB
"@ | Set-Content (Join-Path $TlsRoot "node-b.ext")

openssl genrsa -out (Join-Path $CaDir "cluster-ca.key") 2048
openssl req -x509 -new -key (Join-Path $CaDir "cluster-ca.key") -sha256 -days 365 -out (Join-Path $CaDir "cluster-ca.pem") -subj "/CN=ironmesh-manual-ca"

openssl genrsa -out (Join-Path $RendezvousDir "rendezvous.key") 2048
openssl req -new -key (Join-Path $RendezvousDir "rendezvous.key") -out (Join-Path $RendezvousDir "rendezvous.csr") -subj "/CN=ironmesh-rendezvous"
openssl x509 -req -in (Join-Path $RendezvousDir "rendezvous.csr") -CA (Join-Path $CaDir "cluster-ca.pem") -CAkey (Join-Path $CaDir "cluster-ca.key") -CAcreateserial -out (Join-Path $RendezvousDir "rendezvous.pem") -days 365 -sha256 -extfile (Join-Path $TlsRoot "rendezvous.ext")

openssl genrsa -out (Join-Path $NodeADir "node.key") 2048
openssl req -new -key (Join-Path $NodeADir "node.key") -out (Join-Path $NodeADir "node.csr") -subj "/CN=ironmesh-node-a"
openssl x509 -req -in (Join-Path $NodeADir "node.csr") -CA (Join-Path $CaDir "cluster-ca.pem") -CAkey (Join-Path $CaDir "cluster-ca.key") -CAcreateserial -out (Join-Path $NodeADir "node.pem") -days 365 -sha256 -extfile (Join-Path $TlsRoot "node-a.ext")

openssl genrsa -out (Join-Path $NodeBDir "node.key") 2048
openssl req -new -key (Join-Path $NodeBDir "node.key") -out (Join-Path $NodeBDir "node.csr") -subj "/CN=ironmesh-node-b"
openssl x509 -req -in (Join-Path $NodeBDir "node.csr") -CA (Join-Path $CaDir "cluster-ca.pem") -CAkey (Join-Path $CaDir "cluster-ca.key") -CAcreateserial -out (Join-Path $NodeBDir "node.pem") -days 365 -sha256 -extfile (Join-Path $TlsRoot "node-b.ext")
```

Bash/Linux:

```bash
cd /path/to/ironmesh
ROOT="$PWD/data/manual-relay-test"
NODE_A="00000000-0000-0000-0000-00000000a101"
NODE_B="00000000-0000-0000-0000-00000000a102"

TLS_ROOT="$ROOT/tls"
CA_DIR="$TLS_ROOT/ca"
RENDEZVOUS_DIR="$TLS_ROOT/rendezvous"
NODE_A_DIR="$TLS_ROOT/node-a"
NODE_B_DIR="$TLS_ROOT/node-b"
mkdir -p "$CA_DIR" "$RENDEZVOUS_DIR" "$NODE_A_DIR" "$NODE_B_DIR"

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
subjectAltName=IP:127.0.0.1,URI:urn:ironmesh:node:$NODE_A
EOF

cat > "$TLS_ROOT/node-b.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=IP:127.0.0.1,URI:urn:ironmesh:node:$NODE_B
EOF

openssl genrsa -out "$CA_DIR/cluster-ca.key" 2048
openssl req -x509 -new -key "$CA_DIR/cluster-ca.key" -sha256 -days 365 -out "$CA_DIR/cluster-ca.pem" -subj "/CN=ironmesh-manual-ca"

openssl genrsa -out "$RENDEZVOUS_DIR/rendezvous.key" 2048
openssl req -new -key "$RENDEZVOUS_DIR/rendezvous.key" -out "$RENDEZVOUS_DIR/rendezvous.csr" -subj "/CN=ironmesh-rendezvous"
openssl x509 -req -in "$RENDEZVOUS_DIR/rendezvous.csr" -CA "$CA_DIR/cluster-ca.pem" -CAkey "$CA_DIR/cluster-ca.key" -CAcreateserial -out "$RENDEZVOUS_DIR/rendezvous.pem" -days 365 -sha256 -extfile "$TLS_ROOT/rendezvous.ext"

openssl genrsa -out "$NODE_A_DIR/node.key" 2048
openssl req -new -key "$NODE_A_DIR/node.key" -out "$NODE_A_DIR/node.csr" -subj "/CN=ironmesh-node-a"
openssl x509 -req -in "$NODE_A_DIR/node.csr" -CA "$CA_DIR/cluster-ca.pem" -CAkey "$CA_DIR/cluster-ca.key" -CAcreateserial -out "$NODE_A_DIR/node.pem" -days 365 -sha256 -extfile "$TLS_ROOT/node-a.ext"

openssl genrsa -out "$NODE_B_DIR/node.key" 2048
openssl req -new -key "$NODE_B_DIR/node.key" -out "$NODE_B_DIR/node.csr" -subj "/CN=ironmesh-node-b"
openssl x509 -req -in "$NODE_B_DIR/node.csr" -CA "$CA_DIR/cluster-ca.pem" -CAkey "$CA_DIR/cluster-ca.key" -CAcreateserial -out "$NODE_B_DIR/node.pem" -days 365 -sha256 -extfile "$TLS_ROOT/node-b.ext"
```

## 2. Start secure rendezvous-service

Open PowerShell window 1:

```powershell
Set-Location c:\path\to\ironmesh
$Root = Join-Path $PWD "data/manual-relay-test"
$CaPem = Join-Path $Root "tls\ca\cluster-ca.pem"
$RendezvousCert = Join-Path $Root "tls\rendezvous\rendezvous.pem"
$RendezvousKey = Join-Path $Root "tls\rendezvous\rendezvous.key"

$env:IRONMESH_RENDEZVOUS_BIND = "127.0.0.1:19090"
$env:IRONMESH_RENDEZVOUS_PUBLIC_URL = "https://127.0.0.1:19090"
$env:IRONMESH_RENDEZVOUS_CLIENT_CA_CERT = $CaPem
$env:IRONMESH_RENDEZVOUS_TLS_CERT = $RendezvousCert
$env:IRONMESH_RENDEZVOUS_TLS_KEY = $RendezvousKey
cargo run -p rendezvous-service
```

Leave that window running.

Alternative on Linux/bash:

```bash
cd /path/to/ironmesh
ROOT="$PWD/data/manual-relay-test"
CA_PEM="$ROOT/tls/ca/cluster-ca.pem"
RENDEZVOUS_CERT="$ROOT/tls/rendezvous/rendezvous.pem"
RENDEZVOUS_KEY="$ROOT/tls/rendezvous/rendezvous.key"

export IRONMESH_RENDEZVOUS_BIND="127.0.0.1:19090"
export IRONMESH_RENDEZVOUS_PUBLIC_URL="https://127.0.0.1:19090"
export IRONMESH_RENDEZVOUS_CLIENT_CA_CERT="$CA_PEM"
export IRONMESH_RENDEZVOUS_TLS_CERT="$RENDEZVOUS_CERT"
export IRONMESH_RENDEZVOUS_TLS_KEY="$RENDEZVOUS_KEY"
cargo run -p rendezvous-service
```

Optional health check from a shell where `$Root` is already set:

```powershell
curl.exe --silent --cacert "$Root\tls\ca\cluster-ca.pem" https://127.0.0.1:19090/health
```

```bash
curl --silent --cacert "$ROOT/tls/ca/cluster-ca.pem" https://127.0.0.1:19090/health
```

## 3. Start node A

Use `cluster` mode here, not `local-edge`, so the node has an internal mTLS identity it can reuse for rendezvous authentication.

Open PowerShell window 2:

```powershell
Set-Location c:\path\to\ironmesh
$Root = Join-Path $PWD "data/manual-relay-test"
$env:IRONMESH_NODE_MODE = "cluster"
$env:IRONMESH_CLUSTER_ID = "11111111-1111-7111-8111-111111111111"
$env:IRONMESH_NODE_ID = "00000000-0000-0000-0000-00000000a101"
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
$env:IRONMESH_ADMIN_TOKEN = "admin-secret"
$env:IRONMESH_REQUIRE_CLIENT_AUTH = "true"
cargo run -p server-node
```

Alternative on Linux/bash:

```bash
cd /path/to/ironmesh
ROOT="$PWD/data/manual-relay-test"
export IRONMESH_NODE_MODE="cluster"
export IRONMESH_CLUSTER_ID="11111111-1111-7111-8111-111111111111"
export IRONMESH_NODE_ID="00000000-0000-0000-0000-00000000a101"
export IRONMESH_DATA_DIR="$PWD/data/manual-relay-test/node-a"
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
export IRONMESH_ADMIN_TOKEN="admin-secret"
export IRONMESH_REQUIRE_CLIENT_AUTH="true"
cargo run -p server-node
```

## 4. Start node B

Open PowerShell window 3:

```powershell
Set-Location c:\path\to\ironmesh
$Root = Join-Path $PWD "data/manual-relay-test"
$env:IRONMESH_NODE_MODE = "cluster"
$env:IRONMESH_CLUSTER_ID = "11111111-1111-7111-8111-111111111111"
$env:IRONMESH_NODE_ID = "00000000-0000-0000-0000-00000000a102"
$env:IRONMESH_DATA_DIR = (Join-Path $Root "node-b")
$env:IRONMESH_SERVER_BIND = "127.0.0.1:18082"
$env:IRONMESH_PUBLIC_URL = "http://127.0.0.1:18082"
$env:IRONMESH_INTERNAL_BIND = "127.0.0.1:18182"
$env:IRONMESH_INTERNAL_URL = "https://127.0.0.1:18182"
$env:IRONMESH_INTERNAL_TLS_CA_CERT = (Join-Path $Root "tls\ca\cluster-ca.pem")
$env:IRONMESH_INTERNAL_TLS_CA_KEY = (Join-Path $Root "tls\ca\cluster-ca.key")
$env:IRONMESH_INTERNAL_TLS_CERT = (Join-Path $Root "tls\node-b\node.pem")
$env:IRONMESH_INTERNAL_TLS_KEY = (Join-Path $Root "tls\node-b\node.key")
$env:IRONMESH_RENDEZVOUS_URLS = "https://127.0.0.1:19090"
$env:IRONMESH_RENDEZVOUS_CA_CERT = (Join-Path $Root "tls\ca\cluster-ca.pem")
$env:IRONMESH_RENDEZVOUS_MTLS_REQUIRED = "true"
$env:IRONMESH_RELAY_MODE = "required"
$env:IRONMESH_PUBLIC_PEER_API_ENABLED = "false"
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
ROOT="$PWD/data/manual-relay-test"
export IRONMESH_NODE_MODE="cluster"
export IRONMESH_CLUSTER_ID="11111111-1111-7111-8111-111111111111"
export IRONMESH_NODE_ID="00000000-0000-0000-0000-00000000a102"
export IRONMESH_DATA_DIR="$PWD/data/manual-relay-test/node-b"
export IRONMESH_SERVER_BIND="127.0.0.1:18082"
export IRONMESH_PUBLIC_URL="http://127.0.0.1:18082"
export IRONMESH_INTERNAL_BIND="127.0.0.1:18182"
export IRONMESH_INTERNAL_URL="https://127.0.0.1:18182"
export IRONMESH_INTERNAL_TLS_CA_CERT="$ROOT/tls/ca/cluster-ca.pem"
export IRONMESH_INTERNAL_TLS_CA_KEY="$ROOT/tls/ca/cluster-ca.key"
export IRONMESH_INTERNAL_TLS_CERT="$ROOT/tls/node-b/node.pem"
export IRONMESH_INTERNAL_TLS_KEY="$ROOT/tls/node-b/node.key"
export IRONMESH_RENDEZVOUS_URLS="https://127.0.0.1:19090"
export IRONMESH_RENDEZVOUS_CA_CERT="$ROOT/tls/ca/cluster-ca.pem"
export IRONMESH_RENDEZVOUS_MTLS_REQUIRED="true"
export IRONMESH_RELAY_MODE="required"
export IRONMESH_PUBLIC_PEER_API_ENABLED="false"
export IRONMESH_REPLICATION_FACTOR="2"
export IRONMESH_REPLICATION_AUDIT_INTERVAL_SECS="5"
export IRONMESH_REPLICA_VIEW_SYNC_INTERVAL_SECS="5"
export IRONMESH_STARTUP_REPAIR_DELAY_SECS="1"
export IRONMESH_ADMIN_TOKEN="admin-secret"
export IRONMESH_REQUIRE_CLIENT_AUTH="true"
cargo run -p server-node
```

## 5. Check cluster formation

Open PowerShell window 4 for the client/admin steps:

```powershell
Set-Location c:\path\to\ironmesh
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

## 6. Issue a bootstrap bundle from node A

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

This bootstrap should now include secure rendezvous trust metadata and `rendezvous_mtls_required=true`.

## 7. Enroll one client identity

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

This writes one persisted client identity. Because rendezvous mTLS is required, the enrolled identity should also contain `rendezvous_client_identity_pem`. Keep it. We will reuse the same identity against node B later.

## 8. Write through node A

```powershell
cargo run -p cli-client -- `
  --bootstrap-file $BootstrapAPath `
  --client-identity-file $ClientIdentityPath `
  put notes/hello.txt "hello through secure rendezvous relay"
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
  put notes/hello.txt "hello through secure rendezvous relay"
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

## 9. Wait for replication

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

## 10. Issue a second bootstrap bundle from node B

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

## 11. Read the replicated object through node B

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
hello through secure rendezvous relay
```

If that succeeds, the secure manual relay test is working end to end.

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

Inspect rendezvous presence directly. This endpoint is node-only under rendezvous mTLS, so use a node certificate, not the enrolled client identity:

```powershell
curl.exe --silent `
  --cacert "$Root\tls\ca\cluster-ca.pem" `
  --cert "$Root\tls\node-a\node.pem" `
  --key "$Root\tls\node-a\node.key" `
  https://127.0.0.1:19090/control/presence
```

```bash
cd /path/to/ironmesh
ROOT="$PWD/data/manual-relay-test"
curl --silent \
  --cacert "$ROOT/tls/ca/cluster-ca.pem" \
  --cert "$ROOT/tls/node-a/node.pem" \
  --key "$ROOT/tls/node-a/node.key" \
  https://127.0.0.1:19090/control/presence
```

## Shorter secure variant

If you only want a faster secure smoke test first:

- still do step 1 and step 2 so rendezvous is mTLS-protected
- start only node A
- do step 6 through step 8
- stop after `put` and `get` through node A succeed

That already proves:

- secure rendezvous startup
- secure rendezvous client enrollment path
- relay-capable client access with issued rendezvous client identity

The full recipe above is the better validation because it also proves node-to-node discovery and replication through secure relay.

## Cleanup

- stop the four PowerShell windows with `Ctrl+C`
- remove `data/manual-relay-test`

On Linux/bash:

- stop the four terminal windows with `Ctrl+C`
- run `rm -rf data/manual-relay-test`
