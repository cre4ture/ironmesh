# Ironmesh Security Architecture (Implementation Target)

Status: Design baseline for upcoming implementation (experimental environment, no production rollout constraints yet)

## 1. Purpose
Define the end-state security architecture for:
- server-node to server-node communication,
- folder-agent/client to server-node communication,
- administrative control-plane operations,
- data-at-rest and auditability.

This document replaces ad-hoc security decisions with one coherent model.

## 2. Current Baseline (Already Implemented)
- Admin endpoints support shared token gate:
  - env: `IRONMESH_ADMIN_TOKEN`
  - header: `x-ironmesh-admin-token`
- Destructive maintenance operations require explicit approval:
  - `dry_run=false` requires `approve=true`
- Admin actions are written to persistent audit log:
  - `state/admin_audit.jsonl`

These controls are transitional and not sufficient as final architecture.

## 3. Trust Boundaries
- Data plane:
  - object transfer (`put/get/delete`, replication flows).
- Control plane:
  - node membership, maintenance, restore/purge tooling.
- Admin plane:
  - compaction/archive/restore/purge and future emergency operations.

Each plane must be independently authenticated, authorized, encrypted, and audited.

## 4. Identity and Authentication
### 4.1 Service Identity
- Every server-node gets a unique workload identity (certificate subject/SPIFFE-like ID).
- Every agent gets a unique device/workload identity.

### 4.1.2 Suggested Rust Library Stack (Pure Rust)
Cluster-internal mTLS (server-node <-> server-node) can be implemented with the following Rust crates:
- `rustls` + `tokio-rustls`: TLS 1.3 implementation and async I/O integration (mTLS supported).
- `axum-server` (`tls-rustls` feature): ergonomic TLS listener for Axum/Hyper stacks.
- `rustls-pemfile`: parse PEM-encoded cert chains and private keys.
- `x509-parser`: parse peer certificate DER and extract the logical `node_id` from SAN URI.
- `rcgen` (tests/dev tooling): generate a local CA and per-node certificates for system tests.

### 4.1.1 Compromise: Stable Logical `node_id` + mTLS-Proven Identity (Cluster Internal)
For server-node <-> server-node communication we adopt a compromise that keeps a stable logical `node_id`
(UUID) for cluster membership and placement, while relying on mTLS for cryptographic authentication.

Model:
- Cluster maintains a stable logical identifier: `node_id` (UUID).
- Each node holds a client certificate signed by a cluster "Node CA".
- The certificate encodes the logical `node_id` as an identity claim (SAN URI recommended):
  - `URI: urn:ironmesh:node:<uuid>`
  - Optional (strongly recommended): bind the cert to a specific cluster:
    - `URI: urn:ironmesh:cluster:<cluster_uuid>`

Authorization invariant:
- For any internal endpoint that includes `{node_id}` in the URL path, the authenticated caller identity
  extracted from the peer TLS certificate MUST match that `{node_id}`.
- No internal request should rely on a user-provided `x-ironmesh-node-id` header for caller identity.

Certificate rotation:
- Cert renewal and rekey are allowed without changing `node_id`, as long as the new cert is signed by
  the Node CA and still contains `urn:ironmesh:node:<same uuid>`.
- Revocation is handled by CA/CRL/short-lived certs (preferred) rather than by changing `node_id`.

### 4.2 Transport Authentication
- Require TLS for all HTTP traffic.
- Prefer mTLS for:
  - server-node <-> server-node,
  - folder-agent <-> server-node.
- Reject plaintext HTTP outside explicit local-dev mode.

### 4.3 Human/Admin Authentication
- Replace shared token with identity-backed auth:
  - OIDC/JWT or mTLS client certs for operators and automation.
- Keep token support only as emergency fallback with explicit expiry and rotation.

### 4.4 Node Enrollment and Registration
Goal: only approved nodes can join the cluster, and node credentials can be rotated safely.

Recommended baseline (experimental-friendly):
1. Operator provisions a `node_id` (UUID) and a public `public_url` for the node.
2. Operator (or control plane) issues a Node CA-signed client certificate containing:
   - `urn:ironmesh:node:<uuid>`
   - optionally `urn:ironmesh:cluster:<cluster_uuid>`
3. Operator registers membership in the cluster (admin-authenticated endpoint).
4. Node starts and uses mTLS for all internal cluster endpoints (replication push/pull, reconcile, heartbeat).

Optional future improvement:
- Self-serve enrollment via a short-lived, single-use join token:
  - node generates a keypair + CSR, presents join token, receives signed cert + assigned/confirmed `node_id`.

## 5. Authorization (RBAC)
- Define scoped admin roles:
  - `maintenance.viewer` (read-only audit/list),
  - `maintenance.operator` (dry-run + non-destructive actions),
  - `maintenance.approver` (destructive actions),
  - `maintenance.admin` (full including purge/restore).
- Enforce least privilege on each admin endpoint.
- Keep explicit approval handshake for destructive operations even with RBAC.

### 5.1 Plane Separation Rules
- Internal node-to-node operations (replication/reconcile/heartbeat) require node mTLS authentication.
- Node credential issuance/rotation/revocation and membership changes are ADMIN plane operations:
  - must not be possible via node identity alone.
- Admin token is transitional; long term admin actions must be tied to a human/service principal.

## 6. Cryptography
### 6.1 In Transit
- TLS 1.2+ minimum, TLS 1.3 preferred.
- Strong cipher suites only; disable legacy ciphers/protocols.

### 6.2 At Rest
- Encrypt server state storage where feasible (disk/volume encryption baseline).
- Protect secret material (admin fallback token, private keys) in dedicated secret storage.

### 6.3 Integrity
- Keep per-file content hashes server-side (already introduced in index/snapshot path).
- Use signed or tamper-evident archival metadata for tombstone archives and audit logs.

## 7. Key and Secret Management
- Centralized secret provisioning for:
  - TLS private keys/certs,
  - fallback admin tokens,
  - signing keys for archival/audit integrity.
- Mandatory rotation policies:
  - short-lived certs preferred,
  - token rotation on schedule and incident trigger.

## 8. Audit and Forensics
- All admin decisions logged with:
  - actor identity,
  - source node/device,
  - action, parameters, and outcome.
- Ship audit logs to append-only durable store.
- Add alerting on:
  - authorization denials,
  - destructive actions,
  - repeated failed admin auth attempts.

## 9. Operational Safety Controls
- Dry-run as default for destructive maintenance tooling.
- Two-step confirmation for restore/purge with approval role.
- Provide explicit tooling for:
  - tombstone archive inventory,
  - restore preview,
  - purge preview and execution audit.

## 10. Experimental-Phase Strategy
- No staged rollout and no feature-flag gating required at this phase.
- Implement security controls directly in mainline code and validate via:
  - unit tests,
  - integration/system tests,
  - documented local threat-model checks.
- Re-evaluate rollout strategy only when first production-like environment is introduced.

## 11. Suggested Implementation Order
1. TLS/mTLS plumbing and certificate loading paths.
2. Internal node identity extraction (peer certificate -> `node_id`) + self-only enforcement.
3. Identity extraction middleware (human/admin principals).
3. RBAC middleware and per-endpoint policy map.
4. Replace shared token primary path with identity-backed auth.
5. Audit pipeline hardening (shipping, retention, alert hooks).
6. Admin tooling UX (safe defaults, preview endpoints, explicit approvals).
