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

## 5. Authorization (RBAC)
- Define scoped admin roles:
  - `maintenance.viewer` (read-only audit/list),
  - `maintenance.operator` (dry-run + non-destructive actions),
  - `maintenance.approver` (destructive actions),
  - `maintenance.admin` (full including purge/restore).
- Enforce least privilege on each admin endpoint.
- Keep explicit approval handshake for destructive operations even with RBAC.

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
2. Identity extraction middleware (service and human/admin principals).
3. RBAC middleware and per-endpoint policy map.
4. Replace shared token primary path with identity-backed auth.
5. Audit pipeline hardening (shipping, retention, alert hooks).
6. Admin tooling UX (safe defaults, preview endpoints, explicit approvals).

