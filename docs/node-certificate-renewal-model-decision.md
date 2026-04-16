# Node Certificate Renewal Model Decision

## Status

Accepted.

## Context

- The current implementation renews node enrollment packages through an admin-authenticated issuer endpoint and a separate runtime renewal token.
- That design keeps renewal under explicit operator-controlled authorization, but it couples routine certificate rotation to a human/admin-style credential path.
- The intended purpose of forced certificate renewal in Ironmesh is primarily cryptographic hygiene:
  - rekeying,
  - algorithm/profile upgrades,
  - bounded credential lifetime as a backstop.
- We do not want routine renewal to be the primary mechanism that decides whether a node is still allowed to exist in the cluster.
- We do still want the control plane to decide whether a node identity is currently allowed to renew.

## Decision

Adopt the following model for node certificate renewal:

### Authentication

The current node certificate proves:

- possession of the current private key,
- the stable logical node identity (`node_id`),
- cluster binding when cluster-scoped SANs/claims are present.

Routine renewal requests should therefore be authenticated by the node's current certificate and proof of key possession.

### Authorization

Renewal authorization is a control-plane decision, not a property of certificate validity alone.

The issuer/control plane must decide whether the authenticated `node_id` is currently eligible to renew based on current cluster policy, for example:

- membership/registration state,
- disabled or revoked state,
- replacement/reprovisioning state,
- any future policy predicates.

### Rotation

Successful renewal is a re-issuance operation, not an in-place validity extension.

Renewal should:

- issue fresh keypairs and fresh certificates,
- preserve the stable logical `node_id` unless explicit re-enrollment changes identity,
- allow updated cryptographic policy:
  - validity window,
  - key type/size,
  - signature algorithm,
  - SAN/profile shape within policy.

## Core Rules

1. Routine node certificate renewal is a node-authenticated control-plane operation.
2. Routine renewal should not require a separate human/admin token in the target architecture.
3. Initial issuance, node admission, explicit revocation/disablement, and membership changes remain operator/control-plane actions.
4. A valid current certificate is necessary for routine renewal authentication, but not sufficient for renewal authorization.
5. The issuer must never "extend" the old certificate in place; it must issue new material.
6. Renewal must preserve the stable logical `node_id` unless the workflow is explicit re-enrollment.
7. Certificate expiry remains primarily a crypto-rotation mechanism and only secondarily a damage-limiting backstop.

## Consequences

### Positive

- separates authentication, authorization, and rotation concerns cleanly,
- removes routine dependence on a separate renewal admin token,
- keeps renewal aligned with the actual intended purpose of certificate lifetime,
- allows the control plane to deny renewal without overloading certificate validity semantics.

### Required Capabilities

- the issuer must support certificate-authenticated renewal requests,
- the control plane must expose authoritative current node authorization state,
- disabled/revoked node state must propagate fast enough to make renewal denial meaningful,
- recovery path must exist for expired credentials that can no longer do routine renewal.

### Risks / Tradeoffs

- revocation/disablement becomes more dependent on control-plane correctness and propagation,
- cert-only proof of possession is not enough without an explicit issuer-side authorization check,
- recovery flow for expired or badly skewed nodes must be designed deliberately.

## Non-goals

- This decision does not define the exact wire protocol for renewal.
- This decision does not remove admin/operator control over first enrollment or node revocation.
- This decision does not imply that peers should authorize all cluster actions from certificate identity alone.

## Implementation Direction

Target behavior:

1. Node presents current valid certificate and proves possession of its private key.
2. Issuer resolves the authenticated logical `node_id`.
3. Issuer consults control-plane state to decide whether renewal is allowed.
4. If allowed, issuer returns a newly issued enrollment package / certificate set.
5. Node rotates to the newly issued material without changing logical identity.

Potential transport choices:

- mTLS-authenticated renewal endpoint,
- CSR submission authenticated by the currently valid node certificate,
- equivalent proof-of-possession design that preserves the same security model.

## Follow-up Work

1. Review whether the first-slice internal-peer transport should remain the long-term renewal transport or be replaced by a dedicated issuer protocol.
2. Define richer issuer-side authorization checks for renewal beyond current cluster membership presence.
3. Define the fallback / re-enrollment path for expired certificates.
4. Review whether renewal should independently source mutable bootstrap metadata instead of trusting the caller-supplied package for non-identity fields.
5. Update operational docs and recovery runbooks around renewal failures.

## Current Implementation Note

The current codebase now implements routine automatic node enrollment renewal as a node-authenticated control-plane operation.

### First implementation decisions

To keep the first slice low-effort and reviewable, the implementation makes the following concrete choices for the open protocol points:

- Transport:
  - automatic renewal resolves `bootstrap.enrollment_issuer_url` against the node's current cluster membership view by exact normalized `public_api_url` match,
  - after that lookup it sends `POST /cluster/node-enrollments/renew` over the existing internal peer API path,
  - authentication is the existing internal mTLS node certificate and proof of private-key possession from the TLS handshake.
- Authorization:
  - the issuer requires the authenticated peer certificate `cluster_id` to match the issuer cluster,
  - the authenticated `node_id` must match the requested enrollment package `node_id`,
  - the authenticated `node_id` must still exist in the issuer's current cluster membership view.
- Current control-plane limitation:
  - there is not yet a separate disabled / revoked / replacement lifecycle state for server-node renewal authorization,
  - in this first slice, removal from current cluster membership is the denial mechanism beyond certificate validity.
- Current metadata trust choice:
  - the first slice reuses the caller-supplied enrollment package bootstrap for non-identity fields,
  - it does not yet perform a separate control-plane reconciliation of mutable bootstrap metadata such as URLs or labels before re-issuance.
- Scope limitation:
  - routine automatic renewal currently requires a cluster-mode node enrollment with internal TLS material,
  - it also requires the issuer node to be discoverable in current cluster membership with a usable peer transport path.
- Startup behavior:
  - first-slice automatic renewal runs from the background renewal loop after node startup,
  - it is not attempted before listener startup because issuer resolution now depends on live cluster membership.

### Expired credential recovery

Managed setup-mode nodes now recover expired runtime node certificates by falling back to setup recovery mode on startup instead of attempting normal runtime startup.

The current recovery slice makes these concrete choices:

- startup inspects the stored runtime node enrollment package and treats expired or otherwise unreadable configured node certificates as a recovery condition,
- setup recovery preserves the existing `cluster_id` and stable `node_id`,
- `start-cluster` is rejected while a node is in recovery so the operator cannot accidentally replace an existing cluster identity,
- the recovery workflow is: generate a fresh join request, issue a fresh node enrollment package from an existing control-plane node, and import that package to return to runtime.

### Remaining gap

This recovery path currently covers the managed setup-mode workflow. Non-managed/manual deployments still require an operator to replace the node enrollment package out of band.