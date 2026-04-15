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

1. Define the renewal protocol and transport shape.
2. Define the authoritative issuer-side authorization checks for renewal.
3. Define the fallback / re-enrollment path for expired certificates.
4. Replace the current token-gated renewal model in implementation.
5. Update tests and operational docs when the implementation changes.

## Current Implementation Note

The current codebase still uses a separate renewal admin token for automatic node enrollment renewal.

This document records the accepted future-direction decision and should be treated as the design target for subsequent implementation work.