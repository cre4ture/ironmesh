# Zero-Touch Cluster Setup Strategy

Status: Proposed product-direction document for the regular Ironmesh setup UX

Related documents:

- `docs/multi-node-strategy.md`
- `docs/security-architecture.md`
- `docs/nat-traversal-rendezvous-strategy.md`
- `docs/nat-traversal-implementation-checklist.md`

## 1. Decision

The preferred setup model is:

- managed internal CA behind UI approval,
- no routine requirement for CLI flags or environment variables in the regular setup path,
- first-run node boot into a local HTTPS setup UI,
- two primary first-run choices:
  - `Start a new cluster`
  - `Join an existing cluster`

This keeps the current architectural direction:

- nodes and clients still generate their own local keys,
- cluster-issued credentials remain the long-term trust model,
- existing enrollment/bootstrap concepts are reused,
- operators do not need to manually create TLS material for the normal path.

## 2. Product Goal

For the regular use case, a fresh node should behave like this:

1. Node starts with no special arguments.
2. Node detects that it has not been initialized yet.
3. Node generates a temporary local setup identity and serves a bootstrap HTTPS web UI.
4. Admin opens the web UI and chooses:
   - `Start a new cluster`
   - `Join an existing cluster`
5. After the setup flow completes, the node transitions into normal cluster operation.

The regular setup flow should not require the admin to:

- create CA files manually,
- generate TLS certificates manually,
- pass a large set of environment variables,
- call backend enrollment endpoints directly,
- paste raw cryptographic material into config files.

## 3. Why This Strategy Fits Ironmesh

This is the best fit for the current architecture because:

- Ironmesh already has enrollment flows,
- Ironmesh already has node enrollment packages,
- Ironmesh already has client bootstrap and enrollment,
- the current security direction is still certificate-backed identities,
- the operational pain is mostly setup UX, not the existence of a CA itself.

The design target is therefore:

- keep the internal PKI model,
- hide the PKI management behind guided setup and approval flows.

## 4. First-Run Node Behavior

On first boot, a node should enter a local bootstrap state instead of failing for missing config.

Suggested state model:

- `uninitialized`
  - no cluster membership
  - no cluster CA
  - no node enrollment
  - only bootstrap UI is available
- `pending_join`
  - local key material exists
  - join request created
  - waiting for approval or enrollment material from an existing cluster
- `joining`
  - enrollment material received
  - node is applying config, trust roots, and issued credentials
- `online`
  - normal runtime mode

This aligns well with the older `unpaired -> pending -> joining -> online` direction already captured in `docs/multi-node-strategy.md`.

## 5. Bootstrap UI Strategy

The bootstrap UI should be served over HTTPS from the very first start.

Recommended first-run behavior:

- node generates a temporary bootstrap TLS keypair automatically,
- node generates a self-signed bootstrap certificate automatically,
- node stores it under the node data directory,
- node serves only the setup UI plus minimal health/bootstrap metadata in this mode,
- bootstrap UI binds to the LAN by default,
- advanced mode may still allow a `localhost`-only override through env/CLI.

This bootstrap TLS identity is not the cluster trust anchor.
It is only there so the first-run UI is not plaintext.

For the initial product version:

- browser warning acceptance for the self-signed first-run certificate is acceptable,
- no extra fingerprint-confirmation or setup-code confirmation step is required yet,
- this bootstrap mode is therefore intended for trusted LAN environments.

After cluster creation or join succeeds:

- the bootstrap UI certificate is replaced or sidelined,
- the node switches to normal public/internal trust material.

## 6. `Start a New Cluster` Flow

Target operator flow:

1. Admin opens the first-run UI on a fresh node.
2. Admin clicks `Start a new cluster`.
3. Node generates:
   - a new cluster ID,
   - a managed internal CA,
   - the first node identity,
   - initial cluster-local signing/enrollment state.
4. The bootstrap flow immediately requires the operator to set the first strong admin password.
5. Node becomes the first approved cluster member and the initial signer/controller.
6. UI presents:
   - cluster status,
   - a `Join another node` flow,
   - client bootstrap / pairing flows,
   - signer backup/export controls.

Important product property:

- the first cluster node becomes the initial signer/controller for the managed internal CA path,
- but the operator should not need to see raw CA files in the normal flow.

## 7. `Join an Existing Cluster` Flow

Target operator flow:

1. Fresh node boots into bootstrap UI.
2. Admin clicks `Join an existing cluster`.
3. Node generates its own local keypair and a join request.
4. UI shows the join request in a transportable form, initially:
   - copy-paste request blob,
   - downloadable request file.
5. Admin opens an already-running cluster UI on an approved node.
6. Existing cluster UI imports the join request and issues a node enrollment package for that request.
7. The joining node imports or pastes the issued node enrollment package.
8. The node transitions to `joining`, then `online`.

This preserves the desired security property:

- the joining node generates its own local key first,
- the cluster approves and signs it,
- the operator does not manually handle TLS assets.

This is also the best fit to the current implementation direction because Ironmesh already has node enrollment package issuance. A live approval queue can still be added later.

## 8. Admin UX Direction

The initial UX should optimize for:

- low friction on first setup,
- explicit approval for new members,
- minimal exposure of cryptographic details,
- future ability to add stronger admin auth without redesigning the flow.

Suggested UI surfaces:

- first-run page
  - `Start a new cluster`
  - `Join an existing cluster`
- cluster admin page
  - join-request import and node enrollment issuance
  - client pairing/bootstrap issuance
  - current members
  - signer/CA status
  - backup / recovery guidance
  - signer transfer/import

## 9. Security Position

This strategy does not remove the CA.
It removes the operator burden of managing the CA manually.

That distinction is important:

- trust still comes from a cluster signer/CA,
- but issuance is hidden behind UI approval and enrollment,
- node/client keys are still generated locally,
- approval remains an explicit control point.

## 10. Recommended Defaults

For the normal product path, the defaults should be:

- first-run bootstrap UI enabled automatically,
- bootstrap UI HTTPS enabled automatically,
- bootstrap UI LAN-share enabled automatically,
- `localhost`-only bootstrap remains an advanced override,
- data directory defaults chosen automatically,
- rendezvous and internal trust configured through setup artifacts rather than env vars,
- environment variables remain available only for:
  - testing,
  - advanced deployments,
  - externally managed certificates,
  - automation/infrastructure use.

## 11. Reviewed Decisions and Remaining Follow-Ups

This section records the reviewed decisions after operator feedback.

### 11.1 Bootstrap UI trust model

Decision:

- browser warning acceptance is acceptable for the first-run self-signed HTTPS UI,
- bootstrap UI binds to the LAN by default,
- `localhost`-only remains an advanced override,
- no fingerprint or setup-code confirmation step is required in the first implementation.

Risk note:

- because bootstrap UI is LAN-reachable and unauthenticated before initialization completes, this mode is intended for trusted LAN environments.

### 11.2 No-password first-run admin access

Decision:

- no-password access is accepted only during the `uninitialized` bootstrap state,
- `Start a new cluster` must force creation of the first strong admin password before the node leaves bootstrap mode,
- no external identity provider is required in the first implementation,
- no separate "accept local-only admin mode" step is needed.

Clarification:

- in this document, "local bootstrap admin" means a cluster-local admin account managed by the signer/controller node, not an external identity provider.

### 11.3 Signer placement

Decision:

- the first cluster node is the initial signer/controller,
- the signer role must be transferable later,
- the first implementation does not require encryption at rest for the managed CA key,
- file ownership and permissions must be kept as narrow as practical.

Follow-up:

- the signer transfer flow should be based on explicit managed-CA backup export/import rather than silently duplicating key material across nodes.

### 11.4 Join-request transport

Decision:

- the best-fit initial join path is request import/export plus enrollment-package import/export,
- a live approval queue is not required in the first implementation,
- copy-paste and file import/export are the primary initial transports,
- QR or join-code based flows can be added later if desired.

Reason:

- this fits the current implementation best because Ironmesh already has node enrollment package issuance, so the smallest extension is:
  - joining node creates a join request,
  - existing cluster UI imports that request and issues a node enrollment package,
  - joining node imports the enrollment package.

### 11.5 Node public identity before enrollment

Decision:

- bootstrap UI uses a separate temporary keypair from the final cluster-issued node identity,
- temporary bootstrap TLS is discarded or sidelined as soon as cluster creation or join completes.

Why not reuse the same keypair:

- it would tie an unauthenticated bootstrap surface to the long-lived cluster identity,
- if the bootstrap key were leaked before enrollment, the final node identity would be compromised too,
- bootstrap TLS and final node identity have different trust models, SANs, key usages, and rotation lifecycles,
- a disposable bootstrap key keeps later signer transfer and certificate rotation cleaner.

### 11.6 Recovery and backup

Decision:

- the managed CA must be exportable as an encrypted backup,
- that backup is the basis for signer-role transfer and node-failure recovery,
- split-secret recovery is not required in the first implementation,
- a passphrase-protected backup is sufficient; a separate "recovery code" concept is not required initially.

Reason:

- the benefit over a raw CA backup is that theft of the backup file alone does not immediately compromise cluster issuance.

### 11.7 Multi-admin and audit

Decision:

- start with a single cluster-local admin account protected by a strong password on the current signer/controller node,
- per-approver identity and multi-admin workflows are not required in the first implementation,
- stronger operator auth can be added later without changing the enrollment model.

Initial audit expectation:

- basic audit entries may record a generic local admin actor at first,
- richer operator identity can be layered on later.

### 11.8 Client onboarding alignment

Decision:

- keep the current pairing/bootstrap-based client onboarding path for the first implementation,
- the preferred initial UX is:
  - admin UI issues client bootstrap,
  - QR/bootstrap bundle carries the pairing/enrollment seed,
  - client enrolls and receives its long-lived identity material.

Reason:

- this fits the current implementation best and avoids introducing a separate approval-queue model for clients before it is needed.

### 11.9 Automation without env vars

Decision:

- the regular setup path should persist almost all routine runtime configuration into node-managed state/config generated by setup or enrollment,
- environment variables remain primarily as advanced overrides and automation/test inputs.

Proposal for persisted node-managed state/config:

- bootstrap state:
  - `uninitialized`, `pending_join`, `joining`, `online`
- stable identity:
  - `cluster_id`
  - `node_id`
  - current node role flags such as signer/controller
- network/runtime settings:
  - public bind address
  - public advertised URL
  - internal bind address
  - internal advertised URL
  - rendezvous URLs
  - relay mode
  - public-peer-api enabled flag
- trust and certificate material references:
  - managed trust roots
  - paths to materialized runtime certs/keys under the node data directory
  - enrollment issuer URL and renewal settings
- admin state:
  - bootstrap-completed flag
  - local admin auth metadata
- signer state:
  - signer enabled/disabled
  - managed CA material references
  - signer backup/export metadata

Environment variables should remain primarily for:

- data-dir or bind overrides,
- externally managed certificates,
- externally managed signer/CA integration,
- test harnesses,
- debug/logging and operational overrides.

## 12. Recommended Immediate Direction

The recommended next implementation/design sequence is:

1. Treat this as the desired normal setup UX.
2. Keep env/CLI-heavy startup as the advanced/operator path.
3. Add a first-run bootstrap state and HTTPS setup UI.
4. Implement `Start a new cluster` with forced initial admin-password setup.
5. Implement `Join an existing cluster` using join-request import/export and enrollment-package import/export.
6. Move routine startup configuration into persisted node-managed state/config.
7. Add managed CA backup export/import for signer transfer and recovery.
8. Leave later hardening for follow-up phases:
   - optional `localhost`-only bootstrap mode,
   - optional bootstrap confirmation code/fingerprint UX,
   - encrypt-at-rest for signer material,
   - richer multi-admin and audit models.

## 12a. Current Implementation Snapshot

The first implementation slice is now in place:

- `server-node` can automatically enter a first-run bootstrap mode when it starts without explicit node bootstrap, node enrollment, or advanced env-driven runtime configuration,
- bootstrap mode serves a dedicated HTTPS setup UI using an automatically generated temporary self-signed certificate stored under the node data directory,
- bootstrap mode persists managed setup state under the node data directory so the node can later restart into the normal runtime path without env vars,
- `Start a new cluster` already generates a managed cluster CA, issues this node's initial enrollment package automatically, persists that package locally, and transitions the process into the normal runtime path,
- `Join an existing cluster` already supports generating a transportable join-request blob on the joining node, importing that join request on an existing cluster node to issue a node enrollment package, and importing the issued node enrollment package on the joining node to transition into the normal runtime path.

Important current limitations of this first slice:

- the bootstrap-created admin password is currently mapped onto the existing admin-token model used by the normal runtime UI and admin API; a fuller password/login UX is still a follow-up step,
- managed CA backup/export, signer transfer, encrypt-at-rest for signer material, and richer multi-admin auth are still follow-up work.

## 13. Summary

The chosen strategy is:

- managed internal CA behind UI approval,
- local key generation on the joining node/client,
- automatic issuance by the cluster after approval or request import,
- zero-touch first-run node UX with a local HTTPS setup UI,
- no-password bootstrap mode only while the node is uninitialized,
- forced creation of the first strong admin password during `Start a new cluster`,
- first node as initial signer/controller with transferable signer role,
- encrypted managed-CA backup export/import for recovery and signer transfer,
- request/import plus enrollment/import as the first join transport,
- minimal reliance on CLI flags or environment variables for the normal path.

This is the most practical next-direction because it fits the current Ironmesh architecture while removing the biggest current usability pain: manual PKI and setup complexity.
