# Peer Identity and Reachability Proposal

Status: proposed follow-up design for review before implementation

Related documents:

- `docs/nat-traversal-rendezvous-strategy.md`
- `docs/security-architecture.md`
- `docs/zero-touch-cluster-setup-strategy.md`

## 1. Purpose

Document a cleaner node-to-node transport model where:

- peer identity stays stable and certificate-backed,
- currently reachable addresses are published dynamically,
- direct peer connectivity no longer depends on exposing peer routes on the public listener,
- changing public IP addresses do not force certificate churn.

This document is intentionally a proposal.
It does not describe the current runtime exactly.

## 2. Current model

Today the runtime effectively combines three concerns:

- stable peer identity,
- currently reachable direct addresses,
- listener role selection.

Current direct peer transport uses:

- an internal mTLS listener for node-to-node traffic,
- a public listener for UI, client, and admin traffic,
- an optional `public_peer_api_enabled` mode that also mounts peer routes on the public listener.

Current bootstrap and rendezvous presence publish two endpoint classes:

- `public_url`
- `internal_url`

Current direct HTTPS also relies on ordinary TLS hostname or IP verification, so the certificate SANs must match the address that the caller dials.

That makes the current design workable, but it has two downsides:

1. It overloads the public listener with an optional second role as a peer-to-peer data-plane entrypoint.
2. It ties direct-peer certificate validity to mutable network addressing details.

## 3. Problem statement

For many real deployments, especially home or edge deployments:

- public IP addresses change regularly,
- routers may change port-forwarding targets,
- the externally reachable address for a node is operational data, not identity,
- rendezvous is already present and can distribute fresh reachability data.

In that environment, putting externally reachable peer addresses into node certificates is operationally brittle.

It also obscures the real security question:

- the important property is not "does this certificate match the IP I dialed?"
- the important property is "did I reach the node I intended to reach?"

Those are related in ordinary web PKI, but they do not need to be the same in Ironmesh.

## 4. Proposed model

### 4.1 Stable identity in certificates

Node certificates should carry stable identity claims only:

- `urn:ironmesh:node:<node_id>`
- optionally `urn:ironmesh:cluster:<cluster_id>`

The certificate proves logical identity.
It should not need to prove the node's current public IP address.

Address or DNS SANs may still be present for operator convenience, but they are no longer the primary trust anchor for peer authentication.

### 4.2 Mutable reachability in rendezvous/bootstrap metadata

Reachable addresses become transport metadata rather than identity claims.

Rendezvous presence and bootstrap artifacts should publish one or more peer-reachable candidates such as:

- local/LAN candidate,
- externally reachable NAT-forwarded candidate,
- optional DNS-based candidate,
- relay capability.

These candidates are expected to change over time.
They should be refreshable without rotating the node certificate.

### 4.3 Listener roles

The transport model should converge toward two clear listener roles:

- public listener:
  - UI
  - client API
  - admin API
- peer listener:
  - node-to-node direct transport only
  - mTLS required

That peer listener may still be reachable from outside a NAT through port-forwarding or another published address.
The important change is that external reachability no longer requires mounting peer routes on the public listener.

### 4.4 Direct peer verification

When node A wants to connect directly to node B:

1. node A resolves node B's current candidate addresses from rendezvous or bootstrap metadata,
2. node A dials one candidate,
3. the TLS handshake validates that the certificate chains to the cluster CA,
4. node A extracts `urn:ironmesh:node:<node_id>` from the peer certificate,
5. node A verifies that the presented `node_id` is exactly the expected node B identity.

The dialed address is then treated as a mutable routing hint.
The certificate identity is the stable proof of who answered.

## 5. Why this is security-sound

### 5.1 What address SAN validation gives

Address or DNS SAN validation answers:

- "is this certificate valid for the endpoint name or IP that I dialed?"

That is the normal web-PKI model.

### 5.2 What Ironmesh actually needs

Ironmesh node-to-node transport really needs:

- cluster CA validation,
- expected peer identity validation,
- authorization checks on internal HTTP request paths, for example `/cluster/nodes/{node_id}/heartbeat`, that compare the `{node_id}` in the request path against the node identity proven by the peer certificate.

That means the security-critical question is:

- "did I reach node B?"

not:

- "did I reach whoever currently owns 203.0.113.10:28482?"

If the client explicitly validates the expected `node_id` from the peer certificate, omitting the current address from the certificate is not inherently a security downgrade.

### 5.3 What must not happen

This proposal does **not** mean:

- disabling hostname verification without replacement,
- accepting any certificate signed by the cluster CA regardless of which node it belongs to,
- trusting rendezvous to authenticate peer identity on its own.

The replacement check must be:

- CA-valid cert,
- expected `node_id` SAN present,
- optional cluster binding SAN present and matching.

Without that explicit identity check, removing address SAN validation would weaken security.

## 6. NAT and dynamic-address implications

This proposal fits dynamic residential or edge networking better.

With the proposed model:

- a node certificate can stay stable while the public address changes,
- rendezvous can publish the latest externally reachable candidate,
- dyndns becomes optional convenience rather than a certificate prerequisite,
- the remaining hard problem is pure reachability:
  - port-forwarding,
  - hole punching,
  - or relay fallback.

This does **not** eliminate the need for a reachable path.
It only removes certificate rotation as part of that reachability problem.

## 7. Public peer API impact

Under this proposal, the current `public_peer_api_enabled` path becomes unnecessary.

That flag exists today because the runtime uses the public listener as the only built-in place where a public address can double as a peer endpoint.

After reachability is modeled explicitly, the public listener no longer needs to serve peer routes just to make a node reachable from outside a NAT.

The desired end state is:

- public listener does not expose peer replication or heartbeat routes,
- public listener still serves bootstrap, enrollment, UI, client, and admin flows,
- peer listener can still be published externally through rendezvous as a candidate address,
- relay remains available when no direct candidate works.

## 8. Repo-facing implementation outline

1. Introduce explicit peer reachability metadata separate from `public_url`.
2. Teach bootstrap and rendezvous presence to publish mutable peer candidates.
3. Keep node certificates bound to logical identity, not current address.
4. Add client-side direct-peer verification against expected `node_id` SAN.
5. Keep or add optional cluster-binding SAN validation.
6. Move direct node-to-node traffic fully onto the peer listener.
7. Remove `public_peer_api_enabled` and the public peer route set after migration.

## 9. Current review direction

Based on the current review discussion, the following defaults should be treated as the working direction unless later review finds a strong reason to do something more complex.

1. Peer certificates should start with logical identity SANs only.

  Stable operator-chosen DNS SANs can remain an optional later extension rather than a requirement for the first implementation.

2. Rendezvous presence should be the canonical source of mutable peer candidates.

  Bootstrap may optionally carry seed candidates, but the design should not depend on bootstrap as the long-lived source of truth once rendezvous is reachable.

3. The direct-peer verifier should require both `node_id` and `cluster_id` SANs.

4. The first implementation should use one peer listener.

  If multiple addresses need to be published, they should point at that one listener rather than introducing multiple peer listeners as part of the first cut.

5. The currently known directly affected tests and setup artifacts include the following.

  Unit and bootstrap-shape tests:

  - `crates/server-node-sdk/src/main_tests.rs`: `server_node_config_loads_from_node_bootstrap_file`
  - `crates/server-node-sdk/src/main_tests.rs`: `issue_node_bootstrap_includes_runtime_and_rendezvous_metadata`

  System tests that explicitly enable `IRONMESH_PUBLIC_PEER_API_ENABLED` or depend on bootstrap-issued direct endpoints with usage `PublicApi` for direct-vs-relay behavior:

  Client-side direct-vs-relay tests in this group are only conditionally affected. If bootstrap continues to publish a public client/API endpoint, those tests should keep working because bootstrap issuance and client traffic remain on the public listener. They only need updates if the bootstrap artifact shape or endpoint-usage modeling changes.

  - `tests/system-tests/src/cluster_test.rs`: `read_through_metadata_replication_allows_reads_from_all_five_nodes`
  - `tests/system-tests/src/cluster_test.rs`: `relay_required_rendezvous_cluster_supports_bootstrap_enrollment_and_replication`
  - `tests/system-tests/src/cluster_test.rs`: `bootstrap_client_uses_relay_when_direct_endpoint_is_unreachable`
  - `tests/system-tests/src/cluster_test.rs`: `relay_only_bootstrap_reuses_transport_session_across_multiple_requests`
  - `tests/system-tests/src/cluster_test.rs`: `bootstrap_client_prefers_direct_and_uses_relay_after_rendezvous_restart_and_forced_direct_failure`
  - `tests/system-tests/src/cluster_test.rs`: `relay_required_nodes_reconnect_after_rendezvous_restart_and_replicate`
  - `tests/system-tests/src/cluster_test.rs`: `bootstrap_claim_enrollment_succeeds_via_relay_with_auth_required_node`
  - `tests/system-tests/src/cluster_test.rs`: `bootstrap_claim_enrollment_fails_when_node_not_registered_at_rendezvous`
  - `tests/system-tests/src/web-ui-backend_test.rs`: `web_ui_backend_bootstrap_enroll_default_identity_supports_relay_only_serve_web`

  This is the currently obvious set, not a final migration checklist. Removing server-node public peer routes alone should not break tests that only exercise bootstrap issuance or client access through public API endpoints. The exact final impact depends on whether the migration also changes how bootstrap artifacts model direct endpoints that are currently tagged as `PublicApi`.

## 10. Non-goals

This proposal does not, by itself:

- solve NAT traversal without a reachable path,
- remove the need for relay fallback,
- specify a full QUIC migration,
- replace bootstrap enrollment and trust-root distribution.

It only changes how direct-peer identity and direct-peer reachability are modeled relative to one another.