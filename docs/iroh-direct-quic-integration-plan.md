# iroh Direct QUIC + Hole Punching Integration Plan

Status: proposed follow-up design and implementation plan for review before code changes

Related documents:

- `docs/nat-traversal-rendezvous-strategy.md`
- `docs/nat-traversal-implementation-checklist.md`
- `docs/rendezvous-dynamic-reachability-proposal.md`
- `docs/peer-identity-reachability-proposal.md`
- `docs/transport-multiplexing-checklist.md`
- `docs/security-architecture.md`

## 1. Goal and scope

Integrate `iroh` as IronMesh's first real `DirectQuic` transport so that:

- rendezvous stays the authenticated control plane,
- peers use direct QUIC plus hole punching whenever possible,
- relay remains available as a guaranteed fallback,
- the current rendezvous relay no longer carries the normal high-volume data path,
- the existing HTTP-shaped application semantics stay reusable.

This plan is intentionally **additive**.
Unlike the older replacement-style NAT plan, this work should be rolled out in mixed mode:

- existing direct HTTPS paths keep working,
- the current WebSocket relay tunnel keeps working,
- `iroh` direct QUIC is introduced behind feature flags and path selection,
- rollout can be done across multiple green PRs.

The design decision in this document is:

- use `iroh` for direct point-to-point connectivity and hole punching,
- do **not** replace IronMesh's rendezvous/auth/discovery model with `rust-libp2p`,
- do **not** redesign the application protocol in the first implementation slice.

## 2. Current repo state recap

The current repo already contains most of the control-plane primitives needed for this migration.
The missing piece is the actual direct QUIC transport runtime.

### 2.1 What already exists on `origin/main`

- `crates/rendezvous-server/src/lib.rs` and `crates/transport-sdk/src/rendezvous.rs` already implement:
  - authenticated presence registration,
  - presence listing,
  - dynamic discovery,
  - rendezvous mesh status,
  - relay ticket issuance,
  - relay wake control,
  - server-reflexive candidate synthesis.
- `crates/transport-sdk/src/candidates.rs` and `crates/transport-sdk/src/session.rs` already model:
  - `CandidateKind::DirectQuic`,
  - `TransportPathKind::DirectQuic`,
  - candidate ranking that prefers direct QUIC ahead of direct HTTPS and relay.
- `crates/transport-sdk/src/relay_tunnel.rs`, `src/mux.rs`, and `src/multiplex_transport.rs` already provide:
  - stream multiplexing,
  - transport control handshake,
  - buffered HTTP request/response framing over a generic stream session.
- `crates/server-node-sdk/src/transport_service.rs` already executes buffered transport requests against existing server-node routes.
- `crates/client-sdk/src/session_pool.rs` and `src/ironmesh_client.rs` already support relay-backed multiplexed sessions and bootstrap-driven target planning.
- `apps/rendezvous-service` and `crates/server-node-sdk/src/embedded_rendezvous.rs` already provide:
  - standalone rendezvous deployment,
  - embedded managed rendezvous on the first node,
  - an operator path for multi-rendezvous topologies.

### 2.2 What is missing

- no `iroh` dependency in `crates/transport-sdk`,
- no persistent iroh endpoint secret for nodes or clients,
- no direct QUIC endpoint lifecycle,
- no direct QUIC accept loop on nodes,
- no conversion from rendezvous discovery data into `iroh::EndpointAddr`,
- no direct-path metrics showing direct-versus-relay usage,
- no deployment story for an iroh relay companion,
- no mixed-path rollout plan that keeps relay tunnel and direct HTTPS working while `iroh` is introduced.

### 2.3 Important architectural conclusion

The current relay tunnel transport already proved a key point:

- IronMesh does **not** need a new application protocol to move off HTTP listeners.

The existing buffered transport framing in `crates/transport-sdk/src/multiplex_transport.rs` can be reused on top of iroh bi-streams.
That keeps the first implementation slice narrow:

- new connectivity layer,
- existing request semantics,
- existing auth checks,
- existing route handlers.

## 3. Target architecture

### 3.1 Control plane stays the current rendezvous service

The existing rendezvous service remains the source of truth for:

- authenticated presence,
- peer discovery,
- transport metadata publication,
- relay policy,
- wake or connect-intent hints,
- control-plane health and rollout metrics.

Rendezvous should **not** become an iroh-specific traffic broker for the normal data path.
Its job is coordination, not bulk forwarding.

### 3.2 Direct data plane becomes iroh QUIC

Each node, and later each enrolled client runtime, starts one long-lived `iroh::Endpoint` with:

- a persisted endpoint secret,
- one or more IronMesh ALPNs,
- a configured relay set,
- address publication backed by IronMesh rendezvous,
- accept and dial support for direct QUIC streams.

Direct IronMesh traffic then flows as:

1. peer resolves target transport metadata from rendezvous,
2. peer constructs `iroh::EndpointAddr`,
3. peer dials target `EndpointId` over the IronMesh ALPN,
4. first bi-stream performs the existing transport-session handshake,
5. subsequent streams carry the existing buffered request/response framing,
6. relay tunnel is used only if direct QUIC fails or is unavailable.

### 3.3 Relay hierarchy after the migration

The preferred order should become:

1. `DirectQuic` implemented by `iroh`,
2. existing `DirectHttps` path where it still makes sense,
3. existing rendezvous relay tunnel as last-resort compatibility fallback.

This keeps rollout low-risk:

- direct QUIC is preferred when both sides support it,
- legacy direct HTTPS still covers transitional or operator-managed cases,
- current relay tunnel preserves guaranteed connectivity and mixed-version interoperability.

### 3.4 Why buffered HTTP-over-stream stays in scope

The first iroh slice should reuse the current transport framing instead of inventing a new RPC layer.

Concretely:

- do not rewrite replication or client APIs to a new bespoke QUIC protocol,
- do not move route handling out of `server-node-sdk`,
- wrap iroh bi-streams in the same request/response helpers already used for relay multiplexing.

That keeps the first implementation about connectivity, not application semantics.

## 4. Data model and config changes

### 4.1 Candidate payloads

`crates/transport-sdk/src/candidates.rs` should be extended so `DirectQuic` candidates can carry iroh-specific metadata without overloading older HTTPS callers.

Recommended shape:

```rust
pub struct ConnectionCandidateTransportHints {
    pub transport_id: Option<String>, // iroh EndpointId
    pub relay_url: Option<String>,    // companion relay for this endpoint
    pub alpn: Option<String>,         // e.g. ironmesh/transport/1
    pub direct_addrs: Vec<String>,    // SocketAddr strings or canonical URI form
    pub observed_addrs: Vec<String>,  // addr watcher + rendezvous-observed view
}
```

Recommended candidate encoding:

- keep `kind = direct_quic`,
- set `endpoint` to a canonical transport identifier such as `iroh://<endpoint-id>`,
- use `transport_hints` for the relay URL, ALPN, and direct UDP addresses.

This is preferable to stuffing multiple address classes into one HTTPS-like endpoint string.

### 4.2 Presence and discovery payloads

`crates/transport-sdk/src/rendezvous.rs` should carry explicit direct QUIC transport metadata in:

- `PresenceRegistration`,
- `PresenceEntry`,
- `DiscoveryResponse`.

Recommended additions:

- local `EndpointId`,
- selected home relay URL,
- currently advertised direct UDP addresses,
- last observed external addresses,
- ALPN list,
- transport feature flags,
- freshness timestamp for transport metadata.

Discovery should return enough information to build an `iroh::EndpointAddr` directly from rendezvous data.

### 4.3 Bootstrap artifacts

`crates/transport-sdk/src/bootstrap.rs` should gain explicit direct QUIC policy and relay hints, for example:

- `direct_quic_enabled`,
- `direct_quic_alpns`,
- `direct_quic_relay_urls`,
- optional seed transport candidates for the preferred node set.

Bootstrap does **not** need to become the long-lived source of truth for transport addresses.
It only needs enough data for initial connectivity before rendezvous can provide fresher state.

### 4.4 Persisted runtime identity

Nodes and clients need a second persisted identity alongside their existing IronMesh certificate or credential state:

- IronMesh identity:
  - cluster-scoped node or device identity,
  - existing certificate or signed credential model,
- iroh identity:
  - endpoint secret key,
  - stable `EndpointId`,
  - bound in metadata to the IronMesh identity.

That binding should be stored and revalidated at registration time so that a node cannot publish arbitrary transport IDs for another logical identity.

### 4.5 Admin and metrics views

Admin-visible data should grow to include:

- direct QUIC enabled or disabled,
- local `EndpointId`,
- home relay URL,
- last successful direct connection time,
- current path selected per peer,
- relay fallback reason when direct QUIC was skipped or failed.

## 5. Runtime changes by crate

### 5.1 `crates/transport-sdk`

This crate should own almost all iroh-specific runtime logic.

Recommended additions:

- add the `iroh` dependency,
- add modules such as:
  - `iroh_endpoint.rs`,
  - `iroh_lookup.rs`,
  - `iroh_session.rs`.

Responsibilities:

- create and persist one endpoint per runtime,
- configure relay mode and accepted ALPNs,
- watch endpoint address changes and publish them,
- implement a rendezvous-backed address lookup adapter instead of scattering raw peer addresses through higher layers,
- convert rendezvous discovery responses into `iroh::EndpointAddr`,
- open and accept iroh bi-streams,
- adapt iroh streams into the existing buffered transport helpers,
- expose direct-path diagnostics and connection state to callers.

Important design constraint:

- reuse `BufferedTransportRequest` and `BufferedTransportResponse`,
- do not couple higher layers directly to iroh types.

The higher-layer seam should stay a transport-agnostic "open stream / execute transport request" API.

### 5.2 `crates/rendezvous-server`

This crate remains the control-plane implementation and should be extended to:

- accept direct QUIC transport metadata in presence registration,
- return direct QUIC transport metadata in discovery responses,
- optionally use the existing wake channel to send a "connect intent" hint when a peer is about to dial,
- publish metrics that distinguish direct-capable from relay-only endpoints.

Recommended reuse:

- keep using the existing relay wake WebSocket path instead of inventing a second wake channel,
- keep relay ticket issuance for the old relay tunnel path until mixed rollout is complete.

### 5.3 `apps/rendezvous-service`

The standalone service should gain companion-relay configuration, validation, and health reporting.

Recommended new config items:

- `iroh_relay_public_urls`,
- optional `iroh_relay_bind_addr` for co-located deployments,
- enable or disable flags for direct QUIC advertisement,
- health checks that validate the configured relay companion is reachable.

The standalone service should remain the control-plane process.
It may supervise or describe a companion relay, but the heavy relay data path should not be implemented inside the Axum service itself in the first slice.

### 5.4 `crates/server-node-sdk`

This is the first real consumer of the new direct path.

Required changes:

- create the node's iroh endpoint on startup,
- persist the node's iroh endpoint secret with the existing managed runtime state,
- register transport metadata with rendezvous,
- accept inbound direct QUIC streams on the peer transport ALPN,
- execute buffered transport requests over those streams using the existing `transport_service` logic,
- make peer planning prefer `DirectQuic` when the target has valid transport metadata,
- keep current direct HTTPS and relay tunnel fallbacks.

The first server-node slice should target:

- heartbeat,
- replication,
- reconciliation,
- internal peer API calls already routed through buffered transport.

### 5.5 `crates/client-sdk`

Client runtime changes should come after node-to-node direct QUIC is stable.

Required changes:

- persist a client iroh endpoint secret next to existing client identity material,
- refresh discovery data from rendezvous before falling back to relay,
- build iroh direct sessions for object, metadata, and streaming reads,
- retain the current relay tunnel path for clients without iroh identity or on UDP-hostile networks.

The first client consumers should be:

- CLI bootstrap-driven reads and writes,
- desktop sync runtimes that already use bootstrap-aware clients.

### 5.6 Platform adapters and app wrappers

After `client-sdk` is stable, the platform-specific layers can adopt the new identity handle:

- `apps/cli-client`
- `crates/adapter-windows-cfapi`
- `crates/adapter-linux-fuse`
- `apps/android-app`
- `apps/ios-app`

The key rule is to keep iroh persistence and dialing logic inside Rust crates rather than reimplementing it in each platform wrapper.

## 6. Relay sidecar or companion strategy

### 6.1 Recommended first deployment model

Use an iroh relay **sidecar or companion service** per rendezvous deployment.

That means each control-plane deployment consists of:

- the existing IronMesh rendezvous service for auth, discovery, policy, and wakeups,
- one co-located or explicitly configured iroh relay companion for NAT traversal assistance and relay fallback.

### 6.2 Why sidecar first

Sidecar is the lowest-risk operational model because it:

- keeps heavy UDP and fallback relay traffic out of the Axum control-plane process,
- allows the relay component to scale separately later,
- minimizes IronMesh-specific patches to upstream iroh behavior,
- works for both standalone rendezvous and embedded managed rendezvous,
- lets IronMesh keep its own control-plane authentication and policy boundaries.

### 6.3 Interaction with the current relay tunnel

The current WebSocket relay tunnel should remain in scope during rollout for:

- mixed-version clusters,
- bootstrap claim and enrollment flows that still use HTTPS-facing control paths,
- client runtimes that have not yet adopted iroh,
- emergency fallback and debugging,
- environments where UDP traversal fails consistently.

The target end state is not "delete the current relay immediately".
It is "make its data-volume share small enough that it is no longer the normal path".

### 6.4 Embedded rendezvous implications

Embedded managed rendezvous on the first node should be able to advertise a companion relay as part of the same managed control-plane package, but the relay itself should still be treated as replaceable infrastructure.

Initial practical direction:

- keep embedded rendezvous shipping without mandatory iroh relay,
- enable the iroh companion only for deployments that opt in,
- promote it to the default only after direct-connect metrics are healthy.

## 7. Phased rollout plan

### Phase 0: schema and guardrail groundwork

Scope:

- add direct QUIC transport metadata fields,
- add feature flags and config plumbing,
- document the rollout and metrics,
- keep runtime behavior unchanged.

Exit criteria:

- all new fields are optional,
- relay tunnel and direct HTTPS behavior are unchanged,
- mixed-version tests stay green.

### Phase 1: transport-sdk iroh foundation

Scope:

- add `iroh` to `crates/transport-sdk`,
- create endpoint lifecycle helpers,
- implement discovery-to-`EndpointAddr` conversion,
- implement a stream adapter that reuses buffered transport framing.

Exit criteria:

- local unit tests can dial two in-process endpoints,
- buffered transport request/response works over iroh bi-streams,
- no higher-layer crate is forced to switch yet.

### Phase 2: node-to-node direct QUIC path

Scope:

- start iroh endpoints in `server-node-sdk`,
- register node transport metadata with rendezvous,
- accept inbound direct QUIC peer streams,
- make peer transport prefer `DirectQuic`.

Exit criteria:

- replication, heartbeat, and reconciliation work over direct QUIC in system tests,
- existing relay tunnel fallback still works when direct QUIC fails,
- direct HTTPS remains available for transitional cases.

### Phase 3: companion relay and wake integration

Scope:

- wire companion relay config into standalone and embedded rendezvous,
- publish relay companion health,
- optionally send connect-intent hints via the existing wake channel before dialing.

Exit criteria:

- direct connection latency is acceptable without prolonged relay stickiness,
- operators can see whether a deployment is direct-capable or relay-heavy,
- rendezvous metrics expose companion relay health.

### Phase 4: client adoption

Scope:

- add iroh identity persistence to `client-sdk`,
- move CLI and desktop sync clients onto direct QUIC first,
- keep relay tunnel as transparent fallback.

Exit criteria:

- bootstrap-driven client reads and writes prefer direct QUIC when available,
- client reconnect paths still work after rendezvous restart,
- relay-only environments continue to pass the existing tests.

### Phase 5: cleanup and deprecation

Scope:

- reduce remaining direct HTTPS peer dependencies,
- trim legacy relay-only assumptions from higher layers,
- decide whether `public_peer_api_enabled` can be retired after direct QUIC adoption.

Exit criteria:

- relay bytes are a small minority of total peer traffic,
- mixed-version compatibility window can be closed intentionally,
- the old relay tunnel is no longer the expected normal path.

## 8. Testing plan

### 8.1 Unit tests

Add or extend unit coverage for:

- direct QUIC candidate serialization and validation,
- discovery response merging into planned targets,
- rendezvous-to-`EndpointAddr` conversion,
- ALPN selection and protocol mismatch handling,
- buffered transport over iroh bi-streams,
- fallback ordering from `DirectQuic` to `DirectHttps` to relay.

### 8.2 Crate-level integration tests

Recommended coverage:

- `transport-sdk`
  - two local iroh endpoints exchange buffered transport requests,
  - discovery metadata with relay plus direct addresses is converted correctly,
  - endpoint address changes re-publish cleanly.
- `rendezvous-service`
  - config validation for companion relay URLs,
  - presence and discovery responses include direct QUIC transport metadata,
  - wake path can carry a direct-connect intent.
- `server-node-sdk`
  - presence registration includes direct QUIC metadata,
  - peer planner selects `DirectQuic` when both sides support it,
  - fallback remains relay-safe when the direct attempt fails.

### 8.3 System tests

Add explicit scenarios for:

- two nodes on a reachable network prefer direct QUIC over relay,
- two NATed nodes can connect with hole punching assistance and still fall back cleanly,
- UDP-hostile network conditions force current relay tunnel fallback,
- rendezvous restart does not break existing direct sessions or recovery behavior,
- mixed-capability cluster where one node lacks direct QUIC still replicates correctly,
- bootstrap-driven CLI or desktop client prefers direct QUIC after discovery refresh.

### 8.4 Observability in tests

Tests should assert not only that the operation succeeded, but also which path was used when feasible.

Implementation direction:

- expose direct-versus-relay connection state through transport diagnostics,
- record the selected `TransportPathKind` per session,
- surface per-peer path information in debug endpoints or test-only helpers.

## 9. Rollout metrics and operational gates

### 9.1 Metrics to add

Minimum metrics:

- `ironmesh_direct_quic_connect_total`
- `ironmesh_direct_quic_connect_fail_total`
- `ironmesh_direct_quic_fallback_total`
- `ironmesh_relay_tunnel_session_total`
- `ironmesh_relay_tunnel_bytes_total`
- `ironmesh_iroh_relay_bytes_total`
- `ironmesh_peer_session_path_current`
- `ironmesh_rendezvous_direct_capable_endpoints`
- `ironmesh_rendezvous_relay_only_endpoints`
- `ironmesh_transport_connect_latency_ms`

### 9.2 Operator-facing ratios

Track at least these rollout ratios:

- direct connect ratio,
- relay bytes ratio,
- direct QUIC success ratio after discovery refresh,
- reconnect success ratio after rendezvous restart,
- percentage of peers with stale or missing direct QUIC metadata.

### 9.3 Rollout gates

Do not make direct QUIC the default everywhere until:

- direct success ratio is healthy in system and staging environments,
- relay bytes are measurably reduced,
- fallback rate is stable and understood,
- no regression is observed in bootstrap enrollment or rendezvous restart recovery.

## 10. Suggested PR slicing

These slices are intentionally mergeable on their own.

### PR 1: schema and docs groundwork

Scope:

- candidate metadata extensions,
- rendezvous payload shape extensions behind optional fields,
- docs and config comments,
- no runtime path switch.

### PR 2: transport-sdk iroh runtime

Scope:

- `iroh` dependency,
- endpoint lifecycle,
- address lookup integration,
- buffered transport over iroh bi-streams,
- crate-local tests only.

### PR 3: server-node direct QUIC

Scope:

- node endpoint startup and persistence,
- presence registration for transport metadata,
- direct QUIC accept and dial for peer traffic,
- fallback to existing relay or HTTPS paths.

### PR 4: rendezvous companion and metrics

Scope:

- standalone and embedded config for companion relay,
- wake or connect-intent integration,
- direct-versus-relay metrics and admin views.

### PR 5: client-sdk and CLI or desktop adoption

Scope:

- client iroh identity persistence,
- discovery refresh before relay fallback,
- direct QUIC for bootstrap-aware clients,
- mixed-path system tests.

### PR 6: cleanup and deprecation

Scope:

- remove dead legacy assumptions,
- reduce direct HTTPS peer dependency,
- decide whether the old public peer API path can be retired.

## 11. Risks, open questions, and non-goals

### 11.1 Main risks

- mixed rollout complexity is real: relay tunnel, direct HTTPS, and direct QUIC must coexist for a while,
- iroh identity adds another persisted secret that must be backed up and rotated correctly,
- operator deployments that only allow TCP may see little direct-connect benefit until fallback logic is well tuned,
- embedded managed rendezvous plus companion relay packaging may be operationally heavier than the current single-process story.

### 11.2 Open questions

- Should the first implementation publish one ALPN or separate client and peer ALPNs?
- Should client runtimes get a long-lived iroh identity immediately, or only after node-to-node rollout is stable?
- Should the companion relay be an external operator-managed dependency first, before embedded management is attempted?
- How much of direct QUIC path state should be visible in the admin UI versus debug-only endpoints?

### 11.3 Non-goals for the first slice

- replacing the existing rendezvous control plane,
- rewriting IronMesh's public API to a custom QUIC-native RPC protocol,
- deleting the current relay tunnel before mixed rollout is proven,
- introducing a broader `rust-libp2p` swarm architecture.

## 12. External references

- `iroh` crate docs: <https://docs.rs/iroh/latest/iroh/>
- `iroh::Endpoint` docs: <https://docs.rs/iroh/latest/iroh/endpoint/struct.Endpoint.html>
- `iroh::endpoint::Builder` docs: <https://docs.rs/iroh/latest/iroh/endpoint/struct.Builder.html>
