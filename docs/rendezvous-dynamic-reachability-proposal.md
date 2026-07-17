# Dynamic Reachability Discovery for Rendezvous Services

Status: proposed follow-up design for review before implementation

Related documents:

- `docs/nat-traversal-rendezvous-strategy.md`
- `docs/iroh-direct-quic-integration-plan.md`
- `docs/peer-identity-reachability-proposal.md`
- `docs/security-architecture.md`

## 1. Purpose

Give rendezvous services a way to dynamically track which server nodes and
which peer rendezvous services are currently reachable, and let clients pull
that dynamic list from any rendezvous service they already trust, instead of
being limited to the static endpoint list captured in their bootstrap bundle
at enrollment time.

Two distinct reachability problems are in scope:

- **client/node -> server node**: is a target server node currently
  reachable, and through which candidate address?
- **client/node -> rendezvous service**: which rendezvous services are
  currently part of the mesh and answering, beyond the seed URLs a client
  happened to enroll with?

Terminology note: the request that produced this document used the word
"Grundniveauservices" for the services a client asks for the dynamic list.
That was a speech-recognition artifact for "rendezvous services" -- this
design introduces no new service tier. The seed set is exactly the existing
`rendezvous_urls` a client already has (from `ConnectionBootstrap` /
`ClientBootstrapClaim`).

## 2. Current model (recap)

- Server nodes hold an outbound control connection to every configured
  rendezvous URL and periodically call `register_presence`
  (`crates/rendezvous-server/src/lib.rs:137`), self-reporting
  `public_api_url`, `peer_api_url`, `direct_candidates`, capacity/labels, and
  `relay_mode`. This is a **passive, outbound-only** model by design -- see
  `docs/nat-traversal-rendezvous-strategy.md` section 6.3 -- because many
  nodes sit behind NAT without port-forwarding and cannot be dialed
  arbitrarily.
- Other server nodes call `list_presence` on an interval
  (`crates/server-node-sdk/src/lib.rs:6895`, `spawn_rendezvous_peer_discovery`)
  to discover peers for replication/heartbeat traffic. This endpoint requires
  an authenticated **node** certificate today
  (`require_authenticated_node` in `crates/rendezvous-server/src/auth.rs:50`
  explicitly rejects `PeerIdentity::Device`).
- `ConnectionCandidate` (`crates/transport-sdk/src/candidates.rs`) already
  models a ranked candidate list with kinds `DirectQuic > DirectHttps >
  ServerReflexiveQuic > Relay`. `ServerReflexiveQuic` is defined but never
  produced anywhere in the codebase today -- it is effectively a reserved
  slot for exactly the "address as observed by a third party" (STUN-style)
  concept this proposal implements.
- Rendezvous services have no concept of other rendezvous services. Multi-
  rendezvous redundancy today is limited to: a client trying each of its
  static `rendezvous_urls` in order (`RendezvousControlClient` in
  `crates/transport-sdk/src/rendezvous_runtime.rs`), and the encrypted
  failover package mechanism in `apps/rendezvous-service/src/failover.rs`
  for manually promoting a standby to take over a node's identity. Neither
  gives a rendezvous service live knowledge of its peers.
- Client-sdk (`crates/client-sdk/src/bootstrap.rs`) resolves connection
  targets purely from the static bootstrap bundle
  (`direct_endpoints` + `rendezvous_urls`) via `planned_targets()`. It never
  queries rendezvous for fresher candidates at connect time.

## 3. Decisions already made (from clarification with the user)

These resolve what would otherwise be open questions and constrain the
design below:

1. **No active dialing of server nodes.** Reachability of a server node is
   never determined by the rendezvous service opening an outbound
   connection to a configured IP. It stays passive: rendezvous only learns
   about a node through that node's own outbound control connection.
   Verifying that a candidate address actually works is the connecting
   client's job (it already does this via
   `probe_direct_http_target_blocking` / the direct-then-relay fallback in
   `planned_targets()`).
2. **New signal: connection-origin IP.** When a server node's outbound
   control connection reaches the rendezvous service, the rendezvous
   service records the *observed source IP* of that TCP connection. This is
   new information the node itself cannot know (it doesn't know its own
   NAT-mapped public IP). Combined with the node's self-reported listening
   port, this produces a server-reflexive candidate: if the node's router
   happens to port-forward that port, a client can connect directly.
3. **Rendezvous-to-rendezvous reachability uses active probing.** Unlike
   server nodes, rendezvous services are expected to have stable, publicly
   reachable addresses (this is already assumed by `rendezvous_urls` /
   `relay_public_urls` today). So each rendezvous service is given a
   configured list of peer rendezvous URLs and actively health-checks them.
4. **Scope**: rendezvous-mesh reachability (active) + server-node presence
   (passive, enhanced with the observed-IP candidate). No new
   server-node-to-server-node active probing list.

## 4. Proposed model

### 4.1 Server-node reachability: passive, rendezvous-observed candidate

**Capture.** The rendezvous service already distinguishes the mTLS path
(`MtlsAuthenticatedPeerAcceptor` in `crates/rendezvous-server/src/auth.rs`)
from the plain-HTTP dev path (`axum::serve` in `crates/rendezvous-server/src/lib.rs:122`).
Extend both to inject the raw TCP peer `SocketAddr` as a request extension,
the same way `AuthenticatedPeer` is injected today:

- mTLS path: capture `stream.peer_addr()` in `MtlsAuthenticatedPeerAcceptor::accept`
  before the TLS handshake, alongside the existing `authenticated_peer_from_tls_stream` call.
- plain-HTTP path: switch `axum::serve(listener, app)` to
  `axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())`
  and read it via axum's built-in `ConnectInfo<SocketAddr>` extractor.

A new extractor (or a small enum wrapping both sources) gives
`register_presence` access to `observed_source_addr: SocketAddr`.

**Storage.** Add `observed_source_addr: Option<SocketAddr>` to `PresenceEntry`
(`crates/transport-sdk/src/rendezvous.rs`) -- *not* to `PresenceRegistration`,
because it is server-injected metadata, never client-supplied.
`PresenceRegistry::register` (`crates/transport-sdk/src/rendezvous_runtime.rs:35`)
takes the observed addr as a parameter alongside the registration and stores
it on the entry, refreshed every heartbeat re-registration (interval already
governed by `RENDEZVOUS_REGISTRATION_RETRY_INTERVAL_SECS` in
`crates/server-node-sdk/src/lib.rs`).

**Candidate synthesis.** When building a `PresenceEntry` response (both in
`register_presence`'s response and in `list_presence`), if
`observed_source_addr` is present and the registration carries a
`peer_api_url` (or `public_api_url`) with a port, synthesize one extra
`ConnectionCandidate`:

```
ConnectionCandidate {
    kind: CandidateKind::ServerReflexive,
    endpoint: "https://<observed_ip>:<self_reported_port>",
    rtt_ms: None,
}
```

**Naming decision**: rename `CandidateKind::ServerReflexiveQuic` to a
generic `ServerReflexive` (drop the QUIC coupling). It is unused anywhere
today, so this is a safe rename, and the resulting candidate applies
equally to the HTTPS control-channel case here and to a future QUIC
reflexive candidate. Its existing rank position (`DirectHttps` < candidate
< `Relay`) is already exactly the right place: self-reported direct
addresses are tried first, the unverified rendezvous-observed guess next,
relay last.

**Consumption.** `apply_rendezvous_presence_entries` in
`crates/server-node-sdk/src/lib.rs` (used by the existing peer-discovery
loop for node-to-node connectivity) picks up the new candidate for free
once it's part of `PresenceEntry.registration.direct_candidates` at the
point of serialization -- no consumer-side change needed for node-to-node.
Client-side consumption is new; see 4.3.

### 4.2 Rendezvous-to-rendezvous mesh reachability: active probing

**Config.** Add `peer_rendezvous_urls: Vec<String>` to
`RendezvousServiceConfig` (`apps/rendezvous-service/src/config.rs`), parsed
from a new `IRONMESH_RENDEZVOUS_PEER_URLS` env var using the same
comma-split pattern already used for `IRONMESH_RELAY_PUBLIC_URLS`
(`config.rs:147-157`).

**Probing.** Reuse, don't reinvent: `RendezvousControlClient` in
`crates/transport-sdk/src/rendezvous_runtime.rs` already implements exactly
this pattern (`probe_health_endpoints`, `RendezvousEndpointStatus`,
`TrackedRendezvousRuntimeState` with consecutive-failure tracking) for
clients probing their configured rendezvous URLs. Give
`RendezvousAppState` (`crates/rendezvous-server/src/lib.rs:70`) an instance
of the same client, constructed from `peer_rendezvous_urls`, and spawn a
background task in `serve()` that calls `probe_health_endpoints()` on an
interval (default matching the existing presence heartbeat cadence, ~15s)
and keeps the resulting `RendezvousRuntimeState` in `RendezvousAppState`.

**Exposure.** New endpoint `GET /control/mesh` returning the current
`RendezvousRuntimeState` (peer URL, connected/disconnected,
last_success_unix, consecutive_failures). Same auth policy as
`/control/presence` today, widened per 4.3.

### 4.3 Dynamic discovery for clients

**New endpoint**, `GET /control/discovery?node_id=<uuid>` (node_id optional):

```
struct DiscoveryResponse {
    rendezvous_peers: Vec<RendezvousEndpointStatus>,   // from 4.2
    node_candidates: Option<Vec<ConnectionCandidate>>, // populated when node_id given and known
    node_relay_capable: bool,
}
```

`node_candidates` is `PresenceRegistry::entry_for_identity(Node(node_id))`'s
`direct_candidates` plus the synthesized server-reflexive candidate from
4.1, ranked with the existing `rank_candidates`.

**Auth.** `list_presence` and the new `/control/mesh` and
`/control/discovery` endpoints currently would reject device certificates
via `require_authenticated_node`. Add `require_any_authenticated_peer`
(accepts `Node` or `Device`) and use it for these three read endpoints
instead. `/control/discovery` intentionally returns less than the raw
`/control/presence` dump (no `capacity_bytes`, `free_bytes`, `labels`) since
it is meant for device clients, which should not need node operational
metadata.

**Client-sdk integration.** `crates/client-sdk` already builds a
`RendezvousControlClient` in `connection.rs` / `ironmesh_client.rs` /
`session_pool.rs` for relay use. Add
`RendezvousControlClient::fetch_discovery(node_id)` (mirrors the existing
`list_presence`/`issue_relay_ticket` methods, same multi-URL fallback loop).

Wire this into `ConnectionBootstrap` as an **additive, opt-in refresh step**,
not a change to the default `planned_targets()` behavior (that function and
its ordering are covered by a large existing test suite -- see
`docs/peer-identity-reachability-proposal.md` section 9.5 for the list of
tests already sensitive to target-shape changes). Concretely:

- Add `ConnectionBootstrap::refresh_dynamic_targets_blocking(&self) -> Result<Vec<PlannedConnectionBootstrapTarget>>`
  that calls discovery against each configured `rendezvous_urls` entry,
  merges any new candidates into a fresh set of planned targets (bootstrap's
  static `direct_endpoints` first, then rendezvous-observed candidates,
  then relay), and returns them without mutating the bootstrap object.
- Callers (CLI, desktop, mobile) opt into calling this before connecting,
  or on reconnect-after-failure, rather than it being silently inserted
  into `build_client()` / `build_client_with_identity()`.
- Also add discovery of fresh `rendezvous_urls` themselves (from
  `rendezvous_peers` in the response) so a client whose original seed
  rendezvous URLs later change topology can still find a live one, as long
  as at least one originally-bootstrapped URL still answers.

## 5. Security considerations

- The observed-source-IP candidate is *never* trusted as identity. Exactly
  as in `docs/peer-identity-reachability-proposal.md` section 4.4/5.2: a
  client that dials the reflexive candidate still validates the peer's
  `node_id`/`cluster_id` via mTLS SAN before treating the connection as
  authentic. This proposal only adds a routing hint, never a trust
  decision.
- A rendezvous service reporting a node's observed IP to other cluster
  members is a modest new information disclosure (previously only
  self-reported URLs were shared). Scope stays inside the cluster: only
  authenticated node/device identities of the same cluster can call the
  endpoints that expose it, matching existing `/control/presence`
  authorization.
- `/control/discovery` deliberately narrows the payload for device callers
  (no capacity/labels) to avoid handing operational cluster metadata to
  every enrolled device, addressing the disclosure widening from relaxing
  `require_authenticated_node` to `require_any_authenticated_peer`.
- Mesh probing (4.2) only reaches URLs the rendezvous operator explicitly
  configured (`peer_rendezvous_urls`), never client-supplied addresses, so
  it cannot be used as an SSRF vector.

## 6. Repo-facing changes checklist

1. `crates/transport-sdk/src/candidates.rs`: rename `ServerReflexiveQuic` -> `ServerReflexive`.
2. `crates/transport-sdk/src/rendezvous.rs`: add `observed_source_addr` to `PresenceEntry`; add `DiscoveryResponse` / reuse `RendezvousEndpointStatus`.
3. `crates/transport-sdk/src/rendezvous_runtime.rs`: `PresenceRegistry::register` takes observed addr; add `fetch_discovery` to `RendezvousControlClient`.
4. `crates/rendezvous-server/src/auth.rs`: add `require_any_authenticated_peer`; capture peer `SocketAddr` in `MtlsAuthenticatedPeerAcceptor` and the plain-HTTP `axum::serve` path.
5. `crates/rendezvous-server/src/lib.rs`: `RendezvousAppState` gains a mesh-probing `RendezvousControlClient` + background task; new `/control/mesh` and `/control/discovery` routes; candidate synthesis in `register_presence`/`list_presence`.
6. `apps/rendezvous-service/src/config.rs`: `peer_rendezvous_urls` from `IRONMESH_RENDEZVOUS_PEER_URLS`.
7. `crates/client-sdk/src/bootstrap.rs`: `refresh_dynamic_targets_blocking`.
8. Debian/deploy artifacts (`debian/ironmesh-rendezvous-service.env`, `scripts/deploy-rendezvous-service.sh`): document the new env var.
9. System tests: extend `tests/system-tests/src/cluster_test.rs` (mesh probing between rendezvous instances, reflexive-candidate propagation) and add a client-facing discovery test alongside the existing `cli_managed_rendezvous_latency_test.rs` / `cli_latency_test.rs` added on this branch's parent.

## 7. Suggested implementation phases

1. Server-reflexive candidate: capture + storage + synthesis + rename (items 1-2-3 partial, 4 partial, 5 partial). No new endpoints yet; verify via existing `list_presence` test coverage in `crates/server-node-sdk/src/main_tests.rs`.
2. Rendezvous mesh probing: config + background probing + `/control/mesh` (items 5-6).
3. Client-facing `/control/discovery` + auth widening (items 4-5 remainder).
4. Client-sdk `fetch_discovery` + `refresh_dynamic_targets_blocking`, wired into at least the CLI as the first consumer (item 7).
5. Docs + deploy + system tests (items 8-9).

Each phase is independently mergeable and independently testable; phase 1
alone already delivers value (better direct-connect odds for port-forwarded
home deployments) without touching client-sdk or auth.

## 8. Non-goals

- No STUN/TURN protocol, no UDP hole punching. This only adds an
  HTTPS-reachable reflexive candidate, consistent with the transport model
  in `docs/nat-traversal-rendezvous-strategy.md`.
- No automatic re-election of a "primary" rendezvous service. Mesh
  reachability is informational for clients choosing which URL to try; it
  does not change the existing failover-package-based promotion flow in
  `apps/rendezvous-service/src/failover.rs`.
- No change to how server nodes discover *each other* beyond picking up the
  new candidate kind for free through the existing `list_presence` peer
  discovery loop.
