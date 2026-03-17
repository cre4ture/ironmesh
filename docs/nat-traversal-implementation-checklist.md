# NAT Traversal Implementation Checklist

Status: Concrete repo-mapped implementation plan for the target architecture

## 1. Ground rules

- This is a direct replacement plan, not a migration plan.
- We do not need mixed-version compatibility.
- We do not need to preserve old bootstrap schemas, old auth material, or old direct-only peer registration flows.
- Keep the current HTTP API semantics where useful, but stop treating a static `base_url` as the transport abstraction.

## 1a. Lifecycle guidance

- Node enrollment is the supported production lifecycle path for server nodes.
- Production expectations for certificate issuance, renewal, live TLS reload, and live trust-root updates are centered on the enrollment artifact path.
- Direct env/file CA wiring is still useful for development, testing, externally managed certificates, or other short-lived/manual setups.
- When trust roots change in that direct env/file path, a node restart is acceptable and may be required; live trust-root reload is not a primary design goal there.

## 1b. Current priority order

Use this section as the current source of truth for remaining work. The detailed checklist below still contains older task wording and should be reconciled over time.

1. Client transport target model and relay-capable client sessions. Status: in progress.
   The first slices are now in place: client bootstrap can plan ordered direct-vs-relay targets, direct-only callers use an explicit `resolve_direct_http_target_blocking()` helper instead of treating `resolve_blocking()` as the primary abstraction, issued bootstrap endpoints now carry the owning `node_id` so relay-planned client targets are identity-bound rather than anonymous URLs, `IronMeshClient` can execute relay-backed requests through rendezvous for the non-mTLS client path, enrolled client devices can now use relay against an mTLS-required rendezvous service when enrollment provided a rendezvous client TLS identity, the shared sync-agent plus Linux FUSE startup paths can now build clients directly from bootstrap artifacts instead of collapsing them to one direct URL up front, Linux FUSE now only resolves a direct upstream URL when `--local-edge` actually needs one, Windows CFAPI now preserves bootstrap metadata and builds its runtime fetcher/hydrator/uploader from a bootstrap-aware client rather than re-resolving everything to a direct URL, Android now persists bootstrap plus client identity material and uses bootstrap-aware clients for object operations, folder sync, SAF access, and the embedded web UI, the iOS wrapper now accepts the same bootstrap-or-direct connection input shape, normal CLI data plus read-only commands use the shared bootstrap-aware client transport instead of raw direct `reqwest` calls, the embedded web UI backend now runs on top of `IronMeshClient` so CLI and Android `serve-web` flows can use relay-capable client transport too, and the remaining `client-sdk` convenience types like remote snapshot fetchers and content-addressed caches now also have bootstrap-aware constructors instead of only `base_url` entry points.
   Remaining work: reduce the remaining direct-resolution compatibility paths and helper APIs in `client-sdk` and the smaller direct-only convenience layers that still exist outside the main app/runtime flows. The most notable intentional exception is `--local-edge` style upstream wiring, which still depends on the server-node side retiring `upstream_public_url`.
2. Remove the legacy direct-upstream path from server-node.
   Remaining work: retire `IRONMESH_UPSTREAM_PUBLIC_URL`, `upstream_public_url`, and `refresh_upstream_peer(...)` once rendezvous-first startup is the only supported peer discovery path.
3. Finish removing `base_url` plus `device_token`-shaped app models.
   Remaining work: clean up the remaining compatibility surfaces in `client-sdk` and helper apps so persisted client state is identity-first rather than URL-plus-token-first. Android, Windows, and the iOS wrapper are now on bootstrap-aware connection inputs.
4. Replace the old reachability model in cluster state.
   Remaining work: stop projecting everything into `NodeDescriptor { public_url, internal_url, ... }` and move to stable identity plus dynamic reachability/capability records.
5. Refresh tests and operational docs to match the real implementation state.
   Remaining work: reconcile this checklist with completed work, add outbound-only system scenarios, and keep platform-facing docs aligned with the new enrollment and transport model.

## 2. Target workspace shape

Update the root workspace in `Cargo.toml`:

- add `crates/transport-sdk`
- add `apps/rendezvous-service`

Add shared workspace dependencies in `Cargo.toml` for the new transport layer:

- a QUIC implementation
- `hyper` / `hyper-util` / `http-body-util` for HTTP over custom connectors
- an async WebSocket stack for the rendezvous control channel
- `futures-util`

Keep existing `rustls`, `tokio`, `serde`, `bytes`, and `uuid` usage.

## 3. Critical refactor to make first

The current codebase assumes:

- `client-sdk::IronMeshClient` talks to one `server_base_url`
- peer traffic uses `reqwest::Client`
- bootstrap resolution chooses one direct endpoint up front

That is not enough for relay-backed end-to-end sessions.

Target decision:

- keep HTTP as the application protocol,
- replace direct `reqwest + base_url` assumptions for peer and client data-plane traffic with a transport-aware HTTP client built on top of session-capable connectors,
- keep `reqwest` only where plain direct HTTP(S) still makes sense and no relay/session plumbing is needed.

In practice, this means the peer/client transport work should land before large API rewrites in higher layers.

## 4. Current surface to target surface mapping

| Current owner | Current type or API | Target replacement | Why |
| --- | --- | --- | --- |
| `crates/client-sdk/src/bootstrap.rs` | `ConnectionBootstrap` | `transport_sdk::bootstrap::ClientBootstrap` | Bootstrap becomes rendezvous-aware and no longer resolves to one fixed endpoint. |
| `crates/client-sdk/src/bootstrap.rs` | `ResolvedConnectionBootstrap` | Remove; replace with dynamic session setup in `transport-sdk` | Resolution is now path selection plus session establishment, not one URL probe. |
| `crates/client-sdk/src/bootstrap.rs` | `BootstrapEnrollmentResult` | `EnrolledClientIdentity` | Enrollment should return key-bound identity material, not a bearer token plus URL. |
| `crates/client-sdk/src/device_auth.rs` | `DeviceEnrollmentRequest` / `DeviceEnrollmentResponse` | CSR or public-key enrollment request and signed credential response | Pairing remains enrollment-only. |
| `crates/client-sdk/src/ironmesh_client.rs` | `IronMeshClient { http, server_base_url, bearer_token }` | `IronMeshClient { transport, target, client_identity }` | The client must choose direct or relay paths per session. |
| `crates/client-sdk/src/client_node.rs` | `ClientNode::new(server_base_url)` | `ClientNode::new(transport_handle, target)` | High-level API can stay, constructor contract changes. |
| `crates/server-node-sdk/src/lib.rs` | `ServerNodeConfig` | `ServerNodeConfig` with rendezvous, relay, cluster, and node-identity settings | Static upstream URL is replaced by control-plane connectivity. |
| `crates/server-node-sdk/src/lib.rs` | `ServerState::internal_http: reqwest::Client` | `ServerState::peer_transport: transport_sdk::peer::PeerTransportClient` | Peer traffic must run over direct or relayed sessions. |
| `crates/server-node-sdk/src/cluster.rs` | `NodeDescriptor { public_url, internal_url, ... }` | `NodeRecord { identity, reachability, capabilities, labels, capacity }` | Reachability is dynamic and may include relay-only presence. |
| `crates/server-node-sdk/src/lib.rs` | `BootstrapBundleIssueResponse` | `ClientBootstrap` issued directly from server-node | One bootstrap schema across the stack. |
| `crates/server-node-sdk/src/storage.rs` | `DeviceAuthRecord { token_hash, ... }` | `ClientCredentialRecord { public_key or cert fingerprint, ... }` | Long-lived bearer tokens are no longer the main trust artifact. |
| `crates/adapter-windows-cfapi/src/connection_config.rs` | direct base URL + pairing bootstrap resolution | bootstrap-driven transport config | Windows adapter should consume the same transport stack as other clients. |
| `apps/android-app/src/lib.rs` | JNI functions taking `base_url`, `server_ca_pem`, `auth_token` | JNI functions taking bootstrap or persisted client identity handle | Mobile bindings should stop wiring direct URL and bearer token everywhere. |
| `apps/cli-client/src/main.rs` | `--server-url` | `--bootstrap` or `--rendezvous-url` based startup | CLI should exercise the same connection model as real clients. |

## 5. New crate layout

### `crates/transport-sdk`

Create these modules:

- `bootstrap.rs`
- `identity.rs`
- `rendezvous.rs`
- `relay.rs`
- `candidates.rs`
- `session.rs`
- `peer.rs`
- `http_connector.rs`

Recommended responsibilities:

- `bootstrap.rs`
  - `ClientBootstrap`
  - `NodeBootstrap`
  - `RelayMode`
  - bootstrap validation and JSON serialization
- `identity.rs`
  - device keypair generation
  - CSR or signed-public-key request building
  - credential parsing and persistence helpers
- `rendezvous.rs`
  - outbound control-channel client
  - presence registration
  - candidate exchange
  - relay ticket acquisition
- `relay.rs`
  - tunnel setup
  - stream multiplexing
  - quota and authorization metadata
- `candidates.rs`
  - direct endpoint candidates
  - server-reflexive candidates
  - path ranking input
- `session.rs`
  - authenticated peer session state
  - direct-vs-relay selection
  - reconnect and retry policy
- `peer.rs`
  - `PeerTransportClient`
  - connect-to-node and connect-to-service APIs
- `http_connector.rs`
  - custom connector to run HTTP over transport sessions
  - shared client builder for `client-sdk` and `server-node-sdk`

### `apps/rendezvous-service`

Create:

- `src/main.rs`
- `src/config.rs`
- `src/auth.rs`
- `src/presence.rs`
- `src/control.rs`
- `src/relay.rs`
- `src/state.rs`

Recommended responsibilities:

- authenticate node and client identities
- maintain live endpoint presence
- exchange candidates
- issue relay tickets
- bridge relay streams without terminating inner end-to-end peer security

## 6. Concrete file-by-file checklist

### Root workspace

- [ ] Update `Cargo.toml` workspace members to include `crates/transport-sdk` and `apps/rendezvous-service`.
- [ ] Add shared transport dependencies to root `Cargo.toml`.

### `crates/common`

- [ ] Add `ClusterId` and `DeviceId` aliases or newtypes in `crates/common/src/lib.rs`.
- [ ] Add small shared enums only if they are used across multiple crates and are not transport-internal.

### `crates/client-sdk`

- [ ] Replace `crates/client-sdk/src/bootstrap.rs` with a bootstrap schema that includes `cluster_id`, `rendezvous_urls`, direct endpoint hints, relay policy, and trust roots.
- [ ] Remove `resolve_blocking()` as the primary connection model.
- [ ] Replace `crates/client-sdk/src/device_auth.rs` token enrollment with keypair-based enrollment.
- [ ] Replace `BootstrapEnrollmentResult.device_token` with signed credential material or credential references.
- [ ] Refactor `crates/client-sdk/src/connection.rs` so it creates transport-aware clients instead of direct `reqwest` clients from one base URL.
- [ ] Refactor `crates/client-sdk/src/ironmesh_client.rs` to depend on a transport handle plus logical target, not `server_base_url` plus bearer token.
- [ ] Refactor `crates/client-sdk/src/client_node.rs` constructors to take the new transport-aware client setup.
- [ ] Re-export transport bootstrap and identity types from `crates/client-sdk/src/lib.rs` only if that keeps app code simpler.

### `crates/server-node-sdk`

- [ ] Extend `crates/server-node-sdk/src/lib.rs::ServerNodeConfig` with `cluster_id`, rendezvous URLs, relay policy, and node-identity configuration.
- [ ] Replace `IRONMESH_UPSTREAM_PUBLIC_URL`-driven logic with rendezvous registration and peer discovery.
- [ ] Replace `ServerState::internal_http` with a transport-aware peer client.
- [ ] Replace `refresh_upstream_peer`, `spawn_upstream_peer_bootstrap`, and related direct-upstream refresh logic with persistent rendezvous presence and peer session management.
- [ ] Replace `RegisterNodeRequest` in `crates/server-node-sdk/src/lib.rs` so admin registration manages policy/labels, not direct reachability coordinates.
- [ ] Replace `BootstrapBundleIssueResponse` with the final bootstrap schema emitted directly by `/auth/bootstrap-bundles/issue`.
- [ ] Replace `ClientDeviceEnrollRequest` / `ClientDeviceEnrollResponse` with key-bound client enrollment.
- [ ] Replace `require_client_auth()` so it verifies proof-of-possession credentials instead of matching a bearer token hash.
- [ ] Update peer heartbeat and replication callers to use the new peer transport layer instead of direct `reqwest`.

### `crates/server-node-sdk/src/cluster.rs`

- [ ] Replace `NodeDescriptor` with a record that separates stable identity from current reachability.
- [ ] Keep labels, capacity, and status.
- [ ] Replace raw `public_url` / `internal_url` assumptions with a reachability structure that can represent:
  - direct public API URLs,
  - direct peer candidates,
  - relay-required state,
  - current rendezvous presence.

### `crates/server-node-sdk/src/storage.rs`

- [ ] Replace `ClientAuthState`, `PairingTokenRecord`, and `DeviceAuthRecord` with:
  - pairing records for one-time enrollment authorization,
  - persisted client credential records bound to public keys or certificate fingerprints,
  - revocation metadata for client identities.

### `apps/server-node`

- [ ] Keep `apps/server-node/src/main.rs` thin.
- [ ] Ensure the new rendezvous-related env vars are documented and wired through `server_node_sdk::run_from_env()`.

### `apps/cli-client`

- [x] Update normal CLI data and read-only commands to use bootstrap-aware client construction instead of resolving one direct URL up front.
- [ ] Replace `--server-url` in `apps/cli-client/src/main.rs` with bootstrap- or rendezvous-based startup inputs.
- [x] Update `serve-web` wiring so the embedded web UI also talks through the new client transport stack.

### `crates/adapter-windows-cfapi`

- [x] Replace `crates/adapter-windows-cfapi/src/connection_config.rs` so it resolves bootstrap into transport configuration rather than a single resolved URL.
- [x] Replace `crates/adapter-windows-cfapi/src/auth.rs` persisted `device_token` model with persisted client identity material.
- [x] Update `crates/adapter-windows-cfapi/src/cli.rs` and `crates/adapter-windows-cfapi/src/serve.rs` to stop threading `base_url + bearer_token`.

### `apps/android-app`

- [x] Replace `apps/android-app/src/lib.rs` JNI APIs that currently take `base_url`, `server_ca_pem`, and `auth_token` with bootstrap- or identity-based configuration.
- [x] Replace `BootstrapEnrollmentResult` handling so Android persists client identity material, not a device token.
- [x] Update `apps/android-app/app/src/main/java/io/ironmesh/android/data/IronmeshRepository.kt` data models to store rendezvous/bootstrap identity state instead of `server_base_url + device_token`.

### `crates/server-node-sdk/src/ui`

- [ ] Update `crates/server-node-sdk/src/ui/app.js` and `crates/server-node-sdk/src/ui/index.html` so bootstrap downloads and setup instructions reflect the new bootstrap schema and identity model.

### `crates/web-ui-backend`

- [x] Refactor `crates/web-ui-backend/src/lib.rs` so it can run on top of a prepared `IronMeshClient` instead of requiring a direct-only resolved server URL.

## 7. Environment variable changes

Add to `crates/server-node-sdk/src/lib.rs::ServerNodeConfig::from_env()`:

- `IRONMESH_CLUSTER_ID`
- `IRONMESH_CLUSTER_CA_CERT`
- `IRONMESH_RENDEZVOUS_URLS`
- `IRONMESH_RELAY_MODE`
- `IRONMESH_NODE_CERT`
- `IRONMESH_NODE_KEY`

Keep only if still useful:

- `IRONMESH_SERVER_BIND`
- `IRONMESH_PUBLIC_URL`
- `IRONMESH_PUBLIC_TLS_CERT`
- `IRONMESH_PUBLIC_TLS_KEY`
- `IRONMESH_PUBLIC_TLS_CA_CERT`

Delete or replace:

- `IRONMESH_UPSTREAM_PUBLIC_URL`
- any env whose only purpose is direct one-upstream peering

## 8. Suggested engineering order

This is implementation order, not product rollout order.

1. Create `crates/transport-sdk` and land bootstrap, identity, rendezvous control client, and transport session primitives.
2. Create `apps/rendezvous-service` with authenticated presence plus relay tickets.
3. Replace node registration and peer transport in `server-node-sdk`.
4. Replace client bootstrap and enrollment in `client-sdk`.
5. Refactor `IronMeshClient` and peer callers away from raw `base_url` assumptions.
6. Update Windows adapter, Android bindings, and CLI to use the new stack.
7. Update server-node UI to issue and explain the new bootstrap.
8. Replace tests and fixtures that still assume direct URL plus bearer token startup.

## 9. Test plan mapped to the current repo

### Unit tests

- [ ] Add unit tests in `crates/transport-sdk` for bootstrap parsing, identity enrollment payloads, candidate ranking, relay-ticket validation, and session failover.
- [ ] Replace existing token-auth unit tests in `crates/server-node-sdk/src/main_tests.rs` with client key enrollment and proof-of-possession tests.

### Server-node integration tests

- [ ] Extend `crates/server-node-sdk/src/main_tests.rs` with:
  - node registers to rendezvous on startup,
  - node reconnects after rendezvous restart,
  - peer heartbeats and replication work over relay-only paths,
  - client enrollment issues key-bound credentials,
  - revoked client credentials are rejected.

### System tests

- [ ] Extend `tests/system-tests/src/framework.rs` to start `rendezvous-service`.
- [ ] Replace helper functions that issue or consume old direct-only bootstrap bundles.
- [ ] Add outbound-only connectivity scenarios:
  - client can read/write through relay without any inbound port on the target node,
  - two server nodes can replicate through relay-only paths,
  - direct path is preferred when available and relay is used after forced failure.
- [x] Update Windows CFAPI tests so they consume the persisted client identity artifact instead of expecting a `device_token`.
- [ ] Update Android-facing tests and helpers to cover bootstrap-aware app/runtime flows and relay-capable connection inputs.

## 10. Current code that can be deleted after the replacement lands

Candidates to remove once the new transport stack is in place:

- `ConnectionBootstrap.resolved_endpoint`
- `ResolvedConnectionBootstrap`
- device-token-based `DeviceEnrollmentResponse`
- `ServerState::internal_http`
- direct upstream bootstrap helpers based on `upstream_public_url`
- client startup flows that require `server_base_url` as the primary input

## 11. Definition of done

The work is done when all of the following are true:

- a client can enroll from a bootstrap bundle and then operate with only outbound connectivity,
- two server nodes can heartbeat, replicate, and reconcile when one or both are behind NAT and only reachable through rendezvous plus relay,
- relay mode preserves end-to-end authenticated encryption,
- direct transport is preferred automatically when available,
- no core client or peer path depends on a manually supplied direct server URL as its primary transport model.
