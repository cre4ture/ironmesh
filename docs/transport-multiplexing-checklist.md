# Transport Multiplexing Checklist

Status: active implementation checklist for replacing the pre-release relay HTTP and single-request relay tunnel stack with long-lived WebSocket sessions plus Yamux multiplexing.

## Goals

- Use one long-lived multiplexed transport for both direct and relayed client traffic.
- Eliminate per-request relay tunnel setup overhead for small UI and CLI requests.
- Keep the rendezvous service focused on presence, ticketing, pairing, and byte forwarding.
- Make progress durable: every milestone must update this file and land as a separate commit with verification notes.

## Guardrails

- No backward compatibility work is required.
- No rollout or bridge path is required.
- The current browser-to-embedded-Rust-backend split stays in place for now.
- Every milestone must include:
  - committed checklist updates
  - at least one targeted automated verification step
  - a dedicated commit before the next milestone starts

## Milestones

### Milestone 1: Transport foundation in `transport-sdk`

- [x] Add a generic WebSocket byte-stream adapter suitable for running Yamux over WebSocket frames.
- [x] Add Yamux dependency and a transport-friendly session wrapper.
- [x] Add an initial transport protocol skeleton for session and stream control messages.
- [x] Add tests covering:
  - [x] WebSocket byte-stream binary read/write behavior
  - [x] ping/pong handling
  - [x] at least two concurrent logical streams over one Yamux connection

Primary files:

- [x] [crates/transport-sdk/Cargo.toml](/home/uli/rust-dev/ironmesh/crates/transport-sdk/Cargo.toml)
- [x] [crates/transport-sdk/src/lib.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/lib.rs)
- [x] [crates/transport-sdk/src/ws_stream.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/ws_stream.rs)
- [x] [crates/transport-sdk/src/mux.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/mux.rs)
- [x] [crates/transport-sdk/src/transport_protocol.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/transport_protocol.rs)

### Milestone 2: Persistent relay sessions

- [x] Replace one-request relay tunnel semantics with long-lived paired relay sessions.
- [x] Keep relay tickets and pairing, but pair once per session instead of once per request.
- [x] Remove relay-HTTP request/response semantics from the transport design.
- [x] Add tests covering relay session reuse and reconnect behavior.

Current slice landed:

- [x] Bridge a paired relay tunnel WebSocket into `MultiplexedSession`.
- [x] Add rendezvous client helpers for opening relay-backed multiplexed sessions.
- [x] Separate legacy relay tunnels from multiplexed relay sessions with explicit `session_kind` routing keys.
- [x] Add buffered multiplexed RPC framing and transport handshakes for Yamux streams.
- [x] Rewire buffered relay requests in `client-sdk` and `server-node` to use a warm multiplexed relay session.
- [x] Rewire server-node peer replication and cleanup requests to use multiplexed relay sessions instead of the legacy HTTP-over-tunnel wire format.
- [x] Keep the remaining server-node relay traffic warm and reused instead of reconnecting a fresh multiplexed relay session per peer request.
- [x] Add server-node coverage proving relay peer requests reuse a warm session and reconnect cleanly after that cached session closes.

Primary files:

- [x] [crates/transport-sdk/src/rendezvous.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/rendezvous.rs)
- [x] [crates/transport-sdk/src/rendezvous_runtime.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/rendezvous_runtime.rs)
- [x] [crates/transport-sdk/src/relay_tunnel.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/relay_tunnel.rs)
- [x] [apps/rendezvous-service/src/main.rs](/home/uli/rust-dev/ironmesh/apps/rendezvous-service/src/main.rs)
- [x] [crates/server-node-sdk/src/embedded_rendezvous.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/embedded_rendezvous.rs)
- [x] [crates/server-node-sdk/src/lib.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/lib.rs)
- [x] [crates/server-node-sdk/src/main_tests.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/main_tests.rs)

### Milestone 3: Direct multiplexed server transport

- [x] Add a direct WebSocket transport endpoint on `server-node`.
- [x] Authenticate once per transport session.
- [x] Run the same Yamux/session protocol for direct and relay paths.
- [x] Add tests covering direct multiplexed requests.

Current slice landed:

- [x] Add a direct `/transport/ws` endpoint on `server-node` for authenticated client sessions.
- [x] Reuse the shared buffered multiplex transport framing and handshake over direct WebSocket sessions.
- [x] Route buffered authenticated direct client requests through a cached multiplexed session.
- [x] Expand direct coverage beyond the current buffered request slice with direct store-index, relative-path, HEAD, object-read, object-write, cancellation, and mixed-workload regression tests.

Primary files:

- [x] [crates/server-node-sdk/src/lib.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/lib.rs)
- [x] [crates/client-sdk/src/connection.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/connection.rs)
- [x] [crates/client-sdk/src/ironmesh_client.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/ironmesh_client.rs)

### Milestone 4: Shared server transport service layer

- [ ] Extract store/media/cluster/diagnostic operations from HTTP-only handlers.
- [ ] Make HTTP and multiplexed transport call the same internal async service functions.
- [ ] Stop bouncing relayed requests through local HTTP.

Current slice landed:

- [x] Route current multiplexed health, cluster, diagnostics, store index, object read, thumbnail, and version-list requests through `transport_service`.
- [x] Keep a bounded local-HTTP fallback only for buffered routes that have not been migrated into the shared service layer yet.

Primary files:

- [ ] [crates/server-node-sdk/src/lib.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/lib.rs)
- [ ] [crates/server-node-sdk/src/transport_service.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/transport_service.rs)

### Milestone 5: Client session pool and path management

- [x] Replace per-request relay setup in `IronMeshClient` with warm transport sessions.
- [x] Introduce a session pool for direct and relay paths.
- [x] Keep bootstrap/path-selection logic, but target sessions instead of bespoke request transports.

Current slice landed:

- [x] Move direct and relay warm-session ownership into a shared `session_pool` module instead of transport-specific cached session fields.
- [x] Expose transport session-pool snapshots from `IronMeshClient` so later diagnostics can report connection reuse and resets without reworking the client surface again.

Primary files:

- [x] [crates/client-sdk/src/ironmesh_client.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/ironmesh_client.rs)
- [x] [crates/client-sdk/src/bootstrap.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/bootstrap.rs)
- [x] [crates/client-sdk/src/connection.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/connection.rs)
- [x] [crates/client-sdk/src/session_pool.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/session_pool.rs)

### Milestone 6: Small-request SDK migration

- [x] Move small buffered operations onto multiplexed streams.
- [x] Cover JSON endpoints, relative-path fetches, store index, and object metadata paths.
- [x] Update latency diagnostics to distinguish cold session setup from warm stream reuse.

Current slice landed:

- [x] Extend latency probe results with cold-connect timing and transport-session connect/reuse/reset counters.
- [x] Keep measured sample summaries focused on warm request behavior while still reporting when the probe had to establish or reset transport sessions.

Primary files:

- [x] [crates/client-sdk/src/ironmesh_client.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/ironmesh_client.rs)
- [x] [crates/client-sdk/src/latency_probe.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/latency_probe.rs)
- [x] [apps/cli-client/src/main.rs](/home/uli/rust-dev/ironmesh/apps/cli-client/src/main.rs)
- [x] [crates/web-ui-backend/src/lib.rs](/home/uli/rust-dev/ironmesh/crates/web-ui-backend/src/lib.rs)

### Milestone 7: Bulk transfer stream migration

- [x] Move uploads and downloads onto dedicated multiplexed streams.
- [x] Preserve mixed-workload responsiveness under concurrent large and small transfers.
- [x] Add tests for cancellation and partial failures.

Current slice landed:

- [x] Split multiplexed transport request/response heads from buffered bodies so dedicated stream handlers can share the same Yamux substream protocol.
- [x] Route multiplexed object reads through dedicated `object_read` substreams and rewire ranged download paths to stream bytes directly into their destination writers.
- [x] Move upload-session chunk writes onto dedicated `object_write` substreams for both direct and relay transport sessions.
- [x] Add a direct mixed-workload transport test proving small RPCs stay responsive during a concurrent streamed download on the same warm session.
- [x] Add explicit cancellation and partial-failure coverage for dedicated bulk-transfer substreams.

Primary files:

- [x] [crates/client-sdk/src/ironmesh_client.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/ironmesh_client.rs)
- [x] [crates/server-node-sdk/src/lib.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/lib.rs)

### Milestone 8: Diagnostics and UI wiring

- [x] Expose transport session diagnostics to CLI and web UI.
- [x] Report warm-session reuse, reconnects, and per-relay health.
- [x] Extend latency tooling with cold-connect vs warm-stream metrics.

Current slice landed:

- [x] Show cold-connect and transport-session reuse/reset metrics in the CLI latency output.
- [x] Show cold-connect and transport-session reuse/reset metrics in the web latency page and API typings.

Primary files:

- [x] [apps/cli-client/src/main.rs](/home/uli/rust-dev/ironmesh/apps/cli-client/src/main.rs)
- [x] [crates/web-ui-backend/src/lib.rs](/home/uli/rust-dev/ironmesh/crates/web-ui-backend/src/lib.rs)
- [x] [web/packages/api/src/client-ui/client.ts](/home/uli/rust-dev/ironmesh/web/packages/api/src/client-ui/client.ts)
- [x] [web/apps/client-ui/src/app-shell/ClientShell.tsx](/home/uli/rust-dev/ironmesh/web/apps/client-ui/src/app-shell/ClientShell.tsx)

### Milestone 9: Legacy transport removal

- [x] Remove relay HTTP broker routes and types.
- [x] Remove one-request tunnel execution paths.
- [x] Remove HTTP-over-tunnel request/response codecs that are no longer used.

Current slice landed:

- [x] Stop spawning the legacy relay tunnel acceptor and relay HTTP polling agents inside `server-node` now that peer relay requests use multiplexed sessions.
- [x] Remove the dead `/relay/http/*` broker routes and in-memory relay broker state from standalone rendezvous and embedded rendezvous, leaving the relay tunnel WebSocket endpoint as the only live relayed data-plane entrypoint.
- [x] Remove the now-unused `/relay/http/*` control-client methods from `RendezvousControlClient`.
- [x] Migrate the remaining bootstrap-claim relay redemption path in standalone and embedded rendezvous onto buffered multiplexed transport streams.
- [x] Remove the remaining relay HTTP runtime types and broker implementation from `transport-sdk`.
- [x] Remove the remaining legacy HTTP-over-tunnel codec helpers once those routes are gone.
- [x] Drop the last legacy tunnel-codec branch from the `client-sdk` relay test harness so transport coverage stays on the multiplexed path only.

Primary files:

- [x] [crates/transport-sdk/src/relay.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/relay.rs)
- [x] [crates/transport-sdk/src/relay_http_wire.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/relay_http_wire.rs)
- [x] [crates/transport-sdk/src/rendezvous_runtime.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/rendezvous_runtime.rs)
- [x] [apps/rendezvous-service/src/main.rs](/home/uli/rust-dev/ironmesh/apps/rendezvous-service/src/main.rs)
- [x] [crates/server-node-sdk/src/embedded_rendezvous.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/embedded_rendezvous.rs)
- [x] [crates/client-sdk/src/ironmesh_client.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/ironmesh_client.rs)

### Milestone 10: System-level hardening

- [ ] Add end-to-end tests for:
  - [ ] session reuse over relay
  - [ ] concurrent small requests during large transfers
  - [ ] relay reconnects
  - [ ] failover across configured relays
  - [ ] updated latency diagnostics

Primary files:

- [ ] [crates/client-sdk/src/ironmesh_client.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/ironmesh_client.rs)
- [ ] [crates/server-node-sdk/src/main_tests.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/main_tests.rs)
- [ ] [tests/system-tests/src/framework.rs](/home/uli/rust-dev/ironmesh/tests/system-tests/src/framework.rs)

## Progress log

- [x] 2026-04-08: Create this checklist and commit the migration baseline in `443dc4e` (`docs: add transport multiplexing checklist`).
- [x] 2026-04-08: Complete Milestone 1 transport foundation work in `transport-sdk`.
  Verification:
  - `cargo test -p transport-sdk`
  - `cargo check -p client-sdk -p server-node-sdk -p cli-client -p rendezvous-service`
- [x] 2026-04-08: Start Milestone 2 by bridging paired relay tunnel sockets into `MultiplexedSession` and exposing rendezvous client helpers for relay-backed multiplexed sessions.
  Verification:
  - `cargo test -p transport-sdk`
  - `cargo check -p client-sdk -p server-node-sdk -p cli-client -p rendezvous-service`
- [x] 2026-04-08: Isolate legacy relay HTTP/one-shot tunnel traffic from new multiplexed relay sessions by adding `session_kind` to relay tickets, relay accept requests, and rendezvous pairing keys.
  Verification:
  - `cargo test -p transport-sdk`
  - `cargo check -p client-sdk -p server-node-sdk -p cli-client -p rendezvous-service`
- [x] 2026-04-08: Route buffered relay client requests through a cached multiplexed Yamux session and add buffered transport framing/handshakes for the new relay path.
  Verification:
  - `cargo test -p transport-sdk`
  - `cargo test -p client-sdk relay_transport`
  - `cargo check -p client-sdk -p server-node-sdk -p cli-client -p rendezvous-service`
- [x] 2026-04-08: Extend the shared multiplexed transport to authenticated direct client sessions with `/transport/ws` and cached direct buffered requests.
  Verification:
  - `cargo test -p client-sdk direct_transport`
  - `cargo test -p client-sdk relay_transport`
  - `cargo test -p transport-sdk`
  - `cargo check -p transport-sdk -p client-sdk -p server-node-sdk -p cli-client -p rendezvous-service`
- [x] 2026-04-08: Route the existing multiplexed buffered request surface through a shared server transport dispatcher instead of bouncing those requests through local HTTP.
  Verification:
  - `cargo check -p server-node-sdk`
  - `cargo test -p client-sdk relay_transport`
  - `cargo test -p client-sdk direct_transport`
  - `cargo check -p transport-sdk -p client-sdk -p server-node-sdk -p cli-client -p rendezvous-service`
- [x] 2026-04-08: Consolidate direct and relay warm-session management into a shared client transport session pool and expose reusable session snapshots for diagnostics.
  Verification:
  - `cargo check -p client-sdk`
  - `cargo test -p client-sdk direct_transport`
  - `cargo test -p client-sdk relay_transport`
- [x] 2026-04-08: Extend latency diagnostics to report cold session setup separately from measured warm requests and surface session reuse metrics in the CLI and web UI.
  Verification:
  - `cargo test -p client-sdk latency_probe`
  - `cargo check -p cli-client -p web-ui-backend`
  - `pnpm --dir web --filter @ironmesh/api --filter @ironmesh/client-ui typecheck`
- [x] 2026-04-08: Introduce dedicated object-read transport substreams and stream ranged downloads over multiplexed direct/relay sessions instead of buffering whole range bodies through RPC frames.
  Verification:
  - `cargo check -p transport-sdk -p server-node-sdk -p client-sdk`
  - `cargo test -p transport-sdk`
  - `cargo test -p client-sdk direct_transport`
  - `cargo test -p client-sdk relay_transport`
  - `cargo test -p client-sdk blocking_range_download_handles_concurrent_overlapping_requests`
  - `cargo check -p cli-client -p web-ui-backend`
- [x] 2026-04-08: Stream upload-session chunk writes over dedicated `object_write` substreams and add a mixed-workload transport test covering concurrent large downloads and small RPCs on one warm direct session.
  Verification:
  - `cargo test -p client-sdk direct_transport`
  - `cargo test -p client-sdk relay_transport`
  - `cargo test -p client-sdk blocking_range_download_handles_concurrent_overlapping_requests`
  - `cargo check -p transport-sdk -p server-node-sdk -p client-sdk`
- [x] 2026-04-08: Migrate server-node peer replication and cleanup requests off the legacy relay tunnel wire format and onto multiplexed relay sessions.
  Verification:
  - `cargo check -p server-node-sdk -p transport-sdk`
  - `cargo test -p server-node-sdk execute_replication_cleanup_routes_remote_drop_through_relay`
- [x] 2026-04-08: Remove the live `server-node` runtime hooks for legacy relay HTTP polling and one-request relay tunnel execution, leaving only the multiplexed relay acceptor active.
  Verification:
  - `cargo check -p server-node-sdk`
  - `cargo test -p server-node-sdk execute_replication_cleanup_routes_remote_drop_through_relay`
- [x] 2026-04-08: Remove the dead `/relay/http/*` routes and relay broker state from standalone rendezvous and embedded rendezvous.
  Verification:
  - `cargo check -p rendezvous-service -p server-node-sdk`
- [x] 2026-04-08: Remove the unused rendezvous control-client methods for `/relay/http/*` now that those routes no longer exist.
  Verification:
  - `cargo check -p transport-sdk -p rendezvous-service -p server-node-sdk`
- [x] 2026-04-08: Finish the legacy relay cleanup by migrating bootstrap-claim relay redemption onto multiplexed transport streams, deleting the remaining relay HTTP runtime/types/codecs from `transport-sdk`, and removing the last legacy tunnel branch from the client relay test harness.
  Verification:
  - `cargo check -p transport-sdk -p rendezvous-service -p server-node-sdk -p client-sdk`
  - `cargo test -p transport-sdk`
  - `cargo test -p client-sdk relay_transport`
  - `cargo test -p rendezvous-service relay_client_device_flows_through_mtls_authenticated_rendezvous`
  - `cargo test -p rendezvous-service bootstrap_claim_redeem_flows_through_mtls_rendezvous_without_client_cert`
- [x] 2026-04-08: Keep server-node peer relay traffic on warm cached multiplexed sessions and add regression coverage for both reuse and reconnect-after-close behavior.
  Verification:
  - `cargo check -p server-node-sdk`
  - `cargo test -p server-node-sdk execute_replication_cleanup_routes_remote_drop_through_relay`
  - `cargo test -p server-node-sdk execute_peer_request_reuses_warm_relay_session`
  - `cargo test -p server-node-sdk execute_peer_request_reconnects_after_relay_session_closes`
- [x] 2026-04-08: Close the bulk-transfer hardening gap by adding regression coverage for streamed-download cancellation and retrying streamed upload chunks after a mid-session relay failure.
  Verification:
  - `cargo test -p client-sdk direct_transport_cancels_streamed_download_promptly`
  - `cargo test -p client-sdk relay_transport_retries_streamed_upload_chunk_after_partial_session_failure`
- [x] 2026-04-08: Expand direct multiplexed transport coverage so `/transport/ws` exercises store-index, relative-path, HEAD, upload, download-cancel, and mixed-workload request shapes instead of only a generic JSON probe.
  Verification:
  - `cargo test -p client-sdk direct_transport`
  - `cargo check -p client-sdk`
- [x] 2026-04-08: Reconcile the remaining client-side migration milestones by validating that warm direct/relay session pooling, buffered multiplexed RPC routing, and transport-session diagnostics are all live in the SDK, CLI, and web UI.
  Verification:
  - `cargo test -p client-sdk relay_transport`
  - `cargo test -p client-sdk latency_probe`
  - `cargo check -p cli-client -p web-ui-backend`
