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

- [ ] Replace one-request relay tunnel semantics with long-lived paired relay sessions.
- [ ] Keep relay tickets and pairing, but pair once per session instead of once per request.
- [ ] Remove relay-HTTP request/response semantics from the transport design.
- [ ] Add tests covering relay session reuse and reconnect behavior.

Current slice landed:

- [x] Bridge a paired relay tunnel WebSocket into `MultiplexedSession`.
- [x] Add rendezvous client helpers for opening relay-backed multiplexed sessions.
- [x] Separate legacy relay tunnels from multiplexed relay sessions with explicit `session_kind` routing keys.
- [x] Add buffered multiplexed RPC framing and transport handshakes for Yamux streams.
- [x] Rewire buffered relay requests in `client-sdk` and `server-node` to use a warm multiplexed relay session.
- [x] Rewire server-node peer replication and cleanup requests to use multiplexed relay sessions instead of the legacy HTTP-over-tunnel wire format.
- [ ] Keep the remaining server-node relay traffic warm and reused instead of reconnecting a fresh multiplexed relay session per peer request.

Primary files:

- [ ] [crates/transport-sdk/src/rendezvous.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/rendezvous.rs)
- [ ] [crates/transport-sdk/src/rendezvous_runtime.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/rendezvous_runtime.rs)
- [ ] [crates/transport-sdk/src/relay_tunnel.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/relay_tunnel.rs)
- [ ] [apps/rendezvous-service/src/main.rs](/home/uli/rust-dev/ironmesh/apps/rendezvous-service/src/main.rs)
- [ ] [crates/server-node-sdk/src/embedded_rendezvous.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/embedded_rendezvous.rs)

### Milestone 3: Direct multiplexed server transport

- [ ] Add a direct WebSocket transport endpoint on `server-node`.
- [ ] Authenticate once per transport session.
- [ ] Run the same Yamux/session protocol for direct and relay paths.
- [ ] Add tests covering direct multiplexed requests.

Current slice landed:

- [x] Add a direct `/transport/ws` endpoint on `server-node` for authenticated client sessions.
- [x] Reuse the shared buffered multiplex transport framing and handshake over direct WebSocket sessions.
- [x] Route buffered authenticated direct client requests through a cached multiplexed session.
- [ ] Expand direct coverage beyond the current buffered request slice.

Primary files:

- [ ] [crates/server-node-sdk/src/lib.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/lib.rs)
- [ ] [crates/server-node-sdk/src/server_transport.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/server_transport.rs)

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

- [ ] Replace per-request relay setup in `IronMeshClient` with warm transport sessions.
- [ ] Introduce a session pool for direct and relay paths.
- [ ] Keep bootstrap/path-selection logic, but target sessions instead of bespoke request transports.

Current slice landed:

- [x] Move direct and relay warm-session ownership into a shared `session_pool` module instead of transport-specific cached session fields.
- [x] Expose transport session-pool snapshots from `IronMeshClient` so later diagnostics can report connection reuse and resets without reworking the client surface again.

Primary files:

- [ ] [crates/client-sdk/src/ironmesh_client.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/ironmesh_client.rs)
- [ ] [crates/client-sdk/src/bootstrap.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/bootstrap.rs)
- [ ] [crates/client-sdk/src/connection.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/connection.rs)
- [ ] [crates/client-sdk/src/session_pool.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/session_pool.rs)

### Milestone 6: Small-request SDK migration

- [ ] Move small buffered operations onto multiplexed streams.
- [ ] Cover JSON endpoints, relative-path fetches, store index, and object metadata paths.
- [ ] Update latency diagnostics to distinguish cold session setup from warm stream reuse.

Current slice landed:

- [x] Extend latency probe results with cold-connect timing and transport-session connect/reuse/reset counters.
- [x] Keep measured sample summaries focused on warm request behavior while still reporting when the probe had to establish or reset transport sessions.

Primary files:

- [ ] [crates/client-sdk/src/ironmesh_client.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/ironmesh_client.rs)
- [ ] [crates/client-sdk/src/latency_probe.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/latency_probe.rs)
- [ ] [apps/cli-client/src/main.rs](/home/uli/rust-dev/ironmesh/apps/cli-client/src/main.rs)
- [ ] [crates/web-ui-backend/src/lib.rs](/home/uli/rust-dev/ironmesh/crates/web-ui-backend/src/lib.rs)

### Milestone 7: Bulk transfer stream migration

- [ ] Move uploads and downloads onto dedicated multiplexed streams.
- [ ] Preserve mixed-workload responsiveness under concurrent large and small transfers.
- [ ] Add tests for cancellation and partial failures.

Current slice landed:

- [x] Split multiplexed transport request/response heads from buffered bodies so dedicated stream handlers can share the same Yamux substream protocol.
- [x] Route multiplexed object reads through dedicated `object_read` substreams and rewire ranged download paths to stream bytes directly into their destination writers.
- [x] Move upload-session chunk writes onto dedicated `object_write` substreams for both direct and relay transport sessions.
- [x] Add a direct mixed-workload transport test proving small RPCs stay responsive during a concurrent streamed download on the same warm session.
- [ ] Add explicit cancellation and partial-failure coverage for dedicated bulk-transfer substreams.

Primary files:

- [ ] [crates/client-sdk/src/ironmesh_client.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/ironmesh_client.rs)
- [ ] [crates/server-node-sdk/src/lib.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/lib.rs)

### Milestone 8: Diagnostics and UI wiring

- [ ] Expose transport session diagnostics to CLI and web UI.
- [ ] Report warm-session reuse, reconnects, and per-relay health.
- [ ] Extend latency tooling with cold-connect vs warm-stream metrics.

Current slice landed:

- [x] Show cold-connect and transport-session reuse/reset metrics in the CLI latency output.
- [x] Show cold-connect and transport-session reuse/reset metrics in the web latency page and API typings.

Primary files:

- [ ] [apps/cli-client/src/main.rs](/home/uli/rust-dev/ironmesh/apps/cli-client/src/main.rs)
- [ ] [crates/web-ui-backend/src/lib.rs](/home/uli/rust-dev/ironmesh/crates/web-ui-backend/src/lib.rs)
- [ ] [web/packages/api/src/client-ui/client.ts](/home/uli/rust-dev/ironmesh/web/packages/api/src/client-ui/client.ts)
- [ ] [web/apps/client-ui/src/app-shell/ClientShell.tsx](/home/uli/rust-dev/ironmesh/web/apps/client-ui/src/app-shell/ClientShell.tsx)

### Milestone 9: Legacy transport removal

- [ ] Remove relay HTTP broker routes and types.
- [ ] Remove one-request tunnel execution paths.
- [ ] Remove HTTP-over-tunnel request/response codecs that are no longer used.

Primary files:

- [ ] [crates/transport-sdk/src/relay.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/relay.rs)
- [ ] [crates/transport-sdk/src/relay_http_wire.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/relay_http_wire.rs)
- [ ] [crates/transport-sdk/src/rendezvous_runtime.rs](/home/uli/rust-dev/ironmesh/crates/transport-sdk/src/rendezvous_runtime.rs)
- [ ] [apps/rendezvous-service/src/main.rs](/home/uli/rust-dev/ironmesh/apps/rendezvous-service/src/main.rs)
- [ ] [crates/server-node-sdk/src/lib.rs](/home/uli/rust-dev/ironmesh/crates/server-node-sdk/src/lib.rs)
- [ ] [crates/client-sdk/src/ironmesh_client.rs](/home/uli/rust-dev/ironmesh/crates/client-sdk/src/ironmesh_client.rs)

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
