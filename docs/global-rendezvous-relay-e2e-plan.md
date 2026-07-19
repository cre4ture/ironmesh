# Global Rendezvous Relay and End-to-End Security Plan

Status: Phase 1 is implemented on `main`. Phase 2 is in progress: P2-A and
P2-B are present, and the P2-C registry/verifier foundation plus the versioned
registration protocol are available on this branch's base. The registration
API, node wiring, and Phase-2 end-to-end coverage are still landing in
parallel; Phase 2 is not complete.

## Goal

Offer one or more public IronMesh rendezvous/relay services that hobby-operated
clusters can use without operating their own Internet-reachable service. The
relay operator must not be able to read, change, or inject relayed IronMesh
application traffic.

The first delivery uses **Option 1**: the global service trusts a registered
cluster CA directly. It deliberately does not introduce a separate global
rendezvous PKI yet.

## Non-negotiable ordering

The current WebSocket relay is TLS-protected between each peer and the relay,
but the relay terminates that TLS connection. It can therefore inspect relayed
HTTP bytes today. Multi-cluster onboarding must not be enabled for that relay
mode before an inner end-to-end security layer is deployed.

Implementation order:

1. Add an end-to-end authenticated and encrypted relay transport.
2. Migrate every production relay caller to it and fail closed when it is not
   available.
3. Prove the relay only observes ciphertext in unit and system tests.
4. Make presence, discovery, tickets, and identity verification tenant-aware.
5. Add dynamic, self-service registration of one cluster CA per cluster.

## Phase 1: End-to-end relay transport

Status: implemented on `main`.

### Protocol decision

Use a nested TLS 1.3 connection, not a new bespoke AEAD protocol.

```text
source peer                 global rendezvous relay                 target node
-----------                 -----------------------                 -----------
source mTLS  -- WSS/TLS -->  terminates outer WSS  <-- WSS/TLS --    target mTLS
      |                                                                  |
      +---------- inner mutually authenticated TLS 1.3 ----------------+
                          (ciphertext forwarded as WS binary frames)
                                      |
                              multiplexed streams + HTTP
```

The inner TLS stream runs above `WebSocketByteStream` and below
`MultiplexedSession`. Consequently, multiplex control messages, HTTP request
and response bytes, application credentials, and payloads are all encrypted
from source peer to target node. This is a hard boundary for the global relay:
it sees only outer rendezvous metadata, such as authenticated outer identities,
cluster scope, relay ticket/session id, timing, and frame or byte sizes, plus
the encrypted inner TLS stream. It does not receive application payloads and
does not terminate the inner TLS layer.

Existing cluster-issued identities are sufficient for this first phase:

- A source client uses its enrolled rendezvous client identity for inner mTLS.
- A source node uses its existing internal node identity.
- The target node uses its existing internal node identity as the inner TLS
  server identity.
- The source validates the target certificate chain against the cluster CA and
  requires its `urn:ironmesh:node:<node_id>` and
  `urn:ironmesh:cluster:<cluster_id>` SAN values.
- The target validates the source certificate chain against the cluster CA and
  requires the source device/node SAN to match the identity bound into the
  relay session.

The relay ticket is authorization to pair a relay session. It is not the
application encryption key and cannot decrypt the inner TLS stream. A failed
inner handshake is a connection failure; there is no plaintext fallback.

### Work packages

#### P1-A: Secure stream primitive (`transport-sdk`)

Owner files:

- `crates/transport-sdk/src/relay_security.rs` (new)
- `crates/transport-sdk/src/relay_tunnel.rs`
- `crates/transport-sdk/src/lib.rs`
- `crates/transport-sdk/Cargo.toml` only if a currently transitive dependency
  needs to become direct

Deliverables:

- Parse reusable PEM identities and cluster trust roots.
- Build client and server inner TLS configurations with TLS 1.3 only.
- Validate expected node/device identity SAN values after normal WebPKI chain
  validation.
- Wrap a paired `RelayTunnelClient` into an authenticated encrypted byte
  stream, then create a `MultiplexedSession` above it.
- Unit tests for successful node and device handshakes, wrong peer identity,
  wrong cluster, wrong CA, ciphertext opacity, tampering, and no plaintext
  fallback.

#### P1-B: Client relay integration (`client-sdk`)

Owner files:

- `crates/client-sdk/src/session_pool.rs`
- `crates/client-sdk/src/connection.rs` and focused tests when required

Deliverables:

- Build the source-side inner TLS configuration from the bootstrap cluster CA
  and the enrolled rendezvous identity.
- Require the expected target node identity from the relay ticket/session.
- Replace plain `connect_relay_multiplex_source(...)` use with its secure
  counterpart.
- Expose precise errors for missing identity/trust material and failed peer
  authentication.

#### P1-C: Target-node relay integration (`server-node-sdk` and service host)

Owner files:

- `crates/server-node-sdk/src/lib.rs`
- `apps/rendezvous-service/src/main.rs` only where the standalone relay target
  accept loop exists

Deliverables:

- Construct the target-side inner TLS configuration from the internal node
  identity and cluster CA.
- Bind accepted source certificates to the source identity returned by the
  paired relay session.
- Replace plain multiplex target acceptance with secure acceptance for client
  and node relay paths.
- Keep the rendezvous server as a frame forwarder; it must never receive the
  inner TLS private keys.

#### P1-D: End-to-end validation and documentation

Owner files:

- `tests/system-tests/src/**` for relay-only coverage
- `docs/security-architecture.md`
- `docs/nat-traversal-implementation-checklist.md`

Deliverables:

- A relay-only client-to-node system test that captures relay-side binary
  frames and proves they do not contain an HTTP method, authorization header,
  or known application payload.
- A negative test for a relay that modifies a ciphertext frame.
- A successful direct-path control test so relay protection does not change
  normal direct traffic.
- Update the security documentation only after the production relay callers
  use the secure path.

### Phase 1 acceptance criteria

- The relay is unable to decode application HTTP bytes from a production relay
  path, even while terminating outer WSS.
- Both endpoints authenticate each other using cluster-issued certificates and
  expected SAN identities.
- Certificate, identity, or handshake failures cannot downgrade to the old
  plain relay stream.
- All source and target relay callers use the secure API; old plain conversion
  APIs are test-only or removed.
- Unit, crate integration, and relay-only system tests pass.

## Phase 2: Cluster tenancy for Option 1

Phase 1 acceptance criteria are met on `main`; Phase 2 is now active but not
complete. P2-A and P2-B are present. The P2-C persistent registry and dynamic
verifier work, together with the versioned P2-D registration protocol, are the
foundation for the remaining service API, node integration, and end-to-end
tests. Those remaining parts must land before Phase 2 can be marked complete.

### Tenant key and certificate binding

Tenant ownership is the tuple `(cluster_id, peer_identity)`, never identity
alone. The service must derive `cluster_id` from a verified certificate SAN,
not from an untrusted JSON request body.

For the Option 1 MVP, every cluster has exactly one active registered P-256
CA. Node and device rendezvous certificates must both carry:

- `urn:ironmesh:cluster:<cluster_id>`
- either `urn:ironmesh:node:<node_id>` or
  `urn:ironmesh:device:<device_id>`

The verifier reads the cluster SAN from the presented certificate and selects
exactly that cluster's one registered CA. It must verify only against that CA;
it must not try every CA in the registry as a fallback. A missing, unknown, or
mismatched cluster SAN is a verification failure.

The current node certificate already carries the cluster SAN; client
rendezvous identity issuance needs the same binding before tenant-aware dynamic
trust can be safe.

### Service data model

Persist a cluster registry containing at least:

- `cluster_id`
- one active CA PEM/fingerprint
- creation and last-seen timestamps
- registration key/proof fingerprint
- rate-limit and suspension state

Presence, discovery, wake registrations, relay waiters, and relay tickets use
`(cluster_id, peer_identity)` as their key. Listing or discovery for one
cluster can never return another cluster's presence metadata.

### Dynamic self-service registration

There is no administrative approval per cluster. Instead a new cluster
registers one self-signed P-256 CA over HTTPS and proves possession of the
matching private key by signing the versioned canonical registration proof.
The canonical proof binds the `cluster_id`, normalized CA DER fingerprint,
challenge id, nonce, and expiry. The service must verify that binding, the
challenge expiry and single use, and the P-256 proof before storing the CA for
that cluster.

Registration is idempotent only when the existing `cluster_id` is submitted
with the same normalized CA fingerprint and a valid fresh proof. That request
returns the existing registration rather than creating another active CA. A
request for an existing `cluster_id` with a different CA fingerprint is
rejected, even if the caller can prove possession of that different CA. There
is no self-service or administrator API in the MVP that rewrites a cluster to
a foreign CA.

This is automatic admission, not an assertion that every registrant is
trustworthy. Public operation still needs limits against abuse: registration
rate limits, CA/payload-size limits, IP and account-level quotas if available,
expiry of inactive registrations, audit events, and an operator suspension
mechanism. A registrant can compromise only its own cluster namespace; it
cannot authenticate as another registered cluster.

The service needs a reloadable custom client-certificate verifier that:

1. reads the cluster SAN from the presented certificate,
2. selects that cluster's registered CA,
3. verifies the certificate chain, and
4. rejects a certificate whose node/device SAN or request tenant does not
   match.

### Phase 2 work packages and status

- P2-A: Cluster SAN issuance and validation are present.
- P2-B: In-memory rendezvous presence, discovery, relay, and wake state are
  cluster-keyed.
- P2-C: The persistent cluster CA registry and dynamic verifier work are the
  present foundation; integration completion remains gated on the items below.
- P2-D: The versioned self-service challenge/proof protocol is present. The
  service API, abuse-control wiring, operator suspend/list controls, and node
  auto-registration are still in parallel development.
- P2-E: Two-cluster isolation, restart persistence, and CA-registration system
  tests remain required. Their absence means Phase 2 is not complete.

## Deferred work

The MVP intentionally has no CA rotation. It supports exactly one active P-256
CA per cluster and rejects replacement by another CA. A later rotation design
may introduce an ordered active CA set, an overlap window, issuance from the
new CA, and retirement after the old certificates expire or are revoked. That
is explicitly outside Option 1 MVP and must not be approximated by an
all-registered-CA fallback verifier.

A dedicated global rendezvous PKI is also deferred. It remains a worthwhile
later hardening step because it gives the global operator a narrower,
rendezvous-only credential boundary, but it is not required for the first
Option 1 delivery.

## Delivery dependency

The remaining Phase-2 API, node, and end-to-end test work can proceed in
parallel, but must converge on the single-CA and cluster-SAN rules above. A
merge must not enable global self-registration unless the persistent registry,
dynamic verifier, service-side abuse controls, node opt-in, and isolation and
restart tests are all present.
