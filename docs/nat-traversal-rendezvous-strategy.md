# NAT Traversal, Rendezvous, and Relay Strategy

Status: Proposed architecture for Ironmesh connectivity across NATed clients and server nodes

Implementation checklist: `docs/nat-traversal-implementation-checklist.md`

## 1. Problem

Ironmesh needs reliable communication between:

- server-node <-> server-node,
- client/device <-> server-node,

even when some or all participants are behind NAT and do not have port forwarding.

Requirements:

- direct connectivity should be used when available,
- connectivity must still work when only outbound connections are possible,
- authentication and encryption must remain strong in all modes,
- the UX should stay simple for operators and end users,
- existing HTTP APIs and current bootstrap/auth flows should be reusable where possible.

## 2. Key conclusion

A rendezvous service is necessary, but not sufficient on its own.

Because Ironmesh is still pre-release, this document describes the target architecture directly.
It does not optimize for backward compatibility, mixed-version clusters, or staged rollout.

Recommended design:

1. Every node/client opens an outbound control connection to a rendezvous service.
2. Peers first try direct transport establishment.
3. If direct establishment fails, they fall back to a relay service.
4. Peer-to-peer authentication and encryption stay end-to-end, even when traffic goes through the relay.

Important networking fact:

- Once a TCP, QUIC, WebSocket, or tunneled stream is established in one direction, it is full-duplex.
- That means one successful outbound-established connection is enough to carry request/response traffic in both directions.

This makes outbound-only operation practical.

## 3. Recommended transport model

Use a three-layer connectivity architecture:

### 3.1 Enrollment and identity layer

Keep the current Ironmesh security direction:

- node identities are certificate-backed,
- clients/devices enroll via pairing/bootstrap,
- the cluster CA and node IDs remain the source of truth.

Strengthen it further:

- pairing tokens remain one-time enrollment secrets only,
- enrolled nodes get node certificates,
- enrolled clients/devices should move toward certificate or proof-of-possession identity instead of long-lived bearer tokens,
- every issued credential is bound to `cluster_id` and logical identity (`node_id` or `device_id`).

### 3.2 Rendezvous/control layer

Introduce a dedicated rendezvous service.

Responsibilities:

- accept long-lived outbound control connections from nodes and clients,
- authenticate endpoints,
- maintain "currently reachable" presence state,
- collect connection candidates,
- broker connection attempts between peers,
- authorize relay use,
- avoid handling plaintext application data.

Transport recommendation:

- use `wss://` or HTTPS-based long-lived streams for the control channel because they work through most NATs and restrictive firewalls.

### 3.3 Data layer

Use a tiered preference order:

1. Existing direct public/internal address if reachable.
2. Direct QUIC/UDP peer session using exchanged candidates.
3. Relay tunnel through the rendezvous service or a TURN-like companion relay.

QUIC is the best direct-path target because it supports:

- fast connection setup,
- multiplexed streams,
- better NAT traversal characteristics than plain TCP,
- one transport for replication, heartbeats, and client RPC traffic.

But QUIC will not always succeed. Relay fallback is mandatory for guaranteed connectivity.

## 4. Proposed Ironmesh components

### 4.1 Endpoint transport agent

Each server node and client-facing runtime gets a transport agent responsible for:

- maintaining the outbound control connection,
- gathering connectivity candidates,
- selecting the best path,
- retrying failed paths,
- exposing a logical "connect to peer" API to the rest of Ironmesh.

This agent should hide whether the final path is:

- direct HTTPS,
- direct QUIC,
- or relayed tunnel.

### 4.2 Rendezvous service

New service, separate from storage nodes.

Suggested responsibilities:

- endpoint presence registry,
- candidate exchange,
- session authorization,
- relay ticket issuance,
- optional offline message queue for wakeup hints only.

### 4.3 Relay service

The relay may be part of the rendezvous service at first, but the trust model should treat it as untrusted for payload confidentiality.

Responsibilities:

- bridge byte streams between authenticated peers,
- enforce quotas and ACLs,
- expose per-session metrics,
- never terminate the inner end-to-end peer security layer.

## 5. Security model

### 5.1 Node-to-node

Keep and extend the current internal mTLS model already described in `docs/security-architecture.md`.

- each node has a Node-CA-signed certificate,
- SAN contains `urn:ironmesh:node:<uuid>`,
- optionally also `urn:ironmesh:cluster:<uuid>`,
- authorization continues to bind the authenticated identity to URL/path-level node semantics.

Direct mode:

- node A opens a direct QUIC or TLS connection to node B,
- both sides verify the peer certificate and cluster binding.

Relay mode:

- node A asks the relay for a tunnel to node B,
- the relay bridges raw bytes,
- node A and node B perform mTLS inside the tunnel,
- the relay sees metadata and ciphertext, but not application plaintext.

### 5.2 Client-to-node

Use:

- pairing tokens only for initial enrollment,
- server TLS for server identity,
- per-device keypairs,
- short-lived client certificates or registered device public keys,
- proof-of-possession during session establishment.

That improves security over replayable bearer tokens and fits rendezvous/relay better.

### 5.3 Relay trust boundary

The relay should be treated like a network carrier, not an application server.

That means:

- outer TLS protects endpoint-to-relay transport,
- inner peer TLS or Noise-like session protects endpoint-to-endpoint payloads,
- relay operators cannot impersonate peers without the peer private keys,
- authorization decisions remain at Ironmesh endpoints, not the relay.

## 6. Connection flows

### 6.1 Server-node to server-node

1. Node boots with its certificate and rendezvous URL.
2. Node opens outbound control connection to rendezvous.
3. Node publishes:
   - `node_id`,
   - cluster binding,
   - advertised direct URLs,
   - observed NAT candidates,
   - supported transports.
4. When replication/heartbeat/reconcile needs peer B, node A asks its transport agent for a session.
5. Transport agent tries:
   - direct configured address,
   - direct candidate-based connect,
   - relay tunnel fallback.
6. Once connected, existing internal APIs run over that session.

### 6.2 Client/device to server-node

1. Client receives a bootstrap bundle.
2. Bundle includes:
   - cluster/rendezvous URL(s),
   - server trust root,
   - pairing token or enrollment reference,
   - initial preferred node set if available.
3. Client enrolls and opens outbound control connection.
4. Client resolves target node via rendezvous.
5. Client connects directly if possible, otherwise via relay.
6. Client keeps one logical session that can carry all normal request/response traffic.

### 6.3 Why one-direction establishment is enough

If node B cannot accept inbound connections but keeps an outbound control/relay connection alive, node A can still reach B by asking the rendezvous/relay layer to splice a tunnel onto B's existing outbound session.

After the tunnel is established:

- A can send requests to B,
- B can send responses and server-initiated messages back to A,
- the same stream can be multiplexed for multiple logical operations.

So the important capability is not "both peers must accept inbound sockets".
It is "both peers must be able to maintain at least one outbound path to the rendezvous fabric".

## 7. Target architecture choices

The target architecture should include all of the following from the start:

- every endpoint maintains an outbound control connection to rendezvous,
- every endpoint can use a relay tunnel when no direct path works,
- direct path selection is still preferred when available,
- candidate exchange for direct QUIC/UDP establishment is part of the transport layer,
- client authentication should move to key-bound proof-of-possession identities rather than long-lived bearer tokens.

This means relay support is not a temporary fallback design.
It is a permanent part of the connectivity model, with direct connectivity used as an optimization when possible.

## 8. Concrete repo-facing changes

### 8.1 Bootstrap bundle evolution

Current `ConnectionBootstrap` already carries:

- endpoints,
- resolved endpoint,
- server CA PEM,
- pairing token,
- device label/device ID.

Replace the current bootstrap shape with a rendezvous-aware schema, for example:

```json
{
  "version": 1,
  "endpoints": ["https://node-a.example"],
  "rendezvous_urls": ["https://rendezvous.example"],
  "relay_mode": "preferred",
  "server_ca_pem": "...",
  "cluster_id": "...",
  "pairing_token": "...",
  "device_label": "laptop"
}
```

Meaning:

- `endpoints` stay as direct-connect hints,
- `rendezvous_urls` enable NAT-tolerant resolution,
- relay use is a first-class part of the model,
- clients can make path decisions without any legacy bootstrap constraints.

Distribution note:

- the full bootstrap schema should not be assumed to fit in a reliable single QR,
- when onboarding depends on QR scanning, the preferred transport is a small claim payload that redeems through the rendezvous-facing endpoint and returns the full bootstrap over pinned HTTPS,
- this is especially important when only the rendezvous service is directly reachable and the redeem endpoint is not trusted by public PKI.

See:

- `docs/bootstrap-claim-qr-strategy.md`

### 8.2 Node descriptor evolution

Extend node metadata beyond static `public_url` / `internal_url`.

Suggested additions:

- transport capabilities,
- rendezvous presence state,
- last successful path type,
- relay-required hint,
- cluster-scoped endpoint identity metadata.

### 8.3 New crates/apps

Likely additions:

- `apps/rendezvous-service`
- `crates/transport-sdk`
- optional `crates/relay-proto`

`transport-sdk` should expose a small interface to the rest of the codebase:

- `connect_to_node(node_id)`,
- `connect_public_api(target)`,
- `open_replication_stream(node_id)`,
- `current_path_kind()`.

That keeps `client-sdk` and `server-node-sdk` from embedding NAT logic directly.

### 8.4 Server-node integration

Current `server-node-sdk` already has:

- public listener,
- internal mTLS listener,
- bootstrap bundle issuing,
- client enrollment,
- node descriptors and heartbeats.

Integration path:

- use the transport agent for peer heartbeats and replication calls,
- preserve current HTTP handlers,
- make transport selection an implementation detail under the peer client layer.

## 9. Design recommendation

For Ironmesh, the best overall solution is:

- outbound-friendly rendezvous connectivity for reliability,
- relay support as a built-in transport mode,
- direct-path preference for efficiency,
- candidate-based hole punching for direct-path improvement,
- end-to-end authenticated encryption in every mode,
- pairing tokens only for enrollment, not long-term session trust.

In short:

- yes, use a rendezvous service,
- but pair it with a relay service,
- and keep peer security end-to-end above the relay.

That combination is the simplest design that still works when clients and server nodes sit behind NAT without port forwarding.

## 10. Non-goals and caveats

- A rendezvous service alone cannot guarantee direct connectivity.
- Hole punching will fail in some real networks, especially symmetric NAT or UDP-restricted environments.
- Relay bandwidth and quotas must be planned as first-class operational concerns.
- If browser-native clients become important later, WebRTC may become relevant for that surface area, but it should not drive the core Rust transport design now.
