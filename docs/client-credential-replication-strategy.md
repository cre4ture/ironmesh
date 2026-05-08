# Client Credential Replication Strategy

## Problem

Client enrollment currently succeeds on the server node that handles `/auth/device/enroll`, but the resulting server-side credential record stays local to that node. Authenticated client requests are validated by looking up the signed `device_id` and credential fingerprint in the local `ClientCredentialState`. A secondary node that has not seen the enrollment record therefore rejects the same client, even though the client holds a valid enrolled identity for the cluster.

For redundant multi-node operation, an enrolled client should be accepted by every online cluster node without requiring re-enrollment against each node.

## Security Boundary

The client identity file must not be copied between server nodes. In particular, nodes must never receive or store the client `private_key_pem`.

The server-side replication payload only carries the material a node needs to verify signed client requests:

- `device_id`
- optional device label
- client public key PEM
- public key fingerprint
- issued credential fingerprint
- creation timestamp
- revocation metadata, when present

The full issued credential PEM is also omitted from replication. Nodes can authenticate requests with the public key and credential fingerprint already present in the signed request headers.

## MVP Behavior

The MVP uses best-effort cluster fan-out plus periodic reconciliation over the existing internal peer transport.

1. The enrollment node persists the local `ClientCredentialRecord` after a successful pairing-token enrollment.
2. It starts an asynchronous fan-out to every currently online peer using the internal peer API.
3. Peers import a sanitized credential record through an idempotent upsert endpoint.
4. A periodic reconciliation pass exports sanitized credential snapshots from peers and imports anything missing locally, so nodes that were offline during initial fan-out can catch up later.
5. Revoked credentials are replicated as tombstone-style metadata on the same record. A replicated active credential must never clear an existing local revocation.

The fan-out path is intentionally best effort. Enrollment should not fail just because a secondary is offline or temporarily unreachable. The periodic sync path is the repair mechanism for missed deliveries.

## Conflict Rules

Credential import is keyed by `device_id`.

- Missing local `device_id`: insert the sanitized record.
- Existing `device_id` with the same public key and credential fingerprint: merge non-conflicting metadata and revocation state.
- Existing `device_id` with a different public key or credential fingerprint: reject that imported record, keep the local record unchanged, and record the conflict in logs/audit metadata.

This prevents a secondary from silently replacing a device identity if two nodes somehow issued credentials for the same `device_id`.

## Internal API

The MVP adds internal-peer-only routes:

- `GET /cluster/client-credentials/export`
- `POST /cluster/client-credentials/import`

These routes are available only on the internal peer router, protected by existing node-to-node authentication. Import requests include the source node id and cluster id and are rejected if they do not match the authenticated internal caller.

## Later Hardening

The MVP deliberately avoids a larger auth redesign. Later iterations should consider:

- a durable per-record/event-log schema instead of the current singleton JSON credential state,
- persisted outbox state for fan-out retries across process restarts,
- per-record version counters or source timestamps,
- credential expiry enforcement at request-auth time,
- a cluster-wide client CA or signed client certificate model where nodes primarily replicate revocation state.
