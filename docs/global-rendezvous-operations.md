# Global Rendezvous Operations Checklist

Status: Phase-2 operating contract. The global service API, server-node
registration flow, and end-to-end coverage are implemented on this branch;
they become available on `main` after review and merge.

This checklist applies to an Internet-facing global rendezvous/relay operating
with Option 1. Its security boundary is defined in
`docs/security-architecture.md`: the service handles outer metadata and an
encrypted inner TLS stream, not application payloads or inner TLS termination.

## Service setup

- [ ] Deploy the service behind HTTPS with a valid service certificate and
  private key. Keep this service identity separate from all registered cluster
  CAs and their private keys.
- [ ] Put the registry on durable storage and set
  `IRONMESH_RENDEZVOUS_GLOBAL_CLUSTER_REGISTRY` to its persistent path. The
  parent directory must already exist, the path must not contain `..`, and the
  process account must have only the permissions required to read and update
  that path.
- [ ] Back up the registry and audit records on a schedule, protect backup
  access, and test restoration before enabling public registration.
- [ ] Set `IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_ENABLED=false` until the
  HTTPS endpoint, persistence, audit logging, and abuse controls are verified.

## Phase-2 configuration contract

- [ ] `IRONMESH_RENDEZVOUS_GLOBAL_CLUSTER_REGISTRY` names the persistent
  cluster registry path.
- [ ] `IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_ENABLED` is the global,
  service-side self-registration gate.
- [ ] `IRONMESH_RENDEZVOUS_GLOBAL_ADMIN_TOKEN` protects global registry
  administration, including suspend and resume. Store it in secret storage;
  never log it or place it in a command line.
- [ ] `IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_RATE_LIMIT_PER_MINUTE` sets the
  registration attempt limit. Set an explicit conservative value and alert on
  repeated rate-limit hits.
- [ ] `IRONMESH_RENDEZVOUS_GLOBAL_CHALLENGE_TTL_SECS` sets proof challenge
  lifetime. Set an explicit short operational value and reject expired or
  reused challenges.
- [ ] `IRONMESH_RENDEZVOUS_GLOBAL_MAX_PENDING_CHALLENGES` bounds in-memory
  outstanding registration challenges. Set an explicit conservative value and
  alert when the service rejects registrations because the bound is exhausted.
- [ ] `IRONMESH_GLOBAL_RENDEZVOUS_REGISTRATION_ENABLED` is the server-node
  opt-in. Enable it only on nodes intended to self-register and only after the
  service-side gate is enabled.

These names are the Phase-2 contract. The service and node must not silently
substitute alternate names or treat node opt-in as permission to bypass the
global service gate.

## Registry and admission

- [ ] Enforce exactly one active P-256 CA per `cluster_id`. The cluster SAN on
  a presented certificate selects that CA alone; never fall back to trying all
  registered CAs.
- [ ] Require the versioned canonical challenge proof for a new registration.
  A valid repeat with the same CA fingerprint is idempotent. Reject a different
  CA for an existing `cluster_id`; Option 1 has no CA rotation or CA rewrite.
- [ ] Record accepted, rejected, rate-limited, suspended, and resumed actions
  with timestamp, actor or source, cluster id when known, and reason. Do not
  log tokens, private keys, or proof signatures.

## Monitoring and response

- [ ] Monitor HTTPS certificate expiry, service availability, registry load or
  write failures, registration outcomes, proof failures, rate-limit events,
  and suspended-cluster activity.
- [ ] Alert on repeated invalid proofs, unexpected registration volume,
  registry persistence failures, admin-token failures, and relay or
  authentication errors that could indicate cross-tenant access attempts.
- [ ] Suspend a suspected cluster through the authenticated global admin
  control, retain the audit reason and timestamp, and verify that the service
  enforces the suspension before resuming it. Resume only after the incident
  review is recorded.
- [ ] For an active incident, first disable new registration with
  `IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_ENABLED=false`, suspend affected
  clusters, preserve registry and audit snapshots, rotate exposed service or
  admin secrets, and restore only from a verified registry backup if recovery
  is required.

See `docs/global-rendezvous-relay-e2e-plan.md` for the delivery status and
protocol rules, and `docs/nat-traversal-implementation-checklist.md` for the
repository-wide implementation status.
