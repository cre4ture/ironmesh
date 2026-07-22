# Server-Node Hardware & Reliability Telemetry Strategy

Status: Implemented (core), with a few deliberately deferred extensions (see "Implementation
status" below).

## Implementation status

The core of this strategy is implemented across the node and a new central collector service:

- **Node payload projection** (Section 2, 7): `crates/server-node-sdk/src/reliability_telemetry.rs`
  — a pure, allow-listed converter from the existing `hardware_health_report` into a reduced,
  pseudonymized batch. No raw struct passthrough, so new hardware-health fields cannot silently
  leak into telemetry.
- **Pseudonymization & opt-out** (Section 3, 4.1): HMAC-derived `telemetry_subject_id` with a
  locally persisted salt; `IRONMESH_RELIABILITY_TELEMETRY_ENABLED` env default plus a persisted
  admin override.
- **Transparency endpoints** (Section 3.3): admin-authenticated
  `GET/PUT /api/v1/auth/telemetry/settings` and `GET /api/v1/auth/telemetry/preview`, surfaced in
  the `server-admin` HardwarePage (toggle, exact payload preview, subject id, last-sent state, and
  a bounded sent-history).
- **Background sender** (Section 6): a rare 6-24h timer that POSTs the batch to the collector, with
  bounded retries, content-fingerprint deduplication, and node-local last-sent/error bookkeeping.
- **RAM ECC (EDAC) and CPU thermal-throttle collectors** (Section 2.4): real Linux sysfs
  collection feeding `memory_ecc` and the findings summary.
- **Central collector** (Section 5): `crates/stats-collector-server` — tolerant ingestion with
  per-IP/per-subject rate limiting and append-only SQLite storage, a k-anonymity-safe public
  `GET /v1/stats/summary` (Section 4.3), admin-token-guarded GDPR access/erasure endpoints
  (Section 4.5), a retention sweeper (Section 4.6), and a server-side country-derivation seam
  (Section 4.2).

Deliberately **deferred** (documented at their respective sections, not blockers for the above):

- The first-run bootstrap consent screen (Section 4.4) — the opt-out env/admin toggle is live, but
  the guided setup-time disclosure is left to the `zero-touch-cluster-setup` work.
- A production GeoIP-backed `CountryResolver` (Section 4.2) — the seam and no-op resolver ship
  here; no GeoIP database dependency is bundled.
- Network interface error-rate metrics (Section 2.5), `telemetry_subject_id` rotation (Section 8),
  node-side daily SMART aggregation (Section 8), and an anonymous ingestion token (Section 5.2) —
  optional later stages.
- Production TLS termination / deployment wiring for the collector at `creax.de:44044` — a
  deployment concern, not hardcoded in the crate.
- The legal review of the opt-out-by-default posture (Section 4.4/8) remains a prerequisite before
  any production rollout that actually transmits data off-cluster.

Related documents:

- `docs/server-node-hardware-health-strategy.md` — per-node hardware inventory, SMART enrichment,
  and structured findings (`hardware_health_report`), already implemented
  (`crates/server-node-sdk/src/hardware_health.rs`).
- `docs/server-node-storage-stats-strategy.md` — per-node storage accounting, incremental counters,
  periodic reconciliation, and history retention conventions.
- `docs/security-architecture.md` — trust boundaries, mTLS node identity, admin plane model.
- `docs/multi-node-strategy.md` — cluster metadata model and the only existing "many nodes talk to
  one central service" precedent (rendezvous).
- `docs/data-scrub-auto-repair-strategy.md` — existing IronMesh-runtime-derived reliability findings.
- `docs/node-memory-footprint-reduction-plan.md` — precedent for resource-conscious background work.
- `docs/zero-touch-cluster-setup-strategy.md` — precedent for guided, low-friction admin UX, and the
  anchor point for the bootstrap-time consent step described in Section 4.4.

## 1. Motivation / Context

`docs/server-node-hardware-health-strategy.md` already built a solid, node-local building block: every
server node collects a normalized hardware inventory (system/board/BIOS, CPU, RAM, storage including
optional `smartctl` enrichment, NICs), maintains a lifecycle history (`node_first_seen_at_unix`,
component sightings, cumulative uptime), and derives structured `findings` and generated
`health_notes` from it. The result is visible via an admin-authenticated endpoint
(`GET /api/v1/auth/hardware/health`) and a dedicated `HardwarePage` in `server-admin` — but explicitly
**node-local only**: "This slice does not implement a central fleet collector. It deliberately stops
at producing a safe, structured per-node report that a future central service can ingest as-is."

This document describes exactly that next step: the **opt-out (i.e. enabled by default) transmission**
of a cleaned, project-wide comparable subset of this data to a central statistics collector service.

Benefits for the project:

- Fleet-wide analysis of which hardware model/firmware combinations produce above-average SMART
  warnings, scrub errors, or failures — over time and across all installations, not just a single
  operator's own cluster.
- Early warning for users and project maintainers: "Model X with firmware Y shows an unusually high
  rate of `media_errors` across the fleet."
- More robust capacity planning/recommendations ("which NVMe classes hold up how long in practice").
- A data foundation for future automated warnings in the admin UI ("this model has an elevated
  fleet-wide failure rate").

Benefit for the individual operator: in exchange for participating, `server-admin` can in the future
show fleet comparison values (e.g. "your node is at the fleet median for power-on hours"), which is not
possible without central collection.

This feature is explicitly distinct from `docs/server-node-hardware-health-strategy.md` and
`docs/server-node-storage-stats-strategy.md`: both existing documents/implementations stay node-local
and "not anonymous" (the board there explicitly allows `reporting_node_id` and exact hardware details,
since the operator of their own cluster has access anyway). Once data leaves the cluster's trust
boundary and goes to a service controlled by a third party (the project maintainers), stricter data
minimization and anonymization rules apply (see Section 4). This document therefore defines an
**export/reduction step**, not a 1:1 forwarding of the existing `hardware_health_report`.

## 2. Collected Metrics

The basis is, wherever possible, the collection model already implemented in `hardware_health.rs`
(Linux target platform: sysfs/procfs, `sysinfo`, optional `smartctl --json`). For each metric:
collectability on Linux, effort, benefit.

### 2.1 Storage / SMART (already implemented, reusable)

| Metric | Collectability on Linux | Effort | Benefit |
| --- | --- | --- | --- |
| `reallocated_sector_count` | `smartctl --json`, already in code (`HardwareStorageSmartInfo`) | none (reuse) | strong early indicator of HDD/SATA-SSD failure |
| `pending_sector_count` | same | none | strong early indicator |
| `offline_uncorrectable_sector_count` | same | none | strong early indicator |
| `crc_error_count` | same | none | cable/interface problems, not a pure media error |
| `power_on_hours` | same | none | age/wear comparison per model |
| `power_cycle_count` | same | none | usage load profile |
| `unsafe_shutdown_count` | same | none | correlates with filesystem/metadata errors |
| `percentage_used` / `available_spare_percent` | same (NVMe) | none | NVMe lifespan |
| `media_errors` / `error_log_entries` | same (NVMe) | none | direct error indicators |
| `temperature_celsius` | same | none | operating conditions, correlates with failure rates |
| `smart_passed` (overall verdict) | same | none | compact health status |
| `is_rotational`, `interface_type`, `bus_type` | already in inventory | none | segments the analysis by drive type |

All of these fields already exist 1:1 in `HardwareStorageSmartInfo` / `HardwareStorageDevice` and only
need to be selected, not newly collected.

### 2.2 Node Lifecycle / Uptime (already implemented)

| Metric | Collectability | Effort | Benefit |
| --- | --- | --- | --- |
| `uptime_seconds`, `cumulative_observed_uptime_seconds` | already collected (`HardwareNodeLifecycle`) | none | proxy for reliability/crash frequency (many short uptimes = unstable) |
| `boot_id` change rate | derivable from persisted state | low | reboot/crash frequency per hardware profile |
| `hardware_profile_id` | already collected (deterministic hash over normalized inventory) | none | grouping key for fleet comparison, without exposing raw data |

### 2.3 IronMesh Runtime Reliability (partially implemented)

| Metric | Collectability | Effort | Benefit |
| --- | --- | --- | --- |
| Data-scrub findings by `finding_code` (see `docs/data-scrub-auto-repair-strategy.md`) | already available as scrub history | low (aggregation into counters) | reveals storage instability that SMART doesn't yet report |
| Repair success/failure rates | already available as repair history | low | reliability of the self-healing path across the fleet |
| Sampler/collector errors (storage-stats, process-stats samplers) | already anticipated in the `hardware_health` collector-status model | none | identifies environments where a collector structurally fails (e.g. missing `smartctl`) |

### 2.4 RAM/CPU Errors (included in v1 for RAM ECC; CPU errors remain out of scope)

- **ECC errors (RAM):** on Linux, generally readable via `EDAC`
  (`/sys/devices/system/edac/mc/mc*/ce_count`, `.../ue_count`) — *but only* if the board/BIOS supports
  ECC RAM and the EDAC driver. On most consumer boards (no ECC) this yields nothing. Effort: low
  (sysfs parsing, an optional field analogous to `smartctl`). **Decision (per project owner
  feedback):** include this in the initial (v1) implementation, not deferred, precisely *because* the
  effort is low — this lets us see, from real fleet data, how valuable the signal actually is, even
  though only a subset of the fleet (server/workstation boards) will report it. It is modeled as an
  optional field with `available: bool`, following the existing collector-status conventions, so
  boards without ECC support simply report `available: false` instead of a misleading zero.
- **CPU errors:** there is no reliable, broadly available Linux interface for corrected CPU-internal
  errors on consumer hardware (MCE/`mcelog` exists but is inconsistently available and often requires
  root privileges beyond the server process's sandboxing). Instead of true CPU errors, the v1 scope is
  limited to **CPU throttling events** via `/sys/class/thermal` as a proxy for thermal problems (low
  effort, medium benefit). True MCE logging remains excluded for now — the interface is not reliable
  enough across the fleet's hardware diversity to justify the effort at this stage, unlike ECC where
  the interface is uniform and simply reports "unsupported" where absent.

### 2.5 Network Error Rates (not implemented, low additional effort)

- `rx_errors`, `tx_errors`, `rx_dropped`, `rx_crc_errors` per interface are directly readable on Linux
  via `/sys/class/net/<iface>/statistics/*` (no root, no extra tooling needed). Effort: low. Benefit:
  medium — mainly as a correlation signal for replication/transport problems, less so as a standalone
  "hardware reliability" indicator. Planned as an optional, low-priority addition for the first rollout
  stage, not part of the minimal core schema (Section 7).

### 2.6 Deliberately Excluded

Analogous to the "forbidden" list in `docs/server-node-hardware-health-strategy.md`, but tightened
further for the central collector (see Section 4): no `hostnames`, IP addresses, MAC addresses, object
keys/paths, raw serial numbers, raw log lines, `public_url`, `cluster_id`, user/admin labels. This
applies even to the coarse location feature in Section 4.2: the raw source IP used to derive a country
code is never persisted, logged, or forwarded — only the resulting country code is kept.

## 3. Opt-out Mechanism

### 3.1 Default Behavior

Transmission is **enabled by default** ("opt-out", not "opt-in"), consistent with the existing pattern
for other background features on the node (`IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED`,
`IRONMESH_REPLICATION_REPAIR_ENABLED`, `IRONMESH_STARTUP_REPAIR_ENABLED`,
`IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED` — all in `crates/server-node-sdk/src/lib.rs`, implemented with
`.unwrap_or(true)` and the same `"0" | "false" | "no"` parsing convention).

However, as described in Section 4.4, the *primary* rollout plan pairs this default-on toggle with a
mandatory, pre-selected confirmation step in the bootstrap/setup flow, rather than relying on a silent
background default alone.

Proposed new environment variable, in the exact existing style:

```rust
telemetry_enabled: std::env::var("IRONMESH_RELIABILITY_TELEMETRY_ENABLED")
    .ok()
    .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
    .unwrap_or(true),
```

### 3.2 Ways to Disable

- **Env var / config** (primary, consistent with all existing feature toggles on the node):
  `IRONMESH_RELIABILITY_TELEMETRY_ENABLED=0`.
- **Admin UI toggle** (for operators who don't want to work with config files/environment variables
  directly): a switch on the existing `HardwarePage` in `server-admin`
  (`web/apps/server-admin/src/pages/HardwarePage.tsx`), right next to the existing hardware-health
  display, since that's where the content is most closely related. The toggle needs to be persisted in
  node state (not just env), so it survives a restart — this requires a new, small persistent state
  entry (analogous to the `health/hardware-health-state.json` pattern) that treats the env var as the
  default but the UI setting as an override.
- Admin endpoint to read/set, following the existing auth pattern (`authorize_admin_request`, as in
  `hardware_health_current`): e.g. `GET/PUT /api/v1/auth/telemetry/settings`.

### 3.3 Transparency Before Sending

Important for trust and GDPR transparency obligations: the operator must be able to see **exactly**
what would be sent **before** every transmission. Analogous to the requirement already formulated in
the hardware-health document ("The page should make export easy by exposing the exact JSON payload"):

- A new preview endpoint `GET /api/v1/auth/telemetry/preview` that returns exactly the JSON object that
  would actually be sent in the next batch (the same serialization code as the real transmission, no
  separately maintained "example schema").
- `server-admin` shows this preview in the HardwarePage/settings section, including a "last sent at
  ..." timestamp and a link/button to "show the last sent payload again" (for this, the last-sent
  payload is additionally kept node-locally, e.g. the last N batches, not just the current preview).
- A local log event (via the existing `tracing`/`LogBuffer` infrastructure already used for the
  `server-admin` Logs tab) on every actual send, so operators can also trace it in the Logs tab.

## 4. Data Protection (GDPR-relevant)

The data minimization rules already defined in the hardware-health document (no paths, URLs, IPs,
hostnames, MACs, raw serial numbers, raw logs) remain unchanged as a floor — they apply to the data
that may be extracted from the `hardware_health_report` at all. In addition, because this data now
reaches a service controlled by a third party:

### 4.1 Pseudonymization Instead of Plaintext Node Identity

The existing `reporting_node_id` (a stable, cluster-visible node UUID) **must not** be transmitted
directly to the central collector, since it is potentially re-identifiable in combination with other
cluster-internal information (e.g. by the operator themselves) and would be a stable tracking feature
for operator infrastructure over time.

Instead: a locally derived **telemetry pseudonym key**

```text
telemetry_subject_id = HMAC-SHA256(local_random_salt, "ironmesh-telemetry-v1" || node_id)
```

- `local_random_salt` is generated once locally and persisted (e.g. in the same state file as the
  telemetry toggle) the first time telemetry is enabled (i.e. at first confirmed send), and is never
  transmitted.
- This makes `telemetry_subject_id` stable enough over time for longitudinal analysis ("this node has
  shown rising `reallocated_sector_count` for 3 weeks"), but not traceable back to the cluster-internal
  `node_id` without knowing the local salt.
- Rotation: analogous to the 90-day retention convention from
  `docs/server-node-storage-stats-strategy.md`, an optional periodic rotation (e.g. every 180 days)
  could be offered to further complicate long-term tracking — this does break existing time series
  though; the exact rotation interval is an open question (Section 8) with a trade-off between
  statistical continuity and privacy.
- **No** `cluster_id`, `public_url`, node labels, or any other cluster affiliation is sent along.

### 4.2 Coarse Location Data

Unlike a strict "no location data at all" stance, this document includes an **opt-out-covered, coarse,
country-level** location signal, per explicit project-owner feedback: seeing roughly where in the world
IronMesh is deployed (as other open-source projects with telemetry/usage maps do) is considered
valuable enough to include, as long as it cannot be used to narrow down a specific installation.

- **What is collected:** only an ISO-3166-1 alpha-2 **country code** (e.g. `"DE"`, `"US"`), nothing
  finer (no region, city, postal code, coordinates, or timezone/locale-derived signals).
- **How it is derived:** server-side, at ingestion time, from the TCP source IP address of the
  request — never self-reported by the node, and never derived from GPS/Wi-Fi/IP lookups performed on
  the node itself. This avoids adding any new geolocation logic or dependency to the server-node
  binary.
- **What is *not* persisted:** the raw source IP address is used only in-memory to resolve the country
  code and is discarded immediately afterwards — it is never logged, stored, or forwarded, consistent
  with the "no IP addresses" rule in Section 2.6.
- **Aggregation safeguard:** the public "where in the world is IronMesh used" view only ever shows
  counts per country (e.g. on a world map), never a per-`telemetry_subject_id` breakdown. Section 4.3's
  k-anonymity threshold applies to any cross-tabulation of `country_code` with `hardware_profile_id` as
  well, so that a rare hardware profile in a low-population country cannot be used to single out one
  installation.
- This keeps the original reasoning intact — no fine-grained location, no cross-linkable identifiers —
  while still delivering the "rough world map of usage" the project owner asked for.

### 4.3 Aggregation to Avoid Inference

- `hardware_profile_id` (already deterministically hashed from the normalized inventory, see the
  hardware-health document) remains the grouping key for fleet comparisons, not the exact raw
  inventory. For rare hardware combinations (e.g. a unique custom board) — and, per Section 4.2, for
  rare `country_code` × `hardware_profile_id` combinations — the central service should not expose
  groups below a minimum size (e.g. < 5 nodes per grouping key) individually in publicly/aggregated
  views, to prevent de-anonymization through combination of rare attributes (k-anonymity threshold).
- Raw data (per-`telemetry_subject_id` batches) is stored separately from aggregated/published
  statistics and is not publicly accessible (see Section 5.3).

### 4.4 Legal Basis Under the Opt-out Model

**Primary plan (per project owner feedback):** rather than relying purely on a silent, background
opt-out default, the rollout is anchored on an **explicit-but-preselected confirmation step in the
first-run bootstrap/setup flow**, tied into `docs/zero-touch-cluster-setup-strategy.md`'s "Start a new
cluster" / "Join an existing cluster" steps. The telemetry toggle is pre-checked "on" (so the default
outcome is still opt-out, not opt-in), but the operator must consciously view and pass through a
disclosure screen — listing what is collected, linking to this document, and offering the same preview
described in Section 3.3 — before initial setup can complete. After this first-run confirmation, the
ongoing opt-out mechanics from Section 3 (env var, admin UI toggle) apply for later changes without
repeating the full disclosure flow.

This resolves most of the "opt-out vs. opt-in" tension in practice: the outcome is still opt-out
(pre-selected, no action needed to keep it enabled), but it is never silent — every operator sees the
disclosure at least once, at the point where they are already making comparable decisions (cluster
name, admin credentials, etc.).

The underlying legal basis remains **legitimate interest** (Art. 6(1)(f) GDPR) in reliability
statistics, now further strengthened by:

- the mandatory first-run disclosure (Section 4.4, above),
- strong data minimization (Sections 4.1–4.3),
- full transparency before every transmission (Section 3.3),
- a simple, always-effective objection mechanism (opt-out, Section 3.2),
- no transmission of user content/object data.

This assessment is **not a substitute for a legal review** before production rollout (see Section 8) —
in particular for EU-based users, a data protection impact assessment, or at least a short review,
should be carried out before rollout, since "opt-out by default" is viewed critically in parts of GDPR
interpretation (cf. e.g. cookie-consent case law that requires opt-in for comparable cases). The
bootstrap confirmation step above is this document's proposed way of addressing that risk without
resorting to a full interactive opt-in flow during normal operation.

### 4.5 Right to Erasure and Access

Still needed, even though the collected data is pseudonymized rather than tied to a real-world
identity: pseudonymous data is not the same as truly anonymous data under GDPR, since a
`telemetry_subject_id` remains a stable identifier that its holder (the operator) can use to single out
"their" data over time — that re-identifiability by the data subject themselves is exactly why a
deletion path is still warranted, not optional.

The practical implementation, however, is intentionally lightweight *because* the data is pseudonymous:

- Since `telemetry_subject_id` cannot be mapped back to a node without the locally held salt, the
  central service itself cannot match an erasure/access request to an operator — the operator supplies
  their own `telemetry_subject_id` value (made visible in the preview/settings UI, see Section 3.3).
- No identity verification is required for this request: knowledge of the `telemetry_subject_id` value
  is sufficient proof of "ownership", since it isn't personally identifying information to begin with.
  This keeps the process self-service and low-effort compared to a typical GDPR access request.
- The admin UI therefore gets a "request deletion/access" action that displays `telemetry_subject_id`
  and offers a prepared contact route/email text (exact form still open, Section 8).
- On request for a given `telemetry_subject_id`, the central service must be able to delete all
  associated raw records, without needing to retroactively correct aggregated statistics that are
  already k-anonymized (standard practice for aggregate statistics).

### 4.6 Retention Periods

Following the existing 90-day convention for storage-stats history
(`docs/server-node-storage-stats-strategy.md`):

- Raw data batches (per `telemetry_subject_id`, timestamped): proposed 180-day retention, after which
  they are automatically deleted or reduced to coarsely aggregated time series with no
  `telemetry_subject_id` reference.
- Aggregated/anonymized fleet statistics (e.g. "failure rate by `hardware_profile_id` and month"): may
  be retained indefinitely, since they are no longer personal data, provided the k-anonymity threshold
  from Section 4.3 is respected.

## 5. Central Statistics Collector Architecture

### 5.1 Existing Central Services as Precedent

The codebase currently has two central services addressed by many nodes/clients:

- `crates/rendezvous-server` — the only existing "many nodes/clients talk to one central service"
  building block in the project, with an HTTPS control API, optional mTLS
  (`docs/security-architecture.md`, Section 4.2.1), and a WebSocket relay.
- `crates/web-ui-backend` — by contrast, is not a central multi-tenant service, but a backend that runs
  per client session and talks to one or more server nodes connected by the user. Not a good precedent
  for a fleet-wide collector.

The new statistics collector is functionally closer to `rendezvous-server` (many independent
installations talking to one central, project-operated service) than to `web-ui-backend`.
Recommendation: **a new, standalone service** (e.g. `crates/stats-collector-server`) rather than
docking onto `web-ui-backend` or `rendezvous-server` — both existing services have a different trust and
operational model (cluster-internal, or connection brokering respectively), and mixing in fleet-wide
telemetry would unnecessarily complicate their security boundaries.

### 5.2 Ingestion Endpoint

- **Hosting assumption (per project owner):** the central service is assumed to be hosted at
  `creax.de`, port `44044`.
- Protocol: HTTPS (TLS 1.3), consistent with all other IronMesh HTTP services.
- Auth: deliberately **no** per-node mTLS as in the cluster-internal case — the collector should
  specifically *not* know which cluster/operator a given record belongs to. Instead:
  - no client identity proof beyond the `telemetry_subject_id` that is already part of the payload,
  - abuse protection via rate limiting per source IP and per `telemetry_subject_id` (not via
    login/token), plus a simple plausibility check of the payload schema,
  - optionally (open question, Section 8): an anonymous ingestion token issued once on first
    activation, to make spam/forgery harder without exposing identity.
- Endpoint shape: `POST https://creax.de:44044/v1/ingest/hardware-reliability` with the versioned
  payload sketched in Section 7.

### 5.3 Storage / Access Control

- Raw data ingestion: simple append-only storage (e.g. a relational DB or a time-series store),
  separate from the publicly accessible aggregate view.
- Aggregation: a periodic batch job that condenses raw data into k-anonymous fleet statistics per
  `hardware_profile_id` (and, per Section 4.2, per `country_code` combination) (see 4.3).
- For the time-series aggregation itself — unlike the per-node storage-stats history (where
  `docs/server-node-storage-stats-strategy.md` deliberately decides against an external time-series DB
  per node) — a dedicated time-series/analytics store actually fits here, because this is *one* central
  service rather than many per-node instances. The "GreptimeDB as a future central backend" idea
  already noted in the storage-stats document fits better here than in the node-local case.
- Access control:
  - Raw data (including `telemetry_subject_id` mapping over time): project maintainers/operators of
    the collector service only, admin-authenticated analogous to the existing
    `IRONMESH_ADMIN_TOKEN`/RBAC model from `docs/security-architecture.md`.
  - Aggregated, k-anonymous processed statistics: publicly viewable (e.g. a future "Fleet Reliability"
    dashboard, including the country-level usage map from Section 4.2), since that is exactly the
    community value this feature provides.

### 5.4 Standalone Service vs. Existing Backend Infrastructure

Conclusion: a **new standalone service**, not docking onto `web-ui-backend` or `server-admin`. The
`server-node` itself only gains a new outgoing client (similar to the existing
`RendezvousControlClient` patterns in `client-sdk`) that periodically sends to the new service.

## 6. Transmission Frequency / Batching

Following the patterns already established in the storage-stats document (a combination of a periodic
timer and event-driven, debounced updates):

- No real-time transmission of individual findings — that would generate unnecessary network/
  battery/CPU load and would contradict the principle from
  `docs/node-memory-footprint-reduction-plan.md` and the storage-stats document of pacing background
  work in a resource-conscious way.
- A batch summarizes the current state of the reduced `hardware_health_report` (see Section 2) at a
  point in time, not an event-by-event transmission.
- Proposal: a fixed periodic timer, analogous to the existing `HARDWARE_HEALTH_REFRESH_INTERVAL_SECS`
  (currently 5 minutes for the node-local refresh), but with a much less frequent send interval, e.g.
  every 6–24 hours — the node-local collection stays frequent (for admin-UI freshness), while the
  external transmission is deliberately rarer, since only trends over days/weeks matter.
- No additional immediate send on critical findings in the first rollout stage (consistent with the
  conservative "detect-only first" approach from `docs/data-scrub-auto-repair-strategy.md`); an
  optional accelerated send on new `critical` findings could be a later expansion stage.
- Retry/backoff on send failures, analogous to the existing replication-repair pattern
  (`IRONMESH_REPLICATION_REPAIR_BACKOFF_SECS` as a model): failed batches are dropped or retried a
  limited number of times, never queued unboundedly (no unbounded growing send buffer).
- Deduplication: if nothing material has changed since the last successful send (no new finding, no
  SMART value change above a noise threshold), the send can be skipped to reduce baseline load — the
  exact threshold is an implementation detail.

## 7. Data Schema Versioning / Extensibility

- Every payload carries a top-level `schema_version: u32` field, starting at `1`.
- Additive evolution: new fields are only ever added as optional; existing fields are not renamed or
  have their meaning changed (a meaning change requires a new `schema_version`).
- The central service's ingestion endpoint is implemented tolerance-first: unknown extra fields are
  ignored rather than causing the request to be rejected (allows older servers to coexist with newer
  node versions, and vice versa).
- Analogous to the existing `collectors` status field in `hardware_health_report`, this payload also
  carries an `available: bool`/`collector_state` hint per metric group, so the central service can
  distinguish missing values from "deliberately unsupported" instead of interpreting nulls.
- Rough sketch schema (illustration, not a final specification):

```jsonc
{
  "schema_version": 1,
  "telemetry_subject_id": "hex-hmac...",
  "generated_at_unix": 1752912000,
  "ironmesh_version": "1.0.33",
  "hardware_profile_id": "hp-...",   // as in the existing hardware_health_report
  "country_code": "DE",              // derived server-side from source IP, see Section 4.2; optional
  "node_lifecycle": {
    "uptime_seconds": 431200,
    "cumulative_observed_uptime_seconds": 9871200,
    "boot_count_observed": 7
  },
  "storage_devices": [
    {
      "component_instance_id": "ci-...", // already hashed, see hardware-health document
      "is_rotational": false,
      "interface_type": "nvme",
      "smart": {
        "smart_passed": true,
        "power_on_hours": 5011,
        "reallocated_sector_count": 0,
        "media_errors": 0,
        "percentage_used": 12
      }
    }
  ],
  "memory_ecc": {
    "available": true,
    "correctable_error_count": 0,
    "uncorrectable_error_count": 0
  },
  "reliability_findings_summary": [
    { "finding_code": "chunk_hash_mismatch", "occurrence_count": 2 }
  ],
  "collectors": [
    { "collector_id": "smartctl", "available": true },
    { "collector_id": "edac", "available": true }
  ]
}
```

- Migration path: old `schema_version` payloads remain readable unchanged in raw storage; aggregation
  jobs must normalize in a version-aware way before aggregating across multiple `schema_version`
  values.

## 8. Open Questions / Next Steps

Resolved based on project-owner feedback on the initial draft:

- ~~Hosting of the central service~~ — assumed to be `creax.de`, port `44044` (see Section 5.2); exact
  budget/monitoring setup for operating it is still to be worked out separately.
- ~~RAM-ECC and CPU-MCE collection~~ — RAM ECC (via EDAC) is included in v1 at low effort, specifically
  to gather real data on how valuable the signal is; CPU-MCE remains excluded due to unreliable
  availability (see Section 2.4).
- ~~Cluster- vs. node-granularity of the opt-out~~ — confirmed as a per-node setting for now, consistent
  with all other node env-var toggles (see Section 3).

Still open:

- **Legal review before rollout:** is "enabled by default + opt-out", combined with the bootstrap
  confirmation step from Section 4.4, legally sufficient in the relevant jurisdictions (especially
  EU/GDPR)? Should be clarified before implementation, not just before release.
- **Rotation of `telemetry_subject_id`:** fixed interval (e.g. 180 days) vs. never rotating vs.
  user-controlled ("reset" button in the admin UI)? The trade-off between statistical continuity and
  privacy still needs a decision.
- **Abuse protection without identity:** how is spoofing/spam at the non-authenticated ingestion
  endpoint prevented, without introducing a de-anonymization risk via an auth token? An anonymous
  issuance token (Section 5.2) vs. pure IP rate limiting is still open.
- **Granularity of temperature/SMART time series:** should raw values be transmitted per batch, or
  already reduced node-side to daily aggregates (min/max/mean), to both save bandwidth and reduce the
  fingerprinting risk of individual devices via fine-grained time series?
- **Relationship to the existing `/api/v1/auth/hardware/health` endpoint:** should the payload to be
  sent strictly be a derived, one-way projection from the existing `hardware_health_report` (a
  converter, not a second independent collection), to avoid drift between the node-local and centrally
  sent views? Recommendation: yes, this should be fixed as a requirement before implementation.
- **Admin UI placement:** a new dedicated `server-admin` page/settings section vs. extending the
  existing `HardwarePage.tsx` — still undecided (Section 3.2 proposes extending it, but the scope of
  settings might justify a dedicated settings page if further opt-out telemetry categories are added
  later).
