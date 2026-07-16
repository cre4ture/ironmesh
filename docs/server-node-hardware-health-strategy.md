# Server-Node Hardware Health Strategy

## Goal

Server nodes should report enough hardware and runtime health information to:

- detect likely hardware problems early,
- correlate IronMesh runtime failures with exact hardware builds,
- compare long-term robustness across hardware profiles and firmware combinations,
- avoid sending any user payload data, logical object names, paths, or ownership metadata.

This document defines the first complete slice to implement in the repository.

## Scope Of This Slice

This slice adds node-local hardware health reporting with:

- stable reporter identity via the existing node id,
- normalized hardware inventory,
- lifecycle and age signals for the node and individual components,
- structured findings from both host signals and IronMesh runtime signals,
- generated human-readable health notes derived only from structured fields,
- an admin API endpoint and server-admin page for inspection and export.

This slice does **not** implement a central fleet collector. It deliberately stops at producing a safe,
structured per-node report that a future central service can ingest as-is.

## Privacy And Data-Minimization Rules

The report is **not anonymous**. The reporting node may be identified. The privacy boundary is instead:

- include exact hardware composition and firmware details,
- exclude all user data and user-identifying operational context,
- exclude free-form notes or raw logs from outbound reports.

### Allowed

- node id,
- IronMesh version and revision,
- operating system, kernel, architecture,
- board/system vendor and model,
- BIOS/UEFI version,
- CPU vendor/model/frequency data,
- memory totals and inventory summaries,
- storage vendor/model/firmware/capacity/interface,
- NIC vendor/model/driver/firmware/speed,
- normalized lifecycle counters such as uptime, power-on hours, wear, power cycles,
- normalized findings with timestamps, severities, counts, and allowlisted evidence values.

### Forbidden

- object keys,
- snapshot ids,
- version ids,
- filesystem paths,
- mount paths,
- URLs, IP addresses, hostnames, DNS names,
- MAC addresses,
- raw log lines,
- usernames, admin labels, cluster labels,
- raw serial numbers.

### Stable Component Identity

Component-level trend tracking still needs stable identity. Therefore each component report carries:

- `component_instance_id`: a locally derived hash over stable low-level identifiers such as serial numbers,
  wwids, PCI addresses, or DMI identifiers,
- but **never** the raw identifier material itself.

This enables longitudinal failure tracking without centrally storing raw serial numbers.

## Data Model

### Top-Level Report

The node produces one structured `hardware_health_report` with:

- `reporting_node_id`
- `generated_at_unix`
- `ironmesh_version`
- `ironmesh_revision`
- `hardware_profile_id`
- `inventory`
- `node_lifecycle`
- `collectors`
- `findings`
- `health_notes`

### Hardware Profile

`hardware_profile_id` is a deterministic hash over the normalized hardware inventory excluding:

- runtime timestamps,
- per-report findings,
- stable component instance ids,
- local-only lifecycle counters.

This groups functionally identical hardware builds across the fleet.

### Inventory

The first slice inventory contains:

- system / board / BIOS summary,
- CPU packages and architecture summary,
- memory totals and DIMM-related summaries when available,
- storage devices,
- network devices.

Optional enrichment from `smartctl` is folded into storage devices when available.

### Lifecycle

The node stores a small local state file to preserve:

- `node_first_seen_at_unix`,
- `inventory_last_changed_at_unix`,
- `component_first_seen_at_unix`,
- `component_last_seen_at_unix`,
- observed cumulative uptime across restarts.

The report also includes current boot-derived values such as:

- `boot_id`,
- `booted_at_unix`,
- `uptime_seconds`,
- `cumulative_observed_uptime_seconds`.

### Findings

Each finding is structured as:

- `source`
- `category`
- `finding_code`
- `severity`
- `component_ref`
- `component_instance_id`
- `first_seen_at_unix`
- `last_seen_at_unix`
- `occurrence_count`
- `summary`
- `evidence`

`summary` must be generated from normalized fields only. It must never embed raw logs, keys, or paths.

## Collector Sources

### Host-Level Sources

The first slice uses:

- Linux sysfs / procfs for inventory,
- `sysinfo` temperatures and uptime,
- optional `smartctl --json` for storage lifecycle and failure indicators.

The implementation must degrade gracefully when optional sources are unavailable.

### IronMesh Runtime Sources

The first slice also derives findings from:

- latest retained data scrub results,
- latest retained repair history,
- recent in-memory runtime logs, but only via pattern classification,
- sampler runtime failures such as storage stats or process stats collector failure.

These sources are important because IronMesh may observe corruption or I/O instability before host tooling
reports a hard failure.

## Notes Generation

The backend generates concise `health_notes` from structured findings and inventory. Notes are for operator
readability only and are always derived, never user-authored.

Examples:

- `Disk Samsung PM9A3 on firmware GDC5502Q reports 2 media errors and 94% available spare.`
- `Latest data scrub detected 3 chunk_hash_mismatch issues on this node.`
- `Observed hardware profile changed 2 days ago; inventory drift may affect historical comparisons.`

## API

The first slice adds one admin-authenticated endpoint:

- `GET /api/v1/auth/hardware/health`

The response returns the current structured report together with collector runtime status.

## Admin UI

The server-admin UI adds a dedicated Hardware page that shows:

- hardware profile and node lifecycle summary,
- generated notes,
- collector status,
- current findings,
- normalized hardware inventory grouped by component type.

The page should make export easy by exposing the exact JSON payload.

## Implementation Plan

1. Add backend report structs, lifecycle-state persistence, and collection runtime.
2. Add Linux inventory collection plus optional `smartctl` enrichment.
3. Derive host findings and IronMesh runtime findings without leaking user data.
4. Expose the report through a new admin API route and typed frontend client.
5. Add a server-admin Hardware page for inspection and JSON export.
6. Add focused tests for lifecycle persistence, finding sanitization, and optional `smartctl` parsing.

## Validation Criteria

The slice is complete when:

- a node can produce a report with stable node identity and hardware profile id,
- no object keys, paths, URLs, hostnames, IPs, or raw log lines appear in the report,
- storage and runtime findings are visible in the API and admin UI,
- component first-seen and observed uptime survive restart via local persistence,
- the implementation builds and targeted tests pass.
