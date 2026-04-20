# Backwards Compatibility Aliases And Helpers

Status: Living inventory of temporary compatibility shims, aliases, and format helpers that still exist in the repository.

Use this file to track anything that intentionally preserves older behavior while the canonical contract has already moved on. Review each entry periodically and remove rows as the underlying shim is deleted.

## Maintenance Rules

- Add a row when introducing a new compatibility alias, legacy parser path, or migration helper.
- Keep new code, docs, tests, and generated URLs on the canonical contract unless a row here explains why they cannot yet move.
- Remove the row in the same change that removes the alias or helper.

## Active Entries

| Surface | Canonical contract | Compatibility alias or helper | Implemented in | Remove when |
| --- | --- | --- | --- | --- |
| Server-node public client HTTP routes | `/api/v1/...` | `legacy_public_api` keeps the previous unversioned public routes alive; transport and streamed object handlers also strip `/api/v1` through normalization helpers so both forms keep working during migration | `crates/server-node-sdk/src/lib.rs`, `crates/server-node-sdk/src/transport_service.rs` | All bundled callers, SDK callers, docs, and any external consumers are confirmed to use `/api/v1/...` only |
| Bundled web backend HTTP routes | `/api/v1/...` | `legacy_api` keeps the older `/api/...` routes plus root `/media/thumbnail` alive for bundled-tool compatibility | `crates/web-ui-backend/src/lib.rs` | Bundled UIs and smoke tests no longer need the old `/api/...` or root thumbnail forms |
| Client SDK relative-path handling | `/api/v1/...` | `normalize_client_api_path` and `strip_client_api_v1_prefix` accept older relative paths while direct and multiplexed callers migrate | `crates/client-sdk/src/ironmesh_client.rs` | No internal caller still passes legacy public paths into SDK helpers |
| CLI direct-connection flag | `--server-base-url` | `--server-url` remains an alias for older scripts and docs | `apps/cli-client/src/main.rs` | Direct base-URL startup is fully migrated and the alias is no longer needed |
| Windows CA flag | `--server-ca-pem-file` | `--server-ca-cert` remains accepted as a legacy alias | `crates/adapter-windows-cfapi/src/cli.rs` | Generated commands, docs, and operator habits have moved to `--server-ca-pem-file` |
| Desktop-generated CA flag | `--server-ca-pem-file` | Some desktop-generated command lines still emit `--server-ca-cert` for compatibility with existing consumers | `crates/desktop-client-config/src/lib.rs` | Desktop command generation switches to the canonical flag everywhere |
| Client enrollment JSON field | `device_label` | `label` is still accepted as a serde alias for older enrollment/bootstrap payloads | `crates/client-sdk/src/device_auth.rs`, `crates/client-sdk/src/bootstrap.rs`, `crates/transport-sdk/src/identity.rs`, `crates/server-node-sdk/src/lib.rs` | Older enrollment/bootstrap payloads are no longer expected in the field |
| Desktop managed JSON stores | Top-level `version: 1` | Missing version markers are still treated as legacy v1 for older persisted files | `crates/desktop-client-config/src/lib.rs`, `crates/windows-client-config/src/lib.rs` | Legacy files without explicit version markers no longer need to load in place |
| SQLite schema markers | `cache_meta(schema_version)` and `metadata_meta(schema_version)` rows | Missing schema-version rows are still accepted as legacy current-version databases and rewritten on open | `crates/client-sdk/src/content_addressed_client_cache.rs`, `crates/server-node-sdk/src/storage/sqlite_impl.rs` | All supported databases are known to contain explicit schema rows |

## Review Notes

- Prefer case-by-case cleanup. A compatibility shim can be removed as soon as its own callers are gone; this file is not an all-or-nothing gate.
- When removing a route alias, update the relevant smoke tests first so the canonical path is enforced before the shim disappears.