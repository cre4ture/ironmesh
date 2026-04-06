# Desktop Status Strategy

Status: Adopted for the GNOME-first desktop slice

## Summary

IronMesh should expose a compact desktop status surface that answers three questions quickly:

- Is the client connected to IronMesh right now?
- Is the local folder sync engine healthy or currently transferring changes?
- Is cluster replication healthy after local changes reach the server?

The first implementation priority is a native GNOME Shell extension because the current desktop
target is Ubuntu GNOME. Generic Linux tray support remains a compatibility path, not the lead UX.

## Product goals

- Put a single always-visible indicator in the desktop chrome.
- Keep the top-bar signal simple enough to scan at a glance.
- Keep the detailed breakdown one click away in the indicator menu.
- Avoid desktop-environment setup steps when we can provide a GNOME-native path.
- Reuse the same status model later on Windows, macOS, and generic Linux trays.

## Status model

The desktop indicator should summarize three facets:

1. Connection
   - Connected
   - Degraded
   - Unavailable
2. Local sync
   - Starting
   - Watching
   - Syncing
   - Error
   - Stopped
3. Replication
   - Healthy
   - Needs attention
   - Unknown

The top-level icon should be derived from those facets using this priority:

1. Error
2. Warning / degraded
3. Syncing
4. Healthy / watching
5. Stopped / unknown

This keeps the top bar legible while still preserving richer detail in the menu text.

## Platform order

### 1. GNOME Shell extension

Primary target for desktop status.

Why this is first:

- GNOME is the desktop environment we actively use.
- Ubuntu GNOME does not provide a uniformly reliable first-class tray experience without extra
  extensions.
- A native Shell extension avoids asking the user to install AppIndicator support before they can
  see IronMesh state.

Implementation shape:

- GNOME Shell extension in the top bar.
- IronMesh publishes a small JSON status document under
  `$XDG_RUNTIME_DIR/ironmesh/gnome-status.json`.
- The extension monitors that file and renders:
  - a single top-bar icon,
  - a menu with connection, sync, and replication rows,
  - stale / missing status handling when the agent is not running.

Current repo implementation:

- `apps/ironmesh-folder-agent/src/gnome.rs`
- `apps/ironmesh-folder-agent/gnome-shell-extension/ironmesh-status@ironmesh.io/`

### 2. Windows

Native Windows status remains a separate implementation.

Planned surface split:

- Notification-area icon for overall client state.
- Existing CFAPI shell integration for file-state visibility in Explorer.
- Optional taskbar overlay / progress for large transfers.

This repo already has the Windows provider groundwork in:

- `crates/adapter-windows-cfapi`
- `apps/os-integration`

### 3. macOS

Native macOS status should use a menu-bar extra plus the File Provider integration.

Planned surface split:

- Menu bar extra for global connection/sync/replication state.
- Finder-facing state through File Provider.

This repo already has a macOS File Provider scaffold in:

- `apps/apple-file-provider`

### 4. Generic Linux tray fallback

For KDE and other panels that support `StatusNotifierItem`, we should eventually add a generic tray
implementation. That is still useful, but it is no longer the primary Linux status UX.

## GNOME design details

### Indicator transport

The GNOME Shell extension consumes a JSON document instead of talking directly to the sync runtime
over D-Bus in the first slice.

Reasons:

- simpler to debug from the terminal,
- no GNOME Shell extension IPC boilerplate is required,
- the publisher can be reused by tests and future non-GNOME surfaces.

The transport remains intentionally small so we can switch to D-Bus later if we want richer live
interaction.

### Data sources

The GNOME publisher combines two sources:

- local sync state from `sync-agent-core::run_folder_agent_with_control` status callbacks,
- authenticated remote status from existing IronMesh client JSON endpoints:
  - `/cluster/status`
  - `/cluster/replication/plan`
  - `/health` fallback

This gives us:

- local engine state without inventing a second sync state machine,
- server / cluster visibility without requiring a second desktop-side service.

### Current scope

The first GNOME slice is intentionally single-profile on desktop:

- one `ironmesh-folder-agent` runtime,
- one top-bar indicator,
- one aggregated profile label.

The JSON schema and the Rust publisher are shaped so we can expand to multiple profiles later
without redesigning the extension.

## Operational flow

Recommended GNOME workflow today:

1. Install the extension:
   - `cargo run -p ironmesh-folder-agent -- --root-dir /tmp/placeholder gnome install-extension`
2. Start the folder agent with GNOME status publishing:
   - `cargo run -p ironmesh-folder-agent -- --root-dir <dir> --server-base-url <url> --client-identity-file <file> --publish-gnome-status`
3. Let the extension read the shared status file from the runtime directory.

Notes:

- `gnome print-status-path` prints the exact JSON path the extension watches.
- `--gnome-status-file` lets development environments override the default runtime path.

## Follow-up backlog

- Add an autostart installer for the GNOME runtime path.
- Add an optional local web UI launcher from the indicator menu.
- Expand the GNOME publisher from single-profile to multi-profile aggregation.
- Add a D-Bus transport if the indicator needs richer live actions.
- Add a generic `StatusNotifierItem` fallback implementation for non-GNOME Linux desktops.
