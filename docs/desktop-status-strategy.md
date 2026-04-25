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
- The config app publishes a small merged JSON status document under
  `$XDG_RUNTIME_DIR/ironmesh/gnome-status.json`.
- The extension monitors that file and renders:
  - a single top-bar icon,
  - a menu with connection, sync, and replication rows,
  - a service summary row,
  - a menu action that opens the config app web UI,
  - stale / missing status handling when the config app is not running.

Current repo implementation:

- `crates/desktop-status/src/gnome.rs`
- `apps/config-app/src/main.rs`
- `apps/background-launcher/src/main.rs`
- `apps/folder-agent/src/gnome.rs` as folder-agent telemetry publishing
- `crates/adapter-linux-fuse/src/gnome.rs` as Linux FUSE telemetry publishing
- `apps/folder-agent/gnome-shell-extension/ironmesh-status@ironmesh.io/`

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

The config app owns the shared GNOME status document and combines three sources:

- local process state from managed config-app services:
  - launch reports and live process checks from `desktop-client-config`,
- detailed telemetry documents from active desktop runtimes:
  - `sync-agent-core::run_folder_agent_with_control` status callbacks for folder sync,
  - Linux FUSE mount lifecycle state from `adapter-linux-fuse`,
- authenticated remote status from existing IronMesh client JSON endpoints:
  - `/cluster/status`
  - `/cluster/replication/plan`
  - `/health` fallback

This gives us:

- local engine or mount state without inventing a second desktop-side status service,
- server / cluster visibility without requiring a second desktop-side service.
- one indicator owner even when several configured services are running in parallel.

### Current scope

The GNOME Shell extension consumes one merged config-app status document:

- the config app writes `$XDG_RUNTIME_DIR/ironmesh/gnome-status.json`,
- managed services write per-instance telemetry files under the desktop client state directory,
- the indicator derives one icon from the merged connection, sync, and replication facets,
- the indicator menu can open the config app web UI.

The low-level `--publish-gnome-status` flags remain available for direct runtime debugging, but the
packaged managed flow treats those files as service telemetry rather than the top-level indicator
owner.

## Operational flow

Recommended GNOME workflow today:

1. Install the extension:
  - `cargo run -p ironmesh-config-app -- gnome install-extension`
2. Start the config app:
  - foreground web UI: `cargo run -p ironmesh-config-app`
  - background managed-services owner: `cargo run -p ironmesh-config-app -- --background`
3. Define and start managed services in the config app. The config app publishes the merged status
   file, and service runtimes publish per-instance telemetry files for the aggregator.

Notes:

- `gnome print-status-path` prints the exact JSON path the extension watches.
- `--desktop-status-file` lets development environments override the config-app status path.
- Debian client installs ship an XDG autostart entry for `ironmesh-config-app --background`.
- The Windows prototype installer starts the packaged background launcher after `-Install`; the
  MSIX manifest also keeps the packaged startup task for later sign-ins.
- On GNOME Wayland, a newly copied user extension may not be discoverable until the next session.
  The installer now queues IronMesh in `org.gnome.shell enabled-extensions`, but initial activation
  can still require logging out and back in.
- Linux FUSE snapshot mode can publish per-service telemetry, but its connection and replication
  rows remain intentionally static/unknown because no live server polling is active.

## Follow-up backlog

- Add user-facing controls for enabling or disabling background autostart.
- Add a D-Bus transport if the indicator needs richer live actions.
- Add a generic `StatusNotifierItem` fallback implementation for non-GNOME Linux desktops.
