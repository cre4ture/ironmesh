# Manual Packaged Windows Sync-Root Restart Test

This guide is the operator-facing packaged Windows validation for Pass 8.

It proves that a packaged `ironmesh-os-integration` instance can:

- register a Windows sync root from the packaged config app,
- persist bootstrap and identity state under `%LocalAppData%\Ironmesh\sync-roots\...`,
- reconnect after the packaged runtime is stopped,
- continue syncing after the original bootstrap file is removed.

It complements, rather than replaces, automated coverage in `tests/system-tests/src/cfapi_monitor_test.rs`, especially `test_cfapi_adapter_persists_local_appdata_state_and_restarts_without_bootstrap_argument`.

## Preconditions

- A packaged Windows client build is already installed.
  This can be a Store-installed build or a locally sideloaded MSIX build.
- You have a valid client bootstrap JSON from a release-candidate test node or cluster.
- That bootstrap points at a reachable HTTPS server-node environment.
- You can read and write files under `%LocalAppData%` and under a test folder such as `%USERPROFILE%\Desktop`.

The easiest way to obtain the bootstrap is to use the direct-enroll flow documented in [docs/ci-runbook.md](ci-runbook.md) and copy the resulting bootstrap file onto the Windows test machine.

## Test values

Run these PowerShell commands first:

```powershell
$Bootstrap = Join-Path $env:TEMP "ironmesh-client-bootstrap.json"
$Root = Join-Path $env:USERPROFILE "Desktop\Ironmesh Manual Sync Root"
$SyncRootId = "ironmesh.manual.release.syncroot"
$DisplayName = "Ironmesh Manual Sync Root"
$ConfigPath = Join-Path $env:LOCALAPPDATA "Ironmesh\desktop-client-config\instances.json"
$LaunchReportPath = Join-Path $env:LOCALAPPDATA "Ironmesh\desktop-client-config\last-launch-report.json"
$SyncRootsRoot = Join-Path $env:LOCALAPPDATA "Ironmesh\sync-roots"

New-Item -ItemType Directory -Force -Path $Root | Out-Null
Remove-Item -Recurse -Force $Root\* -ErrorAction SilentlyContinue
```

Copy the bootstrap bundle into `$Bootstrap` before continuing.

## 1. Launch the packaged config app

Open the installed `Ironmesh Config App` from the Start menu.

Confirm the app reports these paths on the overview panel:

- config path: `$ConfigPath`
- launch report path: `$LaunchReportPath`

If the app cannot start or those paths are missing, fail the test.

## 2. Create one Windows OS integration instance

In the `OS Integration Instances` section, create one enabled instance with these values:

- `Instance Name`: `manual-windows-sync-root`
- `Enabled`: checked
- `Sync Root Identifier`: `$SyncRootId`
- `Folder Name in Explorer`: `$DisplayName`
- `Local Folder Location`: `$Root`
- `Initial Setup File`: `$Bootstrap`
- `Remote Folder Prefix`: leave empty unless the bootstrap is intentionally prefix-scoped

Save the instance.

Pass or fail rule:

- `instances.json` is created at `$ConfigPath`.
- The saved instance appears in the config app list with the values above.

## 3. Start the packaged background service once

In the config app, click `Run Enabled Services`.

Wait until the launch report panel updates.

Pass or fail rule:

- `last-launch-report.json` is created at `$LaunchReportPath`.
- The launch report shows the enabled `os-integration` instance starting successfully.
- Explorer shows the configured sync root at `$Root` or under the configured display name.

## 4. Verify LocalAppData sync-root state was materialized

Run these PowerShell commands:

```powershell
Get-ChildItem -Recurse $SyncRootsRoot
```

You should find a sync-root-specific state directory containing at least:

- `connection-bootstrap.json`
- `client-identity.json`

Pass or fail rule:

- both files exist under `%LocalAppData%\Ironmesh\sync-roots\...`
- the original sync-root folder does not contain legacy hidden bootstrap files such as `.ironmesh-connection.json` or `.ironmesh-client-identity.json`

## 5. Prove the first live sync works

Create one file inside the sync root:

```powershell
Set-Content -Path (Join-Path $Root "manual-first-upload.txt") -Value "first packaged windows upload"
```

Verify the remote side sees the new object using whatever release-candidate validation surface you are already using for the same environment. Acceptable checks include:

- `ironmesh` CLI `get manual-first-upload.txt`
- server-admin object browser
- direct server API read through an authenticated client

Pass or fail rule:

- the remote side eventually shows `manual-first-upload.txt`
- its contents match `first packaged windows upload`

## 6. Stop the packaged runtime and remove the original bootstrap file

Stop the packaged `ironmesh-os-integration` process using Task Manager or PowerShell.

One reliable PowerShell option is:

```powershell
Get-Process ironmesh-os-integration -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item $Bootstrap
```

Pass or fail rule:

- the process stops,
- the original bootstrap file at `$Bootstrap` is gone,
- the `%LocalAppData%\Ironmesh\sync-roots\...` state files remain.

## 7. Restart from persisted LocalAppData state only

Return to the packaged config app and click `Run Enabled Services` again.

Pass or fail rule:

- the launch report shows a second successful start,
- the sync root reconnects without needing the deleted bootstrap file,
- no manual instance editing is needed before restart.

## 8. Prove post-restart sync still works

Create one more file after the restart:

```powershell
Set-Content -Path (Join-Path $Root "manual-restart-upload.txt") -Value "second packaged windows upload"
```

Verify the remote side sees the restarted upload.

Pass or fail rule:

- the remote side eventually shows `manual-restart-upload.txt`
- its contents match `second packaged windows upload`

## Optional stronger check

If you want one stronger reconnect proof, create a remote file while the runtime is stopped, then confirm it appears locally after step 7.

## Final pass criteria

This manual flow passes only if all of the following are true:

- the packaged config app can save and relaunch an enabled Windows `os-integration` instance,
- LocalAppData sync-root state is created under `%LocalAppData%\Ironmesh\sync-roots\...`,
- deleting the original bootstrap file does not break restart,
- uploads succeed both before and after restart.

## Record the run

Capture these artifacts for release sign-off:

- installed package version,
- timestamp of the run,
- the relevant `instances.json` entry,
- the relevant `last-launch-report.json` entry,
- confirmation of the two uploaded file names,
- whether Explorer restart guidance was needed.