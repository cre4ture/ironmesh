---
name: windows-ci-access
description: Use when Codex is running on Linux but needs to reproduce or debug a Windows-specific CI failure for this Ironmesh repo. Provides the SSH target, the Windows repo path, and the native-Windows workflow for CFAPI and other OS-specific failures.
---

# Windows CI Access

Use this skill when a failing check needs native Windows behavior. Prefer this over WSL for CFAPI, Cloud Files, or other Windows-only filesystem behavior.

## Access

- Connect with `ssh Uli@192.168.178.129 -p 2222`.
- The repo on that machine is `C:\Users\Uli\rust-dev\ironmesh`.

## Workflow

- For one-off commands, prefer `pwsh -NoProfile -Command ...` over shell-specific wrappers.
- Start in `C:\Users\Uli\rust-dev\ironmesh` and reproduce the smallest failing Windows test or command first.
- Keep the investigation native to Windows. Do not use WSL for CFAPI or placeholder hydration issues.

## Example

```text
ssh Uli@192.168.178.129 -p 2222 "pwsh -NoProfile -Command \"Set-Location 'C:\Users\Uli\rust-dev\ironmesh'; cargo test --manifest-path tests/system-tests/Cargo.toml\""
```
