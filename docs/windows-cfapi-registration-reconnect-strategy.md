# Windows CFAPI Registration And Reconnect Strategy

Status: Proposed design note

## 1. Summary

This note proposes a stricter lifecycle for the Windows CFAPI provider:

- treat CFAPI sync-root registration as persistent OS state, not something to tear down and recreate on every provider start,
- allow first-time registration only on an empty folder,
- treat `unregister` as an explicit local disconnect from the cloud,
- stop implicitly adopting pre-existing local content during plain registration,
- use Windows-persisted sync-root registration metadata as the primary ownership check,
- move restart reconciliation metadata into per-item `FileIdentity`,
- remove `.ironmesh-remote-snapshot.json` from the correctness path.

The main goal is to make the local/cloud relationship predictable and reviewable. A folder should be in one of two states:

- not an IronMesh sync root, or
- an IronMesh sync root with explicit persisted ownership metadata.

We should avoid the ambiguous middle ground where an ordinary populated folder can silently become cloud-managed just because the provider was started on it.

The key update to the earlier version of this note is:

- a separate `.ironmesh-root.json` file is not required for the new strategy,
- we should first ask Windows whether the folder is already registered and, if so, read the persisted sync-root identity from the registration itself,
- `SyncRootIdentity` should hold the root-level ownership/configuration identity,
- per-item `FileIdentity` should hold the file-level reconciliation identity,
- because this is pre-release, we do not need a backwards-compatibility or rollout plan for old populated local roots; we can start with newly created empty local folders only.

## 2. Problems In Current Behavior

Today the CFAPI adapter can be started on a non-empty folder and will treat pre-existing local files as upload candidates. That is useful for a local-first import workflow, but it is dangerous as a default because:

- it blurs initial registration, reconnect, and import/adopt into one action,
- it makes it hard to interpret `unregister`,
- it encourages accidental cloud adoption of unrelated local files,
- it forces recovery logic to guess whether local content was previously cloud-managed.

The current implementation also re-registers when the root is already known by Windows:

- `crates/adapter-windows-cfapi/src/runtime.rs`
- `tests/system-tests/src/framework_win.rs`

That is convenient for tests, but not ideal as the intended product behavior.

## 3. Key Decisions

### 3.1 Registration is persistent OS state

Windows CFAPI registration should be treated as durable platform state. Provider startup should first ask Windows whether the folder is already under a registered sync root and only perform a new registration when no registration exists.

Implication:

- provider startup should prefer "connect to existing registration" over "unregister and re-register".

### 3.2 First-time registration should require an empty folder

A plain `register` operation should succeed only when the target folder is empty.

Allowed default case:

- empty directory that is not currently registered.

Rejected default cases:

- non-empty ordinary directory,
- directory with unknown or mismatched provider metadata,
- directory registered to a different sync root/provider identity.

### 3.3 Unregister means explicit disconnect

`unregister` should mean that the local tree is intentionally severed from its cloud-managed identity.

Implications:

- after `unregister`, the folder should no longer be considered reconnectable by default,
- runtime caches should be removed or invalidated,
- any provider-owned reconnect metadata that survives outside Windows registration should be removed or invalidated so a future plain `register` treats the folder as unmanaged.

### 3.4 Reconnect is only for matching IronMesh-managed roots

A non-empty folder should only be reconnectable when Windows already knows it as an IronMesh-managed sync root and the persisted registration identity matches the requested identity.

This should not rely on incidental files like the connection bootstrap or runtime snapshot cache alone.

## 4. How Startup Should Work

Provider startup should follow this order:

1. Ask Windows whether the target folder is already registered as a sync root.
2. If Windows says the folder is not registered:
   - require the folder to be empty,
   - perform first-time registration,
   - store IronMesh root identity inside the Windows sync-root registration.
3. If Windows says the folder is already registered:
   - read the persisted sync-root identity from Windows,
   - verify that it matches the expected IronMesh identity,
   - if it matches, connect and serve,
   - if it does not match, fail loudly and require manual resolution.

We should not automatically unregister and replace an existing registration during normal startup.

## 5. What Counts As "Matching IronMesh Metadata"

The primary ownership record should be the Windows-persisted sync-root identity from the CFAPI registration itself.

Recommended contents of the sync-root identity blob:

- `provider_instance_id`
- `cluster_id`
- `sync_root_id`
- `prefix`
- optional schema version

This Windows-persisted blob should be the source of truth for "does this folder belong to this IronMesh root?" during normal provider startup.

A reconnect should require at least:

- same `cluster_id`,
- same logical `sync_root_id`,
- same namespace `prefix`,
- same provider identity/versioning scheme.

If any of those mismatch, startup should fail instead of trying to heal the situation implicitly.

We should keep the initial implementation minimal and avoid adding mirrored metadata files unless later debugging needs prove they are worth it.

## 6. Why Existing Metadata Is Not Enough

Current on-disk metadata is not sufficient to make this decision reliably:

- `.ironmesh-connection.json`
  - useful for connectivity,
  - not a strong ownership marker,
  - can also be stored outside the sync root when `--bootstrap-file` is used.
- `.ironmesh-client-identity.json`
  - identifies the device,
  - not the local root ownership,
  - can also live outside the sync root.
- `.ironmesh-remote-snapshot.json`
  - current runtime reconciliation cache,
  - should not be part of the new correctness design,
  - the root-wide remote snapshot is the wrong storage shape for per-item reconciliation data.
- placeholder `FileIdentity`
  - useful while the file remains a placeholder,
  - is the right place for per-item reconciliation data,
  - is not the right place for the root-level ownership proof because it is per-file metadata, not a single root-scoped source of truth,
  - is less directly queryable for root ownership than the sync-root registration metadata itself,
  - may disappear when the root is explicitly unregistered and files are reverted to normal files, which is acceptable because explicit unregister should sever the reconnect path anyway.

## 7. FileIdentity And USN Guidance

Per-file CFAPI metadata is still useful, just not as the primary reconnect check.

Recommended usage:

- `SyncRootIdentity`
  - use as the primary Windows-persisted root ownership metadata,
  - query it at startup to decide whether an existing registration matches the requested IronMesh root.
- `FileIdentity`
  - use it for provider-owned per-file metadata such as normalized path, remote version, remote hash, and last-known clean local hash,
  - make it the primary place for file-level restart reconciliation state.
- USN / change-tracker values
  - use them as change/race guards,
  - do not use them as the sole proof that a file still represents the last synced bytes.

Root ownership and reconnect decisions should be based on the Windows-persisted root registration identity, not inferred from per-file state.

### 7.1 Per-item `FileIdentity` payload

The new strategy should store the following per-item metadata in each placeholder's `FileIdentity`:

- `v`
  - schema version.
- `p`
  - normalized relative path.
- `rv`
  - remote version identifier.
- `rh`
  - remote content hash.
- `rs`
  - remote size in bytes.
- `lh`
  - last-known clean local content hash.
- `pi`
  - provider instance id from the current sync-root registration.

Suggested semantics:

- `rv`, `rh`, and `rs` identify the remote state this placeholder currently represents.
- `lh` identifies the last local byte sequence that was known to be clean and in-sync.
- `pi` lets the provider reject stale per-file metadata if the root is later re-created under a different provider instance.

### 7.2 Concrete size estimate

Using a compact newline-delimited encoding rather than pretty JSON, the non-path fields are small:

- `v=1`
  - about 4 bytes plus newline.
- `rv=<remote version>`
  - typically 20-80 bytes.
- `rh=<64 hex chars>`
  - about 68 bytes.
- `rs=<decimal size>`
  - about 8-24 bytes.
- `lh=<64 hex chars>`
  - about 68 bytes.
- `pi=<uuid>`
  - about 40 bytes using canonical UUID text.

That means the fixed overhead excluding `p` is roughly:

- about 190-300 bytes in common cases.

The dominant variable is `p`, the normalized relative path. That path is already stored in `FileIdentity` today, so the new strategy does not introduce a new fundamental limit. It mainly adds around 180-220 bytes of extra reconciliation metadata on top of the existing path payload.

In practice this should fit comfortably inside the 4 KB `FileIdentity` budget for normal path lengths. If we later want more margin, we should keep the encoding compact or switch to a binary encoding instead of JSON.

### 7.3 What remains for `.ironmesh-remote-snapshot.json`

For the new strategy, nothing needs to remain in `.ironmesh-remote-snapshot.json` for correctness.

The intended end state is:

- `SyncRootIdentity`
  - root ownership/configuration identity.
- per-item `FileIdentity`
  - per-item reconciliation identity.
- no required root-wide snapshot JSON file.

If we keep `.ironmesh-remote-snapshot.json` at all, it should be treated as optional diagnostics only, not as part of the provider's required restart logic.

## 8. Terminology Clarification

The CFAPI naming here is easy to confuse. We should distinguish three different things:

- `SyncRootIdentity`
  - provider-defined opaque metadata stored in the Windows sync-root registration,
  - root-scoped,
  - queryable through sync-root info APIs,
  - returned in callbacks,
  - suitable for reconnect/ownership decisions,
  - size limit: 64 KB.
- root directory `FileIdentity`
  - provider-defined opaque metadata for the root directory item itself,
  - item-scoped rather than registration-scoped,
  - returned only when the callback subject is the sync root itself,
  - useful for item metadata, but less suitable as the primary startup/reconnect truth,
  - size limit: 4 KB.
- `SyncRootFileId` / `FileId`
  - filesystem-maintained numeric identifiers,
  - not provider-owned opaque metadata,
  - useful for identifying filesystem objects, not for storing ownership/configuration data.

Recommended usage:

- put root ownership/configuration identity into `SyncRootIdentity`,
- use `FileIdentity` for per-file or per-directory provider metadata,
- treat `FileId` values as identifiers only, not as metadata storage.

## 9. Registration Rules

### 9.1 Allowed

- Empty folder, not currently registered.
- Already-registered folder with matching Windows sync-root identity and matching requested identity.

### 9.2 Rejected

- Non-empty folder that is not already a matching IronMesh root.
- Folder already registered to some other provider/root identity.
- Folder whose Windows sync-root identity is stale or mismatched.

## 10. Unregister Semantics

When unregistering a root, the provider should:

- disconnect from Windows CFAPI registration,
- remove runtime-only caches such as `.ironmesh-remote-snapshot.json`,
- leave ordinary user files alone unless a separate destructive cleanup flow is explicitly requested.

This preserves the meaning:

- cloud relationship removed,
- local data remains,
- future registration does not implicitly assume prior ownership.

## 11. Implementation Outline

### Phase 1

- Add startup validation helpers:
  - query Windows registration state for the folder,
  - read and validate the Windows-persisted sync-root identity,
  - detect whether the folder is empty except for explicitly internal IronMesh files.
- Change provider startup so it no longer blindly unregisters and re-registers an existing root.
- Remove `.ironmesh-remote-snapshot.json` from the required startup path.

### Phase 2

- Enforce empty-folder-only registration by default.
- Make mismatches fail with actionable error messages.
- Extend per-item `FileIdentity` to include remote version, remote hash, remote size, last-known clean local hash, and provider instance id.
- Make remote-delete reconciliation consult per-item `FileIdentity` instead of `.ironmesh-remote-snapshot.json`.
- Make `unregister` clean up runtime cache.

## 12. Resolved Decisions

- Non-empty first-time registrations are rejected for now.
- `SyncRootIdentity` field details can be finalized during implementation as long as it includes enough information to validate both:
  - exact `sync_root_id`,
  - exact `cluster_id + prefix`.
- `FileIdentity` should use a compact text encoding for now; no binary encoding is needed initially.
- Reconnect should require both:
  - exact `sync_root_id` equality,
  - exact `cluster_id + prefix` equality.

This gives us the stricter and safer pre-release interpretation:

- same root identity,
- same remote data scope.

## 13. Recommended Direction

Recommended baseline:

- plain registration only on empty folders,
- startup checks Windows registration state first,
- reconnect only when both the Windows-persisted `sync_root_id` and `cluster_id + prefix` match,
- per-item restart reconciliation state lives in `FileIdentity`,
- `FileIdentity` uses a compact text encoding,
- unregister means explicit disconnect,
- no implicit re-adoption of populated folders,
- no required `.ironmesh-remote-snapshot.json`.

This is the simplest model for users and the safest model for data ownership.
