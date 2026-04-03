# Nextcloud CFAPI Behavior Reference

Status: Reference note captured from `nextcloud/desktop` `master` on April 3, 2026

## Scope

This note summarizes how Nextcloud Desktop currently uses Windows CFAPI for hydration, pinning, and dehydration so we can compare IronMesh behavior against a production implementation later.

Repository:

- https://github.com/nextcloud/desktop

Primary files reviewed:

- `src/libsync/vfs/cfapi/cfapiwrapper.cpp`
- `src/libsync/vfs/cfapi/cfapiwrapper.h`
- `src/libsync/vfs/cfapi/vfs_cfapi.cpp`

## Key findings

### 1. Nextcloud does not register a dehydrate callback

Their CFAPI callback table includes:

- `CF_CALLBACK_TYPE_FETCH_DATA`
- `CF_CALLBACK_TYPE_CANCEL_FETCH_DATA`
- `CF_CALLBACK_TYPE_NOTIFY_FILE_OPEN_COMPLETION`
- `CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION`
- `CF_CALLBACK_TYPE_VALIDATE_DATA`
- `CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS`
- `CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS`

It does not include `CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE`.

Reference:

- https://github.com/nextcloud/desktop/blob/master/src/libsync/vfs/cfapi/cfapiwrapper.cpp#L641-L649

### 2. Nextcloud registers the sync root with full hydration policy

Their sync-root registration sets:

- `policies.Hydration.Primary = CF_HYDRATION_POLICY_FULL`
- `policies.Hydration.Modifier = CF_HYDRATION_POLICY_MODIFIER_NONE`
- `policies.Population.Primary = CF_POPULATION_POLICY_PARTIAL`

Reference:

- https://github.com/nextcloud/desktop/blob/master/src/libsync/vfs/cfapi/cfapiwrapper.cpp#L876-L883

This is notably different from an implementation that expects Windows to handle background dehydration through platform callbacks.

### 3. They explicitly block self-implicit hydration

Nextcloud connects the sync root with:

- `CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO`
- `CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH`
- `CF_CONNECT_FLAG_BLOCK_SELF_IMPLICIT_HYDRATION`

Reference:

- https://github.com/nextcloud/desktop/blob/master/src/libsync/vfs/cfapi/cfapiwrapper.cpp#L934-L937

### 4. They treat unpinned, hydrated files as a dehydration work item

In local file-state classification, Nextcloud checks Windows file attributes and maps:

- sparse + pinned -> virtual file download
- not sparse + unpinned -> virtual file dehydration

Reference:

- https://github.com/nextcloud/desktop/blob/master/src/libsync/vfs/cfapi/vfs_cfapi.cpp#L277-L304

This means an Explorer `Free up space` action is interpreted as input to their own sync/VFS state machine, not as something they fully delegate to Windows platform dehydration.

### 5. They route dehydration through their own VFS sync path

When a sync item is classified as `ItemTypeVirtualFileDehydration`, `VfsCfApi::updateMetadata(...)` dispatches to `cfapi::dehydratePlaceholder(...)`.

Reference:

- https://github.com/nextcloud/desktop/blob/master/src/libsync/vfs/cfapi/vfs_cfapi.cpp#L185-L191

### 6. They do not use `CfDehydratePlaceholder` in this path

For an existing placeholder, Nextcloud:

- first sets pin state to `OnlineOnly`
- then calls `CfUpdatePlaceholder(..., CF_UPDATE_FLAG_MARK_IN_SYNC | CF_UPDATE_FLAG_DEHYDRATE, ...)`

If the file is not yet a placeholder, they use:

- `CfConvertToPlaceholder(..., CF_CONVERT_FLAG_MARK_IN_SYNC | CF_CONVERT_FLAG_DEHYDRATE, ...)`

References:

- https://github.com/nextcloud/desktop/blob/master/src/libsync/vfs/cfapi/cfapiwrapper.cpp#L1183-L1198

I did not find a `CfDehydratePlaceholder` call in the reviewed CFAPI backend.

### 7. Their file handle path is simple for files

For directories, Nextcloud uses `CfOpenFileWithOplock(...)`.

For files, they open with:

- `CreateFile(..., 0, 0, ..., OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, ...)`

References:

- https://github.com/nextcloud/desktop/blob/master/src/libsync/vfs/cfapi/cfapiwrapper.cpp#L1001-L1014

This is relevant because their dehydration path is built around `CfUpdatePlaceholder` and `CfConvertToPlaceholder`, not `CfDehydratePlaceholder`.

## Practical interpretation

Nextcloud appears to use this model:

1. Let Windows shell actions update pin-related file attributes.
2. Detect `FILE_ATTRIBUTE_UNPINNED` plus hydrated content during local scanning.
3. Treat that as a provider-managed dehydration request.
4. Perform dehydration through `CfUpdatePlaceholder(...CF_UPDATE_FLAG_DEHYDRATE)` or `CfConvertToPlaceholder(...CF_CONVERT_FLAG_DEHYDRATE)`.

That is different from relying on:

- `CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE`
- provider-side calls to `CfDehydratePlaceholder(...)`
- Windows automatically dehydrating the file after an unpin action

## Supporting context

There is also a Nextcloud PR discussing a `free up space` flow as something that triggers their sync engine:

- https://github.com/nextcloud/desktop/pull/6936

That matches the source-code behavior above.

## Why this matters for IronMesh

If IronMesh continues to see:

- Explorer sets `FILE_ATTRIBUTE_UNPINNED`
- the file remains hydrated
- provider-side `CfDehydratePlaceholder(...)` fails with `ERROR_CLOUD_FILE_DEHYDRATION_DISALLOWED`

then Nextcloud suggests a different implementation direction:

- treat unpin as a sync-state transition,
- keep the provider in charge of the dehydration transition,
- and perform dehydration through `CfUpdatePlaceholder(...CF_UPDATE_FLAG_DEHYDRATE)` rather than waiting for Windows to complete the job through `CfDehydratePlaceholder(...)`.
