# IronMesh Windows CFAPI Adapter

This crate contains the Windows Cloud Files (`CFAPI`) adapter used by `os-integration`.

It is responsible for:

- registering and serving an IronMesh sync root on Windows
- materializing remote namespace entries as local placeholders
- hydrating placeholder file ranges on demand
- observing local changes and syncing them back to the server
- preserving metadata-only operations where the platform and backend allow it

## Behavioral Notes

### Placeholder Hydration

- Files are created as cloud placeholders and hydrate on demand when Windows requests file data.
- The adapter does not hydrate placeholders eagerly during normal sync-root registration.

### Manual Hydration Cancel For Testing

- The adapter now exposes a manual cancel path for a currently running hydration.
- This is mainly intended for debugging and test scenarios where a large placeholder hydration was triggered accidentally and you want to stop it without waiting for the full download to finish.
- The running `os-integration serve` process publishes active-hydration markers under `%LocalAppData%\Ironmesh\sync-roots\...` while a file fetch is in flight.
- A cancel request can be issued either:
  - through the packaged Explorer Cloud Files context menu verb `Cancel Hydration`
  - or directly through `os-integration cancel-hydration --root-path <sync-root> --path <relative-or-absolute-path>`
- The cancel request is best-effort and only applies to hydrations that are active at the moment of the request.
- The backend cancellation signal is threaded into the download path, so a large in-flight ranged download can stop mid-transfer instead of waiting for the full object to complete.

What this does not do:

- it does not prevent Explorer from deciding to hydrate in the first place
- it does not replace Explorer's copy behavior with a provider-owned remote copy primitive
- it does not retroactively undo bytes that were already transferred before the cancel request arrived

### Rename And Move Within The Same Sync Root

- Local file rename or move inside the same sync root is optimized as a remote metadata operation when the adapter can match the destination back to the original placeholder or file identity.
- The monitor detects this in [`src/monitor.rs`](./src/monitor.rs) and calls the uploader's `rename_path` hook instead of falling back to upload-plus-delete.
- The live implementation maps that directly to the server-side rename API in [`src/live.rs`](./src/live.rs).
- The server-side rename keeps the remote object identity and only updates namespace metadata in [`../server-node-sdk/src/storage.rs`](../server-node-sdk/src/storage.rs).
- A same-sync-root move is expected to use the same path-to-path rename primitive as a same-directory rename because both end up as `from_path -> to_path` namespace changes.

What is verified today:

- dehydrated in-sync file rename preserves remote object identity
- hydrated in-sync file rename preserves remote object identity
- empty folder rename updates the remote namespace without recreating content
- cross-directory file move inside the same sync root is expected to behave the same way, but is not called out by a separate system test in the current suite

See the Windows system tests:

- [`tests/system-tests/src/cfapi_monitor_test.rs`](../../tests/system-tests/src/cfapi_monitor_test.rs)
  `test_cfapi_dehydrated_in_sync_file_rename_preserves_remote_object_identity`
- [`tests/system-tests/src/cfapi_monitor_test.rs`](../../tests/system-tests/src/cfapi_monitor_test.rs)
  `test_cfapi_hydrated_in_sync_file_rename_preserves_remote_object_identity`
- [`tests/system-tests/src/cfapi_monitor_test.rs`](../../tests/system-tests/src/cfapi_monitor_test.rs)
  `test_cfapi_local_empty_folder_rename_updates_remote_namespace`

### Copy Within The Same Sync Root

Current limitation:

- A normal Explorer file copy of a dehydrated placeholder is not currently delegated to IronMesh as a remote metadata-only copy.
- In practice this means Windows may hydrate the source, perform a local copy, and the adapter may then observe the destination as a new local file that needs upload handling.

Why this limitation exists:

- The CFAPI callback model exposes fetch, delete, and rename/move notifications, but it does not expose a file-copy callback that lets the provider replace Explorer's copy with a remote copy primitive.
- Windows does expose `IStorageProviderCopyHook`, but that hook is for allowing or denying Shell operations on cloud folders, not for handing a file copy off to the provider implementation.

What the backend already supports:

- IronMesh already has a server-side metadata copy operation in the client and server layers.
- The client-side entry point is `copy_path` in [`../client-sdk/src/ironmesh_client.rs`](../client-sdk/src/ironmesh_client.rs).
- The server-side implementation is `copy_object_path` in [`../server-node-sdk/src/storage.rs`](../server-node-sdk/src/storage.rs).

What could still be improved later:

- detect that a newly created local file is really a copy of an existing cloud-backed file
- call the remote `copy_path` operation instead of re-uploading unchanged content
- repair the local destination back into a clean dehydrated placeholder after the copy settles

That would likely avoid the expensive re-upload, but it still would not guarantee that Explorer skips the initial local copy or hydration work.

## Scope Boundary

This README is about sync-root and file-operation behavior of the Windows CFAPI adapter.

Thumbnail behavior for dehydrated placeholders is documented separately in:

- [`../../windows/thumbnail-provider/README.md`](../../windows/thumbnail-provider/README.md)
