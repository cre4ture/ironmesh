# iOS multi-profile folder sync decision

Status: Accepted

Date: 2026-07-19

## Context

Android already models multiple folder-sync configurations below one enrolled device connection.
iOS needs the same functional level without copying Android's WorkManager lifecycle or UI. The
native integration point on iOS is a replicated File Provider extension: Files owns scheduling,
materialization, offline queues, and user-visible domains.

## Decision

Each iOS sync profile registers one `NSFileProviderDomain`. A profile persists a stable identifier,
display name, normalized remote prefix, discovery depth, active/paused lifecycle, network policy,
power policy, and an explicit `shared_device` connection reference. Profiles deliberately share the
app-group connection settings and Keychain-backed enrolled device identity. A second cluster or
identity is a separate future connection-model feature, not an implicit property of a profile.

The extension resolves the profile from its actual domain identifier. All list, metadata, fetch,
create, modify, move, and delete paths pass through a prefix mapper, so one domain cannot escape its
remote scope. Profile configuration and domain registration are idempotent. Reconciliation repairs
profiles independently so one damaged registration does not block the remaining profiles.

On iOS, pause is a persisted operation gate checked before every remote operation. iOS does not
offer the `NSFileProviderManager` disconnect/reconnect API available on macOS. Keeping the domain
registered preserves OS-managed queued operations and materialized files. Resume persists the
active gate before signalling the working-set enumerator. macOS continues to use a non-temporary
domain disconnect/reconnect and rolls back the persisted lifecycle if that OS operation fails.

Network and power restrictions are evaluated from `NWPathMonitor` and Low Power Mode before a
connection is opened. Profiles may allow or defer expensive paths, constrained Low Data Mode paths,
and Low Power Mode. A blocked operation returns a retryable File Provider `serverUnreachable` error;
when an environment transition makes that profile runnable again, the live extension signals its
working-set enumerator so Files can retry queued work. This is an event-driven retry hint, not a
guarantee of immediate execution.

iOS exposes lazy materialization and eviction-on-remote-update, but no provider-level
profile-wide “download eagerly and keep downloaded” policy. The provider therefore advertises
on-demand content. Users and the OS manage offline pinning through Files' **Keep Downloaded** action.
The UI does not promise that the provider can retain an entire profile.

## Discovery and restart recovery

Working-set change enumeration performs a profile-scoped full remote snapshot at the configured
depth. A durable, per-domain generation journal compares that snapshot with the last successful
snapshot and records updated and deleted durable identifiers. File Provider sync anchors encode the
journal generation. Retained generations permit replay after an extension restart or offline gap;
an anchor older than the retained journal returns `syncAnchorExpired`, causing Files to re-enumerate.

There is no fixed foreground polling loop and no Android WorkManager port. Discovery occurs when
Files enumerates, after an explicit app/recovery/conflict-copy working-set signal, or during normal
File Provider retries.
There is currently no APNs/push channel, so this design does not claim immediate unsolicited
background discovery of a remote-only change.

## Concurrent mutations and conflicts

File Provider's base content version is forwarded through Swift and the Rust FFI as a distinct
`expected_revision`. For file PUT, file/marker DELETE, and file rename, the server compares that
revision with the preferred head while holding the same storage lock used for the mutation. A stale
revision returns HTTP 409 and leaves the current bytes/path untouched. The normal version graph
still inherits the verified preferred head; `parent` is not used as a substitute for compare-and-swap.

The extension performs an early metadata check for useful UI feedback, then relies on the server
check to close the race window. When a content PUT loses the race, it refreshes metadata, writes the
user's bytes to a deterministic sibling named
`<name> (IronMesh conflict <stable fingerprint>).<extension>`, and reports File Provider
`cannotSynchronize` with the expected/current revisions and conflict path. Delete and rename races
are intentionally different: rename remains `cannotSynchronize`, while delete uses File Provider's
`fileProviderErrorForRejectedDeletion` with the current item so Files restores the retained remote
version.

Directory deletion is recursive in the current Rust client. A directory-marker revision cannot
protect its children because normal child mutations do not atomically bump that marker. The
extension therefore rejects directory deletion rather than issuing a subtree delete that could
erase a child created after enumeration. Adding a versioned namespace/snapshot CAS token is a
server protocol change tracked in
[#148](https://github.com/cre4ture/ironmesh/issues/148). Until then, directory items deliberately
omit File Provider's delete capability so Files does not present an operation the provider must
reject.

## Consequences and boundaries

- Multiple profiles can be configured, paused, resumed, removed, and recovered independently.
- Remote/local changes and deletions survive app/extension restarts through Files plus the durable
  generation journal.
- Offline operation ordering and materialized-data lifetime remain OS responsibilities; IronMesh
  does not maintain a second foreground queue.
- Profile scopes may overlap. They are separate Files domains and can surface the same remote object;
  the UI should make this explicit rather than silently rejecting a valid configuration.
- Profile mutations are serialized in the app so an in-flight add cannot be overtaken by remove,
  pause, or resume.
- Exact Android screens, WorkManager jobs, and multi-cluster credentials are intentionally not
  ported.

## Verification

AppleCore unit tests exercise profile persistence/state transitions, scope mapping, recovery-signal
policy, journal replay/expiry/deletions, deterministic conflict names, and mutation serialization.
Server handler integration tests cover successful and stale compare-and-swap for PUT, DELETE,
rename, and recursive marker deletion. Swift bridge tests cover expected-revision forwarding and
File Provider error disposition; Xcode simulator builds validate that the app and extension compile
and link. These tests do not claim end-to-end execution by the real Files daemon on a physical device.
