# Ironmesh release facts

Keep this file limited to stable repo-specific facts. Discover common commands from the current repo state when needed.

## Release artifacts

- The workspace release version lives in the root `Cargo.toml` under `[workspace.package].version`.
- `tests/system-tests` is excluded from the main workspace and carries its own `Cargo.lock`.
- `debian/changelog` must gain a new top entry for each release.

## CI expectations

- Use remote GitHub Actions state for the exact commit being released.
- Infer the current required validation lanes from branch protection, workflow files, task runner entries, and recent successful runs instead of preserving a static list here.

## Version update rules

- Bump the workspace version first.
- Refresh `tests/system-tests/Cargo.lock` after the version bump instead of editing it by hand.
- Verify that workspace package entries in that lockfile picked up the new release version.

## Debian changelog rules

- Preserve the current source package name, Ubuntu series, urgency, maintainer format, and Debian revision suffix pattern from the top entry.
- Summarize the release since the previous release tag with a short bullet list.
- Keep the final bullet as a simple workspace release roll line when that remains consistent with recent history.

## Commit and tag rules

- Keep the release commit narrow.
- Inspect recent release commits and tags before choosing the exact commit message.
- Ensure the release tag is an annotated one by providing a tag message.
- Push the tag only after verifying it points at the intended release commit.
