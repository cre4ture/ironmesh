---
name: release-commit
description: Cut a new Ironmesh release commit and tag. Use when Codex needs to prepare a release in this repository by making GitHub Actions green, bumping the workspace version, refreshing the system-tests lockfile, updating the Debian changelog, and committing, tagging, and pushing the release.
---

# Release Commit

Keep the skill high-level. Prefer stable repository facts and current repo inspection over hardcoded command lists.

Keep the final release commit narrow. Land product fixes and CI fixes as ordinary commits first, then use the release commit only for versioning and release metadata unless the caller explicitly asks for a mixed commit.

Read [references/ironmesh-release-facts.md](references/ironmesh-release-facts.md) for the few repo-specific facts that are worth keeping explicit.

## Workflow

1. Make sure the current branch is up to date with the remote.
2. Check clippy and rust fmt locally before pushing any commits.
3. Inspect the current branch and current commit on GitHub Actions.
4. Fix failing CI first and push those fixes before cutting the release commit.
5. Continue only after the release base commit is green remotely.
6. Choose the target version.
7. Update the release files.
8. Commit, tag, and push using the repo's current release convention.
9. Verify the pushed release commit on GitHub Actions.

## Make CI Green

- Treat remote CI state as the source of truth.
- Use the repo's current workflows, task runner, branch protection, and recent runs to discover the right validation path instead of relying on a frozen list of commands.
- Reproduce failures locally when useful, but do not stop at local success; wait for green GitHub runs on the commit that will become the release base.
- Keep CI repair commits separate from the final release commit.

## Choose the Version

- Use the caller's exact target version when provided.
- Default to a patch bump only when the current workspace version is a stable `x.y.z` and the caller asked for the next release without giving a version.
- Stop and ask for the exact target version when the current version is a prerelease or the release channel is ambiguous.
- Derive the current tag and commit naming convention from recent release history instead of assuming it never changes.

## Update the Release Files

- Bump `[workspace.package].version` in the root `Cargo.toml`.
- Refresh `tests/system-tests/Cargo.lock` after the version bump using the appropriate Cargo workflow for that crate; do not hand-edit the lockfile.
- Update `debian/changelog` by preserving the current package metadata style and Debian revision pattern from the existing top entry.
- Summarize the release since the previous release tag concisely.
- Use existing repo helpers when they fit, but do not duplicate their exact command lines in the skill.

## Commit, Tag, and Push

- Stage only the release files unless the caller explicitly wants more.
- Reuse the current repo convention for the release commit message and tag shape by inspecting recent release commits and tags.
- Push both the release commit and the release tag.
- Confirm that the tag points at the intended commit.
- Inspect the pushed release commit on GitHub Actions before declaring the release cut complete.
