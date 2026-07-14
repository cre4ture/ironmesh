# Ironmesh PR Facts

## Repository Facts

- `main` is the default protected target unless the PR explicitly targets another branch.
- Treat the PR's actual base branch and the latest remote head SHA as the source of truth.
- [../../docs/ci-runbook.md](../../docs/ci-runbook.md) summarizes the current required checks and mitigation guidance.
- `just ci-required` is the closest local reproduction of the protected check set.
- `just ci-stable`, `just coverage`, `just ci-web-smoke`, and `just test-system-nightly` are the usual narrower reproductions.

## GitHub Inspection

- Use `gh pr view <pr>` with JSON fields or equivalent GitHub API calls to inspect the head branch, base branch, merge state, review decision, reviews, and status checks for the latest head commit.
- Use `gh pr checks <pr>` for a quick lane summary on the latest head commit.
- Use the review-thread and review-comment APIs when the summary view is not enough to tell whether feedback is still unresolved.
- Compare the fetched base branch with the PR head before deciding whether the PR branch needs a fresh target-branch merge.

## Stop Rule

- Do not stop while required checks for the latest pushed commit are still queued or running.
- Do not stop while the branch is behind its base or while actionable review feedback exists.
- Stop when the latest head commit is green, the branch is current with its base, and no actionable feedback remains, or when user input, approval, or external state is required.
