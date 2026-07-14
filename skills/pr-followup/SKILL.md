---
name: pr-followup
description: Follow an open Ironmesh pull request after it is created or updated. Use when Codex has just opened a PR, just pushed a commit to a feature branch with an open PR, or is asked to babysit a PR until it is ready to merge by periodically checking GitHub for target-branch drift, merge conflicts, review findings, and CI failures, merging the latest target branch into the feature branch, fixing actionable problems, and pushing follow-up commits until nothing remains to do or user input is required.
---

# PR Follow-up

Read [references/ironmesh-pr-facts.md](references/ironmesh-pr-facts.md) before the first poll. Use [../../docs/ci-runbook.md](../../docs/ci-runbook.md) when choosing local CI reproduction and validation commands.

## Workflow

1. Resolve the PR number, head branch, and target branch from the current branch or the caller's explicit PR.
2. Start or re-arm a 20-minute timer immediately after opening the PR and immediately after every push to the PR branch.
3. Treat remote GitHub state for the latest pushed head commit as the source of truth. On each poll, inspect:
   - whether the PR is still open and unmerged,
   - whether the head branch is behind its target branch or has merge conflicts,
   - whether new review comments, review threads, or change requests appeared,
   - whether required CI checks are pending, failed, or newly flaky on the latest head commit.
4. If the target branch moved ahead, merge the latest target branch into the PR branch promptly unless the caller explicitly asked for a rebase-only workflow. Resolve conflicts, rerun the relevant local checks, commit the merge, and push.
5. If CI fails, reproduce the smallest relevant lane locally first. Use the repo's current runbook and task runner instead of memorizing stale command lists. Keep the fix narrow, rerun the relevant checks, and push.
6. If review feedback is concrete and actionable, apply the fix directly. If the feedback is ambiguous, conflicting, or changes product direction, stop and ask the user.
7. After every push, assume a fresh monitoring cycle starts. Reset the 20-minute timer from that push time and continue polling the same PR rather than declaring success early.
8. Keep all automated fixes on the existing PR branch. Do not open a replacement PR or force-push away reviewable history unless the caller explicitly asks.
9. Stop only when one of these is true:
   - the PR is merged or closed,
   - the latest head commit is up to date with the target branch, required checks are complete and green, there are no actionable unresolved review findings, and there is nothing else to change,
   - progress requires user input, approval, missing credentials, or an external state change outside the agent's control.
10. When stopping, leave a concise status summary covering branch freshness, CI state, review state, and the exact blocker if any.

## Review And CI Handling

- Prefer GitHub review threads, review decisions, and required checks over local assumptions.
- Ignore stale comments that no longer apply to the current diff, but do not ignore active change requests or unresolved threads.
- If a failure looks Windows-specific or needs native CFAPI behavior, switch to [../windows-ci-access/SKILL.md](../windows-ci-access/SKILL.md).
- If CI is still running for the latest head commit, keep the timer alive; do not stop just because nothing is actionable yet.
