# Pace Strategy for Meaningful Submissions

This file defines how changes should be delivered in this repository.

## Working rules for Copilot

1. **Plan first for multi-step work**
   - Create a short task plan before coding.
   - Keep exactly one active step at a time.

2. **Submit in meaningful slices**
   - Each slice must be one coherent outcome (example: "add server endpoint", "wire CLI command", "add integration docs").
   - Avoid mixing unrelated refactors and features in the same slice.

3. **Small, reviewable diffs**
   - Prefer focused edits over large rewrites.
   - Keep naming and style consistent with existing code.

4. **Validate each slice**
   - Run the narrowest relevant check first (crate-level or file-level).
   - Then run broader checks when appropriate (`cargo check --workspace`, tests if present).

5. **Report deltas, not repetition**
   - After each slice, summarize:
     - What changed
     - What was validated
     - What comes next

6. **Do not auto-commit unless asked**
   - Prepare clean change sets and wait for explicit commit instruction.

## Suggested commit granularity

Use this pattern for future commits:

- `chore(workspace): scaffold crate/module structure`
- `feat(server): add storage node endpoint(s)`
- `feat(client-sdk): implement cache + transport`
- `feat(cli): add command flow and web entrypoint`
- `feat(mobile): add android/ios storage wrappers`
- `docs: update runbook and architecture notes`

## Pull request checklist

- [ ] Scope is single-purpose and coherent
- [ ] Build/tests pass for touched areas
- [ ] No unrelated formatting or refactor noise
- [ ] Docs updated for behavior/interface changes
- [ ] Next step is explicitly stated
