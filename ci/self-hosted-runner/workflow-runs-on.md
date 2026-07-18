# Making jobs interchangeable between GitHub-hosted and self-hosted

## The constraint

`ubuntu-latest`, `windows-latest`, `macos-latest` are **reserved** GitHub-hosted
labels. They **cannot** be assigned to a self-hosted runner, and GitHub does
**not** auto-fail-over between hosted and self-hosted. So "run here if available,
otherwise on GitHub" is not something a single `runs-on:` label can express.

The workable model: keep one `runs-on` expression per job that reads a **repo
variable** as a switch, with a safe fallback to the hosted runner.

## The pattern (Linux jobs)

Replace:

```yaml
    runs-on: ubuntu-latest
```

with:

```yaml
    runs-on: ${{ (github.event.pull_request.head.repo.fork && 'ubuntu-latest') || vars.IRONMESH_LINUX_RUNNER || 'ubuntu-latest' }}
```

Behaviour:

| Situation                              | Runs on                         |
| -------------------------------------- | ------------------------------- |
| `vars.IRONMESH_LINUX_RUNNER` unset     | `ubuntu-latest` (unchanged)     |
| variable = `ironmesh-linux`, push/main | self-hosted (`ironmesh-linux`)  |
| variable set, **fork** pull request    | `ubuntu-latest` (security gate) |

The fork check enforces the agreed policy: **public-fork PRs never touch the
self-hosted host.** Only same-repo pushes/PRs (i.e. trusted) use it.

## The switch

```bash
# Turn self-hosted ON for Linux jobs:
gh variable set IRONMESH_LINUX_RUNNER --repo cre4ture/ironmesh --body ironmesh-linux
# Turn it OFF again (back to 100% GitHub-hosted):
gh variable delete IRONMESH_LINUX_RUNNER --repo cre4ture/ironmesh
```

Because the default is `ubuntu-latest`, you can commit the workflow change with
the variable **unset** and nothing changes until you deliberately flip it.

## Windows / macOS later

Same pattern, separate variables and labels, e.g.:

```yaml
    # windows-cfapi-check:
    runs-on: ${{ (github.event.pull_request.head.repo.fork && 'windows-latest') || vars.IRONMESH_WINDOWS_RUNNER || 'windows-latest' }}
    # ios-build (macOS/arm64):
    runs-on: ${{ (github.event.pull_request.head.repo.fork && 'macos-latest') || vars.IRONMESH_MACOS_RUNNER || 'macos-latest' }}
```

## Capacity note

One ephemeral runner slot processes one job at a time. `check.yml` fans out to
~10 parallel jobs; with a single slot they serialise. Raise `RUNNER_COUNT` in
`config.env` (one container/CPU-set per slot) to add parallelism.
