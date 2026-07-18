# ironmesh self-hosted runners

Drop-in self-hosted GitHub Actions runners that stay **interchangeable** with
GitHub-hosted runners: the same jobs run unchanged, and a single repo variable
switches a job family between hosted and self-hosted.

## Design

- **Ephemeral, one clean container per job.** A host supervisor loop mints a
  short-lived registration token via the local `gh` auth, launches a disposable
  container (`--rm`, `--ephemeral`), which registers, runs exactly one job, and
  exits. The next job gets a brand-new container. No state leaks between jobs.
- **The powerful credential never enters the container.** Only the ~1h
  single-use registration token does. `gh` (your login) stays on the host.
- **No Docker socket mounted.** Jobs run isolated inside the container, not on
  the host. (Add DinD later only if a job genuinely needs to build images.)
- **Caching still works.** `Swatinem/rust-cache`, `setup-node`, `setup-java`
  etc. use GitHub's server-side cache, which functions on self-hosted runners —
  so ephemeral containers stay fast across runs.

## Security posture (this is a PUBLIC repo)

Self-hosted runners on public repos are risky: PR code can run on your machine.
Mitigations wired in here:

1. **Fork PRs never use the self-hosted host** — the `runs-on` expression forces
   them back to `ubuntu-latest` (see [workflow-runs-on.md](workflow-runs-on.md)).
2. **Ephemeral + container isolation + no host Docker socket.**
3. Keep GitHub's *"Require approval for all outside collaborators"* enabled under
   repo → Settings → Actions → General.

## Linux setup (this host: Ubuntu 24.04 / x86_64)

### 1. Bootstrap (one-time, needs root)

```bash
# Let your user drive Docker without sudo, then RE-LOGIN (or reboot) so the
# group membership reaches your systemd user manager:
sudo groupadd -f docker
sudo usermod -aG docker "$USER"
```

Linger is already enabled on this host, so user services survive logout.

### 2. Configure

```bash
cd ci/self-hosted-runner
cp config.env.example config.env      # edit REPO / labels / RUNNER_COUNT if needed
```

### 3. Build the image

```bash
linux/build.sh
```

### 4. Run it

- **Foreground smoke test (one slot):** `linux/supervisor.sh 0`
- **As a managed service:** `linux/install-service.sh`

Verify it registered:

```bash
gh api repos/cre4ture/ironmesh/actions/runners -q '.runners[] | {name,status,labels:[.labels[].name]}'
```

### 5. Turn it on for CI

Apply the `runs-on` pattern to the Linux jobs (see
[workflow-runs-on.md](workflow-runs-on.md)), commit, then flip the switch:

```bash
gh variable set IRONMESH_LINUX_RUNNER --body ironmesh-linux
```

### Uninstall

```bash
linux/uninstall-service.sh
```

## Windows / macOS (arm64) — later

The architecture is identical; only the container/agent host differs:

- **Windows:** the runner agent must run on a Windows host (Windows containers or
  a native ephemeral agent). Reuse `supervisor` logic in PowerShell; label
  `ironmesh-windows`; variable `IRONMESH_WINDOWS_RUNNER`.
- **macOS/arm64:** Apple's licensing means macOS builds must run on Apple
  hardware; containers can't provide macOS. Use a native ephemeral agent
  (`config.sh --ephemeral`) wrapped by a launchd/loop supervisor; label
  `ironmesh-macos`; variable `IRONMESH_MACOS_RUNNER`.

Both follow the same token-minting + ephemeral-recycle loop and the same
`runs-on` switch pattern.

## Tuning (pre-installed tools) — later

Currently the image ships base OS packages only; toolchains install per-job via
the workflows' setup actions (kept for exact parity with `ubuntu-latest`). To
cut per-job install time, extend `linux/Dockerfile` to pre-bake the pinned
toolchains this repo uses (Rust stable + nightly, Node 20, pnpm 10.6.0, common
`cargo-*` tools, Playwright browser deps, `libfuse3-dev`). Rebuild with
`linux/build.sh`. Do this as a second step once the base runner is proven.
