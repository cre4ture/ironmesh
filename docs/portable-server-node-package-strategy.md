# Portable Server-Node Package And Runtime Dispatch Strategy

Status: Proposed architecture and delivery plan for portable ARM server-node
packages with automatic, safe CPU specialization.

Related notes:

- [Self-Hosted Apt Repository](self-hosted-apt-repository.md)
- [Ubuntu PPA Packaging](ubuntu-ppa-packaging.md)
- [Server-Node Hardware Health Strategy](server-node-hardware-health-strategy.md)
- [Automatic Natural Earth Import](natural-earth-automatic-import-concept.md)

## Decision summary

Ironmesh should publish one portable static `ironmesh-server-node` package per
supported Linux ABI, not rebuild an otherwise identical server package for each
Debian, Ubuntu, or Armbian release.

The server process must remain safe on the ABI baseline of each target. CPU
specialization is an application runtime concern: one installed server binary
selects a feature-specific code path only after a positive kernel capability
check, and otherwise uses the portable path. Package upgrades continue to use
normal apt semantics. A regular `apt upgrade` replaces the package; the next
service start automatically uses any newly shipped compatible specialization.

The first supported portable targets are:

| Debian package architecture | Rust target | CPU baseline | Initial hardware |
| --- | --- | --- | --- |
| `armhf` | `armv7-unknown-linux-musleabihf` | generic ARMv7 hard-float | Orange Pi One and similar boards |
| `arm64` | `aarch64-unknown-linux-musl` | generic AArch64 | 64-bit ARM Linux nodes |

`armhf` is an ABI, not a Cortex-A7 identifier. An `armhf` package must not
globally assume NEON, VFPv4, or a specific microarchitecture.

## Goals

- Install and update the server through ordinary signed apt packages.
- Build a release artifact once per supported ABI rather than once per Linux
  distribution suite.
- Keep the installed `ironmesh-server-node` package name, its systemd unit,
  `/etc/ironmesh/server-node.env`, and its state directory upgrade-compatible.
- Use the fastest safe implementation automatically on supported CPUs.
- Fall back to portable code whenever hardware detection is missing, masked, or
  inconclusive.
- Keep update selection automatic: no per-device bootstrap rerun and no
  `postinst`-initiated nested apt transaction.
- Measure a specialization before carrying its code size and maintenance cost.

## Non-goals

- Replacing apt with a custom package manager.
- Calling `apt`, `apt-get`, `dnf`, or another package manager from a Debian
  maintainer script.
- Treating `/proc/cpuinfo` model text as proof that an instruction extension is
  available.
- Shipping a complete copy of the server executable for every prospective CPU
  model when only a small hashing or cryptography hotspot needs specialization.
- Making the desktop client packages portable through this work; this strategy
  is limited to the headless server node.

## Current starting point

The current Debian package builds native, dynamically linked binaries. The
repository already has a dedicated ARMv7 static build helper:

- `scripts/build-server-node-armv7-musl.sh` builds
  `armv7-unknown-linux-musleabihf` through `cargo zigbuild`.
- It presently applies `-C target-cpu=cortex-a7` to the whole executable.
- `debian/control` makes `gdal-bin` and `unzip` hard dependencies of the
  server-node package.

The global Cortex-A7 setting is useful for a single-board deployment but cannot
be the portable `armhf` default: it permits code generation for instructions
that generic ARMv7 systems need not expose.

The server uses CPU-sensitive dependencies including BLAKE3, `ring`, AES, and
zstd. `ring` already contains ARM runtime capability dispatch. BLAKE3 needs
separate treatment on 32-bit ARM: its `neon` Cargo feature enables a NEON
implementation but assumes it is usable. It is not, by itself, a safe runtime
dispatch mechanism for a generic `armhf` artifact.

## Target architecture

### 1. One normal package per ABI

The public package remains:

```text
ironmesh-server-node
```

It contains one statically linked server executable for its Debian
architecture, the existing systemd integration, and the embedded server-admin
web UI. The repository may publish it in a product-owned `stable` suite, for
example:

```text
dists/stable/main/binary-armhf/
dists/stable/main/binary-arm64/
```

The apt suite selects Ironmesh's release channel; it does not claim that the
host itself is a particular Debian or Ubuntu suite. Supported hosts remain
Debian-family systems with `dpkg`, apt, and systemd.

The binary has no glibc runtime dependency. The package must continue to retain
`${shlibs:Depends}` during packaging so a future accidental dynamic dependency
is detected rather than silently published.

### 2. Runtime CPU dispatch inside the server

The installed executable is a real fat binary: it contains a portable path and
only the additional optimized routines that have justified their presence in
benchmarking. It does not contain complete independent copies of the server.

At process startup, a small internal capability module determines the available
feature set from the Linux auxiliary vector (`AT_HWCAP` and, where applicable,
`AT_HWCAP2`). It exposes a conservative profile such as:

```text
portable
armv7-neon-vfpv4
aarch64-baseline
aarch64-aes-pmull
```

The profile names describe required instruction features, not board marketing
names. A board-model hint may improve tuning after a feature profile has been
accepted, but it must never enable an instruction path on its own.

Each optimized function is compiled with its exact required target features and
called only through a dispatcher that has verified those features. A missing
auxiliary-vector entry, unknown operating system, unsupported architecture, or
failed probe selects `portable`.

The process records its selected profile and reason in the startup log. An
operator override is provided for diagnosis:

```text
IRONMESH_CPU_PROFILE=auto     # default
IRONMESH_CPU_PROFILE=portable # force the baseline implementation
```

An unavailable or incompatible forced optimized profile is rejected and falls
back to `portable`; it must never produce an illegal-instruction crash.

### 3. Standard upgrade behavior

No installer, background package-management agent, or Debian maintainer script
chooses packages after installation. The package manager owns replacement of
the package payload.

```text
apt update && apt upgrade
  -> installs a newer ironmesh-server-node package
  -> ordinary systemd package upgrade restart, if the service is active
  -> new process probes HWCAP again
  -> selects the best code path included in the new binary
```

Consequently, a later release can add a verified optimization and all systems
that receive normal apt updates can use it automatically. If automatic OS
updates are desired, the host's normal unattended-upgrades or fleet-management
policy controls them; Ironmesh does not implement a second updater.

### 4. Optional host tools

Natural Earth conversion needs `unzip` and GDAL executables at runtime, but it
is not required to start or operate the storage node. The portable core package
must not make its ABI promise depend on those distribution packages.

Before publishing `stable`, split those tools into an explicit optional
companion package, for example:

```text
ironmesh-server-node-map-tools
  Depends: ironmesh-server-node (= ${binary:Version}), gdal-bin, unzip
```

The server's existing dependency-health API remains the runtime authority: it
reports whether the optional map-import capability is usable. This keeps the
portable core small while allowing a Debian/Ubuntu-specific companion package
to use normal dependency resolution.

## Why dispatch is not a whole-program `target-cpu` build

`-C target-cpu=cortex-a7` applies to the complete dependency graph. Cargo does
not provide a switch that compiles the complete graph twice for two global CPU
targets and safely merges the results into one binary. Doing so would duplicate
large portions of the server, complicate static C dependencies, and defeat the
space-saving goal.

The practical unit of specialization is a measured hot function or small
subsystem. Initial candidates are streaming BLAKE3 hashing during ingest,
verification, and replication. Each candidate must demonstrate a material
end-to-end benefit on the Orange Pi One before it adds specialized code.

The implementation must not rely on the currently nightly-only 32-bit ARM
`is_arm_feature_detected!` API. The capability module should read the Linux
auxiliary vector directly through a small, tested platform abstraction. This
works for the static musl target and follows the model already used internally
by `ring`.

## Delivery plan

### Phase 0 — Baseline and measurement

1. Add repeatable ARMv7 benchmark scenarios for:
   - streaming content hashing;
   - chunk ingest and verification;
   - replication of a representative object set;
   - an idle server startup and request smoke test.
2. Run them on an Orange Pi One and one generic ARMv7 reference.
3. Record throughput, CPU utilization, memory use, startup time, and binary
   size for a generic static build and the current Cortex-A7-specialized build.
4. Do not add a specialization unless it produces a documented material benefit
   without an unacceptable size, correctness, or maintenance cost.

Exit criteria:

- The release team has a reproducible baseline.
- The first candidate hotspot and the expected gain are explicit.

### Phase 1 — Portable static artifact pipeline

1. Generalize the existing ARMv7 build helper into a target-driven static
   server-node build helper.
2. Build generic `armv7-unknown-linux-musleabihf` without a global Cortex-A7
   target CPU setting.
3. Add generic `aarch64-unknown-linux-musl` support.
4. Verify every artifact with `file` and `readelf` so no unexpected dynamic ELF
   dependencies are published.
5. Package the prebuilt static artifact without rebuilding it under the host
   distribution's toolchain.

Exit criteria:

- CI produces exactly one server binary for each supported ABI.
- A clean Debian/Ubuntu/Armbian install test can install and start the matching
  package without a host glibc requirement.

### Phase 2 — Package-contract split

1. Preserve the public `ironmesh-server-node` package name and all existing
   configuration/state paths.
2. Split map conversion tooling into the optional companion package described
   above.
3. Publish the portable artifacts to a `stable` apt suite while retaining the
   current suite-specific repository entries during migration.
4. Document the supported systemd/apt host contract and the package rollback
   path.

Exit criteria:

- `apt install ironmesh-server-node` and normal upgrades require no custom
  installer.
- Optional map conversion is discoverable and installable without making the
  server core distribution-bound.

### Phase 3 — Capability module and safe dispatch contract

1. Add a small `cpu-capabilities` module or crate with platform-gated tests.
2. Decode only the feature bits that a shipped optimized function requires.
3. Make `portable` the default for every unknown condition.
4. Add structured startup logging and the `IRONMESH_CPU_PROFILE` override.
5. Add tests for automatic selection, forced portable mode, invalid forced
   profiles, and unknown/masked capability data.

Exit criteria:

- The generic `armhf` binary runs on a no-NEON test target.
- The same artifact selects the optimized path on the Orange Pi One when an
  optimization is present.
- No selection case executes an instruction absent from the detected profile.

### Phase 4 — First measured specialization

1. Prototype the measured hot path behind a trait/function-pointer boundary.
2. Keep a portable implementation and add only the required feature-gated
   implementation.
3. Resolve BLAKE3's ARMv7 NEON behavior deliberately: contribute an upstream
   runtime-dispatch capability, maintain a minimal audited patch, or reject it
   if its measured benefit does not justify either option.
4. Benchmark both paths, add regression tests, and enforce a binary-size budget.

Exit criteria:

- The specialized path has an agreed end-to-end performance benefit.
- The packaged binary remains within the release size budget.
- A forced-portable run remains functionally identical.

### Phase 5 — Release and operations

1. Add prebuilt-artifact package installation tests to the release pipeline.
2. Keep compilation matrix size at one build per ABI; run the broader host
   installation matrix as a separate, lightweight test stage.
3. Test real ARM hardware on each release candidate because QEMU can mask or
   expose different CPU capabilities.
4. Publish a release note whenever a new CPU profile becomes available; no
   customer action beyond normal package updates is required.

## CI and verification matrix

| Check | Frequency | Purpose |
| --- | --- | --- |
| Generic static build per ABI | release and relevant code changes | produces the only compiled server artifact per ABI |
| ELF static-link verification | every artifact | prevents accidental glibc/runtime-library coupling |
| Unit and dispatch tests | every pull request | verifies selection and portable fallback semantics |
| Package install/start smoke tests | release and packaging changes | verifies apt, systemd, config preservation, and service startup |
| Orange Pi One hardware benchmark | release candidate / optimization changes | validates real ARMv7 feature detection and benefit |
| 64-bit ARM hardware smoke test | release candidate | validates the `arm64` artifact |

The compatibility matrix multiplies test execution, not expensive compilation.
Compiled artifacts are reused across those tests.

## Security and reliability rules

- Feature detection is allow-list based: the optimized path requires every bit
  it needs; absence of a bit always means portable execution.
- No package script downloads software, invokes a package manager, or modifies
  apt source configuration after installation.
- The server does not use CPU model strings as an instruction-safety boundary.
- Package upgrades retain existing configuration and data ownership.
- Operators can force portable execution before reporting or investigating a
  suspected CPU-specific failure.
- A specialization may be removed in a later package version without changing
  on-disk state; the process simply returns to the portable path.

## Open decisions

1. What benchmark improvement is sufficient to justify a specialized code
   path on a 512 MiB Orange Pi One?
2. Should `stable` become the sole public apt suite after migration, or should
   distribution-specific suite aliases remain permanently for operator
   familiarity?
3. Can BLAKE3 upstream provide safe ARMv7 NEON runtime dispatch, or is a small
   local compatibility layer preferable?
4. What binary-size budget applies to the static server before an optimization
   must be rejected?
5. Which real ARMv7 and ARM64 boards form the release hardware test pool?

## Explicitly rejected alternatives

### Full executable flavor packages with an external launcher

This is easy to implement but stores a nearly complete copy of the server for
each flavor and complicates package replacement. It remains a fallback only if
an essential optimization cannot be isolated into a safe runtime-dispatched
subsystem.

### A bootstrap package that installs another package from `postinst`

By the time `postinst` runs, apt has already resolved the transaction and dpkg
holds the package-management state. A nested apt invocation is not an atomic
or reliable update mechanism. It also fails the normal unattended/offline
package-management expectation.

### Removing unused variant files after package unpacking

dpkg would still record those deleted files as package contents. Upgrades would
restore them and verification would report them missing. It saves neither
download size nor flash writes during installation.
