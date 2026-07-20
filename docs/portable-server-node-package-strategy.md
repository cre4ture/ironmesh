# Portable Server-Node Variant Package Strategy

Status: Proposed architecture and delivery plan for portable ARM server-node
packages with automatic, safe selection of complete CPU-target binaries.

Related notes:

- [Self-Hosted Apt Repository](self-hosted-apt-repository.md)
- [Ubuntu PPA Packaging](ubuntu-ppa-packaging.md)
- [Server-Node Hardware Health Strategy](server-node-hardware-health-strategy.md)
- [Automatic Natural Earth Import](natural-earth-automatic-import-concept.md)

## Decision summary

Ironmesh should publish one static server-node package per supported Linux ABI.
Each package contains a small, explicit set of complete server binaries, each
built for one declared CPU target. A generic selector executable chooses the
best compatible binary whenever the service starts and executes the generic
variant whenever it cannot prove that an optimized variant is safe.

This deliberately does **not** use a fat binary or in-process CPU dispatch.
Every variant is an ordinary complete `ironmesh-server-node` executable with
its own compile-time target options and dependency features. The package-size
cost is accepted in exchange for a straightforward build model, clear failure
isolation, and standard apt update behavior.

The first artifact families are:

| Debian package architecture | Variant ID | Rust target / CPU options | Required capability |
| --- | --- | --- | --- |
| `armhf` | `armv7-generic` | `armv7-unknown-linux-musleabihf` | ARMv7 hard-float baseline |
| `armhf` | `armv7-cortex-a7` | same target, `target-cpu=cortex-a7` | ARMv7 + NEON + VFPv4; Cortex-A7 is a tuning choice |
| `arm64` | `aarch64-generic` | `aarch64-unknown-linux-musl` | AArch64 baseline |

Further variants are added only when a benchmark proves a material benefit and
the release hardware matrix can verify their safety.

## Goals

- Install and update the server through ordinary signed apt packages.
- Build each explicit `(ABI, CPU target)` artifact once, rather than rebuilding
  the same artifact for every Debian, Ubuntu, or Armbian suite.
- Keep `ironmesh-server-node` as the public package and service name.
- Automatically select the fastest installed safe variant at every process
  start.
- Fall back to the generic variant if detection is missing, masked, unknown,
  or inconsistent.
- Allow a later package version to add an optimized target and have normally
  updated systems use it without a new installer or manual selection.
- Keep variant implementation simple: separate, complete static executables
  rather than multiversioned functions in one executable.

## Non-goals

- A fat binary or a Rust in-process runtime-dispatch framework.
- Replacing apt with a custom package manager or self-updater.
- Calling a package manager from `postinst` or another Debian maintainer
  script.
- Treating `/proc/cpuinfo` model text as proof that an instruction extension is
  available.
- Making the desktop-client packages portable through this work; this strategy
  only covers the headless server node.

## Current starting point

The Debian package currently builds native, dynamically linked binaries. The
repository also contains `scripts/build-server-node-armv7-musl.sh`, which
cross-compiles one fully static `armv7-unknown-linux-musleabihf` server binary
using `cargo zigbuild` and applies `-C target-cpu=cortex-a7` globally.

That helper is the source for the initial Cortex-A7 variant, not for the
portable `armhf` baseline. The generic artifact must be built without the
Cortex-A7 option. A complete optimized variant may intentionally enable
dependency features that assume NEON, such as BLAKE3's 32-bit ARM `neon`
feature, because the selector executes that binary only after positive
capability validation.

The current `ironmesh-server-node` package also hard-depends on `gdal-bin` and
`unzip`, although they are required only for optional Natural Earth conversion.
That package contract must be split before a distribution-neutral core package
is published.

## Target package model

### 1. One package contains all variants for its ABI

The public package remains:

```text
ironmesh-server-node
```

An `armhf` package contains the complete generic and Cortex-A7 executables;
an `arm64` package contains the complete AArch64 variant set. Variants are
private package payload, never separate user-facing package names.

```text
/usr/lib/ironmesh-server-node/
  select-server-node
  variants/
    armv7-generic/ironmesh-server-node
    armv7-cortex-a7/ironmesh-server-node
```

`/usr/bin/ironmesh-server-node` and the systemd `ExecStart` entry invoke the
small generic `select-server-node` executable. The selector performs no server
work itself; it chooses one private binary and replaces itself with `exec`.
All variants therefore receive the same command-line arguments, environment,
dedicated system user, configuration file, state directory, and restart
policy.

The binaries duplicate the embedded web UI and most Rust code. This is an
explicitly accepted package-size tradeoff. It avoids fragile linking, Cargo
feature unification, and unsafe partial specialization of transitive native
dependencies.

### 2. Safe selector contract

The selector reads the Linux auxiliary vector (`AT_HWCAP` and, where relevant,
`AT_HWCAP2`) and evaluates a package-shipped, ordered target manifest. A
manifest entry specifies:

- variant ID and executable path;
- supported Debian ABI;
- every required instruction feature;
- optional board-model/tuning metadata;
- package version and executable checksum for diagnostics.

Feature bits are the safety boundary. Board model data may rank two already
safe variants but must never make an otherwise unsupported binary eligible.

Selection is deterministic:

1. Reject entries for another ABI or with a missing executable.
2. Reject entries whose complete feature requirement is not present in HWCAP.
3. Choose the highest-priority remaining entry.
4. If no optimized entry remains, execute the generic ABI variant.

The selector never needs to mutate package files or remember a choice. It
re-evaluates at every service start, which makes cloned SD cards, changed kernel
capability masks, containers, and package upgrades safe by default.

For diagnosis, administrators can set:

```text
IRONMESH_SERVER_NODE_VARIANT=auto           # default
IRONMESH_SERVER_NODE_VARIANT=armv7-generic  # force baseline
```

An explicit optimized ID is accepted only when it passes the same capability
checks. Otherwise the selector logs the rejection and starts the generic
variant. Startup logging records the selected ID, the detected capability
profile, and the fallback reason when applicable.

### 3. Standard apt updates

The package manager owns all package replacement. There is no bootstrapper,
background package-management agent, or nested apt transaction.

```text
apt update && apt upgrade
  -> installs the next ironmesh-server-node package version
  -> payload may contain an additional target binary and manifest entry
  -> ordinary package upgrade restarts an active service
  -> selector evaluates the new payload and chooses the best safe entry
```

This is the mechanism by which already-installed systems gain a later target
variant automatically. Hosts that use the operating system's normal unattended
upgrade or fleet-management policy receive the same result without an
Ironmesh-specific updater.

### 4. Portable distribution contract

Each server executable is fully statically linked with musl and has no glibc
runtime dependency. The repository can therefore expose a product-owned apt
channel such as:

```text
dists/stable/main/binary-armhf/
dists/stable/main/binary-arm64/
```

`stable` identifies the Ironmesh release channel, not the host operating
system. The supported host contract remains a Debian-family system with `dpkg`,
apt, and systemd. `${shlibs:Depends}` remains in the package metadata so an
accidental future dynamic ELF dependency is detected during packaging.

Natural Earth conversion tools move into an optional, distribution-resolved
companion package:

```text
ironmesh-server-node-map-tools
  Depends: ironmesh-server-node (= ${binary:Version}), gdal-bin, unzip
```

The server's existing dependency-health API continues to state whether map
conversion is available. The core storage node can start without those tools.

## Build model

Every variant build is explicit. The build pipeline receives a variant manifest
as input and produces one complete static artifact per manifest entry.

```text
armhf package
  armv7-generic   = cargo zigbuild --target armv7-unknown-linux-musleabihf
  armv7-cortex-a7 = same target + target-cpu=cortex-a7 + approved NEON features
```

The generic target must not inherit optimization flags from a specialized
variant. The target-specific flags, Cargo feature set, resulting checksum, and
required HWCAP bits are recorded together in release metadata so they cannot
drift independently.

No effort is spent merging whole-program target builds into one executable. A
complete variant is simpler to compile, inspect with `file` and `readelf`,
execute under a real board, and roll back by forcing the generic selector ID.

## Delivery plan

### Phase 0 — Target inventory and baseline measurements

1. Define the initial variant manifest: `armv7-generic`,
   `armv7-cortex-a7`, and `aarch64-generic`.
2. Add repeatable benchmarks for streaming hashing, chunk ingest and
   verification, replication, startup, memory use, and binary size.
3. Run the generic and Cortex-A7 binaries on an Orange Pi One and a generic
   ARMv7 reference.
4. Record the exact expected gain and maximum package-size budget for every
   optimized variant.

Exit criteria:

- Every target has an explicit instruction requirement and a real hardware
  test host.
- The project has a reproducible performance and size baseline.

### Phase 1 — Static target artifact pipeline

1. Generalize the current ARMv7 build helper into a manifest-driven static
   variant build helper.
2. Produce a generic ARMv7 artifact without `target-cpu=cortex-a7`.
3. Produce the current Cortex-A7 artifact as a separately named variant.
4. Add generic `aarch64-unknown-linux-musl` support.
5. Verify every artifact with `file`, `readelf`, checksum generation, and a
   version command.

Exit criteria:

- CI compiles exactly one complete binary for every declared target variant.
- No artifact has an unexpected dynamic ELF dependency.

### Phase 2 — Selector and Debian package layout

1. Add the generic, statically linked selector executable.
2. Add a versioned target manifest to the package payload.
3. Move server variants to private paths and change `/usr/bin` plus systemd to
   invoke the selector.
4. Preserve `/etc/ironmesh/server-node.env`, the system user, state directory,
   and public service name across the migration.
5. Add unit tests for ordered matching, unknown HWCAP data, forced generic
   mode, rejected forced variants, and manifest integrity errors.

Exit criteria:

- The generic variant is always selected safely when no optimized target is
  eligible.
- The Orange Pi One selects the Cortex-A7 variant only when its feature
  requirements are satisfied.

### Phase 3 — Portable package contract and repository publication

1. Split `gdal-bin` and `unzip` into the optional map-tools package.
2. Package all variants for an ABI into one `ironmesh-server-node` `.deb`.
3. Publish prebuilt static packages in the signed `stable` suite while keeping
   current suite-specific entries during migration.
4. Add upgrade tests from the existing package layout to the selector layout.

Exit criteria:

- `apt install ironmesh-server-node` and normal upgrades need no custom
  installer or package-selection command.
- Existing configuration and node data survive the package migration.

### Phase 4 — Release validation and operations

1. Install the prebuilt package in clean Debian, Ubuntu, and Armbian test
   images without recompiling it.
2. Run actual hardware smoke and benchmark tests for each supported target.
3. Verify that a package update adding a new target entry switches an eligible,
   already-installed system on its next normal service restart.
4. Publish the selected target ID and fallback reason in the server's startup
   diagnostics and release notes.

## CI and verification matrix

| Check | Frequency | Purpose |
| --- | --- | --- |
| Static build per declared target | release and relevant code changes | produces one complete binary for each variant ID |
| ELF/checksum/version verification | every artifact | validates static linkage and manifest identity |
| Selector unit tests | every pull request | proves safe deterministic target selection |
| Package install/start/upgrade tests | packaging changes and releases | validates apt, systemd, migration, and configuration preservation |
| Orange Pi One benchmark and smoke test | target changes and release candidates | validates Cortex-A7 eligibility and measured benefit |
| ARM64 hardware smoke test | release candidates | validates the AArch64 artifact family |

The expensive matrix is `(ABI, explicit target)`, not `(distribution suite,
ABI)`. Prebuilt artifacts are reused for all distribution installation tests.

## Security and reliability rules

- The selector uses HWCAP feature requirements as an allow-list; missing data
  always selects the generic binary.
- A target ID is not selected merely because a board model name matches.
- All full target binaries receive the same version, command-line interface,
  systemd environment, and configuration contract.
- No package script downloads software, invokes a package manager, or deletes
  files owned by dpkg.
- Operators can force `armv7-generic` before investigating a suspected
  CPU-specific failure.
- Removing a target in a later package release returns affected hosts to the
  generic variant without changing node state.

## Open decisions

1. Which additional ARMv7 and ARM64 targets, if any, justify their package-size
   and CI cost after the first three variants?
2. What benchmark improvement is sufficient to retain an optimized variant on
   a 512 MiB Orange Pi One?
3. Should `stable` become the sole public apt suite after migration, or should
   suite aliases remain for operator familiarity?
4. What binary-size and compressed-download budgets apply per package ABI?
5. Which real boards form the permanent hardware validation pool?

## Explicitly rejected alternatives

### Fat binary or in-process runtime dispatch

Compiling only selected functions multiple times can save space, but it makes
the CPU capability boundary interact with Rust target features, Cargo feature
unification, LTO, and transitive native dependencies. Complete target binaries
are simpler to inspect, benchmark, and validate. The additional package size is
an accepted cost.

### Separate public flavor packages and an external installer

This adds package-selection and update orchestration outside ordinary apt
updates. Keeping every variant for one ABI inside the normal server-node
package lets a standard update deliver a later optimized variant to existing
systems automatically.

### A bootstrap package that installs another package from `postinst`

By the time `postinst` runs, apt has already resolved the transaction and dpkg
holds package-management state. A nested apt invocation is neither atomic nor
reliable.

### Deleting unused variants after unpacking

dpkg would still record those files as package contents. Upgrades would restore
them and verification would report them missing. The approach saves neither
download size nor flash writes during installation.
