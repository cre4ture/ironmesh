# Ubuntu PPA Packaging

This repository now contains Debian packaging metadata under `debian/` for a
single source package that builds three installable packages:

- `ironmesh-server-node`
- `ironmesh-client`
- `ironmesh-rendezvous-service`

## First-release install and update strategy

For Ubuntu, the first-release distribution path should be a Launchpad PPA backed
by the source package in this repository.

That means:

- end users install Ironmesh through `apt`, not from ad-hoc tarballs or a
  custom binary updater,
- updates arrive through the normal Ubuntu package-management path (`apt
  upgrade`, Software Updater, or unattended upgrades),
- the repository only needs to publish per-series source uploads and let
  Launchpad build the binary packages.

Example user flow once the production PPA name exists:

```bash
sudo add-apt-repository ppa:<launchpad-user>/<ppa-name>
sudo apt update
sudo apt install ironmesh-client
```

For server deployments, install `ironmesh-server-node` and/or
`ironmesh-rendezvous-service` instead of, or in addition to,
`ironmesh-client`.

Package-specific notes:

- `ironmesh-client` installs the public `ironmesh` CLI and the packaged desktop
  helpers `ironmesh-config-app`, `ironmesh-folder-agent`,
  `ironmesh-os-integration`, and `ironmesh-background-launcher`.
- Package upgrades replace binaries inside the package payload, while XDG user
  state, `/etc/ironmesh/*.env`, and systemd-managed service state stay outside
  the package and should survive upgrades.
- `ironmesh-server-node` and `ironmesh-rendezvous-service` install systemd
  units plus sample `/etc/ironmesh/*.env` files, but the units remain disabled
  until an operator fills in configuration and runs `systemctl enable --now`.
- GNOME Shell integration stays optional. The client package ships the
  extension assets, but a user still installs or enables them through the CLI
  helper.

## Updating installed systems

Once the PPA is configured, updates should come through the normal Ubuntu
package-management flow:

```bash
sudo apt update
sudo apt upgrade
```

If unattended upgrades or the graphical Software Updater are enabled, those
mechanisms can apply new Ironmesh package versions too. The first release
should not ship a separate in-app updater or another binary replacement path on
Ubuntu.

## Why there is a preparation step

Launchpad PPA builders only receive the uploaded Debian source package. They do
not build from your git checkout, and the Rust/web build in this repository has
two packaging-specific needs:

- Rust dependencies must be vendored into the source package.
- The `server-admin` and `client-ui` assets must already be built so the Rust
  crates can embed them without running `pnpm` during the Launchpad build.

The helper script below prepares both:

```bash
./scripts/prepare-ppa-source.sh
```

## Typical upload flow

1. Prepare vendored crates and prebuilt web assets:

   ```bash
   ./scripts/prepare-ppa-source.sh
   ```

2. Create a unique changelog entry for the Ubuntu series you want to target.
   Example for Ubuntu 24.04 LTS (`noble`):

   ```bash
   dch -D noble -v 0.1.0-1~ppa1~ubuntu24.04.1 "PPA build"
   ```

3. Build the signed Debian source package:

   ```bash
   DEBUILD_KEYID=<your-gpg-key-id> ./scripts/build-ppa-source.sh
   ```

   The helper refreshes `../ironmesh_<upstream-version>.orig.tar.gz`
   automatically from the current working tree before it calls
   `debuild --no-lintian -S -sa -nc`.

4. Upload the resulting source changes file:

   ```bash
   dput ppa:<launchpad-user>/<ppa-name> ../ironmesh_0.1.0-1~ppa1~ubuntu24.04.1_source.changes
   ```

## Notes

- The packaging uses versioned Ubuntu Rust toolchains (`rustc-1.91`,
  `rustc-1.89`, or `rustc-1.85`) because the workspace uses Rust edition 2024.
- The build helper skips `lintian` by default to keep the PPA upload loop fast
  with the large vendored source package. Run `lintian
  ../ironmesh_<version>_source.changes` yourself, or pass `--lintian` to the
  helper if you want the extra check inline.
- If you omit `DEBUILD_KEYID` (or `DEBSIGN_KEYID`), the helper still builds the
  source package but leaves the `.dsc` and `.changes` unsigned. You can sign
  them afterwards with `debsign ../ironmesh_<version>_source.changes`.
- `tests/system-tests` is intentionally excluded from the main workspace so
  stable Cargo on Ubuntu builders does not have to parse nightly-only artifact
  dependency declarations.
- The installed systemd units are present but intentionally not enabled or
  started automatically. Fill in `/etc/ironmesh/server-node.env` or
  `/etc/ironmesh/rendezvous-service.env` and then enable the service manually.
