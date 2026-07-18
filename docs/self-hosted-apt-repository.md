# Self-Hosted Apt Repository

Ironmesh can be published from any static HTTPS web root as a small signed apt
repository. The web server only hosts files; apt verifies the signed `Release`
metadata and the package checksums inside that metadata.

The default Ironmesh target is:

```bash
https://creax.de/apt/ironmesh
```

## Build packages

Create the binary Debian packages on a native builder for each supported
Ubuntu release and architecture. The existing AMD64 packages are built on an
Ubuntu 24.04 (`noble`) AMD64 builder. ARM64 packages for an Ubuntu 20.04
(`focal`) host must be built on an ARM64 Focal builder so their libc
requirements remain compatible with Focal.

On the matching native builder, create the binary Debian packages from the
current checkout:

```bash
./scripts/build-local-debs.sh -- -jauto
```

The packages are written to the parent directory of the checkout.

Ubuntu 20.04 does not provide the package-build Rust versions in its standard
apt repositories. If the Focal ARM64 builder has the required Rust toolchain
on `PATH` (for example through `rustup`), install the remaining native build
tools and use the explicit opt-out below. `-d` is passed only for this local
binary build; it does not change the binary package dependencies.

```bash
sudo apt update
sudo apt install build-essential pkg-config libfuse3-dev dh-sysuser clang
sudo apt install -t focal-backports debhelper
./scripts/build-local-debs.sh --no-check-build-deps -- -j1
```

## Build repository metadata

Generate `pool/`, `dists/`, `Packages.gz`, `Release`, `InRelease`, and the
public archive key. Import the published repository before adding a new target;
this retains the existing suites and architectures in the deployment staging
directory.

```bash
export GPG_TTY="$(tty)"
APT_REPO_SIGN_KEY=5D7762BDB9A2A564D500DE702A2E3C589C188616 \
  ./scripts/build-apt-repository.sh \
    --import-remote creature@creax.de:/home/creature/html/apt/ironmesh
```

The repository is created under `target/apt-repo` by default. If GPG needs the
key passphrase, run the command from a normal terminal so `gpg-agent` can ask
for it.

## Publish to creax.de

Upload the generated repository to the dedicated web directory:

```bash
./scripts/deploy-apt-repository.sh
```

The default deploy target is:

```bash
creature@creax.de:/home/creature/html/apt/ironmesh
```

The deploy script replaces metadata only for the suite being published and
adds package files to the shared pool. It deliberately preserves other suites
and package files, so adding Focal/ARM64 cannot remove the existing
Noble/AMD64 publication.

## Add the Focal ARM64 target

Build the packages on the Ubuntu 20.04 ARM64 builder, then copy the three
`.deb` files to the machine that holds the signing key. Import the published
repository and add the Focal ARM64 index in one command:

```bash
export GPG_TTY="$(tty)"
APT_REPO_SIGN_KEY=5D7762BDB9A2A564D500DE702A2E3C589C188616 \
  ./scripts/build-apt-repository.sh \
    --suite focal \
    --arch arm64 \
    --import-remote creature@creax.de:/home/creature/html/apt/ironmesh \
    ../ironmesh-client_*_arm64.deb \
    ../ironmesh-server-node_*_arm64.deb \
    ../ironmesh-rendezvous-service_*_arm64.deb

./scripts/deploy-apt-repository.sh --suite focal
```

The build helper derives each package architecture from the `.deb` metadata and
regenerates the `Release` architecture list from the package indexes. Repeating
`--arch` permits a staging repository to refresh more than one architecture in
one invocation.

## Verify the published repository

After publishing, check that the signed metadata and package index are visible:

```bash
curl -fsSL https://creax.de/apt/ironmesh/dists/noble/InRelease | gpg --verify
curl -fsSL https://creax.de/apt/ironmesh/dists/noble/main/binary-amd64/Packages.gz \
  | gzip -dc \
  | grep '^Package: '
curl -fsSL https://creax.de/apt/ironmesh/dists/focal/InRelease | gpg --verify
curl -fsSL https://creax.de/apt/ironmesh/dists/focal/main/binary-arm64/Packages.gz \
  | gzip -dc \
  | grep '^Package: '
```

## Client setup

Install the repository key into apt's keyring directory:

```bash
curl -fsSL https://creax.de/apt/ironmesh/ironmesh-archive-keyring.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/ironmesh-archive-keyring.gpg
```

Add exactly one apt source, matching the Ubuntu release and architecture of the
host:

```bash
# Ubuntu 20.04 ARM64
echo 'deb [arch=arm64 signed-by=/usr/share/keyrings/ironmesh-archive-keyring.gpg] https://creax.de/apt/ironmesh focal main' \
  | sudo tee /etc/apt/sources.list.d/ironmesh.list
```

```bash
# Ubuntu 24.04 AMD64
echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/ironmesh-archive-keyring.gpg] https://creax.de/apt/ironmesh noble main' \
  | sudo tee /etc/apt/sources.list.d/ironmesh.list
```

Install or update packages through apt:

```bash
sudo apt update
sudo apt install ironmesh-client
```

Server packages can be installed with `ironmesh-server-node` and
`ironmesh-rendezvous-service`.

## Publishing updates

For a new release, bump `[workspace.package].version` in `Cargo.toml`, build the
local `.deb` packages, rebuild the repository metadata, and deploy again. The
packaging helpers update the upstream portion of `debian/changelog`
automatically while preserving the existing Debian revision suffix:

```bash
./scripts/build-local-debs.sh -- -jauto
export GPG_TTY="$(tty)"
APT_REPO_SIGN_KEY=5D7762BDB9A2A564D500DE702A2E3C589C188616 \
  ./scripts/build-apt-repository.sh
./scripts/deploy-apt-repository.sh
```

Clients receive the update with the normal Ubuntu flow:

```bash
sudo apt update
sudo apt upgrade
```
