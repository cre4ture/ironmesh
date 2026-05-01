# Self-Hosted Apt Repository

Ironmesh can be published from any static HTTPS web root as a small signed apt
repository. The web server only hosts files; apt verifies the signed `Release`
metadata and the package checksums inside that metadata.

The default Ironmesh target is:

```bash
https://creax.de/apt/ironmesh
```

## Build packages

Create the binary Debian packages from the current checkout:

```bash
./scripts/build-local-debs.sh -- -jauto
```

The packages are written to the parent directory of the checkout.

## Build repository metadata

Generate `pool/`, `dists/`, `Packages.gz`, `Release`, `InRelease`, and the
public archive key:

```bash
export GPG_TTY="$(tty)"
APT_REPO_SIGN_KEY=5D7762BDB9A2A564D500DE702A2E3C589C188616 \
  ./scripts/build-apt-repository.sh
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

The deploy script uses `rsync --delete`, so keep that remote directory dedicated
to the apt repository.

## Verify the published repository

After publishing, check that the signed metadata and package index are visible:

```bash
curl -fsSL https://creax.de/apt/ironmesh/dists/noble/InRelease | gpg --verify
curl -fsSL https://creax.de/apt/ironmesh/dists/noble/main/binary-amd64/Packages.gz \
  | gzip -dc \
  | grep '^Package: '
```

## Client setup

Install the repository key into apt's keyring directory:

```bash
curl -fsSL https://creax.de/apt/ironmesh/ironmesh-archive-keyring.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/ironmesh-archive-keyring.gpg
```

Add the apt source:

```bash
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

For a new release, bump `debian/changelog`, build the local `.deb` packages,
rebuild the repository metadata, and deploy again:

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
