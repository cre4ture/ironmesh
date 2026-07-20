#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ZIG_VERSION="0.16.0"
ZIG_TARBALL_SHA256="70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00"
ZIG_TARBALL_URL="https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz"
ZIG_CACHE_DIR="${IRONMESH_ZIG_CACHE_DIR:-${HOME}/.cache/ironmesh-build-tools}"
ZIG_DIR="${ZIG_CACHE_DIR}/zig-x86_64-linux-${ZIG_VERSION}"

TARGET_TRIPLE="armv7-unknown-linux-musleabihf"
PACKAGE="server-node"
BIN_NAME="ironmesh-server-node"

DEPLOY_TARGET=""

log() {
  printf '[build-server-node-armv7-musl] %s\n' "$*"
}

fail() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

usage() {
  cat <<EOF
Cross-compile a fully static ironmesh-server-node binary for armv7 hardfloat
Linux boards, including devices whose libc isn't glibc/musl (e.g. the
LuckFox Nano KVM's uClibc-based Buildroot image).

This targets armv7-unknown-linux-musleabihf and links statically. A static
musl binary only depends on the kernel syscall ABI, not the device's own
libc, so it runs unmodified on uClibc (or any other libc) systems with a
compatible kernel and CPU.

The C-touching dependencies (ring, zstd, sqlite, blake3, ...) need a matching
cross C toolchain; this script uses zig via cargo-zigbuild for that, so no
Docker or system cross-gcc package is required.

Usage:
  ./scripts/build-server-node-armv7-musl.sh [--deploy TARGET]

Options:
  --deploy TARGET   scp the built binary to TARGET after a successful build,
                     e.g. --deploy root@192.168.178.132:/userdata/ironmesh-server-node
  -h, --help        Show this help text.

Environment:
  IRONMESH_ZIG_CACHE_DIR      Where to cache the downloaded zig toolchain.
                               Defaults to ~/.cache/ironmesh-build-tools.
  IRONMESH_PREBUILT_WEB_DIR   Forwarded to the build as-is. Set this to a
                               directory containing prebuilt server-admin/
                               and client-ui/ dist output if pnpm/node_modules
                               aren't available in this checkout (see
                               crates/server-node-sdk/build.rs for the exact
                               layout expected).

Notes:
  - Only x86_64 Linux build hosts are supported.
  - Run this against a checkout that already builds natively; this script
    only handles the cross-compilation toolchain, not unrelated build
    breakage.
EOF
}

while (($# > 0)); do
  case "$1" in
    --deploy)
      [[ $# -ge 2 ]] || fail "--deploy requires a value"
      DEPLOY_TARGET="$2"
      shift 2
      ;;
    --deploy=*)
      DEPLOY_TARGET="${1#*=}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown argument: %s\n\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

install_zig() {
  if command -v zig >/dev/null 2>&1; then
    log "using zig already on PATH: $(command -v zig)"
    return
  fi

  if [[ -x "${ZIG_DIR}/zig" ]]; then
    log "using cached zig at ${ZIG_DIR}/zig"
    export PATH="${ZIG_DIR}:${PATH}"
    return
  fi

  local host_arch
  host_arch="$(uname -m)"
  [[ "${host_arch}" == "x86_64" ]] \
    || fail "this script only auto-downloads zig for x86_64 build hosts (found: ${host_arch}); install zig manually and ensure it's on PATH"

  log "downloading zig ${ZIG_VERSION}"
  mkdir -p "${ZIG_CACHE_DIR}"
  local tarball="${ZIG_CACHE_DIR}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz"
  curl -sL -o "${tarball}" "${ZIG_TARBALL_URL}"

  echo "${ZIG_TARBALL_SHA256}  ${tarball}" | sha256sum -c - \
    || fail "zig tarball checksum mismatch; aborting"

  tar -C "${ZIG_CACHE_DIR}" -xf "${tarball}"
  rm -f "${tarball}"
  export PATH="${ZIG_DIR}:${PATH}"
}

install_cargo_zigbuild() {
  if command -v cargo-zigbuild >/dev/null 2>&1; then
    log "using cargo-zigbuild already installed: $(command -v cargo-zigbuild)"
    return
  fi

  log "installing cargo-zigbuild"
  cargo install cargo-zigbuild
}

install_rust_target() {
  # Run from ROOT_DIR so rustup resolves the repo's pinned toolchain
  # (rust-toolchain.toml) rather than whatever toolchain is active in the
  # caller's cwd when this script is invoked by absolute path.
  (
    cd "${ROOT_DIR}"
    if rustup target list --installed | grep -qx "${TARGET_TRIPLE}"; then
      exit 0
    fi

    log "adding rust target ${TARGET_TRIPLE}"
    rustup target add "${TARGET_TRIPLE}"
  )
}

main() {
  require_command cargo
  require_command rustup
  require_command curl
  require_command sha256sum
  require_command tar

  install_zig
  install_cargo_zigbuild
  install_rust_target

  log "building ${BIN_NAME} for ${TARGET_TRIPLE}"
  (
    cd "${ROOT_DIR}"
    # target-cpu=cortex-a7 unlocks NEON/VFPv4 codegen (confirmed present via
    # /proc/cpuinfo on the LuckFox PicoKVM) instead of the generic armv7
    # baseline, which benefits blake3's SIMD hashing kernels among others.
    #
    # This must be set via the target-scoped CARGO_TARGET_*_RUSTFLAGS var,
    # not a bare RUSTFLAGS: a bare RUSTFLAGS applies to every rustc
    # invocation cargo makes for this build, including host build-script
    # and proc-macro compilation (server-node has apps/server-node/build.rs,
    # plus proc-macro deps like clap_derive) - cortex-a7 is not a valid
    # target-cpu on the x86_64 build host.
    #
    # panic=abort is set here via --config rather than in the shared
    # workspace Cargo.toml: it's safe for this standalone binary, but
    # unsafe to apply workspace-wide since the android/ios app crates rely
    # on catching panics at their FFI boundary to avoid aborting the host
    # app process.
    CARGO_TARGET_ARMV7_UNKNOWN_LINUX_MUSLEABIHF_RUSTFLAGS="-C target-cpu=cortex-a7" \
      cargo zigbuild \
      --locked \
      --config profile.release.panic='"abort"' \
      --target "${TARGET_TRIPLE}" --release -p "${PACKAGE}" --bin "${BIN_NAME}"
  )

  local bin_path="${ROOT_DIR}/target/${TARGET_TRIPLE}/release/${BIN_NAME}"
  [[ -f "${bin_path}" ]] || fail "expected build artifact not found: ${bin_path}"

  log "built: ${bin_path}"
  file "${bin_path}" 2>/dev/null || true

  if [[ -n "${DEPLOY_TARGET}" ]]; then
    log "deploying to ${DEPLOY_TARGET}"
    scp "${bin_path}" "${DEPLOY_TARGET}"
  fi
}

main "$@"
