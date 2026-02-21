set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    @just --list

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

check-stable:
    cargo +stable check --workspace

clippy-stable:
    cargo +stable clippy --workspace --all-targets -- -D warnings

test-stable:
    cargo +stable test --workspace

test-system-nightly:
    cargo -Z bindeps test --manifest-path tests/system-tests/Cargo.toml

test-system-nightly-one name:
    cargo -Z bindeps test --manifest-path tests/system-tests/Cargo.toml --lib -- {{name}} --exact --nocapture

ci-stable:
    cargo +stable check --workspace
    cargo +stable clippy --workspace --all-targets -- -D warnings
    cargo +stable test --workspace
