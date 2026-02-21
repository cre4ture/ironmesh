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

context-refresh:
    @test -f docs/agent-context.md
    @echo "==> Context refresh helper"
    @changed="$$(git diff --name-only -- README.md docs apps/server-node tests/system-tests .cargo rust-toolchain.toml Cargo.toml justfile)"; \
    if [ -n "$$changed" ]; then \
        echo "Potentially context-impacting changes:"; \
        echo "$$changed"; \
    else \
        echo "No staged/unstaged context-impacting changes detected in tracked areas."; \
    fi
    @echo ""
    @echo "Update docs/agent-context.md with:" \
         "(1) what changed" \
         "(2) why" \
         "(3) quick validation command" \
         "(4) source-of-truth files"

context-check:
    @test -f docs/agent-context.md
    @grep -q "## Update Protocol" docs/agent-context.md
    @echo "docs/agent-context.md exists and contains update protocol."
