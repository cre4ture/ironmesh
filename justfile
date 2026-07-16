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

coverage:
    cargo +stable llvm-cov --workspace --all-features --summary-only \
        --ignore-filename-regex 'apps/(android-app|ios-app|cli-client|web-ui)/|apps/(ironmesh-folder-agent|os-integration|ironmesh-config-app|ironmesh-background-launcher)/src/main.rs|apps/server-node/src/main.rs|crates/common/src/lib.rs|crates/adapter-linux-fuse/|crates/desktop-client-config/src/lib.rs|crates/server-node-sdk/src/(embedded_rendezvous|setup|ui\.rs)|crates/server-node-sdk/src/web_maps(\.rs|/)|crates/sync-agent-core/src/folder_agent_ui.rs|crates/web-ui-backend/src/lib.rs' \
        --fail-under-lines 70

web-test-e2e-client:
    cd web && pnpm test:e2e:client-ui

web-test-e2e-server-admin:
    cd web && pnpm test:e2e:server-admin

web-test-e2e-server-admin-rust:
    cd web && pnpm test:e2e:server-admin-rust

web-test-e2e-server-admin-setup-rust:
    cd web && pnpm test:e2e:server-admin-setup-rust

ci-web-smoke:
    just web-test-e2e-client
    just web-test-e2e-server-admin
    just web-test-e2e-server-admin-rust
    just web-test-e2e-server-admin-setup-rust

audit:
    cargo audit

deny:
    cargo deny --exclude system-tests check advisories licenses sources bans

test-all:
    just test-stable
    just test-system-nightly

test-system-nightly:
    cargo +nightly -Z bindeps test --manifest-path tests/system-tests/Cargo.toml

test-system-nightly-one name:
    cargo +nightly -Z bindeps test --manifest-path tests/system-tests/Cargo.toml --lib -- {{name}} --exact --nocapture

ci-stable:
    cargo fmt --all -- --check
    cargo +stable check --workspace
    cargo +stable clippy --workspace --all-targets -- -D warnings
    cargo +stable test --workspace

ci-required:
    just ci-stable
    just coverage
    just ci-web-smoke
    just test-system-nightly

ci-ios:
    cargo test -p ios-app
    cd apps/apple-file-provider && swift test
    DEST="$$(IRONMESH_IOS_SIMULATOR_APP_BUNDLE_ID=dev.ironmesh.apple.iosapp apps/apple-file-provider/scripts/prepare-ios-simulator.sh apps/apple-file-provider/IronmeshAppleFileProvider.xcodeproj IronmeshIosProject)" && \
        xcodebuild test \
            -project apps/apple-file-provider/IronmeshAppleFileProvider.xcodeproj \
            -scheme IronmeshIosProject \
            -destination "$$DEST" \
            -destination-timeout 180

ci-required-macos:
    just ci-required
    just ci-ios

web-install:
    cd web && pnpm install

web-dev-admin:
    cd web && pnpm --filter @ironmesh/server-admin dev

web-dev-client:
    cd web && pnpm --filter @ironmesh/client-ui dev

web-build:
    cd web && pnpm build

web-typecheck:
    cd web && pnpm typecheck

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
