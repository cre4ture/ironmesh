# Web UI Migration Checklist

Status: active implementation checklist for moving the server-node admin UI and client web UI onto a shared React + Mantine workspace.

## Goals

- Use one frontend stack across:
  - `server-node` admin/setup UI
  - `client-ui` web surface
  - Android embedded client web UI
- Keep separate apps for admin and client concerns.
- Share one design system, theme, and API helper layer.
- Preserve the current Rust embedding model: build static assets, then serve/embed them from Rust.

## Target workspace

- `web/apps/server-admin`
- `web/apps/client-ui`
- `web/packages/ui`
- `web/packages/api`
- `web/packages/config`

## Phase 1: Workspace scaffold

- [x] Add the `web/` workspace root.
- [x] Add shared package manifests and base TypeScript config.
- [x] Add `server-admin` scaffold.
- [x] Add `client-ui` scaffold.
- [x] Add `packages/ui` scaffold for shared theme/components.
- [x] Add `packages/api` scaffold for shared API helpers/types.
- [x] Add `packages/config` scaffold for shared frontend config.
- [x] Add root helper commands in `justfile`.

Files:

- [x] [web/package.json](c:/Users/hornu/dev-rust/ironmesh/web/package.json)
- [x] [web/pnpm-workspace.yaml](c:/Users/hornu/dev-rust/ironmesh/web/pnpm-workspace.yaml)
- [x] [web/tsconfig.base.json](c:/Users/hornu/dev-rust/ironmesh/web/tsconfig.base.json)
- [x] [web/README.md](c:/Users/hornu/dev-rust/ironmesh/web/README.md)

## Phase 2: Server admin app

- [ ] Build page parity for the current admin runtime UI.
- [ ] Build page parity for the current setup UI.
- [x] Add shared app shell, page header, status cards, JSON/debug panels.
- [x] Move current admin/session flow into typed API helpers.
- [x] Move current control-plane actions into typed API helpers.

Pages to reach parity:

- [x] Dashboard
- [x] Setup
- [x] Admin login/session
- [x] Bootstrap bundles
- [x] Node enrollment
- [x] Client credentials
- [x] Certificates
- [x] Replication
- [x] Logs
- [x] Control plane promotion

Current Rust sources to replace:

- [x] [crates/server-node-sdk/src/ui/index.html](c:/Users/hornu/dev-rust/ironmesh/crates/server-node-sdk/src/ui/index.html)
- [x] [crates/server-node-sdk/src/ui/app.js](c:/Users/hornu/dev-rust/ironmesh/crates/server-node-sdk/src/ui/app.js)
- [x] [crates/server-node-sdk/src/ui/app.css](c:/Users/hornu/dev-rust/ironmesh/crates/server-node-sdk/src/ui/app.css)
- [x] [crates/server-node-sdk/src/ui/setup_index.html](c:/Users/hornu/dev-rust/ironmesh/crates/server-node-sdk/src/ui/setup_index.html)
- [x] [crates/server-node-sdk/src/ui/setup_app.js](c:/Users/hornu/dev-rust/ironmesh/crates/server-node-sdk/src/ui/setup_app.js)

## Phase 3: Rust embed path for server-admin

- [x] Decide on asset handoff strategy:
  - build output copied into crate-owned generated assets
  - or Rust reads from `web/apps/server-admin/dist` during a pre-build step
- [x] Replace `include_str!`-based hand-written admin asset serving with built static assets.
- [x] Keep the route shape stable where practical.
- [x] Add one smoke test that server-admin assets are served.

Rust integration points:

- [x] [crates/server-node-sdk/src/ui.rs](c:/Users/hornu/dev-rust/ironmesh/crates/server-node-sdk/src/ui.rs)
- [ ] [crates/server-node-sdk/src/lib.rs](c:/Users/hornu/dev-rust/ironmesh/crates/server-node-sdk/src/lib.rs)
- [x] [crates/server-node-sdk/src/setup.rs](c:/Users/hornu/dev-rust/ironmesh/crates/server-node-sdk/src/setup.rs)

## Phase 4: Shared packages hardening

- [ ] Extract common layout and theme patterns from real usage.
- [ ] Add typed API clients for both admin and client web surfaces.
- [ ] Add shared loading/error/empty states.
- [ ] Add shared JSON viewer/log viewer widgets.
- [ ] Add shared QR and copy-to-clipboard helpers where still needed.

## Phase 5: Client UI app

- [x] Build a modern `client-ui` app with the same framework/theme.
- [x] Cover current object browsing and basic object operations.
- [x] Cover current transport-aware startup/auth shape.
- [ ] Keep the client UI separate from admin concerns.

Current Rust integration point:

- [x] [crates/web-ui-backend/src/lib.rs](c:/Users/hornu/dev-rust/ironmesh/crates/web-ui-backend/src/lib.rs)

## Phase 6: Android embedded client UI

- [ ] Replace the current embedded client web assets with built `client-ui` assets.
- [ ] Keep Android bridge/platform-specific logic outside the shared React code where possible.
- [ ] Add one Android-facing smoke path for the embedded web UI startup.

Likely touch points:

- [ ] [apps/android-app/src/lib.rs](c:/Users/hornu/dev-rust/ironmesh/apps/android-app/src/lib.rs)
- [ ] [apps/android-app/app/src/main/java/io/ironmesh/android/data/RustClientBridge.kt](c:/Users/hornu/dev-rust/ironmesh/apps/android-app/app/src/main/java/io/ironmesh/android/data/RustClientBridge.kt)

## Phase 7: Remove old handwritten assets

- [x] Remove legacy server admin HTML/JS/CSS once parity is confirmed.
- [ ] Remove old client web assets once `client-ui` fully replaces them.
- [ ] Update docs to point to the new frontend workspace as the source of truth.

## Verification checklist

- [x] `pnpm install` in `web/`
- [x] `pnpm typecheck`
- [x] `pnpm build`
- [x] `pnpm test:e2e:client-ui`
- [x] `pnpm test:e2e:server-admin`
- [x] `pnpm test:e2e:server-admin-rust`
- [x] `pnpm test:e2e:server-admin-setup-rust`
- [x] server-node serves built admin assets
- [x] setup flow still works end to end
- [x] runtime admin flow still works end to end
- [x] client web UI still works in desktop/web contexts
- [ ] Android embedded client web UI still works

## Notes

- Prefer static assets over SSR frameworks.
- Keep `server-admin` and `client-ui` as separate apps.
- Use `packages/ui` and `packages/api` for shared code, not one giant combined app.
- Current Phase 2 slice covers the high-value runtime admin flows in the React app, including Setup and Logs.
- The React app now serves both runtime admin mode and bootstrap setup mode through the same `/`, `/ui/app.css`, and `/ui/app.js` asset paths.
- Current Phase 3 slice uses a strict `build.rs` handoff: `cargo build` now runs `pnpm build` in `web/`, and server-node routes always serve the built app for both runtime and setup mode.
- The legacy handwritten `server-node` admin/setup assets and the old QR helper route have now been removed from the runtime path.
- One Playwright smoke test runs against the built `server-admin` app through `vite preview` with mocked runtime APIs.
- A matching Playwright smoke now covers the built `client-ui` app through `vite preview`, including text store operations, explorer loading, and cluster views.
- The Rust-served browser smokes now cover both a real runtime node and a real first-run setup node, including setup-to-runtime transition after `Start a new cluster`.
- `web-ui-backend` now uses the same strict `build.rs` bundle handoff pattern as `server-node-sdk`, and `serve-web` system tests verify the React client bundle is what Rust serves.
