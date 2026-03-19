# Ironmesh Web Workspace

This workspace is the shared frontend home for:

- `server-admin`
- `client-ui`
- shared UI components
- shared API helpers

## Package manager

Use `pnpm`.

## Common commands

```bash
pnpm install
pnpm dev:server-admin
pnpm dev:client-ui
pnpm typecheck
pnpm build
pnpm test:e2e:client-ui
pnpm test:e2e:server-admin
pnpm test:e2e:server-admin-rust
pnpm test:e2e:server-admin-setup-rust
```

## Current scope

This workspace now owns the built frontend bundles for:

- the `server-node` admin/setup UI
- the `web-ui-backend` client UI used by `serve-web`
- the shared design system and API helpers used by both

The Rust crates still own the embedding/serving path, but the handwritten embedded HTML/JS assets are being retired in favor of the React apps here.

The source-of-truth migration checklist is:

- `docs/web-ui-migration-checklist.md`
