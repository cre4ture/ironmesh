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
pnpm test:e2e:server-admin
pnpm test:e2e:server-admin-rust
pnpm test:e2e:server-admin-setup-rust
```

## Current scope

This is the scaffold for the planned migration away from the handwritten embedded HTML/JS UIs in the Rust crates.

The source-of-truth migration checklist is:

- `docs/web-ui-migration-checklist.md`
