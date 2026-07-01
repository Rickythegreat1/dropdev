# DevDrop

DevDrop is a local-first "Dropbox for devs" MVP for keeping developer
workspaces coherent across machines and coding agents.

The full MVP models:

- local-first project registry
- workspace readiness
- machine map
- Git freshness detection
- env profile awareness without leaking secret values
- ignored and generated path policy
- local content-addressed object store
- sync preview contracts and future sync engine model
- lazy hydration simulation
- sync queue
- tombstones and deletion semantics
- conflict objects and conflict UI
- agent workspace planner
- Codex handoff contract
- CLI
- Tauri desktop UI
- Codex skills/hooks/MCP tooling
- UX and aesthetic red-team loops
- deterministic test and eval gates

## Slice 0/1 Status

This repository is currently the foundation slice. It includes compileable Rust
contracts, a safe CLI, a React/Vite desktop shell, a Tauri scaffold, docs,
fixtures, inert Codex tools, and deterministic safety tests. It does not perform
real sync, deletion, overwrite, dehydration, Git mutation, or secret capture.

## Commands

```powershell
cargo fmt
cargo fmt --check
cargo test
cargo check
cargo run -p devdrop-cli -- doctor
pnpm install
pnpm typecheck
pnpm test
pnpm desktop:dev
pnpm --filter @devdrop/desktop build
cargo check --manifest-path apps/desktop/src-tauri/Cargo.toml
```

Tauri can be launched with:

```powershell
pnpm desktop:tauri
```

If Tauri platform dependencies are missing on a machine, keep the React/Vite
shell running with `pnpm desktop:dev` and install the missing Tauri dependency
reported by the CLI before building the native shell.
