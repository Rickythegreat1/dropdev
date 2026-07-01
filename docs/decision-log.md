# Decision Log

## Slice 0/1 Decisions

1. Use Rust workspace crates for core, CLI, daemon placeholder, and MCP schema
   placeholder.
2. Keep Tauri as a desktop package scaffold so workspace `cargo test` remains
   focused on core contracts.
3. Use React/Vite for fast route shells and future Playwright coverage.
4. Use BLAKE3 as default hash algorithm; retain SHA-256 as a modeled enum
   variant.
5. Keep hooks present but disabled until explicit install and enablement are
   designed.
6. Represent Windows paths safely as strings in the first contract layer.
7. Keep the initial sync engine as a `devdrop-core` preview contract because the
   requested crate tree does not include a separate sync crate yet.
8. Add `docs/ux-principles.md` as the concise UX rule layer and keep
   `docs/ux-plan.md` as the expanded 35-state inventory.

## Core Engine Slice Decisions

1. Slice Core Engine uses JSON parsing for deterministic model tests; final
   user-facing manifest format remains a product decision unless already locked
   elsewhere.
2. Use `camino` UTF-8 path types only where path semantics matter, while keeping
   compatibility display fields as strings.
3. Model sync-plan approval as a non-mutating receipt/refusal contract; approved
   preview still cannot mutate files, object store state, hydration state, Git
   state, SQLite state, or workspace state.
