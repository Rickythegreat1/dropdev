# End-to-end tests

`crates/devdrop-cli/tests/local_workflow.rs` launches separate CLI processes against
generated temporary folders. It verifies registration persistence, exact-plan
approval, real file copy, repeated apply, stale-target refusal and approved undo.
`crates/devdrop-mcp/tests/stdio.rs` drives the actual MCP executable over stdio.
Core tests cover interruption/restart, partial recovery, races, conflicts,
tombstones and safety/redaction; independent regressions are in
`crates/devdrop-core/tests/security_regressions.rs`.

The desktop has Vitest React/native-adapter tests and
`apps/desktop/tests/browser-smoke.py` for real Chromium browser-demo workflow and
mobile-width verification. Browser smoke needs Python Playwright and Chromium;
it exercises virtual data and does not certify native IPC or OS installers.
Native Tauri and clean-machine installer tests require their documented platform
libraries and target OS. No tests use real user project directories.
