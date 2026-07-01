---
name: devdrop-mcp-builder
description: Scaffold safe DevDrop MCP tools for Codex with typed schemas, redacted outputs, dry-run behavior, and no file mutation or secret exposure.
---

# DevDrop MCP Builder

## When To Use

- Use when adding or changing DevDrop MCP tools, JSON-over-STDIO scaffolds, schema mirrors, Codex handoff tools, queue previews, conflict summaries, eval runners, or local agent context tools.
- Use when exposing DevDrop context to Codex, subagents, hooks, or desktop automation.
- Use when a tool must declare mutation and secret-exposure behavior.

## When Not To Use

- Do not use to build mutating sync, delete, overwrite, hydrate, dehydrate, or Git mutation tools in Slice 0/1.
- Do not use to expose raw file contents, env values, secret-like logs, or unresolved private data.
- Do not claim complete MCP protocol support unless initialization, tool-list handling, request dispatch, and transport behavior are implemented and tested.

## Required Inputs

- Tool name and purpose.
- Input parameters and safe validation rules.
- Output schema and redaction requirements.
- Whether the tool mutates files, metadata, Git, network state, or object store.
- Tests proving dry-run safety and absence of forbidden secret fields.

## Required Outputs

- Typed schema with `mutates_files = false`, `exposes_secret_values = false`, and `SafetyMode::DryRunOnly` unless a future approved slice says otherwise.
- Safe stub or implementation that does not read secret values or raw file contents.
- JSON-over-STDIO behavior clearly labeled as a scaffold if full MCP protocol is not complete.
- Mirrored TypeScript schema when Codex tooling needs it.
- Tests for tool presence, safety mode, redaction, and forbidden response keys.

## Checklist

- Keep Rust `devdrop-mcp` as the canonical safety surface.
- Use STDIO for the local MVP scaffold.
- Return evidence and warnings, not secret values or file contents.
- Keep all Slice 0/1 tools read-only or dry-run.
- Reject fields named `secret`, `env_value`, `raw_value`, `contents`, or `file_contents` in serialized responses.
- Do not route provider/model choices through project-local `.codex/config.toml`.
- Document hook and MCP trust boundaries in `docs/model-routing.md`.

## Examples

- `doctor(project_path)` -> return foundation readiness summary and blocked destructive actions.
- `sync_plan(project_path)` -> return dry-run plan preview only; no apply or CAS write.
- `agent_contract(project_path, task)` -> return allowed/forbidden boundaries and redaction notice, without file contents or env values.

## Failure Modes

- A tool silently reads files to make a better-looking response.
- A response uses a forbidden field key for raw data.
- A dry-run tool claims sync, conflict resolution, or hydration completed.
- TypeScript and Rust schemas drift.
- A local config accidentally enables untrusted hooks.
