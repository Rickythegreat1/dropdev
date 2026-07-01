# Model Routing

DevDrop uses Codex orchestration to make workspace automation safer, not to
make review optional. Routing is deterministic by task class. When a task spans
multiple classes, route it by the highest-risk class and inherit that class's
review, approval, retry, and test gates. For example, a UI change involving
deletion copy is not only Class B; it inherits Class J approval and review
requirements.

## Model Tiers

- `cheap`: bounded docs, simple fixtures, copy variants, redacted critique, and
  isolated tests where deterministic checks can verify the work.
- `standard`: ordinary implementation where blast radius is local and no
  secrets, destructive behavior, sync truth, or architecture boundary changes
  are involved.
- `strong`: sync, filesystem, secrets, deletion, hydration, conflict, daemon,
  permission, architecture, or safety-critical UX work.
- `human approval`: explicit user approval before mutating user files, Git
  state, object store state, hydration state, conflict resolution, deletion, or
  secret-adjacent storage/transport behavior.

Project-local `.codex/config.toml` may document recommended DevDrop hooks,
skills, and local MCP wiring. It must not be treated as provider or model
routing authority where Codex requires user-level configuration.

## Global Routing Rules

- No cheap model writes secrets or security code without strong review.
- No cheap model implements deletion, conflict resolution, tombstone apply,
  hydration, or sync mutation.
- UI changes require UX and aesthetic red-team loops.
- Architecture changes require a strong model.
- Sync, deletion, conflict, tombstone, and hydration changes require sync
  invariant review.
- Hooks and MCP tools require security review.
- If the same failure recurs once in dangerous code, escalate immediately.
- If the same failure recurs twice in safe code, escalate.
- Subagents are allowed only when the task is parallelizable or needs specialist
  review; otherwise the main agent keeps the work in one loop.

## Task Class Routing Matrix

| Task Class | Default model tier | Allowed cheap subagent usage | Required reviewer | Hard gates | Escalation trigger | Maximum autonomous retries | Required tests | Human approval |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| A. Documentation and copy | cheap | Draft docs, copy options, loop-log summaries from redacted context. | Docs reviewer or main agent. | No secret values, no false safety claims, update linked docs when behavior changes. | Copy claims sync, safety, encryption, deletion, or agent capability beyond evidence. | 2; same failure twice escalates. | `rg` sanity checks; relevant cargo/pnpm gates if docs mention runtime contracts. | No, unless copy authorizes destructive behavior or changes safety policy. |
| B. Simple UI component | standard | Draft static component layout or copy variants only. | UX red-team and aesthetic red-team. | Must answer "Can I safely work here?", avoid generic AI dashboard visuals, no destructive action without blocked/preview state. | UI touches deletion, conflict, hydration, env, sync apply, or security copy; inherit higher class. | 2 for safe UI; same failure twice escalates. | `pnpm typecheck`, `pnpm test`, screenshot/route check when available. | No for read-only UI; yes if UI can trigger mutating workflow. |
| C. UX/aesthetic critique | cheap for critique, standard for applied UI changes. | Independent critique passes on redacted screenshots or route code. | UX/aesthetic reviewer. | Must identify evidence gaps, blocked states, anti-slop risks, and receipt requirements. | Critique covers safety-critical deletion, sync, conflict, hydration, or secrets flow. | 2; same critique miss twice escalates. | Rubric check; `pnpm test` if UI docs or code changed. | No, unless approving safety-critical flow language. |
| D. Pure Rust data model | standard | Draft serialization tests or fixture examples only. | Rust reviewer. | Models serialize deterministically, no secret values, generated paths excluded where relevant. | Model affects sync truth, secrets, deletion, hydration, conflicts, or event log. | 2 for safe models; 1 after inheriting dangerous class. | `cargo test`, serialization/redaction tests. | No, unless model enables mutating behavior or secret transport. |
| E. CLI command behavior | standard | Draft help text, dry-run wording, and eval cases for non-mutating commands. | CLI/Rust reviewer. | Dangerous commands must be dry-run or unavailable; output cannot claim real sync complete. | Command can mutate files, Git, CAS, queue, tombstones, hydration, or conflicts. | 2 for read-only CLI; 1 for dangerous preview code. | `cargo test`, command smoke test, redaction tests. | Yes for any mutating command path. |
| F. Git observation | strong | Cheap agent may draft docs/tests only. | Sync/security reviewer. | Observation only unless dry-run preview and approval exist; never mutate Git silently. | Any branch change, checkout, reset, merge, rebase, stash, or write. | 1; repeated failure escalates immediately. | `cargo test`, fixture-backed Git observation tests. | Yes for Git mutation. |
| G. File scanning/hashing | strong | Cheap agent may draft ignore-policy docs or fixture names only. | Security and sync invariant reviewer. | Never read/print secret values; never add ignored/generated paths to CAS; Windows paths tested. | Scanner touches env files, raw contents, generated trees, CAS writes, or broad live filesystem traversal. | 1; repeated failure escalates immediately. | `cargo test`, fixture scan tests, redaction tests, ignore-policy tests. | Yes for broad live scans that persist data or write CAS. |
| H. Watcher/daemon | strong | Cheap agent may draft daemon docs or mocked event fixtures only. | Sync invariant reviewer. | Watcher events are hints only; reconciliation scan is truth; no background mutation without approval. | Background task writes metadata, CAS, files, Git, or queue apply state. | 1; repeated failure escalates immediately. | `cargo test`, deterministic event/reconciliation tests. | Yes for background mutation or auto-apply behavior. |
| I. Hydration | strong | Cheap agent may draft UX copy or fixture labels only. | Sync invariant reviewer and UX reviewer. | Simulation must not masquerade as real content; apply requires preview, approval, rollback notes, and tests. | Any hydrate/dehydrate apply, placeholder replacement, or file write. | 1; repeated failure escalates immediately. | `cargo test`, hydration state-machine tests, fixture tests, UI receipt checks if surfaced. | Yes for real hydrate/dehydrate apply. |
| J. Conflict/deletion/tombstone | strong | Cheap agent may draft docs or redacted UI copy only. | Sync invariant reviewer and security reviewer. | Never silently delete or overwrite; tombstones before removal; conflicts preserve both sides; restore path documented. | Any delete, move, overwrite, conflict resolution, tombstone apply, or restore behavior. | 1; repeated failure escalates immediately. | `cargo test`, fixture conflict/tombstone tests, dry-run and rollback tests. | Yes for every destructive or conflict-resolving action. |
| K. Env/secrets | strong | Cheap agent may draft public docs from redacted examples only. | Security reviewer. | Never print, serialize, persist, display, or send secret values to agents; fingerprints/names only. | Any storage/transport/display of env data, secret-like logs, or redaction code. | 1; repeated failure escalates immediately. | `cargo test`, redaction tests, forbidden-key tests, handoff JSON tests. | Yes for secret-adjacent storage or transport changes. |
| L. MCP/hooks/skills | standard for docs/schemas, strong for behavior. | Cheap agent may draft SKILL.md text or schema mirrors only. | Security reviewer; skill reviewer for SKILL.md changes. | Hooks disabled until trusted; MCP responses redacted/read-only; no full protocol claim unless implemented. | Tool/hook reads files, blocks commands, mutates workspace, exposes context, or affects agent permissions. | 2 for docs/schemas; 1 for behavior; repeated dangerous failure escalates immediately. | `cargo test`, `pnpm test`, schema safety tests, hook disabled tests. | Yes for enabling hooks or mutating MCP tools. |
| M. Architecture | strong | Cheap agent may collect references or summarize existing docs only. | Architecture reviewer plus relevant domain reviewer. | Preserve safety boundaries, sync invariants, UX/aesthetic principles, and full MVP scope. | Architecture changes safety boundaries, storage truth, sync model, permissions, or model routing policy. | 1; repeated failure escalates immediately. | Docs sanity `rg`, affected cargo/pnpm gates, invariant review. | Yes when changing safety boundaries or approval policy. |

## Local MCP Posture

MCP connects models to tools and context. Codex supports MCP in local Codex
surfaces, and the DevDrop MVP uses STDIO for local development.

In Slice 0/1, `devdrop-mcp` is a JSON-over-STDIO scaffold, not a complete MCP
protocol implementation. It exposes typed, safe stubs for:

- `doctor(project_path)`
- `scan(project_path)`
- `sync_plan(project_path)`
- `list_conflicts(project_path)`
- `agent_contract(project_path, task)`
- `design_redteam(screen_name)`
- `ux_redteam(flow_name)`

Every Slice 0/1 MCP response must be dry-run/read-only, must not mutate files,
must not expose env values, and must not include raw file text.

## Hook Trust Boundary

`.codex/hooks.json` keeps hooks absent or disabled until they are trusted. A
hook file being present is not approval to run it, block with it, or use it as
evidence that a safety concern has been solved.

Hooks in Slice 0/1 are inert and dry-run:

- `secret-output-guard` documents future output redaction checks.
- `destructive-command-guard` documents future preview/approval checks.
- `design-slop-guard` documents future visual critique checks.

They do not auto-enable, mutate files, approve destructive behavior, inspect
live env files, or replace human review.

## Codex Handoff

Codex handoff may include project id, display path, machine summary, readiness
findings, Git freshness summary, env key names and fingerprints only, ignored
path policy, queue preview, conflict/tombstone summaries, and blocked dangerous
actions.

It must not include raw env values, raw file text, secret-like logs, or commands
that apply destructive operations without approval.
