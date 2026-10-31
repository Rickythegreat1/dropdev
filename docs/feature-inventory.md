# DevDrop Feature Inventory

DevDrop is a full local-first "Dropbox for devs" MVP. This inventory keeps the
scope broad enough to include CLI, Tauri desktop, Rust engine, sync semantics,
env profiles, agent workspaces, MCP/hooks/skills, and UX red-team loops.

Mode legend: `read-only` observes or reports, `dry-run` previews without
mutation, and `mutating-gated` may change local state only after preview,
explicit approval, rollback notes, event log coverage, and tests.

## CLI

| Feature | User problem | Required behavior | Acceptance criteria | Test/eval | UX risk | Aesthetic risk | Security risk | Owner | Mode |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `devdrop init` | Project starts with no local DevDrop contract. | Create local metadata skeleton and default policies after preview. | Shows target paths, writes only approved metadata, records event. | Fixture init test, Windows path test. | Feels like hidden takeover. | CLI copy too generic. | Writes in wrong folder. | `devdrop-cli`, `devdrop-core` registry. | mutating-gated |
| `devdrop doctor` | User needs quick trust signal. | Print safe readiness summary without claiming sync. | Reports foundation/readiness and blocked actions. | Snapshot output test. | Oversimplified green check. | Status theater. | Leaks env values. | `devdrop-cli`, readiness model. | read-only |
| `devdrop scan` | Workspace state is invisible. | Scan Git/env/ignore/CAS eligibility without mutation. | Findings include causes and evidence. | Fixture scanner evals. | Too noisy to act on. | Wall of badges. | Reads secret values instead of names. | `devdrop-cli`, `devdrop-core` scanner. | read-only |
| `devdrop watch` | User wants freshness while working. | Subscribe to watcher hints and schedule reconciliation scans. | Watcher event never becomes truth alone. | notify-rs hint test, reconciliation test. | Implies live sync magic. | Busy terminal spam. | Trusts spoofed events. | `devdrop-daemon`. | read-only |
| `devdrop status` | User needs current project/machine summary. | Show registry, machine, queue, conflicts, env, and freshness. | Includes "safe to work?" answer and blockers. | Fixture status golden test. | Hides root cause. | Generic dashboard copy. | Exposes paths/secrets too broadly. | `devdrop-cli`, registry/readiness. | read-only |
| `devdrop hydrate` | Files may be lazy/missing. | Simulate or perform approved hydration from local objects. | Default is simulation; apply requires approval. | Hydration state-machine tests. | User thinks file changed when it did not. | Progress bar without evidence. | Writes outside allowlist. | `devdrop-cli`, sync/hydration engine. | dry-run, mutating-gated |
| `devdrop sync plan` | User needs to know what sync would do. | Build replayable plan with queue, CAS, conflicts, tombstones. | Plan lists all intended mutations and blockers. | Two-folder sync fixture eval. | Plan too opaque. | Dense unsafe table. | Omits destructive action. | `devdrop-cli`, sync preview. | dry-run |
| `devdrop sync apply` | User wants approved changes applied. | Apply only a previously logged plan with approval token. | Refuses stale plan, logs receipt, rollback notes exist. | Apply/rollback fixture test. | Looks too easy. | Dangerous primary CTA tone. | Deletes or overwrites without proof. | `devdrop-cli`, sync engine. | mutating-gated |
| `devdrop conflict list` | User cannot see sync conflicts. | List conflict objects with provenance and paths. | Never hides conflicts; shows unresolved count. | Conflict fixture test. | Conflict anxiety. | Alarmist colors. | Reveals secret file names unnecessarily. | `devdrop-cli`, conflict model. | read-only |
| `devdrop conflict resolve` | User needs safe conflict resolution. | Preview resolution, preserve both sides, apply only after approval. | Resolution receipt references both objects. | Conflict resolution fixture test. | User loses work. | Winner-take-all visual bias. | Overwrites wrong side. | `devdrop-cli`, conflict engine. | dry-run, mutating-gated |
| `devdrop machine list` | User lacks cross-machine awareness. | List known machines, roots, freshness, and availability. | Shows current machine and stale peers. | Registry fixture test. | Machine identity confusion. | Decorative topology only. | Leaks local usernames unnecessarily. | `devdrop-cli`, machine registry. | read-only |
| `devdrop env check` | Env readiness is unclear. | Report env profile names, key presence, fingerprints, missing keys. | Never prints values; shows machine availability. | Secret canary test. | Users infer secret is stored. | Vague "configured" pills. | Secret value capture. | `devdrop-cli`, env profile. | read-only |
| `devdrop agent plan` | Agent may start from stale workspace. | Produce safe plan with path allowlist, forbidden paths, warnings. | Includes stale-base and env warnings. | Handoff schema eval. | Agent appears autonomous. | Chatbot aesthetic. | Sends secrets or raw files. | `devdrop-cli`, planner. | dry-run |
| `devdrop agent create` | User needs an isolated agent workspace. | Create approved workspace from plan with safe paths only. | Refuses unapproved plans and forbidden paths. | Agent workspace fixture test. | User cannot tell what agent sees. | Workspace as generic card. | Copies secrets/generated dirs. | `devdrop-cli`, agent workspace engine. | mutating-gated |
| `devdrop mcp serve` | Codex needs safe local tools. | Serve MCP tools that expose redacted readiness and plans. | Tools declare mutability and redaction. | MCP schema/security eval. | Tool trust is unclear. | Invisible automation. | Secret/file-content exposure. | `devdrop-mcp`. | read-only, dry-run |

## Desktop App Pages

| Feature | User problem | Required behavior | Acceptance criteria | Test/eval | UX risk | Aesthetic risk | Security risk | Owner | Mode |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Onboarding | User does not know what DevDrop will touch. | Explain local-first scope, add project, show safety boundaries. | User sees preview before registry write. | Playwright onboarding flow. | Trust lost on first click. | Marketing hero instead of tool. | Broad folder access. | `apps/desktop/src/routes`. | dry-run, mutating-gated |
| Dashboard | User needs "can I work here?" quickly. | Summarize readiness, conflicts, queue, env, machines, next safe action. | No fake metrics; all states link to evidence. | Screenshot red-team. | Hides blockers. | Generic SaaS cards. | Displays secrets in summary. | Dashboard page. | read-only |
| Project detail | User needs project-specific evidence. | Show registry path, manifest, Git, env, ignored policy, queue. | Every finding has cause and source. | Component tests, fixture data. | Too much detail. | Cluttered inspector. | Shows sensitive paths broadly. | Project detail page. | read-only |
| Workspace tree | User needs visible included/excluded paths. | Show eligible, ignored, generated, secret, hydrated states. | `node_modules` and generated dirs excluded by default. | Tree fixture screenshot. | User misreads exclusion as deletion. | File-tree sameness. | Secret file names overexposed. | Workspace tree page. | read-only |
| Hydration center | User needs lazy-file clarity. | Show present, stub, simulated, pending hydration states. | Simulation clearly differs from apply. | Hydration flow test. | User thinks data is available when stubbed. | Magic progress visuals. | Hydrates outside allowlist. | Hydration page. | dry-run, mutating-gated |
| Sync queue | User needs pending work transparency. | Show replayable queue items, dependencies, approval state, receipts. | Apply unavailable until plan is valid. | Queue fixture test. | Queue feels like background magic. | Activity feed noise. | Hidden destructive item. | Sync queue page. | read-only, mutating-gated |
| Conflict center | User needs to preserve work. | Show conflict list, object comparison, provenance, resolution preview. | Both sides remain available until approved resolution. | Conflict UI flow. | Accidentally favors one side. | Panic red overload. | Shows secret diff contents. | Conflict center page. | read-only, mutating-gated |
| Machine map | User needs cross-machine topology. | Show machines, roots, freshness, project availability, stale states. | Current machine and stale peers are obvious. | Machine-map screenshot eval. | Topology is decorative only. | Random network art. | Leaks machine/user identities. | Machine map page. | read-only |
| Env profiles | User needs env readiness without leaks. | Show profiles, keys present/missing, per-machine availability. | Values are impossible to reveal. | Secret canary UI test. | Users think DevDrop stores secrets. | Vague status pills. | Secret display/logging. | Env profiles page. | read-only |
| Agent workspaces | User needs safe agent prep. | Show workspace plan, allowlist, forbidden paths, stale/env warnings. | Agent create blocked until plan approved. | Agent handoff flow. | Agent agency unclear. | AI dashboard tropes. | Sends secrets/raw content. | Agent workspaces page. | dry-run, mutating-gated |
| Settings | User needs policy control. | Manage ignore rules, storage paths, MCP, hooks, approvals. | Dangerous settings require explanation. | Settings fixture tests. | Misconfigured safety. | Preferences dump. | Disables guards silently. | Settings page. | read-only, mutating-gated |
| Logs/audit trail | User needs receipts and accountability. | Show event log, plans, approvals, applies, refusals, redactions. | Every mutation has receipt. | Event-log replay test. | Log too technical. | Monochrome wall. | Logs secrets. | Logs page, event log. | read-only |
| Design system preview | Team needs UI consistency. | Show DevDrop patterns: evidence rails, topology, receipts, approval walls. | Red-team rubric visible. | Visual regression review. | Preview becomes product. | Drifts into shadcn sameness. | None beyond sample data. | Design system page. | read-only |

## Core Engine

| Feature | User problem | Required behavior | Acceptance criteria | Test/eval | UX risk | Aesthetic risk | Security risk | Owner | Mode |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Project registry | Projects across machines are inconsistent. | Track projects, roots, machines, manifests, policies. | Registry survives restart and schema migration. | SQLite fixture tests. | Wrong root selected. | N/A. | Stores sensitive path metadata. | `devdrop-core`, future metadata module. | mutating-gated |
| Workspace manifest | Workspace contents need stable description. | Describe eligible files, ignores, env profile refs, Git refs. | Manifest never includes secret values. | Manifest golden tests. | Manifest mistaken for sync result. | N/A. | Includes generated/secret paths. | `devdrop-core`. | dry-run, mutating-gated |
| Content-addressed object store | Content needs dedupe and replay. | Store eligible bytes by content hash with provenance. | Ignores generated/secret paths; verifies hash. | CAS fixture tests. | User thinks hash means safe. | N/A. | Stores secrets or generated dirs. | `devdrop-core` CAS. | mutating-gated |
| BLAKE3 hashing | Large workspaces need fast hashes. | Stream BLAKE3 hashing with algorithm metadata. | Hashes stable across platforms. | Cross-platform hash tests. | Hash confused with trust. | N/A. | Hashing secret files. | `devdrop-core` hashing. | read-only |
| Local metadata store | Local state needs durability. | SQLite WAL with migrations, busy timeout, checkpoint policy. | Crash-safe event and registry persistence. | DB migration tests. | Metadata feels authoritative globally. | N/A. | Sensitive metadata leakage. | `devdrop-core` metadata. | mutating-gated |
| Event log | Sync needs replayability. | Append events for plans, approvals, applies, conflicts, tombstones. | Replay reconstructs state. | Event replay tests. | Receipts too noisy. | N/A. | Logs secrets. | `devdrop-core` event log. | mutating-gated |
| Tombstones | Deletions need reversible semantics. | Represent delete intent with restore info before deletion. | Delete apply blocked without tombstone and restore path. | Tombstone restore test. | User thinks tombstone deleted file. | N/A. | Tombstones wrong path. | `devdrop-core` tombstones. | dry-run, mutating-gated |
| Conflict objects | Divergent content must be preserved. | Store both sides, provenance, path, resolution state. | Conflict never auto-hidden or overwritten. | Conflict model tests. | Conflict fatigue. | N/A. | Secret diff exposure. | `devdrop-core` conflicts. | mutating-gated |
| Lazy hydration state machine | Partial local content needs clarity. | Model present, stub, simulated, pending, hydrated, failed states. | No write occurs during simulation. | State-machine tests. | Stub looks like real file. | N/A. | Hydrates forbidden path. | `devdrop-core` hydration. | dry-run, mutating-gated |
| Ignored path policy | Generated dependency chaos must stay out. | Default excludes generated and secret paths; explain why. | `node_modules`, `.next`, `dist`, `target`, logs excluded. | Ignore-policy tests. | User cannot override safely. | N/A. | Syncs dependencies or secrets. | `devdrop-core` ignore policy. | read-only, mutating-gated |
| Platform rules | Windows/macOS/Linux path behavior differs. | Normalize comparisons while preserving display paths. | Windows path fixture passes. | Platform path tests. | Path confusion. | N/A. | Writes outside root via path tricks. | `devdrop-core` platform. | read-only |
| Git observation | Stale worktrees break agent work. | Read branch, dirty state, upstream, divergence. | No Git mutation. | Git fixture tests. | Overconfident freshness. | N/A. | Runs unsafe Git command. | `devdrop-core` Git observer. | read-only |
| Git mutation preview | Users may need pull/checkout/clean preview. | Describe exact Git command effects without applying. | Mutation commands require approval and rollback notes. | Git dry-run eval. | Preview mistaken for apply. | N/A. | Mutates Git accidentally. | `devdrop-core`, `devdrop-cli`. | dry-run |
| Machine identity | Cross-device state needs identity. | Generate stable local machine id and roots. | No cloud identity required. | Machine registry test. | Wrong machine selected. | N/A. | Leaks hostname/user. | `devdrop-core` machine. | mutating-gated |
| Readiness scoring | User needs work/no-work decision. | Score from causes: Git, env, conflicts, hydration, queue, ignores. | Score links to evidence and blockers. | Readiness eval set. | Score hides nuance. | N/A. | Includes secret-derived info. | `devdrop-core` readiness. | read-only |

## Sync MVP

| Feature | User problem | Required behavior | Acceptance criteria | Test/eval | UX risk | Aesthetic risk | Security risk | Owner | Mode |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Local object store | Sync needs durable local content. | Store eligible objects and metadata locally. | Object hash verifies stored bytes. | CAS storage tests. | Store feels like backup guarantee. | N/A. | Stores secrets/generated dirs. | `devdrop-core` CAS. | mutating-gated |
| Local two-folder sync simulation | MVP needs safe realism. | Simulate source/target sync between fixture folders. | No real user workspace used by default. | Two-folder fixture eval. | Simulation mistaken for production sync. | N/A. | Deletes fixture data in tests. | sync engine in `devdrop-core`. | dry-run, mutating-gated |
| LAN/mock remote adapter | Future peer sync needs abstraction. | Provide mock adapter contract before network sync. | Adapter can list/get/put in fixture mode. | Adapter contract tests. | LAN sounds production-ready. | N/A. | Sends content over network too early. | future adapter module. | dry-run |
| Sync plan preview | User needs exact before/after. | Produce plan with objects, queue, tombstones, conflicts, approvals. | Plan is replayable and stale-detecting. | Plan golden tests. | Too much complexity. | Generic diff table. | Omits destructive operation. | `devdrop-core` sync preview. | dry-run |
| Conflict preservation | Work must not be lost. | Preserve local and incoming versions. | No overwrite while conflict unresolved. | Conflict fixture eval. | Conflict hidden under status. | Alarmist visuals. | Secret content exposed. | conflict engine. | mutating-gated |
| Tombstone handling | Deletes must sync safely. | Record delete intent, origin, restore object, approval state. | Restore path proven before delete apply. | Tombstone fixture eval. | User fears deletion. | Trash-can simplification. | Deletes wrong file. | tombstone engine. | dry-run, mutating-gated |
| Partial hydration | Not every object should be local. | Track stubs and hydrate on approved request. | Missing content is explicit. | Hydration fixture eval. | Stub confusion. | Magic cloud visuals. | Hydrates forbidden content. | hydration engine. | dry-run, mutating-gated |
| Dry-run before apply | Sync apply is dangerous. | Every mutation requires dry-run plan and approval. | Apply refuses missing preview id. | Apply gate tests. | Approval fatigue. | Shiny dangerous button. | Bypasses gate. | `devdrop-cli`, desktop queue. | dry-run, mutating-gated |

## Env/Profile MVP

| Feature | User problem | Required behavior | Acceptance criteria | Test/eval | UX risk | Aesthetic risk | Security risk | Owner | Mode |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Env key presence | Missing env blocks work. | Detect required key names and presence without values. | Values never stored, printed, or sent. | Secret canary tests. | User expects secret manager. | Vague key badges. | Secret capture. | env profile module. | read-only |
| Env profile names | Projects have modes like dev/test/prod. | Track profile names and required key sets. | Profile can be selected per project/machine. | Profile fixture tests. | Wrong profile selected. | Generic tabs. | Profile reveals sensitive intent. | env profile module, UI page. | mutating-gated |
| Per-machine availability | Machines differ in env setup. | Show which machine has which profile/key presence. | Machine map reflects env gaps. | Machine/env fixture eval. | User blames sync for env issue. | Weak topology. | Hostname/user leakage. | env profile + machine map. | read-only |
| Secret value exclusion | DevDrop must not become secret store. | Exclude values from CLI/UI/MCP/logs/handoff. | Canary absent everywhere. | End-to-end redaction eval. | Users cannot verify policy. | Hidden trust copy. | Critical secret leak. | all surfaces. | read-only |
| Future encrypted value placeholder | Future may support secrets safely. | Document placeholder without implementing value storage. | UI labels feature as unavailable. | Docs/security review. | User thinks encryption exists now. | Lock icon theater. | Premature secret storage. | docs/settings. | read-only |
| Permission model stub | Env access needs boundaries. | Model allow/deny intent for future env reads. | No broad env scrape by default. | Permission contract tests. | Permission wording vague. | OS-dialog mimicry. | Overbroad access. | permission model. | dry-run |

## Agent/Codex MVP

| Feature | User problem | Required behavior | Acceptance criteria | Test/eval | UX risk | Aesthetic risk | Security risk | Owner | Mode |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Agent workspace contract | Agents need safe workspace state. | Define manifest, paths, env warnings, Git freshness, queue/conflicts. | Handoff is redacted and versioned. | Handoff schema eval. | Agent context feels magical. | Chatbot-first UI. | Sends secrets/raw content. | planner/handoff models. | dry-run |
| Safe path allowlist | Agent should see only intended paths. | Explicitly list readable/writable paths. | Forbidden paths rejected. | Allowlist tests. | User cannot inspect scope. | Tiny policy text. | Agent gets broad access. | agent workspace engine. | dry-run, mutating-gated |
| Forbidden path list | Secrets/generated paths need hard blocks. | Block env values, generated dirs, VCS internals, OS secrets. | Violations fail closed. | Forbidden fixture eval. | Hidden denial reason. | Red warning overload. | Secret leak. | agent workspace engine. | read-only |
| Stale-base warning | Agent must not work on stale Git. | Warn on dirty/stale/divergent base. | Handoff includes Git blocker. | Git fixture eval. | Agent proceeds anyway. | Vague caution pill. | Agent overwrites stale work. | planner + Git observer. | read-only |
| Env availability warning | Agent needs env readiness. | Warn missing profile/keys without values. | Handoff lists missing names only. | Env redaction eval. | User thinks agent got secrets. | Generic warning copy. | Secret leak. | planner + env profile. | read-only |
| MCP server | Codex needs structured local tools. | Serve read-only/dry-run tools with explicit schemas. | No tool mutates files by default. | MCP contract tests. | Invisible side effects. | No visible affordance. | Tool leaks content. | `devdrop-mcp`. | read-only, dry-run |
| Codex skills | Repeated loops need instructions. | Provide feature slice, sync review, UX red-team, aesthetic red-team skills. | Skills reference safety rules. | Skill content review. | Skill drift. | N/A. | Skill tells agent unsafe behavior. | `skills/*`. | read-only |
| Hooks | Guardrails need local enforcement. | Secret, destructive, and design guards present but opt-in. | Hooks inert until explicitly enabled. | Hook schema tests. | User assumes hooks active. | N/A. | Hook blocks/permits wrong thing. | `.codex/hooks`, `packages/codex-tools`. | read-only |
| Model routing docs | Work needs right model strength. | Define cheap vs strong model routing. | Stronger model required for risky domains. | Docs review. | Over-escalation slows work. | N/A. | Cheap model handles secrets/deletion. | `docs/model-routing.md`. | read-only |
| Loop logs | Work needs audit trail. | Log major decisions, risks, tests, red-team loops. | Each slice updates loop log. | Docs diff review. | Log becomes performative. | N/A. | Logs sensitive data. | `docs/loop-log.md`. | read-only |

## UX/Aesthetic MVP

| Feature | User problem | Required behavior | Acceptance criteria | Test/eval | UX risk | Aesthetic risk | Security risk | Owner | Mode |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Product metaphor | User needs mental model. | Treat DevDrop as workspace control surface, not AI dashboard. | Screens explain workspace state physically. | UX red-team review. | Metaphor obscures mechanics. | Decorative control cosplay. | None direct. | UX docs, desktop app. | read-only |
| Visual language | Product needs distinctive trust feel. | Calm, spatial, tactile, evidence-first UI. | Avoid banned generic tropes. | Screenshot rubric. | Too quiet for urgent issues. | Generic SaaS/shadcn drift. | None direct. | design system. | read-only |
| Motion principles | State changes need legibility. | Use motion to show cause/effect, not decoration. | Reduced-motion supported. | Motion review. | Motion hides changes. | Flashy AI polish. | None direct. | desktop app. | read-only |
| Empty states | New users need next action. | Empty state explains no project/queue/conflict without false success. | Primary action is safe. | Onboarding screenshots. | Empty means broken. | Marketing filler. | Broad import CTA. | desktop routes. | read-only |
| Warning states | User needs calm risk clarity. | Warnings show cause, evidence, blocked action, next safe step. | No vague severity pills. | Warning-state eval. | Panic or complacency. | Noisy red palette. | User approves unsafe action. | desktop routes. | read-only |
| Conflict states | User needs both versions protected. | Show local/incoming/provenance and blocked resolution. | Both sides inspectable. | Conflict screenshot eval. | Accidentally biases resolution. | Red crisis visual. | Shows secret diff. | Conflict center. | dry-run |
| Trust copy | Users need precise language. | Copy states what did/did not happen. | No fake completion claims. | Copy lint/eval. | Verb ambiguity. | Hype language. | Misleads on secret handling. | all UI/CLI. | read-only |
| Anti-slop rubric | Team needs design quality gate. | Rubric rejects generic AI dashboard patterns. | UI PR includes rubric result. | Red-team checklist. | Rubric ignored. | Slop becomes system. | None direct. | docs/design-redteam-rubric.md. | read-only |
| Red-team loops | Safety and design need adversarial review. | Run UX/aesthetic/security reviews based on touched surface. | Loop log records result. | Loop-log audit. | Review theater. | Same visual drift. | Missed leak/destructive path. | docs, tools/design-redteam. | read-only |

## Current implementation audit (2026-10-31)

Implemented live in `devdrop_core::local`: durable SQLite registry/WAL, bounded
regular-file scans, verified CAS, persisted previews/events, approved two-folder
copy/replace/delete, conflict preservation/resolution, tombstones, rollback and
interruption recovery. CLI `local` and native Tauri routes share that engine.
MCP stdio now implements initialization/discovery/calls with redacted previews.
The browser app runs a clearly labelled virtual-data demo. CI and manual draft
packaging workflows are present; creating them is not evidence they ran remotely.

The local engine now requires an explicit disposable-copy acknowledgement for
apply and rollback. Unix rwx and Windows read-only flags are now previewed, guarded and preserved;
rollback relinks original destination inodes. Unsupported metadata is constrained
or blocked, and access increases need separate approval. Primary working trees
remain forbidden in this beta. Preview metadata and its event
are transactionally committed, with fault-injection rollback coverage.

Remaining beyond this local content-sync beta:

- Remote-machine transport, pairing/identity and cloud-object adapters.
- Live hydration outside the existing bounded sandbox simulation.
- Env key/runtime availability inventory and automated environment provisioning.
- Task-scoped agent workspace execution; handoff remains a redacted contract.
- Full security-descriptor/ownership/xattr/timestamp replication, symlinks and empty directories.
- OS installer validation, signing and physical power-loss testing.
- Verified hosting publication (supported Sites source helper missing here).

The original inventory tables describe product intent. They are not a claim that
all intended features are implemented. See README and deployment record for exact
commands and verification status.

## Dangerous Assumptions

1. A content hash proves trust. It only proves byte identity.
2. A watcher event proves filesystem truth. It is only a hint.
3. A clean Git status means a workspace is ready. Env, hydration, conflicts, and
   queue state also matter.
4. Ignored files are unimportant. Some are critical locally but must not sync.
5. A dry-run plan remains valid forever. It must expire on state changes.
6. A conflict can be summarized without preserving both sides.
7. Tombstones are safe without restore proof.
8. Agent handoff is safe because it is JSON. It can still leak context.
9. SQLite metadata is global truth. It is only local evidence.
10. Good UI can be added later. Trust depends on UI from the first workflow.

## Top 10 UX Failure Modes

1. Dashboard answers "healthy" without showing evidence.
2. User cannot tell whether an action is preview or apply.
3. Conflict flow nudges toward overwriting one side.
4. Env UI implies DevDrop stores secret values.
5. Machine map looks decorative instead of diagnostic.
6. Hydration stubs look like real local files.
7. Queue hides destructive operations behind generic activity.
8. Approval walls become routine click-throughs.
9. Logs are too technical to explain what happened.
10. Agent workspace scope is not inspectable before creation.

## Top 10 Aesthetic Failure Modes

1. Generic AI dashboard layout with metric cards.
2. Purple/blue gradients used as meaning-free atmosphere.
3. Fake glass panels that reduce readability.
4. Default shadcn sameness with no DevDrop identity.
5. Vague status pills replacing evidence.
6. Noisy severity colors that make every state feel urgent.
7. Decorative network maps that do not explain machines.
8. Sparkles or automation motifs that imply magic.
9. Over-rounded controls that feel toy-like for destructive workflows.
10. Empty states that look like marketing pages instead of tools.
