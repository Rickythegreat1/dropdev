# UX Plan

Slice 0/1 creates the 35-state inventory, mock-data requirements, and route
shells. It does not create 35 polished screens.

## Mock Data Required

- Project registry with at least one Windows path.
- Machine map with current machine and one future peer.
- Readiness report with Git, env, ignore policy, CAS, queue, tombstone, and
  conflict sections.
- Env profile containing key names and fingerprints only.
- Queue items marked dry-run only.
- Conflict and tombstone objects with preview-only state.

## Flow 1: First launch -> add project -> readiness scan -> first safe snapshot

| State | User question | Emotional risk | Trust risk | Required evidence | UI pattern | Primary action | Blocked/destructive action | Anti-slop critique | Visual direction notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Opening state | What is DevDrop asking me to do first? | New tool anxiety. | Overpromising sync before trust. | Empty registry, local-only note. | Landing workbench with project bay. | Choose project folder. | Sync apply unavailable. | No hero hype or AI magic. | Quiet bench, one clear intake slot. |
| User intent state | Which folder will be tracked? | Fear of choosing wrong root. | Hidden broad file access. | Path preview and ignore policy summary. | Folder plate with boundary outline. | Confirm folder for scan. | Snapshot apply unavailable. | No vague "connect workspace" copy. | Show root as physical boundary. |
| Scan/status state | Is the workspace ready? | Surprise findings. | False green status. | Git, env, generated path checks. | Evidence rail. | Review findings. | Fix automation unavailable. | No status pill without evidence. | Findings use calm inspection rows. |
| Map/object view state | What objects would matter? | Losing context. | CAS feels invisible. | Eligible file categories, ignored paths. | Object tray. | Inspect policy. | CAS write unavailable. | No abstract blob graphics. | Objects look countable and inspectable. |
| Preview state | What would snapshot do? | Fear of hidden write. | Preview omits ignored paths. | Dry-run summary, excluded generated paths. | Snapshot receipt preview. | Save preview result. | Real snapshot unavailable. | No "done" language. | Receipt shows "would" not "did". |
| Approval/action state | Can I safely proceed? | Premature confirmation. | Approval wall too weak. | Gates missing list. | Approval wall. | Acknowledge blocked state. | Apply snapshot blocked. | No celebratory success state. | Locked control with rollback requirement. |
| Closeout receipt state | What changed? | Ambiguity after action. | User thinks sync happened. | Statement: no files mutated. | Closeout receipt. | Copy next command. | None. | No fake completion badge. | Paper receipt with exact non-actions. |

## Flow 2: Return on another machine -> machine map -> Git/env freshness -> planner recommendation

| State | User question | Emotional risk | Trust risk | Required evidence | UI pattern | Primary action | Blocked/destructive action | Anti-slop critique | Visual direction notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Opening state | Which machine am I on? | Disorientation. | Machine identity is guessed. | Machine id, OS, workspace root. | Current-machine placard. | Inspect machine. | Peer sync blocked. | No generic device card. | Placard sits on topology surface. |
| User intent state | Can I resume work here? | Fear of stale work. | Planner ignores freshness. | Last known project state. | Resume lane. | Select project. | Auto-resume blocked. | No "ready" claim. | Lane shows gaps in evidence. |
| Scan/status state | Is Git fresh and env present? | Merge anxiety. | Git mutation hidden. | Dirty/stale/missing env findings. | Flight-check list. | Review blockers. | Git pull/checkout blocked. | No red panic colors. | Calm checklist with exact unknowns. |
| Map/object view state | How do machines differ? | Confusion across devices. | Topology hides stale source. | Machine comparison. | Machine map. | Compare machines. | Copy from peer blocked. | No decorative network art. | Tracks and nodes show evidence age. |
| Preview state | What does planner recommend? | Agent may do wrong thing. | Recommendation lacks proof. | Inputs used by planner. | Planner docket. | Accept handoff preview. | Auto-fix blocked. | No AI oracle language. | Recommendation is attached to evidence. |
| Approval/action state | What is safe now? | Pressure to continue. | Approval implies mutation. | Blocked action list. | Control lockout. | Open handoff route. | Git mutation blocked. | No big shiny CTA. | Disabled controls explain why. |
| Closeout receipt state | What should I do next? | Unclear next step. | Missing manual command. | Next safe command. | Receipt strip. | Run doctor or Slice 2 scan. | None. | No false reassurance. | Small receipt docked to map. |

## Flow 3: Start agent work -> lazy hydration simulation -> queue preview -> Codex handoff

| State | User question | Emotional risk | Trust risk | Required evidence | UI pattern | Primary action | Blocked/destructive action | Anti-slop critique | Visual direction notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Opening state | Can an agent work safely here? | Losing control to automation. | Agent sees secrets. | Redaction policy and readiness. | Agent prep bench. | Start preparation. | Agent write automation blocked. | No chatbot panel as main UI. | Agent is a task lane, not a mascot. |
| User intent state | What should the agent know? | Oversharing. | Handoff includes file contents. | Handoff schema preview. | Context manifest. | Select safe sections. | Include raw files blocked. | No vague "context pack". | Manifest is inspectable. |
| Scan/status state | What files are hydrated? | Missing dependency fear. | Hydration writes hidden files. | Hydration states. | Hydration gauge rail. | Simulate hydration. | Real hydration blocked. | No magic progress ring. | Tracks show present vs simulated. |
| Map/object view state | What will queue contain? | Queue feels opaque. | Queue applies silently. | Queue item modes. | Queue ledger. | Inspect queue. | Queue apply blocked. | No meaningless activity feed. | Ledger uses verbs and safety mode. |
| Preview state | What will Codex receive? | Secret leak fear. | Handoff has raw values. | JSON preview with redaction notice. | Handoff docket. | Generate preview. | Send/auto-run blocked. | No polished fake JSON if not real. | Schema sections are labeled plates. |
| Approval/action state | Can I hand this off? | Worry about hidden mutation. | Handoff implies permission. | Blocked action list. | Agent approval wall. | Export preview later. | Auto-enable hooks blocked. | No "launch agent" hype. | Approval wall says what remains manual. |
| Closeout receipt state | What did the agent get? | Unclear boundary. | User thinks agent changed files. | Receipt: no files changed. | Handoff receipt. | Copy safe prompt. | None. | No confetti completion. | Receipt is plain and audit-like. |

## Flow 4: Delete safely -> tombstone preview -> approval wall -> restore path

| State | User question | Emotional risk | Trust risk | Required evidence | UI pattern | Primary action | Blocked/destructive action | Anti-slop critique | Visual direction notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Opening state | How does deletion work? | High fear. | Delete is too easy. | Tombstone policy. | Deletion briefing panel. | Read policy. | Delete unavailable. | No trash icon shortcut. | Safety surface dominates. |
| User intent state | Which path would be removed later? | Wrong target fear. | Path boundary unclear. | Exact path and project root. | Path inspection plate. | Select path for preview. | Remove file blocked. | No vague "clean up". | Path appears inside root boundary. |
| Scan/status state | Is it restorable? | Permanent loss fear. | Restore not proven. | Object hash and restore note. | Restore checklist. | Validate preview. | Tombstone apply blocked. | No green success. | Restore path shown before action. |
| Map/object view state | What object backs this path? | CAS mystery. | Object missing. | CAS object summary. | Object cross-section. | Inspect object. | CAS delete blocked. | No decorative file icon. | Object has hash, size, state. |
| Preview state | What would tombstone record? | Misunderstanding semantics. | Tombstone equals delete. | Tombstone JSON preview. | Tombstone receipt preview. | Save preview. | File delete blocked. | No "deleted" wording. | Use "would record" language. |
| Approval/action state | Can deletion happen now? | Accidental approval. | Weak confirmation. | Missing safety gates. | Approval wall. | Acknowledge blocked state. | Delete/apply blocked. | No dangerous primary CTA. | Wall lists dry-run, rollback, tests. |
| Closeout receipt state | What happened? | Need reassurance. | User thinks file gone. | Receipt: no deletion occurred. | Restore receipt. | Copy restore requirements. | None. | No celebratory deletion. | Receipt explicitly says path untouched. |

## Flow 5: Conflict detected -> object comparison -> resolution preview -> closeout receipt

| State | User question | Emotional risk | Trust risk | Required evidence | UI pattern | Primary action | Blocked/destructive action | Anti-slop critique | Visual direction notes |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Opening state | What conflicted? | Merge dread. | Conflict is oversimplified. | Path, local hash, incoming hash. | Conflict docket. | Open comparison. | Auto-resolve blocked. | No vague "needs attention" pill. | Docket has two physical sides. |
| User intent state | Which side should win? | Fear of losing work. | UI nudges one side. | Equal evidence for both sides. | Balanced comparison. | Inspect both. | Choose winner apply blocked. | No biased CTA. | Symmetric surfaces. |
| Scan/status state | Are both objects available? | Missing data concern. | Preview without object. | Object presence states. | Object verification rail. | Verify objects. | Fetch/apply blocked. | No fake diff if absent. | Missing states are explicit. |
| Map/object view state | Where did versions come from? | Machine confusion. | Source machine hidden. | Machine and queue provenance. | Provenance map. | Trace source. | Pull from peer blocked. | No decorative arrows. | Tracks carry hashes and timestamps later. |
| Preview state | What would resolution do? | Overwrite fear. | Preview omits rollback. | Resolution plan and rollback note. | Resolution receipt preview. | Save plan. | Apply resolution blocked. | No "resolve now" language. | Plan shows before/after as plates. |
| Approval/action state | Can this be applied? | Accidental overwrite. | Approval too casual. | Gates missing list. | Conflict approval wall. | Acknowledge blocked state. | Overwrite/apply blocked. | No high-energy red button. | Controls are restrained and exact. |
| Closeout receipt state | What is the safe next step? | Lingering uncertainty. | User thinks conflict solved. | Receipt: conflict unresolved. | Conflict receipt. | Run future fixture eval. | None. | No false resolved state. | Receipt says "still needs review". |

