---
name: devdrop-ux-redteam
description: Critique DevDrop UI and workflow changes for trust, evidence, safety comprehension, blocked actions, receipts, and user confidence.
---

# DevDrop UX Red-Team

## When To Use

- Use for every desktop route, workflow, UI copy, empty state, warning state, conflict flow, hydration flow, tombstone flow, agent handoff, or CLI-to-UI handoff.
- Use when a user must decide whether it is safe to work, sync, delete, hydrate, resolve conflict, or start an agent.
- Use before accepting UI changes that summarize hidden workspace state.

## When Not To Use

- Do not use as a substitute for aesthetic critique; pair with `devdrop-aesthetic-redteam` for visual direction.
- Do not use to approve unsafe operations; pair with sync invariant review.
- Do not use to add explanatory marketing copy where product evidence is missing.

## Required Inputs

- Screen, route, or flow name.
- User intent and user question.
- Current mock data or fixture state.
- Dangerous or blocked actions on the surface.
- Evidence available to justify recommendations.
- Screenshot or implementation reference when available.

## Required Outputs

- UX findings ordered by severity.
- Whether the screen answers: "Can I safely work here?"
- Missing evidence, missing blocked state, or missing receipt.
- Copy changes needed for precise, non-panicky safety language.
- Acceptance criteria before the UI can ship.

## Checklist

- Show causes, not just statuses.
- Show evidence before action: Git freshness, env availability, ignored paths, queue preview, tombstones, conflicts, and hydration state.
- Make destructive actions visibly blocked or approval-gated.
- Separate preview from apply.
- Include closeout receipts that say what changed and what did not happen.
- Avoid vague labels such as "ready", "synced", "safe", or "healthy" unless evidence supports them.
- Make agent handoff constraints visible before starting work.

## Examples

- "Conflict Center route" -> require side-by-side object evidence, preview-only resolution, and a receipt state.
- "Hydration Center" -> require visible lazy/simulated state and no copy implying files were fetched.
- "Dashboard" -> require readiness causes and blocked next steps instead of generic metric cards.

## Failure Modes

- User cannot tell whether local files are about to change.
- User sees a confident recommendation without evidence.
- A dangerous action looks like a normal primary button.
- Closeout copy claims sync completed when only a stub ran.
- Agent handoff hides env or stale-base blockers.
