# UX Principles

DevDrop is a workspace control surface, not a generic AI dashboard. The user
should feel that every recommendation is anchored to inspectable evidence and
that every risky action is deliberately slowed down until it has a preview,
approval, rollback notes, and tests.

## Principles

1. Evidence before action. Show what DevDrop knows, what it does not know, and
   which fixture or scan produced the claim.
2. Local-first clarity. Make it obvious that Slice 0/1 does not sync, delete,
   overwrite, hydrate, mutate Git, or write metadata.
3. Machine topology matters. Show projects in relation to machines and workspace
   roots instead of flattening everything into a table of generic statuses.
4. Secrets are shaped, not shown. Env profiles may reveal file presence, key
   names, and fingerprints, but never raw values.
5. Generated paths are visible exclusions. Users should be able to inspect why
   `node_modules`, `.next`, `dist`, `target`, logs, and `*.log` are excluded.
6. Agent handoff is a contract. Codex receives readiness, queue, conflict,
   tombstone, and redaction evidence, not raw file contents.
7. Receipts matter. Every preview or stubbed command should say what happened,
   what did not happen, and what must exist before real apply can be built.

## Relationship To UX Plan

`docs/ux-plan.md` contains the expanded 35-state design inventory. This file is
the shorter principle layer that future UI work should check before design
red-team review.

