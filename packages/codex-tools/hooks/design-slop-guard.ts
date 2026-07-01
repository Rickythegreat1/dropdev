import type { DevDropHookDefinition } from "./secret-output-guard";

export const designSlopGuard = {
  name: "design-slop-guard",
  enabled: false,
  trusted: false,
  autoEnabled: false,
  mode: "dry-run",
  blocksByDefault: false,
  purpose:
    "Future critique guard for generic AI-dashboard design, vague status language, default component sameness, and decorative noise.",
  observes: [
    "route shells",
    "design-system components",
    "empty states",
    "warning states",
    "workflow copy"
  ],
  doesNot: [
    "block UI changes automatically",
    "replace UX review",
    "write UI files",
    "generate visuals"
  ]
} as const satisfies DevDropHookDefinition;
