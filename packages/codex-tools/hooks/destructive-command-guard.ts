import type { DevDropHookDefinition } from "./secret-output-guard";

export const destructiveCommandGuard = {
  name: "destructive-command-guard",
  enabled: false,
  trusted: false,
  autoEnabled: false,
  mode: "dry-run",
  blocksByDefault: false,
  purpose:
    "Future guard for requiring preview, explicit approval, rollback notes, and fixture tests before destructive actions.",
  observes: [
    "delete commands",
    "overwrite commands",
    "move commands",
    "sync apply",
    "hydrate apply",
    "Git mutation"
  ],
  doesNot: [
    "approve destructive actions",
    "execute commands",
    "mutate files",
    "mutate Git state"
  ]
} as const satisfies DevDropHookDefinition;
