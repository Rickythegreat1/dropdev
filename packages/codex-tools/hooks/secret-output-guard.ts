export type DevDropHookDefinition = {
  name: string;
  enabled: false;
  trusted: false;
  autoEnabled: false;
  mode: "dry-run";
  blocksByDefault: false;
  purpose: string;
  observes: string[];
  doesNot: string[];
};

export const secretOutputGuard = {
  name: "secret-output-guard",
  enabled: false,
  trusted: false,
  autoEnabled: false,
  mode: "dry-run",
  blocksByDefault: false,
  purpose:
    "Future guard for preventing raw env values, raw file text, or secret-like values from reaching Codex output.",
  observes: ["planned output", "handoff JSON", "MCP responses"],
  doesNot: [
    "read env files",
    "read file text",
    "mutate output",
    "block commands automatically"
  ]
} as const satisfies DevDropHookDefinition;
