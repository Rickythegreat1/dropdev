export type HookResult = {
  name: "secret-output-guard";
  enabled: false;
  trusted: false;
  autoEnabled: false;
  mode: "dry-run";
  wouldBlock: false;
  inspectedSignals: string[];
  message: string;
  limitations: string[];
};

export function run(): HookResult {
  return {
    name: "secret-output-guard",
    enabled: false,
    trusted: false,
    autoEnabled: false,
    mode: "dry-run",
    wouldBlock: false,
    inspectedSignals: ["planned-output", "handoff-json", "mcp-response"],
    message:
      "Secret output guard is present for future review but is not trusted or auto-enabled yet.",
    limitations: [
      "Does not inspect live Codex output in Slice 0/1.",
      "Does not read env files or file contents.",
      "Does not mutate, redact, block, or write anything."
    ]
  };
}
