export type HookResult = {
  name: "destructive-command-guard";
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
    name: "destructive-command-guard",
    enabled: false,
    trusted: false,
    autoEnabled: false,
    mode: "dry-run",
    wouldBlock: false,
    inspectedSignals: [
      "delete",
      "overwrite",
      "move",
      "sync apply",
      "hydrate apply",
      "git mutation"
    ],
    message:
      "Destructive command guard is documented but inert; DevDrop destructive actions remain unavailable.",
    limitations: [
      "Does not intercept commands in Slice 0/1.",
      "Does not approve destructive behavior.",
      "Does not mutate user files, Git state, metadata, or object storage."
    ]
  };
}
