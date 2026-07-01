export type EvalGate = {
  id: string;
  expectation: string;
};

export const foundationEvalGates: EvalGate[] = [
  {
    id: "env-values-redacted",
    expectation: "Env profile outputs contain key names and fingerprints only."
  },
  {
    id: "generated-paths-excluded",
    expectation: "Generated paths never enter CAS planning."
  },
  {
    id: "dangerous-actions-dry-run",
    expectation: "Snapshot, hydrate, tombstone, conflict, queue, and handoff actions do not mutate files."
  },
  {
    id: "ux-redteam-required",
    expectation: "UI surfaces are checked against the DevDrop red-team rubric."
  },
  {
    id: "codex-automation-safe",
    expectation:
      "Codex MCP schemas are dry-run/read-only and hooks remain disabled until trusted."
  }
];
