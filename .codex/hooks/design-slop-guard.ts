export type HookResult = {
  name: "design-slop-guard";
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
    name: "design-slop-guard",
    enabled: false,
    trusted: false,
    autoEnabled: false,
    mode: "dry-run",
    wouldBlock: false,
    inspectedSignals: [
      "default shadcn sameness",
      "fake glassmorphism",
      "meaningless metric cards",
      "purple blue AI gradients",
      "vague status pills"
    ],
    message:
      "Design slop guard is a dry-run critique hook; it is not trusted or auto-enabled yet.",
    limitations: [
      "Does not block UI changes automatically.",
      "Does not replace UX or aesthetic red-team review.",
      "Does not write, patch, or generate UI files."
    ]
  };
}
