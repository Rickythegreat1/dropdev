import { invoke } from "@tauri-apps/api/core";

export type Pair = { id: string; name: string; source: string; target: string };
export type Operation = {
  side?: "source" | "target";
  path: string;
  kind: "copy" | "replace" | "delete" | "conflict";
  before: string | null;
  after: string | null;
};
export type Plan = {
  id: string;
  pair_id: string;
  operations: Operation[];
  state: string;
  blockers: string[];
  source_scan?: Record<string, string>;
  target_scan?: Record<string, string>;
  rollback_of?: string;
  reverses?: string | null;
};
export type Event = {
  id?: number | string;
  kind?: string;
  plan_id?: string;
  state?: string;
  message?: string;
  evidence?: {
    path?: string;
    side?: "source" | "target";
    recovery_directory?: string;
    before?: string | null;
  };
};
export type Registry = { pairs: Pair[]; plans: Plan[]; events: Event[] };
export type Receipt = {
  plan_id: string;
  state: string;
  changed: string[];
  message: string;
};
export type Request = { action: string; [key: string]: unknown };
export const native =
  typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
const STORE = "devdrop-disposable-demo-v1";
type Demo = Registry & {
  revision: number;
  source: Record<string, string>;
  target: Record<string, string>;
  baseline: Record<string, string>;
  before: Record<string, Record<string, string>>;
};
const fresh = (): Demo => ({
  pairs: [
    {
      id: "demo-pair",
      name: "Field notes",
      source: "disposable/source",
      target: "disposable/replica",
    },
  ],
  plans: [],
  events: [],
  revision: 1,
  source: { "README.md": "demo-readme-v1", "src/notes.ts": "demo-notes-v1" },
  target: {},
  baseline: {},
  before: {},
});
function load(): Demo {
  try {
    const stored = localStorage.getItem(STORE);
    if (stored) {
      const data = JSON.parse(stored) as Demo;
      if (
        Array.isArray(data.pairs) &&
        Array.isArray(data.plans) &&
        Array.isArray(data.events) &&
        data.source &&
        data.target &&
        data.baseline &&
        data.before &&
        Number.isFinite(data.revision)
      )
        return data;
    }
  } catch {
    /* An unavailable browser store must not block the demo. */
  }
  return fresh();
}
function save(state: Demo) {
  try {
    localStorage.setItem(STORE, JSON.stringify(state));
  } catch {
    /* Session still works if persistence is denied. */
  }
}
let session = load();
export function resetDemo() {
  session = fresh();
  save(session);
}
function same(a: unknown, b: unknown) {
  return JSON.stringify(a) === JSON.stringify(b);
}
function event(state: Demo, kind: string, plan_id?: string) {
  state.events.push({ id: state.events.length + 1, kind, plan_id });
}
export async function command<T>(request: Request): Promise<T> {
  if (native) return invoke<T>("local_command", { request });
  const d = session;
  let result: unknown;
  switch (request.action) {
    case "list":
      result = {
        pairs: d.pairs,
        plans: [...d.plans].reverse(),
        events: [...d.events].reverse(),
      };
      break;
    case "events":
      result = d.events;
      break;
    case "register":
      throw new Error(
        "Folder registration requires the desktop app. The browser demo uses disposable virtual folders.",
      );
    case "preview": {
      if (!d.pairs.some((p) => p.id === request.pair_id))
        throw new Error("Unknown pair.");
      const paths = [
        ...new Set([
          ...Object.keys(d.source),
          ...Object.keys(d.target),
          ...Object.keys(d.baseline),
        ]),
      ].sort();
      const operations: Operation[] = paths.flatMap((path) => {
        const after = d.source[path] ?? null,
          before = d.target[path] ?? null,
          base = d.baseline[path] ?? null;
        if (after === before) return [];
        const kind =
          before !== base
            ? "conflict"
            : after === null
              ? "delete"
              : before === null
                ? "copy"
                : "replace";
        return [{ path, kind, before, after }];
      });
      const plan: Plan = {
        id: `demo-plan-${++d.revision}`,
        pair_id: String(request.pair_id),
        operations,
        state: "planned",
        blockers: operations.some((o) => o.kind === "conflict")
          ? [
              "Replica differs from its last approved baseline. Both versions are preserved.",
            ]
          : [],
        source_scan: { ...d.source },
        target_scan: { ...d.target },
      };
      d.plans.push(plan);
      event(d, "planned", plan.id);
      result = plan;
      break;
    }
    case "rollback_preview": {
      const original = d.plans.find((p) => p.id === request.plan_id);
      if (!original || original.state !== "verified" || !d.before[original.id])
        throw new Error("Choose a verified apply receipt to preview recovery.");
      const after = d.before[original.id];
      const operations: Operation[] = [
        ...new Set([...Object.keys(d.target), ...Object.keys(after)]),
      ]
        .sort()
        .flatMap((path) => {
          const beforeHash = d.target[path] ?? null,
            afterHash = after[path] ?? null;
          if (beforeHash === afterHash) return [];
          return [
            {
              path,
              kind:
                afterHash === null
                  ? "delete"
                  : beforeHash === null
                    ? "copy"
                    : "replace",
              before: beforeHash,
              after: afterHash,
            },
          ];
        });
      const plan: Plan = {
        id: `demo-undo-${++d.revision}`,
        pair_id: original.pair_id,
        operations,
        blockers: [],
        state: "planned",
        source_scan: { ...d.source },
        target_scan: { ...d.target },
        rollback_of: original.id,
      };
      d.plans.push(plan);
      event(d, "rollback_planned", plan.id);
      result = plan;
      break;
    }
    case "apply":
    case "rollback": {
      const plan = d.plans.find((p) => p.id === request.plan_id);
      if (!plan || request.approval !== plan.id)
        throw new Error("Explicit approval must match this plan ID.");
      if (plan.state === "verified") {
        result = {
          plan_id: plan.id,
          state: "verified",
          changed: [],
          message: "This demo plan was already applied. No additional changes.",
        };
        break;
      }
      if (plan.blockers.length)
        throw new Error(
          "Unresolved conflicts block apply. Both versions remain preserved.",
        );
      if (
        !same(plan.source_scan, d.source) ||
        !same(plan.target_scan, d.target)
      )
        throw new Error(
          "Stale plan: virtual folders changed. Build a fresh preview.",
        );
      d.before[plan.id] = { ...d.target };
      plan.operations.forEach((o) => {
        if (o.after === null) delete d.target[o.path];
        else d.target[o.path] = o.after;
      });
      d.baseline = { ...d.target };
      plan.state = "verified";
      event(d, "verified", plan.id);
      result = {
        plan_id: plan.id,
        state: "verified",
        changed: plan.operations.map((o) => o.path),
        message: "Virtual replica updated. No device files were accessed.",
      };
      break;
    }
    case "demo_edit":
      d.source["src/notes.ts"] = `demo-notes-v${++d.revision}`;
      event(d, "virtual_source_edited");
      result = {};
      break;
    case "demo_conflict":
      d.source["src/notes.ts"] = `demo-source-v${++d.revision}`;
      d.target["src/notes.ts"] = `demo-replica-v${d.revision}`;
      event(d, "virtual_both_sides_edited");
      result = {};
      break;
    case "handoff":
      result = {
        project_id: request.pair_id,
        allowed_files: Object.keys(d.source),
        forbidden_files: [".env*", "node_modules/**", ".git/**"],
        blockers: d.plans.filter((p) => p.blockers.length).map((p) => p.id),
        file_contents_included: false,
        environment_values_included: false,
        machine_paths_included: false,
        workspace_creation: "blocked until readiness evidence is reviewed",
      };
      break;
    default:
      throw new Error("Unsupported action.");
  }
  save(d);
  return JSON.parse(JSON.stringify(result)) as T;
}
