import * as React from "react";
import { Dashboard } from "../routes/Dashboard";
import { HydrationCenter } from "../routes/HydrationCenter";
import { RouteShell } from "../routes/RouteShell";

type Route = {
  id: string;
  label: string;
  intent: string;
};

const routes: Route[] = [
  {
    id: "first-launch",
    label: "First Launch",
    intent: "Add a project and run the first non-mutating readiness pass."
  },
  {
    id: "dashboard",
    label: "Dashboard",
    intent: "See evidence, blocked risk, and next safe action without metric theater."
  },
  {
    id: "project-detail",
    label: "Project Detail",
    intent: "Inspect registry, readiness, Git freshness, env profile shape, and ignore policy."
  },
  {
    id: "machine-map",
    label: "Machine Map",
    intent: "Understand workspace topology across machines before acting."
  },
  {
    id: "hydration-center",
    label: "Hydration Center",
    intent: "Simulate lazy hydration without writing files."
  },
  {
    id: "sync-queue",
    label: "Sync Queue",
    intent: "Preview queued sync semantics while apply remains unavailable."
  },
  {
    id: "conflict-center",
    label: "Conflict Center",
    intent: "Compare conflict objects before any resolution is possible."
  },
  {
    id: "env-profiles",
    label: "Env Profiles",
    intent: "Show env readiness using key names and fingerprints only."
  },
  {
    id: "agent-handoff",
    label: "Agent Handoff",
    intent: "Prepare redacted Codex context and blocked-action notes."
  },
  {
    id: "design-system-preview",
    label: "Design System Preview",
    intent: "Audit tactile surfaces against DevDrop aesthetic rules."
  }
];

export function App() {
  const [activeRoute, setActiveRoute] = React.useState("dashboard");
  const route = routes.find((item) => item.id === activeRoute) ?? routes[1];

  return (
    <main className="appShell">
      <aside className="rail" aria-label="DevDrop routes">
        <div className="brandBlock">
          <span className="brandMark" aria-hidden="true" />
          <div>
            <p className="eyebrow">DevDrop</p>
            <h1>Workspace control surface</h1>
          </div>
        </div>
        <nav className="routeList">
          {routes.map((item) => (
            <button
              className={item.id === activeRoute ? "routeButton active" : "routeButton"}
              key={item.id}
              onClick={() => setActiveRoute(item.id)}
              type="button"
            >
              {item.label}
            </button>
          ))}
        </nav>
      </aside>
      {route.id === "dashboard" ? (
        <Dashboard />
      ) : route.id === "hydration-center" ? (
        <HydrationCenter />
      ) : (
        <RouteShell title={route.label} intent={route.intent} />
      )}
    </main>
  );
}
