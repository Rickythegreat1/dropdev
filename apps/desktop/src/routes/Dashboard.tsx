const evidenceRows = [
  "Registry contract exists; no local database has been opened yet.",
  "BLAKE3 is the default content hash; SHA-256 remains modeled for compatibility.",
  "Snapshot, queue, hydration, tombstone, conflict, and handoff actions are preview-only.",
  "Env profiles show key names and fingerprints, never raw values."
];

export function Dashboard() {
  return (
    <section className="surface" aria-labelledby="dashboard-title">
      <div className="pageHeader">
        <p className="eyebrow">Slice 0/1</p>
        <h2 id="dashboard-title">Readiness before movement</h2>
        <p>
          DevDrop is being assembled as a local-first workspace control surface. This
          foundation can explain contracts and blocked actions, but it cannot sync,
          delete, overwrite, dehydrate, or mutate Git state.
        </p>
      </div>

      <div className="workbench">
        <section className="inspectionPane" aria-labelledby="evidence-title">
          <h3 id="evidence-title">Evidence rail</h3>
          <ul>
            {evidenceRows.map((row) => (
              <li key={row}>{row}</li>
            ))}
          </ul>
        </section>

        <section className="topologyPane" aria-labelledby="topology-title">
          <h3 id="topology-title">Machine topology placeholder</h3>
          <div className="mapLine">
            <span className="node current">This machine</span>
            <span className="track" />
            <span className="node future">Future peer</span>
          </div>
          <p>
            The map is spatial on purpose: future states must show which machine has
            which workspace evidence before asking the user to trust a plan.
          </p>
        </section>

        <section className="actionPane" aria-labelledby="action-title">
          <h3 id="action-title">Next safe action</h3>
          <p>
            Run the CLI doctor or open the project detail placeholder. Both routes
            describe what is not allowed yet.
          </p>
          <button type="button" disabled>
            Apply sync unavailable in Slice 0/1
          </button>
        </section>
      </div>
    </section>
  );
}

