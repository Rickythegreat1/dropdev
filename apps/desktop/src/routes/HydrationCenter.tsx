const hydrationRows = [
  {
    path: "src/stub.txt",
    state: "stub",
    evidence: "Exact DevDrop marker, sandbox-only preview available."
  },
  {
    path: "src/already-hydrated.txt",
    state: "hydrated",
    evidence: "Fixture object hash matches expected source."
  },
  {
    path: "src/dirty-local.txt",
    state: "dirty-local",
    evidence: "Local bytes do not match the stub marker or source hash."
  },
  {
    path: "node_modules/pkg/index.js",
    state: "ignored",
    evidence: "Generated dependency path is excluded before hydration."
  },
  {
    path: "src/conflicted.txt",
    state: "conflict",
    evidence: "Conflict state blocks all hydration apply behavior."
  }
];

export function HydrationCenter() {
  return (
    <section className="surface" aria-labelledby="hydration-title">
      <div className="pageHeader">
        <p className="eyebrow">Hydration Center</p>
        <h2 id="hydration-title">Stub replacement stays inside the sandbox</h2>
        <p>
          This view shows the lazy hydration simulation boundary. Desktop can inspect
          states and preview causes, but apply remains a CLI-only test sandbox action.
        </p>
      </div>

      <div className="hydrationBench">
        <section className="hydrationTree" aria-label="Hydration state tree">
          {hydrationRows.map((row) => (
            <button className="hydrationRow" key={row.path} type="button">
              <span className={`stateGlyph state-${row.state}`} aria-hidden="true" />
              <span>
                <strong>{row.path}</strong>
                <small>{row.evidence}</small>
              </span>
              <code>{row.state}</code>
            </button>
          ))}
        </section>

        <section className="hydrationPreview" aria-labelledby="preview-title">
          <p className="eyebrow">Preview evidence</p>
          <h3 id="preview-title">src/stub.txt</h3>
          <dl>
            <div>
              <dt>Source object</dt>
              <dd>object_alpha</dd>
            </div>
            <div>
              <dt>Target state</dt>
              <dd>Exact stub marker</dd>
            </div>
            <div>
              <dt>Risk</dt>
              <dd>Write blocked outside a recognized temp test sandbox.</dd>
            </div>
          </dl>
          <p className="warningCopy">
            Dirty local files, conflicts, ignored paths, secret paths, symlinks, stale
            previews, and missing objects block hydration before any write is attempted.
          </p>
          <button type="button" disabled>
            Apply is CLI-only in a test sandbox
          </button>
        </section>
      </div>
    </section>
  );
}
