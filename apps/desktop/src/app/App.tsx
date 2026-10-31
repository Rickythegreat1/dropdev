import * as React from "react";
import {
  command,
  native,
  resetDemo,
  type Registry,
  type Pair,
  type Plan,
  type Receipt,
  type Operation,
} from "../data/client";

const routes = [
  ["dashboard", "Overview"],
  ["first-launch", "Add project"],
  ["project-detail", "Project evidence"],
  ["machine-map", "Folder map"],
  ["sync-queue", "Sync queue"],
  ["conflict-center", "Conflicts"],
  ["hydration-center", "Object store"],
  ["env-profiles", "Environment"],
  ["agent-handoff", "Agent handoff"],
  ["recovery", "Activity & recovery"],
];
const empty: Registry = { pairs: [], plans: [], events: [] };
const hash = (value: string | null) =>
  value ? (value.length > 24 ? `${value.slice(0, 16)}…` : value) : "Absent";

export function App() {
  const [route, setRoute] = React.useState("dashboard");
  const [data, setData] = React.useState<Registry>(empty);
  const [pairId, setPairId] = React.useState("");
  const [preview, setPreview] = React.useState<Plan | null>(null);
  const [receipt, setReceipt] = React.useState<Receipt | null>(null);
  const [approval, setApproval] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [handoff, setHandoff] = React.useState<unknown>(null);
  const [registration, setRegistration] = React.useState({
    name: "",
    source: "",
    target: "",
  });
  const gate = React.useRef(false);
  const pair = data.pairs.find((p) => p.id === pairId) ?? data.pairs[0];
  const latest = data.plans.find((p) => p.pair_id === pair?.id);
  const conflicts =
    latest?.operations.filter((o) => o.kind === "conflict") ?? [];
  const refresh = async () => {
    const state = await command<Registry>({ action: "list" });
    setData({
      pairs: state.pairs ?? [],
      plans: state.plans ?? [],
      events: state.events ?? [],
    });
  };
  React.useEffect(() => {
    refresh().catch(() =>
      setError("Local state could not be loaded. Reopen the app to retry."),
    );
  }, []);
  async function run(work: () => Promise<void>) {
    if (gate.current) return;
    gate.current = true;
    setBusy(true);
    setError("");
    try {
      await work();
      await refresh();
    } catch (e) {
      setError(
        typeof e === "string"
          ? e
          : e instanceof Error
            ? e.message
            : "Operation failed. Refresh evidence and retry.",
      );
    } finally {
      gate.current = false;
      setBusy(false);
    }
  }
  function selectPair(id: string) {
    setPairId(id);
    setPreview(null);
    setReceipt(null);
    setApproval(false);
    setHandoff(null);
  }
  async function buildPreview() {
    if (!pair) return;
    await run(async () => {
      setReceipt(null);
      setApproval(false);
      setPreview(await command<Plan>({ action: "preview", pair_id: pair.id }));
      setRoute("sync-queue");
    });
  }
  const readyToApply =
    preview &&
    preview.state === "planned" &&
    !preview.blockers.length &&
    !preview.operations.some((o) => o.kind === "conflict");
  return (
    <main className="appShell">
      <aside className="rail" aria-label="DevDrop navigation">
        <a
          className="brandBlock"
          href="#"
          onClick={(e) => {
            e.preventDefault();
            setRoute("dashboard");
          }}
        >
          <span className="brandMark" aria-hidden="true" />
          <div>
            <p className="eyebrow">DevDrop</p>
            <h1>
              Keep your work
              <br />
              within reach.
            </h1>
          </div>
        </a>
        <p className="railCaption">LOCAL WORKSPACE CONTROL</p>
        <nav className="routeList">
          {routes.map(([id, label]) => (
            <button
              key={id}
              className={`routeButton ${route === id ? "active" : ""}`}
              aria-current={route === id ? "page" : undefined}
              onClick={() => setRoute(id)}
            >
              {label}
            </button>
          ))}
        </nav>
        <div className="railFooter">
          <span className="connectionDot" />
          {native ? "Local Rust engine" : "Interactive browser demo"}
          <small>
            {native
              ? "Your files stay on this device."
              : "Virtual folders. No device file access."}
          </small>
        </div>
      </aside>
      <section className="workspace">
        <header className="topbar">
          <span>{native ? "THIS DEVICE" : "DISPOSABLE DEMO"}</span>
          <label className="projectSelect">
            Project{" "}
            <select
              aria-label="Selected project"
              value={pair?.id ?? ""}
              onChange={(e) => selectPair(e.target.value)}
            >
              {!data.pairs.length && <option value="">No projects</option>}
              {data.pairs.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
          <button
            className="quiet"
            disabled={busy}
            onClick={() => run(refresh)}
          >
            Refresh evidence
          </button>
        </header>
        <div className="betaBanner" role="note" aria-label="Beta safety limit">
          <strong>Experimental beta — disposable project copies only.</strong>{" "}
          Never register or sync primary working trees. Replacement and rollback
          copy content only; file permissions and executable bits are not
          preserved.
        </div>
        {!native && (
          <div className="demoBanner">
            <strong>Try the workflow.</strong> This browser demo updates virtual
            folders only. Desktop beta setup is for disposable project copies
            only.{" "}
            <a
              href="https://github.com/Rickythegreat1/dropdev#readme"
              target="_blank"
              rel="noreferrer"
            >
              Desktop setup
            </a>
          </div>
        )}
        <div className="surface" aria-busy={busy}>
          {error && (
            <div className="errorNotice" role="alert">
              <strong>Action stopped</strong>
              <p>{error}</p>
              <span>
                Your next step: refresh evidence and create a new preview.
              </span>
            </div>
          )}
          {receipt && (
            <div className="receipt" role="status">
              <strong>
                {native ? "Apply receipt" : "Demo receipt"} · {receipt.state}
              </strong>
              <p>{receipt.message}</p>
              <code>{receipt.plan_id}</code>
              <span>{receipt.changed.length} paths changed</span>
            </div>
          )}
          {route === "dashboard" && (
            <>
              <PageHeader
                eyebrow="Workspace overview"
                title="Know what moves. Keep what matters."
                description="Compare the source and replica, inspect every change, then approve a specific plan. Local edits and unresolved conflicts stop apply."
              />
              <div className="heroWorkbench">
                <section className="inspectionPane">
                  <p className="eyebrow">Active workspace</p>
                  <h3 className="projectTitle">
                    {pair?.name ?? "Start with two folders"}
                  </h3>
                  {pair ? (
                    <>
                      <FolderMapping pair={pair} />
                      <p className="muted">
                        Source → replica · one-way, approved sync
                      </p>
                    </>
                  ) : (
                    <p>
                      Add an existing source and a separate replica folder to
                      begin.
                    </p>
                  )}
                  <button
                    className="primary"
                    disabled={busy || !pair}
                    onClick={buildPreview}
                  >
                    {busy ? "Reading evidence…" : "Scan & preview changes"}
                  </button>
                </section>
                <section className="evidenceRail">
                  <p className="eyebrow">Before you work</p>
                  <Evidence
                    title={
                      latest
                        ? `Latest plan: ${latest.state}`
                        : "No scan evidence yet"
                    }
                    text={
                      latest
                        ? `${latest.operations.length} planned paths. Scan again whenever folders change.`
                        : "A new reconciliation scan establishes the next exact preview."
                    }
                  />
                  <Evidence
                    title={
                      conflicts.length
                        ? `${conflicts.length} conflicts need attention`
                        : "Conflict protection enabled"
                    }
                    text="Replica changes are preserved. Divergent versions block apply."
                  />
                  <Evidence
                    title="Secrets and generated files stay out"
                    text="Environment values, Git internals and dependency trees are excluded from content storage."
                  />
                </section>
              </div>
              {!native && (
                <DemoTools
                  busy={busy}
                  run={run}
                  invalidate={() => {
                    setPreview(null);
                    setApproval(false);
                  }}
                />
              )}
            </>
          )}
          {route === "first-launch" && (
            <>
              <PageHeader
                eyebrow="Project registry"
                title="Give two folders a shared reference."
                description="Choose a source and a separate replica. Registration records their locations; it does not sync their contents."
              />
              {native ? (
                <form
                  className="registration inspectionPane"
                  onSubmit={(e) => {
                    e.preventDefault();
                    run(async () => {
                      const p = await command<Pair>({
                        action: "register",
                        ...registration,
                      });
                      selectPair(p.id);
                      setRoute("project-detail");
                    });
                  }}
                >
                  <label>
                    Project name
                    <input
                      required
                      maxLength={80}
                      value={registration.name}
                      onChange={(e) =>
                        setRegistration({
                          ...registration,
                          name: e.target.value,
                        })
                      }
                    />
                  </label>
                  <label>
                    Source folder
                    <input
                      required
                      placeholder="Absolute folder path"
                      value={registration.source}
                      onChange={(e) =>
                        setRegistration({
                          ...registration,
                          source: e.target.value,
                        })
                      }
                    />
                  </label>
                  <label>
                    Replica folder
                    <input
                      required
                      placeholder="Separate absolute folder path"
                      value={registration.target}
                      onChange={(e) =>
                        setRegistration({
                          ...registration,
                          target: e.target.value,
                        })
                      }
                    />
                  </label>
                  <p className="muted">
                    Folders must exist, be separate and contain no symlink
                    roots. Both folders must be disposable project copies, never
                    primary working trees.
                  </p>
                  <button className="primary" disabled={busy}>
                    Register folder pair
                  </button>
                </form>
              ) : (
                <section className="inspectionPane">
                  <h3>A disposable pair is ready</h3>
                  <p>
                    The browser cannot register device folders. Use Field notes
                    to explore preview, approval, conflicts and recovery.
                  </p>
                  <button
                    className="primary"
                    onClick={() => setRoute("dashboard")}
                  >
                    Open demo workspace
                  </button>
                </section>
              )}
            </>
          )}
          {route === "project-detail" && (
            <>
              <PageHeader
                eyebrow="Project evidence"
                title={pair?.name ?? "No project selected"}
                description="Folder mappings and scan evidence are local observations. They do not establish remote trust or continuous synchronization."
              />
              {pair && (
                <section className="inspectionPane">
                  <FolderMapping pair={pair} />
                  <dl className="evidenceGrid">
                    <div>
                      <dt>Registry identity</dt>
                      <dd>
                        <code>{pair.id}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>Latest recorded plan</dt>
                      <dd>
                        {latest ? (
                          <code>
                            {latest.id} · {latest.state}
                          </code>
                        ) : (
                          "No preview yet"
                        )}
                      </dd>
                    </div>
                    <div>
                      <dt>Git behavior</dt>
                      <dd>Git directories excluded. No Git mutation.</dd>
                    </div>
                    <div>
                      <dt>Direction</dt>
                      <dd>Source → replica; no automatic peer transport.</dd>
                    </div>
                  </dl>
                  <button
                    className="primary"
                    disabled={busy}
                    onClick={buildPreview}
                  >
                    Scan & preview changes
                  </button>
                </section>
              )}
              {latest && <OperationTable operations={latest.operations} />}
            </>
          )}
          {route === "machine-map" && (
            <>
              <PageHeader
                eyebrow="Folder map"
                title="Two roots. One visible direction."
                description="Each registered pair runs on this device. Network peer sync is not connected; no machine or hostname is inferred."
              />
              {data.pairs.map((p) => (
                <section key={p.id} className="inspectionPane folderMap">
                  <h3>{p.name}</h3>
                  <FolderMapping pair={p} />
                  <p className="muted">
                    Local device · source → replica · changes require preview
                    and approval
                  </p>
                </section>
              ))}
            </>
          )}
          {route === "sync-queue" && (
            <>
              <PageHeader
                eyebrow="Sync queue"
                title="Inspect the change before the click."
                description="The preview names every eligible path. Approval is bound to this plan; a fresh scan is required if either folder changes."
              />
              <div className="toolbar">
                <button
                  className="primary"
                  disabled={busy || !pair}
                  onClick={buildPreview}
                >
                  Build fresh preview
                </button>
                <span className="muted">
                  {preview
                    ? `${preview.operations.length} paths in this preview`
                    : "No preview selected"}
                </span>
              </div>
              {preview ? (
                <>
                  <div className="planIdentity">
                    <code>{preview.id}</code>
                    <span>
                      {preview.rollback_of || preview.reverses
                        ? `Recovery of ${preview.rollback_of || preview.reverses}`
                        : "Source → replica"}
                    </span>
                    <span>{preview.state}</span>
                  </div>
                  <OperationTable operations={preview.operations} />
                  {preview.blockers.map((b, i) => (
                    <p key={i} className="warningCopy">
                      {typeof b === "string" ? b : JSON.stringify(b)}
                    </p>
                  ))}
                  <section className="approvalWall">
                    <p className="eyebrow">Explicit approval</p>
                    <h3>
                      {preview.rollback_of || preview.reverses
                        ? "Approve recovery of this exact plan"
                        : "Approve this exact preview"}
                    </h3>
                    <p>
                      Replacement and deletion operations preserve recovery
                      objects. Conflicts block this plan. Stop editors and other
                      sync tools while applying.
                    </p>
                    <label className="checkbox">
                      <input
                        type="checkbox"
                        checked={approval}
                        disabled={!readyToApply || busy}
                        onChange={(e) => setApproval(e.target.checked)}
                      />
                      I reviewed all paths in <code>{preview.id}</code> and
                      confirm these are disposable copies, never primary working
                      trees. I understand beta replacement and rollback do not
                      preserve file permissions or executable bits.
                    </label>
                    <button
                      className="primary"
                      disabled={!readyToApply || !approval || busy}
                      onClick={() =>
                        run(async () => {
                          const r = await command<Receipt>({
                            action: "apply",
                            plan_id: preview.id,
                            approval: preview.id,
                            disposable_copies: approval,
                          });
                          setReceipt(r);
                          setApproval(false);
                          setPreview({ ...preview, state: r.state });
                        })
                      }
                    >
                      {busy
                        ? "Applying…"
                        : native
                          ? "Apply approved plan"
                          : "Apply to virtual replica"}
                    </button>
                  </section>
                </>
              ) : (
                <Empty
                  title="Start with a reconciliation scan"
                  text="Build a preview to see copies, replacements, tombstones and preserved conflicts."
                />
              )}
            </>
          )}
          {route === "conflict-center" && (
            <>
              <PageHeader
                eyebrow="Conflict center"
                title="Both versions deserve to survive."
                description="A replica change since the last baseline is preserved. DevDrop will not choose a winner or overwrite it silently."
              />
              {conflicts.length ? (
                <>
                  <OperationTable operations={conflicts} />
                  <section className="warningCopy">
                    <h3>Resolution requires your review</h3>
                    <p>
                      Review both versions in your editor, then preview a
                      resolution. Nothing changes until you approve the
                      resulting exact plan. “Preserve both” keeps a conflict
                      sibling and aligns the original path.
                    </p>
                    {native &&
                      conflicts.map((o) => (
                        <div key={o.path} className="toolbar">
                          <code>{o.path}</code>
                          {(["source", "target", "both"] as const).map(
                            (choice) => (
                              <button
                                key={choice}
                                disabled={busy}
                                onClick={() =>
                                  run(async () => {
                                    setPreview(
                                      await command<Plan>({
                                        action: "resolve_preview",
                                        pair_id: pair?.id,
                                        path: o.path,
                                        choice,
                                      }),
                                    );
                                    setApproval(false);
                                    setReceipt(null);
                                    setRoute("sync-queue");
                                  })
                                }
                              >
                                Preview{" "}
                                {choice === "both"
                                  ? "preserve both"
                                  : `keep ${choice}`}
                              </button>
                            ),
                          )}
                        </div>
                      ))}
                  </section>
                </>
              ) : (
                <Empty
                  title="No conflicts in the latest preview"
                  text="This only reflects the recorded scan. Run a fresh preview to check the current folders."
                />
              )}
              <button disabled={busy || !pair} onClick={buildPreview}>
                Check with a fresh scan
              </button>
              {!native && (
                <DemoTools
                  busy={busy}
                  run={run}
                  invalidate={() => {
                    setPreview(null);
                    setApproval(false);
                  }}
                />
              )}
            </>
          )}
          {route === "hydration-center" && (
            <>
              <PageHeader
                eyebrow="Object store"
                title="Content with a recoverable reference."
                description="Eligible source and replica bytes are stored locally by BLAKE3 identity during planning. File text is never displayed in this control surface."
              />
              <section className="inspectionPane">
                <Evidence
                  title="Recovery objects"
                  text="Replacement and deletion previews retain the prior object reference so approved recovery can restore it."
                />
                <Evidence
                  title="Secret and generated paths excluded"
                  text="Secret filenames, dependency trees, Git internals and unsupported symlinks do not enter normal content storage."
                />
                <Evidence
                  title="Lazy hydration stays a sandbox simulation"
                  text="The CLI fixture workflow can preview hydration inside recognized disposable sandboxes. This desktop route does not download files or replace live stubs."
                />
              </section>
              {latest && <OperationTable operations={latest.operations} />}
            </>
          )}
          {route === "env-profiles" && (
            <>
              <PageHeader
                eyebrow="Environment"
                title="Availability without exposure."
                description="Secret files are excluded before content reads. DevDrop does not collect, display, transport or install environment values."
              />
              <section className="inspectionPane">
                <dl className="evidenceGrid">
                  <div>
                    <dt>Default secret boundary</dt>
                    <dd>
                      <code>.env · .env.* · credentials · private keys</code>
                    </dd>
                  </div>
                  <div>
                    <dt>Availability evidence</dt>
                    <dd>Not collected by this folder-sync workflow.</dd>
                  </div>
                  <div>
                    <dt>Agent readiness</dt>
                    <dd>
                      Review required runtime and env setup locally before an
                      agent starts.
                    </dd>
                  </div>
                  <div>
                    <dt>Generated content</dt>
                    <dd>
                      <code>node_modules · target · dist · .git · logs</code>
                    </dd>
                  </div>
                </dl>
                <p className="warningCopy">
                  A completed sync does not mean the environment is ready to
                  run. Set up required secrets independently on each machine.
                </p>
              </section>
            </>
          )}
          {route === "agent-handoff" && (
            <>
              <PageHeader
                eyebrow="Agent handoff"
                title="Hand over boundaries, not secrets."
                description="Generate a redacted contract from registered evidence. Review unresolved conflicts and local environment requirements before starting agent work."
              />
              <section className="inspectionPane">
                <p>
                  No agent starts automatically. File contents, secret values
                  and machine locations stay outside the handoff.
                </p>
                <button
                  className="primary"
                  disabled={busy || !pair}
                  onClick={() =>
                    run(async () =>
                      setHandoff(
                        await command({ action: "handoff", pair_id: pair?.id }),
                      ),
                    )
                  }
                >
                  Generate redacted contract
                </button>
                {handoff !== null && (
                  <pre aria-label="Redacted agent contract">
                    {JSON.stringify(handoff, null, 2)}
                  </pre>
                )}
              </section>
            </>
          )}
          {route === "recovery" && (
            <>
              <PageHeader
                eyebrow="Activity & recovery"
                title="Every apply leaves a trail."
                description="Build a recovery preview from a verified plan, review the affected paths, then approve it through the same apply gate. New local edits can block recovery."
              />
              <section className="inspectionPane">
                <h3>Recorded plans</h3>
                {data.plans.length ? (
                  <div className="planList">
                    {data.plans.map((p) => (
                      <div key={p.id}>
                        <code>{p.id}</code>
                        <span>
                          {p.state} · {p.operations.length} paths
                        </span>
                        <button
                          disabled={
                            busy ||
                            !["verified", "recovery_required"].includes(p.state)
                          }
                          onClick={() =>
                            run(async () => {
                              setPreview(
                                await command<Plan>({
                                  action: "rollback_preview",
                                  plan_id: p.id,
                                }),
                              );
                              setApproval(false);
                              setReceipt(null);
                              setRoute("sync-queue");
                            })
                          }
                        >
                          Preview recovery
                        </button>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p>No plans recorded.</p>
                )}
              </section>
              <section className="inspectionPane activity">
                <h3>Event log</h3>
                {native && (
                  <div className="warningCopy">
                    <strong>
                      Keep recovery backups until your work is verified.
                    </strong>
                    <p>
                      Replacement and deletion retain the outgoing file as{" "}
                      <code>previous</code> inside the recorded recovery
                      directory, relative to the source or replica root shown
                      below. Preserve these directories. A quarantining event
                      records the intended backup location; check locally that
                      the retained file exists before relying on it.
                    </p>
                    <p>
                      If rollback refuses because newer local work exists,
                      preserve that new work and the retained{" "}
                      <code>previous</code> file in separate backup folders
                      before comparing or restoring manually. No file contents
                      are shown here.
                    </p>
                  </div>
                )}
                {data.events.length ? (
                  <ol>
                    {data.events.map((e, i) => (
                      <li key={i}>
                        <span>{String(e.kind ?? e.state ?? "event")}</span>
                        {e.plan_id && <code>{e.plan_id}</code>}
                        {native && e.kind === "quarantining" && e.evidence && (
                          <dl className="recoveryEvidence">
                            {e.evidence.path && (
                              <div>
                                <dt>Affected path</dt>
                                <dd>
                                  <code>{e.evidence.path}</code>
                                </dd>
                              </div>
                            )}
                            {e.evidence.side && (
                              <div>
                                <dt>Registered root</dt>
                                <dd>
                                  {e.evidence.side === "target"
                                    ? "replica (target)"
                                    : "source"}
                                </dd>
                              </div>
                            )}
                            {e.evidence.recovery_directory && (
                              <div>
                                <dt>Recovery location / verify locally</dt>
                                <dd>
                                  <code>
                                    {e.evidence.recovery_directory}/previous
                                  </code>
                                </dd>
                              </div>
                            )}
                            {e.evidence.before && (
                              <div>
                                <dt>Previous object identity</dt>
                                <dd>
                                  <code>{e.evidence.before}</code>
                                </dd>
                              </div>
                            )}
                          </dl>
                        )}
                      </li>
                    ))}
                  </ol>
                ) : (
                  <p>No events recorded.</p>
                )}
              </section>
              {!native && (
                <button
                  className="quiet"
                  disabled={busy}
                  onClick={() =>
                    run(async () => {
                      resetDemo();
                      setPreview(null);
                      setReceipt(null);
                      setApproval(false);
                    })
                  }
                >
                  Reset disposable demo
                </button>
              )}
            </>
          )}
        </div>
        <footer className="workspaceFooter">
          <span>DEVDROP / LOCAL FIRST</span>
          <span>
            {native
              ? "Approved file operations run in Rust."
              : "Demonstration only · no device files read or changed"}
          </span>
        </footer>
      </section>
    </main>
  );
}
function PageHeader({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string;
  title: string;
  description: string;
}) {
  return (
    <div className="pageHeader">
      <p className="eyebrow">{eyebrow}</p>
      <h2>{title}</h2>
      <p>{description}</p>
    </div>
  );
}
function Evidence({ title, text }: { title: string; text: string }) {
  return (
    <div className="evidenceItem">
      <span className="evidenceMarker" aria-hidden="true" />
      <div>
        <h3>{title}</h3>
        <p>{text}</p>
      </div>
    </div>
  );
}
function FolderMapping({ pair }: { pair: Pair }) {
  return (
    <div className="folderMapping">
      <div>
        <span>01 / SOURCE</span>
        <code>{pair.source}</code>
      </div>
      <span className="direction" aria-label="syncs to">
        →
      </span>
      <div>
        <span>02 / REPLICA</span>
        <code>{pair.target}</code>
      </div>
    </div>
  );
}
function Empty({ title, text }: { title: string; text: string }) {
  return (
    <section className="emptyState">
      <span aria-hidden="true">◇</span>
      <h3>{title}</h3>
      <p>{text}</p>
    </section>
  );
}
function OperationTable({ operations }: { operations: Operation[] }) {
  return (
    <div className="tableWrap">
      <table>
        <caption>
          Exact path preview · hashes identify content; file text is omitted
        </caption>
        <thead>
          <tr>
            <th>Path / side</th>
            <th>Action</th>
            <th>Replica before</th>
            <th>After / incoming</th>
          </tr>
        </thead>
        <tbody>
          {operations.map((o, i) => (
            <tr
              key={`${o.path}-${i}`}
              className={o.kind === "conflict" ? "conflictRow" : ""}
            >
              <td>
                <code>{o.path}</code>
                <small className="muted"> · {o.side ?? "target"}</small>
              </td>
              <td>
                <span className={`operation ${o.kind}`}>
                  {o.kind === "delete" ? "delete · tombstone" : o.kind}
                </span>
              </td>
              <td>
                <code title={o.before ?? "Absent"}>{hash(o.before)}</code>
              </td>
              <td>
                <code title={o.after ?? "Absent"}>{hash(o.after)}</code>
              </td>
            </tr>
          ))}
          {!operations.length && (
            <tr>
              <td colSpan={4}>No eligible path changes in this scan.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
function DemoTools({
  busy,
  run,
  invalidate,
}: {
  busy: boolean;
  run: (fn: () => Promise<void>) => Promise<void>;
  invalidate: () => void;
}) {
  return (
    <section className="demoTools">
      <p className="eyebrow">Explore the disposable workspace</p>
      <p>
        Apply a first preview, then simulate a source edit or divergent changes.
      </p>
      <div className="toolbar">
        <button
          disabled={busy}
          onClick={() =>
            run(async () => {
              await command({ action: "demo_edit" });
              invalidate();
            })
          }
        >
          Simulate source edit
        </button>
        <button
          disabled={busy}
          onClick={() =>
            run(async () => {
              await command({ action: "demo_conflict" });
              invalidate();
            })
          }
        >
          Simulate conflict
        </button>
      </div>
    </section>
  );
}
