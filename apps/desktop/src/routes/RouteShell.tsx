type RouteShellProps = {
  title: string;
  intent: string;
};

export function RouteShell({ title, intent }: RouteShellProps) {
  return (
    <section className="surface" aria-labelledby="route-title">
      <div className="pageHeader">
        <p className="eyebrow">Placeholder route</p>
        <h2 id="route-title">{title}</h2>
        <p>{intent}</p>
      </div>

      <div className="placeholderGrid">
        <div className="fieldPlate">
          <span>Evidence required</span>
          <strong>Fixture-backed data before live mutation.</strong>
        </div>
        <div className="fieldPlate">
          <span>Blocked action</span>
          <strong>Real apply/delete/overwrite remains unavailable.</strong>
        </div>
        <div className="fieldPlate">
          <span>Design risk</span>
          <strong>Must avoid generic dashboards and vague state labels.</strong>
        </div>
      </div>
    </section>
  );
}

