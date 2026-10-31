//! Durable local two-folder sync. No HTTP listener or remotely callable writes.
//! Every apply consumes a persisted preview, an exact approval, and fresh scans.
use cap_std::{ambient_authority, fs::Dir};
use fs2::FileExt;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::Duration,
};

type Snapshot = BTreeMap<String, String>;
type Result<T> = std::result::Result<T, LocalError>;

/// Errors are intentionally fixed messages: OS errors may include sensitive paths.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct LocalError(pub &'static str);
fn err(message: &'static str) -> LocalError {
    LocalError(message)
}
fn io<T>(r: std::io::Result<T>) -> Result<T> {
    r.map_err(|_| err("Filesystem operation failed; inspect local permissions and retry."))
}
fn sql<T>(r: rusqlite::Result<T>) -> Result<T> {
    r.map_err(|_| err("Local metadata unavailable or incompatible; preserve the state directory."))
}
fn encode<T: Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|_| err("Metadata encoding failed."))
}
fn decode<T: serde::de::DeserializeOwned>(s: &str) -> Result<T> {
    serde_json::from_str(s)
        .map_err(|_| err("Local metadata is invalid; preserve the state directory."))
}
fn hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 100 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| err("A required request field is missing."))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pair {
    pub id: String,
    pub name: String,
    pub source: String,
    pub target: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Operation {
    pub path: String,
    pub kind: String,
    pub side: String,
    pub before: Option<String>,
    pub after: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub pair_id: String,
    pub operations: Vec<Operation>,
    pub state: String,
    pub blockers: Vec<String>,
    pub source_scan: Snapshot,
    pub target_scan: Snapshot,
    pub base_revision: i64,
    pub reverses: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub plan_id: String,
    pub state: String,
    pub changed: Vec<String>,
    pub message: String,
}

/// Single-writer lock covers SQLite and filesystem operations across CLI/Tauri/MCP.
pub struct Engine {
    db: Connection,
    state: PathBuf,
    _lock: File,
}
impl Engine {
    pub fn open(state: &Path) -> Result<Self> {
        let state = absolute(state)?;
        reject_symlinks(&state)?;
        if state.parent().is_none() {
            return Err(err("Filesystem roots cannot hold DevDrop metadata."));
        }
        if state.exists()
            && !state.join("metadata.sqlite3").exists()
            && !state.join("writer.lock").exists()
            && io(fs::read_dir(&state))?.next().is_some()
        {
            return Err(err("Choose an empty directory for new DevDrop metadata."));
        }
        io(fs::create_dir_all(&state))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            io(fs::set_permissions(
                &state,
                fs::Permissions::from_mode(0o700),
            ))?;
        }
        for child in [
            "writer.lock",
            "metadata.sqlite3",
            "metadata.sqlite3-wal",
            "metadata.sqlite3-shm",
            "objects",
        ] {
            reject_symlinks(&state.join(child))?;
        }
        let lock = io(OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(state.join("writer.lock")))?;
        lock.try_lock_exclusive()
            .map_err(|_| err("Another DevDrop operation is running. Wait for its receipt."))?;
        let db = sql(Connection::open(state.join("metadata.sqlite3")))?;
        sql(db.busy_timeout(Duration::from_secs(5)))?;
        sql(db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS schema_version(version INTEGER NOT NULL);
          INSERT INTO schema_version SELECT 1 WHERE NOT EXISTS(SELECT 1 FROM schema_version);
          CREATE TABLE IF NOT EXISTS pairs(id TEXT PRIMARY KEY, body TEXT NOT NULL, baseline TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY, pair_id TEXT NOT NULL REFERENCES pairs(id), body TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, pair_id TEXT, plan_id TEXT, body TEXT NOT NULL);
        "))?;
        let version: i64 =
            sql(db.query_row("SELECT version FROM schema_version", [], |r| r.get(0)))?;
        if version != 1 {
            return Err(err(
                "Unsupported local metadata schema; upgrade DevDrop without deleting state.",
            ));
        }
        io(fs::create_dir_all(state.join("objects")))?;
        sync_directory(&state)?;
        if let Some(parent) = state.parent() {
            sync_directory(parent)?;
        }
        let engine = Self {
            db,
            state,
            _lock: lock,
        };
        // An interrupted apply is never silently resumed or labelled successful.
        for mut plan in engine.plans()? {
            if plan.state == "applying" {
                plan.state = "recovery_required".into();
                engine.save_plan(&plan)?;
                engine.event(
                    "interrupted",
                    &plan.pair_id,
                    &plan.id,
                    json!({"state":"recovery_required"}),
                )?;
            }
        }
        Ok(engine)
    }
    pub fn register(&self, name: &str, source: &Path, target: &Path) -> Result<Pair> {
        if name.is_empty() || name.len() > 80 || name.chars().any(char::is_control) {
            return Err(err("Project name must be 1–80 printable characters."));
        }
        let source = root(source)?;
        let target = root(target)?;
        if source.starts_with(&target)
            || target.starts_with(&source)
            || self.state.starts_with(&source)
            || self.state.starts_with(&target)
            || source.starts_with(&self.state)
            || target.starts_with(&self.state)
        {
            return Err(err("Source, target, and metadata directories must be separate and must not contain each other."));
        }
        // A root belongs to one pair, so independent pairs cannot mutate it concurrently.
        for p in self.pairs()? {
            for existing in [&p.source, &p.target] {
                let e = Path::new(existing);
                if source.starts_with(e)
                    || target.starts_with(e)
                    || e.starts_with(&source)
                    || e.starts_with(&target)
                {
                    return Err(err(
                        "A registered project already owns one of these directories.",
                    ));
                }
            }
        }
        let source = source
            .to_str()
            .ok_or_else(|| err("Project paths must be valid UTF-8."))?
            .to_owned();
        let target = target
            .to_str()
            .ok_or_else(|| err("Project paths must be valid UTF-8."))?
            .to_owned();
        let id = format!(
            "pair-{}",
            &hash(format!("{source}\0{target}").as_bytes())[..24]
        );
        let p = Pair {
            id,
            name: name.into(),
            source,
            target,
        };
        self.transaction(|| {
            sql(self.db.execute(
                "INSERT INTO pairs(id,body,baseline) VALUES(?1,?2,'{}')",
                params![p.id, encode(&p)?],
            ))?;
            self.event(
                "registered",
                &p.id,
                "",
                json!({"direction":"source_to_target","pair":p}),
            )?;
            Ok(())
        })?;
        Ok(p)
    }
    pub fn pairs(&self) -> Result<Vec<Pair>> {
        self.rows("SELECT body FROM pairs ORDER BY id")
    }
    pub fn plans(&self) -> Result<Vec<Plan>> {
        self.rows("SELECT body FROM plans ORDER BY rowid DESC")
    }
    fn rows<T: serde::de::DeserializeOwned>(&self, query: &str) -> Result<Vec<T>> {
        let mut statement = sql(self.db.prepare(query))?;
        let rows = sql(statement.query_map([], |r| r.get::<_, String>(0)))?;
        rows.map(|r| decode(&sql(r)?)).collect()
    }
    fn pair(&self, id: &str) -> Result<(Pair, Snapshot, i64)> {
        if !valid_id(id) {
            return Err(err("Unknown project identifier."));
        }
        let (p, b, r): (String, String, i64) = sql(self.db.query_row(
            "SELECT body,baseline,revision FROM pairs WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        ))?;
        Ok((decode(&p)?, decode(&b)?, r))
    }
    fn plan(&self, id: &str) -> Result<Plan> {
        if !valid_id(id) {
            return Err(err("Unknown preview identifier."));
        }
        let body: String =
            sql(self
                .db
                .query_row("SELECT body FROM plans WHERE id=?1", [id], |r| r.get(0)))?;
        decode(&body)
    }
    fn save_plan(&self, p: &Plan) -> Result<()> {
        sql(self.db.execute("INSERT INTO plans(id,pair_id,body) VALUES(?1,?2,?3) ON CONFLICT(id) DO UPDATE SET body=excluded.body",params![p.id,p.pair_id,encode(p)?]))?;
        Ok(())
    }
    fn transaction<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        sql(self.db.execute_batch("BEGIN IMMEDIATE"))?;
        match operation() {
            Ok(value) => {
                sql(self.db.execute_batch("COMMIT"))?;
                Ok(value)
            }
            Err(error) => {
                let _ = self.db.execute_batch("ROLLBACK");
                Err(error)
            }
        }
    }
    fn event(&self, kind: &str, pair: &str, plan: &str, body: Value) -> Result<()> {
        sql(self.db.execute(
            "INSERT INTO events(kind,pair_id,plan_id,body) VALUES(?1,?2,?3,?4)",
            params![kind, pair, plan, encode(&body)?],
        ))?;
        Ok(())
    }
    pub fn events(&self) -> Result<Value> {
        let mut q = sql(self.db.prepare(
            "SELECT seq,kind,pair_id,plan_id,body FROM events ORDER BY seq DESC LIMIT 500",
        ))?;
        let rows = sql(q.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        }))?;
        let mut out = vec![];
        for r in rows {
            let (s, k, p, id, b) = sql(r)?;
            out.push(
                json!({"seq":s,"kind":k,"pair_id":p,"plan_id":id,"evidence":decode::<Value>(&b)?}),
            );
        }
        Ok(json!(out))
    }
    fn ensure_no_recovery(&self, pair: &str) -> Result<()> {
        if self.plans()?.iter().any(|p| {
            p.pair_id == pair && matches!(p.state.as_str(), "applying" | "recovery_required")
        }) {
            return Err(err(
                "An interrupted operation needs a rollback preview before another sync.",
            ));
        }
        Ok(())
    }
    fn scans(&self, p: &Pair) -> Result<(Snapshot, Snapshot)> {
        let mut source = self.scan(Path::new(&p.source))?;
        let mut target = self.scan(Path::new(&p.target))?;
        for path in union(&source, &target, &Snapshot::new()) {
            if excluded(Path::new(&p.source), &path)? || excluded(Path::new(&p.target), &path)? {
                source.remove(&path);
                target.remove(&path);
            }
        }
        Ok((source, target))
    }
    pub fn preview(&self, pair_id: &str) -> Result<Plan> {
        self.ensure_no_recovery(pair_id)?;
        let (p, base, revision) = self.pair(pair_id)?;
        let (s, t) = self.scans(&p)?;
        let mut ops = vec![];
        for path in union(&s, &t, &base) {
            // Exclusion is never deletion intent, even if an old baseline tracked this path.
            if excluded(Path::new(&p.source), &path)? || excluded(Path::new(&p.target), &path)? {
                continue;
            }
            let a = s.get(&path);
            let b = t.get(&path);
            let old = base.get(&path);
            if a == b {
                continue;
            }
            let kind = if b == old {
                if a.is_none() {
                    "delete"
                } else if b.is_none() {
                    "copy"
                } else {
                    "replace"
                }
            } else {
                "conflict"
            };
            ops.push(Operation {
                path,
                kind: kind.into(),
                side: "target".into(),
                before: b.cloned(),
                after: a.cloned(),
            });
        }
        let blockers = if dirty_git(&p.source)? || dirty_git(&p.target)? {
            vec![
                "Git worktree has uncommitted changes; commit or move this work before applying."
                    .into(),
            ]
        } else {
            vec![]
        };
        self.new_plan(&p, ops, s, t, revision, None, blockers)
    }
    fn new_plan(
        &self,
        p: &Pair,
        operations: Vec<Operation>,
        source_scan: Snapshot,
        target_scan: Snapshot,
        base_revision: i64,
        reverses: Option<String>,
        blockers: Vec<String>,
    ) -> Result<Plan> {
        let sequence: i64 =
            sql(self
                .db
                .query_row("SELECT COALESCE(MAX(seq),0)+1 FROM events", [], |r| {
                    r.get(0)
                }))?;
        let id = format!(
            "plan-{}",
            &hash(
                encode(&(
                    sequence,
                    &p.id,
                    &operations,
                    &source_scan,
                    &target_scan,
                    base_revision,
                    &reverses
                ))?
                .as_bytes()
            )[..32]
        );
        let plan = Plan {
            id,
            pair_id: p.id.clone(),
            operations,
            state: "planned".into(),
            blockers,
            source_scan,
            target_scan,
            base_revision,
            reverses,
        };
        self.save_plan(&plan)?;
        self.event("preview", &p.id, &plan.id, json!({"plan":plan}))?;
        Ok(plan)
    }
    /// Explicit resolution stores and retains both versions in CAS before any write.
    pub fn resolve_preview(&self, pair_id: &str, path: &str, choice: &str) -> Result<Plan> {
        safe_path(path)?;
        let current = self.preview(pair_id)?;
        let conflict = current
            .operations
            .iter()
            .find(|o| o.path == path && o.kind == "conflict")
            .ok_or_else(|| err("The selected path is not an unresolved conflict."))?;
        let (p, _, revision) = self.pair(pair_id)?;
        let mut ops = vec![];
        match choice {
            "source" => ops.push(Operation {
                kind: kind(&conflict.before, &conflict.after).into(),
                ..conflict.clone()
            }),
            "target" => ops.push(Operation {
                path: path.into(),
                kind: kind(&conflict.after, &conflict.before).into(),
                side: "source".into(),
                before: conflict.after.clone(),
                after: conflict.before.clone(),
            }),
            "both" => {
                let other = conflict
                    .before
                    .as_ref()
                    .ok_or_else(|| err("Keep both requires content on both sides."))?;
                if conflict.after.is_none() {
                    return Err(err("Keep both requires content on both sides."));
                }
                let sibling = format!("{path}.devdrop-conflict-{}", &other[..12]);
                safe_path(&sibling)?;
                if current.source_scan.contains_key(&sibling)
                    || current.target_scan.contains_key(&sibling)
                {
                    return Err(err("Conflict preservation path already exists; choose a side or rename locally and rescan."));
                }
                for side in ["source", "target"] {
                    ops.push(Operation {
                        path: sibling.clone(),
                        kind: "copy".into(),
                        side: side.into(),
                        before: None,
                        after: Some(other.clone()),
                    });
                }
                ops.push(Operation {
                    kind: kind(&conflict.before, &conflict.after).into(),
                    ..conflict.clone()
                });
            }
            _ => {
                return Err(err(
                    "Choose source, target, or both for a resolution preview.",
                ))
            }
        }
        self.new_plan(
            &p,
            ops,
            current.source_scan,
            current.target_scan,
            revision,
            None,
            current.blockers,
        )
    }
    pub fn apply(&self, id: &str, approval: &str) -> Result<Receipt> {
        self.apply_inner(id, approval, None)
    }
    fn apply_inner(
        &self,
        id: &str,
        approval: &str,
        interrupt_after: Option<usize>,
    ) -> Result<Receipt> {
        let mut plan = self.plan(id)?;
        if approval != id {
            self.event(
                "refused",
                &plan.pair_id,
                id,
                json!({"reason":"specific_plan_approval_required"}),
            )?;
            return Err(err("Approve the exact preview ID before applying."));
        }
        if matches!(plan.state.as_str(), "verified" | "rolled_back") {
            return Ok(Receipt {
                plan_id: id.into(),
                state: plan.state,
                changed: vec![],
                message: "This preview already has a verified receipt; no files changed.".into(),
            });
        }
        if plan.state == "stale" {
            return Err(err("Preview is stale; create and approve a new preview."));
        }
        if plan.state != "planned" {
            return Err(err(
                "This operation needs recovery; create a rollback preview.",
            ));
        }
        if !plan.blockers.is_empty() || plan.operations.iter().any(|o| o.kind == "conflict") {
            return Err(err("Unresolved conflicts or readiness blockers prevent apply. Resolve them and create a new preview."));
        }
        if plan.reverses.is_none() {
            self.ensure_no_recovery(&plan.pair_id)?;
        }
        let (p, _, revision) = self.pair(&plan.pair_id)?;
        let (s, t) = self.scans(&p)?;
        if s != plan.source_scan || t != plan.target_scan || revision != plan.base_revision {
            self.event("refused", &p.id, id, json!({"reason":"stale_preview"}))?;
            return Err(err(
                "Preview is stale; scan and preview again before approving.",
            ));
        }
        if plan.reverses.is_none() && (dirty_git(&p.source)? || dirty_git(&p.target)?) {
            return Err(err(
                "Git worktree changed; create a new preview after preserving local work.",
            ));
        }
        self.event("approved", &p.id, id, json!({"approved_plan_id":id}))?;
        plan.state = "applying".into();
        self.save_plan(&plan)?;
        self.event(
            "applying",
            &p.id,
            id,
            json!({"recovery":"Use rollback_preview on this plan if interrupted."}),
        )?;
        let mut changed = vec![];
        for (index, op) in plan.operations.iter().enumerate() {
            if interrupt_after == Some(index) {
                return Err(err("Test interruption; recovery is required."));
            }
            if op.kind == "delete" {
                if let Some(h) = &op.before {
                    self.object(h)?;
                }
                self.event("tombstone",&p.id,id,json!({"operation":op,"origin":"approved_local_plan","restore_object":op.before,"approval":id}))?;
            }
            let result = self.write_operation(&p, op, id, index);
            if result.is_err() {
                plan.state = "recovery_required".into();
                self.save_plan(&plan)?;
                self.event(
                    "failed",
                    &p.id,
                    id,
                    json!({"changed":changed,"state":"recovery_required"}),
                )?;
                return Err(err(
                    "Apply interrupted. Preserve .devdrop-recovery-<plan-id>-<operation-index>/previous under the affected registered root; the event log names each directory. Create a rollback preview. If the preserved bytes changed, restore them manually first.",
                ));
            }
            changed.push(format!("{}:{}", op.side, op.path));
            self.event(
                "operation_verified",
                &p.id,
                id,
                json!({"index":index,"operation":op}),
            )?;
        }
        let (after_s, after_t) = self.scans(&p)?;
        let mut expected_s = plan.source_scan.clone();
        let mut expected_t = plan.target_scan.clone();
        for op in &plan.operations {
            let map = if op.side == "source" {
                &mut expected_s
            } else {
                &mut expected_t
            };
            set(map, &op.path, op.after.clone());
        }
        if after_s != expected_s || after_t != expected_t {
            plan.state = "recovery_required".into();
            self.save_plan(&plan)?;
            return Err(err("Final verification found changed files. Preserve work and create a rollback preview."));
        }
        // Commit completion, baseline, and replay receipt atomically. Applying was durable before mutation.
        let baseline: Snapshot = after_s
            .iter()
            .filter(|(k, v)| after_t.get(*k) == Some(*v))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        plan.state = if plan.reverses.is_some() {
            "rolled_back"
        } else {
            "verified"
        }
        .into();
        sql(self.db.execute_batch("BEGIN IMMEDIATE"))?;
        let finish = (|| {
            sql(self.db.execute(
                "UPDATE pairs SET baseline=?1,revision=revision+1 WHERE id=?2",
                params![encode(&baseline)?, p.id],
            ))?;
            self.save_plan(&plan)?;
            for mut previous in self.plans()? {
                if previous.pair_id == p.id && previous.id != id && previous.state == "planned" {
                    previous.state = "stale".into();
                    self.save_plan(&previous)?;
                }
            }
            if let Some(original) = &plan.reverses {
                let mut original = self.plan(original)?;
                original.state = "rolled_back".into();
                self.save_plan(&original)?;
            }
            self.event("receipt",&p.id,id,json!({"state":plan.state,"changed":changed,"verified":true,"baseline":baseline,"revision":revision+1}))?;
            Ok(())
        })();
        match finish {
            Ok(()) => sql(self.db.execute_batch("COMMIT"))?,
            Err(e) => {
                let _ = self.db.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
        sql(self.db.execute_batch("PRAGMA wal_checkpoint(FULL)"))?;
        Ok(Receipt{plan_id:id.into(),state:plan.state,changed,message:"Verified against fresh scans. Original bytes are retained in the local object store; rollback requires its own approved preview.".into()})
    }
    pub fn rollback_preview(&self, id: &str) -> Result<Plan> {
        let original = self.plan(id)?;
        if !matches!(
            original.state.as_str(),
            "verified" | "applying" | "recovery_required"
        ) {
            return Err(err(
                "Only an applied or interrupted preview can be rolled back.",
            ));
        }
        let (p, _, revision) = self.pair(&original.pair_id)?;
        let (s, t) = self.scans(&p)?;
        let mut ops = vec![];
        for (index, o) in original.operations.iter().enumerate().rev() {
            let root_path = Path::new(if o.side == "source" {
                &p.source
            } else {
                &p.target
            });
            let stage = root_path.join(format!(".devdrop-recovery-{}-{index}", original.id));
            let backup = stage.join("previous");
            let staged = if stage.exists() {
                reject_symlinks(&backup)?;
                if backup.exists() {
                    let d = io(Dir::open_ambient_dir(&stage, ambient_authority()))?;
                    if current_hash(&d, "previous")? != o.before {
                        return Err(err("New work was preserved in a .devdrop-recovery-* directory. Restore it manually before rollback."));
                    }
                    true
                } else {
                    false
                }
            } else {
                false
            };
            let map = if o.side == "source" { &s } else { &t };
            let now = map.get(&o.path).cloned();
            if now == o.before {
                continue;
            }
            if now != o.after && !(staged && now.is_none()) {
                return Err(err("Files changed after apply; rollback would overwrite new work. Preserve those files before retrying."));
            }
            if let Some(h) = &o.before {
                self.object(h)?;
            }
            ops.push(Operation {
                path: o.path.clone(),
                side: o.side.clone(),
                kind: kind(&now, &o.before).into(),
                before: now,
                after: o.before.clone(),
            });
        }
        self.new_plan(&p, ops, s, t, revision, Some(id.into()), vec![])
    }
    fn write_operation(&self, p: &Pair, o: &Operation, id: &str, index: usize) -> Result<()> {
        self.write_operation_with_hook(p, o, id, index, |_| {})
    }
    fn write_operation_with_hook(
        &self,
        p: &Pair,
        o: &Operation,
        id: &str,
        index: usize,
        mut hook: impl FnMut(&str),
    ) -> Result<()> {
        safe_path(&o.path)?;
        let path = Path::new(if o.side == "source" {
            &p.source
        } else {
            &p.target
        });
        root(path)?;
        let dir = io(Dir::open_ambient_dir(path, ambient_authority()))?;
        check_parents(path, &o.path)?;
        if current_hash(&dir, &o.path)? != o.before {
            return Err(err("File changed after preview."));
        }
        let incoming = match &o.after {
            Some(h) => Some(self.object(h)?),
            None => None,
        };
        // Move the actual outgoing inode to an exclusive recovery directory before
        // replacement. A last-moment edit is preserved even when its hash differs.
        // New content always uses no-clobber hard-link installation, never rename-overwrite.
        hook("before_quarantine");
        if o.before.is_some() {
            let stage = format!(".devdrop-recovery-{id}-{index}");
            io(dir.create_dir(&stage))?;
            let recovery = io(dir.open_dir(&stage))?;
            self.event(
                "quarantining",
                &p.id,
                id,
                json!({"path":o.path,"side":o.side,"recovery_directory":stage,"before":o.before}),
            )?;
            io(dir.rename(&o.path, &recovery, "previous"))?;
            sync_directory(path)?;
            sync_directory(&path.join(&stage))?;
            if current_hash(&recovery, "previous")? != o.before {
                return Err(err("Target changed during commit; new work is preserved in a .devdrop-recovery-* directory under its registered root."));
            }
        }
        hook("before_install");
        if let Some(bytes) = incoming {
            if let Some(parent) = Path::new(&o.path).parent() {
                if !parent.as_os_str().is_empty() {
                    io(dir.create_dir_all(parent))?;
                }
            }
            check_parents(path, &o.path)?;
            let parent = Path::new(&o.path).parent().unwrap_or_else(|| Path::new(""));
            let temporary = parent.join(format!(".devdrop-tmp-{id}-{index}"));
            let mut opts = cap_std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            let mut f = io(dir.open_with(&temporary, &opts))?;
            io(f.write_all(&bytes))?;
            io(f.sync_all())?;
            drop(f);
            // A concurrently-created destination is preserved and blocks the operation.
            io(dir.hard_link(&temporary, &dir, &o.path))?;
            io(dir.remove_file(&temporary))?;
        }
        if current_hash(&dir, &o.path)? != o.after {
            return Err(err("Written content did not verify."));
        }
        // Directory fsync makes rename/unlink durable on Unix, in addition to SQLite FULL commits.
        #[cfg(unix)]
        {
            let parent = Path::new(&o.path).parent().unwrap_or_else(|| Path::new(""));
            let f = io(File::open(path.join(parent)))?;
            io(f.sync_all())?;
        }
        Ok(())
    }
    fn object(&self, h: &str) -> Result<Vec<u8>> {
        if h.len() != 64
            || !h
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(err("Invalid object identifier."));
        }
        let path = self.state.join("objects").join(h);
        reject_symlinks(&path)?;
        let bytes = io(fs::read(path))?;
        if hash(&bytes) != h {
            return Err(err(
                "Object hash mismatch; preserve state and restore from an intact copy.",
            ));
        }
        Ok(bytes)
    }
    fn store(&self, bytes: &[u8]) -> Result<String> {
        let h = hash(bytes);
        let path = self.state.join("objects").join(&h);
        reject_symlinks(&path)?;
        match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(mut f) => {
                io(f.write_all(bytes))?;
                io(f.sync_all())?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(err("Object storage write failed.")),
        }
        sync_directory(&self.state.join("objects"))?;
        if self.object(&h)? != bytes {
            return Err(err("Stored object did not verify."));
        }
        Ok(h)
    }
    fn scan(&self, path: &Path) -> Result<Snapshot> {
        let path = root(path)?;
        let dir = io(Dir::open_ambient_dir(&path, ambient_authority()))?;
        let mut map = Snapshot::new();
        let mut casefold = BTreeSet::new();
        let mut total = 0u64;
        // Parse only validated, bounded local .gitignore files. The walker never
        // opens ignore/config files on its own, including global/home policies.
        let scan_error = std::sync::Arc::new(std::sync::Mutex::new(None));
        let filter_error = scan_error.clone();
        let scan_root = path.clone();
        let walker = ignore::WalkBuilder::new(&path)
            .hidden(false)
            .ignore(false)
            .git_ignore(false)
            .parents(false)
            .git_global(false)
            .git_exclude(false)
            .require_git(false)
            .follow_links(false)
            .filter_entry(move |entry| {
                if entry.depth() == 0 {
                    return true;
                }
                if !eligible(
                    entry
                        .path()
                        .file_name()
                        .and_then(|x| x.to_str())
                        .unwrap_or(""),
                ) {
                    return false;
                }
                let relative = match entry
                    .path()
                    .strip_prefix(&scan_root)
                    .ok()
                    .and_then(|x| x.to_str())
                {
                    Some(p) => p,
                    None => {
                        *filter_error.lock().unwrap() =
                            Some(err("Workspace paths must be valid UTF-8."));
                        return false;
                    }
                };
                match excluded(&scan_root, relative) {
                    Ok(exclude) => !exclude,
                    Err(e) => {
                        *filter_error.lock().unwrap() = Some(e);
                        false
                    }
                }
            })
            .build();
        for entry in walker {
            let entry = entry.map_err(|_| {
                err("Scan was incomplete. Fix local read permissions before previewing.")
            })?;
            if entry.depth() == 0 {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(&path)
                .map_err(|_| err("Scan escaped project root."))?;
            let path_str = relative
                .to_str()
                .ok_or_else(|| err("A workspace path is not valid UTF-8."))?
                .replace('\\', "/");
            safe_path(&path_str)?;
            let m = io(fs::symlink_metadata(entry.path()))?;
            if m.file_type().is_symlink() {
                return Err(err(
                    "Symlinks are blocked in sync roots; move or exclude them before previewing.",
                ));
            }
            if m.is_dir() {
                continue;
            }
            if !m.is_file() {
                return Err(err("Special files are blocked in sync roots."));
            }
            if m.len() > 64 * 1024 * 1024
                || map.len() >= 10000
                || total + m.len() > 256 * 1024 * 1024
            {
                return Err(err(
                    "Scan budget exceeded; narrow the registered directories.",
                ));
            }
            if m.permissions().readonly() {
                return Err(err(
                    "Read-only files require a separate writable sync directory.",
                ));
            }
            if !casefold.insert(path_str.to_lowercase()) {
                return Err(err(
                    "Case-colliding paths are blocked for cross-platform safety.",
                ));
            }
            check_parents(&path, &path_str)?;
            let mut f = io(dir.open(&path_str))?;
            let mut bytes = vec![];
            io(std::io::Read::by_ref(&mut f)
                .take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes))?;
            if bytes.len() > 64 * 1024 * 1024 {
                return Err(err("File grew beyond scan budget."));
            }
            if secret_content(&bytes) {
                return Err(err("Potential secret content detected; exclude it before previewing. No content was stored for this file."));
            }
            total += bytes.len() as u64;
            map.insert(path_str, self.store(&bytes)?);
        }
        if let Some(error) = scan_error.lock().unwrap().take() {
            return Err(error);
        }
        Ok(map)
    }
}
fn union(a: &Snapshot, b: &Snapshot, c: &Snapshot) -> BTreeSet<String> {
    a.keys().chain(b.keys()).chain(c.keys()).cloned().collect()
}
fn set(map: &mut Snapshot, path: &str, value: Option<String>) {
    if let Some(v) = value {
        map.insert(path.into(), v);
    } else {
        map.remove(path);
    }
}
fn kind(before: &Option<String>, after: &Option<String>) -> &'static str {
    if after.is_none() {
        "delete"
    } else if before.is_none() {
        "copy"
    } else {
        "replace"
    }
}
fn absolute(path: &Path) -> Result<PathBuf> {
    if path.as_os_str().is_empty() {
        return Err(err("Directory path is required."));
    }
    let p = if path.is_absolute() {
        path.to_path_buf()
    } else {
        io(std::env::current_dir())?.join(path)
    };
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(err(
            "Directory paths must not contain traversal components.",
        ));
    }
    Ok(p)
}
fn reject_symlinks(path: &Path) -> Result<()> {
    let mut p = PathBuf::new();
    for component in path.components() {
        p.push(component);
        // A Windows drive/verbatim prefix is not a complete path until its
        // RootDir component is appended. Inspecting `\\?\C:` alone is invalid.
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&p) {
            Ok(m) if m.file_type().is_symlink() => return Err(err("Symlink paths are blocked.")),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(err("Cannot inspect path safety.")),
        }
    }
    Ok(())
}
fn root(path: &Path) -> Result<PathBuf> {
    let p = absolute(path)?;
    reject_symlinks(&p)?;
    let p = io(fs::canonicalize(p))?;
    if !p.is_dir() {
        return Err(err("Register existing directories only."));
    }
    if p.parent().is_none() {
        return Err(err("Filesystem roots cannot be registered."));
    }
    Ok(p)
}
fn eligible(name: &str) -> bool {
    let lower = name.to_lowercase();
    !matches!(
        lower.as_str(),
        ".git"
            | ".hg"
            | ".svn"
            | ".netrc"
            | ".docker"
            | ".kube"
            | ".gnupg"
            | ".config"
            | ".ssh"
            | ".aws"
            | ".azure"
            | ".npmrc"
            | ".pypirc"
            | "credentials"
            | "secrets"
            | "node_modules"
            | ".next"
            | "dist"
            | "target"
            | "logs"
            | "build"
            | ".ds_store"
    ) && !lower.starts_with(".env")
        && !lower.starts_with(".devdrop-")
        && !lower.ends_with(".log")
        && !lower.ends_with(".pem")
        && !lower.ends_with(".key")
        && !lower.ends_with(".p12")
        && !lower.ends_with(".pfx")
        && !lower.contains("credentials")
}
fn safe_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 240
        || path.contains('\\')
        || path.contains(':')
        || path
            .chars()
            .any(|c| matches!(c, '?' | '<' | '>' | '*' | '|' | '\"'))
        || path.chars().any(char::is_control)
        || Path::new(path)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        || path.split('/').any(|c| {
            !eligible(c)
                || c.ends_with('.')
                || c.ends_with(' ')
                || matches!(
                    c.split('.')
                        .next()
                        .unwrap_or("")
                        .to_ascii_uppercase()
                        .as_str(),
                    "CON"
                        | "PRN"
                        | "AUX"
                        | "NUL"
                        | "COM1"
                        | "COM2"
                        | "COM3"
                        | "COM4"
                        | "COM5"
                        | "COM6"
                        | "COM7"
                        | "COM8"
                        | "COM9"
                        | "LPT1"
                        | "LPT2"
                        | "LPT3"
                        | "LPT4"
                        | "LPT5"
                        | "LPT6"
                        | "LPT7"
                        | "LPT8"
                        | "LPT9"
                )
        })
    {
        return Err(err("Path is outside the portable non-secret sync policy."));
    }
    Ok(())
}
fn check_parents(root: &Path, path: &str) -> Result<()> {
    safe_path(path)?;
    reject_symlinks(&root.join(path))
}
fn current_hash(dir: &Dir, path: &str) -> Result<Option<String>> {
    match dir.symlink_metadata(path) {
        Ok(m) => {
            if !m.is_file() || m.file_type().is_symlink() {
                return Err(err("Target is not a regular file."));
            }
            let bytes = io(dir.read(path))?;
            Ok(Some(hash(&bytes)))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(err("Cannot verify target file.")),
    }
}
fn secret_content(bytes: &[u8]) -> bool {
    let s = String::from_utf8_lossy(bytes);
    s.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")
        || s.contains("-----BEGIN PRIVATE KEY-----")
        || s.contains("-----BEGIN RSA PRIVATE KEY-----")
        || s.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
        || s.contains("-----BEGIN EC PRIVATE KEY-----")
        || s.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|word| {
                (word.starts_with("AKIA") && word.len() == 20)
                    || (word.starts_with("ghp_") && word.len() >= 36)
                    || (word.starts_with("github_pat_") && word.len() > 30)
            })
}
fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        io(File::open(path).and_then(|f| f.sync_all()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
fn excluded(root: &Path, path: &str) -> Result<bool> {
    safe_path(path)?;
    let root_dir = io(Dir::open_ambient_dir(root, ambient_authority()))?;
    let mut policies = Vec::new();
    let mut parent = PathBuf::new();
    let components: Vec<_> = Path::new(path).components().collect();
    for (index, component) in components.iter().enumerate() {
        let relative = parent.join(".gitignore");
        let ignore_file = root.join(&relative);
        reject_symlinks(&ignore_file)?;
        match root_dir.symlink_metadata(&relative) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_type().is_symlink()
                    || metadata.len() > 1024 * 1024
                {
                    return Err(err(
                        "Ignore policy must be a regular file of at most 1 MiB.",
                    ));
                }
                let mut file = io(root_dir.open(&relative))?;
                let mut bytes = vec![];
                io(std::io::Read::by_ref(&mut file)
                    .take(1024 * 1024 + 1)
                    .read_to_end(&mut bytes))?;
                if bytes.len() > 1024 * 1024 {
                    return Err(err("Ignore policy exceeds the 1 MiB scan budget."));
                }
                let content = std::str::from_utf8(&bytes)
                    .map_err(|_| err("Ignore policy must be valid UTF-8."))?;
                let mut builder = ignore::gitignore::GitignoreBuilder::new(root.join(&parent));
                for line in content.trim_start_matches('\u{feff}').lines() {
                    builder
                        .add_line(Some(ignore_file.clone()), line)
                        .map_err(|_| err("Ignore policy could not be parsed."))?;
                }
                policies.push(
                    builder
                        .build()
                        .map_err(|_| err("Ignore policy could not be parsed."))?,
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(err("Ignore policy could not be inspected.")),
        }
        parent.push(component);
        let directory = index + 1 < components.len()
            || root_dir
                .symlink_metadata(&parent)
                .map(|m| m.is_dir())
                .unwrap_or(false);
        let mut ignored = false;
        for policy in &policies {
            let matched = policy.matched(root.join(&parent), directory);
            if !matched.is_none() {
                ignored = matched.is_ignore();
            }
        }
        // Git does not descend into an excluded directory; child negations cannot reopen it.
        if ignored {
            return Ok(true);
        }
    }
    Ok(false)
}
fn dirty_git(root: &str) -> Result<bool> {
    if !Path::new(root).ancestors().any(|p| {
        let git = p.join(".git");
        git.is_file() || git.join("HEAD").is_file()
    }) {
        return Ok(false);
    }
    fn command(root: &str) -> std::process::Command {
        let mut command = std::process::Command::new("git");
        command.args(["-c", "core.fsmonitor=false", "-C", root]);
        for name in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "GIT_COMMON_DIR",
            "GIT_CONFIG_PARAMETERS",
            "GIT_CONFIG_COUNT",
        ] {
            command.env_remove(name);
        }
        command.env("GIT_OPTIONAL_LOCKS", "0");
        command
    }
    // Status may execute clean/process filters to compare tracked files. Refuse
    // repositories configured with external filters before asking Git to inspect them.
    let filters = command(root)
        .args([
            "config",
            "--null",
            "--name-only",
            "--get-regexp",
            r"^filter\..*\.(clean|process)$",
        ])
        .output()
        .map_err(|_| {
            err("Git observation unavailable; install Git before applying this project.")
        })?;
    if filters.status.success() && !filters.stdout.is_empty() {
        return Err(err(
            "External Git filters are configured; use a separate plain sync directory.",
        ));
    }
    if !filters.status.success() && filters.status.code() != Some(1) {
        return Err(err("Git configuration could not be verified."));
    }
    let output = command(root)
        .args([
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--ignore-submodules=all",
            "--",
            ".",
        ])
        .output()
        .map_err(|_| {
            err("Git observation unavailable; install Git before applying this project.")
        })?;
    if !output.status.success() {
        return Err(err("Git state could not be verified; apply is blocked."));
    }
    Ok(!output.stdout.is_empty())
}
/// Shared native bridge. Browser clients never get a filesystem API.
pub fn dispatch(state_dir: &Path, request: Value) -> Result<Value> {
    let engine = Engine::open(state_dir)?;
    let value = match text(&request, "action")? {
        "list" => {
            json!({"pairs":engine.pairs()?,"plans":engine.plans()?,"events":engine.events()?})
        }
        "register" => json!(engine.register(
            text(&request, "name")?,
            Path::new(text(&request, "source")?),
            Path::new(text(&request, "target")?)
        )?),
        "preview" => json!(engine.preview(text(&request, "pair_id")?)?),
        "resolve_preview" => json!(engine.resolve_preview(
            text(&request, "pair_id")?,
            text(&request, "path")?,
            text(&request, "choice")?
        )?),
        "apply" | "rollback" => {
            json!(engine.apply(text(&request, "plan_id")?, text(&request, "approval")?)?)
        }
        "rollback_preview" => json!(engine.rollback_preview(text(&request, "plan_id")?)?),
        "events" => engine.events()?,
        "handoff" => {
            let pair_id = text(&request, "pair_id")?;
            let (p, _, revision) = engine.pair(pair_id)?;
            let (s, t) = engine.scans(&p)?;
            let pending=engine.plans()?.into_iter().filter(|p|p.pair_id==pair_id && matches!(p.state.as_str(),"planned"|"recovery_required")).map(|p|json!({"plan_id":p.id,"state":p.state,"conflicts":p.operations.iter().filter(|o|o.kind=="conflict").count(),"blockers":p.blockers})).collect::<Vec<_>>();
            json!({"pair_id":p.id,"revision":revision,"source_files":s.len(),"target_files":t.len(),"workspace_creation_allowed":false,"pending":pending,"forbidden":["secrets","generated files","Git mutations","filesystem apply via MCP"],"redaction_notice":"No root paths, project names, raw file contents, task text, or env values are included. Approval is required in the local app or CLI."})
        }
        _ => return Err(err("Unsupported local action.")),
    };
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Workspace {
        _temp: tempfile::TempDir,
        source: PathBuf,
        target: PathBuf,
        state: PathBuf,
    }
    impl Workspace {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let source = fs::canonicalize(temp.path()).unwrap().join("source");
            let target = fs::canonicalize(temp.path()).unwrap().join("target");
            let state = fs::canonicalize(temp.path()).unwrap().join("state");
            fs::create_dir(&source).unwrap();
            fs::create_dir(&target).unwrap();
            Self {
                _temp: temp,
                source,
                target,
                state,
            }
        }
        fn engine(&self) -> Engine {
            Engine::open(&self.state).unwrap()
        }
        fn register(&self, e: &Engine) -> Pair {
            e.register("Disposable test", &self.source, &self.target)
                .unwrap()
        }
        fn source(&self, path: &str, bytes: &[u8]) {
            let p = self.source.join(path);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, bytes).unwrap();
        }
        fn target(&self, path: &str, bytes: &[u8]) {
            let p = self.target.join(path);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, bytes).unwrap();
        }
    }
    #[test]
    fn restart_approval_idempotency_and_exact_preview() {
        let w = Workspace::new();
        w.source("src/main.rs", b"first");
        let e = w.engine();
        let p = w.register(&e);
        let plan = e.preview(&p.id).unwrap();
        assert_eq!(plan.operations.len(), 1);
        assert_eq!(plan.operations[0].kind, "copy");
        assert!(!w.target.join("src/main.rs").exists());
        assert!(e.apply(&plan.id, "yes").is_err());
        drop(e);
        let e = w.engine();
        assert_eq!(e.pairs().unwrap()[0].id, p.id);
        let receipt = e.apply(&plan.id, &plan.id).unwrap();
        assert_eq!(receipt.state, "verified");
        assert_eq!(fs::read(w.target.join("src/main.rs")).unwrap(), b"first");
        assert!(e.apply(&plan.id, &plan.id).unwrap().changed.is_empty());
        assert!(e.preview(&p.id).unwrap().operations.is_empty());
    }
    #[test]
    fn stale_source_target_and_metadata_revisions_refuse() {
        let w = Workspace::new();
        w.source("a", b"first");
        let e = w.engine();
        let p = w.register(&e);
        let first = e.preview(&p.id).unwrap();
        w.source("a", b"new source");
        assert!(e
            .apply(&first.id, &first.id)
            .unwrap_err()
            .to_string()
            .contains("stale"));
        let second = e.preview(&p.id).unwrap();
        w.target("b", b"independent edit");
        assert!(e.apply(&second.id, &second.id).is_err());
        assert!(!w.target.join("a").exists());
        fs::remove_file(w.target.join("b")).unwrap();
        let a = e.preview(&p.id).unwrap();
        let b = e.preview(&p.id).unwrap();
        e.apply(&a.id, &a.id).unwrap();
        assert!(e.apply(&b.id, &b.id).is_err());
    }
    #[test]
    fn conflict_preserves_both_and_resolution_is_separately_approved() {
        let w = Workspace::new();
        w.source("a", b"source");
        w.target("a", b"target");
        let e = w.engine();
        let p = w.register(&e);
        let plan = e.preview(&p.id).unwrap();
        assert_eq!(plan.operations[0].kind, "conflict");
        assert!(e.apply(&plan.id, &plan.id).is_err());
        assert_eq!(fs::read(w.target.join("a")).unwrap(), b"target");
        for bytes in [b"source".as_slice(), b"target".as_slice()] {
            assert_eq!(e.object(&hash(bytes)).unwrap(), bytes);
        }
        let resolution = e.resolve_preview(&p.id, "a", "both").unwrap();
        assert_eq!(resolution.operations.len(), 3);
        assert!(e.apply(&resolution.id, &plan.id).is_err());
        e.apply(&resolution.id, &resolution.id).unwrap();
        let sibling = format!("a.devdrop-conflict-{}", &hash(b"target")[..12]);
        assert_eq!(fs::read(w.target.join(&sibling)).unwrap(), b"target");
        assert_eq!(fs::read(w.source.join(&sibling)).unwrap(), b"target");
        assert_eq!(fs::read(w.target.join("a")).unwrap(), b"source");
        assert!(e.preview(&p.id).unwrap().operations.is_empty());
    }
    #[test]
    fn target_resolution_and_deletion_conflict_are_explicit() {
        let w = Workspace::new();
        w.source("a", b"source");
        w.target("a", b"target");
        let e = w.engine();
        let p = w.register(&e);
        let resolve = e.resolve_preview(&p.id, "a", "target").unwrap();
        assert_eq!(resolve.operations[0].side, "source");
        e.apply(&resolve.id, &resolve.id).unwrap();
        assert_eq!(fs::read(w.source.join("a")).unwrap(), b"target");
        fs::remove_file(w.target.join("a")).unwrap();
        let conflict = e.preview(&p.id).unwrap();
        assert_eq!(conflict.operations[0].kind, "conflict");
        assert!(e.apply(&conflict.id, &conflict.id).is_err());
    }
    #[test]
    fn approved_replace_delete_tombstone_restore_and_dirty_guard() {
        let w = Workspace::new();
        w.source("a", b"original");
        let e = w.engine();
        let p = w.register(&e);
        let initial = e.preview(&p.id).unwrap();
        e.apply(&initial.id, &initial.id).unwrap();
        w.source("a", b"updated");
        let update = e.preview(&p.id).unwrap();
        assert_eq!(update.operations[0].kind, "replace");
        e.apply(&update.id, &update.id).unwrap();
        let undo = e.rollback_preview(&update.id).unwrap();
        w.target("a", b"new local work");
        assert!(e.apply(&undo.id, &undo.id).is_err());
        assert!(e.rollback_preview(&update.id).is_err());
        w.target("a", b"updated");
        let undo = e.rollback_preview(&update.id).unwrap();
        e.apply(&undo.id, &undo.id).unwrap();
        assert_eq!(fs::read(w.target.join("a")).unwrap(), b"original");
        // Source differs again after rollback; resolve intentionally, then delete from the shared baseline.
        let resolution = e.resolve_preview(&p.id, "a", "source").unwrap();
        e.apply(&resolution.id, &resolution.id).unwrap();
        fs::remove_file(w.source.join("a")).unwrap();
        let deletion = e.preview(&p.id).unwrap();
        assert_eq!(deletion.operations[0].kind, "delete");
        assert!(w.target.join("a").exists());
        e.apply(&deletion.id, &deletion.id).unwrap();
        assert!(!w.target.join("a").exists());
        assert!(e
            .events()
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["kind"] == "tombstone"));
        let restore = e.rollback_preview(&deletion.id).unwrap();
        e.apply(&restore.id, &restore.id).unwrap();
        assert_eq!(fs::read(w.target.join("a")).unwrap(), b"updated");
    }
    #[test]
    fn interruption_reopen_and_partial_rollback_preserve_all_bytes() {
        let w = Workspace::new();
        w.source("a", b"alpha");
        w.source("b", b"bravo");
        let e = w.engine();
        let p = w.register(&e);
        let plan = e.preview(&p.id).unwrap();
        assert!(e.apply_inner(&plan.id, &plan.id, Some(1)).is_err());
        assert!(w.target.join("a").exists());
        assert!(!w.target.join("b").exists());
        drop(e);
        let e = w.engine();
        assert_eq!(e.plan(&plan.id).unwrap().state, "recovery_required");
        assert!(e.preview(&p.id).is_err());
        assert!(e.apply(&plan.id, &plan.id).is_err());
        let rollback = e.rollback_preview(&plan.id).unwrap();
        assert_eq!(rollback.operations.len(), 1);
        e.apply(&rollback.id, &rollback.id).unwrap();
        assert!(!w.target.join("a").exists());
        assert_eq!(fs::read(w.source.join("a")).unwrap(), b"alpha");
        assert_eq!(e.plan(&plan.id).unwrap().state, "rolled_back");
        assert_eq!(e.preview(&p.id).unwrap().operations.len(), 2);
    }
    #[test]
    fn interruption_before_checkpoint_recognizes_files_not_progress_counter() {
        let w = Workspace::new();
        w.source("a", b"alpha");
        let e = w.engine();
        let p = w.register(&e);
        let mut plan = e.preview(&p.id).unwrap();
        plan.state = "applying".into();
        e.save_plan(&plan).unwrap();
        e.write_operation(&p, &plan.operations[0], &plan.id, 0)
            .unwrap();
        drop(e);
        let e = w.engine();
        let rollback = e.rollback_preview(&plan.id).unwrap();
        assert_eq!(rollback.operations.len(), 1);
        e.apply(&rollback.id, &rollback.id).unwrap();
        assert!(!w.target.join("a").exists());
    }
    #[test]
    fn corruption_missing_objects_and_state_lock_fail_closed() {
        let w = Workspace::new();
        w.source("a", b"alpha");
        let e = w.engine();
        assert!(Engine::open(&w.state).is_err());
        let p = w.register(&e);
        let plan = e.preview(&p.id).unwrap();
        fs::write(w.state.join("objects").join(hash(b"alpha")), b"corrupt").unwrap();
        assert!(e.apply(&plan.id, &plan.id).is_err());
        assert!(!w.target.join("a").exists());
    }
    #[test]
    fn secrets_generated_gitignore_never_enter_objects_output_or_events() {
        let w = Workspace::new();
        let canary = ["DO", "NOT", "STORE", "VALUE"].join("_");
        w.source(".env", canary.as_bytes());
        w.source("nested/.env.production", canary.as_bytes());
        w.source("node_modules/pkg/file", canary.as_bytes());
        w.source("private.pem", canary.as_bytes());
        w.source(".git/config", canary.as_bytes());
        w.source("ignored.txt", canary.as_bytes());
        w.source(".gitignore", b"ignored.txt\n");
        w.source("a", b"normal");
        let e = w.engine();
        let p = w.register(&e);
        fs::remove_dir_all(w.source.join(".git")).unwrap();
        let plan = e.preview(&p.id).unwrap();
        assert!(!encode(&plan).unwrap().contains(&canary));
        assert!(!e.events().unwrap().to_string().contains(&canary));
        assert!(!w
            .state
            .join("objects")
            .join(hash(canary.as_bytes()))
            .exists());
        assert_eq!(plan.operations.len(), 2);
        e.apply(&plan.id, &plan.id).unwrap();
        assert!(!w.target.join(".env").exists());
        assert!(!w.target.join("ignored.txt").exists());
    }
    #[test]
    fn secret_patterns_fail_closed_and_do_not_leak() {
        let w = Workspace::new();
        let bytes = ["-----BEGIN ", "PRIVATE KEY-----"].concat();
        w.source("a", bytes.as_bytes());
        let e = w.engine();
        let p = w.register(&e);
        let error = e.preview(&p.id).unwrap_err().to_string();
        assert!(!error.contains(&bytes));
        assert!(!w
            .state
            .join("objects")
            .join(hash(bytes.as_bytes()))
            .exists());
    }
    #[test]
    fn overlap_portable_path_and_traversal_are_refused() {
        let w = Workspace::new();
        let e = w.engine();
        assert!(e.register("bad", &w.source, &w.source).is_err());
        let nested = w.source.join("nested");
        fs::create_dir(&nested).unwrap();
        assert!(e.register("bad", &w.source, &nested).is_err());
        assert!(e
            .register("bad", w.source.parent().unwrap(), &w.target)
            .is_err());
        for path in [
            "../outside",
            "/absolute",
            "C:/escape",
            "a\\b",
            ".env",
            "a/.env/x",
            "node_modules/a",
            "NUL.txt",
            "a.",
            "a?",
            "a\nvalue",
        ] {
            assert!(safe_path(path).is_err(), "{path}");
        }
    }
    #[test]
    #[cfg(unix)]
    fn symlinks_and_parent_swaps_cannot_escape_or_overwrite() {
        use std::os::unix::fs::symlink;
        let w = Workspace::new();
        w.source("nested/a", b"alpha");
        let outside = w._temp.path().join("outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("a"), b"outside").unwrap();
        let e = w.engine();
        let p = w.register(&e);
        let plan = e.preview(&p.id).unwrap();
        symlink(&outside, w.target.join("nested")).unwrap();
        assert!(e.apply(&plan.id, &plan.id).is_err());
        assert_eq!(fs::read(outside.join("a")).unwrap(), b"outside");
        fs::remove_file(w.target.join("nested")).unwrap();
        symlink(outside.join("a"), w.source.join("link")).unwrap();
        assert!(e.preview(&p.id).is_err());
    }
    #[test]
    fn no_op_plan_still_requires_approval_and_logs_verified_receipt() {
        let w = Workspace::new();
        let e = w.engine();
        let p = w.register(&e);
        let plan = e.preview(&p.id).unwrap();
        assert!(plan.operations.is_empty());
        assert!(e.apply(&plan.id, "").is_err());
        assert_eq!(e.apply(&plan.id, &plan.id).unwrap().state, "verified");
        assert!(e
            .events()
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["kind"] == "receipt"));
    }
    #[test]
    fn editor_race_before_quarantine_preserves_actual_displaced_bytes() {
        let w = Workspace::new();
        w.source("a", b"initial");
        let e = w.engine();
        let p = w.register(&e);
        let initial = e.preview(&p.id).unwrap();
        e.apply(&initial.id, &initial.id).unwrap();
        w.source("a", b"incoming");
        let mut plan = e.preview(&p.id).unwrap();
        plan.state = "applying".into();
        e.save_plan(&plan).unwrap();
        let result = e.write_operation_with_hook(&p, &plan.operations[0], &plan.id, 0, |stage| {
            if stage == "before_quarantine" {
                w.target("a", b"editor unsaved new work");
            }
        });
        assert!(result.is_err());
        let recovery = w
            .target
            .join(format!(".devdrop-recovery-{}-0/previous", plan.id));
        assert_eq!(fs::read(recovery).unwrap(), b"editor unsaved new work");
        assert!(!w.target.join("a").exists());
        assert!(e.rollback_preview(&plan.id).is_err());
    }
    #[test]
    fn editor_race_before_install_never_clobbers_recreated_target() {
        let w = Workspace::new();
        w.source("a", b"initial");
        let e = w.engine();
        let p = w.register(&e);
        let initial = e.preview(&p.id).unwrap();
        e.apply(&initial.id, &initial.id).unwrap();
        w.source("a", b"incoming");
        let plan = e.preview(&p.id).unwrap();
        let result = e.write_operation_with_hook(&p, &plan.operations[0], &plan.id, 0, |stage| {
            if stage == "before_install" {
                w.target("a", b"new independent file");
            }
        });
        assert!(result.is_err());
        assert_eq!(
            fs::read(w.target.join("a")).unwrap(),
            b"new independent file"
        );
        assert_eq!(
            fs::read(
                w.target
                    .join(format!(".devdrop-recovery-{}-0/previous", plan.id))
            )
            .unwrap(),
            b"initial"
        );
    }
    #[test]
    fn recovery_handles_crash_between_quarantine_and_install() {
        let w = Workspace::new();
        w.source("a", b"old");
        let e = w.engine();
        let p = w.register(&e);
        let initial = e.preview(&p.id).unwrap();
        e.apply(&initial.id, &initial.id).unwrap();
        w.source("a", b"new");
        let mut plan = e.preview(&p.id).unwrap();
        plan.state = "applying".into();
        e.save_plan(&plan).unwrap();
        let stage = w.target.join(format!(".devdrop-recovery-{}-0", plan.id));
        fs::create_dir(&stage).unwrap();
        fs::rename(w.target.join("a"), stage.join("previous")).unwrap();
        drop(e);
        let e = w.engine();
        let rollback = e.rollback_preview(&plan.id).unwrap();
        assert_eq!(rollback.operations[0].kind, "copy");
        e.apply(&rollback.id, &rollback.id).unwrap();
        assert_eq!(fs::read(w.target.join("a")).unwrap(), b"old");
    }
}
