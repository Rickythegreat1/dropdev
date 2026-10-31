//! FIXTURE-ONLY peer simulator, not a product transport or deployable authentication.
//! CLI artifacts may be relayed between fresh VMs externally; this program opens no sockets.
//! Only the fixed generated `src/shared.txt` payload namespace is accepted.
use devdrop_core::{
    file_permissions as access,
    local::{Engine, Pair, Plan},
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, &'static str>;
const SCHEMA: &str = "devdrop-fixture-peer/v1";
const PATH: &str = "src/shared.txt";
const ALICE: &str = "fixture-alice";
const BOB: &str = "fixture-bob";
const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const POLICY: &str = "platform-local-plain-readable-fixture";
const LIMIT: u64 = 64 * 1024;
// Public, fixed, TEST-ONLY key. Anyone can forge this tag; it is NOT authentication.
const PUBLIC_TEST_TAG_KEY: [u8; 32] = [0x42; 32];
const INITIAL: &str = "generated shared fixture, revision one\n";
const EDITED: &str = "generated shared fixture, revision two\n";
const LOCAL_EDIT: &str = "generated offline local edit fixture\n";

fn require(condition: bool, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message)
    }
}
fn io<T>(result: std::io::Result<T>) -> Result<T> {
    result.map_err(|_| "Generated fixture IO failed; no user tree is supported.")
}
fn sql<T>(result: rusqlite::Result<T>) -> Result<T> {
    result.map_err(|_| "Generated fixture journal failed.")
}
fn engine<T>(result: std::result::Result<T, devdrop_core::local::LocalError>) -> Result<T> {
    result.map_err(|_| "Fixture engine operation unexpectedly refused.")
}
fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| "Fixture encoding failed.")
}
fn digest(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
fn hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}
fn tag(domain: &str, value: &str) -> String {
    blake3::keyed_hash(
        &PUBLIC_TEST_TAG_KEY,
        format!("{domain}\0{value}").as_bytes(),
    )
    .to_hex()
    .to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    schema: String,
    session: String,
    sender: String,
    receiver: String,
    sequence: u64,
    previous_digest: String,
    path: String,
    policy: String,
    operation: String,
    payload: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Packet {
    body: Body,
    digest: String,
    public_test_tag: String,
}
impl Packet {
    fn fixture(session: &str, sequence: u64, previous_digest: &str) -> Result<Self> {
        let payload = match sequence {
            1 => Some(INITIAL.into()),
            2 => Some(EDITED.into()),
            3 => None,
            _ => return Err("Unsupported fixture sequence."),
        };
        let mut packet = Self {
            body: Body {
                schema: SCHEMA.into(),
                session: session.into(),
                sender: ALICE.into(),
                receiver: BOB.into(),
                sequence,
                previous_digest: previous_digest.into(),
                path: PATH.into(),
                policy: POLICY.into(),
                operation: if payload.is_some() { "write" } else { "delete" }.into(),
                payload,
            },
            digest: String::new(),
            public_test_tag: String::new(),
        };
        packet.retag()?;
        Ok(packet)
    }
    fn retag(&mut self) -> Result<()> {
        self.digest = digest(&encoded(&self.body)?);
        self.public_test_tag = tag("packet", &self.digest);
        Ok(())
    }
    fn validate(&self, session: &str) -> Result<()> {
        require(
            self.body.schema == SCHEMA && self.body.session == session && hex(session),
            "Unknown fixture session or schema.",
        )?;
        require(
            self.body.sender == ALICE && self.body.receiver == BOB,
            "Unknown fixture peer identity.",
        )?;
        require(
            self.body.path == PATH && self.body.policy == POLICY,
            "Unsupported fixture path or permission namespace.",
        )?;
        require(
            hex(&self.body.previous_digest),
            "Invalid fixture predecessor digest.",
        )?;
        let expected = match self.body.sequence {
            1 => Some(INITIAL),
            2 => Some(EDITED),
            3 => None,
            _ => return Err("Unsupported fixture sequence."),
        };
        require(
            self.body.payload.as_deref() == expected
                && self.body.operation
                    == if expected.is_some() {
                        "write"
                    } else {
                        "delete"
                    },
            "Only exact generated fixture payloads are accepted.",
        )?;
        require(
            self.digest == digest(&encoded(&self.body)?)
                && self.public_test_tag == tag("packet", &self.digest),
            "Fixture integrity tag mismatch.",
        )
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Offer {
    schema: String,
    simulator_only: bool,
    session: String,
    packets: Vec<Packet>,
}
impl Offer {
    fn validate(&self) -> Result<()> {
        require(
            self.schema == SCHEMA && self.simulator_only && self.packets.len() == 3,
            "Invalid bounded fixture offer.",
        )?;
        let mut previous = ZERO.to_owned();
        for (index, packet) in self.packets.iter().enumerate() {
            packet.validate(&self.session)?;
            require(
                packet.body.sequence == index as u64 + 1 && packet.body.previous_digest == previous,
                "Offer chain is not contiguous.",
            )?;
            previous = packet.digest.clone();
        }
        Ok(())
    }
    fn digest(&self) -> Result<String> {
        Ok(digest(&encoded(self)?))
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Check {
    name: String,
    passed: bool,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplyBody {
    schema: String,
    simulator_only: bool,
    receiver: String,
    session: String,
    offer_digest: String,
    accepted_digests: Vec<String>,
    received_sequence: u64,
    workspace_after_rollback_hash: String,
    preserved_conflict_hash: String,
    workspace_matches_latest_inbox: bool,
    checks: Vec<Check>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    body: ReplyBody,
    digest: String,
    public_test_tag: String,
}
const RECEIVER_CHECKS: &[&str] = &[
    "tamper_identity_traversal_and_namespace_refused",
    "journal_commit_stage_failure_restart_recovery",
    "accepted_packet_stages_private_inbox_only",
    "specific_plan_and_disposable_approval_required",
    "initial_transfer_verified",
    "withheld_update_out_of_order_delete_refused",
    "offline_local_edit_preserved_as_conflict",
    "explicit_keep_both_resolution_verified",
    "restart_duplicate_replay_is_inert",
    "altered_same_sequence_collision_refused",
    "delete_requires_preview_and_verified_apply",
    "retained_original_rollback_verified",
    "permission_widening_requires_extra_approval",
    "durable_receive_cursor_and_payloads_verified",
];
fn checks(names: &[&str]) -> Vec<Check> {
    names
        .iter()
        .map(|name| Check {
            name: (*name).into(),
            passed: true,
        })
        .collect()
}
fn evidence(
    phase: &str,
    offer_digest: Option<&str>,
    reply_digest: Option<&str>,
    checks: Vec<Check>,
) -> Value {
    json!({"schema":"devdrop-peer-simulation-evidence/v1","phase":phase,"simulator_only":true,
      "transport":if phase=="local"{"same-process-disposable-simulation"}else{"fixture-artifact-relay"},
      "production_transport":false,"direct_peer_tcp":false,"authentication":"public-test-tag-not-security",
      "execution_boundary":"One CLI process per phase; separate VM isolation and runtime observations are provided externally by CI.",
      "crash_model":"Injected failure after durable journal commit, followed by receiver reopen; no process-kill or host-power-loss claim.",
      "permission_policy":"Fixed fixture intent recreated on the receiver platform; artifact filesystem modes are never trusted as source permission evidence.",
      "runtime":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"process_id":std::process::id()},
      "offer_digest":offer_digest,"reply_digest":reply_digest,"checks":checks})
}

fn no_symlinks(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        io(std::env::current_dir())?.join(path)
    };
    require(
        !absolute
            .components()
            .any(|c| matches!(c, Component::ParentDir)),
        "Traversal in artifact root is unsupported.",
    )?;
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component);
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                require(
                    !metadata.file_type().is_symlink(),
                    "Symlink artifact roots are refused.",
                )?;
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    require(
                        metadata.file_attributes() & 0x400 == 0,
                        "Reparse artifact roots are refused.",
                    )?;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("Cannot verify artifact root safety."),
        }
    }
    Ok(())
}
fn planned_output(path: &Path) -> Result<PathBuf> {
    no_symlinks(path)?;
    let name = path
        .file_name()
        .ok_or("A new artifact directory name is required.")?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let parent = io(fs::canonicalize(parent))?;
    require(
        io(fs::metadata(&parent))?.is_dir(),
        "Artifact parent must be a directory.",
    )?;
    Ok(parent.join(name))
}
fn private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        io(fs::DirBuilder::new().mode(0o700).create(path))?;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let parent = path
            .parent()
            .ok_or("A private generated parent is required.")?;
        let parent_handle = io(OpenOptions::new()
            .read(true)
            .custom_flags(0x02000000 | 0x00200000)
            .open(parent))?;
        access::inspect_directory(&parent_handle).map_err(|_| {
            "Windows fixture output requires a canonical current-user private parent directory."
        })?;
        io(fs::create_dir(path))?;
        access::make_disposable_test_directory_private(path)
            .map_err(|_| "Cannot protect generated fixture directory.")?;
    }
    #[cfg(not(any(unix, windows)))]
    return Err("Private generated directories are unsupported on this platform.");
    Ok(())
}
struct GeneratedRoot(PathBuf);
impl GeneratedRoot {
    fn new(path: &Path, inputs: &[&Path]) -> Result<Self> {
        let path = planned_output(path)?;
        for input in inputs {
            let input = io(fs::canonicalize(input))?;
            require(
                !path.starts_with(&input) && !input.starts_with(&path),
                "Artifact output must be separate from imported inputs.",
            )?;
        }
        require(
            fs::symlink_metadata(&path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "Output directory must be new; existing paths are never overwritten.",
        )?;
        private_directory(&path)?;
        Ok(Self(path))
    }
    fn child(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
    fn directory(&self, name: &str) -> Result<PathBuf> {
        let path = self.child(name);
        private_directory(&path)?;
        Ok(path)
    }
}
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = io(options.open(path))?;
    io(file.write_all(bytes))?;
    io(file.sync_all())?;
    Ok(())
}
fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    write_new(path, &encoded(value)?)
}
fn read_manifest<T: serde::de::DeserializeOwned>(directory: &Path, name: &str) -> Result<T> {
    require(
        matches!(name, "offer.json" | "reply.json"),
        "Unknown manifest filename.",
    )?;
    no_symlinks(directory)?;
    require(
        io(fs::symlink_metadata(directory))?.is_dir(),
        "Artifact input must be a directory.",
    )?;
    let path = directory.join(name);
    let metadata = io(fs::symlink_metadata(&path))?;
    require(
        metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() <= LIMIT,
        "Manifest must be a bounded regular file, never a symlink.",
    )?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        require(
            metadata.file_attributes() & 0x400 == 0,
            "Reparse manifests are refused.",
        )?;
        options.custom_flags(0x00200000);
    }
    let file = io(options.open(&path))?;
    let metadata = io(file.metadata())?;
    require(
        metadata.is_file() && metadata.len() <= LIMIT,
        "Manifest changed type or exceeded budget.",
    )?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        require(
            metadata.file_attributes() & 0x400 == 0,
            "Reparse manifests are refused.",
        )?;
    }
    let mut bytes = Vec::new();
    io(file.take(LIMIT + 1).read_to_end(&mut bytes))?;
    require(
        bytes.len() as u64 <= LIMIT,
        "Manifest exceeded input budget.",
    )?;
    serde_json::from_slice(&bytes).map_err(|_| "Invalid strict fixture manifest.")
}
fn journal(path: &Path) -> Result<Connection> {
    let db = sql(Connection::open(path))?;
    sql(db.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;CREATE TABLE IF NOT EXISTS cursor(role TEXT PRIMARY KEY,session TEXT NOT NULL,sequence INTEGER NOT NULL,digest TEXT NOT NULL);CREATE TABLE IF NOT EXISTS packets(sequence INTEGER PRIMARY KEY,digest TEXT NOT NULL,packet TEXT NOT NULL,staged INTEGER NOT NULL);"))?;
    Ok(db)
}
fn set_plain(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        io(fs::set_permissions(path, fs::Permissions::from_mode(0o644)))?;
    }
    #[cfg(windows)]
    {
        let mut p = io(fs::metadata(path))?.permissions();
        p.set_readonly(false);
        io(fs::set_permissions(path, p))?;
    }
    Ok(())
}
fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    io(io(File::open(path))?.sync_all())?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}
fn write_fixture(root: &Path, value: &str) -> Result<()> {
    let src = root.join("src");
    if !src.exists() {
        private_directory(&src)?;
        sync_directory(root)?;
    }
    let path = root.join(PATH);
    if path.exists() {
        set_plain(&path)?;
    }
    io(fs::write(&path, value.as_bytes()))?;
    set_plain(&path)?;
    io(io(OpenOptions::new().read(true).write(true).open(&path))?.sync_all())?;
    sync_directory(&src)
}
fn fixture_hash(root: &Path) -> Result<Option<String>> {
    let path = root.join(PATH);
    match fs::read(path) {
        Ok(bytes) => Ok(Some(digest(&bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err("Cannot verify generated fixture content."),
    }
}
fn approved(engine_ref: &Engine, plan: &Plan) -> Result<()> {
    require(
        matches!(
            engine(engine_ref.apply(&plan.id, &plan.id, true, true))?
                .state
                .as_str(),
            "verified" | "rolled_back"
        ),
        "Fixture apply did not verify.",
    )
}
fn new_session(root: &GeneratedRoot) -> Result<String> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Clock unavailable for fixture session label.")?
        .as_nanos();
    Ok(digest(
        format!(
            "fixture-session:{}:{}:{}",
            std::process::id(),
            nanos,
            root.0.file_name().unwrap_or_default().to_string_lossy()
        )
        .as_bytes(),
    ))
}

fn offer_phase(output: &Path) -> Result<Value> {
    let root = GeneratedRoot::new(output, &[])?;
    let source = root.directory("producer-source")?;
    let target = root.directory("producer-replica")?;
    let state = root.child("producer-state");
    let engine_ref = engine(Engine::open(&state))?;
    let pair = engine(engine_ref.register("Generated producer fixture", &source, &target))?;
    let session = new_session(&root)?;
    let mut db = journal(&root.child("send.sqlite3"))?;
    sql(db.execute(
        "INSERT INTO cursor VALUES('send',?1,0,?2)",
        params![session, ZERO],
    ))?;
    let mut packets = Vec::new();
    let mut previous = ZERO.to_owned();
    for sequence in 1..=3 {
        match sequence {
            1 => write_fixture(&source, INITIAL)?,
            2 => write_fixture(&source, EDITED)?,
            _ => io(fs::remove_file(source.join(PATH)))?,
        };
        let plan = engine(engine_ref.preview(&pair.id))?;
        approved(&engine_ref, &plan)?;
        let packet = Packet::fixture(&session, sequence, &previous)?;
        let transaction = sql(db.transaction())?;
        sql(transaction.execute(
            "INSERT INTO packets VALUES(?1,?2,?3,1)",
            params![
                sequence,
                packet.digest,
                String::from_utf8(encoded(&packet)?).map_err(|_| "Fixture encoding failed.")?
            ],
        ))?;
        sql(transaction.execute(
            "UPDATE cursor SET sequence=?1,digest=?2 WHERE role='send'",
            params![sequence, packet.digest],
        ))?;
        sql(transaction.commit())?;
        previous = packet.digest.clone();
        packets.push(packet);
    }
    sql(db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);"))?;
    drop(db);
    drop(engine_ref);
    let db = journal(&root.child("send.sqlite3"))?;
    require(
        sql(
            db.query_row("SELECT sequence FROM cursor WHERE role='send'", [], |r| {
                r.get::<_, u64>(0)
            }),
        )? == 3,
        "Send cursor did not survive reopen.",
    )?;
    require(
        sql(db.query_row("SELECT count(*) FROM packets", [], |r| r.get::<_, u64>(0)))? == 3,
        "Send journal lost fixture packets.",
    )?;
    drop(db);
    let offer = Offer {
        schema: SCHEMA.into(),
        simulator_only: true,
        session,
        packets,
    };
    offer.validate()?;
    let offer_digest = offer.digest()?;
    write_json(&root.child("offer.json"), &offer)?;
    let report = evidence(
        "offer",
        Some(&offer_digest),
        None,
        checks(&[
            "generated_sender_engine_three_verified_receipts",
            "durable_send_cursor_and_packets_verified",
            "offer_chain_integrity_verified",
        ]),
    );
    write_json(&root.child("evidence.json"), &report)?;
    Ok(report)
}

#[derive(Debug, PartialEq, Eq)]
enum Acceptance {
    Staged,
    Duplicate,
    DuplicatePendingRecovery,
}
struct Receiver {
    root: PathBuf,
    inbox: PathBuf,
    workspace: PathBuf,
    db: Connection,
    engine: Engine,
    pair: Pair,
    session: String,
}
impl Receiver {
    fn open(root: &GeneratedRoot, session: &str) -> Result<Self> {
        let inbox = root.child("inbox");
        let workspace = root.child("workspace");
        for path in [&inbox, &workspace] {
            if !path.exists() {
                private_directory(path)?;
            }
        }
        let db = journal(&root.child("receive.sqlite3"))?;
        sql(db.execute(
            "INSERT OR IGNORE INTO cursor VALUES('receive',?1,0,?2)",
            params![session, ZERO],
        ))?;
        let saved: String = sql(db.query_row(
            "SELECT session FROM cursor WHERE role='receive'",
            [],
            |r| r.get(0),
        ))?;
        require(
            saved == session,
            "Receiver journal belongs to another fixture session.",
        )?;
        let engine_ref = engine(Engine::open(&root.child("receiver-state")))?;
        let pairs = engine(engine_ref.pairs())?;
        let pair = if let Some(pair) = pairs
            .into_iter()
            .find(|p| p.name == "Generated receiver fixture")
        {
            pair
        } else {
            engine(engine_ref.register("Generated receiver fixture", &inbox, &workspace))?
        };
        require(
            Path::new(&pair.source) == inbox && Path::new(&pair.target) == workspace,
            "Receiver root mapping is not its generated inbox/workspace.",
        )?;
        let mut receiver = Self {
            root: root.0.clone(),
            inbox,
            workspace,
            db,
            engine: engine_ref,
            pair,
            session: session.into(),
        };
        let pending: Option<String> = sql(receiver
            .db
            .query_row(
                "SELECT packet FROM packets WHERE staged=0 ORDER BY sequence DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional())?;
        if let Some(body) = pending {
            let packet: Packet = serde_json::from_str(&body)
                .map_err(|_| "Pending generated journal packet is invalid.")?;
            packet.validate(session)?;
            receiver.stage(&packet)?;
        }
        Ok(receiver)
    }
    fn cursor(&self) -> Result<(u64, String)> {
        sql(self.db.query_row(
            "SELECT sequence,digest FROM cursor WHERE role='receive'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))
    }
    fn accept(&mut self, packet: &Packet, interrupt_after_commit: bool) -> Result<Acceptance> {
        packet.validate(&self.session)?;
        let (sequence, previous) = self.cursor()?;
        if packet.body.sequence <= sequence {
            let accepted: Option<(String, i64)> = sql(self
                .db
                .query_row(
                    "SELECT digest,staged FROM packets WHERE sequence=?1",
                    [packet.body.sequence],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional())?;
            return match accepted {
                Some((same, staged)) if same == packet.digest => Ok(if staged == 1 {
                    Acceptance::Duplicate
                } else {
                    Acceptance::DuplicatePendingRecovery
                }),
                _ => Err("Same-sequence collision refused."),
            };
        }
        require(
            packet.body.sequence == sequence + 1 && packet.body.previous_digest == previous,
            "Gap or reordered fixture packet refused.",
        )?;
        require(
            sql(self
                .db
                .query_row("SELECT count(*) FROM packets WHERE staged=0", [], |r| {
                    r.get::<_, u64>(0)
                }))?
                == 0,
            "Recover pending inbox staging before accepting another packet.",
        )?;
        let transaction = sql(self.db.transaction())?;
        sql(transaction.execute(
            "INSERT INTO packets VALUES(?1,?2,?3,0)",
            params![
                packet.body.sequence,
                packet.digest,
                String::from_utf8(encoded(packet)?).map_err(|_| "Fixture encoding failed.")?
            ],
        ))?;
        sql(transaction.execute(
            "UPDATE cursor SET sequence=?1,digest=?2 WHERE role='receive'",
            params![packet.body.sequence, packet.digest],
        ))?;
        sql(transaction.commit())?;
        if interrupt_after_commit {
            return Err("Injected failure after accepted journal commit; private inbox recovery is pending.");
        }
        self.stage(packet)?;
        Ok(Acceptance::Staged)
    }
    fn stage(&mut self, packet: &Packet) -> Result<()> {
        packet.validate(&self.session)?;
        match packet.body.payload.as_deref() {
            Some(value) => write_fixture(&self.inbox, value)?,
            None => {
                let path = self.inbox.join(PATH);
                if path.exists() {
                    set_plain(&path)?;
                    io(fs::remove_file(path))?;
                    sync_directory(&self.inbox.join("src"))?;
                }
            }
        }
        sql(self.db.execute(
            "UPDATE packets SET staged=1 WHERE sequence=?1 AND digest=?2",
            params![packet.body.sequence, packet.digest],
        ))?;
        Ok(())
    }
    fn preview(&self) -> Result<Plan> {
        require(
            sql(self
                .db
                .query_row("SELECT count(*) FROM packets WHERE staged=0", [], |r| {
                    r.get::<_, u64>(0)
                }))?
                == 0,
            "Pending accepted packet must be staged before a workspace preview.",
        )?;
        engine(self.engine.preview(&self.pair.id))
    }
}

fn permission_scenario(receiver: &Receiver) -> Result<()> {
    let source = receiver.root.join("mode-source");
    let target = receiver.root.join("mode-target");
    private_directory(&source)?;
    private_directory(&target)?;
    write_fixture(&source, INITIAL)?;
    let file = source.join(PATH);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        io(fs::set_permissions(
            &file,
            fs::Permissions::from_mode(0o600),
        ))?;
    }
    #[cfg(windows)]
    {
        let mut permissions = io(fs::metadata(&file))?.permissions();
        permissions.set_readonly(true);
        io(fs::set_permissions(&file, permissions))?;
    }
    let pair = engine(
        receiver
            .engine
            .register("Generated permission fixture", &source, &target),
    )?;
    let first = engine(receiver.engine.preview(&pair.id))?;
    approved(&receiver.engine, &first)?;
    let before = access::inspect_file(&io(File::open(target.join(PATH)))?)
        .map_err(|_| "Cannot inspect generated permission fixture.")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        io(fs::set_permissions(
            &file,
            fs::Permissions::from_mode(0o700),
        ))?;
    }
    #[cfg(windows)]
    {
        let mut permissions = io(fs::metadata(&file))?.permissions();
        permissions.set_readonly(false);
        io(fs::set_permissions(&file, permissions))?;
    }
    let widening = engine(receiver.engine.preview(&pair.id))?;
    require(
        widening.operations.iter().any(|o| o.permission_widening),
        "Permission fixture did not identify widening.",
    )?;
    require(
        receiver
            .engine
            .apply(&widening.id, &widening.id, true, false)
            .is_err(),
        "Permission widening applied without extra approval.",
    )?;
    require(
        access::inspect_file(&io(File::open(target.join(PATH)))?)
            .map_err(|_| "Cannot inspect generated permissions.")?
            == before,
        "Refused widening changed the generated target.",
    )?;
    approved(&receiver.engine, &widening)?;
    let undo = engine(receiver.engine.rollback_preview(&widening.id))?;
    approved(&receiver.engine, &undo)?;
    require(
        access::inspect_file(&io(File::open(target.join(PATH)))?)
            .map_err(|_| "Cannot inspect restored generated permissions.")?
            == before,
        "Permission rollback did not restore metadata.",
    )
}
fn file_identity(path: &Path) -> Result<String> {
    Ok(access::inspect_file(&io(File::open(path))?)
        .map_err(|_| "Cannot inspect generated retained-file identity.")?
        .guard)
}
fn receive_phase(input: &Path, output: &Path) -> Result<Value> {
    let offer: Offer = read_manifest(input, "offer.json")?;
    offer.validate()?;
    let offer_digest = offer.digest()?;
    let root = GeneratedRoot::new(output, &[input])?;
    let mut receiver = Receiver::open(&root, &offer.session)?;
    // All negative packets are generated here; no arbitrary import API is exposed.
    for mutation in 0..5 {
        let mut bad = offer.packets[0].clone();
        match mutation {
            0 => bad.public_test_tag = ZERO.into(),
            1 => {
                bad.body.sender = "unknown-fixture-peer".into();
                bad.retag()?;
            }
            2 => {
                bad.body.path = "../outside".into();
                bad.retag()?;
            }
            3 => {
                bad.body.path = ".env".into();
                bad.retag()?;
            }
            _ => {
                bad.body.session = digest(b"different fixture session");
                bad.retag()?;
            }
        }
        require(
            receiver.accept(&bad, false).is_err(),
            "Invalid fixture packet was accepted.",
        )?;
        require(
            receiver.cursor()?.0 == 0 && fixture_hash(&receiver.workspace)?.is_none(),
            "Invalid packet changed cursor or workspace.",
        )?;
    }
    require(
        receiver.accept(&offer.packets[0], true).is_err(),
        "Stage interruption injection did not fire.",
    )?;
    require(
        receiver.cursor()?.0 == 1 && fixture_hash(&receiver.workspace)?.is_none(),
        "Accepted pending packet changed workspace.",
    )?;
    require(
        receiver.preview().is_err(),
        "Unstaged accepted packet allowed workspace preview.",
    )?;
    require(
        receiver.accept(&offer.packets[0], false)? == Acceptance::DuplicatePendingRecovery,
        "Pending duplicate was not distinguished.",
    )?;
    drop(receiver);
    let mut receiver = Receiver::open(&root, &offer.session)?;
    require(
        fixture_hash(&receiver.inbox)? == Some(digest(INITIAL.as_bytes()))
            && fixture_hash(&receiver.workspace)?.is_none(),
        "Restart did not recover private inbox only.",
    )?;
    let first = receiver.preview()?;
    require(
        receiver
            .engine
            .apply(&first.id, "wrong-preview", true, true)
            .is_err(),
        "Apply ignored exact-plan approval.",
    )?;
    require(
        receiver
            .engine
            .apply(&first.id, &first.id, false, true)
            .is_err(),
        "Apply ignored disposable acknowledgement.",
    )?;
    require(
        fixture_hash(&receiver.workspace)?.is_none(),
        "Refused approval changed workspace.",
    )?;
    approved(&receiver.engine, &first)?;
    require(
        fixture_hash(&receiver.workspace)? == Some(digest(INITIAL.as_bytes())),
        "Initial verified transfer hash mismatch.",
    )?;
    require(
        receiver.accept(&offer.packets[2], false).is_err() && receiver.cursor()?.0 == 1,
        "Out-of-order deletion crossed the withheld update.",
    )?;
    write_fixture(&receiver.workspace, LOCAL_EDIT)?;
    require(
        receiver.accept(&offer.packets[1], false)? == Acceptance::Staged,
        "Reconnect update did not stage.",
    )?;
    require(
        fixture_hash(&receiver.workspace)? == Some(digest(LOCAL_EDIT.as_bytes())),
        "Packet staging overwrote offline local work.",
    )?;
    let conflict = receiver.preview()?;
    require(
        conflict.operations.iter().any(|o| o.kind == "conflict"),
        "Offline edit conflict was hidden.",
    )?;
    require(
        receiver
            .engine
            .apply(&conflict.id, &conflict.id, true, true)
            .is_err(),
        "Unresolved conflict was applied.",
    )?;
    let resolution = engine(
        receiver
            .engine
            .resolve_preview(&receiver.pair.id, PATH, "both"),
    )?;
    approved(&receiver.engine, &resolution)?;
    let preserved = receiver.workspace.join(format!(
        "{PATH}.devdrop-conflict-{}",
        &digest(LOCAL_EDIT.as_bytes())[..12]
    ));
    require(
        digest(&io(fs::read(&preserved))?) == digest(LOCAL_EDIT.as_bytes())
            && fixture_hash(&receiver.workspace)? == Some(digest(EDITED.as_bytes())),
        "Explicit keep-both did not preserve both versions.",
    )?;
    drop(receiver);
    let mut receiver = Receiver::open(&root, &offer.session)?;
    let events_before = encoded(&engine(receiver.engine.events())?)?;
    require(
        receiver.accept(&offer.packets[1], false)? == Acceptance::Duplicate,
        "Exact duplicate was not inert replay.",
    )?;
    require(
        encoded(&engine(receiver.engine.events())?)? == events_before,
        "Duplicate replay mutated engine receipts.",
    )?;
    let mut collision = offer.packets[1].clone();
    collision.body.previous_digest = ZERO.into();
    collision.retag()?;
    require(
        receiver.accept(&collision, false).is_err(),
        "Altered same-sequence packet was accepted.",
    )?;
    let prior_identity = file_identity(&receiver.workspace.join(PATH))?;
    let prior_access = access::inspect_file(&io(File::open(receiver.workspace.join(PATH)))?)
        .map_err(|_| "Cannot inspect retained fixture metadata.")?;
    require(
        receiver.accept(&offer.packets[2], false)? == Acceptance::Staged,
        "Deletion intent did not stage.",
    )?;
    require(
        fixture_hash(&receiver.workspace)? == Some(digest(EDITED.as_bytes())),
        "Staging deletion removed workspace content.",
    )?;
    let deletion = receiver.preview()?;
    require(
        deletion
            .operations
            .iter()
            .any(|o| o.path == PATH && o.kind == "delete"),
        "Deletion preview omitted intent.",
    )?;
    approved(&receiver.engine, &deletion)?;
    require(
        fixture_hash(&receiver.workspace)?.is_none(),
        "Verified deletion did not remove fixture target.",
    )?;
    let undo = engine(receiver.engine.rollback_preview(&deletion.id))?;
    approved(&receiver.engine, &undo)?;
    require(
        fixture_hash(&receiver.workspace)? == Some(digest(EDITED.as_bytes()))
            && file_identity(&receiver.workspace.join(PATH))? == prior_identity,
        "Retained original did not restore.",
    )?;
    require(
        access::inspect_file(&io(File::open(receiver.workspace.join(PATH)))?)
            .map_err(|_| "Cannot inspect restored fixture metadata.")?
            == prior_access,
        "Retained rollback changed supported metadata.",
    )?;
    permission_scenario(&receiver)?;
    let accepted: Vec<String> = {
        let mut query = sql(receiver
            .db
            .prepare("SELECT digest FROM packets ORDER BY sequence"))?;
        let rows = sql(query.query_map([], |r| r.get::<_, String>(0)))?;
        rows.map(sql).collect::<Result<Vec<_>>>()?
    };
    require(
        receiver.cursor()?.0 == 3
            && accepted
                == offer
                    .packets
                    .iter()
                    .map(|p| p.digest.clone())
                    .collect::<Vec<_>>(),
        "Durable receiver chain differs from offer.",
    )?;
    sql(receiver
        .db
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);"))?;
    drop(receiver);
    let receiver = Receiver::open(&root, &offer.session)?;
    require(
        receiver.cursor()?.0 == 3,
        "Receiver cursor did not survive final reopen.",
    )?;
    {
        let mut query = sql(receiver
            .db
            .prepare("SELECT sequence,digest,packet,staged FROM packets ORDER BY sequence"))?;
        let rows = sql(query.query_map([], |row| {
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        }))?;
        let mut count = 0;
        for row in rows {
            let (sequence, saved_digest, saved_json, staged) = sql(row)?;
            let packet: Packet = serde_json::from_str(&saved_json)
                .map_err(|_| "Reopened accepted packet payload is invalid.")?;
            packet.validate(&offer.session)?;
            let expected = offer
                .packets
                .get(count)
                .ok_or("Reopened accepted journal contains extra packets.")?;
            require(sequence==expected.body.sequence && saved_digest==expected.digest && staged==1 && encoded(&packet)?==encoded(expected)?,"Reopened accepted packet payload, sequence, digest or staged flag differs from offer.")?;
            count += 1;
        }
        require(
            count == offer.packets.len(),
            "Reopened accepted packet payloads are incomplete.",
        )?;
    }
    let body = ReplyBody {
        schema: SCHEMA.into(),
        simulator_only: true,
        receiver: BOB.into(),
        session: offer.session,
        offer_digest: offer_digest.clone(),
        accepted_digests: accepted,
        received_sequence: 3,
        workspace_after_rollback_hash: digest(EDITED.as_bytes()),
        preserved_conflict_hash: digest(LOCAL_EDIT.as_bytes()),
        workspace_matches_latest_inbox: false,
        checks: checks(RECEIVER_CHECKS),
    };
    let reply_digest = digest(&encoded(&body)?);
    let reply = Reply {
        body,
        digest: reply_digest.clone(),
        public_test_tag: tag("reply", &reply_digest),
    };
    write_json(&root.child("reply.json"), &reply)?;
    let mut report = evidence(
        "receive",
        Some(&offer_digest),
        Some(&reply_digest),
        checks(RECEIVER_CHECKS),
    );
    report["retained_inode_observation"] = json!("opened-file-identity-and-access-guard-match");
    report["workspace_matches_latest_inbox"] = json!(false);
    report["workspace_state"] = json!(
        "Intentionally restored after approved deletion; latest imported intent remains deletion."
    );
    write_json(&root.child("evidence.json"), &report)?;
    Ok(report)
}
fn verify_phase(offer_dir: &Path, reply_dir: &Path, output: &Path) -> Result<Value> {
    let offer: Offer = read_manifest(offer_dir, "offer.json")?;
    offer.validate()?;
    let reply: Reply = read_manifest(reply_dir, "reply.json")?;
    require(
        reply.body.schema == SCHEMA
            && reply.body.simulator_only
            && reply.body.receiver == BOB
            && reply.body.session == offer.session,
        "Reply fixture identity/session mismatch.",
    )?;
    let offer_digest = offer.digest()?;
    require(
        reply.body.offer_digest == offer_digest,
        "Reply is not bound to the offered fixture bundle.",
    )?;
    require(
        reply.digest == digest(&encoded(&reply.body)?)
            && reply.public_test_tag == tag("reply", &reply.digest),
        "Reply integrity tag mismatch.",
    )?;
    require(
        reply.body.accepted_digests
            == offer
                .packets
                .iter()
                .map(|p| p.digest.clone())
                .collect::<Vec<_>>()
            && reply.body.received_sequence == 3,
        "Reply accepted chain does not match offer.",
    )?;
    require(
        reply.body.workspace_after_rollback_hash == digest(EDITED.as_bytes())
            && reply.body.preserved_conflict_hash == digest(LOCAL_EDIT.as_bytes())
            && !reply.body.workspace_matches_latest_inbox,
        "Reply fixture outcome mismatch.",
    )?;
    require(
        reply.body.checks.len() == RECEIVER_CHECKS.len()
            && reply
                .body
                .checks
                .iter()
                .zip(RECEIVER_CHECKS)
                .all(|(check, name)| check.name == *name && check.passed),
        "Reply did not report every bounded scenario.",
    )?;
    let root = GeneratedRoot::new(output, &[offer_dir, reply_dir])?;
    let mut report = evidence(
        "verify",
        Some(&offer_digest),
        Some(&reply.digest),
        checks(&[
            "bounded_offer_and_reply_integrity_verified",
            "offer_digest_reply_binding_verified",
            "accepted_packet_chain_verified",
            "all_receiver_scenario_receipts_present",
            "expected_conflict_and_rollback_hashes_verified",
        ]),
    );
    report["verifier_identity"] =
        json!("Fresh verifier invocation, not the original producer and not a network peer.");
    report["trust_limit"]=json!("Public fixture tags and receipts are simulation evidence, not deployable authentication or independent proof that workspace actions occurred.");
    write_json(&root.child("verification.json"), &report)?;
    write_json(&root.child("evidence.json"), &report)?;
    Ok(report)
}
fn local_phase() -> Result<Value> {
    let temp = io(tempfile::tempdir())?;
    let base = io(fs::canonicalize(temp.path()))?;
    #[cfg(windows)]
    access::make_disposable_test_directory_private(&base)
        .map_err(|_| "Cannot protect generated simulation root.")?;
    let offer = base.join("offer");
    let reply = base.join("reply");
    let verification = base.join("verification");
    offer_phase(&offer)?;
    receive_phase(&offer, &reply)?;
    let mut report = verify_phase(&offer, &reply, &verification)?;
    report["phase"] = json!("local");
    report["transport"] = json!("same-process-disposable-simulation");
    report["execution_boundary"]=json!("All three roles ran in one process with separate generated roots, states, CAS stores and journals; no VM or direct network boundary was crossed.");
    report["checks"] =
        serde_json::to_value(checks(RECEIVER_CHECKS)).map_err(|_| "Evidence encoding failed.")?;
    Ok(report)
}
fn arguments() -> Result<Value> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["local"]=>local_phase(),
        ["offer","--output",output]=>offer_phase(Path::new(output)),
        ["receive","--input",input,"--output",output]=>receive_phase(Path::new(input),Path::new(output)),
        ["verify","--offer",offer,"--reply",reply,"--output",output]=>verify_phase(Path::new(offer),Path::new(reply),Path::new(output)),
        _=>Err("Usage: peer_simulation local | offer --output NEWDIR | receive --input OFFERDIR --output NEWDIR | verify --offer OFFERDIR --reply REPLYDIR --output NEWDIR"),
    }
}
fn main() {
    match arguments() {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(text) => println!("{text}"),
            Err(_) => {
                eprintln!("Sanitized evidence encoding failed.");
                std::process::exit(1);
            }
        },
        Err(message) => {
            eprintln!("{message}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        access::make_disposable_test_directory_private(&fs::canonicalize(temp.path()).unwrap())
            .unwrap();
        temp
    }
    #[test]
    fn all_bounded_local_peer_scenarios_and_safe_evidence() {
        let report = local_phase().expect("Generated simulator scenarios must pass.");
        assert!(report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["passed"] == true));
        let serialized = serde_json::to_string(&report).unwrap();
        for forbidden in [
            INITIAL.trim_end(),
            EDITED.trim_end(),
            LOCAL_EDIT.trim_end(),
            "\"public_test_tag\":",
            "\"payload\":",
            "/tmp/",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "Evidence must omit fixture contents, tags and paths."
            );
        }
        assert_eq!(report["transport"], "same-process-disposable-simulation");
        assert_eq!(report["production_transport"], false);
    }
    #[test]
    fn strict_input_budgets_and_new_output_boundary() {
        let temp = temp();
        let base = fs::canonicalize(temp.path()).unwrap();
        let offer = base.join("offer");
        offer_phase(&offer).unwrap();
        assert!(offer_phase(&offer).is_err());
        assert!(receive_phase(&offer, &offer.join("nested-output")).is_err());
        let oversized = base.join("oversized");
        private_directory(&oversized).unwrap();
        write_new(
            &oversized.join("offer.json"),
            &vec![b' '; LIMIT as usize + 1],
        )
        .unwrap();
        assert!(read_manifest::<Offer>(&oversized, "offer.json").is_err());
        let mut value: Value =
            serde_json::from_slice(&fs::read(offer.join("offer.json")).unwrap()).unwrap();
        value["unexpected"] = json!(true);
        assert!(serde_json::from_value::<Offer>(value).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let linked = base.join("linked-root");
            symlink(&offer, &linked).unwrap();
            assert!(read_manifest::<Offer>(&linked, "offer.json").is_err());
            let inside = base.join("linked-manifest");
            private_directory(&inside).unwrap();
            symlink(offer.join("offer.json"), inside.join("offer.json")).unwrap();
            assert!(read_manifest::<Offer>(&inside, "offer.json").is_err());
            assert!(offer_phase(&base.join("linked-output")).is_ok());
            let linked_output = base.join("output-symlink");
            symlink(base.join("linked-output"), &linked_output).unwrap();
            assert!(offer_phase(&linked_output).is_err());
        }
    }
    #[test]
    fn fresh_verifier_rejects_changed_reply_and_wrong_offer_binding() {
        let temp = temp();
        let base = fs::canonicalize(temp.path()).unwrap();
        let offer = base.join("offer");
        let reply = base.join("reply");
        offer_phase(&offer).unwrap();
        receive_phase(&offer, &reply).unwrap();
        let mut receipt: Reply = read_manifest(&reply, "reply.json").unwrap();
        receipt.body.offer_digest = ZERO.into();
        receipt.digest = digest(&encoded(&receipt.body).unwrap());
        receipt.public_test_tag = tag("reply", &receipt.digest);
        let altered = base.join("altered");
        private_directory(&altered).unwrap();
        write_json(&altered.join("reply.json"), &receipt).unwrap();
        assert!(verify_phase(&offer, &altered, &base.join("rejected-verifier-output")).is_err());
        assert!(!base.join("rejected-verifier-output").exists());
    }
}
