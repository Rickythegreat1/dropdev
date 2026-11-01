//! Private bounded proposal journal. This module never applies a project file.
use crate::{
    pairing::{Paired, Scope},
    wire::{Envelope, Receipt, ReceiptStatus},
    PeerError, PeerResult,
};
use devdrop_core::file_permissions as access;
use fs2::FileExt;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::Duration,
};

const ZERO: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_STORED_MESSAGES: u64 = 64;
const MAX_STORED_BYTES: u64 = 1024 * 1024;
const MAX_ENVELOPE_BYTES: usize = 32 * 1024;
const APPLICATION_ID: u32 = 0x44565051;
const MARKER: &[u8] = b"devdrop-private-peer-queue-v1\n";
/// Exact immutable wire proposal reference for local review and approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalRef {
    pub pairing_id: String,
    pub sequence: u64,
    pub digest: String,
}
fn io<T>(value: std::io::Result<T>) -> PeerResult<T> {
    value.map_err(|_| PeerError("Private peer queue filesystem operation failed."))
}
fn sql<T>(value: rusqlite::Result<T>) -> PeerResult<T> {
    value.map_err(|_| PeerError("Private peer queue metadata is unavailable; preserve its state."))
}
fn require(value: bool, reason: &'static str) -> PeerResult<()> {
    if value {
        Ok(())
    } else {
        Err(PeerError(reason))
    }
}
fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn no_symlinks(path: &Path) -> PeerResult<()> {
    require(path.is_absolute(), "Peer queue paths must be absolute.")?;
    let mut current = PathBuf::new();
    for component in path.components() {
        require(
            !matches!(component, Component::ParentDir | Component::CurDir),
            "Peer queue path traversal is refused.",
        )?;
        current.push(component);
        if matches!(component, Component::Prefix(_)) {
            continue;
        }
        if let Some(name) = component.as_os_str().to_str() {
            require(
                !matches!(
                    name.to_ascii_lowercase().as_str(),
                    ".aws" | ".ssh" | ".gnupg" | ".git" | ".azure"
                ),
                "Credential and repository metadata directories cannot contain a peer queue.",
            )?;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                require(
                    !metadata.file_type().is_symlink(),
                    "Symlink peer queue paths are refused.",
                )?;
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    require(
                        metadata.file_attributes() & 0x400 == 0,
                        "Reparse peer queue paths are refused.",
                    )?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(PeerError("Cannot inspect peer queue path safety.")),
        }
    }
    Ok(())
}
fn directory(path: &Path) -> PeerResult<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x02000000 | 0x00200000);
    }
    io(options.open(path))
}
fn private_directory(path: &Path) -> PeerResult<()> {
    require(
        io(fs::symlink_metadata(path))?.is_dir(),
        "Peer queue root must be a directory.",
    )?;
    let file = directory(path)?;
    access::inspect_directory(&file).map_err(PeerError)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        require(
            io(file.metadata())?.permissions().mode() & 0o777 == 0o700,
            "Peer queue directory must already be owner-only.",
        )?;
    }
    Ok(())
}
fn existing_file(path: &Path, write: bool) -> PeerResult<File> {
    require(
        io(fs::symlink_metadata(path))?.is_file(),
        "Peer queue children must be regular files.",
    )?;
    let mut options = OpenOptions::new();
    options.read(true).write(write);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x00200000);
    }
    let file = io(options.open(path))?;
    private_file(&file)?;
    Ok(file)
}
fn private_file(file: &File) -> PeerResult<()> {
    let metadata = access::inspect_file(file).map_err(PeerError)?;
    #[cfg(unix)]
    require(
        matches!(
            metadata.permissions,
            access::FilePermissions::Unix { mode: 0o600 }
        ),
        "Peer queue files must already be owner-only.",
    )?;
    #[cfg(windows)]
    require(
        matches!(
            metadata.permissions,
            access::FilePermissions::Windows { readonly: false }
        ),
        "Peer queue files must be private writable regular files.",
    )?;
    Ok(())
}
fn new_file(path: &Path) -> PeerResult<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = io(options.open(path))?;
    private_file(&file)?;
    io(file.sync_all())?;
    Ok(file)
}
fn sync_directory(path: &Path) -> PeerResult<()> {
    #[cfg(unix)]
    io(directory(path)?.sync_all())?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Explicit unlock is required: a concurrent fork can retain a duplicated open
/// description after the owner's File closes, even with CLOEXEC at exec time.
struct WriterLock(File);
impl Drop for WriterLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

/// An explicitly created private queue. It has no project root or apply method.
pub struct Inbox {
    root: PathBuf,
    db: Connection,
    // Fields drop in declaration order: close/checkpoint SQLite before unlock.
    _writer: WriterLock,
}
impl std::fmt::Debug for Inbox {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Inbox { private_path_and_payloads: REDACTED }")
    }
}
impl Inbox {
    /// Creates only a new directory. Existing user directories are never adopted.
    pub fn create_new(path: &Path) -> PeerResult<Self> {
        no_symlinks(path)?;
        require(
            fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound),
            "Choose a new empty peer queue path; existing paths are never overwritten.",
        )?;
        let parent = path
            .parent()
            .ok_or(PeerError("Peer queue needs a parent directory."))?;
        let name = path
            .file_name()
            .ok_or(PeerError("Peer queue needs a directory name."))?;
        let parent = io(fs::canonicalize(parent))?;
        #[cfg(windows)]
        private_directory(&parent)?;
        let root = parent.join(name);
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        io(builder.create(&root))?;
        private_directory(&root)?;
        new_file(&root.join("writer.lock"))?;
        new_file(&root.join("queue.sqlite3"))?;
        let mut marker = new_file(&root.join("queue-kind"))?;
        io(marker.write_all(MARKER))?;
        io(marker.sync_all())?;
        sync_directory(&root)?;
        sync_directory(&parent)?;
        Self::open_internal(&root, true)
    }
    /// Reopens only a previously initialized, private queue. Keys are not stored.
    pub fn open(path: &Path) -> PeerResult<Self> {
        Self::open_internal(path, false)
    }
    fn open_internal(path: &Path, initialize: bool) -> PeerResult<Self> {
        no_symlinks(path)?;
        let root = io(fs::canonicalize(path))?;
        private_directory(&root)?;
        for name in [
            "queue-kind",
            "writer.lock",
            "queue.sqlite3",
            "queue.sqlite3-wal",
            "queue.sqlite3-shm",
        ] {
            let child = root.join(name);
            no_symlinks(&child)?;
            match fs::symlink_metadata(&child) {
                Ok(metadata) => {
                    require(
                        metadata.is_file(),
                        "Peer queue children must be regular files.",
                    )?;
                    existing_file(&child, false)?;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::NotFound
                        && matches!(name, "queue.sqlite3-wal" | "queue.sqlite3-shm") => {}
                Err(_) => {
                    return Err(PeerError(
                        "Peer queue is incomplete; preserve existing state.",
                    ))
                }
            }
        }
        let mut marker = Vec::new();
        io(existing_file(&root.join("queue-kind"), false)?
            .take(64)
            .read_to_end(&mut marker))?;
        require(
            marker == MARKER,
            "This is not an initialized private peer queue.",
        )?;
        let writer = existing_file(&root.join("writer.lock"), true)?;
        writer
            .try_lock_exclusive()
            .map_err(|_| PeerError("Another local peer queue writer is active."))?;
        let writer = WriterLock(writer);
        let db = sql(Connection::open(root.join("queue.sqlite3")))?;
        sql(db.busy_timeout(Duration::from_millis(200)))?;
        let application_id: u32 = sql(db.query_row("PRAGMA application_id", [], |r| r.get(0)))?;
        require(
            if initialize {
                application_id == 0
            } else {
                application_id == APPLICATION_ID
            },
            "This database is not an initialized peer queue; preserve existing data.",
        )?;
        sql(db.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;PRAGMA foreign_keys=ON;PRAGMA trusted_schema=OFF;PRAGMA temp_store=MEMORY;"))?;
        if initialize {
            sql(db.execute_batch("BEGIN IMMEDIATE;
                PRAGMA application_id=1146507345;
                CREATE TABLE schema_version(version INTEGER NOT NULL);
                INSERT INTO schema_version VALUES(2);
                CREATE TABLE sessions(id TEXT PRIMARY KEY,local_fingerprint TEXT NOT NULL,remote_fingerprint TEXT NOT NULL,channel TEXT NOT NULL,sequence INTEGER NOT NULL,digest TEXT NOT NULL,encoded_bytes INTEGER NOT NULL,scope_json TEXT);
                CREATE TABLE proposals(pairing_id TEXT NOT NULL REFERENCES sessions(id),sequence INTEGER NOT NULL,digest TEXT NOT NULL,payload BLOB NOT NULL,encoded_bytes INTEGER NOT NULL,PRIMARY KEY(pairing_id,sequence));
                CREATE TABLE events(event_id INTEGER PRIMARY KEY,kind TEXT NOT NULL,pairing_id TEXT NOT NULL,sequence INTEGER NOT NULL,digest TEXT NOT NULL);
                COMMIT;"))?;
        }
        let version = sql(
            db.query_row("SELECT version FROM schema_version", [], |row| {
                row.get::<_, u32>(0)
            }),
        )?;
        if version == 1 {
            sql(db.execute_batch("BEGIN IMMEDIATE;ALTER TABLE sessions ADD COLUMN scope_json TEXT;UPDATE schema_version SET version=2;COMMIT;"))?;
        } else {
            require(
                version == 2,
                "Unsupported peer queue schema; preserve its state.",
            )?;
        }
        sync_directory(&root)?;
        Ok(Self {
            root,
            db,
            _writer: writer,
        })
    }
    pub fn cursor(&self, pairing_id: &str) -> PeerResult<(u64, String)> {
        require(digest_valid(pairing_id), "Invalid pairing identity.")?;
        Ok(sql(self
            .db
            .query_row(
                "SELECT sequence,digest FROM sessions WHERE id=?1",
                [pairing_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional())?
        .unwrap_or((0, ZERO.into())))
    }
    pub fn pending_count(&self) -> PeerResult<u32> {
        sql(self
            .db
            .query_row("SELECT count(*) FROM proposals", [], |r| r.get(0)))
    }
    pub fn event_count(&self) -> PeerResult<u64> {
        sql(self
            .db
            .query_row("SELECT count(*) FROM events", [], |r| r.get(0)))
    }
    /// Local metadata listing only. Receiving never marks a proposal applied.
    pub fn proposal_refs(&self) -> PeerResult<Vec<ProposalRef>> {
        let mut query=sql(self.db.prepare("SELECT CASE WHEN length(pairing_id)=64 THEN pairing_id END,sequence,CASE WHEN length(digest)=64 THEN digest END FROM proposals ORDER BY pairing_id,sequence LIMIT 65"))?;
        let rows = sql(query.query_map([], |row| {
            Ok(ProposalRef {
                pairing_id: row.get(0)?,
                sequence: row.get(1)?,
                digest: row.get(2)?,
            })
        }))?;
        let mut output = Vec::new();
        for row in rows {
            let item = sql(row)?;
            require(
                output.len() < 64
                    && digest_valid(&item.pairing_id)
                    && digest_valid(&item.digest)
                    && item.sequence > 0
                    && item.sequence <= 16,
                "Invalid or excessive local queue metadata.",
            )?;
            output.push(item);
        }
        Ok(output)
    }
    /// Revalidates every retained packet, policy and chain checkpoint without
    /// reviving expired/revoked network keys. Only the local bridge calls this.
    pub(crate) fn validated_proposal(&self, reference: &ProposalRef) -> PeerResult<Envelope> {
        require(
            digest_valid(&reference.pairing_id)
                && digest_valid(&reference.digest)
                && reference.sequence > 0
                && reference.sequence <= 16,
            "Invalid exact local proposal reference.",
        )?;
        struct Context {
            local: Option<String>,
            remote: Option<String>,
            channel: Option<String>,
            sequence: u64,
            digest: Option<String>,
            used: u64,
            scope: Option<String>,
        }
        let context:Context=sql(self.db.query_row("SELECT CASE WHEN length(local_fingerprint)=64 THEN local_fingerprint END,CASE WHEN length(remote_fingerprint)=64 THEN remote_fingerprint END,CASE WHEN length(channel)<=64 THEN channel END,sequence,CASE WHEN length(digest)=64 THEN digest END,encoded_bytes,CASE WHEN length(scope_json)<=8192 THEN scope_json END FROM sessions WHERE id=?1",[&reference.pairing_id],|row|Ok(Context{local:row.get(0)?,remote:row.get(1)?,channel:row.get(2)?,sequence:row.get(3)?,digest:row.get(4)?,used:row.get(5)?,scope:row.get(6)?})))?;
        let scope:Scope=serde_json::from_str(context.scope.as_deref().ok_or(PeerError("Legacy or invalid pairing policy is review-only; explicitly pair again before importing."))?).map_err(|_|PeerError("Retained pairing policy is invalid."))?;
        scope.validate()?;
        let local = context
            .local
            .ok_or(PeerError("Retained local identity is invalid."))?;
        let remote = context
            .remote
            .ok_or(PeerError("Retained remote identity is invalid."))?;
        let head = context
            .digest
            .ok_or(PeerError("Retained checkpoint is invalid."))?;
        require(
            context.channel.as_deref() == Some(scope.channel.as_str())
                && context.sequence > 0
                && context.sequence <= u64::from(scope.max_messages)
                && reference.sequence <= context.sequence,
            "Retained policy and checkpoint differ.",
        )?;
        let mut query=sql(self.db.prepare("SELECT sequence,CASE WHEN length(digest)=64 THEN digest END,encoded_bytes,CASE WHEN length(payload)<=32768 THEN payload END FROM proposals WHERE pairing_id=?1 ORDER BY sequence LIMIT 17"))?;
        let rows = sql(query.query_map([&reference.pairing_id], |row| {
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, u64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        }))?;
        let (mut sequence, mut previous, mut used, mut selected) =
            (0u64, ZERO.to_owned(), 0u64, None);
        for row in rows {
            let (number, saved, length, payload) = sql(row)?;
            let saved = saved.ok_or(PeerError("Retained proposal digest is invalid."))?;
            let payload = payload.ok_or(PeerError(
                "Retained proposal exceeds bounded storage policy.",
            ))?;
            require(
                number == sequence + 1
                    && number <= u64::from(scope.max_messages)
                    && payload.len() as u64 == length
                    && payload.len() <= scope.max_bytes_per_proposal as usize,
                "Retained proposal order or size differs.",
            )?;
            let envelope: Envelope = serde_json::from_slice(&payload)
                .map_err(|_| PeerError("Retained proposal schema is invalid."))?;
            envelope.validate_stored(&reference.pairing_id, &scope, &remote, &local)?;
            require(
                envelope.sequence == number
                    && envelope.previous_digest == previous
                    && envelope.digest()? == saved
                    && envelope.encode()? == payload,
                "Retained proposal content or chain integrity differs.",
            )?;
            used = used
                .checked_add(length)
                .ok_or(PeerError("Retained byte accounting overflow."))?;
            require(
                used <= u64::from(scope.max_total_bytes),
                "Retained proposal quota differs.",
            )?;
            if number == reference.sequence {
                require(
                    saved == reference.digest,
                    "Local review requires the exact accepted proposal digest.",
                )?;
                selected = Some(envelope);
            }
            sequence = number;
            previous = saved;
        }
        require(
            sequence == context.sequence && previous == head && used == context.used,
            "Retained checkpoint, payloads or byte accounting differ.",
        )?;
        selected.ok_or(PeerError("Exact queued proposal is unavailable."))
    }
    /// Only the authenticated transport calls this from a network request.
    /// Commit means stored for local review, never project apply or stage.
    pub fn accept(&mut self, pair: &Paired, envelope: &Envelope) -> PeerResult<Receipt> {
        pair.ensure_active()?;
        envelope.validate_incoming(pair)?;
        let bytes =
            serde_json::to_vec(envelope).map_err(|_| PeerError("Cannot encode proposal."))?;
        require(
            bytes.len() <= MAX_ENVELOPE_BYTES
                && bytes.len() <= pair.scope().max_bytes_per_proposal as usize,
            "Proposal exceeds its encoded quota.",
        )?;
        let digest = envelope.digest()?;
        let scope_json = serde_json::to_string(pair.scope())
            .map_err(|_| PeerError("Cannot retain proposal policy."))?;
        let transaction = sql(self.db.transaction())?;
        sql(transaction.execute(
            "INSERT OR IGNORE INTO sessions(id,local_fingerprint,remote_fingerprint,channel,sequence,digest,encoded_bytes,scope_json) VALUES(?1,?2,?3,?4,0,?5,0,?6)",
            params![
                pair.id(),
                pair.local_fingerprint(),
                pair.remote_fingerprint(),
                pair.scope().channel,
                ZERO,
                scope_json
            ],
        ))?;
        let (local,remote,channel,sequence,previous,used):(String,String,String,u64,String,u64)=sql(transaction.query_row("SELECT local_fingerprint,remote_fingerprint,channel,sequence,digest,encoded_bytes FROM sessions WHERE id=?1",[pair.id()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))))?;
        let retained_scope: Option<String> = sql(transaction.query_row(
            "SELECT scope_json FROM sessions WHERE id=?1",
            [pair.id()],
            |row| row.get(0),
        ))?;
        require(
            retained_scope.as_deref() == Some(scope_json.as_str()),
            "Retained pairing policy differs or is legacy; explicitly pair again.",
        )?;
        require(
            local == pair.local_fingerprint()
                && remote == pair.remote_fingerprint()
                && channel == pair.scope().channel,
            "Queue pairing binding differs from the approved grant.",
        )?;
        if envelope.sequence <= sequence {
            let saved: Option<(String, Vec<u8>)> = sql(transaction
                .query_row(
                    "SELECT CASE WHEN length(digest)=64 THEN digest END,CASE WHEN length(payload)<=32768 THEN payload END FROM proposals WHERE pairing_id=?1 AND sequence=?2",
                    params![pair.id(), envelope.sequence],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional())?;
            require(
                saved.is_some_and(|(old, body)| old == digest && body == bytes),
                "Altered same-sequence proposal was refused.",
            )?;
            let pending_count = sql(transaction.query_row(
                "SELECT count(*) FROM proposals WHERE pairing_id=?1",
                [pair.id()],
                |r| r.get(0),
            ))?;
            // Read-only duplicate path does not emit a new event or consume quota.
            return Ok(Receipt {
                pairing_id: pair.id().into(),
                sequence: envelope.sequence,
                digest,
                status: ReceiptStatus::Duplicate,
                pending_count,
            });
        }
        require(
            envelope.sequence == sequence + 1 && envelope.previous_digest == previous,
            "Proposal sequence gap or predecessor mismatch.",
        )?;
        require(
            envelope.sequence <= u64::from(pair.scope().max_messages),
            "Pairing message quota is exhausted.",
        )?;
        require(
            used.checked_add(bytes.len() as u64)
                .is_some_and(|total| total <= u64::from(pair.scope().max_total_bytes)),
            "Pairing retained-byte quota is exhausted.",
        )?;
        let (count, total): (u64, u64) = sql(transaction.query_row(
            "SELECT count(*),coalesce(sum(encoded_bytes),0) FROM proposals",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        require(
            count < MAX_STORED_MESSAGES && total + bytes.len() as u64 <= MAX_STORED_BYTES,
            "Local proposal queue is full; review existing state.",
        )?;
        pair.ensure_active()?;
        sql(transaction.execute(
            "INSERT INTO proposals VALUES(?1,?2,?3,?4,?5)",
            params![
                pair.id(),
                envelope.sequence,
                digest,
                bytes,
                bytes.len() as u64
            ],
        ))?;
        sql(transaction.execute(
            "UPDATE sessions SET sequence=?2,digest=?3,encoded_bytes=?4 WHERE id=?1",
            params![
                pair.id(),
                envelope.sequence,
                digest,
                used + bytes.len() as u64
            ],
        ))?;
        sql(transaction.execute("INSERT INTO events(kind,pairing_id,sequence,digest) VALUES('proposal_queued',?1,?2,?3)",params![pair.id(),envelope.sequence,digest]))?;
        pair.ensure_active()?;
        sql(transaction.commit())?;
        sync_directory(&self.root)?;
        let pending_count = sql(self.db.query_row(
            "SELECT count(*) FROM proposals WHERE pairing_id=?1",
            [pair.id()],
            |r| r.get(0),
        ))?;
        Ok(Receipt {
            pairing_id: pair.id().into(),
            sequence: envelope.sequence,
            digest,
            status: ReceiptStatus::Queued,
            pending_count,
        })
    }
    /// Local-only review. Returns private payload to local code, never to the wire.
    /// Expired pairings do not destroy pending recovery evidence.
    pub fn review(
        &self,
        pairing_id: &str,
        sequence: u64,
        confirmed_digest: &str,
    ) -> PeerResult<Envelope> {
        require(
            digest_valid(pairing_id) && digest_valid(confirmed_digest),
            "Invalid local proposal review identity.",
        )?;
        let row: Option<(String, Vec<u8>)> = sql(self
            .db
            .query_row(
                "SELECT CASE WHEN length(digest)=64 THEN digest END,CASE WHEN length(payload)<=32768 THEN payload END FROM proposals WHERE pairing_id=?1 AND sequence=?2",
                params![pairing_id, sequence],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional())?;
        let (saved, bytes) =
            row.ok_or(PeerError("The requested pending proposal is unavailable."))?;
        require(
            saved == confirmed_digest && bytes.len() <= MAX_ENVELOPE_BYTES,
            "Local review must confirm the exact pending digest.",
        )?;
        let envelope: Envelope = serde_json::from_slice(&bytes)
            .map_err(|_| PeerError("Stored proposal is invalid; preserve the queue."))?;
        require(
            envelope.pairing_id == pairing_id
                && envelope.sequence == sequence
                && envelope.digest()? == saved,
            "Stored proposal integrity did not verify.",
        )?;
        Ok(envelope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        pairing::{tests::pair, PairingFlow},
        wire::{tests::put, Change, ZERO_DIGEST},
    };
    fn temp() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        #[cfg(windows)]
        access::make_disposable_test_directory_private(&fs::canonicalize(root.path()).unwrap())
            .unwrap();
        root
    }
    #[test]
    fn durable_exact_replay_collision_gap_and_private_review() {
        let root = temp();
        let path = fs::canonicalize(root.path()).unwrap().join("queue");
        let (a, b) = pair();
        let mut inbox = Inbox::create_new(&path).unwrap();
        assert!(
            Inbox::open(&path).is_err(),
            "A concurrent writer must be refused."
        );
        let frame =
            Envelope::new(&a, 1, ZERO_DIGEST, vec![put(b"GENERATED_PAYLOAD_CANARY")]).unwrap();
        let receipt = inbox.accept(&b, &frame).unwrap();
        assert_eq!(receipt.status, ReceiptStatus::Queued);
        assert_eq!(inbox.event_count().unwrap(), 1);
        assert_eq!(
            inbox.accept(&b, &frame).unwrap().status,
            ReceiptStatus::Duplicate
        );
        assert_eq!(inbox.event_count().unwrap(), 1);
        assert_eq!(inbox.pending_count().unwrap(), 1);
        let collision =
            Envelope::new(&a, 1, ZERO_DIGEST, vec![put(b"generated other content")]).unwrap();
        assert!(inbox.accept(&b, &collision).is_err());
        let gap = Envelope::new(
            &a,
            3,
            &receipt.digest,
            vec![put(b"generated third content")],
        )
        .unwrap();
        assert!(inbox.accept(&b, &gap).is_err());
        let mut tampered = frame.clone();
        if let Change::Put { hash, .. } = &mut tampered.changes[0] {
            *hash = ZERO.into();
        }
        assert!(inbox.accept(&b, &tampered).is_err());
        assert_eq!(inbox.cursor(b.id()).unwrap(), (1, receipt.digest.clone()));
        assert!(inbox.review(b.id(), 1, ZERO).is_err());
        drop(inbox);
        let mut reopened = Inbox::open(&path).unwrap();
        let reviewed = reopened.review(b.id(), 1, &receipt.digest).unwrap();
        assert_eq!(reviewed.digest().unwrap(), frame.digest().unwrap());
        assert!(!format!("{reviewed:?}").contains("GENERATED_PAYLOAD_CANARY"));
        assert!(!format!("{reopened:?}").contains("queue.sqlite3"));
        assert_eq!(
            reopened.accept(&b, &frame).unwrap().status,
            ReceiptStatus::Duplicate
        );
        assert_eq!(reopened.event_count().unwrap(), 1);
        b.revoke();
        assert!(reopened.accept(&b, &frame).is_err());
        assert!(
            reopened.review(b.id(), 1, &receipt.digest).is_ok(),
            "Revocation must preserve local recovery evidence."
        );
    }
    #[test]
    fn retained_policy_chain_and_payload_validate_without_live_pairing_keys() {
        let root = temp();
        let path = fs::canonicalize(root.path()).unwrap().join("queue");
        let (mut inbox, (a, b)) = (Inbox::create_new(&path).unwrap(), pair());
        let first = Envelope::new(
            &a,
            1,
            ZERO_DIGEST,
            vec![put(b"retained policy initial fixture")],
        )
        .unwrap();
        let second = Envelope::new(
            &a,
            2,
            &first.digest().unwrap(),
            vec![put(b"retained policy second fixture")],
        )
        .unwrap();
        inbox.accept(&b, &first).unwrap();
        inbox.accept(&b, &second).unwrap();
        let reference = ProposalRef {
            pairing_id: b.id().into(),
            sequence: 2,
            digest: second.digest().unwrap(),
        };
        a.revoke();
        b.revoke();
        drop(a);
        drop(b);
        drop(inbox);
        let reopened = Inbox::open(&path).unwrap();
        assert_eq!(
            reopened
                .validated_proposal(&reference)
                .unwrap()
                .digest()
                .unwrap(),
            reference.digest
        );
        assert_eq!(reopened.proposal_refs().unwrap().len(), 2);
        reopened
            .db
            .execute("DELETE FROM proposals WHERE sequence=1", [])
            .unwrap();
        assert!(reopened.validated_proposal(&reference).is_err());
    }
    #[test]
    fn legacy_scope_migration_preserves_raw_review_but_blocks_import() {
        let root = temp();
        let path = fs::canonicalize(root.path()).unwrap().join("queue");
        let (mut inbox, (a, b)) = (Inbox::create_new(&path).unwrap(), pair());
        let frame = Envelope::new(&a, 1, ZERO_DIGEST, vec![put(b"legacy queue fixture")]).unwrap();
        inbox.accept(&b, &frame).unwrap();
        let reference = ProposalRef {
            pairing_id: b.id().into(),
            sequence: 1,
            digest: frame.digest().unwrap(),
        };
        inbox
            .db
            .execute_batch(
                "ALTER TABLE sessions DROP COLUMN scope_json;UPDATE schema_version SET version=1;",
            )
            .unwrap();
        drop(inbox);
        let reopened = Inbox::open(&path).unwrap();
        assert!(reopened
            .review(&reference.pairing_id, 1, &reference.digest)
            .is_ok());
        assert!(reopened.validated_proposal(&reference).is_err());
        assert_eq!(reopened.event_count().unwrap(), 1);
    }
    #[test]
    fn local_import_revalidates_bounded_policy_and_stored_content() {
        let root = temp();
        let path = fs::canonicalize(root.path()).unwrap().join("queue");
        let (mut inbox, (a, b)) = (Inbox::create_new(&path).unwrap(), pair());
        let frame =
            Envelope::new(&a, 1, ZERO_DIGEST, vec![put(b"local validation fixture")]).unwrap();
        inbox.accept(&b, &frame).unwrap();
        let mut changed = frame.clone();
        if let Change::Put { path, .. } = &mut changed.changes[0] {
            *path = "src/unapproved.txt".into();
        }
        let bytes = changed.encode().unwrap();
        let changed_digest = changed.digest().unwrap();
        inbox
            .db
            .execute(
                "UPDATE proposals SET digest=?1,payload=?2,encoded_bytes=?3",
                params![changed_digest, bytes, bytes.len()],
            )
            .unwrap();
        inbox
            .db
            .execute(
                "UPDATE sessions SET digest=?1,encoded_bytes=?2",
                params![changed_digest, bytes.len()],
            )
            .unwrap();
        let reference = ProposalRef {
            pairing_id: b.id().into(),
            sequence: 1,
            digest: changed_digest,
        };
        assert!(inbox.validated_proposal(&reference).is_err());
        inbox
            .db
            .execute("UPDATE proposals SET payload=zeroblob(40000)", [])
            .unwrap();
        assert!(inbox.validated_proposal(&reference).is_err());
    }
    #[test]
    fn accepted_payload_cursor_and_event_are_one_transaction() {
        let root = temp();
        let path = fs::canonicalize(root.path()).unwrap().join("queue");
        let (a, b) = pair();
        let mut inbox = Inbox::create_new(&path).unwrap();
        inbox.db.execute_batch("CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'generated transaction failure'); END;").unwrap();
        let frame = Envelope::new(
            &a,
            1,
            ZERO_DIGEST,
            vec![put(b"generated rollback transaction fixture")],
        )
        .unwrap();
        assert!(inbox.accept(&b, &frame).is_err());
        assert_eq!(inbox.pending_count().unwrap(), 0);
        assert_eq!(inbox.cursor(b.id()).unwrap(), (0, ZERO.into()));
        drop(inbox);
        let mut inbox = Inbox::open(&path).unwrap();
        assert_eq!(inbox.pending_count().unwrap(), 0);
        assert_eq!(inbox.event_count().unwrap(), 0);
        inbox.db.execute_batch("DROP TRIGGER fail_event;").unwrap();
        assert_eq!(
            inbox.accept(&b, &frame).unwrap().status,
            ReceiptStatus::Queued
        );
    }
    #[test]
    fn quota_and_changed_pairing_are_refused_without_cursor_advancement() {
        let root = temp();
        let path = fs::canonicalize(root.path()).unwrap().join("queue");
        let x = PairingFlow::new_ephemeral().unwrap();
        let y = PairingFlow::new_ephemeral().unwrap();
        let xo = x.offer();
        let yo = y.offer();
        let mut scope = crate::pairing::tests::scope();
        scope.max_total_bytes = 1;
        let a = x.approve(&yo, &yo.fingerprint, scope.clone()).unwrap();
        let b = y.approve(&xo, &xo.fingerprint, scope).unwrap();
        let mut inbox = Inbox::create_new(&path).unwrap();
        let frame =
            Envelope::new(&a, 1, ZERO_DIGEST, vec![put(b"generated bounded payload")]).unwrap();
        assert!(inbox.accept(&b, &frame).is_err());
        assert_eq!(inbox.pending_count().unwrap(), 0);
        assert_eq!(inbox.cursor(b.id()).unwrap().0, 0);
        let (other_a, other_b) = pair();
        let foreign = Envelope::new(
            &other_a,
            1,
            ZERO_DIGEST,
            vec![put(b"generated foreign pairing")],
        )
        .unwrap();
        assert!(inbox.accept(&b, &foreign).is_err());
        assert!(inbox
            .review(other_b.id(), 1, &foreign.digest().unwrap())
            .is_err());
    }
    #[test]
    fn receipt_count_is_scoped_to_pair_not_other_local_sessions() {
        let root = temp();
        let path = fs::canonicalize(root.path()).unwrap().join("queue");
        let mut inbox = Inbox::create_new(&path).unwrap();
        for _ in 0..2 {
            let x = PairingFlow::new_ephemeral().unwrap();
            let y = PairingFlow::new_ephemeral().unwrap();
            let xo = x.offer();
            let yo = y.offer();
            let mut scope = crate::pairing::tests::scope();
            scope.max_messages = 1;
            let a = x.approve(&yo, &yo.fingerprint, scope.clone()).unwrap();
            let b = y.approve(&xo, &xo.fingerprint, scope).unwrap();
            let frame = Envelope::new(
                &a,
                1,
                ZERO_DIGEST,
                vec![put(b"generated per-pair quota fixture")],
            )
            .unwrap();
            assert_eq!(inbox.accept(&b, &frame).unwrap().pending_count, 1);
            assert_eq!(inbox.accept(&b, &frame).unwrap().pending_count, 1);
        }
        assert_eq!(inbox.pending_count().unwrap(), 2);
    }
    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess helper invoked only by the inherited-descriptor regression"]
    fn inherited_writer_child() {
        if std::env::var_os("DEVDROP_INHERITED_WRITER_CHILD").is_some() {
            // FD0 is the deliberately inherited writer description, not a pipe.
            // Keep it alive independently of reads; the parent kills/waits us.
            println!("DEVDROP_INHERITED_CHILD_READY");
            std::io::Write::flush(&mut std::io::stdout()).unwrap();
            std::thread::sleep(Duration::from_secs(10));
        }
    }
    #[cfg(unix)]
    #[test]
    fn inherited_writer_description_does_not_extend_owner_lock() {
        use std::process::{Child, Command, Stdio};
        struct ChildGuard(Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let root = temp();
        let path = fs::canonicalize(root.path()).unwrap().join("queue");
        let mut inbox = Inbox::create_new(&path).unwrap();
        let (a, b) = pair();
        let proposal = Envelope::new(
            &a,
            1,
            ZERO_DIGEST,
            vec![put(b"generated inherited lock fixture")],
        )
        .unwrap();
        let receipt = inbox.accept(&b, &proposal).unwrap();
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "store::tests::inherited_writer_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("DEVDROP_INHERITED_WRITER_CHILD", "1")
                .stdin(Stdio::from(inbox._writer.0.try_clone().unwrap()))
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        // Wait for the actual ignored helper to execute before testing owner drop.
        // This also catches an accidental omission of --ignored in the child args.
        use std::io::BufRead;
        let mut output = std::io::BufReader::new(child.0.stdout.take().unwrap());
        let mut ready = false;
        for _ in 0..8 {
            let mut line = String::new();
            if output.read_line(&mut line).unwrap() == 0 {
                break;
            }
            if line.contains("DEVDROP_INHERITED_CHILD_READY") {
                ready = true;
                break;
            }
        }
        assert!(
            ready,
            "The inherited-descriptor helper must signal readiness."
        );
        drop(inbox);
        let reopened = Inbox::open(&path);
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "The inherited-description child must still be alive."
        );
        let reopened=reopened.expect("Owner drop must explicitly release its writer lock even while a child retains a duplicate description.");
        assert_eq!(reopened.cursor(b.id()).unwrap(), (1, receipt.digest));
        assert!(
            Inbox::open(&path).is_err(),
            "A genuine new writer must still be excluded."
        );
        drop(child);
        assert!(
            Inbox::open(&path).is_err(),
            "Closing the old inherited descriptor must not unlock the new writer."
        );
        drop(reopened);
        assert!(Inbox::open(&path).is_ok());
    }
    #[cfg(unix)]
    #[test]
    fn non_regular_queue_paths_are_refused_without_waiting_for_pipe_io() {
        let root = temp();
        let base = fs::canonicalize(root.path()).unwrap();
        let path = base.join("queue");
        let inbox = Inbox::create_new(&path).unwrap();
        drop(inbox);
        fs::remove_file(path.join("writer.lock")).unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(path.join("writer.lock"))
            .status()
            .unwrap()
            .success());
        assert!(Inbox::open(&path).is_err());
        let fifo = base.join("not-a-directory");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());
        assert!(Inbox::open(&fifo).is_err());
    }
    #[test]
    fn queue_roots_children_marker_and_schema_fail_closed() {
        let root = temp();
        let base = fs::canonicalize(root.path()).unwrap();
        let path = base.join("queue");
        let inbox = Inbox::create_new(&path).unwrap();
        assert!(Inbox::create_new(&path).is_err());
        drop(inbox);
        fs::write(path.join("queue-kind"), b"unrecognized generated marker").unwrap();
        assert!(Inbox::open(&path).is_err());
        fs::write(path.join("queue-kind"), MARKER).unwrap();
        let db = Connection::open(path.join("queue.sqlite3")).unwrap();
        db.execute_batch("PRAGMA application_id=42;").unwrap();
        drop(db);
        assert!(Inbox::open(&path).is_err());
        let path2 = base.join("queue2");
        let inbox = Inbox::create_new(&path2).unwrap();
        drop(inbox);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let outside = base.join("generated-outside");
            fs::write(&outside, b"generated untouched marker").unwrap();
            fs::remove_file(path2.join("queue.sqlite3")).unwrap();
            symlink(&outside, path2.join("queue.sqlite3")).unwrap();
            assert!(Inbox::open(&path2).is_err());
            assert_eq!(fs::read(&outside).unwrap(), b"generated untouched marker");
            let path3 = base.join("queue3");
            let inbox = Inbox::create_new(&path3).unwrap();
            drop(inbox);
            fs::set_permissions(&path3, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(Inbox::open(&path3).is_err());
            let target = base.join("generated-link-target");
            fs::create_dir(&target).unwrap();
            let link = base.join("symlink-parent");
            symlink(&target, &link).unwrap();
            assert!(Inbox::create_new(&link.join("child")).is_err());
            assert!(!target.join("child").exists());
        }
    }
}
