//! Generated-fixture acceptance for the reusable local received-proposal bridge.
//! Real loopback mTLS admits a queue only; every filesystem transaction below is
//! separately reviewed, previewed and explicitly approved by the local driver.
use devdrop_core::{file_permissions as access, local::Engine};
use devdrop_peer::{
    bridge::{
        self, ApplyApproval, LocalSide, LocalTarget, PreviewApproval, ProposalRef, ResolutionChoice,
    },
    pairing::{Paired, PairingFlow, Scope},
    store::Inbox,
    transport::{PeerClient, PeerServer},
    wire::{Change, Envelope, ZERO_DIGEST},
    PeerError, PeerResult,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    sync::{Arc, Mutex},
};
const PATH: &str = "src/shared.txt";
const KEEP: &str = "unmentioned.txt";
const FIRST: &[u8] = b"generated reviewed initial bytes\n";
const SECOND: &[u8] = b"generated reviewed incoming edit\n";
const THIRD: &[u8] = b"generated reviewed change after rollback\n";
const LOCAL: &[u8] = b"generated preserved local edit\n";
const UNRELATED: &[u8] = b"generated unrelated common baseline\n";
fn need(value: bool, message: &'static str) -> PeerResult<()> {
    if value {
        Ok(())
    } else {
        Err(PeerError(message))
    }
}
fn io<T>(value: std::io::Result<T>) -> PeerResult<T> {
    value.map_err(|_| PeerError("Generated import acceptance IO failed."))
}
fn core<T>(value: std::result::Result<T, devdrop_core::local::LocalError>) -> PeerResult<T> {
    value.map_err(|error| PeerError(error.0))
}
fn hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
fn directory(path: &Path) -> PeerResult<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    io(builder.create(path))?;
    #[cfg(windows)]
    access::make_disposable_test_directory_private(path).map_err(PeerError)?;
    Ok(())
}
fn plain() -> access::FilePermissions {
    #[cfg(unix)]
    {
        access::FilePermissions::Unix { mode: 0o600 }
    }
    #[cfg(windows)]
    {
        access::FilePermissions::Windows { readonly: false }
    }
}
fn restrictive_probe() -> access::FilePermissions {
    #[cfg(unix)]
    {
        plain()
    }
    #[cfg(windows)]
    {
        access::FilePermissions::Windows { readonly: true }
    }
}
fn wider_probe() -> access::FilePermissions {
    #[cfg(unix)]
    {
        access::FilePermissions::Unix { mode: 0o700 }
    }
    #[cfg(windows)]
    {
        plain()
    }
}
fn write(root: &Path, path: &str, bytes: &[u8]) -> PeerResult<()> {
    let target = root.join(path);
    if let Some(parent) = target.parent() {
        if !parent.exists() {
            directory(parent)?;
        }
    }
    #[cfg(windows)]
    if target.exists() {
        use std::os::windows::fs::OpenOptionsExt;
        let file = io(OpenOptions::new()
            .read(true)
            .access_mode(0x8000_0000 | 0x0100)
            .open(&target))?;
        access::apply_permissions(&file, &plain()).map_err(PeerError)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = io(options.open(target))?;
    io(file.write_all(bytes))?;
    access::apply_permissions(&file, &plain()).map_err(PeerError)?;
    io(file.sync_all())?;
    Ok(())
}
fn file_hash(root: &Path, path: &str) -> PeerResult<String> {
    Ok(hash(&io(fs::read(root.join(path)))?))
}
fn put(bytes: &[u8], permissions: access::FilePermissions) -> Change {
    Change::Put {
        path: PATH.into(),
        hash: hash(bytes),
        bytes: bytes.to_vec(),
        permissions,
    }
}
fn pair() -> PeerResult<(Paired, Paired)> {
    let a = PairingFlow::new_ephemeral()?;
    let b = PairingFlow::new_ephemeral()?;
    let ao = a.offer();
    let bo = b.offer();
    let scope = Scope {
        channel: "local-received-import".into(),
        paths: BTreeSet::from([PATH.into()]),
        allow_delete: true,
        max_messages: 16,
        max_bytes_per_proposal: 32768,
        max_total_bytes: 262144,
    };
    Ok((
        a.approve(&bo, &bo.fingerprint, scope.clone())?,
        b.approve(&ao, &ao.fingerprint, scope)?,
    ))
}
async fn deliver(
    inbox: Arc<Mutex<Inbox>>,
    a: &Paired,
    b: &Paired,
    envelope: &Envelope,
) -> PeerResult<()> {
    let server = Arc::new(
        PeerServer::bind(
            b.clone(),
            inbox,
            "127.0.0.1:0"
                .parse()
                .map_err(|_| PeerError("Invalid generated endpoint."))?,
        )
        .await?,
    );
    let task = tokio::spawn({
        let server = server.clone();
        async move { server.serve_one().await }
    });
    let receipt = PeerClient::new(a.clone())?
        .send(server.local_addr()?, envelope)
        .await?;
    task.await
        .map_err(|_| PeerError("Generated TLS receiver failed."))??;
    need(
        receipt.digest == envelope.digest()?,
        "Authenticated receipt did not bind exact queued content.",
    )
}
fn reference(envelope: &Envelope) -> PeerResult<ProposalRef> {
    Ok(ProposalRef {
        pairing_id: envelope.pairing_id.clone(),
        sequence: envelope.sequence,
        digest: envelope.digest()?,
    })
}
fn consent(reference: &ProposalRef) -> PreviewApproval {
    PreviewApproval {
        confirmed_digest: reference.digest.clone(),
        disposable_copies: true,
    }
}
fn approval(reference: &ProposalRef, plan: &str, widen: bool) -> ApplyApproval {
    ApplyApproval {
        approved_plan_id: plan.into(),
        confirmed_digest: reference.digest.clone(),
        disposable_copies: true,
        allow_permission_widening: widen,
    }
}
fn open_engine(path: &Path) -> PeerResult<Engine> {
    core(Engine::open(path))
}
fn drop_queue(inbox: Arc<Mutex<Inbox>>) -> PeerResult<()> {
    drop(
        Arc::try_unwrap(inbox)
            .map_err(|_| PeerError("Unexpected live receiver queue owner."))?
            .into_inner()
            .map_err(|_| PeerError("Generated queue lock unavailable."))?,
    );
    Ok(())
}
async fn acceptance() -> PeerResult<Value> {
    let temp = io(tempfile::tempdir())?;
    let base = io(fs::canonicalize(temp.path()))?;
    #[cfg(windows)]
    access::make_disposable_test_directory_private(&base).map_err(PeerError)?;
    let source = base.join("source");
    let target = base.join("target");
    directory(&source)?;
    directory(&target)?;
    write(&source, KEEP, UNRELATED)?;
    write(&target, KEEP, UNRELATED)?;
    let state = base.join("engine");
    let queue = base.join("queue");
    let engine = open_engine(&state)?;
    let pair_local = core(engine.register("Disposable local import", &source, &target))?;
    let baseline = core(engine.preview(&pair_local.id))?;
    core(engine.apply(&baseline.id, &baseline.id, true, false))?;
    let target_mapping = LocalTarget {
        pair_id: pair_local.id.clone(),
        side: LocalSide::Target,
    };
    let inbox = Arc::new(Mutex::new(Inbox::create_new(&queue)?));
    let (a, b) = pair()?;
    let mut previous = ZERO_DIGEST.to_owned();
    let mut packets = Vec::new();
    for (index, change) in [
        put(FIRST, plain()),
        put(SECOND, plain()),
        Change::Delete {
            path: PATH.into(),
            previous_hash: hash(SECOND),
        },
        put(THIRD, restrictive_probe()),
        put(THIRD, wider_probe()),
    ]
    .into_iter()
    .enumerate()
    {
        let frame = Envelope::new(&a, index as u64 + 1, &previous, vec![change])?;
        deliver(inbox.clone(), &a, &b, &frame).await?;
        previous = frame.digest()?;
        packets.push(frame);
    }
    a.revoke();
    b.revoke();
    drop(a);
    drop(b);
    drop_queue(inbox)?;
    let inbox = Inbox::open(&queue)?;
    need(
        !target.join(PATH).exists(),
        "Network receipt changed the working tree.",
    )?;
    let refs = packets
        .iter()
        .map(reference)
        .collect::<PeerResult<Vec<_>>>()?;
    let metadata = bridge::review(&inbox, &refs[0])?;
    let review_json = serde_json::to_string(&metadata)
        .map_err(|_| PeerError("Sanitized review encoding failed."))?;
    need(
        !review_json.contains("generated reviewed initial") && !review_json.contains("\"bytes\""),
        "Sanitized review leaked payload.",
    )?;
    need(
        bridge::preview(
            &inbox,
            &engine,
            &refs[1],
            &target_mapping,
            &consent(&refs[1]),
        )
        .is_err(),
        "Out-of-order local import was accepted.",
    )?;
    let mut declined = consent(&refs[0]);
    declined.disposable_copies = false;
    need(
        bridge::preview(&inbox, &engine, &refs[0], &target_mapping, &declined).is_err(),
        "Preview bypassed disposable confirmation.",
    )?;
    declined.disposable_copies = true;
    declined.confirmed_digest = ZERO_DIGEST.into();
    need(
        bridge::preview(&inbox, &engine, &refs[0], &target_mapping, &declined).is_err(),
        "Preview bypassed exact digest confirmation.",
    )?;
    need(
        !state.join("objects").join(hash(FIRST)).exists(),
        "Unapproved received payload entered CAS.",
    )?;
    let first = bridge::preview(
        &inbox,
        &engine,
        &refs[0],
        &target_mapping,
        &consent(&refs[0]),
    )?;
    need(
        first.operations.len() == 1
            && first.operations[0].path == PATH
            && first.operations[0].side == "target"
            && !target.join(PATH).exists(),
        "Received preview widened scope or applied content.",
    )?;
    let mut wrong = approval(&refs[0], &first.plan_id, false);
    wrong.approved_plan_id = "wrong-plan".into();
    need(
        bridge::apply(
            &inbox,
            &engine,
            &refs[0],
            &target_mapping,
            &first.plan_id,
            &wrong,
        )
        .is_err(),
        "Apply bypassed exact preview approval.",
    )?;
    // Generated SQLite fault after filesystem installation but before the atomic
    // import-head/receipt commit. No product fault hook or source write is added.
    let metadata_path = state.join("metadata.sqlite3");
    let db = rusqlite::Connection::open(&metadata_path)
        .map_err(|_| PeerError("Generated fault database unavailable."))?;
    db.execute_batch("CREATE TRIGGER reject_import_receipt BEFORE INSERT ON events WHEN NEW.kind='received_import_verified' BEGIN SELECT RAISE(ABORT,'generated receipt fault'); END;").map_err(|_|PeerError("Generated receipt fault unavailable."))?;
    drop(db);
    need(
        bridge::apply(
            &inbox,
            &engine,
            &refs[0],
            &target_mapping,
            &first.plan_id,
            &approval(&refs[0], &first.plan_id, false),
        )
        .is_err(),
        "Injected receipt interruption did not fail.",
    )?;
    need(
        target.join(PATH).exists(),
        "Receipt fault did not reach the filesystem boundary.",
    )?;
    drop(engine);
    drop(inbox);
    let engine = open_engine(&state)?;
    let inbox = Inbox::open(&queue)?;
    need(
        core(engine.get_plan(&first.plan_id))?.state == "recovery_required",
        "Interrupted apply was labelled verified.",
    )?;
    let undo = bridge::rollback_preview(
        &inbox,
        &engine,
        &refs[0],
        &target_mapping,
        &first.plan_id,
        &consent(&refs[0]),
    )?;
    bridge::apply(
        &inbox,
        &engine,
        &refs[0],
        &target_mapping,
        &undo.plan_id,
        &approval(&refs[0], &undo.plan_id, false),
    )?;
    need(
        !target.join(PATH).exists(),
        "Interrupted transaction did not restore the original absent target.",
    )?;
    let db = rusqlite::Connection::open(&metadata_path)
        .map_err(|_| PeerError("Generated fault database unavailable."))?;
    db.execute_batch("DROP TRIGGER reject_import_receipt;")
        .map_err(|_| PeerError("Generated receipt fault cleanup failed."))?;
    drop(db);
    let fresh = bridge::preview(
        &inbox,
        &engine,
        &refs[0],
        &target_mapping,
        &consent(&refs[0]),
    )?;
    need(
        fresh.plan_id != first.plan_id,
        "Failed transaction reused an invalid approval.",
    )?;
    bridge::apply(
        &inbox,
        &engine,
        &refs[0],
        &target_mapping,
        &fresh.plan_id,
        &approval(&refs[0], &fresh.plan_id, false),
    )?;
    need(
        file_hash(&target, PATH)? == hash(FIRST),
        "First import failed hash verification.",
    )?;
    drop(engine);
    drop(inbox);
    let engine = open_engine(&state)?;
    let inbox = Inbox::open(&queue)?;
    let repeated = bridge::preview(
        &inbox,
        &engine,
        &refs[0],
        &target_mapping,
        &consent(&refs[0]),
    )?;
    need(
        repeated.plan_id == fresh.plan_id && repeated.state == "verified",
        "Restart lost the verified wire-to-plan mapping.",
    )?;
    need(
        bridge::apply(
            &inbox,
            &engine,
            &refs[0],
            &target_mapping,
            &fresh.plan_id,
            &approval(&refs[0], &fresh.plan_id, false),
        )?
        .changed
        .is_empty(),
        "Repeated exact approval mutated files.",
    )?;
    let wrong_target = LocalTarget {
        pair_id: pair_local.id.clone(),
        side: LocalSide::Source,
    };
    need(
        bridge::apply(
            &inbox,
            &engine,
            &refs[0],
            &wrong_target,
            &fresh.plan_id,
            &approval(&refs[0], &fresh.plan_id, false),
        )
        .is_err(),
        "Received preview remapped its local side.",
    )?;
    write(&source, KEEP, b"generated unrelated next edit")?;
    let common = core(engine.preview(&pair_local.id))?;
    need(
        common
            .operations
            .iter()
            .any(|operation| operation.path == KEEP && operation.kind == "replace"),
        "Unmentioned common baseline was reset.",
    )?;
    write(&source, KEEP, UNRELATED)?;
    write(&target, PATH, LOCAL)?;
    let conflict = bridge::preview(
        &inbox,
        &engine,
        &refs[1],
        &target_mapping,
        &consent(&refs[1]),
    )?;
    need(
        conflict
            .operations
            .iter()
            .any(|operation| operation.kind == "conflict"),
        "Dirty local edit was not preserved as conflict.",
    )?;
    need(
        bridge::apply(
            &inbox,
            &engine,
            &refs[1],
            &target_mapping,
            &conflict.plan_id,
            &approval(&refs[1], &conflict.plan_id, false),
        )
        .is_err(),
        "Unresolved received conflict applied.",
    )?;
    let resolution = bridge::resolve_preview(
        &inbox,
        &engine,
        &refs[1],
        &target_mapping,
        &conflict.plan_id,
        PATH,
        ResolutionChoice::Both,
        &consent(&refs[1]),
    )?;
    need(
        resolution
            .operations
            .iter()
            .all(|operation| operation.side == "target"),
        "Received conflict resolution wrote the opposite local side.",
    )?;
    bridge::apply(
        &inbox,
        &engine,
        &refs[1],
        &target_mapping,
        &resolution.plan_id,
        &approval(&refs[1], &resolution.plan_id, false),
    )?;
    let preserved = format!("{PATH}.devdrop-conflict-{}", &hash(LOCAL)[..12]);
    need(
        file_hash(&target, &preserved)? == hash(LOCAL)
            && file_hash(&target, PATH)? == hash(SECOND)
            && !source.join(PATH).exists(),
        "Scoped conflict resolution lost local or opposite-side work.",
    )?;
    let before = access::inspect_file(&io(File::open(target.join(PATH)))?).map_err(PeerError)?;
    let deletion = bridge::preview(
        &inbox,
        &engine,
        &refs[2],
        &target_mapping,
        &consent(&refs[2]),
    )?;
    need(
        deletion.operations.len() == 1
            && deletion.operations[0].path == PATH
            && deletion.operations[0].kind == "delete"
            && target.join(PATH).exists(),
        "Explicit deletion preview changed or widened files.",
    )?;
    bridge::apply(
        &inbox,
        &engine,
        &refs[2],
        &target_mapping,
        &deletion.plan_id,
        &approval(&refs[2], &deletion.plan_id, false),
    )?;
    need(
        !target.join(PATH).exists(),
        "Approved deletion did not verify.",
    )?;
    let restore = bridge::rollback_preview(
        &inbox,
        &engine,
        &refs[2],
        &target_mapping,
        &deletion.plan_id,
        &consent(&refs[2]),
    )?;
    bridge::apply(
        &inbox,
        &engine,
        &refs[2],
        &target_mapping,
        &restore.plan_id,
        &approval(&refs[2], &restore.plan_id, false),
    )?;
    need(
        access::inspect_file(&io(File::open(target.join(PATH)))?).map_err(PeerError)? == before,
        "Received deletion rollback lost original inode/access metadata.",
    )?;
    let rolled = bridge::preview(
        &inbox,
        &engine,
        &refs[2],
        &target_mapping,
        &consent(&refs[2]),
    )?;
    need(
        rolled.state == "rolled_back" && target.join(PATH).exists(),
        "Replayed deleted proposal silently reapplied after rollback.",
    )?;
    let after_undo = bridge::preview(
        &inbox,
        &engine,
        &refs[3],
        &target_mapping,
        &consent(&refs[3]),
    )?;
    need(
        after_undo
            .operations
            .iter()
            .any(|operation| operation.kind == "conflict"),
        "Historical remote baseline hid restored work.",
    )?;
    let restored = bridge::resolve_preview(
        &inbox,
        &engine,
        &refs[3],
        &target_mapping,
        &after_undo.plan_id,
        PATH,
        ResolutionChoice::Incoming,
        &consent(&refs[3]),
    )?;
    bridge::apply(
        &inbox,
        &engine,
        &refs[3],
        &target_mapping,
        &restored.plan_id,
        &approval(&refs[3], &restored.plan_id, false),
    )?;
    let permissions = bridge::preview(
        &inbox,
        &engine,
        &refs[4],
        &target_mapping,
        &consent(&refs[4]),
    )?;
    need(
        permissions
            .operations
            .iter()
            .any(|operation| operation.permission_widening),
        "Received permission widening was not visible.",
    )?;
    need(
        bridge::apply(
            &inbox,
            &engine,
            &refs[4],
            &target_mapping,
            &permissions.plan_id,
            &approval(&refs[4], &permissions.plan_id, false),
        )
        .is_err(),
        "Received widening bypassed extra approval.",
    )?;
    bridge::apply(
        &inbox,
        &engine,
        &refs[4],
        &target_mapping,
        &permissions.plan_id,
        &approval(&refs[4], &permissions.plan_id, true),
    )?;
    need(
        file_hash(&source, KEEP)? == hash(UNRELATED)
            && file_hash(&target, KEEP)? == hash(UNRELATED)
            && file_hash(&target, &preserved)? == hash(LOCAL)
            && file_hash(&target, PATH)? == hash(THIRD)
            && !source.join(PATH).exists(),
        "Received import changed unmentioned or opposite-side work.",
    )?;
    need(
        inbox.proposal_refs()?.len() == 5,
        "Local apply consumed or mutated the immutable queue.",
    )?;
    let names = [
        "real_loopback_mtls_queues_only",
        "retained_policy_review_without_live_pairing_keys",
        "sanitized_review_omits_payload",
        "exact_digest_disposable_gate_before_cas",
        "local_application_sequence_is_contiguous",
        "immutable_plan_and_destination_approval",
        "receipt_failure_recovery_and_rollback",
        "durable_preview_receipt_mapping_and_replay",
        "unmentioned_paths_and_common_baseline_preserved",
        "dirty_conflict_preserved_on_selected_side_only",
        "explicit_deletion_and_retained_inode_restore",
        "rollback_does_not_rewind_remote_history",
        "permission_widening_requires_extra_approval",
        "immutable_peer_queue_not_consumed",
    ];
    Ok(
        json!({"schema":"devdrop-local-import-evidence/v1","fixture_only":true,"transport":"real-loopback-mtls","network_apply":false,"sparse_staging":false,"runtime":{"os":std::env::consts::OS,"arch":std::env::consts::ARCH},"checks":names.into_iter().map(|name|json!({"name":name,"passed":true})).collect::<Vec<_>>(),"interruption_model":"Injected SQLite receipt commit failure after actual file installation; reopen and approved rollback. No guest or physical power-loss claim.","queue_proposals":5}),
    )
}
#[tokio::main]
async fn main() {
    if std::env::args().len() != 1 {
        eprintln!("This generated acceptance example accepts no user paths or network addresses.");
        std::process::exit(1);
    }
    match acceptance().await {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("{}", error.0);
            std::process::exit(1);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn real_tls_to_exact_local_import_recovery_and_rollback() {
        let report = acceptance()
            .await
            .expect("Generated local import acceptance must pass.");
        need(
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .all(|check| check["passed"] == true),
            "Acceptance check failed.",
        )
        .unwrap();
        let rendered = report.to_string();
        for private in [
            "generated reviewed",
            "generated preserved",
            "certificate_der",
            "private_key",
            "source_scan",
            "/tmp/",
        ] {
            assert!(!rendered.contains(private));
        }
    }
}
