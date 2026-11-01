//! Real localhost TLS acceptance with ephemeral identities and generated data only.
//! This executable accepts no folders, credentials, listen addresses or devices.
use devdrop_core::{
    file_permissions as access,
    local::{Engine, Plan},
};
use devdrop_peer::{
    pairing::{Paired, PairingFlow, Scope},
    store::Inbox,
    transport::{PeerClient, PeerServer},
    wire::{Change, Envelope, Receipt, ReceiptStatus, ZERO_DIGEST},
    PeerError, PeerResult,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    sync::{Arc, Mutex},
};
const PATH: &str = "src/shared.txt";
const INITIAL: &[u8] = b"generated authenticated initial fixture\n";
const EDITED: &[u8] = b"generated authenticated remote edit\n";
const LOCAL_EDIT: &[u8] = b"generated offline local edit\n";
fn need(value: bool, reason: &'static str) -> PeerResult<()> {
    if value {
        Ok(())
    } else {
        Err(PeerError(reason))
    }
}
fn io<T>(value: std::io::Result<T>) -> PeerResult<T> {
    value.map_err(|_| PeerError("Generated acceptance fixture IO failed."))
}
fn core<T>(value: Result<T, devdrop_core::local::LocalError>) -> PeerResult<T> {
    value.map_err(|_| PeerError("Generated acceptance Engine operation refused."))
}
fn hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
fn scope(channel: &str) -> Scope {
    Scope {
        channel: channel.into(),
        paths: BTreeSet::from([PATH.into()]),
        allow_delete: true,
        max_messages: 16,
        max_bytes_per_proposal: 32 * 1024,
        max_total_bytes: 256 * 1024,
    }
}
fn pair(scope: Scope) -> PeerResult<(Paired, Paired)> {
    let a = PairingFlow::new_ephemeral()?;
    let b = PairingFlow::new_ephemeral()?;
    let ao = a.offer();
    let bo = b.offer();
    // Fixture driver explicitly confirms both fingerprints. No automatic pairing API.
    Ok((
        a.approve(&bo, &bo.fingerprint, scope.clone())?,
        b.approve(&ao, &ao.fingerprint, scope)?,
    ))
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
fn plain_permissions() -> access::FilePermissions {
    #[cfg(unix)]
    {
        access::FilePermissions::Unix { mode: 0o600 }
    }
    #[cfg(windows)]
    {
        access::FilePermissions::Windows { readonly: false }
    }
}
fn write_generated(
    root: &Path,
    bytes: &[u8],
    permissions: &access::FilePermissions,
) -> PeerResult<()> {
    let src = root.join("src");
    if !src.exists() {
        directory(&src)?;
    }
    let path = root.join(PATH);
    if path.exists() {
        let metadata = io(fs::symlink_metadata(&path))?;
        need(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "Generated stage path changed type.",
        )?;
    }
    #[cfg(windows)]
    if path.exists() {
        use std::os::windows::fs::OpenOptionsExt;
        // Attribute-write access permits clearing a generated readonly flag
        // without requesting generic content-write access on the readonly file.
        let file = io(OpenOptions::new()
            .read(true)
            .access_mode(0x8000_0000 | 0x0100)
            .open(&path))?;
        access::apply_permissions(&file, &plain_permissions()).map_err(PeerError)?;
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = io(options.open(&path))?;
    io(file.write_all(bytes))?;
    access::apply_permissions(&file, permissions).map_err(PeerError)?;
    io(file.sync_all())?;
    Ok(())
}
fn selected_put(root: &Path) -> PeerResult<Change> {
    let mut file = io(File::open(root.join(PATH)))?;
    let before = access::inspect_file(&file).map_err(PeerError)?;
    let mut bytes = Vec::new();
    io((&mut file).take(16 * 1024 + 1).read_to_end(&mut bytes))?;
    need(
        bytes.len() <= 16 * 1024,
        "Selected generated fixture exceeded data quota.",
    )?;
    need(
        access::inspect_file(&file).map_err(PeerError)? == before,
        "Selected fixture changed while captured.",
    )?;
    Ok(Change::Put {
        path: PATH.into(),
        hash: hash(&bytes),
        bytes,
        permissions: before.permissions,
    })
}
fn file_hash(root: &Path) -> PeerResult<Option<String>> {
    match fs::read(root.join(PATH)) {
        Ok(b) => Ok(Some(hash(&b))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(PeerError("Cannot inspect generated workspace outcome.")),
    }
}
/// Deliberately private fixture adapter, not a product import or network stage API.
/// Exact local digest approval and disposable intent precede any cache mutation.
fn stage_fixture(
    root: &Path,
    envelope: &Envelope,
    confirmed_digest: &str,
    disposable: bool,
) -> PeerResult<()> {
    need(
        disposable && envelope.digest()? == confirmed_digest,
        "Local staging requires exact digest confirmation and disposable intent.",
    )?;
    need(
        envelope.changes.len() == 1 && envelope.changes[0].path() == PATH,
        "Only generated fixture namespace is supported by this adapter.",
    )?;
    match &envelope.changes[0] {
        Change::Put {
            bytes,
            hash: expected,
            permissions,
            ..
        } => {
            need(
                hash(bytes) == *expected,
                "Received fixture integrity changed.",
            )?;
            write_generated(root, bytes, permissions)
        }
        Change::Delete { previous_hash, .. } => {
            need(
                file_hash(root)? == Some(previous_hash.clone()),
                "Delete intent does not match the staged local predecessor.",
            )?;
            io(fs::remove_file(root.join(PATH)))
        }
    }
}
fn apply(engine: &Engine, plan: &Plan, allow_widening: bool) -> PeerResult<()> {
    let r = core(engine.apply(&plan.id, &plan.id, true, allow_widening))?;
    need(
        matches!(r.state.as_str(), "verified" | "rolled_back"),
        "Fixture apply/rollback did not verify.",
    )
}
async fn listener(pair: Paired, inbox: Arc<Mutex<Inbox>>) -> PeerResult<Arc<PeerServer>> {
    Ok(Arc::new(
        PeerServer::bind(
            pair,
            inbox,
            "127.0.0.1:0"
                .parse()
                .map_err(|_| PeerError("Internal loopback address invalid."))?,
        )
        .await?,
    ))
}
async fn exchange(
    client: &PeerClient,
    server: &Arc<PeerServer>,
    proposal: &Envelope,
) -> PeerResult<Receipt> {
    let task = tokio::spawn({
        let server = server.clone();
        async move { server.serve_one().await }
    });
    let client_result = client.send(server.local_addr()?, proposal).await;
    let server_result = task
        .await
        .map_err(|_| PeerError("Local TLS server task failed."))?;
    let receipt = client_result?;
    need(
        receipt == server_result?,
        "Local client/server receipt mismatch.",
    )?;
    Ok(receipt)
}
fn lock(inbox: &Arc<Mutex<Inbox>>) -> PeerResult<std::sync::MutexGuard<'_, Inbox>> {
    inbox
        .lock()
        .map_err(|_| PeerError("Local proposal queue is unavailable."))
}
async fn permission_acceptance(base: &Path) -> PeerResult<()> {
    let mode = base.join("mode-fixture");
    directory(&mode)?;
    let source = mode.join("selected-source");
    let view = mode.join("remote-view");
    let target = mode.join("workspace");
    for p in [&source, &view, &target] {
        directory(p)?;
    }
    let (a, b) = pair(scope("permission-fixture"))?;
    let inbox = Arc::new(Mutex::new(Inbox::create_new(&mode.join("queue"))?));
    let server = listener(b.clone(), inbox.clone()).await?;
    let client = PeerClient::new(a.clone())?;
    let initial = {
        #[cfg(unix)]
        {
            plain_permissions()
        }
        #[cfg(windows)]
        {
            access::FilePermissions::Windows { readonly: true }
        }
    };
    write_generated(&source, INITIAL, &initial)?;
    let first = Envelope::new(&a, 1, ZERO_DIGEST, vec![selected_put(&source)?])?;
    let receipt = exchange(&client, &server, &first).await?;
    let reviewed = lock(&inbox)?.review(b.id(), 1, &receipt.digest)?;
    stage_fixture(&view, &reviewed, &receipt.digest, true)?;
    let engine = core(Engine::open(&mode.join("sync-state")))?;
    let pair = core(engine.register("Generated authenticated permissions", &view, &target))?;
    let first_plan = core(engine.preview(&pair.id))?;
    apply(&engine, &first_plan, false)?;
    let original = access::inspect_file(&io(File::open(target.join(PATH)))?).map_err(PeerError)?;
    let wider = {
        #[cfg(unix)]
        {
            access::FilePermissions::Unix { mode: 0o700 }
        }
        #[cfg(windows)]
        {
            plain_permissions()
        }
    };
    write_generated(&source, INITIAL, &wider)?;
    let second = Envelope::new(&a, 2, &receipt.digest, vec![selected_put(&source)?])?;
    let receipt = exchange(&client, &server, &second).await?;
    need(
        access::inspect_file(&io(File::open(target.join(PATH)))?).map_err(PeerError)? == original,
        "Network receipt unexpectedly changed target permissions.",
    )?;
    let reviewed = lock(&inbox)?.review(b.id(), 2, &receipt.digest)?;
    stage_fixture(&view, &reviewed, &receipt.digest, true)?;
    let plan = core(engine.preview(&pair.id))?;
    need(
        plan.operations
            .iter()
            .any(|o| o.kind == "permissions" && o.permission_widening),
        "Source permission increase was not previewed.",
    )?;
    need(
        engine.apply(&plan.id, &plan.id, true, false).is_err(),
        "Pairing bypassed local access-increase approval.",
    )?;
    need(
        access::inspect_file(&io(File::open(target.join(PATH)))?).map_err(PeerError)? == original,
        "Rejected widening changed target metadata.",
    )?;
    apply(&engine, &plan, true)?;
    let undo = core(engine.rollback_preview(&plan.id))?;
    apply(&engine, &undo, false)?;
    need(
        access::inspect_file(&io(File::open(target.join(PATH)))?).map_err(PeerError)? == original,
        "Permission rollback failed to restore retained identity and flags.",
    )?;
    Ok(())
}
async fn run() -> PeerResult<Value> {
    let temp = io(tempfile::tempdir())?;
    let base = io(fs::canonicalize(temp.path()))?;
    #[cfg(windows)]
    access::make_disposable_test_directory_private(&base).map_err(PeerError)?;
    let source = base.join("selected-source");
    let view = base.join("remote-view");
    let workspace = base.join("workspace");
    for p in [&source, &view, &workspace] {
        directory(p)?;
    }
    write_generated(&source, INITIAL, &plain_permissions())?;
    let (a, b) = pair(scope("disposable-project"))?;
    need(
        a.id() == b.id() && a.local_fingerprint() != b.local_fingerprint(),
        "Explicit paired identities/context differ.",
    )?;
    let queue_path = base.join("received-queue");
    let inbox = Arc::new(Mutex::new(Inbox::create_new(&queue_path)?));
    let server = listener(b.clone(), inbox.clone()).await?;
    let client = PeerClient::new(a.clone())?;
    let initial = Envelope::new(&a, 1, ZERO_DIGEST, vec![selected_put(&source)?])?;
    let first_receipt = exchange(&client, &server, &initial).await?;
    need(
        first_receipt.status == ReceiptStatus::Queued
            && file_hash(&workspace)?.is_none()
            && file_hash(&view)?.is_none(),
        "Network receipt unexpectedly wrote project or staged view.",
    )?;
    let reviewed = lock(&inbox)?.review(b.id(), 1, &first_receipt.digest)?;
    need(
        stage_fixture(&view, &reviewed, &first_receipt.digest, false).is_err(),
        "Local staging bypassed disposable intent.",
    )?;
    stage_fixture(&view, &reviewed, &first_receipt.digest, true)?;
    let engine = core(Engine::open(&base.join("sync-state")))?;
    let project = core(engine.register("Generated authenticated project", &view, &workspace))?;
    let plan = core(engine.preview(&project.id))?;
    need(
        engine.apply(&plan.id, "wrong-plan", true, false).is_err()
            && engine.apply(&plan.id, &plan.id, false, false).is_err(),
        "Pairing bypassed exact-plan or disposable approval.",
    )?;
    need(
        file_hash(&workspace)?.is_none(),
        "Refused local approvals changed the target.",
    )?;
    apply(&engine, &plan, false)?;
    need(
        file_hash(&workspace)? == Some(hash(INITIAL)),
        "Authenticated transfer did not reach generated target after local approvals.",
    )?;
    let events = lock(&inbox)?.event_count()?;
    let replay = exchange(&client, &server, &initial).await?;
    need(
        replay.status == ReceiptStatus::Duplicate && lock(&inbox)?.event_count()? == events,
        "Exact network replay was not inert.",
    )?;
    let collision = Envelope::new(
        &a,
        1,
        ZERO_DIGEST,
        vec![Change::Put {
            path: PATH.into(),
            hash: hash(EDITED),
            bytes: EDITED.to_vec(),
            permissions: plain_permissions(),
        }],
    )?;
    let task = tokio::spawn({
        let server = server.clone();
        async move { server.serve_one().await }
    });
    need(
        client.send(server.local_addr()?, &collision).await.is_err()
            && task
                .await
                .map_err(|_| PeerError("Collision server task failed."))?
                .is_err(),
        "Altered same-sequence network message was accepted.",
    )?;
    let old_address = server.local_addr()?;
    drop(server);
    write_generated(&source, EDITED, &plain_permissions())?;
    write_generated(&workspace, LOCAL_EDIT, &plain_permissions())?;
    let update = Envelope::new(&a, 2, &first_receipt.digest, vec![selected_put(&source)?])?;
    need(
        client.send(old_address, &update).await.is_err(),
        "Offline listener unexpectedly accepted a proposal.",
    )?;
    need(
        lock(&inbox)?.cursor(b.id())?.0 == 1,
        "Offline attempt advanced durable sequence.",
    )?;
    let old = Arc::try_unwrap(inbox)
        .map_err(|_| PeerError("Local queue still has an active reference."))?;
    drop(
        old.into_inner()
            .map_err(|_| PeerError("Local queue lock poisoned."))?,
    );
    let inbox = Arc::new(Mutex::new(Inbox::open(&queue_path)?));
    let server = listener(b.clone(), inbox.clone()).await?;
    let update_receipt = exchange(&client, &server, &update).await?;
    need(
        file_hash(&workspace)? == Some(hash(LOCAL_EDIT)),
        "Reconnect receipt overwrote offline work.",
    )?;
    let reviewed = lock(&inbox)?.review(b.id(), 2, &update_receipt.digest)?;
    stage_fixture(&view, &reviewed, &update_receipt.digest, true)?;
    let conflict = core(engine.preview(&project.id))?;
    need(
        conflict.operations.iter().any(|o| o.kind == "conflict")
            && engine
                .apply(&conflict.id, &conflict.id, true, false)
                .is_err(),
        "Offline conflict was hidden or silently applied.",
    )?;
    let resolution = core(engine.resolve_preview(&project.id, PATH, "both"))?;
    apply(&engine, &resolution, false)?;
    let preserved = workspace.join(format!(
        "{PATH}.devdrop-conflict-{}",
        &hash(LOCAL_EDIT)[..12]
    ));
    need(
        hash(&io(fs::read(preserved))?) == hash(LOCAL_EDIT)
            && file_hash(&workspace)? == Some(hash(EDITED)),
        "Keep-both did not retain offline and remote versions.",
    )?;
    let prior = access::inspect_file(&io(File::open(workspace.join(PATH)))?).map_err(PeerError)?;
    io(fs::remove_file(source.join(PATH)))?;
    let delete = Envelope::new(
        &a,
        3,
        &update_receipt.digest,
        vec![Change::Delete {
            path: PATH.into(),
            previous_hash: hash(EDITED),
        }],
    )?;
    let deletion_receipt = exchange(&client, &server, &delete).await?;
    need(
        file_hash(&workspace)? == Some(hash(EDITED)),
        "Queued tombstone removed target before local approval.",
    )?;
    let reviewed = lock(&inbox)?.review(b.id(), 3, &deletion_receipt.digest)?;
    // A newer staged predecessor must survive a stale incoming delete precondition.
    write_generated(&view, LOCAL_EDIT, &plain_permissions())?;
    need(
        stage_fixture(&view, &reviewed, &deletion_receipt.digest, true).is_err()
            && file_hash(&view)? == Some(hash(LOCAL_EDIT)),
        "Stale incoming delete discarded newer staged data.",
    )?;
    write_generated(&view, EDITED, &plain_permissions())?;
    stage_fixture(&view, &reviewed, &deletion_receipt.digest, true)?;
    let deletion = core(engine.preview(&project.id))?;
    need(
        deletion
            .operations
            .iter()
            .any(|o| o.path == PATH && o.kind == "delete"),
        "Deletion intent missing from preview.",
    )?;
    need(
        engine
            .apply(&deletion.id, &deletion.id, false, false)
            .is_err()
            && file_hash(&workspace)? == Some(hash(EDITED)),
        "Tombstone bypassed disposable approval.",
    )?;
    apply(&engine, &deletion, false)?;
    need(
        file_hash(&workspace)?.is_none(),
        "Approved tombstone did not apply.",
    )?;
    let undo = core(engine.rollback_preview(&deletion.id))?;
    apply(&engine, &undo, false)?;
    need(
        file_hash(&workspace)? == Some(hash(EDITED))
            && access::inspect_file(&io(File::open(workspace.join(PATH)))?).map_err(PeerError)?
                == prior,
        "Rollback did not restore original inode and supported metadata.",
    )?;
    permission_acceptance(&base).await?;
    b.revoke();
    need(
        server.serve_one().await.is_err(),
        "Locally revoked server admitted a new request.",
    )?;
    need(
        lock(&inbox)?
            .review(b.id(), 3, &deletion_receipt.digest)
            .is_ok(),
        "Revocation destroyed local recovery evidence.",
    )?;
    let report = json!({"schema":"devdrop-authenticated-localhost-evidence/v1","topology":{"machines":1,"processes":1,"network":"real TCP IPv4 loopback; OS-assigned ports","host_os":std::env::consts::OS,"architecture":std::env::consts::ARCH,"cross_device_network_acceptance":false},"transport":"mutual TLS1.3 with exact leaf pins and ALPN checks on both endpoints","identity_storage":"ephemeral private keys in RAM only; no production identity lifecycle","pairing":{"id":a.id(),"sender_fingerprint":a.local_fingerprint(),"receiver_fingerprint":b.local_fingerprint(),"confirmed_on_both_ends":true,"paths_count":a.scope().paths.len()},"receipt_means":"private proposal queued for local review, never workspace apply","offline_model":"real loopback listener stopped, queue closed/reopened, authenticated reconnect; not physical VM/network outage","revocation":"local endpoint stops new admissions; already-admitted queue transaction may complete","timeout":"unknown queue outcome until exact retry; no implication of workspace apply","sender_outbox":"retained in RAM for retries; process-kill recovery not claimed","checks":[{"name":"explicit_dual_fingerprint_pairing","passed":true},{"name":"real_mutual_tls13_encrypted_transfer","passed":true},{"name":"network_receipt_has_no_stage_or_workspace_write","passed":true},{"name":"exact_local_staging_and_apply_approval_required","passed":true},{"name":"durable_exact_replay_is_inert","passed":true},{"name":"altered_same_sequence_is_refused","passed":true},{"name":"offline_and_durable_queue_reopen","passed":true},{"name":"authenticated_reconnect_preserves_offline_edit","passed":true},{"name":"conflict_blocks_then_keep_both_preserves_versions","passed":true},{"name":"stale_delete_precondition_preserves_staged_data","passed":true},{"name":"tombstone_requires_local_preview_and_apply","passed":true},{"name":"original_inode_and_metadata_rollback","passed":true},{"name":"network_permission_change_requires_local_widening_approval","passed":true},{"name":"local_revocation_preserves_recovery_evidence","passed":true}]});
    let serialized = serde_json::to_string(&report)
        .map_err(|_| PeerError("Cannot encode sanitized acceptance report."))?;
    for value in [INITIAL, EDITED, LOCAL_EDIT] {
        need(
            !serialized.contains(
                std::str::from_utf8(value)
                    .map_err(|_| PeerError("Generated fixture text invalid."))?
                    .trim_end(),
            ),
            "Acceptance report leaked generated payload.",
        )?;
    }
    Ok(report)
}
#[tokio::main]
async fn main() {
    if std::env::args_os().count() != 1 {
        eprintln!("This acceptance executable accepts no paths, devices or credentials.");
        std::process::exit(2);
    }
    match run().await {
        Ok(report) => println!("{report}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn real_localhost_engine_acceptance_and_redacted_report() {
        let report = run()
            .await
            .expect("Generated authenticated localhost acceptance must pass.");
        assert_eq!(report["topology"]["machines"], 1);
        assert_eq!(report["topology"]["cross_device_network_acceptance"], false);
        assert_eq!(report["checks"].as_array().unwrap().len(), 14);
        assert!(report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["passed"] == true));
    }
}
