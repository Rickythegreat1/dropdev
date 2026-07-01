use crate::content_hash::ContentHash;
use crate::ignore_policy::{IgnorePolicy, PathClassification};
use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
};

/// Exact marker prefix for DevDrop hydration stubs.
pub const STUB_MARKER_PREFIX: &str = "DEV_DROP_STUB_V1";
/// Test-only sandbox metadata filename.
pub const HYDRATION_SANDBOX_FILE: &str = ".devdrop-hydration-sandbox.json";
/// Deterministic test-only sandbox schema.
pub const HYDRATION_SANDBOX_SCHEMA: &str = "devdrop.hydration-sandbox.test";
/// Deterministic test-only sandbox version.
pub const HYDRATION_SANDBOX_VERSION: u32 = 1;
/// Deterministic sandbox kind that live workspaces must not use.
pub const HYDRATION_SANDBOX_KIND: &str = "test-only";
/// Deterministic sandbox creator used by tests.
pub const HYDRATION_SANDBOX_CREATED_BY: &str = "devdrop-test-sandbox";
/// Known deterministic fixture object key.
pub const FIXTURE_OBJECT_ALPHA_KEY: &str = "fixture_object_alpha";
/// Known deterministic fixture object id.
pub const FIXTURE_OBJECT_ALPHA_ID: &str = "object_alpha";
const FIXTURE_OBJECT_ALPHA_BYTES: &[u8] =
    b"DevDrop fixture object alpha.\nHydrated from a test sandbox only.\n";

/// Hydration state for a workspace object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HydrationState {
    /// Object is absent.
    Absent,
    /// Object is a DevDrop hydration stub.
    Stub,
    /// Object content is present and verified.
    Hydrated,
    /// Object is stale relative to preview evidence.
    Stale,
    /// Local content differs from a safe stub or known source.
    DirtyLocal,
    /// Conflict state blocks hydration.
    Conflict,
    /// Ignored/generated path cannot hydrate.
    Ignored,
    /// Source object is unavailable.
    Unavailable,
    /// Legacy compatibility: full bytes are present locally.
    Present,
    /// Legacy compatibility: lazy hydration is simulated.
    SimulatedLazy,
    /// Legacy compatibility: placeholder/stub is known but not real content.
    MissingStub,
}

/// Non-mutating hydration operation included in a sync plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HydrationOperation {
    /// Workspace path the operation would affect.
    pub path: Utf8PathBuf,
    /// Operation kind.
    pub kind: HydrationOperationKind,
    /// Human-readable dry-run summary.
    pub summary: String,
}

/// Hydration operation kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HydrationOperationKind {
    /// Simulate making content available lazily.
    SimulateHydrate,
    /// Simulate turning content into a lazy placeholder.
    SimulateDehydrate,
}

/// Registry entry for one deterministic fixture object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HydrationRegistryEntry {
    /// Object identifier, never a filesystem path.
    pub object_id: String,
    /// Deterministic fixture key, never a filesystem path.
    pub fixture_key: String,
    /// Expected BLAKE3 content hash hex.
    pub hash: String,
    /// Expected byte size.
    pub size: u64,
}

/// Test-only hydration sandbox metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HydrationSandboxMetadata {
    /// Deterministic schema string.
    pub schema: String,
    /// Schema version.
    pub version: u32,
    /// Must be test-only.
    pub sandbox_kind: String,
    /// Must identify DevDrop test sandbox setup.
    pub created_by: String,
    /// Deterministic registry fingerprint.
    pub registry_fingerprint: String,
    /// Object registry map keyed by object id.
    pub registry: BTreeMap<String, HydrationRegistryEntry>,
    /// Project-relative paths with dirty-local state.
    pub dirty_local_paths: Vec<String>,
    /// Project-relative paths with conflict state.
    pub conflict_paths: Vec<String>,
}

impl HydrationSandboxMetadata {
    /// Builds deterministic test-only metadata for the known fixture object.
    pub fn test_fixture() -> Self {
        let hash = ContentHash::hash_bytes(FIXTURE_OBJECT_ALPHA_BYTES);
        let entry = HydrationRegistryEntry {
            object_id: FIXTURE_OBJECT_ALPHA_ID.to_string(),
            fixture_key: FIXTURE_OBJECT_ALPHA_KEY.to_string(),
            hash: hash.digest,
            size: FIXTURE_OBJECT_ALPHA_BYTES.len() as u64,
        };
        let mut registry = BTreeMap::new();
        registry.insert(entry.object_id.clone(), entry);
        let registry_fingerprint = registry_fingerprint(&registry);
        Self {
            schema: HYDRATION_SANDBOX_SCHEMA.to_string(),
            version: HYDRATION_SANDBOX_VERSION,
            sandbox_kind: HYDRATION_SANDBOX_KIND.to_string(),
            created_by: HYDRATION_SANDBOX_CREATED_BY.to_string(),
            registry_fingerprint,
            registry,
            dirty_local_paths: Vec::new(),
            conflict_paths: Vec::new(),
        }
    }

    /// Returns metadata with one dirty-local path.
    pub fn with_dirty_path(mut self, path: impl Into<String>) -> Self {
        self.dirty_local_paths.push(path.into());
        self
    }

    /// Returns metadata with one conflict path.
    pub fn with_conflict_path(mut self, path: impl Into<String>) -> Self {
        self.conflict_paths.push(path.into());
        self
    }
}

/// Resolved deterministic fixture source object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HydrationSource {
    /// Object identifier.
    pub object_id: String,
    /// Fixture key.
    pub fixture_key: String,
    /// Expected content hash.
    pub content_hash: ContentHash,
    /// Expected byte size.
    pub size: u64,
}

/// Non-secret marker parsed from a DevDrop hydration stub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HydrationStubMarker {
    /// Object identifier.
    pub object_id: String,
    /// Expected source hash.
    pub content_hash: ContentHash,
    /// Expected byte size.
    pub size: u64,
}

/// Hydration blocker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HydrationBlocker {
    /// Path is canonical fixture source material.
    CanonicalFixtureReadOnly,
    /// Path is not inside a recognized test sandbox.
    UnrecognizedSandbox,
    /// Sandbox metadata was malformed or incomplete.
    InvalidSandboxMetadata,
    /// Path escapes the sandbox root.
    OutsideSandboxRoot,
    /// Target path is a symlink.
    TargetSymlink,
    /// Parent directory is a symlink.
    ParentSymlink,
    /// Ignored/generated paths cannot hydrate.
    IgnoredPath,
    /// Secret-classified paths cannot hydrate.
    SecretPath,
    /// Stub marker is missing or not exact.
    StubMarkerMissing,
    /// Object id is invalid or path-like.
    InvalidObjectId,
    /// Registry key is invalid or path-like.
    InvalidRegistryKey,
    /// Source object is not present in the deterministic registry.
    SourceObjectMissing,
    /// Source object hash or size does not match expected metadata.
    SourceHashMismatch,
    /// Target changed after preview.
    StalePreview,
    /// Dirty local state blocks hydration.
    DirtyLocal,
    /// Conflict state blocks hydration.
    Conflict,
    /// Metadata observation failed.
    MetadataError,
    /// Write failed and recovery is required.
    PartialWriteFailure,
}

/// Hydration dry-run preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HydrationPreview {
    /// Target path as display metadata.
    pub target_path: String,
    /// Sandbox root as display metadata.
    pub sandbox_root: Option<String>,
    /// Current hydration state.
    pub state: HydrationState,
    /// Source object metadata when safely resolved.
    pub source: Option<HydrationSource>,
    /// Exact expected stub marker.
    pub expected_stub_marker: Option<String>,
    /// Hash of the expected stub marker.
    pub expected_stub_hash: Option<ContentHash>,
    /// Expected stub byte length.
    pub expected_stub_size: Option<u64>,
    /// Whether apply is allowed.
    pub can_apply: bool,
    /// Whether this preview is idempotent.
    pub idempotent: bool,
    /// Whether this preview is dry-run.
    pub dry_run: bool,
    /// Whether preview mutated files. Always false.
    pub mutated_files: bool,
    /// Blockers preventing apply.
    pub blockers: Vec<HydrationBlocker>,
    /// Human-readable risk summary.
    pub risk: String,
    /// Redaction notice.
    pub redaction_notice: String,
}

/// Hydration apply receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HydrationApplyReceipt {
    /// Target path as display metadata.
    pub target_path: String,
    /// Whether a write was attempted.
    pub attempted_write: bool,
    /// Whether the final verified write completed.
    pub write_completed: bool,
    /// Whether the target was already hydrated and no write occurred.
    pub idempotent: bool,
    /// Whether a file was mutated.
    pub mutated_files: bool,
    /// Blockers or failure reasons.
    pub blockers: Vec<HydrationBlocker>,
    /// Recovery guidance.
    pub recovery_action: String,
    /// Final content hash when verified.
    pub final_hash: Option<ContentHash>,
}

/// Hydration state counts.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HydrationCounts {
    pub absent: usize,
    pub stub: usize,
    pub hydrated: usize,
    pub stale: usize,
    pub dirty_local: usize,
    pub conflict: usize,
    pub ignored: usize,
    pub unavailable: usize,
}

/// Options for hydration apply.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HydrationApplyOptions {
    /// Test hook that simulates a failure after temp write but before final write.
    pub simulate_failure_after_temp_write: bool,
}

impl HydrationApplyReceipt {
    fn blocked(path: impl Into<String>, blockers: Vec<HydrationBlocker>) -> Self {
        Self {
            target_path: path.into(),
            attempted_write: false,
            write_completed: false,
            idempotent: false,
            mutated_files: false,
            blockers,
            recovery_action: "No write was attempted. Review blockers and rerun hydrate --dry-run."
                .to_string(),
            final_hash: None,
        }
    }

    fn idempotent(path: impl Into<String>, hash: ContentHash) -> Self {
        Self {
            target_path: path.into(),
            attempted_write: false,
            write_completed: false,
            idempotent: true,
            mutated_files: false,
            blockers: Vec::new(),
            recovery_action: "No recovery needed; target already matches the source object."
                .to_string(),
            final_hash: Some(hash),
        }
    }
}

/// Returns bytes for a deterministic fixture object key.
pub fn fixture_object_bytes(key: &str) -> Option<&'static [u8]> {
    match key {
        FIXTURE_OBJECT_ALPHA_KEY => Some(FIXTURE_OBJECT_ALPHA_BYTES),
        _ => None,
    }
}

/// Builds the exact DevDrop stub marker.
pub fn exact_stub_marker(object_id: &str, hash: &ContentHash, size: u64) -> String {
    format!(
        "{STUB_MARKER_PREFIX} object_id={object_id} hash=blake3:{} size={size}\n",
        hash.digest
    )
}

/// Parses an exact DevDrop stub marker.
pub fn parse_stub_marker(text: &str) -> Result<HydrationStubMarker, HydrationBlocker> {
    let parts: Vec<_> = text.trim_end_matches('\n').split(' ').collect();
    if parts.len() != 4 || parts[0] != STUB_MARKER_PREFIX || !text.ends_with('\n') {
        return Err(HydrationBlocker::StubMarkerMissing);
    }

    let object_id = parts[1]
        .strip_prefix("object_id=")
        .ok_or(HydrationBlocker::StubMarkerMissing)?;
    validate_identifier(object_id).map_err(|_| HydrationBlocker::InvalidObjectId)?;

    let hash = parts[2]
        .strip_prefix("hash=blake3:")
        .ok_or(HydrationBlocker::StubMarkerMissing)?;
    if hash.len() != 64 || !hash.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(HydrationBlocker::StubMarkerMissing);
    }

    let size = parts[3]
        .strip_prefix("size=")
        .ok_or(HydrationBlocker::StubMarkerMissing)?
        .parse::<u64>()
        .map_err(|_| HydrationBlocker::StubMarkerMissing)?;

    Ok(HydrationStubMarker {
        object_id: object_id.to_string(),
        content_hash: ContentHash {
            algorithm: crate::HashAlgorithm::Blake3,
            digest: hash.to_string(),
        },
        size,
    })
}

/// Creates a dry-run hydration preview.
pub fn preview_hydration(path: impl AsRef<Path>) -> HydrationPreview {
    preview_hydration_inner(path.as_ref())
}

/// Applies a hydration preview with default options.
pub fn apply_hydration_preview(preview: &HydrationPreview) -> HydrationApplyReceipt {
    apply_hydration_preview_with_options(preview, HydrationApplyOptions::default())
}

/// Applies hydration from a preview.
pub fn apply_hydration_preview_with_options(
    preview: &HydrationPreview,
    options: HydrationApplyOptions,
) -> HydrationApplyReceipt {
    if !preview.blockers.is_empty() || !preview.can_apply {
        return HydrationApplyReceipt::blocked(
            preview.target_path.clone(),
            preview.blockers.clone(),
        );
    }

    if preview.idempotent {
        let Some(source) = &preview.source else {
            return HydrationApplyReceipt::blocked(
                preview.target_path.clone(),
                vec![HydrationBlocker::SourceObjectMissing],
            );
        };
        return HydrationApplyReceipt::idempotent(
            preview.target_path.clone(),
            source.content_hash.clone(),
        );
    }

    let current = preview_hydration(&preview.target_path);
    if current.expected_stub_hash != preview.expected_stub_hash
        || current.expected_stub_size != preview.expected_stub_size
    {
        return HydrationApplyReceipt::blocked(
            preview.target_path.clone(),
            vec![HydrationBlocker::StalePreview],
        );
    }
    if !current.blockers.is_empty() || !current.can_apply || current.source != preview.source {
        return HydrationApplyReceipt::blocked(preview.target_path.clone(), current.blockers);
    }

    let Some(source) = &preview.source else {
        return HydrationApplyReceipt::blocked(
            preview.target_path.clone(),
            vec![HydrationBlocker::SourceObjectMissing],
        );
    };
    let Some(bytes) = fixture_object_bytes(&source.fixture_key) else {
        return HydrationApplyReceipt::blocked(
            preview.target_path.clone(),
            vec![HydrationBlocker::SourceObjectMissing],
        );
    };

    let target = PathBuf::from(&preview.target_path);
    let temp_path = target.with_extension("devdrop-hydrate.tmp");
    let temp_result = write_and_verify_temp(&temp_path, bytes, &source.content_hash);
    if temp_result.is_err() || options.simulate_failure_after_temp_write {
        let _ = fs::remove_file(&temp_path);
        return HydrationApplyReceipt {
            target_path: preview.target_path.clone(),
            attempted_write: true,
            write_completed: false,
            idempotent: false,
            mutated_files: false,
            blockers: vec![HydrationBlocker::PartialWriteFailure],
            recovery_action:
                "Temporary write failed before final replacement. The original target should be inspected and dry-run should be repeated."
                    .to_string(),
            final_hash: None,
        };
    }

    let replace_result = replace_target_with_temp(&temp_path, &target);
    if replace_result.is_err() {
        let _ = fs::remove_file(&temp_path);
        return HydrationApplyReceipt {
            target_path: preview.target_path.clone(),
            attempted_write: true,
            write_completed: false,
            idempotent: false,
            mutated_files: false,
            blockers: vec![HydrationBlocker::PartialWriteFailure],
            recovery_action:
                "Final replacement failed. Re-run dry-run before another apply attempt.".to_string(),
            final_hash: None,
        };
    }

    let final_bytes = match fs::read(&target) {
        Ok(bytes) => bytes,
        Err(_) => return HydrationApplyReceipt {
            target_path: preview.target_path.clone(),
            attempted_write: true,
            write_completed: false,
            idempotent: false,
            mutated_files: false,
            blockers: vec![HydrationBlocker::PartialWriteFailure],
            recovery_action:
                "Final verification could not read target. Inspect the sandbox target and retry."
                    .to_string(),
            final_hash: None,
        },
    };
    let final_hash = ContentHash::hash_bytes(&final_bytes);
    if final_hash != source.content_hash {
        return HydrationApplyReceipt {
            target_path: preview.target_path.clone(),
            attempted_write: true,
            write_completed: false,
            idempotent: false,
            mutated_files: false,
            blockers: vec![HydrationBlocker::PartialWriteFailure],
            recovery_action:
                "Final target hash did not match source. Treat target as suspect and restore from fixture sandbox."
                    .to_string(),
            final_hash: Some(final_hash),
        };
    }

    HydrationApplyReceipt {
        target_path: preview.target_path.clone(),
        attempted_write: true,
        write_completed: true,
        idempotent: false,
        mutated_files: true,
        blockers: Vec::new(),
        recovery_action: "No recovery needed; target content hash matches source.".to_string(),
        final_hash: Some(final_hash),
    }
}

/// Builds and applies a hydration preview.
pub fn apply_hydration(path: impl AsRef<Path>) -> HydrationApplyReceipt {
    let preview = preview_hydration(path);
    apply_hydration_preview(&preview)
}

/// Returns hydration counts for a recognized test sandbox.
pub fn hydration_counts(path: impl AsRef<Path>) -> HydrationCounts {
    let root = match load_sandbox(path.as_ref()) {
        Ok(sandbox) => sandbox.root,
        Err(_) => return HydrationCounts::default(),
    };
    let mut counts = HydrationCounts::default();
    let Ok(entries) = fs::read_dir(root) else {
        return counts;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.file_name().and_then(|name| name.to_str()) == Some(HYDRATION_SANDBOX_FILE) {
            continue;
        }
        let preview = preview_hydration(path);
        match preview.state {
            HydrationState::Absent => counts.absent += 1,
            HydrationState::Stub => counts.stub += 1,
            HydrationState::Hydrated => counts.hydrated += 1,
            HydrationState::Stale => counts.stale += 1,
            HydrationState::DirtyLocal => counts.dirty_local += 1,
            HydrationState::Conflict => counts.conflict += 1,
            HydrationState::Ignored => counts.ignored += 1,
            HydrationState::Unavailable => counts.unavailable += 1,
            HydrationState::Present
            | HydrationState::SimulatedLazy
            | HydrationState::MissingStub => counts.unavailable += 1,
        }
    }
    counts
}

fn preview_hydration_inner(path: &Path) -> HydrationPreview {
    let target_path = path.to_string_lossy().to_string();
    if is_canonical_hydration_fixture(path) {
        return blocked_preview(
            target_path,
            HydrationState::Unavailable,
            vec![HydrationBlocker::CanonicalFixtureReadOnly],
        );
    }

    let sandbox = match load_sandbox(path) {
        Ok(sandbox) => sandbox,
        Err(blocker) => {
            return blocked_preview(target_path, HydrationState::Unavailable, vec![blocker])
        }
    };

    let relative = relative_path(&sandbox.root, path);
    let classification = IgnorePolicy::default().classify(&relative);
    if classification == PathClassification::Generated {
        return blocked_preview_with_root(
            target_path,
            sandbox.root,
            HydrationState::Ignored,
            vec![HydrationBlocker::IgnoredPath],
        );
    }
    if classification == PathClassification::Secret {
        return blocked_preview_with_root(
            target_path,
            sandbox.root,
            HydrationState::Unavailable,
            vec![HydrationBlocker::SecretPath],
        );
    }
    if sandbox
        .metadata
        .conflict_paths
        .iter()
        .any(|item| item == &relative)
    {
        return blocked_preview_with_root(
            target_path,
            sandbox.root,
            HydrationState::Conflict,
            vec![HydrationBlocker::Conflict],
        );
    }
    if sandbox
        .metadata
        .dirty_local_paths
        .iter()
        .any(|item| item == &relative)
    {
        return blocked_preview_with_root(
            target_path,
            sandbox.root,
            HydrationState::DirtyLocal,
            vec![HydrationBlocker::DirtyLocal],
        );
    }

    let path_checks = validate_target_path(&sandbox.root, path);
    if !path_checks.is_empty() {
        return blocked_preview_with_root(
            target_path,
            sandbox.root,
            HydrationState::Unavailable,
            path_checks,
        );
    }

    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(_) => {
            return blocked_preview_with_root(
                target_path,
                sandbox.root,
                HydrationState::Absent,
                vec![HydrationBlocker::StubMarkerMissing],
            )
        }
    };

    if let Ok(marker) = parse_stub_marker(&text) {
        let (source, blockers) = resolve_source(&sandbox.metadata, &marker);
        let expected_marker =
            exact_stub_marker(&marker.object_id, &marker.content_hash, marker.size);
        let expected_stub_hash = ContentHash::hash_bytes(expected_marker.as_bytes());
        return HydrationPreview {
            target_path,
            sandbox_root: Some(sandbox.root.to_string_lossy().to_string()),
            state: if blockers.is_empty() {
                HydrationState::Stub
            } else {
                HydrationState::Unavailable
            },
            source,
            expected_stub_marker: Some(expected_marker),
            expected_stub_hash: Some(expected_stub_hash),
            expected_stub_size: Some(text.len() as u64),
            can_apply: blockers.is_empty(),
            idempotent: false,
            dry_run: true,
            mutated_files: false,
            blockers,
            risk: "CLI-only sandbox simulation. Apply replaces an exact DevDrop stub only."
                .to_string(),
            redaction_notice:
                "Preview includes metadata and marker fields only; secret values are absent."
                    .to_string(),
        };
    }

    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => {
            return blocked_preview_with_root(
                target_path,
                sandbox.root,
                HydrationState::Absent,
                vec![HydrationBlocker::StubMarkerMissing],
            )
        }
    };
    let hash = ContentHash::hash_bytes(&bytes);
    if let Some(source) = sandbox
        .metadata
        .registry
        .values()
        .find_map(|entry| source_if_entry_matches(entry, &hash, bytes.len() as u64))
    {
        return HydrationPreview {
            target_path,
            sandbox_root: Some(sandbox.root.to_string_lossy().to_string()),
            state: HydrationState::Hydrated,
            source: Some(source),
            expected_stub_marker: None,
            expected_stub_hash: None,
            expected_stub_size: None,
            can_apply: true,
            idempotent: true,
            dry_run: true,
            mutated_files: false,
            blockers: Vec::new(),
            risk: "Target already matches a deterministic fixture object.".to_string(),
            redaction_notice:
                "Preview includes metadata and hash evidence only; secret values are absent."
                    .to_string(),
        };
    }

    blocked_preview_with_root(
        target_path,
        sandbox.root,
        HydrationState::DirtyLocal,
        vec![HydrationBlocker::DirtyLocal],
    )
}

fn blocked_preview(
    target_path: String,
    state: HydrationState,
    blockers: Vec<HydrationBlocker>,
) -> HydrationPreview {
    HydrationPreview {
        target_path,
        sandbox_root: None,
        state,
        source: None,
        expected_stub_marker: None,
        expected_stub_hash: None,
        expected_stub_size: None,
        can_apply: false,
        idempotent: false,
        dry_run: true,
        mutated_files: false,
        blockers,
        risk: "Hydration refused before reading arbitrary file contents.".to_string(),
        redaction_notice: "Secret values and raw file contents are absent.".to_string(),
    }
}

fn blocked_preview_with_root(
    target_path: String,
    root: PathBuf,
    state: HydrationState,
    blockers: Vec<HydrationBlocker>,
) -> HydrationPreview {
    HydrationPreview {
        target_path,
        sandbox_root: Some(root.to_string_lossy().to_string()),
        state,
        source: None,
        expected_stub_marker: None,
        expected_stub_hash: None,
        expected_stub_size: None,
        can_apply: false,
        idempotent: false,
        dry_run: true,
        mutated_files: false,
        blockers,
        risk: "Hydration blocked by sandbox safety checks.".to_string(),
        redaction_notice: "Secret values and raw file contents are absent.".to_string(),
    }
}

struct LoadedSandbox {
    root: PathBuf,
    metadata: HydrationSandboxMetadata,
}

fn load_sandbox(path: &Path) -> Result<LoadedSandbox, HydrationBlocker> {
    let start = if path.is_dir() {
        path
    } else {
        path.parent().unwrap_or(path)
    };
    for ancestor in start.ancestors() {
        let metadata_path = ancestor.join(HYDRATION_SANDBOX_FILE);
        if metadata_path.exists() {
            let root =
                fs::canonicalize(ancestor).map_err(|_| HydrationBlocker::InvalidSandboxMetadata)?;
            let text = fs::read_to_string(metadata_path)
                .map_err(|_| HydrationBlocker::InvalidSandboxMetadata)?;
            let metadata: HydrationSandboxMetadata = serde_json::from_str(&text)
                .map_err(|_| HydrationBlocker::InvalidSandboxMetadata)?;
            validate_sandbox_metadata(&metadata)?;
            return Ok(LoadedSandbox { root, metadata });
        }
    }
    Err(HydrationBlocker::UnrecognizedSandbox)
}

fn validate_sandbox_metadata(metadata: &HydrationSandboxMetadata) -> Result<(), HydrationBlocker> {
    if metadata.schema != HYDRATION_SANDBOX_SCHEMA
        || metadata.version != HYDRATION_SANDBOX_VERSION
        || metadata.sandbox_kind != HYDRATION_SANDBOX_KIND
        || metadata.created_by != HYDRATION_SANDBOX_CREATED_BY
        || metadata.registry.is_empty()
        || metadata.registry_fingerprint != registry_fingerprint(&metadata.registry)
    {
        return Err(HydrationBlocker::InvalidSandboxMetadata);
    }

    for (key, entry) in &metadata.registry {
        validate_identifier(key).map_err(|_| HydrationBlocker::InvalidObjectId)?;
        if key != &entry.object_id {
            return Err(HydrationBlocker::InvalidSandboxMetadata);
        }
        validate_identifier(&entry.object_id).map_err(|_| HydrationBlocker::InvalidObjectId)?;
        validate_identifier(&entry.fixture_key)
            .map_err(|_| HydrationBlocker::InvalidRegistryKey)?;
        if fixture_object_bytes(&entry.fixture_key).is_none() {
            return Err(HydrationBlocker::InvalidRegistryKey);
        }
        if entry.hash.len() != 64
            || !entry
                .hash
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            return Err(HydrationBlocker::InvalidSandboxMetadata);
        }
    }
    Ok(())
}

fn registry_fingerprint(registry: &BTreeMap<String, HydrationRegistryEntry>) -> String {
    let mut payload = String::from("devdrop-hydration-registry-v1\n");
    for (key, entry) in registry {
        payload.push_str(key);
        payload.push('\0');
        payload.push_str(&entry.object_id);
        payload.push('\0');
        payload.push_str(&entry.fixture_key);
        payload.push('\0');
        payload.push_str(&entry.hash);
        payload.push('\0');
        payload.push_str(&entry.size.to_string());
        payload.push('\n');
    }
    blake3::hash(payload.as_bytes()).to_hex().to_string()
}

fn resolve_source(
    metadata: &HydrationSandboxMetadata,
    marker: &HydrationStubMarker,
) -> (Option<HydrationSource>, Vec<HydrationBlocker>) {
    let Some(entry) = metadata.registry.get(&marker.object_id) else {
        return (None, vec![HydrationBlocker::SourceObjectMissing]);
    };
    let Some(source) = source_if_entry_matches(entry, &marker.content_hash, marker.size) else {
        return (None, vec![HydrationBlocker::SourceHashMismatch]);
    };
    (Some(source), Vec::new())
}

fn source_if_entry_matches(
    entry: &HydrationRegistryEntry,
    hash: &ContentHash,
    size: u64,
) -> Option<HydrationSource> {
    let bytes = fixture_object_bytes(&entry.fixture_key)?;
    let actual_hash = ContentHash::hash_bytes(bytes);
    if entry.hash != actual_hash.digest || entry.size != bytes.len() as u64 {
        return None;
    }
    if hash.digest != actual_hash.digest || size != bytes.len() as u64 {
        return None;
    }
    Some(HydrationSource {
        object_id: entry.object_id.clone(),
        fixture_key: entry.fixture_key.clone(),
        content_hash: actual_hash,
        size: bytes.len() as u64,
    })
}

fn validate_identifier(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 80
        || value.contains("..")
        || value.contains('/')
        || value.contains('\\')
        || value.contains(':')
        || value.chars().any(char::is_control)
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(());
    }
    Ok(())
}

fn validate_target_path(root: &Path, target: &Path) -> Vec<HydrationBlocker> {
    let mut blockers = Vec::new();
    let parent = target.parent().unwrap_or(root);
    let parent_metadata = match fs::symlink_metadata(parent) {
        Ok(metadata) => metadata,
        Err(_) => {
            blockers.push(HydrationBlocker::MetadataError);
            return blockers;
        }
    };
    if parent_metadata.file_type().is_symlink() {
        blockers.push(HydrationBlocker::ParentSymlink);
    }

    if let Ok(metadata) = fs::symlink_metadata(target) {
        if metadata.file_type().is_symlink() {
            blockers.push(HydrationBlocker::TargetSymlink);
        }
    }

    let Ok(parent_canonical) = fs::canonicalize(parent) else {
        blockers.push(HydrationBlocker::MetadataError);
        return blockers;
    };
    if !parent_canonical.starts_with(root) {
        blockers.push(HydrationBlocker::OutsideSandboxRoot);
    }

    blockers
}

fn relative_path(root: &Path, path: &Path) -> String {
    let normalized_root = normalize_path(root);
    let normalized_path = path
        .parent()
        .and_then(|parent| fs::canonicalize(parent).ok())
        .and_then(|parent| path.file_name().map(|file_name| parent.join(file_name)))
        .map(normalize_path)
        .unwrap_or_else(|| normalize_path(path));
    normalized_path
        .strip_prefix(normalized_root)
        .unwrap_or(normalized_path.as_path())
        .to_string_lossy()
        .replace('\\', "/")
}

fn normalize_path(path: impl AsRef<Path>) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.as_ref().components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

fn is_canonical_hydration_fixture(path: &Path) -> bool {
    path.to_string_lossy()
        .replace('\\', "/")
        .contains("fixtures/repos/hydration-project")
}

fn write_and_verify_temp(
    temp_path: &Path,
    bytes: &[u8],
    expected_hash: &ContentHash,
) -> Result<(), ()> {
    let mut file = fs::File::create(temp_path).map_err(|_| ())?;
    file.write_all(bytes).map_err(|_| ())?;
    file.sync_all().map_err(|_| ())?;
    let actual = fs::read(temp_path).map_err(|_| ())?;
    if ContentHash::hash_bytes(&actual) == *expected_hash {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(unix)]
fn replace_target_with_temp(temp_path: &Path, target: &Path) -> Result<(), ()> {
    fs::rename(temp_path, target).map_err(|_| ())
}

#[cfg(windows)]
fn replace_target_with_temp(temp_path: &Path, target: &Path) -> Result<(), ()> {
    fs::copy(temp_path, target).map_err(|_| ())?;
    fs::remove_file(temp_path).map_err(|_| ())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_sandbox(root: &Path, metadata: &HydrationSandboxMetadata) {
        fs::write(
            root.join(HYDRATION_SANDBOX_FILE),
            serde_json::to_string_pretty(metadata).expect("metadata serializes"),
        )
        .expect("write sandbox metadata");
    }

    fn write_stub(root: &Path, path: &str) -> PathBuf {
        let metadata = HydrationSandboxMetadata::test_fixture();
        write_sandbox(root, &metadata);
        let entry = metadata
            .registry
            .get(FIXTURE_OBJECT_ALPHA_ID)
            .expect("entry");
        let hash = ContentHash {
            algorithm: crate::HashAlgorithm::Blake3,
            digest: entry.hash.clone(),
        };
        let marker = exact_stub_marker(&entry.object_id, &hash, entry.size);
        let target = root.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(&target, marker).expect("write stub");
        target
    }

    #[test]
    fn dry_run_refuses_unknown_path_without_reading_contents() {
        let dir = tempdir().expect("tempdir");
        let canary = "DD_DO_NOT_LEAK_VALUE";
        let target = dir.path().join("live.txt");
        fs::write(&target, canary).expect("write live file");

        let preview = preview_hydration(&target);
        let json = serde_json::to_string(&preview).expect("preview serializes");

        assert!(preview
            .blockers
            .contains(&HydrationBlocker::UnrecognizedSandbox));
        assert!(!json.contains(canary));
        assert!(!preview.mutated_files);
    }

    #[test]
    fn stub_from_test_sandbox_hydrates() {
        let dir = tempdir().expect("tempdir");
        let target = write_stub(dir.path(), "src/stub.txt");
        let preview = preview_hydration(&target);

        assert_eq!(preview.state, HydrationState::Stub);
        assert!(preview.can_apply);
        assert!(!preview.mutated_files);

        let receipt = apply_hydration_preview(&preview);
        assert!(receipt.attempted_write);
        assert!(receipt.write_completed);
        assert!(receipt.mutated_files);
        assert!(!receipt.idempotent);

        let bytes = fs::read(&target).expect("hydrated target");
        assert_eq!(
            ContentHash::hash_bytes(&bytes),
            preview.source.unwrap().content_hash
        );
    }

    #[test]
    fn repeated_hydration_is_idempotent() {
        let dir = tempdir().expect("tempdir");
        let target = write_stub(dir.path(), "src/stub.txt");
        let first = apply_hydration(&target);
        assert!(first.mutated_files);

        let second_preview = preview_hydration(&target);
        let second = apply_hydration_preview(&second_preview);
        assert!(second.idempotent);
        assert!(!second.attempted_write);
        assert!(!second.write_completed);
        assert!(!second.mutated_files);
    }

    #[test]
    fn dirty_ignored_secret_missing_conflict_and_non_marker_block() {
        let dir = tempdir().expect("tempdir");
        let mut metadata = HydrationSandboxMetadata::test_fixture()
            .with_dirty_path("dirty.txt")
            .with_conflict_path("conflict.txt");
        write_sandbox(dir.path(), &metadata);

        for (path, blocker) in [
            ("dirty.txt", HydrationBlocker::DirtyLocal),
            ("node_modules/pkg.txt", HydrationBlocker::IgnoredPath),
            (".env", HydrationBlocker::SecretPath),
            ("missing.txt", HydrationBlocker::StubMarkerMissing),
            ("conflict.txt", HydrationBlocker::Conflict),
            ("plain.txt", HydrationBlocker::DirtyLocal),
        ] {
            let target = dir.path().join(path);
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent).expect("parent");
            }
            if path != "missing.txt" {
                fs::write(&target, "plain user text").expect("write target");
            }
            let preview = preview_hydration(&target);
            assert!(preview.blockers.contains(&blocker), "{path:?}");
            let receipt = apply_hydration_preview(&preview);
            assert!(!receipt.attempted_write);
            assert!(!receipt.write_completed);
            assert!(!receipt.idempotent);
            assert!(!receipt.mutated_files);
        }

        metadata.registry_fingerprint = "bad".to_string();
        write_sandbox(dir.path(), &metadata);
        let target = dir.path().join("plain.txt");
        let preview = preview_hydration(&target);
        assert!(preview
            .blockers
            .contains(&HydrationBlocker::InvalidSandboxMetadata));
    }

    #[test]
    fn malicious_marker_object_ids_are_refused() {
        for object_id in ["../x", r"..\x", r"C:\x", "/tmp/x", r"\\server\share\x"] {
            let marker = format!(
                "{STUB_MARKER_PREFIX} object_id={object_id} hash=blake3:{} size=1\n",
                "a".repeat(64)
            );
            assert!(matches!(
                parse_stub_marker(&marker),
                Err(HydrationBlocker::InvalidObjectId)
            ));
        }
    }

    #[test]
    fn malicious_registry_keys_are_refused() {
        for key in ["../x", r"..\x", r"C:\x", "/tmp/x", r"\\server\share\x"] {
            let dir = tempdir().expect("tempdir");
            let mut metadata = HydrationSandboxMetadata::test_fixture();
            let mut entry = metadata
                .registry
                .remove(FIXTURE_OBJECT_ALPHA_ID)
                .expect("entry");
            entry.fixture_key = key.to_string();
            metadata.registry.insert(entry.object_id.clone(), entry);
            metadata.registry_fingerprint = registry_fingerprint(&metadata.registry);
            write_sandbox(dir.path(), &metadata);
            let target = dir.path().join("stub.txt");
            fs::write(
                &target,
                exact_stub_marker(
                    FIXTURE_OBJECT_ALPHA_ID,
                    &ContentHash::hash_bytes(FIXTURE_OBJECT_ALPHA_BYTES),
                    FIXTURE_OBJECT_ALPHA_BYTES.len() as u64,
                ),
            )
            .expect("write stub");

            let preview = preview_hydration(target);
            assert!(preview.blockers.iter().any(|blocker| matches!(
                blocker,
                HydrationBlocker::InvalidSandboxMetadata | HydrationBlocker::InvalidRegistryKey
            )));
        }
    }

    #[test]
    fn stale_preview_blocks_apply() {
        let dir = tempdir().expect("tempdir");
        let target = write_stub(dir.path(), "stub.txt");
        let preview = preview_hydration(&target);
        fs::write(&target, "changed").expect("change stub after preview");

        let receipt = apply_hydration_preview(&preview);
        assert!(receipt.blockers.contains(&HydrationBlocker::StalePreview));
        assert!(!receipt.attempted_write);
        assert!(!receipt.write_completed);
        assert!(!receipt.mutated_files);
    }

    #[test]
    fn source_hash_mismatch_blocks() {
        let dir = tempdir().expect("tempdir");
        let mut metadata = HydrationSandboxMetadata::test_fixture();
        if let Some(entry) = metadata.registry.get_mut(FIXTURE_OBJECT_ALPHA_ID) {
            entry.hash = "0".repeat(64);
        }
        metadata.registry_fingerprint = registry_fingerprint(&metadata.registry);
        write_sandbox(dir.path(), &metadata);
        let entry = metadata
            .registry
            .get(FIXTURE_OBJECT_ALPHA_ID)
            .expect("entry");
        let marker = exact_stub_marker(
            &entry.object_id,
            &ContentHash {
                algorithm: crate::HashAlgorithm::Blake3,
                digest: entry.hash.clone(),
            },
            entry.size,
        );
        let target = dir.path().join("stub.txt");
        fs::write(&target, marker).expect("write stub");

        let preview = preview_hydration(&target);
        assert!(preview
            .blockers
            .contains(&HydrationBlocker::SourceHashMismatch));
    }

    #[test]
    fn canonical_fixture_paths_are_refused() {
        let canonical = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/repos/hydration-project/README.md");
        let before = fs::read(&canonical).expect("read canonical fixture before");
        let preview = preview_hydration(canonical);
        assert!(preview
            .blockers
            .contains(&HydrationBlocker::CanonicalFixtureReadOnly));
        let receipt = apply_hydration_preview(&preview);
        assert!(!receipt.attempted_write);
        assert!(!receipt.mutated_files);
        let after = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/repos/hydration-project/README.md"),
        )
        .expect("read canonical fixture after");
        assert_eq!(before, after);
    }

    #[test]
    fn checked_in_stub_marker_example_matches_fixture_object() {
        let example = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/repos/hydration-project/stub-marker.example.txt");
        let expected = exact_stub_marker(
            FIXTURE_OBJECT_ALPHA_ID,
            &ContentHash::hash_bytes(FIXTURE_OBJECT_ALPHA_BYTES),
            FIXTURE_OBJECT_ALPHA_BYTES.len() as u64,
        );
        let actual = fs::read_to_string(example).expect("read example marker");
        assert_eq!(actual, expected, "expected marker:\n{expected}");
    }

    #[test]
    fn partial_failure_is_recoverable_and_not_success() {
        let dir = tempdir().expect("tempdir");
        let target = write_stub(dir.path(), "stub.txt");
        let preview = preview_hydration(&target);
        let receipt = apply_hydration_preview_with_options(
            &preview,
            HydrationApplyOptions {
                simulate_failure_after_temp_write: true,
            },
        );

        assert!(receipt.attempted_write);
        assert!(!receipt.write_completed);
        assert!(!receipt.mutated_files);
        assert!(receipt
            .blockers
            .contains(&HydrationBlocker::PartialWriteFailure));
        assert!(fs::read_to_string(&target)
            .expect("target still readable")
            .starts_with(STUB_MARKER_PREFIX));
    }

    #[cfg(windows)]
    #[test]
    fn symlink_target_and_parent_block_on_windows_when_available() {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let dir = tempdir().expect("tempdir");
        let target = write_stub(dir.path(), "stub.txt");
        let link = dir.path().join("link.txt");
        if symlink_file(&target, &link).is_ok() {
            let preview = preview_hydration(&link);
            assert!(preview.blockers.contains(&HydrationBlocker::TargetSymlink));
        }

        let real_parent = dir.path().join("real-parent");
        fs::create_dir(&real_parent).expect("real parent");
        let linked_parent = dir.path().join("linked-parent");
        if symlink_dir(&real_parent, &linked_parent).is_ok() {
            let parent_target = linked_parent.join("stub.txt");
            fs::write(&parent_target, fs::read_to_string(&target).expect("stub")).expect("stub");
            let preview = preview_hydration(&parent_target);
            assert!(preview.blockers.contains(&HydrationBlocker::ParentSymlink));
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlink_target_and_parent_block_on_unix() {
        use std::os::unix::fs::{symlink, symlink as symlink_dir};

        let dir = tempdir().expect("tempdir");
        let target = write_stub(dir.path(), "stub.txt");
        let link = dir.path().join("link.txt");
        symlink(&target, &link).expect("symlink target");
        let preview = preview_hydration(&link);
        assert!(preview.blockers.contains(&HydrationBlocker::TargetSymlink));

        let real_parent = dir.path().join("real-parent");
        fs::create_dir(&real_parent).expect("real parent");
        let linked_parent = dir.path().join("linked-parent");
        symlink_dir(&real_parent, &linked_parent).expect("symlink dir");
        let parent_target = linked_parent.join("stub.txt");
        fs::write(&parent_target, fs::read_to_string(&target).expect("stub")).expect("stub");
        let preview = preview_hydration(&parent_target);
        assert!(preview.blockers.contains(&HydrationBlocker::ParentSymlink));
    }
}
