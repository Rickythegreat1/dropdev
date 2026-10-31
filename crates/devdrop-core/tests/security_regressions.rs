//! Regressions for independently reproduced data-loss and path-boundary findings.
//! All roots and payloads are generated under tempfile; no user directories are read.
use devdrop_core::local::{Engine, Pair};
use std::{fs, path::PathBuf, process::Command};

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
        let state = fs::canonicalize(temp.path()).unwrap().join("metadata");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&target).unwrap();
        Self {
            _temp: temp,
            source,
            target,
            state,
        }
    }
    fn pair(&self, engine: &Engine) -> Pair {
        engine
            .register("generated review fixture", &self.source, &self.target)
            .unwrap()
    }
}

#[test]
fn newly_ignored_content_is_preserved_instead_of_deleted() {
    let w = Workspace::new();
    fs::write(
        w.source.join("keep.txt"),
        b"preserve existing workspace content",
    )
    .unwrap();
    let engine = Engine::open(&w.state).unwrap();
    let pair = w.pair(&engine);
    let first = engine.preview(&pair.id).unwrap();
    engine.apply(&first.id, &first.id).unwrap();
    fs::write(w.source.join(".gitignore"), b"keep.txt\n").unwrap();
    let next = engine.preview(&pair.id).unwrap();
    assert!(next.operations.iter().all(|op| op.path != "keep.txt"));
    engine.apply(&next.id, &next.id).unwrap();
    assert_eq!(
        fs::read(w.target.join("keep.txt")).unwrap(),
        b"preserve existing workspace content"
    );
    assert!(engine.preview(&pair.id).unwrap().operations.is_empty());
}

#[test]
fn ripgrep_ignore_configuration_cannot_create_deletion_intent() {
    let w = Workspace::new();
    fs::write(
        w.source.join("keep.txt"),
        b"preserve existing workspace content",
    )
    .unwrap();
    let engine = Engine::open(&w.state).unwrap();
    let pair = w.pair(&engine);
    let first = engine.preview(&pair.id).unwrap();
    engine.apply(&first.id, &first.id).unwrap();
    fs::write(w.source.join(".ignore"), b"keep.txt\n").unwrap();
    let next = engine.preview(&pair.id).unwrap();
    assert!(next.operations.iter().all(|op| op.kind != "delete"));
    engine.apply(&next.id, &next.id).unwrap();
    assert_eq!(
        fs::read(w.target.join("keep.txt")).unwrap(),
        b"preserve existing workspace content"
    );
}

#[cfg(unix)]
#[test]
fn metadata_child_symlinks_cannot_redirect_local_storage_writes() {
    use std::os::unix::fs::symlink;
    for child in [
        "metadata.sqlite3",
        "metadata.sqlite3-wal",
        "metadata.sqlite3-shm",
        "writer.lock",
        "objects",
    ] {
        let w = Workspace::new();
        fs::create_dir(&w.state).unwrap();
        let outside = w._temp.path().join("unrelated");
        if child == "objects" {
            fs::create_dir(&outside).unwrap();
        } else {
            fs::write(&outside, b"untouched unrelated generated file").unwrap();
        }
        symlink(&outside, w.state.join(child)).unwrap();
        assert!(
            Engine::open(&w.state).is_err(),
            "accepted a symlink for {child}"
        );
        if child != "objects" {
            assert_eq!(
                fs::read(outside).unwrap(),
                b"untouched unrelated generated file"
            );
        }
    }
}

fn git(root: &std::path::Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "disposable Git fixture command failed"
    );
}

#[test]
fn dirty_git_is_detected_when_registered_root_is_inside_worktree() {
    let w = Workspace::new();
    let nested = w.source.join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(nested.join("work.txt"), b"committed content").unwrap();
    git(&w.source, &["init", "--quiet"]);
    git(&w.source, &["add", "nested/work.txt"]);
    git(
        &w.source,
        &[
            "-c",
            "user.name=Generated Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "generated fixture",
        ],
    );
    fs::write(nested.join("work.txt"), b"uncommitted generated change").unwrap();
    let engine = Engine::open(&w.state).unwrap();
    let pair = engine
        .register("nested generated fixture", &nested, &w.target)
        .unwrap();
    match engine.preview(&pair.id) {
        Ok(plan) => {
            assert!(
                !plan.blockers.is_empty(),
                "nested root silently bypassed dirty Git gate"
            );
            assert!(engine.apply(&plan.id, &plan.id).is_err());
        }
        Err(error) => {
            // Standard hosted runners configure Git LFS globally. A refusal to
            // execute any external filter is also a valid nested-worktree gate.
            assert!(error.to_string().contains("External Git filters"));
        }
    }
    assert!(!w.target.join("work.txt").exists());
}

#[cfg(unix)]
#[test]
fn git_observation_does_not_execute_repository_clean_filter() {
    let w = Workspace::new();
    fs::write(w.source.join("work.txt"), b"committed content").unwrap();
    fs::write(w.source.join(".gitattributes"), b"*.txt filter=generated\n").unwrap();
    git(&w.source, &["init", "--quiet"]);
    git(&w.source, &["add", "."]);
    git(
        &w.source,
        &[
            "-c",
            "user.name=Generated Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "generated fixture",
        ],
    );
    let marker = w._temp.path().join("unexpected-filter-execution");
    let filter = format!("touch '{}'; cat", marker.display());
    git(&w.source, &["config", "filter.generated.clean", &filter]);
    fs::write(w.source.join("work.txt"), b"uncommitted generated change").unwrap();
    let engine = Engine::open(&w.state).unwrap();
    let pair = w.pair(&engine);
    let result = engine.preview(&pair.id);
    assert!(
        !marker.exists(),
        "read-only Git observation executed a repository clean filter"
    );
    assert!(result.is_err() || !result.unwrap().blockers.is_empty());
}

#[cfg(unix)]
#[test]
fn symlinked_gitignore_policy_is_refused_without_capturing_external_bytes() {
    use std::os::unix::fs::symlink;
    let w = Workspace::new();
    let outside = w._temp.path().join("private-policy-source");
    let canary = b"PRIVATE_GENERATED_POLICY_CANARY_49211";
    fs::write(&outside, canary).unwrap();
    fs::write(w.source.join("work.txt"), b"ordinary fixture").unwrap();
    symlink(&outside, w.source.join(".gitignore")).unwrap();
    let engine = Engine::open(&w.state).unwrap();
    let pair = w.pair(&engine);
    let error = engine.preview(&pair.id).unwrap_err().to_string();
    assert!(!error.contains("PRIVATE_GENERATED_POLICY_CANARY"));
    assert!(!error.contains(outside.to_str().unwrap()));
    for object in fs::read_dir(w.state.join("objects")).unwrap() {
        assert_ne!(fs::read(object.unwrap().path()).unwrap(), canary);
    }
    assert!(!w.target.join("work.txt").exists());
}

#[test]
fn oversized_gitignore_policy_fails_closed_before_object_storage() {
    let w = Workspace::new();
    let huge = vec![b'x'; 1024 * 1024 + 1];
    fs::write(w.source.join(".gitignore"), &huge).unwrap();
    fs::write(w.source.join("work.txt"), b"ordinary fixture").unwrap();
    let engine = Engine::open(&w.state).unwrap();
    let pair = w.pair(&engine);
    let error = engine.preview(&pair.id).unwrap_err().to_string();
    assert!(!error.contains("xxxxxxxx"));
    for object in fs::read_dir(w.state.join("objects")).unwrap() {
        assert_ne!(fs::read(object.unwrap().path()).unwrap(), huge);
    }
    assert!(!w.target.join("work.txt").exists());
}

#[test]
fn nested_anchored_gitignore_is_scoped_to_its_own_directory() {
    let w = Workspace::new();
    fs::create_dir(w.source.join("nested")).unwrap();
    fs::write(w.source.join("nested/.gitignore"), b"/private.txt\n").unwrap();
    let canary = b"generated ignored nested content 74922";
    fs::write(w.source.join("nested/private.txt"), canary).unwrap();
    fs::write(
        w.source.join("nested/public.txt"),
        b"ordinary public fixture",
    )
    .unwrap();
    let engine = Engine::open(&w.state).unwrap();
    let pair = w.pair(&engine);
    let plan = engine.preview(&pair.id).unwrap();
    assert!(plan
        .operations
        .iter()
        .all(|op| op.path != "nested/private.txt"));
    assert!(plan
        .operations
        .iter()
        .any(|op| op.path == "nested/public.txt"));
    for object in fs::read_dir(w.state.join("objects")).unwrap() {
        assert_ne!(fs::read(object.unwrap().path()).unwrap(), canary);
    }
    engine.apply(&plan.id, &plan.id).unwrap();
    assert!(!w.target.join("nested/private.txt").exists());
}

#[test]
fn nested_gitignore_can_reinclude_a_file_inside_an_unignored_parent() {
    let w = Workspace::new();
    fs::create_dir(w.source.join("nested")).unwrap();
    fs::write(w.source.join(".gitignore"), b"*.txt\n").unwrap();
    fs::write(w.source.join("nested/.gitignore"), b"!public.txt\n").unwrap();
    fs::write(
        w.source.join("nested/public.txt"),
        b"ordinary public fixture",
    )
    .unwrap();
    fs::write(
        w.source.join("nested/private.txt"),
        b"ordinary ignored fixture",
    )
    .unwrap();
    let engine = Engine::open(&w.state).unwrap();
    let pair = w.pair(&engine);
    let plan = engine.preview(&pair.id).unwrap();
    assert!(plan
        .operations
        .iter()
        .any(|op| op.path == "nested/public.txt"));
    assert!(plan
        .operations
        .iter()
        .all(|op| op.path != "nested/private.txt"));
    engine.apply(&plan.id, &plan.id).unwrap();
    assert!(w.target.join("nested/public.txt").exists());
    assert!(!w.target.join("nested/private.txt").exists());
}
