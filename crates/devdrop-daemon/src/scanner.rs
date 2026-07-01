use std::{
    collections::HashSet,
    fs,
    path::{Component, Path, PathBuf},
};

use devdrop_core::{IgnorePolicy, PathClassification};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::state::RegisteredProject;

/// Default maximum metadata entries inspected per scan.
pub const DEFAULT_SCAN_BUDGET: usize = 10_000;

/// Metadata-only scan report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    /// Registered project ID.
    pub project_id: String,
    /// Number of metadata entries inspected.
    pub inspected_entries: usize,
    /// Project-relative tracked paths observed.
    pub tracked_paths: Vec<String>,
    /// Project-relative generated/ignored paths pruned.
    pub ignored_paths: Vec<String>,
    /// Project-relative secret-bearing paths observed as metadata only.
    pub secret_metadata_paths: Vec<String>,
    /// Project-relative symlink paths skipped.
    pub skipped_symlinks: Vec<String>,
    /// Metadata scan errors that were reported instead of swallowed.
    pub errors: Vec<ScanErrorSummary>,
    /// Whether the scan stopped because the budget was exhausted.
    pub budget_exhausted: bool,
    /// Whether files were mutated. Always false in this daemon slice.
    pub mutated_files: bool,
    /// Whether this scan read file contents. Always false in this daemon slice.
    pub read_file_contents: bool,
    /// Redaction notice for API/log consumers.
    pub redaction_notice: String,
}

impl ScanReport {
    /// Empty safe report for a registered project.
    pub fn empty(project_id: impl Into<String>) -> Self {
        Self {
            project_id: project_id.into(),
            inspected_entries: 0,
            tracked_paths: Vec::new(),
            ignored_paths: Vec::new(),
            secret_metadata_paths: Vec::new(),
            skipped_symlinks: Vec::new(),
            errors: Vec::new(),
            budget_exhausted: false,
            mutated_files: false,
            read_file_contents: false,
            redaction_notice:
                "Daemon reports metadata only; secret values and file contents are absent."
                    .to_string(),
        }
    }
}

/// Safe scan error summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanErrorSummary {
    /// Project-relative path if it is safely available.
    pub relative_path: Option<String>,
    /// Error category.
    pub kind: ScanErrorKind,
    /// Redacted error message.
    pub message: String,
}

/// Scan error categories.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanErrorKind {
    /// Project root is missing or not readable.
    RootUnavailable,
    /// Directory could not be read.
    ReadDirectory,
    /// Entry metadata could not be observed.
    Metadata,
    /// Path was outside the registered root.
    OutsideRegisteredRoot,
    /// Symlink or canonical loop was skipped.
    LoopOrSymlink,
}

/// Runs a metadata-only reconciliation scan for a registered project.
pub fn scan_project_metadata(
    project: &RegisteredProject,
    policy: &IgnorePolicy,
    max_entries: usize,
) -> ScanReport {
    let mut report = ScanReport::empty(project.id.clone());

    if !project.root.exists() {
        report.errors.push(ScanErrorSummary {
            relative_path: None,
            kind: ScanErrorKind::RootUnavailable,
            message: "Registered project root is not available for metadata scan.".to_string(),
        });
        return report;
    }

    let root = normalize_path(&project.root);
    let mut stack = vec![root.clone()];
    let mut visited_dirs = HashSet::new();

    while let Some(dir) = stack.pop() {
        if report.inspected_entries >= max_entries {
            report.budget_exhausted = true;
            break;
        }

        match fs::canonicalize(&dir) {
            Ok(canonical) => {
                if !visited_dirs.insert(canonical) {
                    report.skipped_symlinks.push(relative_path(&root, &dir));
                    report.errors.push(ScanErrorSummary {
                        relative_path: Some(relative_path(&root, &dir)),
                        kind: ScanErrorKind::LoopOrSymlink,
                        message: "Directory loop was skipped during metadata scan.".to_string(),
                    });
                    continue;
                }
            }
            Err(error) => {
                report.errors.push(ScanErrorSummary {
                    relative_path: Some(relative_path(&root, &dir)),
                    kind: ScanErrorKind::Metadata,
                    message: redact_error(error),
                });
                continue;
            }
        }

        let read_dir = match fs::read_dir(&dir) {
            Ok(read_dir) => read_dir,
            Err(error) => {
                report.errors.push(ScanErrorSummary {
                    relative_path: Some(relative_path(&root, &dir)),
                    kind: ScanErrorKind::ReadDirectory,
                    message: redact_error(error),
                });
                continue;
            }
        };

        for entry_result in read_dir {
            if report.inspected_entries >= max_entries {
                report.budget_exhausted = true;
                break;
            }

            let entry = match entry_result {
                Ok(entry) => entry,
                Err(error) => {
                    report.errors.push(ScanErrorSummary {
                        relative_path: Some(relative_path(&root, &dir)),
                        kind: ScanErrorKind::ReadDirectory,
                        message: redact_error(error),
                    });
                    continue;
                }
            };

            let path = normalize_path(&entry.path());
            if !path_is_contained(&root, &path) {
                report.errors.push(ScanErrorSummary {
                    relative_path: None,
                    kind: ScanErrorKind::OutsideRegisteredRoot,
                    message: "Entry escaped the registered project root and was skipped."
                        .to_string(),
                });
                continue;
            }

            report.inspected_entries += 1;
            let relative = relative_path(&root, &path);
            let classification = policy.classify(&relative);

            let metadata = match fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    report.errors.push(ScanErrorSummary {
                        relative_path: Some(relative),
                        kind: ScanErrorKind::Metadata,
                        message: redact_error(error),
                    });
                    continue;
                }
            };

            if metadata.file_type().is_symlink() {
                report.skipped_symlinks.push(relative);
                continue;
            }

            match classification {
                PathClassification::Generated => {
                    report.ignored_paths.push(relative);
                }
                PathClassification::Secret => {
                    report.secret_metadata_paths.push(relative);
                }
                PathClassification::Tracked => {
                    if metadata.is_dir() {
                        stack.push(path);
                    } else {
                        report.tracked_paths.push(relative);
                    }
                }
            }
        }
    }

    warn!(
        project_id = %project.id,
        inspected_entries = report.inspected_entries,
        ignored_paths = report.ignored_paths.len(),
        secret_metadata_paths = report.secret_metadata_paths.len(),
        scan_errors = report.errors.len(),
        budget_exhausted = report.budget_exhausted,
        mutated_files = false,
        "metadata-only reconciliation scan completed"
    );

    report
}

/// Returns whether a candidate path is lexically contained by the root.
pub fn path_is_contained(root: &Path, candidate: &Path) -> bool {
    let root = normalize_path(root);
    let candidate = if candidate.is_absolute() {
        normalize_path(candidate)
    } else {
        normalize_path(root.join(candidate))
    };
    candidate == root || candidate.starts_with(root)
}

/// Produces a project-relative path string after lexical normalization.
pub fn relative_path(root: &Path, path: &Path) -> String {
    let root = normalize_path(root);
    let path = normalize_path(path);
    path.strip_prefix(&root)
        .unwrap_or(path.as_path())
        .to_string_lossy()
        .replace('\\', "/")
}

fn redact_error(error: std::io::Error) -> String {
    format!("Metadata observation error: {}", error.kind())
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

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use devdrop_core::IgnorePolicy;
    use tempfile::tempdir;

    use super::*;

    fn registered(root: PathBuf) -> RegisteredProject {
        RegisteredProject::new("project:test", "test", root)
    }

    #[test]
    fn ignored_generated_paths_are_pruned() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/repos/ignored-path-project");
        let report = scan_project_metadata(&registered(root), &IgnorePolicy::default(), 1_000);

        assert!(report
            .ignored_paths
            .iter()
            .any(|path| path == "node_modules"));
        assert!(report.ignored_paths.iter().any(|path| path == ".next"));
        assert!(report.ignored_paths.iter().any(|path| path == "dist"));
        assert!(report.ignored_paths.iter().any(|path| path == "target"));
        assert!(report.ignored_paths.iter().any(|path| path == "logs"));
        assert!(report.ignored_paths.iter().any(|path| path == "build.log"));
        assert!(!report
            .tracked_paths
            .iter()
            .any(|path| path.contains("node_modules")));
        assert!(!report.mutated_files);
        assert!(!report.read_file_contents);
    }

    #[test]
    fn secret_paths_are_metadata_only_and_values_are_absent() {
        let dir = tempdir().expect("tempdir");
        let canary = "DD_DO_NOT_LEAK_VALUE";
        fs::write(dir.path().join(".env"), format!("TOKEN={canary}")).expect("write env");
        fs::write(dir.path().join("src.txt"), "tracked").expect("write tracked");

        let report = scan_project_metadata(
            &registered(dir.path().to_path_buf()),
            &IgnorePolicy::default(),
            100,
        );
        let json = serde_json::to_string(&report).expect("report serializes");

        assert!(report
            .secret_metadata_paths
            .iter()
            .any(|path| path == ".env"));
        assert!(!json.contains(canary));
        assert!(report.tracked_paths.iter().any(|path| path == "src.txt"));
    }

    #[test]
    fn traversal_like_paths_do_not_escape_registered_root() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path().join("root");
        let outside = dir.path().join("outside.txt");
        fs::create_dir(&root).expect("create root");
        fs::write(&outside, "outside").expect("write outside");

        assert!(!path_is_contained(
            &root,
            &root.join("..").join("outside.txt")
        ));
        assert!(path_is_contained(&root, &root.join("inside.txt")));
    }

    #[test]
    fn scan_budget_is_reported() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("a.txt"), "a").expect("write a");
        fs::write(dir.path().join("b.txt"), "b").expect("write b");

        let report = scan_project_metadata(
            &registered(dir.path().to_path_buf()),
            &IgnorePolicy::default(),
            1,
        );
        assert!(report.budget_exhausted);
        assert_eq!(report.inspected_entries, 1);
    }

    #[test]
    fn scan_errors_are_reported() {
        let report = scan_project_metadata(
            &registered(PathBuf::from("definitely-missing-devdrop-root")),
            &IgnorePolicy::default(),
            100,
        );

        assert!(!report.errors.is_empty());
        assert_eq!(report.errors[0].kind, ScanErrorKind::RootUnavailable);
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_skipped_on_unix() {
        use std::os::unix::fs::symlink;

        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("target.txt"), "target").expect("write target");
        symlink(dir.path().join("target.txt"), dir.path().join("link.txt")).expect("symlink");

        let report = scan_project_metadata(
            &registered(dir.path().to_path_buf()),
            &IgnorePolicy::default(),
            100,
        );
        assert!(report
            .skipped_symlinks
            .iter()
            .any(|path| path == "link.txt"));
    }

    #[cfg(windows)]
    #[test]
    fn symlinks_are_skipped_on_windows_when_available() {
        use std::os::windows::fs::symlink_file;

        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("target.txt"), "target").expect("write target");
        if symlink_file(dir.path().join("target.txt"), dir.path().join("link.txt")).is_err() {
            return;
        }

        let report = scan_project_metadata(
            &registered(dir.path().to_path_buf()),
            &IgnorePolicy::default(),
            100,
        );
        assert!(report
            .skipped_symlinks
            .iter()
            .any(|path| path == "link.txt"));
    }
}
