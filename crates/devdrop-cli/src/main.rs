use clap::{Parser, Subcommand};
use devdrop_core::{
    apply_hydration, hydration_counts, preview_hydration, ApprovalFlag, HydrationApplyReceipt,
    IgnorePolicy, ReadinessReport, SyncPlan, SyncPlanReceipt,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Parser)]
#[command(name = "devdrop")]
#[command(about = "DevDrop local-first workspace coherence MVP")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Initialize local DevDrop metadata contracts without writing files.
    Init,
    /// Print workspace readiness.
    Doctor {
        /// Emit stable JSON instead of human output.
        #[arg(long)]
        json: bool,
    },
    /// Run a deterministic fixture-backed scan only.
    Scan {
        /// Optional fixture path or name. Unknown paths are not recursively scanned.
        path: Option<String>,
    },
    /// Show deterministic status from the same safe report path as scan.
    Status {
        /// Optional fixture path or name. Unknown paths are not recursively scanned.
        path: Option<String>,
    },
    /// Simulate lazy hydration. Preview remains dry-run; apply is sandbox-only.
    Hydrate {
        /// Preview safety gate. No hydration is applied.
        #[arg(long)]
        dry_run: bool,
        /// Fixture sandbox path to preview.
        path: Option<String>,
        #[command(subcommand)]
        command: Option<HydrateCommand>,
    },
    /// Preview sync behavior.
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },
    /// Inspect and preview conflict behavior.
    Conflict {
        #[command(subcommand)]
        command: ConflictCommand,
    },
    /// Inspect machine map placeholders.
    Machine {
        #[command(subcommand)]
        command: MachineCommand,
    },
    /// Inspect env profile readiness without values.
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// Plan redacted agent work.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Preview local MCP integration.
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Legacy dry-run snapshot preview.
    #[command(hide = true)]
    Snapshot,
    /// Legacy redacted handoff preview.
    #[command(hide = true)]
    Handoff,
}

#[derive(Debug, Subcommand)]
enum SyncCommand {
    /// Build a dry-run sync plan. Inherently non-mutating.
    Plan,
    /// Preview sync apply. Requires --dry-run in this slice.
    Apply {
        /// Required safety gate. No apply is performed.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
enum HydrateCommand {
    /// Apply sandbox-only hydration to an exact DevDrop stub.
    Apply {
        /// Target path inside a recognized test hydration sandbox.
        path: String,
    },
}

#[derive(Debug, Subcommand)]
enum ConflictCommand {
    /// List unresolved conflict concepts. Read-only.
    List {
        /// Optional fixture path or name.
        path: Option<String>,
    },
    /// Preview conflict resolution. Requires --dry-run.
    Resolve {
        /// Required safety gate. No conflict is resolved.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
enum MachineCommand {
    /// List deterministic machine map placeholders.
    List,
}

#[derive(Debug, Subcommand)]
enum EnvCommand {
    /// Check env key presence/fingerprint shape without values.
    Check {
        /// Optional fixture path or name.
        path: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Produce a redacted agent plan.
    Plan {
        /// Task words. The report does not echo raw task text.
        #[arg(required = true, num_args = 1..)]
        task: Vec<String>,
    },
    /// Produce a redacted agent contract.
    Contract {
        /// Task words. The report does not echo raw task text.
        #[arg(required = true, num_args = 1..)]
        task: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    /// Preview delegation to the devdrop-mcp JSON-over-STDIO scaffold.
    Serve,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CliReport {
    command: String,
    safe_to_work: bool,
    summary: String,
    blockers: Vec<String>,
    warnings: Vec<String>,
    evidence: Vec<String>,
    recommendations: Vec<String>,
    dry_run: bool,
    mutation_flags: MutationFlags,
    fixture_scenario: FixtureScenario,
    redaction_notice: String,
    exit_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MutationFlags {
    mutated_files: bool,
    mutated_git: bool,
    wrote_object_store: bool,
    wrote_sqlite: bool,
    wrote_registry: bool,
    wrote_manifest: bool,
    wrote_metadata: bool,
    changed_hydration_state: bool,
    resolved_conflicts: bool,
    applied_tombstones: bool,
}

impl MutationFlags {
    fn none() -> Self {
        Self {
            mutated_files: false,
            mutated_git: false,
            wrote_object_store: false,
            wrote_sqlite: false,
            wrote_registry: false,
            wrote_manifest: false,
            wrote_metadata: false,
            changed_hydration_state: false,
            resolved_conflicts: false,
            applied_tombstones: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum FixtureScenario {
    Ready,
    StaleGit,
    MissingEnv,
    Conflict,
    IgnoredPath,
    Hydration,
    Unknown,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let (output, exit_code) = render(cli.command)?;
    println!("{output}");
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

fn render(command: Commands) -> anyhow::Result<(String, i32)> {
    let json = matches!(command, Commands::Doctor { json: true });
    let report = handle_command(command);
    let exit_code = report.exit_code;

    if json {
        Ok((serde_json::to_string_pretty(&report)?, exit_code))
    } else {
        Ok((render_human(&report), exit_code))
    }
}

fn handle_command(command: Commands) -> CliReport {
    match command {
        Commands::Init => init_report(),
        Commands::Doctor { .. } => doctor_report(),
        Commands::Scan { path } => scenario_report("scan", scenario_from_path(path.as_deref())),
        Commands::Status { path } => status_report(path.as_deref()),
        Commands::Hydrate {
            dry_run,
            path,
            command,
        } => match command {
            Some(HydrateCommand::Apply { path }) => hydrate_apply_report(&path),
            None => hydrate_preview_report(dry_run, path.as_deref()),
        },
        Commands::Sync { command } => match command {
            SyncCommand::Plan => sync_plan_report(),
            SyncCommand::Apply { dry_run } => sync_apply_report(dry_run),
        },
        Commands::Conflict { command } => match command {
            ConflictCommand::List { path } => {
                conflict_list_report(scenario_from_path(path.as_deref()))
            }
            ConflictCommand::Resolve { dry_run } => conflict_resolve_report(dry_run),
        },
        Commands::Machine { command } => match command {
            MachineCommand::List => machine_list_report(),
        },
        Commands::Env { command } => match command {
            EnvCommand::Check { path } => env_check_report(scenario_from_path(path.as_deref())),
        },
        Commands::Agent { command } => match command {
            AgentCommand::Plan { task } => agent_report("agent plan", task.len()),
            AgentCommand::Contract { task } => agent_report("agent contract", task.len()),
        },
        Commands::Mcp { command } => match command {
            McpCommand::Serve => mcp_serve_report(),
        },
        Commands::Snapshot => legacy_dry_run_report(
            "snapshot",
            "Snapshot preview is dry-run only; no content-addressed objects are written.",
        ),
        Commands::Handoff => legacy_dry_run_report(
            "handoff",
            "Handoff preview is dry-run only; raw file text and env values are absent.",
        ),
    }
}

fn base_report(command: &str, summary: impl Into<String>) -> CliReport {
    CliReport {
        command: command.to_string(),
        safe_to_work: false,
        summary: summary.into(),
        blockers: Vec::new(),
        warnings: Vec::new(),
        evidence: Vec::new(),
        recommendations: Vec::new(),
        dry_run: true,
        mutation_flags: MutationFlags::none(),
        fixture_scenario: FixtureScenario::Unknown,
        redaction_notice:
            "Env values, raw file text, and generated dependency trees are not displayed."
                .to_string(),
        exit_code: 0,
    }
}

fn init_report() -> CliReport {
    let mut report = base_report(
        "init",
        "Initialization preview only. No manifest, registry, database, metadata, or config file was written.",
    );
    report
        .blockers
        .push("Local registry persistence is not implemented in this slice.".to_string());
    report.evidence.push(
        "Mutation flags show no file, registry, database, manifest, or metadata writes."
            .to_string(),
    );
    report.recommendations.push(
        "Use scan against known fixtures to inspect deterministic readiness states.".to_string(),
    );
    report
}

fn doctor_report() -> CliReport {
    let readiness = ReadinessReport::foundation_stub();
    let mut report = base_report("doctor", readiness.summary);
    report.blockers = readiness
        .blockers
        .into_iter()
        .map(|finding| format!("{}: {}", finding.area, finding.message))
        .collect();
    report.warnings = readiness
        .warnings
        .into_iter()
        .map(|finding| format!("{}: {}", finding.area, finding.message))
        .collect();
    report.evidence.push(format!(
        "{}; real sync complete: {}",
        readiness.slice, readiness.sync_complete
    ));
    report.evidence.push(
        "Doctor is non-mutating and does not inspect raw env values or file text.".to_string(),
    );
    report.recommendations.push(
        "Run scan with a known fixture path for deterministic readiness evidence.".to_string(),
    );
    report
}

fn scenario_report(command: &str, scenario: FixtureScenario) -> CliReport {
    let mut report = match scenario {
        FixtureScenario::Ready => {
            let mut report = base_report(
                command,
                "Known ready fixture: no deterministic blockers are modeled.",
            );
            report.safe_to_work = true;
            report
                .evidence
                .push("Fixture scenario: ready-project.".to_string());
            report.warnings.push(
                "This is fixture-backed only; no live recursive scan was performed.".to_string(),
            );
            report
        }
        FixtureScenario::StaleGit => {
            let mut report = base_report(
                command,
                "Known stale Git fixture: base freshness needs attention.",
            );
            report
                .blockers
                .push("Git freshness is stale in this fixture scenario.".to_string());
            report
                .evidence
                .push("Fixture scenario: stale-git-project.".to_string());
            report.recommendations.push(
                "Refresh Git state with preview-only commands before agent work.".to_string(),
            );
            report
        }
        FixtureScenario::MissingEnv => {
            let mut report = base_report(
                command,
                "Known missing env fixture: required key presence is incomplete.",
            );
            report.blockers.push(
                "Required env key name is missing; no value was read or printed.".to_string(),
            );
            report
                .evidence
                .push("Fixture scenario: missing-env-project.".to_string());
            report
                .evidence
                .push("Env evidence is limited to key names and fingerprints only.".to_string());
            report
                .recommendations
                .push("Provide required env keys locally, then re-run env check.".to_string());
            report
        }
        FixtureScenario::Conflict => {
            let mut report = base_report(
                command,
                "Known conflict fixture: unresolved conflict concepts are present.",
            );
            report
                .blockers
                .push("Unresolved conflicts are visible and not hidden.".to_string());
            report
                .evidence
                .push("Fixture scenario: conflict-project.".to_string());
            report
                .evidence
                .push("Conflict model preserves local and remote/mock versions.".to_string());
            report.recommendations.push(
                "Use conflict list, then conflict resolve --dry-run for preview only.".to_string(),
            );
            report
        }
        FixtureScenario::IgnoredPath => {
            let policy = IgnorePolicy::default();
            let mut report = base_report(
                command,
                "Known ignored-path fixture: generated paths are excluded by policy.",
            );
            report.safe_to_work = true;
            report
                .evidence
                .push("Fixture scenario: ignored-path-project.".to_string());
            report.evidence.push(format!(
                "build.log classification: {:?}",
                policy.classify("fixtures/repos/ignored-path-project/build.log")
            ));
            report.evidence.push(format!(
                "node_modules classification: {:?}",
                policy.classify("node_modules/example/index.js")
            ));
            report
                .warnings
                .push("Generated paths are not added to content-addressed storage.".to_string());
            report
        }
        FixtureScenario::Hydration => {
            let mut report = base_report(
                command,
                "Known hydration fixture: lazy hydration is simulation-only.",
            );
            report
                .blockers
                .push("Hydration apply is unavailable; only simulation is allowed.".to_string());
            report
                .evidence
                .push("Fixture scenario: hydration-project.".to_string());
            report.evidence.push(
                "No workspace files are written and no hydration state is changed.".to_string(),
            );
            report
                .recommendations
                .push("Use hydrate --dry-run <path> to preview hydration wording.".to_string());
            report
        }
        FixtureScenario::Unknown => unknown_fixture_report(command),
    };

    report.fixture_scenario = scenario;
    report
}

fn unknown_fixture_report(command: &str) -> CliReport {
    let mut report = base_report(
        command,
        "Unknown fixture scenario. DevDrop did not recursively scan this path.",
    );
    report.blockers.push(
        "No deterministic fixture scenario matched the provided path or current directory."
            .to_string(),
    );
    report
        .evidence
        .push("Safe fallback: report was built from path/name classification only.".to_string());
    report.recommendations.push(
        "Use fixtures/repos/ready-project or another known fixture for deterministic CLI evals."
            .to_string(),
    );
    report
}

fn status_report(path: Option<&str>) -> CliReport {
    let mut report = scenario_report("status", scenario_from_path(path));
    if let Some(path) = path {
        let counts = hydration_counts(path);
        if counts.stub
            + counts.hydrated
            + counts.dirty_local
            + counts.conflict
            + counts.ignored
            + counts.unavailable
            > 0
        {
            report.evidence.push(format!(
                "Hydration counts: absent={}, stub={}, hydrated={}, stale={}, dirty-local={}, conflict={}, ignored={}, unavailable={}",
                counts.absent,
                counts.stub,
                counts.hydrated,
                counts.stale,
                counts.dirty_local,
                counts.conflict,
                counts.ignored,
                counts.unavailable
            ));
        }
    }
    report
}

fn hydrate_preview_report(dry_run: bool, path: Option<&str>) -> CliReport {
    if !dry_run {
        return refusal_report(
            "hydrate",
            "Hydration requires --dry-run in this slice.",
            "No hydration was performed and no workspace files were written.",
        );
    }

    let Some(path) = path else {
        return refusal_report(
            "hydrate",
            "Hydration dry-run requires a path.",
            "No hydration preview was produced.",
        );
    };

    let preview = preview_hydration(path);
    let mut report = scenario_report("hydrate", scenario_from_path(Some(path)));
    report.summary = if preview.can_apply {
        "Hydration dry-run preview: exact sandbox stub can be applied by CLI-only simulation."
            .to_string()
    } else {
        "Hydration dry-run refused or blocked before apply.".to_string()
    };
    report.evidence.push(format!("Target path: {path}"));
    report
        .evidence
        .push(format!("Hydration state: {:?}", preview.state));
    report
        .evidence
        .push(format!("Dry-run mutated files: {}", preview.mutated_files));
    if let Some(source) = preview.source {
        report.evidence.push(format!(
            "Source object: {}; size: {}; hash: blake3:{}",
            source.object_id, source.size, source.content_hash.digest
        ));
    }
    report.evidence.push(format!("Risk: {}", preview.risk));
    for blocker in preview.blockers {
        report
            .blockers
            .push(format!("Hydration blocker: {blocker:?}"));
    }
    report.recommendations.push(
        "Use `devdrop hydrate apply <path>` only inside a recognized test sandbox.".to_string(),
    );
    report
}

fn hydrate_apply_report(path: &str) -> CliReport {
    let receipt = apply_hydration(path);
    hydration_receipt_report(path, receipt)
}

fn hydration_receipt_report(path: &str, receipt: HydrationApplyReceipt) -> CliReport {
    let mut report = scenario_report("hydrate apply", scenario_from_path(Some(path)));
    report.summary = if receipt.write_completed {
        "Hydration apply completed inside a recognized test sandbox and final hash verified."
            .to_string()
    } else if receipt.idempotent {
        "Hydration apply confirmed target is already hydrated; no write occurred.".to_string()
    } else {
        "Hydration apply refused or failed recoverably; no successful hydration was reported."
            .to_string()
    };
    report.dry_run = false;
    report.exit_code = if receipt.write_completed || receipt.idempotent {
        0
    } else {
        2
    };
    report.mutation_flags.mutated_files = receipt.mutated_files;
    report.evidence.push(format!("Target path: {path}"));
    report
        .evidence
        .push(format!("Attempted write: {}", receipt.attempted_write));
    report
        .evidence
        .push(format!("Write completed: {}", receipt.write_completed));
    report
        .evidence
        .push(format!("Idempotent: {}", receipt.idempotent));
    report
        .evidence
        .push(format!("Mutated files: {}", receipt.mutated_files));
    if let Some(hash) = receipt.final_hash {
        report
            .evidence
            .push(format!("Final content hash: blake3:{}", hash.digest));
    }
    for blocker in receipt.blockers {
        report
            .blockers
            .push(format!("Hydration blocker: {blocker:?}"));
    }
    report.recommendations.push(receipt.recovery_action);
    report
}

fn sync_plan_report() -> CliReport {
    let plan = SyncPlan::fixture_with_delete();
    let mut report = base_report(
        "sync plan",
        "Sync plan is a dry-run preview. It is inherently non-mutating.",
    );
    report.blockers.push(
        "The preview contains a destructive operation that cannot be applied in this slice."
            .to_string(),
    );
    report.evidence.push(format!("Plan id: {}", plan.plan_id));
    report.evidence.push(format!(
        "Operations: {}; destructive flagged: {}",
        plan.operations.len(),
        plan.destructive_operations_flagged
    ));
    report.recommendations.push(
        "Review the plan, then use sync apply --dry-run for a non-mutating receipt preview."
            .to_string(),
    );
    report
}

fn sync_apply_report(dry_run: bool) -> CliReport {
    if !dry_run {
        return refusal_report(
            "sync apply",
            "Sync apply requires --dry-run in this slice.",
            "No sync apply was performed and no files, Git state, CAS objects, SQLite data, or metadata were changed.",
        );
    }

    let plan = SyncPlan::fixture_with_delete();
    let receipt = plan
        .approval_preview(ApprovalFlag::approved_by("cli-dry-run"))
        .expect("approved dry-run produces a receipt model");
    receipt_report("sync apply", receipt)
}

fn receipt_report(command: &str, receipt: SyncPlanReceipt) -> CliReport {
    let mut report = base_report(
        command,
        "Sync apply dry-run receipt preview. No apply was performed.",
    );
    report.blockers.push(
        "Real apply remains blocked until approval, rollback notes, fixture tests, and invariant review exist.".to_string(),
    );
    report
        .evidence
        .push(format!("Plan id: {}", receipt.plan_id));
    report.evidence.push(format!(
        "Destructive operations previewed: {}",
        receipt.destructive_operations_count
    ));
    report.evidence.push(receipt.summary);
    report
        .recommendations
        .push("Do not treat this receipt as completed sync.".to_string());
    report
}

fn conflict_list_report(scenario: FixtureScenario) -> CliReport {
    let mut report = scenario_report("conflict list", scenario);
    if scenario != FixtureScenario::Conflict {
        report.summary =
            "Conflict list is read-only; no live conflict scan was performed.".to_string();
        report
            .warnings
            .push("No deterministic conflict fixture matched this path.".to_string());
    }
    report
}

fn conflict_resolve_report(dry_run: bool) -> CliReport {
    if !dry_run {
        return refusal_report(
            "conflict resolve",
            "Conflict resolve requires --dry-run in this slice.",
            "No conflict was resolved, hidden, overwritten, or deleted.",
        );
    }

    let mut report = base_report(
        "conflict resolve",
        "Conflict resolution dry-run preview only. Both sides remain preserved.",
    );
    report.blockers.push(
        "Resolution apply is unavailable until preview, approval, receipt, and tests exist."
            .to_string(),
    );
    report
        .evidence
        .push("Local and remote/mock versions are preserved in the model.".to_string());
    report.recommendations.push(
        "Use conflict list to inspect unresolved conflicts before any future resolution."
            .to_string(),
    );
    report
}

fn machine_list_report() -> CliReport {
    let mut report = base_report(
        "machine list",
        "Machine map preview only. No registry database was read or written.",
    );
    report.warnings.push(
        "Machine identity and path mappings are placeholder evidence in this slice.".to_string(),
    );
    report
        .evidence
        .push("Local metadata persistence is not initialized.".to_string());
    report
        .recommendations
        .push("Implement registry persistence before trusting machine topology.".to_string());
    report
}

fn env_check_report(scenario: FixtureScenario) -> CliReport {
    let mut report = scenario_report("env check", scenario);
    report.summary = match scenario {
        FixtureScenario::MissingEnv => {
            "Env check found missing key names in a deterministic fixture.".to_string()
        }
        _ => "Env check is redacted and fixture-backed only.".to_string(),
    };
    report
        .evidence
        .push("Env profile awareness records key names and fingerprints only.".to_string());
    report
}

fn agent_report(command: &str, task_words: usize) -> CliReport {
    let mut report = base_report(
        command,
        "Agent workspace planning is redacted and non-mutating.",
    );
    report
        .blockers
        .push("Agent start is blocked until readiness, env, stale-base, conflict, and hydration checks pass.".to_string());
    report.evidence.push(format!(
        "Task scope received as {task_words} word(s); raw task text is not echoed."
    ));
    report
        .recommendations
        .push("Use agent contract after fixture-backed readiness scanner data exists.".to_string());
    report
}

fn mcp_serve_report() -> CliReport {
    let mut report = base_report(
        "mcp serve",
        "MCP serve preview delegates to the devdrop-mcp JSON-over-STDIO scaffold.",
    );
    report
        .warnings
        .push("This CLI does not claim full MCP protocol support in this slice.".to_string());
    report.evidence.push(
        "Use cargo run -p devdrop-mcp -- --list-tools to inspect safe scaffold tools.".to_string(),
    );
    report
}

fn legacy_dry_run_report(command: &str, summary: &str) -> CliReport {
    let mut report = base_report(command, summary);
    report.blockers.push(
        "This legacy command is retained as a dry-run compatibility surface only.".to_string(),
    );
    report.evidence.push(
        "No files, Git state, CAS objects, registry data, metadata, or workspace state were mutated."
            .to_string(),
    );
    report
}

fn refusal_report(command: &str, summary: &str, evidence: &str) -> CliReport {
    let mut report = base_report(command, summary);
    report.blockers.push(
        "Required dry-run gate was not provided; the command refused to continue.".to_string(),
    );
    report.evidence.push(evidence.to_string());
    report
        .recommendations
        .push(format!("Re-run `{command} --dry-run` to preview safely."));
    report
}

fn scenario_from_path(path: Option<&str>) -> FixtureScenario {
    let Some(path) = path else {
        return FixtureScenario::Unknown;
    };
    let normalized = path.replace('\\', "/").to_lowercase();

    if normalized.contains("ready-project") {
        FixtureScenario::Ready
    } else if normalized.contains("stale-git-project") {
        FixtureScenario::StaleGit
    } else if normalized.contains("missing-env-project") {
        FixtureScenario::MissingEnv
    } else if normalized.contains("conflict-project") {
        FixtureScenario::Conflict
    } else if normalized.contains("ignored-path-project") {
        FixtureScenario::IgnoredPath
    } else if normalized.contains("hydration-project") {
        FixtureScenario::Hydration
    } else {
        FixtureScenario::Unknown
    }
}

fn render_human(report: &CliReport) -> String {
    let mut out = String::new();
    out.push_str("DevDrop workspace flight check\n");
    out.push_str(&format!("Command: {}\n", report.command));
    out.push_str(&format!(
        "Can safely work: {}\n",
        if report.safe_to_work {
            "yes"
        } else {
            "not yet"
        }
    ));
    out.push_str(&format!(
        "Mode: dry-run / non-mutating (mutated_files: {})\n",
        report.mutation_flags.mutated_files
    ));
    out.push_str(&format!("Summary: {}\n\n", report.summary));

    push_group(&mut out, "Blockers", &report.blockers);
    push_group(&mut out, "Warnings", &report.warnings);
    push_group(&mut out, "Evidence", &report.evidence);
    push_group(&mut out, "Recommended next action", &report.recommendations);

    out.push_str("Redaction\n");
    out.push_str(&format!("- {}\n", report.redaction_notice));
    out
}

fn push_group(out: &mut String, label: &str, items: &[String]) {
    out.push_str(label);
    out.push('\n');
    if items.is_empty() {
        out.push_str("- none\n\n");
        return;
    }

    for item in items {
        out.push_str("- ");
        out.push_str(item);
        out.push('\n');
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use devdrop_core::{
        exact_stub_marker, ContentHash, HydrationSandboxMetadata, FIXTURE_OBJECT_ALPHA_ID,
        HYDRATION_SANDBOX_FILE,
    };
    use serde_json::Value;
    use std::{fs, path::PathBuf};
    use tempfile::tempdir;

    const FORBIDDEN_REPORT_KEYS: &[&str] = &[
        "secret",
        "env_value",
        "raw_value",
        "contents",
        "file_contents",
    ];

    #[test]
    fn requested_commands_parse() {
        let commands = [
            vec!["devdrop", "init"],
            vec!["devdrop", "doctor"],
            vec!["devdrop", "doctor", "--json"],
            vec!["devdrop", "scan"],
            vec!["devdrop", "status"],
            vec![
                "devdrop",
                "hydrate",
                "--dry-run",
                "fixtures/repos/hydration-project",
            ],
            vec!["devdrop", "hydrate", "apply", "sandbox/stub.txt"],
            vec!["devdrop", "sync", "plan"],
            vec!["devdrop", "sync", "apply", "--dry-run"],
            vec!["devdrop", "conflict", "list"],
            vec!["devdrop", "conflict", "resolve", "--dry-run"],
            vec!["devdrop", "machine", "list"],
            vec!["devdrop", "env", "check"],
            vec!["devdrop", "agent", "plan", "inspect", "readiness"],
            vec!["devdrop", "agent", "contract", "inspect", "readiness"],
            vec!["devdrop", "mcp", "serve"],
        ];

        for command in commands {
            Cli::try_parse_from(command).expect("command parses");
        }
    }

    #[test]
    fn doctor_json_has_stable_schema_and_no_raw_secret_values() {
        let (output, exit_code) =
            render(Commands::Doctor { json: true }).expect("doctor json renders");
        assert_eq!(exit_code, 0);
        let value: Value = serde_json::from_str(&output).expect("valid json");
        assert_eq!(value["command"], "doctor");
        assert!(value.get("safe_to_work").is_some());
        assert!(value.get("mutation_flags").is_some());
        assert!(!output.contains("redact-this-value"));
        assert!(!output.contains("successfully synced"));
    }

    #[test]
    fn cli_report_never_uses_forbidden_raw_data_keys() {
        for report in all_sample_reports() {
            let value = serde_json::to_value(&report).expect("report serializes");
            assert_no_forbidden_keys(&value, &report.command);
        }
    }

    #[test]
    fn every_cli_report_includes_false_mutation_flags() {
        for report in all_sample_reports() {
            if report.command == "hydrate apply" && report.exit_code == 0 {
                assert!(report.mutation_flags.mutated_files, "{}", report.command);
            } else {
                assert!(!report.mutation_flags.mutated_files, "{}", report.command);
            }
            assert!(!report.mutation_flags.mutated_git, "{}", report.command);
            assert!(
                !report.mutation_flags.wrote_object_store,
                "{}",
                report.command
            );
            assert!(!report.mutation_flags.wrote_sqlite, "{}", report.command);
            assert!(!report.mutation_flags.wrote_registry, "{}", report.command);
            assert!(!report.mutation_flags.wrote_manifest, "{}", report.command);
            assert!(!report.mutation_flags.wrote_metadata, "{}", report.command);
            assert!(
                !report.mutation_flags.changed_hydration_state,
                "{}",
                report.command
            );
            assert!(
                !report.mutation_flags.resolved_conflicts,
                "{}",
                report.command
            );
            assert!(
                !report.mutation_flags.applied_tombstones,
                "{}",
                report.command
            );
        }
    }

    #[test]
    fn fixture_scenarios_are_deterministic() {
        let cases = [
            ("fixtures/repos/ready-project", FixtureScenario::Ready, true),
            (
                "fixtures/repos/stale-git-project",
                FixtureScenario::StaleGit,
                false,
            ),
            (
                "fixtures/repos/missing-env-project",
                FixtureScenario::MissingEnv,
                false,
            ),
            (
                "fixtures/repos/conflict-project",
                FixtureScenario::Conflict,
                false,
            ),
            (
                "fixtures/repos/ignored-path-project",
                FixtureScenario::IgnoredPath,
                true,
            ),
            (
                "fixtures/repos/hydration-project",
                FixtureScenario::Hydration,
                false,
            ),
            (
                "fixtures/repos/does-not-exist",
                FixtureScenario::Unknown,
                false,
            ),
        ];

        for (path, scenario, safe) in cases {
            let report = scenario_report("scan", scenario_from_path(Some(path)));
            assert_eq!(report.fixture_scenario, scenario);
            assert_eq!(report.safe_to_work, safe);
            assert!(
                report
                    .evidence
                    .iter()
                    .chain(report.blockers.iter())
                    .any(|line| line.contains("fixture") || line.contains("Fixture")),
                "{path} should describe fixture basis"
            );
        }
    }

    #[test]
    fn sync_plan_is_allowed_without_dry_run_arg_but_reports_dry_run() {
        let report = handle_command(Commands::Sync {
            command: SyncCommand::Plan,
        });
        assert_eq!(report.command, "sync plan");
        assert!(report.dry_run);
        assert!(!report.mutation_flags.mutated_files);
        assert!(report.summary.contains("dry-run"));
    }

    #[test]
    fn dangerous_commands_refuse_without_dry_run() {
        let hydrate = handle_command(Commands::Hydrate {
            dry_run: false,
            path: Some("fixtures/repos/hydration-project".to_string()),
            command: None,
        });
        let sync_apply = handle_command(Commands::Sync {
            command: SyncCommand::Apply { dry_run: false },
        });
        let conflict_resolve = handle_command(Commands::Conflict {
            command: ConflictCommand::Resolve { dry_run: false },
        });

        for report in [hydrate, sync_apply, conflict_resolve] {
            assert!(!report.safe_to_work);
            assert!(report.summary.contains("requires --dry-run"));
            assert!(report.blockers.iter().any(|line| line.contains("refused")));
            assert!(!report.mutation_flags.mutated_files);
        }
    }

    #[test]
    fn dry_run_dangerous_commands_are_non_mutating() {
        let reports = [
            handle_command(Commands::Hydrate {
                dry_run: true,
                path: Some("fixtures/repos/hydration-project".to_string()),
                command: None,
            }),
            handle_command(Commands::Sync {
                command: SyncCommand::Apply { dry_run: true },
            }),
            handle_command(Commands::Conflict {
                command: ConflictCommand::Resolve { dry_run: true },
            }),
        ];

        for report in reports {
            assert!(report.dry_run);
            assert!(!report.mutation_flags.mutated_files);
            assert!(!report.mutation_flags.changed_hydration_state);
            assert!(!report.mutation_flags.resolved_conflicts);
        }
    }

    #[test]
    fn dry_run_language_exists_for_dangerous_and_legacy_surfaces() {
        let outputs = [
            render(Commands::Hydrate {
                dry_run: true,
                path: Some("fixtures/repos/hydration-project".to_string()),
                command: None,
            })
            .unwrap(),
            render(Commands::Sync {
                command: SyncCommand::Apply { dry_run: true },
            })
            .unwrap(),
            render(Commands::Conflict {
                command: ConflictCommand::Resolve { dry_run: true },
            })
            .unwrap(),
            render(Commands::Snapshot).unwrap(),
            render(Commands::Handoff).unwrap(),
        ];

        for output in outputs {
            let output = output.0;
            let lower = output.to_lowercase();
            assert!(
                lower.contains("dry-run") || lower.contains("non-mutating"),
                "{output}"
            );
        }
    }

    #[test]
    fn cli_copy_passes_ux_redteam_assertions() {
        let reports = all_sample_reports();
        for report in reports {
            let output = render_human(&report);
            assert!(output.contains("DevDrop workspace flight check"));
            assert!(output.contains("Can safely work:"));
            assert!(output.contains("Blockers"));
            assert!(output.contains("Warnings"));
            assert!(output.contains("Evidence"));
            assert!(output.contains("Recommended next action"));
            assert!(!output.contains("AI says"));
            assert!(!output.contains("successfully synced"));
            assert!(!output.contains("all good"));
            if report.fixture_scenario == FixtureScenario::Conflict
                || report.command.contains("conflict")
            {
                assert!(output.to_lowercase().contains("conflict"));
            }
        }
    }

    #[test]
    fn init_states_no_manifest_registry_database_or_metadata_written() {
        let (output, exit_code) = render(Commands::Init).unwrap();
        assert_eq!(exit_code, 0);
        assert!(output
            .contains("No manifest, registry, database, metadata, or config file was written"));
        assert!(output.contains("mutated_files: false"));
    }

    #[test]
    fn mcp_serve_does_not_claim_full_protocol_support() {
        let report = handle_command(Commands::Mcp {
            command: McpCommand::Serve,
        });
        let output = render_human(&report);
        assert!(output.contains("JSON-over-STDIO scaffold"));
        assert!(output.contains("does not claim full MCP protocol support"));
    }

    #[test]
    fn hydrate_apply_succeeds_only_in_test_sandbox_and_then_is_idempotent() {
        let target = write_cli_hydration_sandbox();
        let report = handle_command(Commands::Hydrate {
            dry_run: false,
            path: None,
            command: Some(HydrateCommand::Apply {
                path: target.to_string_lossy().to_string(),
            }),
        });
        assert_eq!(report.exit_code, 0);
        assert!(report.mutation_flags.mutated_files);
        assert!(report.summary.contains("final hash verified"));

        let second = handle_command(Commands::Hydrate {
            dry_run: false,
            path: None,
            command: Some(HydrateCommand::Apply {
                path: target.to_string_lossy().to_string(),
            }),
        });
        assert_eq!(second.exit_code, 0);
        assert!(!second.mutation_flags.mutated_files);
        assert!(second.summary.contains("already hydrated"));
    }

    #[test]
    fn hydrate_apply_refuses_canonical_fixture_path() {
        let canonical = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/repos/hydration-project/stub-marker.example.txt");
        let report = handle_command(Commands::Hydrate {
            dry_run: false,
            path: None,
            command: Some(HydrateCommand::Apply {
                path: canonical.to_string_lossy().to_string(),
            }),
        });

        assert_ne!(report.exit_code, 0);
        assert!(!report.mutation_flags.mutated_files);
        assert!(report
            .blockers
            .iter()
            .any(|line| line.contains("CanonicalFixtureReadOnly")));
    }

    fn all_sample_reports() -> Vec<CliReport> {
        vec![
            handle_command(Commands::Init),
            handle_command(Commands::Doctor { json: false }),
            handle_command(Commands::Scan {
                path: Some("fixtures/repos/ready-project".to_string()),
            }),
            handle_command(Commands::Scan {
                path: Some("fixtures/repos/stale-git-project".to_string()),
            }),
            handle_command(Commands::Scan {
                path: Some("fixtures/repos/missing-env-project".to_string()),
            }),
            handle_command(Commands::Scan {
                path: Some("fixtures/repos/conflict-project".to_string()),
            }),
            handle_command(Commands::Scan {
                path: Some("fixtures/repos/ignored-path-project".to_string()),
            }),
            handle_command(Commands::Scan {
                path: Some("fixtures/repos/hydration-project".to_string()),
            }),
            handle_command(Commands::Scan {
                path: Some("fixtures/repos/unknown-project".to_string()),
            }),
            handle_command(Commands::Status { path: None }),
            handle_command(Commands::Hydrate {
                dry_run: true,
                path: Some("fixtures/repos/hydration-project".to_string()),
                command: None,
            }),
            handle_command(Commands::Sync {
                command: SyncCommand::Plan,
            }),
            handle_command(Commands::Sync {
                command: SyncCommand::Apply { dry_run: true },
            }),
            handle_command(Commands::Conflict {
                command: ConflictCommand::List {
                    path: Some("fixtures/repos/conflict-project".to_string()),
                },
            }),
            handle_command(Commands::Conflict {
                command: ConflictCommand::Resolve { dry_run: true },
            }),
            handle_command(Commands::Machine {
                command: MachineCommand::List,
            }),
            handle_command(Commands::Env {
                command: EnvCommand::Check {
                    path: Some("fixtures/repos/missing-env-project".to_string()),
                },
            }),
            handle_command(Commands::Agent {
                command: AgentCommand::Plan {
                    task: vec!["inspect".to_string(), "readiness".to_string()],
                },
            }),
            handle_command(Commands::Agent {
                command: AgentCommand::Contract {
                    task: vec!["inspect".to_string(), "readiness".to_string()],
                },
            }),
            handle_command(Commands::Mcp {
                command: McpCommand::Serve,
            }),
            handle_command(Commands::Snapshot),
            handle_command(Commands::Handoff),
        ]
    }

    fn write_cli_hydration_sandbox() -> PathBuf {
        let dir = tempdir().expect("tempdir");
        let root = dir.keep();
        let metadata = HydrationSandboxMetadata::test_fixture();
        fs::write(
            root.join(HYDRATION_SANDBOX_FILE),
            serde_json::to_string_pretty(&metadata).expect("metadata serializes"),
        )
        .expect("write metadata");
        let entry = metadata
            .registry
            .get(FIXTURE_OBJECT_ALPHA_ID)
            .expect("entry");
        let hash = ContentHash {
            algorithm: devdrop_core::HashAlgorithm::Blake3,
            digest: entry.hash.clone(),
        };
        let target = root.join("src").join("stub.txt");
        fs::create_dir_all(target.parent().expect("parent")).expect("parent dir");
        fs::write(
            &target,
            exact_stub_marker(&entry.object_id, &hash, entry.size),
        )
        .expect("write stub");
        target
    }

    fn assert_no_forbidden_keys(value: &Value, command: &str) {
        match value {
            Value::Object(map) => {
                for (key, nested) in map {
                    assert!(
                        !FORBIDDEN_REPORT_KEYS.contains(&key.as_str()),
                        "{command} report contains forbidden raw-data key {key}"
                    );
                    assert_no_forbidden_keys(nested, command);
                }
            }
            Value::Array(items) => {
                for item in items {
                    assert_no_forbidden_keys(item, command);
                }
            }
            _ => {}
        }
    }
}
