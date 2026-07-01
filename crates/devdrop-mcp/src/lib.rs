use devdrop_core::{doctor_report_text, SafetyMode, SyncPreview};
use serde::{Deserialize, Serialize};

pub const STDIO_SCAFFOLD_NOTE: &str =
    "JSON-over-STDIO scaffold for local Slice 0/1 testing; not a complete MCP protocol implementation.";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpToolParameter {
    pub name: String,
    pub type_name: String,
    pub required: bool,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpToolSchema {
    pub name: String,
    pub description: String,
    pub mutates_files: bool,
    pub exposes_secret_values: bool,
    pub safety_mode: SafetyMode,
    pub transport: String,
    pub protocol_note: String,
    pub parameters: Vec<McpToolParameter>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tool", rename_all = "snake_case")]
pub enum McpToolRequest {
    Doctor { project_path: String },
    Scan { project_path: String },
    SyncPlan { project_path: String },
    ListConflicts { project_path: String },
    AgentContract { project_path: String, task: String },
    DesignRedteam { screen_name: String },
    UxRedteam { flow_name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpToolResponse {
    pub tool: String,
    pub safety_mode: SafetyMode,
    pub mutates_files: bool,
    pub exposes_secret_values: bool,
    pub transport: String,
    pub protocol_note: String,
    pub summary: String,
    pub project_path: Option<String>,
    pub subject: Option<String>,
    pub warnings: Vec<String>,
    pub evidence: Vec<String>,
    pub next_steps: Vec<String>,
    pub redaction_notice: String,
}

pub fn slice_zero_one_tools() -> Vec<McpToolSchema> {
    mcp_tool_schemas()
}

pub fn mcp_tool_schemas() -> Vec<McpToolSchema> {
    vec![
        schema(
            "doctor",
            "Return a redacted Slice 0/1 readiness summary for a project path.",
            vec![param("project_path", "string", "Project path used as context only.")],
        ),
        schema(
            "scan",
            "Preview a redacted readiness scan; does not read env values or mutate files.",
            vec![param("project_path", "string", "Project path used as context only.")],
        ),
        schema(
            "sync_plan",
            "Return a dry-run sync plan scaffold; no apply, CAS write, or file mutation occurs.",
            vec![param("project_path", "string", "Project path used as context only.")],
        ),
        schema(
            "list_conflicts",
            "Return conflict-summary scaffolding without resolving or hiding conflicts.",
            vec![param("project_path", "string", "Project path used as context only.")],
        ),
        schema(
            "agent_contract",
            "Return a redacted agent workspace contract for a task without file text or env values.",
            vec![
                param("project_path", "string", "Project path used as context only."),
                param("task", "string", "Task description used to scope a future handoff."),
            ],
        ),
        schema(
            "design_redteam",
            "Return aesthetic red-team prompts for a screen without generating UI changes.",
            vec![param("screen_name", "string", "Screen or route name to critique.")],
        ),
        schema(
            "ux_redteam",
            "Return UX red-team prompts for a flow without changing product behavior.",
            vec![param("flow_name", "string", "Flow name to critique.")],
        ),
    ]
}

pub fn dispatch(request: McpToolRequest) -> McpToolResponse {
    match request {
        McpToolRequest::Doctor { project_path } => response(
            "doctor",
            Some(project_path),
            None,
            "DevDrop Slice 0/1 foundation doctor response. Real sync is not complete.",
            vec![
                "No readiness scan has been performed by this scaffold.".to_string(),
                "Destructive actions are unavailable or dry-run only.".to_string(),
            ],
            vec![doctor_report_text()],
            vec!["Run Slice 2 readiness scanner before relying on workspace status.".to_string()],
        ),
        McpToolRequest::Scan { project_path } => response(
            "scan",
            Some(project_path),
            None,
            "Readiness scan scaffold only; no project files, env values, or Git state are inspected.",
            vec![
                "This response is fixture-shaped and not a live scan.".to_string(),
                "Watcher events remain hints; reconciliation scans are future work.".to_string(),
            ],
            vec![
                "Would check registry membership, Git freshness, env key presence, ignored paths, hydration state, queue, tombstones, and conflicts.".to_string(),
            ],
            vec!["Implement fixture-backed scanner before exposing live readiness.".to_string()],
        ),
        McpToolRequest::SyncPlan { project_path } => {
            let preview = SyncPreview::foundation_stub("project:mcp-preview");
            response(
                "sync_plan",
                Some(project_path),
                None,
                "Dry-run sync plan scaffold only; no apply, delete, overwrite, Git mutation, or CAS write occurs.",
                vec![
                    "Plan is not based on live filesystem inspection.".to_string(),
                    "Any future apply requires preview, approval, rollback notes, and fixture tests.".to_string(),
                ],
                vec![
                    format!("safety_mode: {:?}", preview.mode),
                    format!(
                        "requires_reconciliation_scan: {}",
                        preview.requires_reconciliation_scan
                    ),
                    format!(
                        "watcher_events_are_hints: {}",
                        preview.watcher_events_are_hints
                    ),
                ],
                vec!["Keep sync apply unavailable until the invariant review passes.".to_string()],
            )
        }
        McpToolRequest::ListConflicts { project_path } => response(
            "list_conflicts",
            Some(project_path),
            None,
            "Conflict list scaffold only; no conflicts are resolved, hidden, or modified.",
            vec!["No live conflict detection is implemented in Slice 0/1.".to_string()],
            vec![
                "Future conflict objects must preserve both local and incoming sides.".to_string(),
                "Future resolution must be previewed before apply.".to_string(),
            ],
            vec!["Add fixture-backed conflict summaries before agent use.".to_string()],
        ),
        McpToolRequest::AgentContract { project_path, task } => response(
            "agent_contract",
            Some(project_path),
            Some(task),
            "Agent workspace contract scaffold only; safe boundaries are described without exposing file text or env values.",
            vec![
                "Contract is not derived from a live registry yet.".to_string(),
                "Stale-base and env-availability checks are placeholders.".to_string(),
            ],
            vec![
                "Allowed future scope: task-scoped project paths, readiness findings, queue previews, conflict summaries.".to_string(),
                "Forbidden future scope: ignored/generated paths, env values, raw logs, destructive commands without approval.".to_string(),
            ],
            vec!["Use Slice 2 scanner data before starting real agent workspaces.".to_string()],
        ),
        McpToolRequest::DesignRedteam { screen_name } => response(
            "design_redteam",
            None,
            Some(screen_name),
            "Aesthetic red-team scaffold for DevDrop UI surfaces.",
            vec!["This tool returns critique prompts only and does not edit UI files.".to_string()],
            vec![
                "Check for default shadcn sameness, fake glass, meaningless metric cards, vague pills, generic SaaS layout, and purple/blue AI gradients.".to_string(),
                "Prefer calm, spatial, tactile, evidence-first object and machine state.".to_string(),
            ],
            vec!["Pair with UX red-team before accepting visual UI changes.".to_string()],
        ),
        McpToolRequest::UxRedteam { flow_name } => response(
            "ux_redteam",
            None,
            Some(flow_name),
            "UX red-team scaffold for trust, evidence, blocked actions, previews, and receipts.",
            vec!["This tool returns critique prompts only and does not edit workflow files.".to_string()],
            vec![
                "Ask whether the user can tell if it is safe to work here.".to_string(),
                "Require causes, evidence, preview states, approval walls, blocked destructive actions, and closeout receipts.".to_string(),
            ],
            vec!["Run sync invariant review too when a flow touches filesystem, env, Git, hydration, tombstones, or conflicts.".to_string()],
        ),
    }
}

pub fn sample_safe_responses() -> Vec<McpToolResponse> {
    vec![
        dispatch(McpToolRequest::Doctor {
            project_path: sample_project_path(),
        }),
        dispatch(McpToolRequest::Scan {
            project_path: sample_project_path(),
        }),
        dispatch(McpToolRequest::SyncPlan {
            project_path: sample_project_path(),
        }),
        dispatch(McpToolRequest::ListConflicts {
            project_path: sample_project_path(),
        }),
        dispatch(McpToolRequest::AgentContract {
            project_path: sample_project_path(),
            task: "Prepare a safe readiness review.".to_string(),
        }),
        dispatch(McpToolRequest::DesignRedteam {
            screen_name: "Dashboard".to_string(),
        }),
        dispatch(McpToolRequest::UxRedteam {
            flow_name: "First launch to first safe snapshot".to_string(),
        }),
    ]
}

fn schema(
    name: impl Into<String>,
    description: impl Into<String>,
    parameters: Vec<McpToolParameter>,
) -> McpToolSchema {
    McpToolSchema {
        name: name.into(),
        description: description.into(),
        mutates_files: false,
        exposes_secret_values: false,
        safety_mode: SafetyMode::DryRunOnly,
        transport: "stdio-json-scaffold".to_string(),
        protocol_note: STDIO_SCAFFOLD_NOTE.to_string(),
        parameters,
    }
}

fn param(
    name: impl Into<String>,
    type_name: impl Into<String>,
    description: impl Into<String>,
) -> McpToolParameter {
    McpToolParameter {
        name: name.into(),
        type_name: type_name.into(),
        required: true,
        description: description.into(),
    }
}

fn response(
    tool: impl Into<String>,
    project_path: Option<String>,
    subject: Option<String>,
    summary: impl Into<String>,
    warnings: Vec<String>,
    evidence: Vec<String>,
    next_steps: Vec<String>,
) -> McpToolResponse {
    McpToolResponse {
        tool: tool.into(),
        safety_mode: SafetyMode::DryRunOnly,
        mutates_files: false,
        exposes_secret_values: false,
        transport: "stdio-json-scaffold".to_string(),
        protocol_note: STDIO_SCAFFOLD_NOTE.to_string(),
        summary: summary.into(),
        project_path,
        subject,
        warnings,
        evidence,
        next_steps,
        redaction_notice:
            "No env values, raw file text, generated dependency trees, or secret-like values are exposed."
                .to_string(),
    }
}

fn sample_project_path() -> String {
    r"C:\Users\Home\Documents\GitHub\dropdev".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const REQUIRED_TOOLS: &[&str] = &[
        "doctor",
        "scan",
        "sync_plan",
        "list_conflicts",
        "agent_contract",
        "design_redteam",
        "ux_redteam",
    ];

    const FORBIDDEN_RESPONSE_KEYS: &[&str] = &[
        "secret",
        "env_value",
        "raw_value",
        "contents",
        "file_contents",
    ];

    #[test]
    fn mcp_tools_include_required_slice_tools() {
        let tools = mcp_tool_schemas();
        for required in REQUIRED_TOOLS {
            assert!(
                tools.iter().any(|tool| tool.name == *required),
                "missing required MCP tool {required}"
            );
        }
    }

    #[test]
    fn mcp_tools_are_read_only_redacted_and_dry_run() {
        for tool in mcp_tool_schemas() {
            assert!(!tool.mutates_files, "{} must not mutate files", tool.name);
            assert!(
                !tool.exposes_secret_values,
                "{} must not expose secret values",
                tool.name
            );
            assert_eq!(
                tool.safety_mode,
                SafetyMode::DryRunOnly,
                "{} must stay DryRunOnly",
                tool.name
            );
        }
    }

    #[test]
    fn stub_responses_are_read_only_redacted_and_dry_run() {
        for response in sample_safe_responses() {
            assert!(
                !response.mutates_files,
                "{} response must not mutate files",
                response.tool
            );
            assert!(
                !response.exposes_secret_values,
                "{} response must not expose secret values",
                response.tool
            );
            assert_eq!(
                response.safety_mode,
                SafetyMode::DryRunOnly,
                "{} response must stay DryRunOnly",
                response.tool
            );
        }
    }

    #[test]
    fn serialized_responses_do_not_use_forbidden_raw_data_keys() {
        for response in sample_safe_responses() {
            let value = serde_json::to_value(&response).expect("response serializes");
            assert_no_forbidden_keys(&value, &response.tool);
        }
    }

    #[test]
    fn json_over_stdio_request_shape_dispatches_doctor() {
        let request: McpToolRequest = serde_json::from_str(
            r#"{"tool":"doctor","project_path":"C:\\Users\\Home\\Documents\\GitHub\\dropdev"}"#,
        )
        .expect("request parses");
        let response = dispatch(request);
        assert_eq!(response.tool, "doctor");
        assert_eq!(response.safety_mode, SafetyMode::DryRunOnly);
        assert!(response.summary.contains("foundation"));
        assert!(!response.mutates_files);
    }

    fn assert_no_forbidden_keys(value: &Value, tool: &str) {
        match value {
            Value::Object(map) => {
                for (key, nested) in map {
                    assert!(
                        !FORBIDDEN_RESPONSE_KEYS.contains(&key.as_str()),
                        "{tool} response contains forbidden raw-data key {key}"
                    );
                    assert_no_forbidden_keys(nested, tool);
                }
            }
            Value::Array(items) => {
                for item in items {
                    assert_no_forbidden_keys(item, tool);
                }
            }
            _ => {}
        }
    }
}
