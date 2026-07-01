export type McpSafetyMode = "DryRunOnly";
export type McpTransport = "stdio-json-scaffold";

export type McpToolName =
  | "doctor"
  | "scan"
  | "sync_plan"
  | "list_conflicts"
  | "agent_contract"
  | "design_redteam"
  | "ux_redteam";

export type McpToolParameter = {
  name: string;
  typeName: "string";
  required: true;
  description: string;
};

export type McpToolSchema = {
  name: McpToolName;
  description: string;
  mutatesFiles: false;
  exposesSecretValues: false;
  safetyMode: McpSafetyMode;
  transport: McpTransport;
  protocolNote: string;
  parameters: readonly McpToolParameter[];
};

const protocolNote =
  "JSON-over-STDIO scaffold for local Slice 0/1 testing; not a complete MCP protocol implementation.";

const parameter = (
  name: string,
  description: string
): McpToolParameter => ({
  name,
  typeName: "string",
  required: true,
  description
});

const schema = (
  name: McpToolName,
  description: string,
  parameters: readonly McpToolParameter[]
): McpToolSchema => ({
  name,
  description,
  mutatesFiles: false,
  exposesSecretValues: false,
  safetyMode: "DryRunOnly",
  transport: "stdio-json-scaffold",
  protocolNote,
  parameters
});

export const mcpToolSchemas = [
  schema("doctor", "Return a redacted Slice 0/1 readiness summary.", [
    parameter("project_path", "Project path used as context only.")
  ]),
  schema("scan", "Preview a redacted readiness scan without file mutation.", [
    parameter("project_path", "Project path used as context only.")
  ]),
  schema("sync_plan", "Return a dry-run sync plan scaffold without apply.", [
    parameter("project_path", "Project path used as context only.")
  ]),
  schema("list_conflicts", "Return conflict-summary scaffolding without resolution.", [
    parameter("project_path", "Project path used as context only.")
  ]),
  schema("agent_contract", "Return a redacted agent workspace contract.", [
    parameter("project_path", "Project path used as context only."),
    parameter("task", "Task description used to scope a future handoff.")
  ]),
  schema("design_redteam", "Return aesthetic red-team prompts for a screen.", [
    parameter("screen_name", "Screen or route name to critique.")
  ]),
  schema("ux_redteam", "Return UX red-team prompts for a flow.", [
    parameter("flow_name", "Flow name to critique.")
  ])
] as const satisfies readonly McpToolSchema[];

export const requiredMcpToolNames = [
  "doctor",
  "scan",
  "sync_plan",
  "list_conflicts",
  "agent_contract",
  "design_redteam",
  "ux_redteam"
] as const satisfies readonly McpToolName[];
