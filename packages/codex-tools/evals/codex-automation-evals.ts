import { destructiveCommandGuard } from "../hooks/destructive-command-guard";
import { designSlopGuard } from "../hooks/design-slop-guard";
import { secretOutputGuard } from "../hooks/secret-output-guard";
import { mcpToolSchemas, requiredMcpToolNames } from "../mcp/schemas";

type ExpectFalse<T extends false> = T;
type ExpectDryRun<T extends "dry-run"> = T;
type ExpectMcpDryRun<T extends "DryRunOnly"> = T;

type SchemaMutationCheck = ExpectFalse<
  (typeof mcpToolSchemas)[number]["mutatesFiles"]
>;
type SchemaSecretCheck = ExpectFalse<
  (typeof mcpToolSchemas)[number]["exposesSecretValues"]
>;
type SchemaSafetyCheck = ExpectMcpDryRun<
  (typeof mcpToolSchemas)[number]["safetyMode"]
>;

const hookDefinitions = [
  secretOutputGuard,
  destructiveCommandGuard,
  designSlopGuard
] as const;

type HookEnabledCheck = ExpectFalse<(typeof hookDefinitions)[number]["enabled"]>;
type HookTrustedCheck = ExpectFalse<(typeof hookDefinitions)[number]["trusted"]>;
type HookAutoEnabledCheck = ExpectFalse<
  (typeof hookDefinitions)[number]["autoEnabled"]
>;
type HookModeCheck = ExpectDryRun<(typeof hookDefinitions)[number]["mode"]>;

export function assertCodexAutomationContracts(): void {
  const missingTools = requiredMcpToolNames.filter(
    (name) => !mcpToolSchemas.some((tool) => tool.name === name)
  );

  const unsafeTools = mcpToolSchemas.filter(
    (tool) =>
      tool.mutatesFiles ||
      tool.exposesSecretValues ||
      tool.safetyMode !== "DryRunOnly"
  );

  const activeHooks = hookDefinitions.filter(
    (hook) => hook.enabled || hook.trusted || hook.autoEnabled || hook.mode !== "dry-run"
  );

  if (missingTools.length > 0) {
    throw new Error(`Missing MCP tools: ${missingTools.join(", ")}`);
  }

  if (unsafeTools.length > 0) {
    throw new Error(`Unsafe MCP schemas: ${unsafeTools.map((tool) => tool.name).join(", ")}`);
  }

  if (activeHooks.length > 0) {
    throw new Error(`Hooks must remain disabled and dry-run: ${activeHooks.map((hook) => hook.name).join(", ")}`);
  }
}

export type CodexAutomationCompileTimeChecks = {
  schemaMutation: SchemaMutationCheck;
  schemaSecrets: SchemaSecretCheck;
  schemaSafety: SchemaSafetyCheck;
  hookEnabled: HookEnabledCheck;
  hookTrusted: HookTrustedCheck;
  hookAutoEnabled: HookAutoEnabledCheck;
  hookMode: HookModeCheck;
};
