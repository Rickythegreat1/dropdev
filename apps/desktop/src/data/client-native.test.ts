import { afterEach, expect, test, vi } from "vitest";
const invoke = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke }));
afterEach(() => {
  delete (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__;
  vi.resetModules();
});
test("native adapter sends exact approved plan to Tauri IPC without a network endpoint", async () => {
  (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
  vi.resetModules();
  const nativeClient = await import("./client");
  expect(nativeClient.native).toBe(true);
  invoke.mockResolvedValueOnce({
    plan_id: "plan-exact",
    state: "verified",
    changed: [],
  });
  await nativeClient.command({
    action: "apply",
    plan_id: "plan-exact",
    approval: "plan-exact",
  });
  expect(invoke).toHaveBeenCalledWith("local_command", {
    request: { action: "apply", plan_id: "plan-exact", approval: "plan-exact" },
  });
});
test("native errors propagate to the workflow refusal state", async () => {
  (window as unknown as Record<string, unknown>).__TAURI_INTERNALS__ = {};
  vi.resetModules();
  const nativeClient = await import("./client");
  invoke.mockRejectedValueOnce("Stale preview: scan again.");
  await expect(
    nativeClient.command({
      action: "apply",
      plan_id: "plan-old",
      approval: "plan-old",
    }),
  ).rejects.toBe("Stale preview: scan again.");
});
