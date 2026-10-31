import { beforeEach, expect, test, vi } from "vitest";
import {
  command,
  resetDemo,
  type Plan,
  type Receipt,
  type Registry,
} from "./client";
beforeEach(resetDemo);
const preview = () =>
  command<Plan>({ action: "preview", pair_id: "demo-pair" });
const apply = (plan: Plan) =>
  command<Receipt>({
    action: "apply",
    plan_id: plan.id,
    approval: plan.id,
    disposable_copies: true,
  });
test("browser demo requires exact approval and repeated apply is idempotent", async () => {
  const plan = await preview();
  expect(plan.operations).toHaveLength(2);
  await expect(
    command({
      action: "apply",
      plan_id: plan.id,
      approval: "other-plan",
      disposable_copies: true,
    }),
  ).rejects.toThrow("Explicit approval");
  expect((await apply(plan)).changed).toHaveLength(2);
  expect((await apply(plan)).changed).toHaveLength(0);
  expect((await preview()).operations).toHaveLength(0);
});
test("stale scan refuses apply and preserves target", async () => {
  const plan = await preview();
  await command({ action: "demo_edit" });
  await expect(apply(plan)).rejects.toThrow("Stale plan");
  const fresh = await preview();
  expect(fresh.target_scan).toEqual({});
});
test("divergent versions stay visible and block apply", async () => {
  await apply(await preview());
  await command({ action: "demo_conflict" });
  const plan = await preview();
  expect(plan.operations.find((o) => o.kind === "conflict")).toBeTruthy();
  await expect(apply(plan)).rejects.toThrow("Unresolved conflicts");
  expect((await preview()).operations).toEqual(plan.operations);
});
test("recovery is previewed and restores earlier virtual replica", async () => {
  const plan = await preview();
  await apply(plan);
  const undo = await command<Plan>({
    action: "rollback_preview",
    plan_id: plan.id,
  });
  expect(undo.operations.every((o) => o.kind === "delete")).toBe(true);
  expect((await apply(undo)).state).toBe("verified");
  expect((await preview()).target_scan).toEqual({});
});
test("browser registration cannot accept arbitrary device paths", async () => {
  await expect(
    command({ action: "register", source: "/secret", target: "/target" }),
  ).rejects.toThrow("desktop app");
});
test("demo metadata survives a module restart", async () => {
  const plan = await preview();
  await apply(plan);
  vi.resetModules();
  const reloaded = await import("./client");
  const state = await reloaded.command<Registry>({ action: "list" });
  expect(
    state.plans.some((p) => p.id === plan.id && p.state === "verified"),
  ).toBe(true);
});

test("beta apply and rollback refuse missing or false disposable-copy confirmation without changes", async () => {
  const plan = await preview();
  for (const action of ["apply", "rollback"]) {
    for (const disposable_copies of [undefined, false, "true"]) {
      await expect(
        command({
          action,
          plan_id: plan.id,
          approval: plan.id,
          disposable_copies,
        }),
      ).rejects.toThrow("Beta apply requires confirmation");
    }
  }
  expect((await preview()).target_scan).toEqual({});
});

test("permission-only access increase needs separate approval and recovery restores its previous mode", async () => {
  await apply(await preview());
  await command({ action: "demo_permissions" });
  const plan = await preview();
  expect(plan.operations).toHaveLength(1);
  expect(plan.operations[0]).toMatchObject({
    kind: "permissions",
    permissions_before: { platform: "unix", mode: 0o644 },
    permissions_after: { platform: "unix", mode: 0o755 },
    permission_widening: true,
  });
  for (const allow_permission_widening of [undefined, false, "true"]) {
    await expect(
      command({
        action: "apply",
        plan_id: plan.id,
        approval: plan.id,
        disposable_copies: true,
        allow_permission_widening,
      }),
    ).rejects.toThrow("separate explicit approval");
  }
  expect((await preview()).target_permissions?.["src/notes.ts"]).toEqual({
    platform: "unix",
    mode: 0o644,
  });
  await command({
    action: "apply",
    plan_id: plan.id,
    approval: plan.id,
    disposable_copies: true,
    allow_permission_widening: true,
  });
  const recovery = await command<Plan>({
    action: "rollback_preview",
    plan_id: plan.id,
  });
  expect(recovery.operations[0]).toMatchObject({
    kind: "permissions",
    permissions_before: { platform: "unix", mode: 0o755 },
    permissions_after: { platform: "unix", mode: 0o644 },
    permission_widening: false,
  });
  await apply(recovery);
  expect((await preview()).target_permissions?.["src/notes.ts"]).toEqual({
    platform: "unix",
    mode: 0o644,
  });
});

test("permission changes invalidate a previously built content plan", async () => {
  const plan = await preview();
  await command({ action: "demo_permissions" });
  await expect(apply(plan)).rejects.toThrow("Stale plan");
});
