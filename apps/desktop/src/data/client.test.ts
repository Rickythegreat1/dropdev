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
  command<Receipt>({ action: "apply", plan_id: plan.id, approval: plan.id });
test("browser demo requires exact approval and repeated apply is idempotent", async () => {
  const plan = await preview();
  expect(plan.operations).toHaveLength(2);
  await expect(
    command({ action: "apply", plan_id: plan.id, approval: "other-plan" }),
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
