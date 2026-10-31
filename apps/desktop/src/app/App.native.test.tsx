import { expect, test, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
const command = vi.hoisted(() => vi.fn());
vi.mock("../data/client", () => ({
  command,
  native: true,
  resetDemo: vi.fn(),
}));
import { App } from "./App";

test("native recovery activity shows only allowlisted backup metadata and manual-preservation instructions", async () => {
  const before = "a".repeat(64);
  command.mockResolvedValue({
    pairs: [
      {
        id: "pair-test",
        name: "Disposable pair",
        source: "/disposable/source",
        target: "/disposable/target",
      },
    ],
    plans: [],
    events: [
      {
        kind: "quarantining",
        plan_id: "plan-test",
        evidence: {
          path: "src/notes.ts",
          side: "target",
          recovery_directory: ".devdrop-recovery-plan-test-0",
          before,
          raw_contents: "CANARY_DO_NOT_RENDER_RAW_BYTES",
        },
      },
    ],
  });
  render(<App />);
  const user = userEvent.setup();
  await screen.findByRole("heading", { name: "Disposable pair" });
  await user.click(screen.getByRole("button", { name: "Activity & recovery" }));
  expect(screen.getByText("src/notes.ts")).toBeTruthy();
  expect(screen.getByText("replica (target)")).toBeTruthy();
  expect(
    screen.getByText(".devdrop-recovery-plan-test-0/previous"),
  ).toBeTruthy();
  expect(screen.getByText(before)).toBeTruthy();
  expect(
    screen.getByText(/If rollback refuses because newer local work exists/),
  ).toBeTruthy();
  expect(screen.queryByText("CANARY_DO_NOT_RENDER_RAW_BYTES")).toBeNull();
  expect(screen.queryByText(/virtual folders only/)).toBeNull();
});

test("native apply sends disposable-copy confirmation only after the explicit beta acknowledgement", async () => {
  command.mockClear();
  const state = {
    pairs: [
      {
        id: "pair-beta",
        name: "Beta copies",
        source: "/disposable/source",
        target: "/disposable/target",
      },
    ],
    plans: [],
    events: [],
  };
  const plan = {
    id: "plan-beta",
    pair_id: "pair-beta",
    operations: [
      {
        path: "README.md",
        kind: "copy",
        side: "target",
        before: null,
        after: "a".repeat(64),
      },
    ],
    blockers: [],
    state: "planned",
  };
  command.mockImplementation(async (request) => {
    if (request.action === "preview") return plan;
    if (request.action === "apply")
      return {
        plan_id: plan.id,
        state: "verified",
        changed: ["README.md"],
        message: "Disposable copy updated.",
      };
    return state;
  });
  render(<App />);
  const user = userEvent.setup();
  await screen.findByRole("heading", { name: "Beta copies" });
  for (const route of ["Add project", "Activity & recovery", "Overview"]) {
    await user.click(screen.getByRole("button", { name: route }));
    expect(
      screen.getByRole("note", { name: "Beta safety limit" }).textContent,
    ).toContain("file permissions and executable bits are not preserved");
  }
  await user.click(
    screen.getByRole("button", { name: "Scan & preview changes" }),
  );
  const apply = await screen.findByRole("button", {
    name: "Apply approved plan",
  });
  expect((apply as HTMLButtonElement).disabled).toBe(true);
  await user.click(apply);
  expect(
    command.mock.calls.some(([request]) => request.action === "apply"),
  ).toBe(false);
  const acknowledgement = screen.getByRole("checkbox");
  expect(acknowledgement.parentElement?.textContent).toContain(
    "disposable copies, never primary working trees",
  );
  expect(acknowledgement.parentElement?.textContent).toContain(
    "do not preserve file permissions or executable bits",
  );
  await user.click(acknowledgement);
  await user.click(apply);
  expect(command).toHaveBeenCalledWith({
    action: "apply",
    plan_id: "plan-beta",
    approval: "plan-beta",
    disposable_copies: true,
  });
});
