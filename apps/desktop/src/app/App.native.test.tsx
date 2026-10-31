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
    ).toContain("Supported Unix rwx bits and Windows readonly are preserved");
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
    "only supported Unix rwx bits or Windows readonly are preserved",
  );
  await user.click(acknowledgement);
  await user.click(apply);
  expect(command).toHaveBeenCalledWith({
    action: "apply",
    plan_id: "plan-beta",
    approval: "plan-beta",
    disposable_copies: true,
    allow_permission_widening: false,
  });
});

test("Unix and Windows access increases are visible and need a fresh separate acknowledgement for each preview", async () => {
  command.mockClear();
  const state = {
    pairs: [
      {
        id: "pair-modes",
        name: "Permission copies",
        source: "/disposable/source",
        target: "/disposable/target",
      },
    ],
    plans: [],
    events: [],
  };
  let sequence = 0;
  command.mockImplementation(async (request) => {
    if (request.action === "preview")
      return {
        id: `plan-modes-${++sequence}`,
        pair_id: "pair-modes",
        state: "planned",
        metadata_version: 1,
        blockers: [],
        operations: [
          {
            path: "run.sh",
            kind: "permissions",
            side: "target",
            before: "same-object",
            after: "same-object",
            permissions_before: { platform: "unix", mode: 0o644 },
            permissions_after: { platform: "unix", mode: 0o755 },
            permission_widening: true,
          },
          {
            path: "notes.txt",
            kind: "permissions",
            side: "target",
            before: "same-object",
            after: "same-object",
            permissions_before: { platform: "windows", readonly: true },
            permissions_after: { platform: "windows", readonly: false },
            permission_widening: true,
          },
        ],
      };
    if (request.action === "apply")
      return {
        plan_id: request.plan_id,
        state: "verified",
        changed: ["run.sh", "notes.txt"],
        message: "Supported permission flags verified.",
      };
    return state;
  });
  render(<App />);
  const user = userEvent.setup();
  await screen.findByRole("heading", { name: "Permission copies" });
  await user.click(
    screen.getByRole("button", { name: "Scan & preview changes" }),
  );
  expect(screen.getByText("Unix 0644 → Unix 0755")).toBeTruthy();
  expect(screen.getByText("Windows read-only → Windows writable")).toBeTruthy();
  expect(
    screen.getAllByText("Access increase · extra approval required"),
  ).toHaveLength(2);
  const applyButton = screen.getByRole("button", {
    name: "Apply approved plan",
  });
  await user.click(
    screen.getByRole("checkbox", { name: /I reviewed all paths/ }),
  );
  expect((applyButton as HTMLButtonElement).disabled).toBe(true);
  const widening = screen.getByRole("checkbox", {
    name: "I approve the listed access increases",
  });
  expect((widening as HTMLInputElement).checked).toBe(false);
  await user.click(widening);
  expect((applyButton as HTMLButtonElement).disabled).toBe(false);
  await user.click(screen.getByRole("button", { name: "Build fresh preview" }));
  expect(
    (
      screen.getByRole("checkbox", {
        name: "I approve the listed access increases",
      }) as HTMLInputElement
    ).checked,
  ).toBe(false);
  expect((applyButton as HTMLButtonElement).disabled).toBe(true);
  await user.click(
    screen.getByRole("checkbox", { name: /I reviewed all paths/ }),
  );
  await user.click(
    screen.getByRole("checkbox", {
      name: "I approve the listed access increases",
    }),
  );
  await user.click(applyButton);
  expect(command).toHaveBeenCalledWith({
    action: "apply",
    plan_id: "plan-modes-2",
    approval: "plan-modes-2",
    disposable_copies: true,
    allow_permission_widening: true,
  });
});
