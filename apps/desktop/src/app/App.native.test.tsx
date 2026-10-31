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
