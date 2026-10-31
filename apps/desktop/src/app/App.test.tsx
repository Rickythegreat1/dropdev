import { beforeEach, expect, test } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./App";
import { resetDemo } from "../data/client";
beforeEach(resetDemo);
test("preview needs a separate explicit approval and displays an honest receipt", async () => {
  const user = userEvent.setup();
  render(<App />);
  await screen.findByText("Field notes", { selector: "h3" });
  await user.click(
    screen.getByRole("button", { name: /Scan & preview changes/ }),
  );
  const apply = await screen.findByRole("button", {
    name: "Apply to virtual replica",
  });
  expect((apply as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByText("src/notes.ts")).toBeTruthy();
  await user.click(screen.getByRole("checkbox"));
  expect((apply as HTMLButtonElement).disabled).toBe(false);
  await user.dblClick(apply);
  await screen.findByRole("status");
  expect(
    screen.getByText("Virtual replica updated. No device files were accessed."),
  ).toBeTruthy();
  expect((apply as HTMLButtonElement).disabled).toBe(true);
});
test("conflicts disable approval and show both references", async () => {
  const user = userEvent.setup();
  render(<App />);
  await screen.findByText("Field notes", { selector: "h3" });
  await user.click(screen.getByRole("button", { name: "Simulate conflict" }));
  await user.click(
    screen.getByRole("button", { name: /Scan & preview changes/ }),
  );
  await screen.findByText("conflict", { selector: ".operation" });
  expect((screen.getByRole("checkbox") as HTMLInputElement).disabled).toBe(
    true,
  );
  expect(screen.getByText(/demo-source-v/)).toBeTruthy();
  expect(screen.getByText(/demo-replica-v/)).toBeTruthy();
});
test("every navigation route renders working evidence or a precise empty state", async () => {
  const user = userEvent.setup();
  render(<App />);
  await screen.findByText("Field notes", { selector: "h3" });
  for (const name of [
    "Add project",
    "Project evidence",
    "Folder map",
    "Sync queue",
    "Conflicts",
    "Object store",
    "Environment",
    "Agent handoff",
    "Activity & recovery",
  ]) {
    await user.click(screen.getByRole("button", { name }));
    await waitFor(() =>
      expect(screen.getAllByRole("heading", { level: 2 }).length).toBe(1),
    );
  }
  expect(screen.getByRole("heading", { name: "Event log" })).toBeTruthy();
});
