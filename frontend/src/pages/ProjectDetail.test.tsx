import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import * as client from "../api/client";
import { ProjectDetail } from "./ProjectDetail";

const PROJECT = {
  id: 1,
  name: "Test Co",
  target: "example.com",
  scope_notes: "only example.com",
  authorized: true,
  created_at: "2026-01-01",
};

describe("ProjectDetail", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows an error message when loading the project fails", async () => {
    vi.spyOn(client, "getProject").mockRejectedValue(new Error("project fetch failed"));

    render(
      <MemoryRouter initialEntries={["/projects/1"]}>
        <Routes>
          <Route path="/projects/:id" element={<ProjectDetail />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("project fetch failed");
  });

  it("disables the new scan button until active modules are confirmed", async () => {
    vi.spyOn(client, "getProject").mockResolvedValue(PROJECT);

    render(
      <MemoryRouter initialEntries={["/projects/1"]}>
        <Routes>
          <Route path="/projects/:id" element={<ProjectDetail />} />
        </Routes>
      </MemoryRouter>,
    );

    const button = await screen.findByRole("button", { name: /novo scan/i });
    expect(button).toBeDisabled();

    fireEvent.click(screen.getByRole("checkbox"));

    expect(button).toBeEnabled();
  });

  it("passes the confirmation through to createScan", async () => {
    vi.spyOn(client, "getProject").mockResolvedValue(PROJECT);
    const createScanSpy = vi.spyOn(client, "createScan").mockResolvedValue({
      id: 5,
      project_id: 1,
      status: "pending",
      started_at: null,
      finished_at: null,
    });

    render(
      <MemoryRouter initialEntries={["/projects/1"]}>
        <Routes>
          <Route path="/projects/:id" element={<ProjectDetail />} />
          <Route path="/scans/:id" element={<div>Scan report</div>} />
        </Routes>
      </MemoryRouter>,
    );

    fireEvent.click(await screen.findByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: /novo scan/i }));

    await screen.findByText("Scan report");
    expect(createScanSpy).toHaveBeenCalledWith(1, true);
  });
});
