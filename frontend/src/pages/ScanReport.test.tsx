import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import * as client from "../api/client";
import { ScanReport } from "./ScanReport";

describe("ScanReport", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows findings once the scan status is complete", async () => {
    vi.spyOn(client, "getScan").mockResolvedValue({
      id: 1,
      project_id: 1,
      status: "complete",
      started_at: null,
      finished_at: null,
    });
    vi.spyOn(client, "getScanFindings").mockResolvedValue([
      { id: 1, module: "subfinder", type: "subdomain", value: "a.example.com", data: {} },
    ]);

    render(
      <MemoryRouter initialEntries={["/scans/1"]}>
        <Routes>
          <Route path="/scans/:id" element={<ScanReport />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("Status: complete")).toBeInTheDocument();
    expect(await screen.findByText("a.example.com")).toBeInTheDocument();
  });
});
