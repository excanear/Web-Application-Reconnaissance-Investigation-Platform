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

  it("renders technology findings in a dedicated section", async () => {
    vi.spyOn(client, "getScan").mockResolvedValue({
      id: 1,
      project_id: 1,
      status: "complete",
      started_at: null,
      finished_at: null,
    });
    vi.spyOn(client, "getScanFindings").mockResolvedValue([
      {
        id: 1,
        module: "tech_fingerprint",
        type: "technology",
        value: "example.com",
        data: { category: "web_server", name: "nginx", version: "1.18.0", confidence: "high" },
      },
    ]);

    render(
      <MemoryRouter initialEntries={["/scans/1"]}>
        <Routes>
          <Route path="/scans/:id" element={<ScanReport />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByRole("heading", { name: /tecnologias/i })).toBeInTheDocument();
    expect(await screen.findByText("nginx")).toBeInTheDocument();
    expect(screen.getByText("1.18.0")).toBeInTheDocument();
    expect(screen.getByText("web_server")).toBeInTheDocument();
  });

  it("renders CVE findings in a dedicated section with severity and matched technology", async () => {
    vi.spyOn(client, "getScan").mockResolvedValue({
      id: 1,
      project_id: 1,
      status: "complete",
      started_at: null,
      finished_at: null,
    });
    vi.spyOn(client, "getScanFindings").mockResolvedValue([
      {
        id: 1,
        module: "cve_correlation",
        type: "cve",
        value: "CVE-2021-23017",
        data: {
          cvss_score: 9.4,
          severity: "CRITICAL",
          description: "A vuln in nginx resolver.",
          matched_technology: "nginx",
          matched_technology_version: "1.18.0",
        },
      },
    ]);

    render(
      <MemoryRouter initialEntries={["/scans/1"]}>
        <Routes>
          <Route path="/scans/:id" element={<ScanReport />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByRole("heading", { name: /cves/i })).toBeInTheDocument();
    expect(await screen.findByText("CVE-2021-23017")).toBeInTheDocument();
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
    expect(screen.getByText("9.4")).toBeInTheDocument();
    expect(screen.getByText(/nginx 1.18.0/)).toBeInTheDocument();
  });

  it("sorts CVE findings by CVSS score descending", async () => {
    vi.spyOn(client, "getScan").mockResolvedValue({
      id: 1,
      project_id: 1,
      status: "complete",
      started_at: null,
      finished_at: null,
    });
    vi.spyOn(client, "getScanFindings").mockResolvedValue([
      {
        id: 1,
        module: "cve_correlation",
        type: "cve",
        value: "CVE-LOW",
        data: { cvss_score: 3.1, severity: "LOW", description: "", matched_technology: "nginx", matched_technology_version: "1.18.0" },
      },
      {
        id: 2,
        module: "cve_correlation",
        type: "cve",
        value: "CVE-HIGH",
        data: { cvss_score: 9.8, severity: "CRITICAL", description: "", matched_technology: "nginx", matched_technology_version: "1.18.0" },
      },
    ]);

    render(
      <MemoryRouter initialEntries={["/scans/1"]}>
        <Routes>
          <Route path="/scans/:id" element={<ScanReport />} />
        </Routes>
      </MemoryRouter>,
    );

    const rows = await screen.findAllByRole("row");
    const cveIds = rows.map((r) => r.textContent).filter((t) => t?.includes("CVE-"));
    expect(cveIds[0]).toContain("CVE-HIGH");
    expect(cveIds[1]).toContain("CVE-LOW");
  });

  it("still renders other finding types in the generic table", async () => {
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

    expect(await screen.findByText("a.example.com")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /tecnologias/i })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /cves/i })).not.toBeInTheDocument();
  });

  it("shows an error message when polling the scan fails", async () => {
    vi.spyOn(client, "getScan").mockRejectedValue(new Error("scan fetch failed"));

    render(
      <MemoryRouter initialEntries={["/scans/1"]}>
        <Routes>
          <Route path="/scans/:id" element={<ScanReport />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("scan fetch failed");
  });
});
