import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";

import * as client from "../api/client";
import { ProjectDetail } from "./ProjectDetail";

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
});
