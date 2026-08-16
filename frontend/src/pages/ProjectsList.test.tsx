import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import * as client from "../api/client";
import { ProjectsList } from "./ProjectsList";

describe("ProjectsList", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows an error message when listing projects fails", async () => {
    vi.spyOn(client, "listProjects").mockRejectedValue(new Error("network down"));

    render(
      <MemoryRouter>
        <ProjectsList />
      </MemoryRouter>,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("network down");
  });
});
