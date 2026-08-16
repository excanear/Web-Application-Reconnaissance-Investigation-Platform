import { describe, expect, it } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { NewProject } from "./NewProject";

describe("NewProject", () => {
  it("disables submit until authorized is checked", () => {
    render(
      <MemoryRouter>
        <NewProject />
      </MemoryRouter>,
    );

    const submit = screen.getByRole("button", { name: /criar projeto/i });
    expect(submit).toBeDisabled();

    fireEvent.click(screen.getByRole("checkbox"));

    expect(submit).toBeEnabled();
  });
});
