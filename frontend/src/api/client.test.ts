import { beforeEach, describe, expect, it, vi } from "vitest";
import { createProject, listProjects } from "./client";

describe("api client", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn());
  });

  it("listProjects calls GET /projects and returns parsed JSON", async () => {
    const projects = [
      {
        id: 1,
        name: "Test",
        target: "example.com",
        scope_notes: "ok",
        authorized: true,
        created_at: "2026-01-01",
      },
    ];
    (fetch as any).mockResolvedValueOnce({ ok: true, json: async () => projects });

    const result = await listProjects();

    expect(fetch).toHaveBeenCalledWith(
      "http://localhost:8000/projects",
      expect.objectContaining({ headers: { "Content-Type": "application/json" } }),
    );
    expect(result).toEqual(projects);
  });

  it("createProject throws when the response is not ok", async () => {
    (fetch as any).mockResolvedValueOnce({ ok: false, status: 422 });

    await expect(
      createProject({
        name: "Test",
        target: "example.com",
        scope_notes: "ok",
        authorized: false,
      }),
    ).rejects.toThrow("Request to /projects failed with status 422");
  });
});
