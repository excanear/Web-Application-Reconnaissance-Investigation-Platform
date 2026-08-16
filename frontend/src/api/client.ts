const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8000";

export interface Project {
  id: number;
  name: string;
  target: string;
  scope_notes: string;
  authorized: boolean;
  created_at: string;
}

export interface Scan {
  id: number;
  project_id: number;
  status: "pending" | "running" | "complete" | "failed";
  started_at: string | null;
  finished_at: string | null;
}

export interface Finding {
  id: number;
  module: string;
  type: string;
  value: string;
  data: Record<string, unknown>;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...init,
  });
  if (!response.ok) {
    throw new Error(`Request to ${path} failed with status ${response.status}`);
  }
  return response.json();
}

export function listProjects(): Promise<Project[]> {
  return request("/projects");
}

export function createProject(payload: {
  name: string;
  target: string;
  scope_notes: string;
  authorized: boolean;
}): Promise<Project> {
  return request("/projects", { method: "POST", body: JSON.stringify(payload) });
}

export function getProject(id: number): Promise<Project> {
  return request(`/projects/${id}`);
}

export function createScan(projectId: number): Promise<Scan> {
  return request(`/projects/${projectId}/scans`, { method: "POST" });
}

export function getScan(id: number): Promise<Scan> {
  return request(`/scans/${id}`);
}

export function getScanFindings(id: number): Promise<Finding[]> {
  return request(`/scans/${id}/findings`);
}
