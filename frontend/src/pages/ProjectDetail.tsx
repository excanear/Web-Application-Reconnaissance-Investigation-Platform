import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";

import { createScan, getProject, type Project } from "../api/client";

export function ProjectDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [project, setProject] = useState<Project | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getProject(Number(id))
      .then(setProject)
      .catch((err) => setError((err as Error).message));
  }, [id]);

  async function handleNewScan() {
    try {
      const scan = await createScan(Number(id));
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  if (error) return <p role="alert">{error}</p>;
  if (!project) return <p>Carregando...</p>;

  return (
    <div>
      <h1>{project.name}</h1>
      <p>Alvo: {project.target}</p>
      <p>Escopo: {project.scope_notes}</p>
      <button onClick={handleNewScan}>Novo scan</button>
    </div>
  );
}
