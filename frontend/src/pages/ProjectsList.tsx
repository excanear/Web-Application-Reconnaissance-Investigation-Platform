import { useEffect, useState } from "react";
import { Link } from "react-router-dom";

import { listProjects, type Project } from "../api/client";

export function ProjectsList() {
  const [projects, setProjects] = useState<Project[]>([]);

  useEffect(() => {
    listProjects().then(setProjects);
  }, []);

  return (
    <div>
      <h1>Projetos</h1>
      <Link to="/projects/new">Novo projeto</Link>
      <ul>
        {projects.map((project) => (
          <li key={project.id}>
            <Link to={`/projects/${project.id}`}>
              {project.name} ({project.target})
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}
