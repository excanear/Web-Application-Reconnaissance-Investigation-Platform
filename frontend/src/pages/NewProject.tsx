import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";

import { createProject } from "../api/client";

export function NewProject() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [scopeNotes, setScopeNotes] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      const project = await createProject({
        name,
        target,
        scope_notes: scopeNotes,
        authorized,
      });
      navigate(`/projects/${project.id}`);
    } catch (err) {
      setError((err as Error).message);
    }
  }

  return (
    <form onSubmit={handleSubmit}>
      <h1>Novo Projeto</h1>
      <label>
        Nome
        <input value={name} onChange={(e) => setName(e.target.value)} required />
      </label>
      <label>
        Alvo (dominio)
        <input value={target} onChange={(e) => setTarget(e.target.value)} required />
      </label>
      <label>
        Escopo autorizado
        <textarea
          value={scopeNotes}
          onChange={(e) => setScopeNotes(e.target.value)}
          required
        />
      </label>
      <label>
        <input
          type="checkbox"
          checked={authorized}
          onChange={(e) => setAuthorized(e.target.checked)}
        />
        Confirmo que tenho autorizacao para testar este alvo
      </label>
      {error && <p role="alert">{error}</p>}
      <button type="submit" disabled={!authorized}>
        Criar projeto
      </button>
    </form>
  );
}
