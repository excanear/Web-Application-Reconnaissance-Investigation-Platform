import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";

import { getScan, getScanFindings, type Finding, type Scan } from "../api/client";

const POLL_INTERVAL_MS = 3000;

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#b91c1c",
  HIGH: "#c2410c",
  MEDIUM: "#a16207",
  LOW: "#4d7c0f",
};

export function ScanReport() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const scanId = Number(id);
    let cancelled = false;
    let timer: ReturnType<typeof setInterval>;

    async function poll() {
      try {
        const current = await getScan(scanId);
        if (cancelled) return;
        setScan(current);
        if (current.status === "complete" || current.status === "failed") {
          clearInterval(timer);
          const scanFindings = await getScanFindings(scanId);
          if (cancelled) return;
          setFindings(scanFindings);
        }
      } catch (err) {
        if (cancelled) return;
        clearInterval(timer);
        setError((err as Error).message);
      }
    }

    poll();
    timer = setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [id]);

  if (error) return <p role="alert">{error}</p>;
  if (!scan) return <p>Carregando...</p>;

  const technologies = findings.filter((f) => f.type === "technology");
  const cves = [...findings.filter((f) => f.type === "cve")].sort(
    (a, b) => (Number(b.data.cvss_score) || 0) - (Number(a.data.cvss_score) || 0),
  );
  const other = findings.filter((f) => f.type !== "technology" && f.type !== "cve");

  return (
    <div>
      <h1>Scan #{scan.id}</h1>
      <p>Status: {scan.status}</p>

      {technologies.length > 0 && (
        <section>
          <h2>Tecnologias</h2>
          <table>
            <thead>
              <tr>
                <th>Categoria</th>
                <th>Nome</th>
                <th>Versao</th>
                <th>Confianca</th>
                <th>Host</th>
              </tr>
            </thead>
            <tbody>
              {technologies.map((f) => (
                <tr key={f.id}>
                  <td>{String(f.data.category ?? "")}</td>
                  <td>{String(f.data.name ?? "")}</td>
                  <td>{f.data.version ? String(f.data.version) : "-"}</td>
                  <td>{String(f.data.confidence ?? "")}</td>
                  <td>{f.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      {cves.length > 0 && (
        <section>
          <h2>CVEs</h2>
          <table>
            <thead>
              <tr>
                <th>CVE</th>
                <th>Severidade</th>
                <th>CVSS</th>
                <th>Tecnologia afetada</th>
                <th>Descricao</th>
              </tr>
            </thead>
            <tbody>
              {cves.map((f) => {
                const severity = String(f.data.severity ?? "");
                return (
                  <tr key={f.id}>
                    <td>{f.value}</td>
                    <td style={{ color: SEVERITY_COLORS[severity] ?? undefined, fontWeight: "bold" }}>
                      {severity}
                    </td>
                    <td>{f.data.cvss_score !== undefined && f.data.cvss_score !== null ? String(f.data.cvss_score) : "-"}</td>
                    <td>
                      {String(f.data.matched_technology ?? "")} {String(f.data.matched_technology_version ?? "")}
                    </td>
                    <td>{String(f.data.description ?? "")}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      )}

      <section>
        <h2>Outros achados</h2>
        <table>
          <thead>
            <tr>
              <th>Tipo</th>
              <th>Valor</th>
              <th>Modulo</th>
            </tr>
          </thead>
          <tbody>
            {other.map((finding) => (
              <tr key={finding.id}>
                <td>{finding.type}</td>
                <td>{finding.value}</td>
                <td>{finding.module}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
