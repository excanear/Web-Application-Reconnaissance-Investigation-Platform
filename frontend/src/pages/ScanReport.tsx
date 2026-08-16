import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";

import { getScan, getScanFindings, type Finding, type Scan } from "../api/client";

const POLL_INTERVAL_MS = 3000;

export function ScanReport() {
  const { id } = useParams<{ id: string }>();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);

  useEffect(() => {
    const scanId = Number(id);
    let cancelled = false;
    let timer: ReturnType<typeof setInterval>;

    async function poll() {
      const current = await getScan(scanId);
      if (cancelled) return;
      setScan(current);
      if (current.status === "complete" || current.status === "failed") {
        clearInterval(timer);
        setFindings(await getScanFindings(scanId));
      }
    }

    poll();
    timer = setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [id]);

  if (!scan) return <p>Carregando...</p>;

  return (
    <div>
      <h1>Scan #{scan.id}</h1>
      <p>Status: {scan.status}</p>
      <table>
        <thead>
          <tr>
            <th>Tipo</th>
            <th>Valor</th>
            <th>Modulo</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => (
            <tr key={finding.id}>
              <td>{finding.type}</td>
              <td>{finding.value}</td>
              <td>{finding.module}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
