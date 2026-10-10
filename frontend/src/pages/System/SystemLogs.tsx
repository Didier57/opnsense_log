import { useEffect, useMemo, useState } from "react";
import { api } from "../../api/client";

const LEVEL_CLASS: Record<string, string> = {
  ERROR: "block",
  WARNING: "other",
  INFO: "pass",
  DEBUG: "",
};

export function SystemLogs() {
  const [items, setItems] = useState<{ ts: string; level: string; source: string; message: string }[]>(
    [],
  );
  const [source, setSource] = useState("");

  const load = () => api.systemLogs(300).then((r) => setItems(r.items)).catch(() => undefined);

  useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, []);

  const sources = useMemo(
    () => Array.from(new Set(items.map((item) => item.source))).sort(),
    [items],
  );
  const filtered = source ? items.filter((item) => item.source === source) : items;

  return (
    <>
      <div className="topbar">
        <h2>Journaux système</h2>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <span className="muted">Source :</span>
          <select value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="">Toutes les sources</option>
            {sources.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
          <button onClick={load}>Rafraîchir</button>
        </div>
      </div>
      <div className="panel">
        <div className="table-scroll">
          <table className="log-table">
            <thead>
              <tr>
                <th>Heure</th>
                <th>Niveau</th>
                <th>Source</th>
                <th>Message</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item, index) => (
                <tr key={index}>
                  <td className="mono">{new Date(item.ts).toLocaleString()}</td>
                  <td>
                    <span className={`badge ${LEVEL_CLASS[item.level] ?? "other"}`}>{item.level}</span>
                  </td>
                  <td>{item.source}</td>
                  <td className="mono">{item.message}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {items.length === 0 && <p className="muted">Aucun journal.</p>}
        {items.length > 0 && filtered.length === 0 && (
          <p className="muted">Aucun journal pour cette source.</p>
        )}
      </div>
    </>
  );
}
