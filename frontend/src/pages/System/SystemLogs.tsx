import { useEffect, useState } from "react";
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

  const load = () => api.systemLogs(300).then((r) => setItems(r.items)).catch(() => undefined);

  useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, []);

  return (
    <>
      <div className="topbar">
        <h2>Journaux système</h2>
        <button onClick={load}>Rafraîchir</button>
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
              {items.map((item, index) => (
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
      </div>
    </>
  );
}
