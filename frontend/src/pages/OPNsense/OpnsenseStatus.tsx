import { useEffect, useState } from "react";
import { api } from "../../api/client";
import { SyncButton } from "../../components/SyncButton";
import { FilterlogImportPanel } from "../../components/FilterlogImportPanel";

export function OpnsenseStatus() {
  const [status, setStatus] = useState<Record<string, any> | null>(null);
  const [error, setError] = useState("");

  const load = () =>
    api
      .systemStatus()
      .then((res) => {
        setStatus(res);
        setError("");
      })
      .catch((err) => setError(String(err)));

  useEffect(() => {
    load();
  }, []);

  return (
    <>
      <div className="topbar">
        <h2>État OPNsense</h2>
        <SyncButton onDone={load} />
      </div>
      <div className="panel">
        {error && <p className="error">{error}</p>}
        {status ? (
          <ul>
            <li>
              <span className={`status-dot ${status.opnsense?.connected ? "ok" : "bad"}`} />
              OPNsense{" "}
              {status.opnsense?.connected
                ? "connecté"
                : status.opnsense?.configured
                  ? "injoignable"
                  : "non configuré"}
              {status.opnsense?.error ? ` — ${status.opnsense.error}` : ""}
            </li>
            <li>
              <span className={`status-dot ${status.database?.ok ? "ok" : "bad"}`} /> Base de données{" "}
              {status.database?.ok ? "OK" : "erreur"}
            </li>
            <li>
              <span className="status-dot ok" /> Syslog {status.syslog?.protocol} :
              {status.syslog?.port}
            </li>
            <li>
              <span className={`status-dot ${status.websocket?.running ? "ok" : "bad"}`} /> WebSocket (
              {status.websocket?.subscribers ?? 0} abonnés)
            </li>
          </ul>
        ) : (
          !error && <p className="muted">Chargement…</p>
        )}
      </div>
      <FilterlogImportPanel />
    </>
  );
}
