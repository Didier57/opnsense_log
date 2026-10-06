import { useEffect, useState } from "react";
import { api } from "../../api/client";
import { SyncButton } from "../../components/SyncButton";

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
        <h2>OPNsense status</h2>
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
                ? "connected"
                : status.opnsense?.configured
                  ? "unreachable"
                  : "not configured"}
              {status.opnsense?.error ? ` — ${status.opnsense.error}` : ""}
            </li>
            <li>
              <span className={`status-dot ${status.database?.ok ? "ok" : "bad"}`} /> Database{" "}
              {status.database?.ok ? "OK" : "error"}
            </li>
            <li>
              <span className="status-dot ok" /> Syslog {status.syslog?.protocol} :
              {status.syslog?.port}
            </li>
            <li>
              <span className={`status-dot ${status.websocket?.running ? "ok" : "bad"}`} /> WebSocket (
              {status.websocket?.subscribers ?? 0} subscribers)
            </li>
          </ul>
        ) : (
          !error && <p className="muted">Loading…</p>
        )}
      </div>
    </>
  );
}
