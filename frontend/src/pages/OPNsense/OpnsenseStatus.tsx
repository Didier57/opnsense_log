import { useEffect, useState } from "react";
import { api } from "../../api/client";

export function OpnsenseStatus() {
  const [status, setStatus] = useState<Record<string, any> | null>(null);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () => api.systemStatus().then(setStatus).catch(() => undefined);
  useEffect(() => {
    load();
  }, []);

  const sync = async () => {
    setBusy(true);
    try {
      const result = await api.syncRules();
      setMessage(JSON.stringify(result));
      load();
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="topbar">
        <h2>OPNsense status</h2>
        <button onClick={sync} disabled={busy} className="active">
          {busy ? "Synchronising…" : "Synchronise now"}
        </button>
      </div>
      <div className="panel">
        {status ? (
          <ul>
            <li>
              <span className={`status-dot ${status.opnsense?.connected ? "ok" : "bad"}`} />
              OPNsense {status.opnsense?.connected ? "connected" : "unreachable"}
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
          </ul>
        ) : (
          <p className="muted">Loading…</p>
        )}
        {message && <pre className="mono">{message}</pre>}
      </div>
    </>
  );
}
