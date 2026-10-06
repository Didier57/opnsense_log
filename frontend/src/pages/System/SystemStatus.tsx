import { useEffect, useState } from "react";
import { api } from "../../api/client";
import { StatCard } from "../../components/StatCard";

export function SystemStatus() {
  const [status, setStatus] = useState<Record<string, any> | null>(null);
  const [monitoring, setMonitoring] = useState<Record<string, number> | null>(null);

  const load = () => {
    api.systemStatus().then(setStatus).catch(() => undefined);
    api.monitoring().then(setMonitoring).catch(() => undefined);
  };

  useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, []);

  return (
    <>
      <div className="topbar">
        <h2>System status</h2>
        <button onClick={load}>Refresh</button>
      </div>
      <div className="cards">
        <StatCard label="Syslog received" value={monitoring?.received ?? 0} />
        <StatCard label="Parsed" value={monitoring?.parsed ?? 0} />
        <StatCard label="Invalid" value={monitoring?.invalid ?? 0} />
        <StatCard label="Events / sec" value={(monitoring?.events_per_sec ?? 0).toFixed(2)} />
      </div>
      <div className="panel">
        {status ? (
          <ul>
            <li>
              <span className={`status-dot ${status.syslog?.running ? "ok" : "bad"}`} /> Syslog listener{" "}
              {status.syslog?.protocol} :{status.syslog?.port}
            </li>
            <li>
              <span className={`status-dot ${status.database?.ok ? "ok" : "bad"}`} /> Database{" "}
              {status.database?.ok ? "OK" : "error"}
            </li>
            <li>
              <span className={`status-dot ${status.opnsense?.connected ? "ok" : "unknown"}`} /> OPNsense{" "}
              {status.opnsense?.connected ? "connected" : "not connected"}
            </li>
            <li className="muted">Uptime {Math.round(status.uptime_seconds ?? 0)} s</li>
          </ul>
        ) : (
          <p className="muted">Loading…</p>
        )}
      </div>
    </>
  );
}
