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
        <h2>État du système</h2>
        <button onClick={load}>Rafraîchir</button>
      </div>
      <div className="cards">
        <StatCard label="Syslog reçus" value={monitoring?.received ?? 0} />
        <StatCard label="Analysés" value={monitoring?.parsed ?? 0} />
        <StatCard label="Invalides" value={monitoring?.invalid ?? 0} />
        <StatCard label="Événements / s" value={(monitoring?.events_per_sec ?? 0).toFixed(2)} />
      </div>
      <div className="panel">
        {status ? (
          <ul>
            <li>
              <span className={`status-dot ${status.syslog?.running ? "ok" : "bad"}`} /> Écouteur Syslog{" "}
              {status.syslog?.protocol} :{status.syslog?.port}
            </li>
            <li>
              <span className={`status-dot ${status.database?.ok ? "ok" : "bad"}`} /> Base de données{" "}
              {status.database?.ok ? "OK" : "erreur"}
            </li>
            <li>
              <span className={`status-dot ${status.opnsense?.connected ? "ok" : "unknown"}`} /> OPNsense{" "}
              {status.opnsense?.connected ? "connecté" : "non connecté"}
            </li>
            <li className="muted">Durée de fonctionnement {Math.round(status.uptime_seconds ?? 0)} s</li>
          </ul>
        ) : (
          <p className="muted">Chargement…</p>
        )}
      </div>
    </>
  );
}
