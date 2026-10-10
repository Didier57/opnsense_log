import { useEffect, useState } from "react";
import { api } from "../../api/client";
import { StatCard } from "../../components/StatCard";

function formatUptime(totalSeconds: number): string {
  const s = Math.max(0, Math.floor(totalSeconds));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const parts: string[] = [];
  if (d) parts.push(`${d} j`);
  if (d || h) parts.push(`${h} h`);
  parts.push(`${m} min`);
  parts.push(`${sec} s`);
  return parts.join(" ");
}

export function SystemStatus() {
  const [status, setStatus] = useState<Record<string, any> | null>(null);
  const [monitoring, setMonitoring] = useState<Record<string, number> | null>(null);
  const [optimizeMsg, setOptimizeMsg] = useState("");

  const load = () => {
    api.systemStatus().then(setStatus).catch(() => undefined);
    api.monitoring().then(setMonitoring).catch(() => undefined);
  };

  useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, []);

  const optimize = async () => {
    if (
      !window.confirm(
        "Reconstruire la base des événements (triée par date) ? Opération lourde qui peut prendre plusieurs minutes, à lancer de préférence sans trafic important.",
      )
    )
      return;
    setOptimizeMsg("");
    try {
      await api.optimizeDb();
      setOptimizeMsg("Optimisation lancée en arrière-plan — voir Journaux système pour la fin.");
    } catch (err) {
      setOptimizeMsg(String(err));
    }
  };

  return (
    <>
      <div className="topbar">
        <h2>État du système</h2>
        <div style={{ display: "flex", gap: 8 }}>
          <button onClick={optimize}>Optimiser la base</button>
          <button onClick={load}>Rafraîchir</button>
        </div>
      </div>
      {optimizeMsg && <p className="muted">{optimizeMsg}</p>}
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
              <span className={`status-dot ${status.syslog?.connected ? "ok" : "bad"}`} /> Écouteur Syslog{" "}
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
            <li className="muted">
              Durée de fonctionnement (application backend) {formatUptime(monitoring?.uptime_seconds ?? 0)}
            </li>
          </ul>
        ) : (
          <p className="muted">Chargement…</p>
        )}
      </div>
    </>
  );
}
