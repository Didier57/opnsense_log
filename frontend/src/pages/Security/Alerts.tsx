import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../../api/client";
import { formatDateTime } from "../../format";
import type { Alert, SearchClause } from "../../types";

function severityClass(severity: string): string {
  const value = (severity || "").toLowerCase();
  if (value === "critical" || value === "high") return "block";
  return "other";
}

export interface AlertFilterState {
  clauses: SearchClause[];
  logic: string;
  start?: string;
  end?: string;
}

function alertFilters(alert: Alert): AlertFilterState {
  const clauses: SearchClause[] = [];
  if (alert.src_ip) clauses.push({ field: "src_ip", op: "eq", value: alert.src_ip });
  const windowSec = Number(alert.details?.window_sec) || 60;
  const reference = alert.event_time || alert.created_at;
  let start: string | undefined;
  let end: string | undefined;
  if (reference) {
    const time = new Date(reference).getTime();
    if (!Number.isNaN(time)) {
      start = new Date(time - windowSec * 1000).toISOString();
      end = new Date(time + 5000).toISOString();
    }
  }
  return { clauses, logic: "AND", start, end };
}

export function Alerts() {
  const navigate = useNavigate();
  const [items, setItems] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const load = () =>
    api
      .alerts()
      .then((data) => {
        setItems(data.items);
        setTotal(data.total);
      })
      .catch((e) => setError(String(e)));

  useEffect(() => {
    load();
  }, []);

  const runNow = async () => {
    setBusy(true);
    setMessage("");
    setError("");
    try {
      const result = await api.runDetection();
      setMessage(`Analyse terminée : ${result.created} nouvelle(s) alerte(s).`);
      load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const clear = async () => {
    if (!window.confirm("Supprimer toutes les alertes ?")) return;
    try {
      await api.clearAlerts();
      load();
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <>
      <div className="topbar">
        <h2>
          Alertes de sécurité <span className="muted" style={{ fontSize: 13 }}>{total}</span>
        </h2>
        <div className="filters">
          <button className="active" onClick={runNow} disabled={busy}>
            {busy ? "Analyse…" : "Analyser maintenant"}
          </button>
          <button onClick={load}>Rafraîchir</button>
          <button onClick={clear}>Vider</button>
        </div>
      </div>

      {message && <p className="muted">{message}</p>}
      {error && <p className="error">{error}</p>}

      <div className="panel">
        {items.length === 0 ? (
          <p className="muted">Aucune alerte.</p>
        ) : (
          <div className="table-scroll">
            <table className="log-table">
              <thead>
                <tr>
                  <th>Date-Heure</th>
                  <th>Gravité</th>
                  <th>Type</th>
                  <th>IP source</th>
                  <th>Détail</th>
                </tr>
              </thead>
              <tbody>
                {items.map((alert) => (
                  <tr
                    key={alert.id}
                    style={{ cursor: "pointer" }}
                    title="Voir les journaux associés dans l'historique"
                    onClick={() => navigate("/historical", { state: alertFilters(alert) })}
                  >
                    <td className="mono" title={`Alerte générée le ${formatDateTime(alert.created_at)}`}>
                      {formatDateTime(alert.event_time || alert.created_at)}
                    </td>
                    <td>
                      <span className={`badge ${severityClass(alert.severity)}`}>
                        {alert.severity.toUpperCase()}
                      </span>
                    </td>
                    <td>{alert.rule}</td>
                    <td className="mono">{alert.src_ip || "—"}</td>
                    <td>
                      <strong>{alert.title}</strong>
                      <div className="muted" style={{ fontSize: 12 }}>
                        {alert.message}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <p className="muted">
        La détection s'exécute en arrière-plan même sans navigateur ouvert. Configurez les seuils dans
        Détection et les envois dans Notifications.
      </p>
    </>
  );
}
