import { useEffect, useState } from "react";
import { api } from "../api/client";
import { formatNumber } from "../format";
import type { FilterlogImportStatus } from "../types";

export function FilterlogImportPanel() {
  const [status, setStatus] = useState<FilterlogImportStatus | null>(null);
  const [message, setMessage] = useState("");

  const load = () =>
    api
      .importFilterlogStatus()
      .then(setStatus)
      .catch(() => undefined);

  useEffect(() => {
    load();
    const id = window.setInterval(load, 3000);
    return () => window.clearInterval(id);
  }, []);

  const start = async () => {
    setMessage("");
    try {
      const res = await api.importFilterlog();
      setStatus(res.status);
      setMessage(res.started ? "Import démarré…" : "Un import est déjà en cours.");
    } catch (err) {
      setMessage(String(err));
    }
  };

  const running = Boolean(status?.running);

  return (
    <div className="panel">
      <div className="topbar">
        <h3 style={{ margin: 0 }}>Récupération des logs OPNsense</h3>
        <button className="active" onClick={start} disabled={running}>
          {running ? "Import en cours…" : "Récupérer les logs"}
        </button>
      </div>
      <p className="muted">
        Lit les fichiers de logs du pare-feu par SSH et importe uniquement les événements manquants
        (les jours déjà présents sont ignorés). Utile après un arrêt de l'application.
      </p>
      {message && <p className="muted">{message}</p>}
      {status?.error && <p className="error">{status.error}</p>}
      {status ? (
        <ul>
          <li>
            État :{" "}
            <span className={`status-dot ${running ? "ok" : "unknown"}`} />{" "}
            {running ? "en cours" : status.finished_at ? "terminé" : "inactif"}
          </li>
          <li>
            Fichiers : {formatNumber(status.files_scanned)} / {formatNumber(status.files_total)}{" "}
            analysés, {formatNumber(status.files_imported)} importés,{" "}
            {formatNumber(status.files_skipped)} déjà complets
          </li>
          <li>
            Lignes lues : {formatNumber(status.lines)} — importées :{" "}
            {formatNumber(status.inserted)} — ignorées : {formatNumber(status.skipped)} — invalides :{" "}
            {formatNumber(status.invalid)}
          </li>
          {status.current_file && <li className="muted mono">Fichier : {status.current_file}</li>}
        </ul>
      ) : (
        <p className="muted">Chargement…</p>
      )}
    </div>
  );
}
