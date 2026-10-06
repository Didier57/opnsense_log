import { useEffect, useState } from "react";
import { api } from "../../api/client";

const RETENTION_PRESETS = [
  { value: 0, label: "Illimitée (aucune suppression)" },
  { value: 7, label: "7 jours" },
  { value: 30, label: "30 jours" },
  { value: 90, label: "90 jours" },
  { value: 180, label: "180 jours" },
  { value: 365, label: "365 jours" },
];

interface AppForm {
  log_retention_days: number;
  retention_check_interval_min: number;
  display_timezone: string;
}

const DEFAULT_FORM: AppForm = {
  log_retention_days: 30,
  retention_check_interval_min: 60,
  display_timezone: "",
};

export function Settings() {
  const [form, setForm] = useState<AppForm>(DEFAULT_FORM);
  const [custom, setCustom] = useState(false);
  const [info, setInfo] = useState<Record<string, any> | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const loadInfo = () => api.settings().then(setInfo).catch(() => undefined);

  const load = () =>
    api
      .appSettings()
      .then((data) => {
        const next: AppForm = {
          log_retention_days: Number(data.log_retention_days ?? 30),
          retention_check_interval_min: Number(data.retention_check_interval_min ?? 60),
          display_timezone: String(data.display_timezone ?? ""),
        };
        setForm(next);
        setCustom(!RETENTION_PRESETS.some((p) => p.value === next.log_retention_days));
      })
      .catch(() => undefined);

  useEffect(() => {
    load();
    loadInfo();
  }, []);

  const save = async () => {
    setBusy(true);
    setMessage("");
    setError("");
    try {
      await api.updateAppSettings({ ...form });
      setMessage("Enregistré. La rétention est appliquée au prochain passage de la tâche de nettoyage.");
      loadInfo();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="topbar">
        <h2>Paramètres de l'application</h2>
        <button className="active" onClick={save} disabled={busy}>
          {busy ? "…" : "Enregistrer"}
        </button>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Rétention des journaux</h3>
        <p className="muted">
          Durée de conservation des événements avant suppression automatique. Choisissez « Illimitée » pour
          ne jamais supprimer (attention à l'espace disque).
        </p>
        <div className="filters">
          <label className="muted" style={{ fontSize: 12 }}>
            Conserver les journaux
            <br />
            <select
              value={custom ? "custom" : String(form.log_retention_days)}
              onChange={(e) => {
                if (e.target.value === "custom") {
                  setCustom(true);
                } else {
                  setCustom(false);
                  setForm({ ...form, log_retention_days: Number(e.target.value) });
                }
              }}
            >
              {RETENTION_PRESETS.map((preset) => (
                <option key={preset.value} value={String(preset.value)}>
                  {preset.label}
                </option>
              ))}
              <option value="custom">Autre (jours)…</option>
            </select>
          </label>
          {custom && (
            <label className="muted" style={{ fontSize: 12 }}>
              Nombre de jours
              <br />
              <input
                type="number"
                min={0}
                value={form.log_retention_days}
                onChange={(e) => setForm({ ...form, log_retention_days: Number(e.target.value) })}
              />
            </label>
          )}
          <label className="muted" style={{ fontSize: 12 }}>
            Intervalle de nettoyage (min)
            <br />
            <input
              type="number"
              min={5}
              value={form.retention_check_interval_min}
              onChange={(e) =>
                setForm({ ...form, retention_check_interval_min: Number(e.target.value) })
              }
            />
          </label>
        </div>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Affichage</h3>
        <label className="muted" style={{ fontSize: 12 }}>
          Fuseau horaire d'affichage
          <br />
          <input
            value={form.display_timezone}
            placeholder="Europe/Luxembourg"
            style={{ width: 280 }}
            onChange={(e) => setForm({ ...form, display_timezone: e.target.value })}
          />
        </label>
      </div>

      {message && <p className="muted">{message}</p>}
      {error && <p className="error">{error}</p>}

      {info && (
        <div className="panel">
          <h3 style={{ marginTop: 0 }}>Système (lecture seule)</h3>
          <p className="muted">Ces valeurs proviennent des variables d'environnement et ne sont pas modifiables ici.</p>
          <table className="log-table">
            <tbody>
              <tr>
                <td className="muted" style={{ width: 240 }}>Écoute Syslog</td>
                <td className="mono">
                  {info.syslog?.protocol} :{info.syslog?.port}
                </td>
              </tr>
              <tr>
                <td className="muted">File d'attente / workers</td>
                <td className="mono">
                  {info.syslog?.queue_maxsize} / {info.syslog?.workers}
                </td>
              </tr>
              <tr>
                <td className="muted">Répertoire de données</td>
                <td className="mono">{info.storage?.data_dir}</td>
              </tr>
              <tr>
                <td className="muted">Taille des lots</td>
                <td className="mono">{info.storage?.batch_size}</td>
              </tr>
              <tr>
                <td className="muted">Rétention active</td>
                <td className="mono">
                  {info.storage?.retention_days === 0
                    ? "Illimitée"
                    : `${info.storage?.retention_days} jours`}
                </td>
              </tr>
              <tr>
                <td className="muted">Authentification</td>
                <td className="mono">{info.application?.auth_enabled ? "activée" : "désactivée"}</td>
              </tr>
              <tr>
                <td className="muted">Moteur de base de données</td>
                <td className="mono">DuckDB</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
