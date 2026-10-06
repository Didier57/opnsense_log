import { useEffect, useState } from "react";
import { api } from "../../api/client";

interface GeoForm {
  geoip_enabled: boolean;
  geoip_account_id: string;
  geoip_license_key: string;
}

const DEFAULT_FORM: GeoForm = {
  geoip_enabled: true,
  geoip_account_id: "",
  geoip_license_key: "",
};

export function GeoipSettings() {
  const [form, setForm] = useState<GeoForm>(DEFAULT_FORM);
  const [status, setStatus] = useState<Record<string, unknown> | null>(null);
  const [hasKey, setHasKey] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const load = () => {
    api
      .geoipSettings()
      .then((data) => {
        setForm({
          geoip_enabled: Boolean(data.geoip_enabled ?? true),
          geoip_account_id: String(data.geoip_account_id ?? ""),
          geoip_license_key: "",
        });
        setHasKey(Boolean(data.has_license_key));
      })
      .catch(() => undefined);
    api.geoipStatus().then(setStatus).catch(() => undefined);
  };

  useEffect(load, []);

  const save = async () => {
    setBusy(true);
    setMessage("");
    setError("");
    try {
      await api.updateGeoip({ ...form });
      setMessage("Enregistré.");
      load();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  const update = async () => {
    setBusy(true);
    setMessage("");
    setError("");
    try {
      const result = await api.updateGeoipDatabase();
      if (result.ok) setMessage(`Base téléchargée (${result.source ?? "source inconnue"}).`);
      else setError(`Échec du téléchargement : ${result.error ?? "erreur inconnue"}`);
      load();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="topbar">
        <h2>Géolocalisation (pays)</h2>
        <div className="filters">
          <button onClick={update} disabled={busy}>
            Mettre à jour la base
          </button>
          <button className="active" onClick={save} disabled={busy}>
            {busy ? "…" : "Enregistrer"}
          </button>
        </div>
      </div>
      <div className="panel">
        <label className="filters">
          <input
            type="checkbox"
            checked={form.geoip_enabled}
            onChange={(e) => setForm({ ...form, geoip_enabled: e.target.checked })}
          />
          Activer la géolocalisation
        </label>
        <p className="muted">
          Par défaut, la base gratuite DB-IP Lite est utilisée (aucun compte requis). Si vous renseignez un
          identifiant et une clé de licence MaxMind, la base GeoLite2 est utilisée à la place. La licence
          MaxMind configurée dans OPNsense (Firewall → Aliases → GeoIP) est récupérée automatiquement lors de
          la synchronisation.
        </p>
        <div className="grid-2">
          <label>
            Identifiant MaxMind (Account ID)
            <input
              value={form.geoip_account_id}
              onChange={(e) => setForm({ ...form, geoip_account_id: e.target.value })}
            />
          </label>
          <label>
            Clé de licence MaxMind{hasKey ? " (une clé est enregistrée)" : ""}
            <input
              type="password"
              value={form.geoip_license_key}
              onChange={(e) => setForm({ ...form, geoip_license_key: e.target.value })}
              placeholder={hasKey ? "••••••••" : ""}
            />
          </label>
        </div>
        {message && <p className="muted">{message}</p>}
        {error && <p className="error">{error}</p>}
      </div>
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>État de la base</h3>
        {status ? (
          <ul>
            <li>Activée : {status.enabled ? "oui" : "non"}</li>
            <li>Base présente : {status.database ? "oui" : "non"}</li>
            <li>Source : {status.source === "maxmind" ? "MaxMind GeoLite2" : "DB-IP Lite"}</li>
            <li>
              Fichier : <span className="mono">{String(status.path ?? "")}</span>
            </li>
            <li>Mise à jour : {status.updated_at ? String(status.updated_at) : "—"}</li>
          </ul>
        ) : (
          <p className="muted">Chargement…</p>
        )}
      </div>
    </>
  );
}
