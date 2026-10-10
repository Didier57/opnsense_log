import { useEffect, useState } from "react";
import { api } from "../../api/client";
import { useInstance } from "../../instance";

const FIELDS: { key: string; label: string; type?: string }[] = [
  { key: "opnsense_host", label: "Hôte" },
  { key: "opnsense_ssh_port", label: "Port SSH", type: "number" },
  { key: "opnsense_username", label: "Nom d'utilisateur" },
  { key: "opnsense_auth_type", label: "Type d'authentification (password / key)" },
  { key: "opnsense_password", label: "Mot de passe (laisser vide pour conserver l'actuel)", type: "password" },
  { key: "opnsense_key_path", label: "Chemin de la clé privée" },
  { key: "opnsense_sync_interval_min", label: "Intervalle de synchronisation (min)", type: "number" },
  { key: "opnsense_import_wait_syslog_sec", label: "Attente des premiers logs syslog avant import au démarrage (s)", type: "number" },
  { key: "opnsense_import_max_days", label: "Import : nombre de jours maximum à parcourir (0 = illimité)", type: "number" },
  { key: "opnsense_api_scheme", label: "Protocole API OPNsense (https / http)" },
  { key: "opnsense_api_port", label: "Port API OPNsense (celui de l'interface web)", type: "number" },
  { key: "opnsense_api_key", label: "Clé API OPNsense" },
  { key: "opnsense_api_secret", label: "Secret API OPNsense (laisser vide pour conserver l'actuel)", type: "password" },
];

export function OpnsenseSettings() {
  const { instances, instance } = useInstance();
  const [form, setForm] = useState<Record<string, any>>({});
  const [hasPassword, setHasPassword] = useState(false);
  const [hasApiKey, setHasApiKey] = useState(false);
  const [hasApiSecret, setHasApiSecret] = useState(false);
  const [showHelp, setShowHelp] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () =>
    api
      .opnsenseSettings()
      .then((data) => {
        const next: Record<string, any> = {};
        FIELDS.forEach((field) => {
          next[field.key] = data[field.key] ?? "";
        });
        next.opnsense_sync_enabled = Boolean(data.opnsense_sync_enabled);
        next.opnsense_import_on_start = Boolean(data.opnsense_import_on_start);
        next.opnsense_ha_enabled = Boolean(data.opnsense_ha_enabled);
        next.opnsense_ha_master = data.opnsense_ha_master ?? "";
        setHasPassword(Boolean(data.has_password));
        setHasApiKey(Boolean(data.has_api_key));
        setHasApiSecret(Boolean(data.has_api_secret));
        setForm(next);
      })
      .catch(() => undefined);

  useEffect(() => {
    load();
  }, []);

  const save = async () => {
    setError("");
    setMessage("");
    setBusy(true);
    try {
      const payload: Record<string, unknown> = { ...form };
      // Never overwrite a stored password/secret with an empty field.
      if (!payload.opnsense_password) delete payload.opnsense_password;
      if (!payload.opnsense_api_secret) delete payload.opnsense_api_secret;
      if (!payload.opnsense_api_key) delete payload.opnsense_api_key;
      await api.updateOpnsense(payload);
      setMessage("Enregistré.");
      load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    setError("");
    setMessage("");
    setBusy(true);
    try {
      const result = await api.testOpnsense();
      setMessage(result.message || (result.ok ? "Connexion réussie" : "Échec de la connexion"));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const generateKey = async () => {
    if (
      !window.confirm(
        "Générer une nouvelle clé API sur le firewall via SSH (utilisateur « " +
          (form.opnsense_username || "root") +
          " ») ? Une paire clé/secret sera créée et enregistrée ici.",
      )
    )
      return;
    setError("");
    setMessage("");
    setBusy(true);
    try {
      const result = await api.generateOpnsenseApiKey();
      setMessage(result.message || (result.ok ? "Clé API générée" : "Échec"));
      if (result.ok) load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const detectApi = async () => {
    setError("");
    setMessage("");
    setBusy(true);
    try {
      const result = await api.detectOpnsenseApi();
      setMessage(result.message || (result.ok ? "Détecté" : "Échec de la détection"));
      if (result.ok) load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const testApi = async () => {
    setError("");
    setMessage("");
    setBusy(true);
    try {
      const result = await api.testOpnsenseApi();
      setMessage(result.message || (result.ok ? "API OK" : "Échec de l'API"));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="topbar">
        <h2>Connexion OPNsense</h2>
        <div className="filters">
          <button onClick={test} disabled={busy}>
            Tester la connexion SSH
          </button>
          <button onClick={detectApi} disabled={busy}>
            Détecter (SSH)
          </button>
          <button onClick={testApi} disabled={busy}>
            Tester l'API
          </button>
          <button
            onClick={generateKey}
            disabled={busy || Boolean(form.opnsense_ha_enabled)}
            title={
              Boolean(form.opnsense_ha_enabled)
                ? "En HA, générez la clé sur l'instance maître : elle sera héritée ici"
                : undefined
            }
          >
            Générer la clé API (SSH)
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
            checked={Boolean(form.opnsense_sync_enabled)}
            onChange={(e) => setForm({ ...form, opnsense_sync_enabled: e.target.checked })}
          />
          Activer la synchronisation automatique
        </label>
        <label className="filters">
          <input
            type="checkbox"
            checked={Boolean(form.opnsense_import_on_start)}
            onChange={(e) => setForm({ ...form, opnsense_import_on_start: e.target.checked })}
          />
          Récupérer les logs OPNsense (fichiers) au démarrage de l'application
        </label>
        <label className="filters">
          <input
            type="checkbox"
            checked={Boolean(form.opnsense_ha_enabled)}
            onChange={(e) =>
              setForm({
                ...form,
                opnsense_ha_enabled: e.target.checked,
                opnsense_ha_master: e.target.checked ? form.opnsense_ha_master || "" : "",
              })
            }
          />
          Ce pare-feu fait partie d'un cluster Haute Disponibilité (HA)
        </label>
        {form.opnsense_ha_enabled && (
          <div style={{ marginBottom: 10 }}>
            <label className="muted" style={{ display: "block", marginBottom: 4 }}>
              Instance maître (clé API héritée)
            </label>
            <select
              value={form.opnsense_ha_master ?? ""}
              onChange={(e) => setForm({ ...form, opnsense_ha_master: e.target.value })}
              style={{ width: 320 }}
            >
              <option value="">— Choisir —</option>
              {instances
                .filter((inst) => inst.id !== instance?.id)
                .map((inst) => (
                  <option key={inst.id} value={inst.id}>
                    {inst.name}
                    {inst.enabled ? "" : " (désactivée)"}
                  </option>
                ))}
            </select>
            <p className="muted" style={{ fontSize: 12, marginTop: 4 }}>
              En HA, OPNsense réplique la configuration (clés API comprises) du maître. La clé et le
              secret de cette instance sont donc <strong>hérités en direct</strong> de l'instance
              maître : une seule clé sert aux deux nœuds, plus de désynchronisation.
            </p>
          </div>
        )}
        {message && <p className="muted">{message}</p>}
        {error && <p className="error">{error}</p>}
        {FIELDS.map((field) => (
          <div key={field.key} style={{ marginBottom: 10 }}>
            <label className="muted" style={{ display: "block", marginBottom: 4 }}>
              {field.label}
              {field.key === "opnsense_password" && hasPassword ? " (un mot de passe est enregistré)" : ""}
              {field.key === "opnsense_api_key" && hasApiKey ? " (une clé est enregistrée)" : ""}
            </label>
            <input
              type={field.type || "text"}
              value={form[field.key] ?? ""}
              disabled={
                Boolean(form.opnsense_ha_enabled) &&
                (field.key === "opnsense_api_key" || field.key === "opnsense_api_secret")
              }
              placeholder={
                (field.key === "opnsense_password" && hasPassword) ||
                (field.key === "opnsense_api_secret" && hasApiSecret) ||
                (field.key === "opnsense_api_key" && hasApiKey)
                  ? "••••••••"
                  : undefined
              }
              style={{ width: 320 }}
              onChange={(e) =>
                setForm({
                  ...form,
                  [field.key]:
                    field.type === "number" ? Number(e.target.value) : e.target.value,
                })
              }
            />
          </div>
        ))}
        <p className="muted">
          Préférez l'authentification par clé SSH. Les paramètres sont stockés côté serveur (volume de données) et
          remplacent les valeurs par défaut des variables d'environnement. Les clés privées ne sont jamais écrites dans les journaux.
        </p>
      </div>

      <div className="panel">
        <div className="filters" style={{ justifyContent: "space-between" }}>
          <h3 style={{ margin: 0 }}>Clé API OPNsense (blocage automatique)</h3>
          <button onClick={() => setShowHelp((v) => !v)}>
            {showHelp ? "Masquer l'aide" : "Aide"}
          </button>
        </div>
        <p className="muted" style={{ fontSize: 12 }}>
          Utilisée pour ajouter les IP des alertes (force brute / scan de ports) dans un alias de pare-feu.
          {hasApiKey && hasApiSecret ? " Une clé est actuellement enregistrée." : " Aucune clé enregistrée."}
        </p>
        {showHelp && (
          <div className="panel" style={{ background: "var(--bg-soft, rgba(255,255,255,0.03))" }}>
            <p className="muted" style={{ fontSize: 12 }}>
              Deux méthodes :
            </p>
            <ol className="muted" style={{ fontSize: 12 }}>
              <li>
                Cliquez sur <strong>« Générer la clé API (SSH) »</strong> : l'application crée une clé (nommée
                « OPNsense_log ») sur le firewall via SSH et l'enregistre automatiquement.
              </li>
              <li>
                Ou créez-la à la main dans OPNsense : <em>Système → Accès → Utilisateurs</em>, sélectionnez
                l'utilisateur, bouton « + » dans la section <em>Clés API</em>, puis copiez la clé et le secret ici.
                Le secret n'est affiché qu'une seule fois.
              </li>
            </ol>
          </div>
        )}
      </div>
    </>
  );
}
