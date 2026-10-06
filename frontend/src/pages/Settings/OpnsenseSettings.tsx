import { useEffect, useState } from "react";
import { api } from "../../api/client";

const FIELDS: { key: string; label: string; type?: string }[] = [
  { key: "opnsense_host", label: "Hôte" },
  { key: "opnsense_ssh_port", label: "Port SSH", type: "number" },
  { key: "opnsense_username", label: "Nom d'utilisateur" },
  { key: "opnsense_auth_type", label: "Type d'authentification (password / key)" },
  { key: "opnsense_password", label: "Mot de passe (laisser vide pour conserver l'actuel)", type: "password" },
  { key: "opnsense_key_path", label: "Chemin de la clé privée" },
  { key: "opnsense_sync_interval_min", label: "Intervalle de synchronisation (min)", type: "number" },
];

export function OpnsenseSettings() {
  const [form, setForm] = useState<Record<string, any>>({});
  const [hasPassword, setHasPassword] = useState(false);
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
        setHasPassword(Boolean(data.has_password));
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
      // Never overwrite a stored password with an empty field.
      if (!payload.opnsense_password) delete payload.opnsense_password;
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

  return (
    <>
      <div className="topbar">
        <h2>Connexion OPNsense</h2>
        <div className="filters">
          <button onClick={test} disabled={busy}>
            Tester la connexion
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
        {message && <p className="muted">{message}</p>}
        {error && <p className="error">{error}</p>}
        {FIELDS.map((field) => (
          <div key={field.key} style={{ marginBottom: 10 }}>
            <label className="muted" style={{ display: "block", marginBottom: 4 }}>
              {field.label}
              {field.key === "opnsense_password" && hasPassword ? " (un mot de passe est enregistré)" : ""}
            </label>
            <input
              type={field.type || "text"}
              value={form[field.key] ?? ""}
              placeholder={
                field.key === "opnsense_password" && hasPassword ? "••••••••" : undefined
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
    </>
  );
}
