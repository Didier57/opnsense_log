import { useEffect, useState } from "react";
import { api } from "../../api/client";

interface NotificationForm {
  smtp_enabled: boolean;
  smtp_host: string;
  smtp_port: number;
  smtp_security: string;
  smtp_username: string;
  smtp_password: string;
  smtp_from_email: string;
  smtp_from_name: string;
  smtp_to: string;
}

const DEFAULT_FORM: NotificationForm = {
  smtp_enabled: false,
  smtp_host: "",
  smtp_port: 587,
  smtp_security: "starttls",
  smtp_username: "",
  smtp_password: "",
  smtp_from_email: "",
  smtp_from_name: "Analyseur de logs OPNsense",
  smtp_to: "",
};

const SECURITY_OPTIONS = [
  { value: "none", label: "Aucun (port 25)" },
  { value: "ssl", label: "SSL/TLS implicite (port 465)" },
  { value: "starttls", label: "STARTTLS (port 587)" },
];

export function NotificationsSettings() {
  const [form, setForm] = useState<NotificationForm>(DEFAULT_FORM);
  const [hasPassword, setHasPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const load = () =>
    api
      .notificationSettings()
      .then((data) => {
        setForm({
          smtp_enabled: Boolean(data.smtp_enabled ?? false),
          smtp_host: String(data.smtp_host ?? ""),
          smtp_port: Number(data.smtp_port ?? 587),
          smtp_security: String(data.smtp_security ?? "starttls"),
          smtp_username: String(data.smtp_username ?? ""),
          smtp_password: "",
          smtp_from_email: String(data.smtp_from_email ?? ""),
          smtp_from_name: String(data.smtp_from_name ?? ""),
          smtp_to: String(data.smtp_to ?? ""),
        });
        setHasPassword(Boolean(data.has_password));
      })
      .catch((e) => setError(String(e)));

  useEffect(() => {
    load();
  }, []);

  const payload = () => {
    const data: Record<string, unknown> = { ...form };
    if (!form.smtp_password) delete data.smtp_password;
    return data;
  };

  const save = async () => {
    setBusy(true);
    setMessage("");
    setError("");
    try {
      await api.updateNotifications(payload());
      setMessage("Enregistré.");
      load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    setBusy(true);
    setMessage("");
    setError("");
    try {
      await api.updateNotifications(payload());
      const result = await api.testNotifications();
      setMessage(result.message || (result.ok ? "E-mail de test envoyé." : "Échec de l'envoi."));
      load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="topbar">
        <h2>Notifications par e-mail (SMTP)</h2>
        <div className="filters">
          <button onClick={test} disabled={busy}>
            Tester l'envoi
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
            checked={form.smtp_enabled}
            onChange={(e) => setForm({ ...form, smtp_enabled: e.target.checked })}
          />
          Envoyer un e-mail lors de nouvelles alertes
        </label>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Serveur SMTP</h3>
        <div className="grid-2">
          <label className="muted" style={{ fontSize: 12 }}>
            Serveur
            <br />
            <input
              value={form.smtp_host}
              placeholder="smtp.exemple.com"
              onChange={(e) => setForm({ ...form, smtp_host: e.target.value })}
            />
          </label>
          <label className="muted" style={{ fontSize: 12 }}>
            Port
            <br />
            <input
              type="number"
              min={1}
              max={65535}
              value={form.smtp_port}
              onChange={(e) => setForm({ ...form, smtp_port: Number(e.target.value) })}
            />
          </label>
          <label className="muted" style={{ fontSize: 12 }}>
            Sécurité / chiffrement
            <br />
            <select
              value={form.smtp_security}
              onChange={(e) => setForm({ ...form, smtp_security: e.target.value })}
            >
              {SECURITY_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
          <label className="muted" style={{ fontSize: 12 }}>
            Nom d'utilisateur
            <br />
            <input
              value={form.smtp_username}
              onChange={(e) => setForm({ ...form, smtp_username: e.target.value })}
            />
          </label>
          <label className="muted" style={{ fontSize: 12 }}>
            Mot de passe {hasPassword ? "(un mot de passe est enregistré)" : ""}
            <br />
            <input
              type="password"
              value={form.smtp_password}
              placeholder={hasPassword ? "••••••••" : ""}
              onChange={(e) => setForm({ ...form, smtp_password: e.target.value })}
            />
          </label>
        </div>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Expéditeur et destinataire</h3>
        <div className="grid-2">
          <label className="muted" style={{ fontSize: 12 }}>
            E-mail de l'expéditeur
            <br />
            <input
              value={form.smtp_from_email}
              placeholder="alertes@exemple.com"
              onChange={(e) => setForm({ ...form, smtp_from_email: e.target.value })}
            />
          </label>
          <label className="muted" style={{ fontSize: 12 }}>
            Nom de l'expéditeur
            <br />
            <input
              value={form.smtp_from_name}
              onChange={(e) => setForm({ ...form, smtp_from_name: e.target.value })}
            />
          </label>
          <label className="muted" style={{ fontSize: 12 }}>
            Destinataire(s) (séparés par des virgules)
            <br />
            <input
              value={form.smtp_to}
              placeholder="admin@exemple.com"
              style={{ width: 320 }}
              onChange={(e) => setForm({ ...form, smtp_to: e.target.value })}
            />
          </label>
        </div>
      </div>

      {message && <p className="muted">{message}</p>}
      {error && <p className="error">{error}</p>}
    </>
  );
}
