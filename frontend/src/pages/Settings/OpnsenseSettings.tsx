import { useEffect, useState } from "react";
import { api } from "../../api/client";

const FIELDS: { key: string; label: string; type?: string }[] = [
  { key: "opnsense_host", label: "Host" },
  { key: "opnsense_ssh_port", label: "SSH port", type: "number" },
  { key: "opnsense_username", label: "Username" },
  { key: "opnsense_auth_type", label: "Auth type (password / key)" },
  { key: "opnsense_password", label: "Password (leave empty to keep current)", type: "password" },
  { key: "opnsense_key_path", label: "Private key path" },
  { key: "opnsense_sync_interval_min", label: "Sync interval (min)", type: "number" },
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
      setMessage("Saved.");
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
      setMessage(result.message || (result.ok ? "Connection OK" : "Connection failed"));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="topbar">
        <h2>OPNsense connection</h2>
        <div className="filters">
          <button onClick={test} disabled={busy}>
            Test connection
          </button>
          <button className="active" onClick={save} disabled={busy}>
            {busy ? "…" : "Save"}
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
          Enable automatic synchronisation
        </label>
        {message && <p className="muted">{message}</p>}
        {error && <p className="error">{error}</p>}
        {FIELDS.map((field) => (
          <div key={field.key} style={{ marginBottom: 10 }}>
            <label className="muted" style={{ display: "block", marginBottom: 4 }}>
              {field.label}
              {field.key === "opnsense_password" && hasPassword ? " (a password is stored)" : ""}
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
          Prefer SSH key authentication. Settings are stored server-side (data volume) and
          override any defaults from environment variables. Private keys are never written to logs.
        </p>
      </div>
    </>
  );
}
