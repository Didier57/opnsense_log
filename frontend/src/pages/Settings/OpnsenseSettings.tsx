import { useEffect, useState } from "react";
import { api } from "../../api/client";

const FIELDS: { key: string; label: string; type?: string }[] = [
  { key: "opnsense_host", label: "Host" },
  { key: "opnsense_port", label: "SSH port", type: "number" },
  { key: "opnsense_username", label: "Username" },
  { key: "opnsense_auth_type", label: "Auth type (password / key)" },
  { key: "opnsense_password", label: "Password", type: "password" },
  { key: "opnsense_key_path", label: "Private key path" },
  { key: "opnsense_sync_interval_min", label: "Sync interval (min)", type: "number" },
];

export function OpnsenseSettings() {
  const [form, setForm] = useState<Record<string, any>>({});
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const load = () =>
    api
      .opnsenseSettings()
      .then((data) => {
        const next: Record<string, any> = {};
        FIELDS.forEach((field) => {
          next[field.key] = data[field.key] ?? "";
        });
        next.opnsense_enabled = Boolean(data.opnsense_enabled);
        setForm(next);
      })
      .catch(() => undefined);

  useEffect(() => {
    load();
  }, []);

  const save = async () => {
    setError("");
    setMessage("");
    try {
      await api.updateOpnsense(form);
      setMessage("Saved.");
      load();
    } catch (e) {
      setError(String(e));
    }
  };

  const test = async () => {
    setError("");
    setMessage("");
    try {
      const result = await api.testOpnsense();
      setMessage(result.message || (result.ok ? "Connection OK" : "Connection failed"));
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <>
      <div className="topbar">
        <h2>OPNsense connection</h2>
        <div className="filters">
          <button onClick={test}>Test connection</button>
          <button className="active" onClick={save}>
            Save
          </button>
        </div>
      </div>
      <div className="panel">
        <label className="filters">
          <input
            type="checkbox"
            checked={Boolean(form.opnsense_enabled)}
            onChange={(e) => setForm({ ...form, opnsense_enabled: e.target.checked })}
          />
          Enable automatic synchronisation
        </label>
        {message && <p className="muted">{message}</p>}
        {error && <p className="error">{error}</p>}
        {FIELDS.map((field) => (
          <div key={field.key} style={{ marginBottom: 10 }}>
            <label className="muted" style={{ display: "block", marginBottom: 4 }}>
              {field.label}
            </label>
            <input
              type={field.type || "text"}
              value={form[field.key] ?? ""}
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
          Prefer SSH key authentication. Private key contents are never written to logs.
        </p>
      </div>
    </>
  );
}
