import { useEffect, useState } from "react";
import { api } from "../../api/client";

interface DetectionForm {
  detection_enabled: boolean;
  detection_ignore_private: boolean;
  detection_spike_enabled: boolean;
  detection_interval_sec: number;
  detection_portscan_ports: number;
  detection_portscan_window_sec: number;
  detection_bruteforce_count: number;
  detection_bruteforce_window_sec: number;
  detection_spike_threshold: number;
  detection_spike_window_sec: number;
  detection_notify_cooldown_min: number;
}

const DEFAULT_FORM: DetectionForm = {
  detection_enabled: true,
  detection_ignore_private: true,
  detection_spike_enabled: false,
  detection_interval_sec: 60,
  detection_portscan_ports: 20,
  detection_portscan_window_sec: 60,
  detection_bruteforce_count: 20,
  detection_bruteforce_window_sec: 120,
  detection_spike_threshold: 300,
  detection_spike_window_sec: 60,
  detection_notify_cooldown_min: 60,
};

const NUMBER_FIELDS: { key: keyof DetectionForm; label: string; min: number }[] = [
  { key: "detection_interval_sec", label: "Intervalle d'analyse (s)", min: 15 },
  { key: "detection_portscan_ports", label: "Scan de ports — nb de ports distincts", min: 2 },
  { key: "detection_portscan_window_sec", label: "Scan de ports — fenêtre (s)", min: 5 },
  { key: "detection_bruteforce_count", label: "Force brute — nb de blocages", min: 2 },
  { key: "detection_bruteforce_window_sec", label: "Force brute — fenêtre (s)", min: 5 },
  { key: "detection_spike_threshold", label: "Pic de trafic — nb d'événements", min: 1 },
  { key: "detection_spike_window_sec", label: "Pic de trafic — fenêtre (s)", min: 5 },
  { key: "detection_notify_cooldown_min", label: "Anti-doublon e-mail (min)", min: 0 },
];

export function DetectionSettings() {
  const [form, setForm] = useState<DetectionForm>(DEFAULT_FORM);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const load = () =>
    api
      .detectionSettings()
      .then((data) => {
        setForm({
          detection_enabled: Boolean(data.detection_enabled ?? true),
          detection_ignore_private: Boolean(data.detection_ignore_private ?? true),
          detection_spike_enabled: Boolean(data.detection_spike_enabled ?? false),
          detection_interval_sec: Number(data.detection_interval_sec ?? 60),
          detection_portscan_ports: Number(data.detection_portscan_ports ?? 20),
          detection_portscan_window_sec: Number(data.detection_portscan_window_sec ?? 60),
          detection_bruteforce_count: Number(data.detection_bruteforce_count ?? 20),
          detection_bruteforce_window_sec: Number(data.detection_bruteforce_window_sec ?? 120),
          detection_spike_threshold: Number(data.detection_spike_threshold ?? 300),
          detection_spike_window_sec: Number(data.detection_spike_window_sec ?? 60),
          detection_notify_cooldown_min: Number(data.detection_notify_cooldown_min ?? 60),
        });
      })
      .catch((e) => setError(String(e)));

  useEffect(() => {
    load();
  }, []);

  const save = async () => {
    setBusy(true);
    setMessage("");
    setError("");
    try {
      await api.updateDetection({ ...form });
      setMessage("Enregistré.");
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
        <h2>Moteur de détection</h2>
        <button className="active" onClick={save} disabled={busy}>
          {busy ? "…" : "Enregistrer"}
        </button>
      </div>

      <div className="panel">
        <p className="muted">
          La détection analyse les journaux en arrière-plan (indépendamment du navigateur) et crée des alertes
          lorsque les seuils ci-dessous sont dépassés.
        </p>
        <label className="filters">
          <input
            type="checkbox"
            checked={form.detection_enabled}
            onChange={(e) => setForm({ ...form, detection_enabled: e.target.checked })}
          />
          Activer le moteur de détection
        </label>
        <label className="filters">
          <input
            type="checkbox"
            checked={form.detection_ignore_private}
            onChange={(e) => setForm({ ...form, detection_ignore_private: e.target.checked })}
          />
          Ignorer les adresses privées / locales (LAN) — évite les fausses alertes
        </label>
        <label className="filters">
          <input
            type="checkbox"
            checked={form.detection_spike_enabled}
            onChange={(e) => setForm({ ...form, detection_spike_enabled: e.target.checked })}
          />
          Détecter les pics de trafic (désactivé par défaut — génère beaucoup d'alertes)
        </label>
        <p className="muted" style={{ fontSize: 12 }}>
          L'anti-doublon e-mail empêche de renvoyer une alerte identique (même type, même IP source) pendant le délai
          choisi, y compris après un redémarrage. 0 = désactivé.
        </p>
      </div>

      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Seuils</h3>
        <div className="grid-2">
          {NUMBER_FIELDS.map((field) => (
            <label key={field.key} className="muted" style={{ fontSize: 12 }}>
              {field.label}
              <br />
              <input
                type="number"
                min={field.min}
                value={form[field.key] as number}
                onChange={(e) => setForm({ ...form, [field.key]: Number(e.target.value) })}
              />
            </label>
          ))}
        </div>
      </div>

      {message && <p className="muted">{message}</p>}
      {error && <p className="error">{error}</p>}
    </>
  );
}
