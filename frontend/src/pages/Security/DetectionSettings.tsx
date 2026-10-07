import { useEffect, useState } from "react";
import { api } from "../../api/client";
import { formatDateTime } from "../../format";
import type { BlockedIp } from "../../types";

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

interface BlockingForm {
  blocking_enabled: boolean;
  blocking_alias: string;
  blocking_mode: string;
  blocking_whitelist: string;
  blocking_ttl_hours: number;
  blocking_notify_email: boolean;
  blocking_token_days: number;
}

const DEFAULT_BLOCKING: BlockingForm = {
  blocking_enabled: false,
  blocking_alias: "",
  blocking_mode: "manual",
  blocking_whitelist: "",
  blocking_ttl_hours: 0,
  blocking_notify_email: true,
  blocking_token_days: 7,
};

export function DetectionSettings() {
  const [form, setForm] = useState<DetectionForm>(DEFAULT_FORM);
  const [blocking, setBlocking] = useState<BlockingForm>(DEFAULT_BLOCKING);
  const [blocked, setBlocked] = useState<BlockedIp[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [blockMessage, setBlockMessage] = useState("");
  const [blockError, setBlockError] = useState("");

  const loadBlocking = () =>
    api
      .blockingSettings()
      .then((data) =>
        setBlocking({
          blocking_enabled: Boolean(data.blocking_enabled ?? false),
          blocking_alias: String(data.blocking_alias ?? ""),
          blocking_mode: String(data.blocking_mode ?? "manual"),
          blocking_whitelist: String(data.blocking_whitelist ?? ""),
          blocking_ttl_hours: Number(data.blocking_ttl_hours ?? 0),
          blocking_notify_email: Boolean(data.blocking_notify_email ?? true),
          blocking_token_days: Number(data.blocking_token_days ?? 7),
        }),
      )
      .catch(() => undefined);

  const loadBlocked = () =>
    api
      .blockedList()
      .then((data) => setBlocked(data.items))
      .catch(() => undefined);

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
    loadBlocking();
    loadBlocked();
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

  const saveBlocking = async () => {
    setBlockMessage("");
    setBlockError("");
    try {
      await api.updateBlocking({ ...blocking });
      setBlockMessage("Enregistré.");
      loadBlocking();
    } catch (e) {
      setBlockError(String(e));
    }
  };

  const pruneBlocked = async () => {
    setBlockMessage("");
    setBlockError("");
    try {
      const result = await api.pruneBlocking();
      setBlockMessage(`${result.removed} IP expirée(s) retirée(s).`);
      loadBlocked();
    } catch (e) {
      setBlockError(String(e));
    }
  };

  const unblockIp = async (ip: string) => {
    setBlockMessage("");
    setBlockError("");
    try {
      const result = await api.unblockIp(ip);
      if (!result.ok) throw new Error(result.error || "Échec du retrait");
      setBlockMessage(`${ip} retirée.`);
      loadBlocked();
    } catch (e) {
      setBlockError(String(e));
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

      <div className="panel">
        <div className="filters" style={{ justifyContent: "space-between" }}>
          <h3 style={{ margin: 0 }}>Blocage automatique (alias OPNsense)</h3>
          <div className="filters">
            <button onClick={pruneBlocked}>Retirer les IP expirées</button>
            <button className="active" onClick={saveBlocking}>
              Enregistrer le blocage
            </button>
          </div>
        </div>
        <p className="muted" style={{ fontSize: 12 }}>
          Ajoute les IP sources des alertes <strong>force brute</strong> et <strong>scan de ports</strong> dans un alias
          de pare-feu de type « Host(s) ». Seules les IP publiques sont ajoutées (les adresses privées et la liste
          blanche sont ignorées). Nécessite une clé API OPNsense (voir Paramètres → OPNsense).
        </p>
        <label className="filters">
          <input
            type="checkbox"
            checked={blocking.blocking_enabled}
            onChange={(e) => setBlocking({ ...blocking, blocking_enabled: e.target.checked })}
          />
          Activer le blocage automatique
        </label>
        <div className="grid-2">
          <label className="muted" style={{ fontSize: 12 }}>
            Nom de l'alias « Host(s) » cible
            <br />
            <input
              type="text"
              value={blocking.blocking_alias}
              onChange={(e) => setBlocking({ ...blocking, blocking_alias: e.target.value })}
            />
          </label>
          <label className="muted" style={{ fontSize: 12 }}>
            Mode
            <br />
            <select
              value={blocking.blocking_mode}
              onChange={(e) => setBlocking({ ...blocking, blocking_mode: e.target.value })}
            >
              <option value="manual">Manuel (bouton sur les alertes)</option>
              <option value="auto">Automatique</option>
            </select>
          </label>
          <label className="muted" style={{ fontSize: 12 }}>
            Durée de blocage (heures, 0 = illimité)
            <br />
            <input
              type="number"
              min={0}
              value={blocking.blocking_ttl_hours}
              onChange={(e) => setBlocking({ ...blocking, blocking_ttl_hours: Number(e.target.value) })}
            />
          </label>
          <label className="muted" style={{ fontSize: 12 }}>
            Validité du lien de déblocage (jours)
            <br />
            <input
              type="number"
              min={1}
              value={blocking.blocking_token_days}
              onChange={(e) => setBlocking({ ...blocking, blocking_token_days: Number(e.target.value) })}
            />
          </label>
        </div>
        <label className="filters">
          <input
            type="checkbox"
            checked={blocking.blocking_notify_email}
            onChange={(e) => setBlocking({ ...blocking, blocking_notify_email: e.target.checked })}
          />
          Envoyer un e-mail lors d'un blocage (avec un bouton « Débloquer » — nécessite SMTP et l'URL publique)
        </label>
        <label className="muted" style={{ fontSize: 12 }}>
          Liste blanche (IP ou CIDR, séparés par des virgules — jamais bloqués)
          <br />
          <textarea
            rows={2}
            style={{ width: "100%" }}
            value={blocking.blocking_whitelist}
            onChange={(e) => setBlocking({ ...blocking, blocking_whitelist: e.target.value })}
          />
        </label>
        {blockMessage && <p className="muted">{blockMessage}</p>}
        {blockError && <p className="error">{blockError}</p>}
        {blocked.length > 0 && (
          <div className="table-scroll" style={{ maxHeight: 200 }}>
            <table className="log-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Règle</th>
                  <th>Source</th>
                  <th>Ajoutée</th>
                  <th>Expire</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {blocked.map((row) => (
                  <tr key={row.ip}>
                    <td className="mono">{row.ip}</td>
                    <td>{row.rule || "—"}</td>
                    <td>{row.source || "—"}</td>
                    <td className="mono">{row.added_at ? formatDateTime(row.added_at) : "—"}</td>
                    <td className="mono">{row.expires_at ? formatDateTime(row.expires_at) : "jamais"}</td>
                    <td>
                      <button
                        title="Retirer cette IP de l'alias et de la liste"
                        onClick={() => unblockIp(row.ip)}
                      >
                        Retirer
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {message && <p className="muted">{message}</p>}
      {error && <p className="error">{error}</p>}
    </>
  );
}
