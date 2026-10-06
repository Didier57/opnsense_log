import type { FirewallEvent } from "../../types";
import { formatDateTime } from "../../format";

interface Props {
  event: FirewallEvent | null;
  onClose: () => void;
  ruleDescription?: string;
}

const FIELDS: [keyof FirewallEvent, string][] = [
  ["rule_id", "ID de règle"],
  ["interface", "Interface"],
  ["reason", "Raison"],
  ["action", "Action"],
  ["direction", "Sens"],
  ["ip_version", "Version IP"],
  ["protocol", "Protocole"],
  ["src_ip", "IP source"],
  ["src_port", "Port source"],
  ["dst_ip", "IP destination"],
  ["dst_port", "Port destination"],
  ["tcp_flags", "Drapeaux TCP"],
  ["options", "Options"],
  ["length", "Longueur"],
  ["hostname", "Hôte"],
  ["parse_status", "État d'analyse"],
];

export function EventDetails({ event, onClose, ruleDescription }: Props) {
  if (!event) return null;
  return (
    <div className="panel">
      <div className="topbar">
        <h3 style={{ margin: 0 }}>Détails de l'événement</h3>
        <button onClick={onClose}>Fermer</button>
      </div>
      <p className="muted">{formatDateTime(event.event_time)}</p>
      {ruleDescription && (
        <p>
          <strong>Règle :</strong> {ruleDescription}
        </p>
      )}
      <table className="log-table">
        <tbody>
          {FIELDS.map(([key, label]) => (
            <tr key={String(key)}>
              <td className="muted" style={{ width: 160 }}>
                {label}
              </td>
              <td className="mono">{String(event[key] ?? "")}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <details style={{ marginTop: 10 }}>
        <summary className="muted">Ligne brute</summary>
        <pre className="mono" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
          {event.raw}
        </pre>
      </details>
    </div>
  );
}
