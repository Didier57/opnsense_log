import type { FirewallEvent } from "../../types";
import { formatDateTime } from "../../format";

interface Props {
  event: FirewallEvent | null;
  onClose: () => void;
  ruleDescription?: string;
}

const FIELDS: [keyof FirewallEvent, string][] = [
  ["rule_id", "Rule ID"],
  ["interface", "Interface"],
  ["reason", "Reason"],
  ["action", "Action"],
  ["direction", "Direction"],
  ["ip_version", "IP version"],
  ["protocol", "Protocol"],
  ["src_ip", "Source IP"],
  ["src_port", "Source port"],
  ["dst_ip", "Destination IP"],
  ["dst_port", "Destination port"],
  ["tcp_flags", "TCP flags"],
  ["options", "Options"],
  ["length", "Length"],
  ["hostname", "Host"],
  ["parse_status", "Parse status"],
];

export function EventDetails({ event, onClose, ruleDescription }: Props) {
  if (!event) return null;
  return (
    <div className="panel">
      <div className="topbar">
        <h3 style={{ margin: 0 }}>Event details</h3>
        <button onClick={onClose}>Close</button>
      </div>
      <p className="muted">{formatDateTime(event.event_time)}</p>
      {ruleDescription && (
        <p>
          <strong>Rule:</strong> {ruleDescription}
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
        <summary className="muted">Raw line</summary>
        <pre className="mono" style={{ whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
          {event.raw}
        </pre>
      </details>
    </div>
  );
}
