import type { FirewallEvent } from "../../types";
import { actionClass, formatTime, portLabel } from "../../format";

interface Props {
  events: FirewallEvent[];
  onSelect?: (event: FirewallEvent) => void;
  interfaceMap?: Record<string, string>;
  ruleMap?: Record<string, string>;
}

function interfaceLabel(event: FirewallEvent, interfaceMap: Record<string, string>): string {
  return interfaceMap[event.interface] || event.interface;
}

function directionLabel(direction: string): string {
  return direction || "—";
}

export function LogTable({ events, onSelect, interfaceMap = {}, ruleMap = {} }: Props) {
  if (events.length === 0) {
    return <p className="muted">Aucun événement.</p>;
  }
  return (
    <div className="table-scroll">
      <table className="log-table">
        <thead>
          <tr>
            <th>Interface</th>
            <th>Sens</th>
            <th>Date-Heure</th>
            <th>Protocole</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Action</th>
            <th>Label</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, index) => (
            <tr key={`${event.event_time}-${index}`} onClick={() => onSelect?.(event)}>
              <td title={interfaceLabel(event, interfaceMap)}>
                <span className="truncate">{interfaceLabel(event, interfaceMap)}</span>
              </td>
              <td>
                <span className="badge other">{directionLabel(event.direction)}</span>
              </td>
              <td className="mono">{formatTime(event.event_time)}</td>
              <td>{event.protocol}</td>
              <td className="mono" title={`${event.src_ip}${portLabel(event.src_port)}`}>
                <span className="truncate">
                  {event.src_ip}
                  {portLabel(event.src_port)}
                </span>
              </td>
              <td className="mono" title={`${event.dst_ip}${portLabel(event.dst_port)}`}>
                <span className="truncate">
                  {event.dst_ip}
                  {portLabel(event.dst_port)}
                </span>
              </td>
              <td>
                <span className={`badge ${actionClass(event.action)}`}>{event.action.toUpperCase()}</span>
              </td>
              <td title={ruleMap[event.rule_id] ?? ""}>
                {ruleMap[event.rule_id] ? (
                  <span className="truncate">{ruleMap[event.rule_id]}</span>
                ) : (
                  <span className="muted">—</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
