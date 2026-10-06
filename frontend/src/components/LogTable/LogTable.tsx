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

export function LogTable({ events, onSelect, interfaceMap = {}, ruleMap = {} }: Props) {
  if (events.length === 0) {
    return <p className="muted">No events.</p>;
  }
  return (
    <div className="table-scroll">
      <table className="log-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Interface</th>
            <th>Action</th>
            <th>In/Out</th>
            <th>Proto</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Label</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, index) => (
            <tr key={`${event.event_time}-${index}`} onClick={() => onSelect?.(event)}>
              <td className="mono">{formatTime(event.event_time)}</td>
              <td title={event.interface}>{interfaceLabel(event, interfaceMap)}</td>
              <td>
                <span className={`badge ${actionClass(event.action)}`}>{event.action.toUpperCase()}</span>
              </td>
              <td>
                <span className="badge other">
                  {event.direction ? event.direction[0].toUpperCase() + event.direction.slice(1) : "—"}
                </span>
              </td>
              <td>{event.protocol}</td>
              <td className="mono">
                {event.src_ip}
                {portLabel(event.src_port)}
              </td>
              <td className="mono">
                {event.dst_ip}
                {portLabel(event.dst_port)}
              </td>
              <td title={ruleMap[event.rule_id] ?? ""}>
                {ruleMap[event.rule_id] ?? <span className="muted">—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
