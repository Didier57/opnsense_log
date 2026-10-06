import type { FirewallEvent } from "../types";
import { actionClass, formatTime, portLabel } from "../format";

interface Props {
  events: FirewallEvent[];
  onSelect?: (event: FirewallEvent) => void;
  interfaceMap?: Record<string, string>;
}

export function LogTable({ events, onSelect, interfaceMap = {} }: Props) {
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
            <th>Direction</th>
            <th>Proto</th>
            <th>Source</th>
            <th>Destination</th>
            <th>Flags</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event, index) => {
            const iface = interfaceMap[event.interface] || event.interface;
            return (
              <tr key={`${event.event_time}-${index}`} onClick={() => onSelect?.(event)}>
                <td className="mono">{formatTime(event.event_time)}</td>
                <td title={event.interface}>{iface}</td>
                <td>
                  <span className={`badge ${actionClass(event.action)}`}>{event.action.toUpperCase()}</span>
                </td>
                <td>{event.direction}</td>
                <td>{event.protocol}</td>
                <td className="mono">
                  {event.src_ip}
                  {portLabel(event.src_port)}
                </td>
                <td className="mono">
                  {event.dst_ip}
                  {portLabel(event.dst_port)}
                </td>
                <td className="mono">{event.tcp_flags}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
