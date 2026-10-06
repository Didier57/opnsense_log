import { useEffect, useState } from "react";
import { api } from "../../api/client";
import { SyncButton } from "../../components/SyncButton";
import type { OpnsenseInterface } from "../../types";

export function OpnsenseInterfaces() {
  const [items, setItems] = useState<OpnsenseInterface[]>([]);

  const load = () => api.interfaces().then((r) => setItems(r.items)).catch(() => undefined);
  useEffect(() => {
    load();
  }, []);

  return (
    <>
      <div className="topbar">
        <h2>Interfaces OPNsense</h2>
        <SyncButton onDone={load} />
      </div>
      <div className="panel">
        <table className="log-table">
          <thead>
            <tr>
              <th>Nom</th>
              <th>Périphérique</th>
              <th>Description</th>
              <th>IPv4</th>
              <th>IPv6</th>
            </tr>
          </thead>
          <tbody>
            {items.map((iface) => (
              <tr key={iface.name}>
                <td>{iface.name}</td>
                <td className="mono">{iface.device}</td>
                <td>
                  {iface.description} <span className="muted">({iface.device})</span>
                </td>
                <td className="mono">{iface.ipv4}</td>
                <td className="mono">{iface.ipv6}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {items.length === 0 && <p className="muted">Aucune interface. Configurez le SSH et synchronisez.</p>}
      </div>
    </>
  );
}
