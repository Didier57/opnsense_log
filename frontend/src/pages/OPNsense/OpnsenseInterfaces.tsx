import { useEffect, useState } from "react";
import { api } from "../../api/client";
import type { OpnsenseInterface } from "../../types";

export function OpnsenseInterfaces() {
  const [items, setItems] = useState<OpnsenseInterface[]>([]);

  useEffect(() => {
    api.interfaces().then((r) => setItems(r.items)).catch(() => undefined);
  }, []);

  return (
    <>
      <div className="topbar">
        <h2>OPNsense interfaces</h2>
        <button className="active" onClick={() => api.syncRules().then(() => api.interfaces().then((r) => setItems(r.items)))}>
          Synchronise
        </button>
      </div>
      <div className="panel">
        <table className="log-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Device</th>
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
        {items.length === 0 && <p className="muted">No interfaces. Configure SSH and synchronise.</p>}
      </div>
    </>
  );
}
