import { useEffect, useState } from "react";
import { api } from "../../api/client";
import type { OpnsenseRule } from "../../types";

export function OpnsenseRules() {
  const [items, setItems] = useState<OpnsenseRule[]>([]);
  const [selected, setSelected] = useState<OpnsenseRule | null>(null);

  const load = () => api.rules().then((r) => setItems(r.items)).catch(() => undefined);
  useEffect(() => {
    load();
  }, []);

  return (
    <>
      <div className="topbar">
        <h2>OPNsense rules</h2>
        <button
          className="active"
          onClick={() => api.syncRules().then(() => load())}
        >
          Synchronise
        </button>
      </div>
      <div className="panel">
        <table className="log-table">
          <thead>
            <tr>
              <th>Rule ID</th>
              <th>Description</th>
              <th>Interface</th>
              <th>Action</th>
              <th>Direction</th>
              <th>Protocol</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Enabled</th>
            </tr>
          </thead>
          <tbody>
            {items.map((rule) => (
              <tr key={rule.rule_id} onClick={() => setSelected(rule)}>
                <td className="mono">{rule.rule_id}</td>
                <td>{rule.description}</td>
                <td>{rule.interface}</td>
                <td>{rule.action}</td>
                <td>{rule.direction}</td>
                <td>{rule.protocol}</td>
                <td className="mono">{rule.source}</td>
                <td className="mono">{rule.destination}</td>
                <td>{rule.enabled ? "yes" : "no"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {items.length === 0 && <p className="muted">No rules. Configure SSH and synchronise.</p>}
      </div>
      {selected && (
        <div className="panel">
          <div className="topbar">
            <h3 style={{ margin: 0 }}>Rule {selected.rule_id}</h3>
            <button onClick={() => setSelected(null)}>Close</button>
          </div>
          <p>{selected.description}</p>
          <pre className="mono">{JSON.stringify(selected.history ?? [], null, 2)}</pre>
        </div>
      )}
    </>
  );
}
