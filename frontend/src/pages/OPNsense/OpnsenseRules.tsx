import { useEffect, useState } from "react";
import { api } from "../../api/client";
import { SyncButton } from "../../components/SyncButton";
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
        <h2>Règles OPNsense</h2>
        <SyncButton onDone={load} />
      </div>
      <div className="panel">
        <div className="table-scroll">
          <table className="log-table">
            <thead>
              <tr>
                <th>ID de règle</th>
                <th>Description</th>
                <th>Interface</th>
                <th>Action</th>
                <th>Sens</th>
                <th>Protocole</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Activée</th>
              </tr>
            </thead>
            <tbody>
              {items.map((rule) => (
                <tr key={rule.rule_id} onClick={() => setSelected(rule)}>
                  <td className="mono">{rule.rule_id}</td>
                  <td className="desc-cell" title={rule.description}>
                    {rule.description}
                  </td>
                  <td>{rule.interface}</td>
                  <td>{rule.action}</td>
                  <td>{rule.direction}</td>
                  <td>{rule.protocol}</td>
                  <td className="mono wrap-cell" title={rule.source}>
                    {rule.source}
                  </td>
                  <td className="mono wrap-cell" title={rule.destination}>
                    {rule.destination}
                  </td>
                  <td>{rule.enabled ? "oui" : "non"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {items.length === 0 && <p className="muted">Aucune règle. Configurez le SSH et synchronisez.</p>}
      </div>
      {selected && (
        <div className="panel">
          <div className="topbar">
            <h3 style={{ margin: 0 }}>Règle {selected.rule_id}</h3>
            <button onClick={() => setSelected(null)}>Fermer</button>
          </div>
          <p>{selected.description}</p>
          <pre className="mono">{JSON.stringify(selected.history ?? [], null, 2)}</pre>
        </div>
      )}
    </>
  );
}
