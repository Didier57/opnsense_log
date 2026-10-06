import { useEffect, useState } from "react";
import { api } from "../../api/client";

export function Settings() {
  const [settings, setSettings] = useState<Record<string, unknown> | null>(null);
  const [status, setStatus] = useState<Record<string, any> | null>(null);

  useEffect(() => {
    api.settings().then(setSettings).catch(() => undefined);
    api.systemStatus().then(setStatus).catch(() => undefined);
  }, []);

  return (
    <>
      <div className="topbar">
        <h2>Application settings</h2>
      </div>
      <div className="panel">
        <p className="muted">
          Configuration is read from environment variables. Restart the container to apply changes.
        </p>
        {settings && (
          <table className="log-table">
            <tbody>
              {Object.entries(settings).map(([key, value]) => (
                <tr key={key}>
                  <td className="muted" style={{ width: 220 }}>
                    {key}
                  </td>
                  <td className="mono">{String(value)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Storage</h3>
        <p className="muted">
          Database engine: DuckDB. Data directory persists in the Docker volume.
        </p>
        {status?.storage && <pre className="mono">{JSON.stringify(status.storage, null, 2)}</pre>}
      </div>
    </>
  );
}
