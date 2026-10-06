import { useState } from "react";
import { api } from "../api/client";

interface SyncResult {
  ok: boolean;
  error?: string;
  interfaces?: number;
  rules?: number;
}

export function SyncButton({ onDone }: { onDone?: () => void }) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [ok, setOk] = useState<boolean | null>(null);

  const run = async () => {
    setBusy(true);
    setMessage("");
    setOk(null);
    try {
      const result = (await api.syncRules()) as SyncResult;
      if (result.ok) {
        setOk(true);
        setMessage(`Synchronised: ${result.interfaces ?? 0} interfaces, ${result.rules ?? 0} rules`);
      } else {
        setOk(false);
        setMessage(`Failed: ${result.error ?? "unknown error"}`);
      }
      onDone?.();
    } catch (err) {
      setOk(false);
      setMessage(`Failed: ${String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <button className="active" onClick={run} disabled={busy}>
        {busy ? "Synchronising…" : "Synchronise"}
      </button>
      {message && (
        <span className={ok ? "muted" : "error"} style={{ fontSize: 13 }}>
          {message}
        </span>
      )}
    </>
  );
}
