import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";

interface SyncResult {
  ok: boolean;
  error?: string;
  interfaces?: number;
  rules?: number;
}

export function SyncButton({ onDone }: { onDone?: () => void }) {
  const [busy, setBusy] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [message, setMessage] = useState("");
  const [ok, setOk] = useState<boolean | null>(null);
  const timer = useRef<number | null>(null);

  useEffect(() => {
    if (busy) {
      const started = Date.now();
      setElapsed(0);
      timer.current = window.setInterval(() => setElapsed(Math.round((Date.now() - started) / 1000)), 1000);
    } else if (timer.current !== null) {
      window.clearInterval(timer.current);
      timer.current = null;
    }
    return () => {
      if (timer.current !== null) window.clearInterval(timer.current);
    };
  }, [busy]);

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
        {busy ? `Synchronising… ${elapsed}s` : "Synchronise"}
      </button>
      {message && (
        <span className={ok ? "muted" : "error"} style={{ fontSize: 13 }}>
          {message}
        </span>
      )}
    </>
  );
}
