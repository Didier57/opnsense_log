import { useEffect, useRef, useState } from "react";
import { api } from "../api/client";

interface SyncResult {
  ok: boolean;
  error?: string;
  interfaces?: number;
  rules?: number;
  leases?: number;
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
        setMessage(
          `Synchronisé : ${result.interfaces ?? 0} interfaces, ${result.rules ?? 0} règles, ${result.leases ?? 0} baux DHCP`,
        );
      } else {
        setOk(false);
        setMessage(`Échec : ${result.error ?? "erreur inconnue"}`);
      }
      onDone?.();
    } catch (err) {
      setOk(false);
      setMessage(`Échec : ${String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <button className="active" onClick={run} disabled={busy}>
        {busy ? `Synchronisation… ${elapsed}s` : "Synchroniser"}
      </button>
      {message && (
        <span className={ok ? "muted" : "error"} style={{ fontSize: 13 }}>
          {message}
        </span>
      )}
    </>
  );
}
