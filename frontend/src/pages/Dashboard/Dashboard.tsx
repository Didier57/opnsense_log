import { useCallback, useEffect, useRef, useState } from "react";
import { api, liveSocketUrl } from "../../api/client";
import { StatCard } from "../../components/StatCard";
import { BarList } from "../../components/Charts/BarList";
import type { Overview, Summary } from "../../types";

const INTERVALS = [5, 10, 30, 60];

export function Dashboard() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [overview, setOverview] = useState<Overview | null>(null);
  const [auto, setAuto] = useState(true);
  const [intervalSec, setIntervalSec] = useState(5);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const inflight = useRef(false);

  const load = useCallback(async () => {
    if (inflight.current) return;
    inflight.current = true;
    setRefreshing(true);
    try {
      const [s, ov] = await Promise.all([api.summary(), api.overview()]);
      setSummary(s);
      setOverview(ov);
      setUpdatedAt(new Date());
    } catch {
      /* keep the previous values on transient errors */
    } finally {
      inflight.current = false;
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  // Periodic refresh so the dashboard stays up to date without manual reload.
  useEffect(() => {
    if (!auto) return;
    const id = window.setInterval(load, intervalSec * 1000);
    return () => window.clearInterval(id);
  }, [auto, intervalSec, load]);

  // Refresh promptly (debounced) whenever new events arrive over the live feed.
  useEffect(() => {
    if (!auto) return;
    let closed = false;
    let retry = 0;
    let timer = 0;
    let socket: WebSocket | null = null;
    const schedule = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(load, 3000);
    };
    const connect = () => {
      socket = new WebSocket(liveSocketUrl());
      socket.onmessage = schedule;
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        if (!closed) {
          retry = Math.min(retry + 1, 5);
          window.setTimeout(connect, 1000 * retry);
        }
      };
    };
    connect();
    return () => {
      closed = true;
      window.clearTimeout(timer);
      socket?.close();
    };
  }, [auto, load]);

  const countries = (overview?.countries ?? []).map((c) => ({
    value: c.value,
    label: `${c.name} (${c.value})`,
    count: c.count,
  }));

  return (
    <>
      <div className="topbar">
        <h2>
          Tableau de bord
          {auto && <span className={`status-dot ${refreshing ? "ok" : "unknown"}`} style={{ marginLeft: 8 }} />}
        </h2>
        <div className="filters">
          <span className="muted" style={{ fontSize: 12 }}>
            {updatedAt ? `Actualisé à ${updatedAt.toLocaleTimeString()}` : "…"}
          </span>
          <label className="muted" style={{ fontSize: 12 }}>
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> Temps réel
          </label>
          <select value={intervalSec} onChange={(e) => setIntervalSec(Number(e.target.value))}>
            {INTERVALS.map((value) => (
              <option key={value} value={value}>
                toutes les {value}s
              </option>
            ))}
          </select>
          <button onClick={load} disabled={refreshing}>
            {refreshing ? "…" : "Actualiser"}
          </button>
        </div>
      </div>
      <div className="cards">
        <StatCard label="Événements" value={summary?.total ?? 0} />
        <StatCard label="Bloqués" value={summary?.blocked ?? 0} />
        <StatCard label="Autorisés" value={summary?.passed ?? 0} />
        <StatCard label="Interfaces" value={summary?.interfaces ?? 0} />
      </div>
      <div className="grid-3">
        <BarList title="Pays sources" items={countries} flags />
        <BarList title="Principales IP sources externes" items={overview?.src_external ?? []} />
        <BarList title="Principales IP sources internes" items={overview?.src_internal ?? []} />
      </div>
      <div className="grid-3">
        <BarList title="Principales IP destinations externes" items={overview?.dst_external ?? []} />
        <BarList title="Principales IP destinations internes" items={overview?.dst_internal ?? []} />
        <BarList title="Principaux ports de destination" items={overview?.dst_ports ?? []} />
      </div>
      <div className="grid-2">
        <BarList title="Protocoles" items={overview?.protocols ?? []} />
        <BarList title="Principales règles" items={overview?.rules ?? []} />
      </div>
    </>
  );
}
