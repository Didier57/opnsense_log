import { useEffect, useRef, useState } from "react";
import { liveSocketUrl } from "../../api/client";
import { LogTable } from "../../components/LogTable/LogTable";
import { EventDetails } from "../../components/EventDetails/EventDetails";
import { QuickFilters } from "../../components/Filters/QuickFilters";
import { useInterfaceMap } from "../../hooks/useInterfaceMap";
import type { FirewallEvent, SearchClause } from "../../types";

const LIMITS = [500, 1000, 5000];

function matches(event: FirewallEvent, clauses: SearchClause[]): boolean {
  return clauses.every((clause) => {
    const value = event[clause.field];
    if (clause.op === "eq") {
      if (typeof clause.value === "number") return Number(value) === clause.value;
      return String(value ?? "").toLowerCase() === String(clause.value).toLowerCase();
    }
    if (clause.op === "contains") {
      return String(value ?? "").toLowerCase().includes(String(clause.value).toLowerCase());
    }
    return true;
  });
}

export function Live() {
  const [events, setEvents] = useState<FirewallEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const [connected, setConnected] = useState(false);
  const [limit, setLimit] = useState(1000);
  const [clauses, setClauses] = useState<SearchClause[]>([]);
  const [selected, setSelected] = useState<FirewallEvent | null>(null);
  const pausedRef = useRef(paused);
  const limitRef = useRef(limit);
  const clausesRef = useRef(clauses);
  const interfaceMap = useInterfaceMap();

  pausedRef.current = paused;
  limitRef.current = limit;
  clausesRef.current = clauses;

  useEffect(() => {
    const socket = new WebSocket(liveSocketUrl());
    socket.onopen = () => setConnected(true);
    socket.onclose = () => setConnected(false);
    socket.onerror = () => setConnected(false);
    socket.onmessage = (message) => {
      if (pausedRef.current) return;
      const event = JSON.parse(message.data) as FirewallEvent;
      if (!matches(event, clausesRef.current)) return;
      setEvents((prev) => {
        const next = [event, ...prev];
        return next.length > limitRef.current ? next.slice(0, limitRef.current) : next;
      });
    };
    return () => socket.close();
  }, []);

  return (
    <>
      <div className="topbar">
        <h2>
          Live view{" "}
          <span className={`status-dot ${connected ? "ok" : "bad"}`} />
          <span className="muted" style={{ fontSize: 13 }}>
            {connected ? "connected" : "disconnected"}
          </span>
        </h2>
        <div className="filters">
          <button onClick={() => setPaused((p) => !p)} className={paused ? "active" : ""}>
            {paused ? "Resume" : "Pause"}
          </button>
          <button onClick={() => setEvents([])}>Clear</button>
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            {LIMITS.map((l) => (
              <option key={l} value={l}>
                last {l}
              </option>
            ))}
          </select>
        </div>
      </div>
      <QuickFilters active={clauses} onChange={setClauses} />
      <div className="panel">
        <p className="muted">{events.length} events buffered</p>
        <LogTable events={events} onSelect={setSelected} interfaceMap={interfaceMap} />
      </div>
      <EventDetails event={selected} onClose={() => setSelected(null)} />
    </>
  );
}
