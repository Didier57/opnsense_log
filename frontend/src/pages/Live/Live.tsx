import { useEffect, useMemo, useRef, useState } from "react";
import { liveSocketUrl } from "../../api/client";
import { LogTable } from "../../components/LogTable/LogTable";
import { EventDetails } from "../../components/EventDetails/EventDetails";
import { QuickFilters, QUICK_FILTERS } from "../../components/Filters/QuickFilters";
import { AdvancedFilters } from "../../components/Filters/AdvancedFilters";
import { useInterfaceMap } from "../../hooks/useInterfaceMap";
import { useInterfaces, findInterfaceDevice } from "../../hooks/useInterfaces";
import { useRuleMap } from "../../hooks/useRuleMap";
import { eventMatches } from "../../filters";
import type { FirewallEvent, SearchClause } from "../../types";

const LIMITS = [500, 1000, 5000];

export function Live() {
  const [raw, setRaw] = useState<FirewallEvent[]>([]);
  const [paused, setPaused] = useState(false);
  const [connected, setConnected] = useState(false);
  const [limit, setLimit] = useState(1000);
  const [clauses, setClauses] = useState<SearchClause[]>([]);
  const [logic, setLogic] = useState("AND");
  const [selected, setSelected] = useState<FirewallEvent | null>(null);

  const pausedRef = useRef(paused);
  const limitRef = useRef(limit);
  const pendingRef = useRef<FirewallEvent[]>([]);
  const interfaceMap = useInterfaceMap();
  const interfaces = useInterfaces();
  const ruleMap = useRuleMap();

  pausedRef.current = paused;
  limitRef.current = limit;

  const lanDev = findInterfaceDevice(interfaces, "LAN");
  const wanDev = findInterfaceDevice(interfaces, "WAN");
  const quickList = [
    ...QUICK_FILTERS,
    ...(lanDev ? [{ label: "LAN", clause: { field: "interface", op: "eq", value: lanDev } as SearchClause }] : []),
    ...(wanDev ? [{ label: "WAN", clause: { field: "interface", op: "eq", value: wanDev } as SearchClause }] : []),
  ];

  useEffect(() => {
    let socket: WebSocket | null = null;
    let closed = false;
    let retry = 0;
    let reconnectTimer: number | null = null;

    const connect = () => {
      socket = new WebSocket(liveSocketUrl());
      socket.onopen = () => {
        setConnected(true);
        retry = 0;
      };
      socket.onmessage = (message) => {
        if (pausedRef.current) return;
        try {
          pendingRef.current.push(JSON.parse(message.data) as FirewallEvent);
        } catch {
          /* ignore malformed frames */
        }
      };
      socket.onerror = () => socket?.close();
      socket.onclose = () => {
        setConnected(false);
        if (closed) return;
        retry = Math.min(retry + 1, 6);
        reconnectTimer = window.setTimeout(connect, Math.min(15000, 500 * 2 ** retry));
      };
    };
    connect();

    // Coalesce incoming events and flush at a fixed pace so a burst of logs
    // cannot saturate the UI.
    const flushTimer = window.setInterval(() => {
      if (pendingRef.current.length === 0) return;
      const batch = pendingRef.current.reverse();
      pendingRef.current = [];
      setRaw((prev) => {
        const next = [...batch, ...prev];
        return next.length > limitRef.current ? next.slice(0, limitRef.current) : next;
      });
    }, 200);

    return () => {
      closed = true;
      window.clearInterval(flushTimer);
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, []);

  const events = useMemo(
    () => raw.filter((event) => eventMatches(event, clauses, logic)),
    [raw, clauses, logic],
  );

  const clearAll = () => {
    setClauses([]);
  };

  return (
    <>
      <div className="topbar">
        <h2>
          Temps réel <span className={`status-dot ${connected ? "ok" : "bad"}`} />
          <span className="muted" style={{ fontSize: 13 }}>
            {connected ? "connecté" : "déconnecté"}
          </span>
        </h2>
        <div className="filters">
          <button onClick={() => setPaused((p) => !p)} className={paused ? "active" : ""}>
            {paused ? "Reprendre" : "Pause"}
          </button>
          <button onClick={() => setRaw([])}>Vider</button>
          <button onClick={clearAll}>Réinitialiser les filtres</button>
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            {LIMITS.map((l) => (
              <option key={l} value={l}>
                derniers {l}
              </option>
            ))}
          </select>
        </div>
      </div>

      <QuickFilters active={clauses} onChange={setClauses} quickList={quickList} />
      <AdvancedFilters
        clauses={clauses}
        logic={logic}
        onLogicChange={setLogic}
        onChange={setClauses}
      />

      <div className="panel">
        <p className="muted">
          {events.length} événements affichés sur {raw.length} en mémoire
        </p>
        <LogTable
          events={events}
          onSelect={setSelected}
          interfaceMap={interfaceMap}
          ruleMap={ruleMap}
        />
      </div>
      <EventDetails
        event={selected}
        onClose={() => setSelected(null)}
        ruleDescription={selected ? ruleMap[selected.rule_id] : undefined}
      />
    </>
  );
}
