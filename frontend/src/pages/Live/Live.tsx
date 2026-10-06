import { useEffect, useMemo, useRef, useState } from "react";
import { api, liveSocketUrl } from "../../api/client";
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
  const [lookupEnabled, setLookupEnabled] = useState(false);
  const [hostnameMap, setHostnameMap] = useState<Record<string, string>>({});

  const pausedRef = useRef(paused);
  const limitRef = useRef(limit);
  const pendingRef = useRef<FirewallEvent[]>([]);
  const eventsRef = useRef<FirewallEvent[]>([]);
  const hostnameMapRef = useRef(hostnameMap);
  const interfaceMap = useInterfaceMap();
  const interfaces = useInterfaces();
  const ruleMap = useRuleMap();

  pausedRef.current = paused;
  limitRef.current = limit;
  hostnameMapRef.current = hostnameMap;

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
  eventsRef.current = events;

  // Resolve hostnames for the currently displayed IPs, at a slow pace and only
  // for IPs we have not seen yet, so the background lookups never compete with
  // the live stream.
  useEffect(() => {
    if (!lookupEnabled) return;
    const timer = window.setInterval(() => {
      const known = hostnameMapRef.current;
      const ips = new Set<string>();
      for (const event of eventsRef.current) {
        if (event.src_ip) ips.add(event.src_ip);
        if (event.dst_ip) ips.add(event.dst_ip);
      }
      const pending = [...ips].filter((ip) => !(ip in known)).slice(0, 200);
      if (pending.length === 0) return;
      api
        .lookupHostnames(pending)
        .then((res) => {
          const found: Record<string, string> = {};
          Object.entries(res.items).forEach(([ip, name]) => {
            if (name) found[ip] = name;
          });
          if (Object.keys(found).length > 0) {
            setHostnameMap((prev) => ({ ...prev, ...found }));
          }
        })
        .catch(() => undefined);
    }, 2000);
    return () => window.clearInterval(timer);
  }, [lookupEnabled]);

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
          <label className="muted" style={{ fontSize: 13, display: "flex", alignItems: "center", gap: 6 }}>
            <input
              type="checkbox"
              checked={lookupEnabled}
              onChange={(e) => setLookupEnabled(e.target.checked)}
            />
            Rechercher les noms d'hôtes
          </label>
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
          hostnameMap={lookupEnabled ? hostnameMap : {}}
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
