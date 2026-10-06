import { useEffect, useMemo, useRef, useState } from "react";
import { liveSocketUrl } from "../../api/client";
import { LogTable } from "../../components/LogTable/LogTable";
import { EventDetails } from "../../components/EventDetails/EventDetails";
import { QuickFilters, QUICK_FILTERS } from "../../components/Filters/QuickFilters";
import { AdvancedFilters } from "../../components/Filters/AdvancedFilters";
import { TimeRangePicker } from "../../components/TimeRangePicker";
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
  const [range, setRange] = useState<{ start?: string; end?: string }>({});
  const [selected, setSelected] = useState<FirewallEvent | null>(null);

  const pausedRef = useRef(paused);
  const limitRef = useRef(limit);
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
    const socket = new WebSocket(liveSocketUrl());
    socket.onopen = () => setConnected(true);
    socket.onclose = () => setConnected(false);
    socket.onerror = () => setConnected(false);
    socket.onmessage = (message) => {
      if (pausedRef.current) return;
      const event = JSON.parse(message.data) as FirewallEvent;
      setRaw((prev) => {
        const next = [event, ...prev];
        return next.length > limitRef.current ? next.slice(0, limitRef.current) : next;
      });
    };
    return () => socket.close();
  }, []);

  const events = useMemo(
    () => raw.filter((event) => eventMatches(event, clauses, logic, range.start, range.end)),
    [raw, clauses, logic, range],
  );

  const clearAll = () => {
    setClauses([]);
    setRange({});
  };

  return (
    <>
      <div className="topbar">
        <h2>
          Live view <span className={`status-dot ${connected ? "ok" : "bad"}`} />
          <span className="muted" style={{ fontSize: 13 }}>
            {connected ? "connected" : "disconnected"}
          </span>
        </h2>
        <div className="filters">
          <button onClick={() => setPaused((p) => !p)} className={paused ? "active" : ""}>
            {paused ? "Resume" : "Pause"}
          </button>
          <button onClick={() => setRaw([])}>Clear</button>
          <button onClick={clearAll}>Reset filters</button>
          <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
            {LIMITS.map((l) => (
              <option key={l} value={l}>
                last {l}
              </option>
            ))}
          </select>
        </div>
      </div>

      <TimeRangePicker onApply={(start, end) => setRange({ start, end })} />
      <QuickFilters active={clauses} onChange={setClauses} quickList={quickList} />
      <AdvancedFilters
        clauses={clauses}
        logic={logic}
        onLogicChange={setLogic}
        onChange={setClauses}
      />

      <div className="panel">
        <p className="muted">
          {events.length} events shown of {raw.length} buffered
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
