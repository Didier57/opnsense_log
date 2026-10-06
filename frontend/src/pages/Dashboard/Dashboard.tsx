import { useEffect, useState } from "react";
import { api } from "../../api/client";
import { StatCard } from "../../components/StatCard";
import { LineChart } from "../../components/Charts/LineChart";
import { BarList } from "../../components/Charts/BarList";
import type { Summary, TimeseriesPoint, TopItem } from "../../types";

export function Dashboard() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [points, setPoints] = useState<TimeseriesPoint[]>([]);
  const [topSrc, setTopSrc] = useState<TopItem[]>([]);
  const [topPorts, setTopPorts] = useState<TopItem[]>([]);
  const [topRules, setTopRules] = useState<TopItem[]>([]);

  useEffect(() => {
    api.summary().then(setSummary).catch(() => undefined);
    api.timeseries(undefined, undefined, "hour").then((r) => setPoints(r.points)).catch(() => undefined);
    api.top("src_ip", undefined, undefined, 10).then((r) => setTopSrc(r.items)).catch(() => undefined);
    api.top("dst_port", undefined, undefined, 10).then((r) => setTopPorts(r.items)).catch(() => undefined);
    api.top("rule_id", undefined, undefined, 10).then((r) => setTopRules(r.items)).catch(() => undefined);
  }, []);

  return (
    <>
      <div className="topbar">
        <h2>Tableau de bord</h2>
      </div>
      <div className="cards">
        <StatCard label="Événements" value={summary?.total ?? 0} />
        <StatCard label="Bloqués" value={summary?.blocked ?? 0} />
        <StatCard label="Autorisés" value={summary?.passed ?? 0} />
        <StatCard label="Interfaces" value={summary?.interfaces ?? 0} />
      </div>
      <div className="panel">
        <h3 style={{ marginTop: 0 }}>Événements dans le temps</h3>
        <LineChart points={points} />
      </div>
      <div className="grid-3">
        <BarList title="Principales IP sources" items={topSrc} />
        <BarList title="Principaux ports de destination" items={topPorts} />
        <BarList title="Principales règles" items={topRules} />
      </div>
    </>
  );
}
