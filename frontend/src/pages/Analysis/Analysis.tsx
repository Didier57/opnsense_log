import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api } from "../../api/client";
import { StatCard } from "../../components/StatCard";
import { BarList } from "../../components/Charts/BarList";
import { TimeRangePicker } from "../../components/TimeRangePicker";
import { formatNumber } from "../../format";
import type { Summary, TopItem } from "../../types";

const DIMENSIONS: Record<string, { dimension: string; title: string }> = {
  sources: { dimension: "src_ip", title: "Principales sources" },
  destinations: { dimension: "dst_ip", title: "Principales destinations" },
  ports: { dimension: "dst_port", title: "Principaux ports de destination" },
  rules: { dimension: "rule_id", title: "Principales règles" },
  interfaces: { dimension: "interface", title: "Trafic par interface" },
  countries: { dimension: "country", title: "Trafic par pays" },
};

export function Analysis() {
  const { kind } = useParams();
  const [summary, setSummary] = useState<Summary | null>(null);
  const [items, setItems] = useState<TopItem[]>([]);
  const [range, setRange] = useState<{ start?: string; end?: string }>({});
  const [byProtocol, setByProtocol] = useState<TopItem[]>([]);
  const [byAction, setByAction] = useState<TopItem[]>([]);

  const load = (start?: string, end?: string) => {
    api.summary(start, end).then(setSummary).catch(() => undefined);
    api.top("protocol", start, end, 10).then((r) => setByProtocol(r.items)).catch(() => undefined);
    api.top("action", start, end, 10).then((r) => setByAction(r.items)).catch(() => undefined);
    if (kind === "countries") {
      api
        .countries(start, end, 25)
        .then((r) =>
          setItems(r.items.map((it) => ({ value: `${it.name} (${it.value})`, count: it.count }))),
        )
        .catch(() => undefined);
    } else if (kind && DIMENSIONS[kind]) {
      api.top(DIMENSIONS[kind].dimension, start, end, 25).then((r) => setItems(r.items)).catch(() => undefined);
    }
  };

  useEffect(() => {
    load(range.start, range.end);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [kind]);

  const detail = kind ? DIMENSIONS[kind] : undefined;
  if (kind && !detail) {
    return <p className="error">Vue d'analyse inconnue.</p>;
  }

  return (
    <>
      <div className="topbar">
        <h2>{detail ? detail.title : "Vue d'ensemble de l'analyse"}</h2>
      </div>
      <TimeRangePicker
        onApply={(start, end) => {
          setRange({ start, end });
          load(start, end);
        }}
      />
      {!detail && (
        <div className="cards">
          <StatCard label="Événements" value={summary?.total ?? 0} />
          <StatCard label="Bloqués" value={summary?.blocked ?? 0} />
          <StatCard label="Autorisés" value={summary?.passed ?? 0} />
          <StatCard label="Sources uniques" value={summary?.sources ?? 0} />
        </div>
      )}
      {summary && summary.total > 0 && (
        <p className="muted">
          PASS {((summary.passed / summary.total) * 100).toFixed(1)}% · BLOCK{" "}
          {((summary.blocked / summary.total) * 100).toFixed(1)}%
        </p>
      )}
      {detail ? (
        <BarList items={items} />
      ) : (
        <div className="grid-2">
          <BarList title="Protocoles" items={byProtocol} />
          <BarList title="Actions" items={byAction} />
        </div>
      )}
      {summary && (
        <p className="muted">Total des événements : {formatNumber(summary.total)}</p>
      )}
    </>
  );
}
