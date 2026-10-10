import { formatNumber } from "../../format";
import { CountryFlag } from "../CountryFlag";

interface Item {
  value: string | number | null;
  count: number;
  label?: string;
  passed?: number;
  blocked?: number;
}

const SEG_MIN_PCT = 8;

export function BarList({
  items,
  title,
  flags = false,
}: {
  items: Item[];
  title?: string;
  flags?: boolean;
}) {
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <div className="panel">
      {title && <h3 style={{ marginTop: 0 }}>{title}</h3>}
      {items.length === 0 && <p className="muted">Aucune donnée.</p>}
      {items.map((item, index) => {
        const empty = item.value === null || item.value === "";
        const text = item.label ?? (empty ? "(aucun)" : String(item.value));
        const widthPct = (item.count / max) * 100;
        const split = item.passed !== undefined && item.blocked !== undefined;
        let bar;
        if (split) {
          const passed = item.passed ?? 0;
          const blocked = item.blocked ?? 0;
          const total = item.count || passed + blocked || 1;
          const passPct = Math.round((passed / total) * 100);
          const blockPct = 100 - passPct;
          const tip = `${text} — PASS ${passPct}% (${formatNumber(passed)}) · BLOCK ${blockPct}% (${formatNumber(blocked)})`;
          bar = (
            <span className="bar bar-split" style={{ width: `${widthPct}%`, minWidth: 2 }} title={tip}>
              {passPct > 0 && (
                <span
                  className="seg seg-pass"
                  style={{ width: `${passPct}%` }}
                  title={tip}
                >
                  {widthPct * (passPct / 100) >= SEG_MIN_PCT ? `${passPct}%` : ""}
                </span>
              )}
              {blockPct > 0 && (
                <span
                  className="seg seg-block"
                  style={{ width: `${blockPct}%` }}
                  title={tip}
                >
                  {widthPct * (blockPct / 100) >= SEG_MIN_PCT ? `${blockPct}%` : ""}
                </span>
              )}
            </span>
          );
        } else {
          bar = (
            <span
              className="bar"
              style={{ width: `${widthPct}%`, minWidth: 2 }}
              title={`${text}: ${formatNumber(item.count)}`}
            />
          );
        }
        return (
          <div className="bar-row" key={`${item.value}-${index}`}>
            <span className="k mono" title={text}>
              {flags && !empty ? <CountryFlag code={String(item.value)} /> : null}
              {text}
            </span>
            <span className="bar-track">{bar}</span>
            <span className="n">{formatNumber(item.count)}</span>
          </div>
        );
      })}
    </div>
  );
}
