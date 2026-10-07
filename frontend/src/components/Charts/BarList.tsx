import { formatNumber } from "../../format";
import { CountryFlag } from "../CountryFlag";

interface Item {
  value: string | number | null;
  count: number;
  label?: string;
}

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
        return (
          <div className="bar-row" key={`${item.value}-${index}`}>
            <span className="k mono" title={text}>
              {flags && !empty ? <CountryFlag code={String(item.value)} /> : null}
              {text}
            </span>
            <span className="bar" style={{ width: `${(item.count / max) * 100}%`, minWidth: 2 }} />
            <span className="n">{formatNumber(item.count)}</span>
          </div>
        );
      })}
    </div>
  );
}
