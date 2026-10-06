import { formatNumber } from "../../format";

interface Item {
  value: string | number | null;
  count: number;
}

export function BarList({ items, title }: { items: Item[]; title?: string }) {
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <div className="panel">
      {title && <h3 style={{ marginTop: 0 }}>{title}</h3>}
      {items.length === 0 && <p className="muted">Aucune donnée.</p>}
      {items.map((item, index) => (
        <div className="bar-row" key={`${item.value}-${index}`}>
          <span className="k mono" title={String(item.value)}>
            {item.value === null || item.value === "" ? "(aucun)" : String(item.value)}
          </span>
          <span className="bar" style={{ width: `${(item.count / max) * 100}%`, minWidth: 2 }} />
          <span className="n">{formatNumber(item.count)}</span>
        </div>
      ))}
    </div>
  );
}
