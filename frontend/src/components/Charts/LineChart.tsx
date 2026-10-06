interface Point {
  bucket: string;
  total: number;
  blocked: number;
}

export function LineChart({ points, height = 160 }: { points: Point[]; height?: number }) {
  if (points.length === 0) {
    return <p className="muted">Aucune donnée.</p>;
  }
  const width = 760;
  const max = Math.max(1, ...points.map((p) => p.total));
  const step = points.length > 1 ? width / (points.length - 1) : width;

  const path = (key: "total" | "blocked") =>
    points
      .map((point, index) => {
        const x = index * step;
        const y = height - (point[key] / max) * height;
        return `${index === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(" ");

  return (
    <div className="panel">
      <svg viewBox={`0 0 ${width} ${height}`} style={{ width: "100%", height }}>
        <path d={path("total")} fill="none" stroke="#3b82f6" strokeWidth={2} />
        <path d={path("blocked")} fill="none" stroke="#d9534f" strokeWidth={2} />
      </svg>
      <div className="muted" style={{ fontSize: 12 }}>
        <span style={{ color: "#3b82f6" }}>● total</span>{" "}
        <span style={{ color: "#d9534f" }}>● bloqués</span> ({points.length} points)
      </div>
    </div>
  );
}
