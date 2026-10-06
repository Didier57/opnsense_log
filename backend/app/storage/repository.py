"""Repository layer: batch inserts, historical search and statistics."""
from __future__ import annotations

from datetime import datetime, timezone

from ..parser.models import FirewallEvent
from .database import _EVENT_COLUMNS, Database, get_database

_PLACEHOLDERS = ", ".join("?" for _ in _EVENT_COLUMNS)
_QUOTED_COLS = ", ".join(f'"{c}"' for c in _EVENT_COLUMNS)
_INSERT_SQL = (
    f"INSERT INTO events ({_QUOTED_COLS}) VALUES ({_PLACEHOLDERS})"
)

# Only these fields may be used in a search filter (SQL injection protection).
# Values are quoted identifiers so reserved words such as "offset" are safe.
FILTER_FIELDS: dict[str, str] = {
    "event_time": '"event_time"',
    "rule_id": '"rule_id"',
    "rule_number": '"rule_number"',
    "interface": '"interface"',
    "reason": '"reason"',
    "action": '"action"',
    "direction": '"direction"',
    "ip_version": '"ip_version"',
    "protocol": '"protocol"',
    "src_ip": '"src_ip"',
    "dst_ip": '"dst_ip"',
    "src_port": '"src_port"',
    "dst_port": '"dst_port"',
    "hostname": '"hostname"',
    "tcp_flags": '"tcp_flags"',
    "length": '"length"',
    "flags": '"flags"',
    "raw": '"raw"',
}

ALLOWED_OPS = {"eq", "ne", "contains", "not_contains", "regex", "in", "gt", "lt", "gte", "lte"}


def _event_row(event: FirewallEvent) -> tuple:
    row = event.to_row()
    return tuple(row.get(col) for col in _EVENT_COLUMNS)


class EventRepository:
    def __init__(self, db: Database | None = None) -> None:
        # Opened lazily: constructing the repository (e.g. from the syslog server
        # singleton at import time) must not block on opening a large DuckDB file.
        self._db = db

    @property
    def db(self) -> Database:
        if self._db is None:
            self._db = get_database()
        return self._db

    # ------------------------------------------------------------------ write
    def insert_events(self, events: list[FirewallEvent]) -> int:
        if not events:
            return 0
        rows = [_event_row(e) for e in events]
        self.db.executemany_write(_INSERT_SQL, rows)
        return len(rows)

    def delete_older_than(self, cutoff: datetime) -> int:
        result = self.db.execute_write(
            "DELETE FROM events WHERE event_time < ? RETURNING 1", [cutoff]
        )
        rows = result.fetchall()
        return len(rows)

    def count(self) -> int:
        return self.db.execute_read("SELECT COUNT(*) FROM events").fetchone()[0]

    # ---------------------------------------------------------------- search
    @staticmethod
    def _build_clause(clause: dict) -> tuple[str, list]:
        field = clause.get("field")
        op = clause.get("op", "eq")
        value = clause.get("value")
        if field not in FILTER_FIELDS:
            raise ValueError(f"invalid filter field: {field}")
        if op not in ALLOWED_OPS:
            raise ValueError(f"invalid operator: {op}")
        col = FILTER_FIELDS[field]

        if op == "eq":
            return f"{col} = ?", [value]
        if op == "ne":
            return f"{col} <> ?", [value]
        if op == "contains":
            return f"{col} ILIKE ?", [f"%{value}%"]
        if op == "not_contains":
            return f"({col} IS NULL OR {col} NOT ILIKE ?)", [f"%{value}%"]
        if op == "regex":
            return f"regexp_matches({col}, ?)", [value]
        if op == "gt":
            return f"{col} > ?", [value]
        if op == "lt":
            return f"{col} < ?", [value]
        if op == "gte":
            return f"{col} >= ?", [value]
        if op == "lte":
            return f"{col} <= ?", [value]
        if op == "in":
            values = value if isinstance(value, list) else [value]
            marks = ", ".join("?" for _ in values)
            return f"{col} IN ({marks})", list(values)
        raise ValueError(f"unsupported operator: {op}")

    def build_where(
        self,
        clauses: list[dict] | None,
        logic: str = "AND",
        start: datetime | None = None,
        end: datetime | None = None,
        extra: list[str] | None = None,
    ) -> tuple[str, list]:
        fragments: list[str] = list(extra or [])
        params: list = []
        if start is not None:
            fragments.append("event_time >= ?")
            params.append(start)
        if end is not None:
            fragments.append("event_time <= ?")
            params.append(end)
        for clause in clauses or []:
            frag, frag_params = self._build_clause(clause)
            fragments.append(frag)
            params.extend(frag_params)
        if not fragments:
            return "", []
        joiner = " OR " if logic.upper() == "OR" else " AND "
        return " WHERE " + joiner.join(f"({f})" for f in fragments), params

    def search(
        self,
        clauses: list[dict] | None = None,
        logic: str = "AND",
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "event_time",
        order_dir: str = "desc",
    ) -> dict:
        limit = max(1, min(limit, 5000))
        offset = max(0, offset)
        order_col = FILTER_FIELDS.get(order_by, "event_time")
        order_dir = "ASC" if order_dir.lower() == "asc" else "DESC"

        where, params = self.build_where(clauses, logic, start, end)
        total = self.db.execute_read(
            f"SELECT COUNT(*) FROM events{where}", params
        ).fetchone()[0]
        rows = self.db.execute_read(
            f"SELECT {_QUOTED_COLS} FROM events{where} "
            f"ORDER BY {order_col} {order_dir} LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
        events = [dict(zip(_EVENT_COLUMNS, row)) for row in rows]
        return {"total": total, "limit": limit, "offset": offset, "events": events}

    # ------------------------------------------------------------- statistics
    def summary(self, start: datetime | None = None, end: datetime | None = None) -> dict:
        where, params = self.build_where(None, start=start, end=end)
        row = self.db.execute_read(
            f"""
            SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE lower("action") = 'pass') AS passed,
                COUNT(*) FILTER (WHERE lower("action") IN ('block', 'reject')) AS blocked,
                COUNT(DISTINCT "interface") AS interfaces,
                COUNT(DISTINCT "src_ip") AS sources
            FROM events{where}
            """,
            params,
        ).fetchone()
        keys = ["total", "passed", "blocked", "interfaces", "sources"]
        return dict(zip(keys, row))

    def _top(self, expr: str, where: str, params: list, limit: int = 10) -> list[dict]:
        rows = self.db.execute_read(
            f"SELECT {expr} AS value, COUNT(*) AS count FROM events{where} "
            f"GROUP BY 1 ORDER BY count DESC LIMIT ?",
            [*params, limit],
        ).fetchall()
        return [{"value": r[0], "count": r[1]} for r in rows]

    def top_values(
        self,
        dimension: str,
        start: datetime | None = None,
        end: datetime | None = None,
        limit: int = 10,
    ) -> list[dict]:
        columns = {
            "src_ip": '"src_ip"',
            "dst_ip": '"dst_ip"',
            "dst_port": '"dst_port"',
            "src_port": '"src_port"',
            "protocol": '"protocol"',
            "interface": '"interface"',
            "rule_id": '"rule_id"',
            "action": '"action"',
        }
        col = columns.get(dimension)
        if col is None:
            raise ValueError(f"invalid dimension: {dimension}")
        where, params = self.build_where(None, start=start, end=end)
        return self._top(col, where, params, limit)

    def timeseries(
        self,
        start: datetime | None = None,
        end: datetime | None = None,
        bucket: str = "minute",
    ) -> list[dict]:
        buckets = {
            "minute": "date_trunc('minute', \"event_time\")",
            "hour": "date_trunc('hour', \"event_time\")",
            "day": "date_trunc('day', \"event_time\")",
        }
        expr = buckets.get(bucket, buckets["minute"])
        where, params = self.build_where(None, start=start, end=end)
        rows = self.db.execute_read(
            f"""
            SELECT {expr} AS bucket,
                   COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE lower("action") IN ('block', 'reject')) AS blocked
            FROM events{where}
            GROUP BY 1 ORDER BY 1
            """,
            params,
        ).fetchall()
        return [{"bucket": r[0], "total": r[1], "blocked": r[2]} for r in rows]
