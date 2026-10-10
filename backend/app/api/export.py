"""Export of filtered results to CSV / JSON."""
from __future__ import annotations

import csv
import io
import json
import uuid
from collections.abc import Iterator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from ..geoip.resolver import geo_resolver
from ..instances import resolve_instance_id
from ..storage.database import _EVENT_COLUMNS, get_database
from ..storage.repository import EventRepository
from .deps import InstanceId, require_user
from .schemas import SearchRequest

router = APIRouter(prefix="/api/export", tags=["export"])

_QUOTED_COLS = ", ".join(f'"{c}"' for c in _EVENT_COLUMNS)
_CHUNK = 5000


def _country_ips(payload: SearchRequest, instance: str | None = None) -> list[str] | None:
    if not payload.countries:
        return None
    wanted = {code.strip().upper() for code in payload.countries if code.strip()}
    if not wanted:
        return None
    repo = EventRepository(instance_id=instance)
    candidates = set(repo.distinct_ips("src_ip", payload.start, payload.end))
    candidates.update(repo.distinct_ips("dst_ip", payload.start, payload.end))
    resolved = geo_resolver.resolve(list(candidates), instance_id=instance)
    return [ip for ip, info in resolved.items() if info and str(info.get("country", "")).upper() in wanted]


def _where_for(payload: SearchRequest, instance: str | None = None) -> tuple[str, list]:
    repo = EventRepository(instance_id=instance)
    clauses = [c.model_dump() for c in payload.clauses]
    where, params = repo.build_where(clauses, payload.logic, payload.start, payload.end)
    country_ips = _country_ips(payload, instance)
    if country_ips is not None:
        if not country_ips:
            where += (" AND " if where else " WHERE ") + "1 = 0"
        else:
            marks = ", ".join("?" for _ in country_ips)
            where += (" AND " if where else " WHERE ") + f'("src_ip" IN ({marks}) OR "dst_ip" IN ({marks}))'
            params = [*params, *country_ips, *country_ips]
    return where, params


def _iter_rows(payload: SearchRequest, instance: str | None = None) -> Iterator[list]:
    where, params = _where_for(payload, instance)
    db = get_database(resolve_instance_id(instance))
    offset = 0
    while True:
        rows = db.execute_read(
            f"SELECT {_QUOTED_COLS} FROM events{where} "
            f"ORDER BY event_time DESC LIMIT ? OFFSET ?",
            [*params, _CHUNK, offset],
        ).fetchall()
        if not rows:
            break
        for row in rows:
            yield list(row)
        if len(rows) < _CHUNK:
            break
        offset += _CHUNK


def _csv_stream(payload: SearchRequest, instance: str | None = None) -> Iterator[str]:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(_EVENT_COLUMNS)
    yield buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)
    for row in _iter_rows(payload, instance):
        writer.writerow(row)
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)


def _json_stream(payload: SearchRequest, instance: str | None = None) -> Iterator[str]:
    yield "["
    first = True
    for row in _iter_rows(payload, instance):
        record = {col: (val.isoformat() if hasattr(val, "isoformat") else val)
                  for col, val in zip(_EVENT_COLUMNS, row)}
        prefix = "" if first else ","
        first = False
        yield prefix + json.dumps(record, default=str)
    yield "]"


@router.post("")
def export(
    payload: SearchRequest,
    fmt: str = "csv",
    instance: str | None = InstanceId,
    user: str = Depends(require_user),
):
    fmt = fmt.lower()
    if fmt == "csv":
        return StreamingResponse(
            _csv_stream(payload, instance),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="events.csv"'},
        )
    if fmt == "json":
        return StreamingResponse(
            _json_stream(payload, instance),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="events.json"'},
        )
    raise HTTPException(status_code=400, detail=f"unsupported format: {fmt}")


@router.post("/async")
def export_async(
    payload: SearchRequest,
    fmt: str = "csv",
    instance: str | None = InstanceId,
    user: str = Depends(require_user),
) -> dict:
    """Placeholder for asynchronous large exports (returns a job id)."""
    return {"job_id": str(uuid.uuid4()), "status": "not_implemented", "format": fmt}
