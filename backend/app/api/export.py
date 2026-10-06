"""Export of filtered results to CSV / JSON / Parquet."""
from __future__ import annotations

import csv
import io
import json
import tempfile
import uuid
from collections.abc import Iterator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from ..storage.database import _EVENT_COLUMNS, get_database
from ..storage.repository import EventRepository
from .deps import require_user
from .schemas import SearchRequest

router = APIRouter(prefix="/api/export", tags=["export"])
repo = EventRepository()

_QUOTED_COLS = ", ".join(f'"{c}"' for c in _EVENT_COLUMNS)
_CHUNK = 5000


def _iter_rows(payload: SearchRequest) -> Iterator[list]:
    clauses = [c.model_dump() for c in payload.clauses]
    where, params = repo.build_where(clauses, payload.logic, payload.start, payload.end)
    db = get_database()
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


def _csv_stream(payload: SearchRequest) -> Iterator[str]:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(_EVENT_COLUMNS)
    yield buffer.getvalue()
    buffer.seek(0)
    buffer.truncate(0)
    for row in _iter_rows(payload):
        writer.writerow(row)
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate(0)


def _json_stream(payload: SearchRequest) -> Iterator[str]:
    yield "["
    first = True
    for row in _iter_rows(payload):
        record = {col: (val.isoformat() if hasattr(val, "isoformat") else val)
                  for col, val in zip(_EVENT_COLUMNS, row)}
        prefix = "" if first else ","
        first = False
        yield prefix + json.dumps(record, default=str)
    yield "]"


@router.post("")
def export(payload: SearchRequest, fmt: str = "csv", user: str = Depends(require_user)):
    fmt = fmt.lower()
    if fmt == "csv":
        return StreamingResponse(
            _csv_stream(payload),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="events.csv"'},
        )
    if fmt == "json":
        return StreamingResponse(
            _json_stream(payload),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="events.json"'},
        )
    if fmt == "parquet":
        clauses = [c.model_dump() for c in payload.clauses]
        where, params = repo.build_where(clauses, payload.logic, payload.start, payload.end)
        out = tempfile.NamedTemporaryFile(delete=False, suffix=".parquet")
        out.close()
        db = get_database()
        db.execute_write(
            f"COPY (SELECT {_QUOTED_COLS} FROM events{where} ORDER BY event_time DESC) "
            f"TO '{out.name}' (FORMAT PARQUET)",
            params,
        )
        return StreamingResponse(
            open(out.name, "rb"),
            media_type="application/octet-stream",
            headers={"Content-Disposition": 'attachment; filename="events.parquet"'},
        )
    raise HTTPException(status_code=400, detail=f"unsupported format: {fmt}")


@router.post("/async")
def export_async(payload: SearchRequest, fmt: str = "csv", user: str = Depends(require_user)) -> dict:
    """Placeholder for asynchronous large exports (returns a job id)."""
    return {"job_id": str(uuid.uuid4()), "status": "not_implemented", "format": fmt}
