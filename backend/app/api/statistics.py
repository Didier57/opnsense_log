"""Statistics and analytics endpoints."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query

from ..storage.repository import EventRepository
from .deps import require_user

router = APIRouter(prefix="/api/statistics", tags=["statistics"])
repo = EventRepository()


@router.get("/summary")
def summary(
    start: datetime | None = None,
    end: datetime | None = None,
    user: str = Depends(require_user),
) -> dict:
    return repo.summary(start=start, end=end)


@router.get("/top/{dimension}")
def top(
    dimension: str,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = Query(10, ge=1, le=100),
    user: str = Depends(require_user),
) -> dict:
    try:
        return {"dimension": dimension, "items": repo.top_values(dimension, start, end, limit)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/timeseries")
def timeseries(
    start: datetime | None = None,
    end: datetime | None = None,
    bucket: str = "minute",
    user: str = Depends(require_user),
) -> dict:
    return {"bucket": bucket, "points": repo.timeseries(start=start, end=end, bucket=bucket)}
