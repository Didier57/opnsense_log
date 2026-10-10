"""Statistics and analytics endpoints."""
from __future__ import annotations

import ipaddress
import logging
import time
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query

from ..geoip.resolver import geo_resolver
from ..storage.repository import EventRepository
from .deps import InstanceId, require_user

logger = logging.getLogger("api.statistics")

router = APIRouter(prefix="/api/statistics", tags=["statistics"])


def _note(name: str, started: float) -> None:
    """Warn when a statistics query is slow, to help diagnose regressions."""
    elapsed = time.perf_counter() - started
    if elapsed >= 2.0:
        logger.warning("statistics.%s slow: %.1fs", name, elapsed)


@router.get("/summary")
def summary(
    start: datetime | None = None,
    end: datetime | None = None,
    instance: str | None = InstanceId,
    user: str = Depends(require_user),
) -> dict:
    repo = EventRepository(instance_id=instance)
    started = time.perf_counter()
    result = repo.summary(start=start, end=end)
    _note("summary", started)
    return result


@router.get("/top/{dimension}")
def top(
    dimension: str,
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = Query(10, ge=1, le=100),
    instance: str | None = InstanceId,
    user: str = Depends(require_user),
) -> dict:
    repo = EventRepository(instance_id=instance)
    started = time.perf_counter()
    try:
        items = repo.top_values(dimension, start, end, limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    _note(f"top.{dimension}", started)
    return {"dimension": dimension, "items": items}


def _aggregate_countries(
    items: list[dict],
    limit: int,
    instance: str | None = None,
    blocked_counts: dict[str, int] | None = None,
    sort_by: str = "count",
) -> list[dict]:
    resolved = geo_resolver.resolve(
        [item["value"] for item in items if item.get("value")], instance_id=instance
    )
    totals: dict[str, dict] = {}
    for item in items:
        info = resolved.get(item["value"]) if item.get("value") else None
        if not info:
            continue
        code = info["country"]
        entry = totals.setdefault(
            code, {"value": code, "name": info.get("name") or code, "count": 0}
        )
        entry["count"] += item["count"]
        if blocked_counts is not None:
            blocked = blocked_counts.get(item["value"], 0)
            entry["blocked"] = entry.get("blocked", 0) + blocked
            entry["passed"] = entry.get("passed", 0) + max(0, item["count"] - blocked)
    return sorted(totals.values(), key=lambda entry: entry.get(sort_by, 0), reverse=True)[:limit]


@router.get("/countries")
def countries(
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = Query(20, ge=1, le=100),
    instance: str | None = InstanceId,
    user: str = Depends(require_user),
) -> dict:
    """Top countries of the source IPs (GeoIP resolved).

    Each item also carries the ``passed``/``blocked`` split so the UI can colour
    the bar by outcome.
    """
    repo = EventRepository(instance_id=instance)
    started = time.perf_counter()
    src = repo.top_with_blocked("src_ip", start, end, 500)
    blocked_counts = {item["value"]: item["blocked"] for item in src if item.get("value")}
    items = _aggregate_countries(src, limit, instance, blocked_counts)
    _note("countries", started)
    return {"items": items}


def _is_internal(value: object) -> bool:
    try:
        addr = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


@router.get("/overview")
def overview(
    start: datetime | None = None,
    end: datetime | None = None,
    instance: str | None = InstanceId,
    user: str = Depends(require_user),
) -> dict:
    """Dashboard overview: top countries plus top internal/external IPs."""
    repo = EventRepository(instance_id=instance)
    started = time.perf_counter()
    src = repo.top_with_blocked("src_ip", start, end, 500)
    _note("overview.src", started)
    marker = time.perf_counter()
    dst = repo.top_values("dst_ip", start, end, 500)
    _note("overview.dst", marker)
    blocked_counts = {item["value"]: item["blocked"] for item in src if item.get("value")}
    src_external = [item for item in src if not _is_internal(item.get("value"))][:10]
    src_internal = [item for item in src if _is_internal(item.get("value"))][:10]
    dst_external = [item for item in dst if not _is_internal(item.get("value"))][:10]
    dst_internal = [item for item in dst if _is_internal(item.get("value"))][:10]

    marker = time.perf_counter()
    countries = _aggregate_countries(src, 10, instance, blocked_counts)
    _note("overview.countries", marker)
    marker = time.perf_counter()
    dst_countries = _aggregate_countries(dst, 10, instance)
    _note("overview.dst_countries", marker)
    marker = time.perf_counter()
    countries_blocked = _aggregate_countries(src, 10, instance, blocked_counts, sort_by="blocked")
    _note("overview.countries_blocked", marker)
    marker = time.perf_counter()
    result = {
        "countries": countries,
        "dst_countries": dst_countries,
        "countries_blocked": countries_blocked,
        "src_external": src_external,
        "src_internal": src_internal,
        "dst_external": dst_external,
        "dst_internal": dst_internal,
        "blocked_ips": sorted(
            (
                {"value": item["value"], "count": item["blocked"]}
                for item in src
                if item.get("blocked")
            ),
            key=lambda entry: entry["count"],
            reverse=True,
        )[:10],
        "directions": repo.top_values("direction", start, end, 10),
        "protocols": repo.top_values("protocol", start, end, 10),
    }
    _note("overview.tops", marker)
    _note("overview", started)
    return result


@router.get("/timeseries")
def timeseries(
    start: datetime | None = None,
    end: datetime | None = None,
    bucket: str = "minute",
    instance: str | None = InstanceId,
    user: str = Depends(require_user),
) -> dict:
    repo = EventRepository(instance_id=instance)
    started = time.perf_counter()
    points = repo.timeseries(start=start, end=end, bucket=bucket)
    _note("timeseries", started)
    return {"bucket": bucket, "points": points}
