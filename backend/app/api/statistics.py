"""Statistics and analytics endpoints."""
from __future__ import annotations

import ipaddress
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query

from ..geoip.resolver import geo_resolver
from ..storage.repository import EventRepository
from .deps import InstanceId, require_user

router = APIRouter(prefix="/api/statistics", tags=["statistics"])


@router.get("/summary")
def summary(
    start: datetime | None = None,
    end: datetime | None = None,
    instance: str | None = InstanceId,
    user: str = Depends(require_user),
) -> dict:
    repo = EventRepository(instance_id=instance)
    return repo.summary(start=start, end=end)


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
    try:
        return {"dimension": dimension, "items": repo.top_values(dimension, start, end, limit)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def _aggregate_countries(items: list[dict], limit: int, instance: str | None = None) -> list[dict]:
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
    return sorted(totals.values(), key=lambda entry: entry["count"], reverse=True)[:limit]


@router.get("/countries")
def countries(
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = Query(20, ge=1, le=100),
    instance: str | None = InstanceId,
    user: str = Depends(require_user),
) -> dict:
    """Top countries of the source IPs (GeoIP resolved)."""
    repo = EventRepository(instance_id=instance)
    ips = repo.top_values("src_ip", start, end, 500)
    return {"items": _aggregate_countries(ips, limit, instance)}


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
    src = repo.top_values("src_ip", start, end, 500)
    dst = repo.top_values("dst_ip", start, end, 500)
    blocked = repo.top_values("src_ip", start, end, 500, actions=["block", "reject"])
    src_external = [item for item in src if not _is_internal(item.get("value"))][:10]
    src_internal = [item for item in src if _is_internal(item.get("value"))][:10]
    dst_external = [item for item in dst if not _is_internal(item.get("value"))][:10]
    dst_internal = [item for item in dst if _is_internal(item.get("value"))][:10]

    return {
        "countries": _aggregate_countries(src, 10, instance),
        "dst_countries": _aggregate_countries(dst, 10, instance),
        "countries_blocked": _aggregate_countries(blocked, 10, instance),
        "src_external": src_external,
        "src_internal": src_internal,
        "dst_external": dst_external,
        "dst_internal": dst_internal,
        "blocked_ips": repo.top_values("src_ip", start, end, 10, actions=["block", "reject"]),
        "src_ports": repo.top_values("src_port", start, end, 10),
        "dst_ports": repo.top_values("dst_port", start, end, 10),
        "directions": repo.top_values("direction", start, end, 10),
        "protocols": repo.top_values("protocol", start, end, 10),
        "rules": repo.top_values("rule_id", start, end, 10),
    }


@router.get("/timeseries")
def timeseries(
    start: datetime | None = None,
    end: datetime | None = None,
    bucket: str = "minute",
    instance: str | None = InstanceId,
    user: str = Depends(require_user),
) -> dict:
    repo = EventRepository(instance_id=instance)
    return {"bucket": bucket, "points": repo.timeseries(start=start, end=end, bucket=bucket)}
