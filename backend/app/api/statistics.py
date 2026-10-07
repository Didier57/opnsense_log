"""Statistics and analytics endpoints."""
from __future__ import annotations

import ipaddress
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query

from ..geoip.resolver import geo_resolver
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


@router.get("/countries")
def countries(
    start: datetime | None = None,
    end: datetime | None = None,
    limit: int = Query(20, ge=1, le=100),
    user: str = Depends(require_user),
) -> dict:
    """Top countries of the source IPs (GeoIP resolved)."""
    ips = repo.top_values("src_ip", start, end, 500)
    resolved = geo_resolver.resolve([item["value"] for item in ips if item.get("value")])
    totals: dict[str, dict] = {}
    for item in ips:
        ip = item.get("value")
        info = resolved.get(ip) if ip else None
        if not info:
            continue
        code = info["country"]
        entry = totals.setdefault(
            code, {"value": code, "name": info.get("name") or code, "count": 0}
        )
        entry["count"] += item["count"]
    items = sorted(totals.values(), key=lambda entry: entry["count"], reverse=True)[:limit]
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
    user: str = Depends(require_user),
) -> dict:
    """Dashboard overview: top countries plus top internal/external IPs."""
    src = repo.top_values("src_ip", start, end, 500)
    dst = repo.top_values("dst_ip", start, end, 500)
    src_external = [item for item in src if not _is_internal(item.get("value"))][:10]
    src_internal = [item for item in src if _is_internal(item.get("value"))][:10]
    dst_external = [item for item in dst if not _is_internal(item.get("value"))][:10]
    dst_internal = [item for item in dst if _is_internal(item.get("value"))][:10]

    resolved = geo_resolver.resolve([item["value"] for item in src if item.get("value")])
    totals: dict[str, dict] = {}
    for item in src:
        info = resolved.get(item["value"]) if item.get("value") else None
        if not info:
            continue
        code = info["country"]
        entry = totals.setdefault(
            code, {"value": code, "name": info.get("name") or code, "count": 0}
        )
        entry["count"] += item["count"]
    countries = sorted(totals.values(), key=lambda entry: entry["count"], reverse=True)[:10]

    return {
        "countries": countries,
        "src_external": src_external,
        "src_internal": src_internal,
        "dst_external": dst_external,
        "dst_internal": dst_internal,
        "dst_ports": repo.top_values("dst_port", start, end, 10),
        "protocols": repo.top_values("protocol", start, end, 10),
        "rules": repo.top_values("rule_id", start, end, 10),
    }


@router.get("/timeseries")
def timeseries(
    start: datetime | None = None,
    end: datetime | None = None,
    bucket: str = "minute",
    user: str = Depends(require_user),
) -> dict:
    return {"bucket": bucket, "points": repo.timeseries(start=start, end=end, bucket=bucket)}
