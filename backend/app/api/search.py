"""Advanced search endpoint supporting AND/OR logic and operators."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..geoip.resolver import geo_resolver
from ..storage.repository import EventRepository
from .deps import InstanceId, require_user
from .schemas import SearchRequest

router = APIRouter(prefix="/api/search", tags=["search"])


@router.post("")
def search(
    payload: SearchRequest,
    instance: str | None = InstanceId,
    user: str = Depends(require_user),
) -> dict:
    repo = EventRepository(instance_id=instance)
    clauses = [c.model_dump() for c in payload.clauses]
    country_ips: list[str] | None = None
    if payload.countries:
        wanted = {code.strip().upper() for code in payload.countries if code.strip()}
        candidates = set(repo.distinct_ips("src_ip", payload.start, payload.end))
        candidates.update(repo.distinct_ips("dst_ip", payload.start, payload.end))
        resolved = geo_resolver.resolve(list(candidates), instance_id=instance)
        country_ips = [
            ip
            for ip, info in resolved.items()
            if info and str(info.get("country", "")).upper() in wanted
        ]
    try:
        return repo.search(
            clauses=clauses,
            logic=payload.logic,
            start=payload.start,
            end=payload.end,
            limit=payload.limit,
            offset=payload.offset,
            order_by=payload.order_by,
            order_dir=payload.order_dir,
            country_ips=country_ips,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
