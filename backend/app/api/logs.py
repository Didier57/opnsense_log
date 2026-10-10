"""Event query endpoints."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query

from ..storage.repository import EventRepository
from .deps import InstanceId, require_user

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("")
def query_logs(
    start: datetime | None = None,
    end: datetime | None = None,
    action: str | None = None,
    protocol: str | None = None,
    interface: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    dst_port: int | None = None,
    rule_id: str | None = None,
    ip_version: int | None = None,
    direction: str | None = None,
    limit: int = Query(100, ge=1, le=5000),
    offset: int = Query(0, ge=0),
    order_dir: str = "desc",
    instance: str | None = InstanceId,
    user: str = Depends(require_user),
) -> dict:
    repo = EventRepository(instance_id=instance)
    clauses: list[dict] = []
    for field, value in (
        ("action", action),
        ("protocol", protocol),
        ("interface", interface),
        ("src_ip", src_ip),
        ("dst_ip", dst_ip),
        ("dst_port", dst_port),
        ("rule_id", rule_id),
        ("ip_version", ip_version),
        ("direction", direction),
    ):
        if value is not None:
            clauses.append({"field": field, "op": "eq", "value": value})
    return repo.search(
        clauses=clauses, start=start, end=end, limit=limit, offset=offset, order_dir=order_dir
    )
