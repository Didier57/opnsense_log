"""Reverse-DNS hostname lookup endpoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ..core.hostnames import resolver
from .deps import require_user

router = APIRouter(prefix="/api", tags=["lookup"])

_MAX_IPS = 200


@router.get("/lookup")
def lookup_hostnames(
    ips: str = Query(default="", description="Comma-separated list of IP addresses"),
    user: str = Depends(require_user),
) -> dict:
    values = [item.strip() for item in ips.split(",") if item.strip()][:_MAX_IPS]
    return {"items": resolver.resolve(values)}
