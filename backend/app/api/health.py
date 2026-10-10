"""Health and monitoring endpoints."""
from __future__ import annotations

from fastapi import APIRouter

from ..core.stats import get_counters
from ..syslog.server import get_syslog_server
from ..websocket.live import get_live_hub
from .deps import InstanceId

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
def health() -> dict:
    return {"status": "healthy"}


@router.get("/health/ready")
def ready(instance: str | None = InstanceId) -> dict:
    return {
        "status": "ready",
        "syslog": get_syslog_server(instance).connected,
        "subscribers": get_live_hub(instance).subscriber_count,
    }


@router.get("/monitoring")
def monitoring(instance: str | None = InstanceId) -> dict:
    return get_counters(instance).snapshot()
