"""Health and monitoring endpoints."""
from __future__ import annotations

from fastapi import APIRouter

from ..core.stats import counters
from ..syslog.server import syslog_server
from ..websocket.live import live_hub

router = APIRouter(prefix="/api", tags=["health"])


@router.get("/health")
def health() -> dict:
    return {"status": "healthy"}


@router.get("/health/ready")
def ready() -> dict:
    return {
        "status": "ready",
        "syslog": syslog_server.connected,
        "subscribers": live_hub.subscriber_count,
    }


@router.get("/monitoring")
def monitoring() -> dict:
    return counters.snapshot()
