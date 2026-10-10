"""Live WebSocket endpoint."""
from __future__ import annotations

from fastapi import APIRouter, WebSocket

from ..storage.repository import EventRepository
from ..websocket.live import get_live_hub

router = APIRouter(tags=["live"])

_BACKLOG = 200


@router.websocket("/api/live/ws")
async def live_ws(websocket: WebSocket) -> None:
    instance_id = websocket.query_params.get("instance")
    repo = EventRepository(instance_id=instance_id)
    # The backlog is loaded lazily inside the handler so the socket is accepted
    # (and live traffic starts flowing) without waiting for the database.
    await get_live_hub(instance_id).handler(
        websocket, load_initial=lambda: repo.recent(_BACKLOG)
    )
