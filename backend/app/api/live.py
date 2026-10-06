"""Live WebSocket endpoint."""
from __future__ import annotations

from fastapi import APIRouter, WebSocket

from ..websocket.live import live_hub

router = APIRouter(tags=["live"])


@router.websocket("/api/live/ws")
async def live_ws(websocket: WebSocket) -> None:
    await live_hub.handler(websocket)
