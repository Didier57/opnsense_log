"""Live WebSocket endpoint."""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, WebSocket

from ..storage.repository import EventRepository
from ..websocket.live import live_hub

router = APIRouter(tags=["live"])
logger = logging.getLogger("opnsense.live")

_BACKLOG = 200


@router.websocket("/api/live/ws")
async def live_ws(websocket: WebSocket) -> None:
    repo = EventRepository()
    try:
        # Priming the view must never block the event loop on a large database.
        initial = await asyncio.to_thread(repo.recent, _BACKLOG)
    except Exception:  # noqa: BLE001
        logger.exception("Unable to load recent events for the live backlog")
        initial = []
    await live_hub.handler(websocket, initial)
