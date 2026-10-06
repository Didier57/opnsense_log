"""Live event hub fanning out parsed events to WebSocket subscribers."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict
from datetime import date, datetime

from fastapi import WebSocket

from ..parser.models import FirewallEvent

logger = logging.getLogger("opnsense.live")


class LiveHub:
    def __init__(self) -> None:
        self._subscribers: set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()

    async def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=10_000)
        async with self._lock:
            self._subscribers.add(queue)
        return queue

    async def unsubscribe(self, queue: asyncio.Queue) -> None:
        async with self._lock:
            self._subscribers.discard(queue)

    def publish(self, event: FirewallEvent) -> None:
        payload = _serialize(event)
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                # Slow consumer: drop the oldest to keep the stream live.
                try:
                    queue.get_nowait()
                    queue.put_nowait(payload)
                except Exception:  # noqa: BLE001
                    pass

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    async def handler(self, websocket: WebSocket, initial: list[dict] | None = None) -> None:
        await websocket.accept()
        queue = await self.subscribe()
        try:
            # Prime the view with the most recent persisted events so the live
            # table is not empty while waiting for new traffic.
            for row in initial or []:
                await websocket.send_json(_json_safe(row))
            while True:
                payload = await queue.get()
                await websocket.send_json(payload)
        except Exception:  # noqa: BLE001 - client disconnect
            pass
        finally:
            await self.unsubscribe(queue)


def _serialize(event: FirewallEvent) -> dict:
    data = asdict(event)
    data["event_time"] = event.event_time.isoformat()
    return data


def _json_safe(row: dict) -> dict:
    return {
        key: value.isoformat() if isinstance(value, (datetime, date)) else value
        for key, value in row.items()
    }


live_hub = LiveHub()
