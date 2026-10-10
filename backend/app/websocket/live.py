"""Live event hub fanning out parsed events to WebSocket subscribers."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import asdict
from datetime import date, datetime

from fastapi import WebSocket

from ..parser.models import FirewallEvent

logger = logging.getLogger("opnsense.live")

# A burst of logs (e.g. a port scan) can produce several thousand events per
# second. Sending one WebSocket frame per event would swamp the browser, so
# events are coalesced into batches: after the first event we wait a short
# moment to accumulate the burst, then flush everything queued in one frame.
_COALESCE_SEC = 0.15
_MAX_BATCH = 1000
# When no event flows, a heartbeat is sent so an idle-but-dead connection (e.g.
# after a firewall reboot that leaves the socket half-open) is detected: the
# send fails on the server side and the client watchdog reconnects.
_HEARTBEAT_SEC = 15
_HEARTBEAT = {"heartbeat": True}


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

    async def handler(
        self,
        websocket: WebSocket,
        load_initial: Callable[[], list[dict]] | None = None,
    ) -> None:
        # Accept the connection first so the client switches to "connected"
        # immediately, then load the (potentially slow) backlog in a worker
        # thread. Events that arrive while the backlog is being read are already
        # queued (we subscribe before the read) so none of them are lost, and
        # live frames are only delayed by the backlog read, never blocked by it.
        await websocket.accept()
        queue = await self.subscribe()
        try:
            if load_initial is not None:
                try:
                    initial = await asyncio.to_thread(load_initial)
                except Exception:  # noqa: BLE001 - a bad backlog must not kill the stream
                    logger.exception("Unable to load recent events for the live backlog")
                    initial = []
                if initial:
                    await websocket.send_json([_json_safe(row) for row in initial])
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=_HEARTBEAT_SEC)
                except asyncio.TimeoutError:
                    # Nothing to send: keep the connection warm and let a dead
                    # peer be detected when the heartbeat send fails.
                    await websocket.send_json(_HEARTBEAT)
                    continue
                batch = [payload]
                # Let a burst accumulate, then flush everything already queued
                # in one frame instead of one frame per event.
                await asyncio.sleep(_COALESCE_SEC)
                while len(batch) < _MAX_BATCH:
                    try:
                        batch.append(queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                await websocket.send_json(batch)
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
