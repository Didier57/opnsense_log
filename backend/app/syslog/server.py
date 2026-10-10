"""Asyncio Syslog receiver (UDP + TCP) with a parse/insert pipeline.

Architecture::

    Syslog -> Receive Queue -> Parser Workers -> Batch Insert -> DuckDB
                                     \\
                                      -> LiveHub (WebSocket fan-out)
"""
from __future__ import annotations

import asyncio
import logging

from ..config import settings
from ..core.stats import counters
from ..parser import parse_message
from ..storage.repository import EventRepository
from ..websocket.live import live_hub

logger = logging.getLogger("opnsense.syslog")


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue, hostname_resolver) -> None:
        self.queue = queue
        self.resolve_hostname = hostname_resolver

    def datagram_received(self, data: bytes, addr) -> None:
        counters.incr_received()
        text = data.decode("utf-8", errors="replace").strip()
        if not text:
            return
        hostname = self.resolve_hostname(addr[0])
        self._enqueue(text, hostname)

    def _enqueue(self, text: str, hostname: str) -> None:
        try:
            self.queue.put_nowait((text, hostname))
        except asyncio.QueueFull:
            counters.incr_invalid()


class SyslogServer:
    def __init__(self) -> None:
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=settings.syslog_queue_maxsize)
        # Parsed events are handed to a dedicated inserter so the parser workers
        # (which also fan out to the live view) never wait on a database write.
        self._insert_queue: asyncio.Queue = asyncio.Queue(maxsize=settings.syslog_queue_maxsize)
        self.repo = EventRepository()
        self._transports: list = []
        self._servers: list = []
        self._workers: list[asyncio.Task] = []
        self._inserter: asyncio.Task | None = None
        self._hostnames: dict[str, str] = {}
        self._running = False

    def _resolve_hostname(self, ip: str) -> str:
        return self._hostnames.get(ip, ip)

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        protocols = settings.syslog_protocols
        port = settings.syslog_port
        if "udp" in protocols:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(self.queue, self._resolve_hostname),
                local_addr=(settings.syslog_host, port),
            )
            self._transports.append(transport)
            logger.info("Syslog listener started on UDP %s", port)
        if "tcp" in protocols:
            server = await asyncio.start_server(
                self._handle_tcp_client, settings.syslog_host, port
            )
            self._servers.append(server)
            logger.info("Syslog listener started on TCP %s", port)

        for i in range(max(1, settings.parser_workers)):
            self._workers.append(asyncio.create_task(self._worker(i), name=f"parser-{i}"))
        self._inserter = asyncio.create_task(self._insert_loop(), name="db-inserter")

    async def _handle_tcp_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        hostname = peer[0] if peer else ""
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                counters.incr_received()
                text = line.decode("utf-8", errors="replace").strip()
                if text:
                    try:
                        self.queue.put_nowait((text, hostname))
                    except asyncio.QueueFull:
                        counters.incr_invalid()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:  # noqa: BLE001
                pass

    async def _worker(self, worker_id: int) -> None:
        while True:
            try:
                text, hostname = await self.queue.get()
                self._process(text, hostname)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("Parser worker %s error", worker_id)

    def _process(self, text: str, hostname: str) -> None:
        result = parse_message(text, hostname=hostname)
        if result.event is None:
            counters.incr_invalid()
            return
        counters.incr_parsed()
        # Fan out to the live view immediately: this never touches the database,
        # so a slow insert can no longer freeze the live stream.
        live_hub.publish(result.event)
        try:
            self._insert_queue.put_nowait(result.event)
        except asyncio.QueueFull:
            counters.incr_invalid()

    async def _insert_loop(self) -> None:
        """Batch parsed events and persist them, decoupled from the live stream.

        A dedicated task drains the insert queue so a DuckDB write never blocks
        the parser workers that feed the WebSocket subscribers.
        """
        batch: list = []
        timeout = settings.batch_flush_ms / 1000
        while True:
            try:
                if not batch:
                    batch.append(await self._insert_queue.get())
                while len(batch) < settings.batch_size:
                    try:
                        batch.append(
                            await asyncio.wait_for(self._insert_queue.get(), timeout=timeout)
                        )
                    except asyncio.TimeoutError:
                        break
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                logger.exception("Insert loop error")
            if batch:
                await self._flush(batch)
                batch = []

    async def _flush(self, batch: list) -> None:
        try:
            await asyncio.to_thread(self.repo.insert_events, batch)
        except Exception:  # noqa: BLE001
            logger.exception("Batch insert failed for %s events", len(batch))

    async def stop(self) -> None:
        self._running = False
        for task in self._workers:
            task.cancel()
        if self._inserter is not None:
            self._inserter.cancel()
        for server in self._servers:
            server.close()
        for transport in self._transports:
            transport.close()
        logger.info("Syslog listeners stopped")

    @property
    def connected(self) -> bool:
        return self._running


# Module-level singleton used by the API health checks.
syslog_server = SyslogServer()
