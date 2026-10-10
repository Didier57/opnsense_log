"""Asyncio Syslog receiver (UDP + TCP) with a parse/insert pipeline.

Architecture::

    Syslog -> Receive Queue -> Parser Workers -> Batch Insert -> DuckDB
                                     \\
                                      -> LiveHub (WebSocket fan-out)

One :class:`SyslogServer` is created per OPNsense instance, each listening on
its own port (``instances.syslog_port``) and fanning out to its own live hub.
"""
from __future__ import annotations

import asyncio
import logging
import threading

from ..config import settings
from ..core.stats import get_counters
from ..parser import parse_message
from ..storage.repository import EventRepository
from ..websocket.live import get_live_hub

logger = logging.getLogger("opnsense.syslog")


def _protocols(value: str) -> list[str]:
    value = (value or "udp").lower()
    if value == "both":
        return ["udp", "tcp"]
    return [value] if value in ("udp", "tcp") else ["udp"]


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue, hostname_resolver, counters) -> None:
        self.queue = queue
        self.resolve_hostname = hostname_resolver
        self.counters = counters

    def datagram_received(self, data: bytes, addr) -> None:
        self.counters.incr_received()
        text = data.decode("utf-8", errors="replace").strip()
        if not text:
            return
        hostname = self.resolve_hostname(addr[0])
        self._enqueue(text, hostname)

    def _enqueue(self, text: str, hostname: str) -> None:
        try:
            self.queue.put_nowait((text, hostname))
        except asyncio.QueueFull:
            self.counters.incr_invalid()


class SyslogServer:
    def __init__(self, instance_id: str | None = None) -> None:
        self.instance_id = instance_id
        self.counters = get_counters(instance_id)
        self.live_hub = get_live_hub(instance_id)
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=settings.syslog_queue_maxsize)
        # Parsed events are handed to a dedicated inserter so the parser workers
        # (which also fan out to the live view) never wait on a database write.
        self._insert_queue: asyncio.Queue = asyncio.Queue(maxsize=settings.syslog_queue_maxsize)
        self.repo = EventRepository(instance_id=instance_id)
        self._transports: list = []
        self._servers: list = []
        self._workers: list[asyncio.Task] = []
        self._inserter: asyncio.Task | None = None
        self._hostnames: dict[str, str] = {}
        self._running = False

    def _resolve_hostname(self, ip: str) -> str:
        return self._hostnames.get(ip, ip)

    def _listen_config(self) -> tuple[int, list[str]]:
        """Resolve the port and protocols from the instance row (fallback settings)."""
        port = settings.syslog_port
        protocols = settings.syslog_protocols
        try:
            from ..instances import get_instance, resolve_instance_id

            iid = resolve_instance_id(self.instance_id)
            inst = get_instance(iid) if iid else None
            if inst:
                if inst.get("syslog_port"):
                    port = int(inst["syslog_port"])
                if inst.get("syslog_protocol"):
                    protocols = _protocols(inst["syslog_protocol"])
        except Exception:  # noqa: BLE001 - fall back to global settings
            pass
        return port, protocols

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        port, protocols = self._listen_config()
        if "udp" in protocols:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(self.queue, self._resolve_hostname, self.counters),
                local_addr=(settings.syslog_host, port),
            )
            self._transports.append(transport)
            logger.info("Syslog listener started on UDP %s (instance %s)", port, self.instance_id)
        if "tcp" in protocols:
            server = await asyncio.start_server(
                self._handle_tcp_client, settings.syslog_host, port
            )
            self._servers.append(server)
            logger.info("Syslog listener started on TCP %s (instance %s)", port, self.instance_id)

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
                self.counters.incr_received()
                text = line.decode("utf-8", errors="replace").strip()
                if text:
                    try:
                        self.queue.put_nowait((text, hostname))
                    except asyncio.QueueFull:
                        self.counters.incr_invalid()
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
            self.counters.incr_invalid()
            return
        self.counters.incr_parsed()
        # Fan out to the live view immediately: this never touches the database,
        # so a slow insert can no longer freeze the live stream.
        self.live_hub.publish(result.event)
        try:
            self._insert_queue.put_nowait(result.event)
        except asyncio.QueueFull:
            self.counters.incr_invalid()

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
        logger.info("Syslog listeners stopped (instance %s)", self.instance_id)

    @property
    def connected(self) -> bool:
        return self._running


class SyslogManager:
    """Owns one :class:`SyslogServer` per OPNsense instance."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._servers: dict[str, SyslogServer] = {}

    def get(self, instance_id: str | None = None) -> SyslogServer:
        from ..instances import resolve_instance_id

        key = resolve_instance_id(instance_id) or ""
        with self._lock:
            server = self._servers.get(key)
            if server is None:
                server = SyslogServer(instance_id=instance_id)
                self._servers[key] = server
            return server

    async def start_all(self) -> None:
        from ..instances import list_instances

        try:
            instances = list_instances()
        except Exception:  # noqa: BLE001
            instances = []
        if not instances:
            await self.get(None).start()
            return
        for inst in instances:
            if inst.get("enabled", True):
                try:
                    await self.get(inst["id"]).start()
                except Exception:  # noqa: BLE001
                    logger.exception("Could not start syslog listener for %s", inst.get("id"))

    async def stop_all(self) -> None:
        for server in list(self._servers.values()):
            try:
                await server.stop()
            except Exception:  # noqa: BLE001
                logger.exception("Could not stop syslog listener")


def get_syslog_server(instance_id: str | None = None) -> SyslogServer:
    return syslog_manager.get(instance_id)


# Module-level defaults kept for backward compatibility with health checks.
syslog_manager = SyslogManager()
syslog_server = SyslogServer()
