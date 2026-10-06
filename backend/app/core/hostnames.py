"""Reverse-DNS hostname resolution with an in-memory and DuckDB cache.

Resolution is performed in worker threads with a short timeout so that a slow
or unresponsive DNS server can never block the event pipeline or the API. All
results are cached (positive results persistently in DuckDB, negative results
in memory only) because reverse lookups are expensive and highly repetitive.
"""
from __future__ import annotations

import ipaddress
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ..config import settings
from ..storage.database import get_database

_NETWORK_TIMEOUT = 2.0  # seconds to wait for a single PTR lookup
_NEGATIVE_TTL = 600  # seconds to remember a failed lookup
_MAX_WORKERS = 8


@dataclass
class _Entry:
    hostname: str | None
    expires: float


class HostnameResolver:
    def __init__(self) -> None:
        self._mem: dict[str, _Entry] = {}
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="rdns")

    def _ttl(self) -> int:
        try:
            minutes = int(getattr(settings, "hostname_lookup_ttl_min", 1440))
        except (TypeError, ValueError):
            minutes = 1440
        return max(minutes, 1) * 60

    def _db_lookup(self, ips: list[str]) -> dict[str, str]:
        if not ips:
            return {}
        placeholders = ", ".join("?" for _ in ips)
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self._ttl())
        try:
            rows = get_database().execute_read(
                f'SELECT "ip", "hostname" FROM hostname_cache '
                f'WHERE "ip" IN ({placeholders}) AND "updated_at" >= ?',
                [*ips, cutoff],
            ).fetchall()
        except Exception:  # noqa: BLE001
            return {}
        return {ip: hostname for ip, hostname in rows if hostname}

    def _db_store(self, mapping: dict[str, str]) -> None:
        if not mapping:
            return
        try:
            get_database().executemany_write(
                'INSERT INTO hostname_cache ("ip", "hostname", "updated_at") VALUES (?, ?, now()) '
                'ON CONFLICT ("ip") DO UPDATE SET "hostname" = excluded."hostname", '
                '"updated_at" = excluded."updated_at"',
                [[ip, hostname] for ip, hostname in mapping.items()],
            )
        except Exception:  # noqa: BLE001
            pass

    def _reverse(self, ip: str) -> str | None:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            return None
        hostname = hostname.rstrip(".")
        return hostname or None

    def _resolve_batch(self, ips: list[str]) -> dict[str, str | None]:
        futures = {ip: self._pool.submit(self._reverse, ip) for ip in ips}
        out: dict[str, str | None] = {}
        for ip, future in futures.items():
            try:
                out[ip] = future.result(timeout=_NETWORK_TIMEOUT)
            except Exception:  # noqa: BLE001 - timeout or worker error
                out[ip] = None
        return out

    def resolve(self, ips: list[str]) -> dict[str, str | None]:
        unique: list[str] = []
        seen: set[str] = set()
        for raw in ips:
            value = (raw or "").strip()
            if not value or value in seen:
                continue
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue
            seen.add(value)
            unique.append(value)

        now = time.time()
        result: dict[str, str | None] = {}
        missing: list[str] = []
        with self._lock:
            for ip in unique:
                entry = self._mem.get(ip)
                if entry and entry.expires > now:
                    result[ip] = entry.hostname
                else:
                    missing.append(ip)

        if not missing:
            return result

        ttl = self._ttl()
        db_hits = self._db_lookup(missing)
        to_resolve: list[str] = []
        with self._lock:
            for ip in missing:
                if ip in db_hits:
                    result[ip] = db_hits[ip]
                    self._mem[ip] = _Entry(db_hits[ip], now + ttl)
                else:
                    to_resolve.append(ip)

        if to_resolve:
            resolved = self._resolve_batch(to_resolve)
            found: dict[str, str] = {}
            with self._lock:
                for ip, hostname in resolved.items():
                    result[ip] = hostname
                    self._mem[ip] = _Entry(hostname, now + (ttl if hostname else _NEGATIVE_TTL))
                    if hostname:
                        found[ip] = hostname
            self._db_store(found)

        return result


resolver = HostnameResolver()
