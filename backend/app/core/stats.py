"""Runtime counters exposed by the monitoring API."""
from __future__ import annotations

import threading
import time


class Counters:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.received = 0
        self.parsed = 0
        self.invalid = 0
        self.started_at = time.time()
        self._last_received = 0
        self._last_ts = time.time()
        self.events_per_sec = 0.0

    def incr_received(self, n: int = 1) -> None:
        with self._lock:
            self.received += n

    def incr_parsed(self, n: int = 1) -> None:
        with self._lock:
            self.parsed += n

    def incr_invalid(self, n: int = 1) -> None:
        with self._lock:
            self.invalid += n

    def sample_rate(self) -> float:
        with self._lock:
            now = time.time()
            elapsed = now - self._last_ts
            if elapsed > 0:
                self.events_per_sec = (self.received - self._last_received) / elapsed
            self._last_received = self.received
            self._last_ts = now
            return self.events_per_sec

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "received": self.received,
                "parsed": self.parsed,
                "invalid": self.invalid,
                "uptime_seconds": int(time.time() - self.started_at),
                "events_per_sec": round(self.events_per_sec, 2),
            }


counters = Counters()

_counters_lock = threading.Lock()
_counters_by_instance: dict[str, Counters] = {}


def get_counters(instance_id: str | None = None) -> Counters:
    """Return the runtime counters for an instance (or the system default)."""
    from ..instances import resolve_instance_id

    key = resolve_instance_id(instance_id) or ""
    with _counters_lock:
        existing = _counters_by_instance.get(key)
        if existing is None:
            existing = Counters()
            _counters_by_instance[key] = existing
        return existing
