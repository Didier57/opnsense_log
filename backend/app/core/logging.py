"""Internal application logging configuration."""
from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone

from ..config import settings


class RingBufferHandler(logging.Handler):
    """Keep recent log records in memory so they can be exposed via the API."""

    def __init__(self, capacity: int = 500) -> None:
        super().__init__()
        self.capacity = capacity
        self.records: list[dict] = []

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self.records.append(
                {
                    "ts": datetime.fromtimestamp(record.created, tz=timezone.utc),
                    "level": record.levelname,
                    "source": record.name,
                    "message": self.format(record),
                }
            )
            if len(self.records) > self.capacity:
                del self.records[: len(self.records) - self.capacity]
        except Exception:  # noqa: BLE001
            pass


ring_handler = RingBufferHandler()


def setup_logging() -> None:
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    fmt = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        stream = logging.StreamHandler(sys.stdout)
        stream.setFormatter(fmt)
        root.addHandler(stream)
    ring_handler.setFormatter(logging.Formatter("%(message)s"))
    if ring_handler not in root.handlers:
        root.addHandler(ring_handler)
