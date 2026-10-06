"""Background retention task."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from ..config import settings
from .repository import EventRepository

logger = logging.getLogger("opnsense.retention")


async def retention_loop(repo: EventRepository | None = None) -> None:
    """Delete events older than ``LOG_RETENTION_DAYS`` periodically.

    ``LOG_RETENTION_DAYS = 0`` disables deletion (unlimited retention).
    """
    repo = repo or EventRepository()
    interval = max(5, settings.retention_check_interval_min) * 60
    while True:
        try:
            if settings.log_retention_days > 0:
                cutoff = datetime.now(timezone.utc) - timedelta(days=settings.log_retention_days)
                deleted = repo.delete_older_than(cutoff)
                if deleted:
                    logger.info("Retention: deleted %s events older than %s", deleted, cutoff)
        except Exception:  # noqa: BLE001
            logger.exception("Retention loop error")
        await asyncio.sleep(interval)
