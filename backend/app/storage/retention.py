"""Background retention task."""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from ..settings_store import get_app_settings
from .repository import EventRepository

logger = logging.getLogger("opnsense.retention")


async def retention_loop(repo: EventRepository | None = None) -> None:
    """Delete events older than the configured retention period.

    The retention (``LOG_RETENTION_DAYS``) and check interval are read from the
    runtime settings store on every cycle, so changes saved in the web UI take
    effect without a restart. ``LOG_RETENTION_DAYS = 0`` disables deletion
    (unlimited retention).
    """
    repo = repo or EventRepository()
    while True:
        try:
            cfg = get_app_settings()
            days = cfg["log_retention_days"]
            interval = max(5, cfg["retention_check_interval_min"]) * 60
            if days > 0:
                cutoff = datetime.now(timezone.utc) - timedelta(days=days)
                deleted = await asyncio.to_thread(repo.delete_older_than, cutoff)
                if deleted:
                    logger.info("Retention: deleted %s events older than %s", deleted, cutoff)
        except Exception:  # noqa: BLE001
            logger.exception("Retention loop error")
            interval = 3600
        await asyncio.sleep(interval)
