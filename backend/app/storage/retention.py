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
    (unlimited retention). Deletion runs for every configured instance (each has
    its own database file).
    """
    while True:
        try:
            cfg = get_app_settings()
            days = cfg["log_retention_days"]
            interval = max(5, cfg["retention_check_interval_min"]) * 60
            if days > 0:
                cutoff = datetime.now(timezone.utc) - timedelta(days=days)
                targets = [repo] if repo is not None else _instance_repositories()
                for target in targets:
                    deleted = await asyncio.to_thread(target.delete_older_than, cutoff)
                    if deleted:
                        logger.info(
                            "Retention: deleted %s events older than %s", deleted, cutoff
                        )
        except Exception:  # noqa: BLE001
            logger.exception("Retention loop error")
            interval = 3600
        await asyncio.sleep(interval)


def _instance_repositories() -> list[EventRepository]:
    from ..instances import list_instances

    repos = []
    for inst in list_instances():
        repos.append(EventRepository(instance_id=inst["id"]))
    return repos
