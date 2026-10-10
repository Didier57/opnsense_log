"""FastAPI application entry point."""
from __future__ import annotations

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response

from .api import api_router
from .config import settings
from .core.logging import setup_logging
from .core.stats import counters
from .detection.engine import detection_loop
from .geoip.resolver import geo_update_loop
from .opnsense.settings_store import get_opnsense_settings
from .opnsense.sync import OPNSenseSync
from .storage.retention import retention_loop
from .syslog.server import syslog_manager

logger = logging.getLogger("opnsense.main")


def _instances() -> list[dict]:
    """All configured OPNsense instances (best effort)."""
    try:
        from .instances import list_instances

        return list_instances()
    except Exception:  # noqa: BLE001
        logger.exception("Could not list OPNsense instances")
        return []


async def _opnsense_sync_loop() -> None:
    """Periodically sync every OPNsense instance.

    Reads the enable flag and interval from each instance's settings so the
    values saved in the web UI take effect without a restart.
    """
    last: dict[str, float] = {}
    while True:
        for inst in _instances():
            iid = inst["id"]
            try:
                cfg = get_opnsense_settings(mask_password=False, instance_id=iid)
            except Exception:  # noqa: BLE001
                logger.exception("Could not read OPNsense settings for %s", iid)
                continue
            if not cfg.get("opnsense_sync_enabled"):
                continue
            interval = max(5, int(cfg.get("opnsense_sync_interval_min") or 30)) * 60
            now = time.monotonic()
            if now - last.get(iid, 0.0) < interval:
                continue
            last[iid] = now
            try:
                await asyncio.to_thread(OPNSenseSync(instance_id=iid).sync)
            except Exception:  # noqa: BLE001
                logger.exception("OPNsense sync failed for %s", iid)
        # Poll frequently so enabling a toggle or adding an instance is picked up.
        await asyncio.sleep(30)


# Per-instance "startup import finished" events. The heartbeat loop waits on
# each one so it cannot advance the watermark past the downtime window before
# the import has read it.
_import_done_events: dict[str, asyncio.Event] = {}
_import_tasks: dict[str, asyncio.Task] = {}


def _import_done_event(instance_id: str) -> asyncio.Event:
    event = _import_done_events.get(instance_id)
    if event is None:
        event = asyncio.Event()
        _import_done_events[instance_id] = event
    return event


async def _startup_filterlog_import_instance(instance_id: str) -> None:
    """Fill the gap left while the container was down for one instance.

    OPNsense does not resume sending syslog immediately after a restart, so we
    first wait (bounded by ``opnsense_import_wait_syslog_sec``) until a *new*
    event (newer than everything already stored) is received again, then backfill
    the files only up to that first event time.
    """
    event = _import_done_event(instance_id)
    try:
        cfg = get_opnsense_settings(mask_password=False, instance_id=instance_id)
    except Exception:  # noqa: BLE001
        logger.exception("Could not read OPNsense settings for startup import (%s)", instance_id)
        event.set()
        return
    try:
        if not cfg.get("opnsense_host") or not cfg.get("opnsense_import_on_start", True):
            return
        from .opnsense.filterlog_import import (
            first_event_after,
            global_max_event_time,
            run_import,
        )

        marker = await asyncio.to_thread(global_max_event_time, instance_id)
        if marker is None:
            logger.info("No stored events yet; skipping startup OPNsense import (%s)", instance_id)
            return
        wait_sec = max(0, int(cfg.get("opnsense_import_wait_syslog_sec") or 120))
        until = None
        waited = 0
        while waited < wait_sec:
            candidate = await asyncio.to_thread(first_event_after, marker, instance_id)
            if candidate is not None:
                until = candidate
                logger.info(
                    "Syslog reception resumed at %s; backfilling files (%s)", candidate, instance_id
                )
                break
            await asyncio.sleep(3)
            waited += 3
        if until is None:
            logger.info(
                "No syslog received within %ds; importing files up to now (%s)", wait_sec, instance_id
            )
        await asyncio.to_thread(
            run_import, False, until, int(cfg.get("opnsense_import_max_days") or 0), instance_id
        )
        logger.info("Startup OPNsense filter log import finished (%s)", instance_id)
    except Exception:  # noqa: BLE001
        logger.exception("Startup filter log import failed (%s)", instance_id)
    finally:
        event.set()


async def _startup_filterlog_import_loop() -> None:
    """Launch the startup gap import once per (new) instance."""
    while True:
        for inst in _instances():
            iid = inst["id"]
            task = _import_tasks.get(iid)
            if task is None or task.done():
                if task is not None and task.done():
                    continue  # already ran once; never restart
                _import_tasks[iid] = asyncio.create_task(
                    _startup_filterlog_import_instance(iid), name=f"filterlog-import-{iid}"
                )
        await asyncio.sleep(30)


async def _filterlog_heartbeat_loop() -> None:
    """Persist a periodic heartbeat per instance while the application runs.

    The heartbeat marks the last moment the app was known to be up, so the next
    startup can compute the precise downtime window and only fill that gap. It is
    held back until that instance's startup import has finished so it cannot
    erase the gap.
    """
    from .opnsense.filterlog_import import set_last_run

    while True:
        for inst in _instances():
            iid = inst["id"]
            event = _import_done_events.get(iid)
            if event is None or not event.is_set():
                continue
            try:
                await asyncio.to_thread(set_last_run, None, iid)
            except Exception:  # noqa: BLE001
                logger.exception("Could not record filter log import heartbeat (%s)", iid)
        await asyncio.sleep(30)


async def _blocking_reconcile_once() -> None:
    """Re-apply recorded blocks that are missing from each firewall alias.

    Repairs drift after a restart (e.g. an OPNsense reboot cleared the alias).
    """
    from .detection.blocking_store import get_blocking_settings
    from .opnsense.blocker import reconcile_alias

    await asyncio.sleep(30)
    for inst in _instances():
        iid = inst["id"]
        try:
            cfg = get_blocking_settings(instance_id=iid)
            if not cfg.get("blocking_enabled") or cfg.get("blocking_dry_run"):
                continue
            result = await asyncio.to_thread(reconcile_alias, iid)
            if result.get("reconciled"):
                logger.info(
                    "Startup blocking reconciliation restored %d IP(s) (%s)",
                    result["reconciled"],
                    iid,
                )
        except Exception:  # noqa: BLE001 - never break startup
            logger.exception("Startup blocking reconciliation failed (%s)", iid)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    # Uptime shown in Système -> État measures the lifetime of the backend
    # application (this process), starting from now.
    counters.started_at = time.time()
    logger.info("Starting OPNsense Log Analyzer")
    # Ensure at least one OPNsense instance exists (migrating legacy data on the
    # first run) before binding any listener.
    try:
        from .instances import bootstrap

        await asyncio.to_thread(bootstrap)
    except Exception:  # noqa: BLE001 - never block startup on bootstrap
        logger.exception("Instance bootstrap failed")
    # Bind the syslog sockets *before* opening the database so that events start
    # flowing into the Live view immediately, even when opening a large DuckDB
    # file (WAL replay) is slow. Workers resolve the DB lazily on first flush.
    await syslog_manager.start_all()
    logger.info("Syslog listener is up; waiting for data")
    # Initialise storage early so schema exists before the first insert. Running
    # it in a thread keeps the event loop (and syslog reception) responsive.
    from .storage.database import get_database

    await asyncio.to_thread(get_database)
    # One-time move of the legacy free-text whitelist into the managed allowlist.
    try:
        from .detection.allowlist_store import migrate_legacy_whitelist

        migrated = await asyncio.to_thread(migrate_legacy_whitelist)
        if migrated:
            logger.info("Imported %d legacy whitelist entrie(s) into the allowlist", len(migrated))
    except Exception:  # noqa: BLE001 - never block startup on migration
        logger.exception("Legacy whitelist migration failed")
    tasks = [
        asyncio.create_task(retention_loop(), name="retention"),
        asyncio.create_task(_opnsense_sync_loop(), name="opnsense-sync"),
        asyncio.create_task(detection_loop(), name="detection"),
        asyncio.create_task(geo_update_loop(), name="geoip"),
        asyncio.create_task(_startup_filterlog_import_loop(), name="filterlog-import"),
        asyncio.create_task(_filterlog_heartbeat_loop(), name="filterlog-heartbeat"),
        asyncio.create_task(_blocking_reconcile_once(), name="blocking-reconcile"),
    ]
    yield
    logger.info("Shutting down")
    await syslog_manager.stop_all()
    for task in tasks:
        task.cancel()


app = FastAPI(title="OPNsense Log Analyzer", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

# Serve the built frontend when present (production container).
_static_dir = Path(__file__).resolve().parent.parent / "static"
_index_file = _static_dir / "index.html"

if _index_file.is_file():
    _static_root = _static_dir.resolve()

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str) -> Response:
        """Serve static files, falling back to index.html for client routes.

        This lets the React single-page app handle deep links (e.g. /dashboard)
        when the page is refreshed, without breaking API 404 semantics.
        """
        if full_path.startswith("api/"):
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        candidate = (_static_root / full_path).resolve()
        if full_path and (candidate == _static_root or _static_root in candidate.parents) and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_index_file)


def run() -> None:
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.web_host,
        port=settings.web_port,
        log_level=settings.log_level.lower(),
    )


if __name__ == "__main__":
    run()
