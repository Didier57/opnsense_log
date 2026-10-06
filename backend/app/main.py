"""FastAPI application entry point."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from .api import api_router
from .config import settings
from .core.logging import setup_logging
from .opnsense.settings_store import get_opnsense_settings
from .opnsense.sync import OPNSenseSync
from .storage.retention import retention_loop
from .syslog.server import syslog_server

logger = logging.getLogger("opnsense.main")


async def _opnsense_sync_loop() -> None:
    """Periodically sync OPNsense config.

    Reads the enable flag and interval from the runtime settings store so the
    values saved in the web UI take effect without a restart.
    """
    while True:
        try:
            cfg = get_opnsense_settings(mask_password=False)
        except Exception:  # noqa: BLE001
            logger.exception("Could not read OPNsense settings")
            cfg = {}
        enabled = bool(cfg.get("opnsense_sync_enabled"))
        interval_min = max(5, int(cfg.get("opnsense_sync_interval_min") or 30))
        if enabled:
            try:
                await asyncio.to_thread(OPNSenseSync().sync)
            except Exception:  # noqa: BLE001
                logger.exception("OPNsense sync loop error")
            await asyncio.sleep(interval_min * 60)
        else:
            # Poll periodically so enabling the toggle is picked up quickly.
            await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info("Starting OPNsense Log Analyzer")
    # Initialise storage early so schema exists before the first insert.
    from .storage.database import get_database

    get_database()
    await syslog_server.start()
    tasks = [
        asyncio.create_task(retention_loop(), name="retention"),
        asyncio.create_task(_opnsense_sync_loop(), name="opnsense-sync"),
    ]
    yield
    logger.info("Shutting down")
    await syslog_server.stop()
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
if _static_dir.is_dir():
    app.mount("/", StaticFiles(directory=str(_static_dir), html=True), name="static")


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
