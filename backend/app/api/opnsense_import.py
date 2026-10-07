"""OPNsense filter log import endpoints (SSH backfill)."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..opnsense.filterlog_import import import_job, start_import
from .deps import require_user

router = APIRouter(prefix="/api/opnsense/filterlog", tags=["opnsense"])


@router.post("/import")
def start_import_endpoint(full: bool = False, user: str = Depends(require_user)) -> dict:
    started = start_import(full=full)
    return {"ok": True, "started": started, "status": import_job.snapshot()}


@router.get("/import/status")
def import_status(user: str = Depends(require_user)) -> dict:
    return import_job.snapshot()
