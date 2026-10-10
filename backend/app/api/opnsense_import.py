"""OPNsense filter log import endpoints (SSH backfill)."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..opnsense.filterlog_import import get_import_job, start_import
from ..opnsense.settings_store import get_opnsense_settings
from .deps import require_user

router = APIRouter(prefix="/api/opnsense/filterlog", tags=["opnsense"])


@router.post("/import")
def start_import_endpoint(
    full: bool = False,
    instance_id: str | None = None,
    user: str = Depends(require_user),
) -> dict:
    max_days = 0
    if not full:
        try:
            max_days = int(
                get_opnsense_settings(mask_password=True, instance_id=instance_id).get(
                    "opnsense_import_max_days"
                )
                or 0
            )
        except Exception:  # noqa: BLE001 - fall back to no limit
            max_days = 0
    started = start_import(full=full, max_days=max_days, instance_id=instance_id)
    return {"ok": True, "started": started, "status": get_import_job(instance_id).snapshot()}


@router.get("/import/status")
def import_status(instance_id: str | None = None, user: str = Depends(require_user)) -> dict:
    return get_import_job(instance_id).snapshot()
