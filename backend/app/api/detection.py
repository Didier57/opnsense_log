"""Security detection endpoints: alerts and detection/notification settings."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ..detection.allowlist_store import add_allowlist, list_allowlist, remove_allowlist
from ..detection.blocking_store import get_blocking_settings, update_blocking_settings
from ..detection.engine import clear_alerts, list_alerts, run_cycle
from ..detection.store import get_detection_settings, update_detection_settings
from ..notifications.mailer import send_test_email
from ..notifications.store import get_smtp_settings, update_smtp_settings
from ..opnsense.blocker import (
    apply_ips,
    list_blocked,
    prune_expired,
    reconcile_alias,
    refresh_detected_tables,
    unblock_ips,
)
from .deps import require_user
from .schemas import (
    AllowlistAdd,
    AllowlistRemove,
    BlockingSettings,
    BlockRequest,
    DetectionSettings,
    NotificationSettings,
)

router = APIRouter(prefix="/api", tags=["detection"])


@router.get("/alerts")
def get_alerts(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: str = Depends(require_user),
) -> dict:
    return list_alerts(limit=limit, offset=offset)


@router.delete("/alerts")
def delete_alerts(user: str = Depends(require_user)) -> dict:
    return {"ok": True, "deleted": clear_alerts()}


@router.post("/alerts/run")
def run_detection(user: str = Depends(require_user)) -> dict:
    created = run_cycle()
    return {"ok": True, "created": len(created), "alerts": created}


@router.get("/settings/detection")
def get_detection(user: str = Depends(require_user)) -> dict:
    return get_detection_settings()


@router.put("/settings/detection")
def put_detection(payload: DetectionSettings, user: str = Depends(require_user)) -> dict:
    return update_detection_settings(payload.model_dump(exclude_none=True))


@router.get("/settings/notifications")
def get_notifications(user: str = Depends(require_user)) -> dict:
    return get_smtp_settings(mask_password=True)


@router.put("/settings/notifications")
def put_notifications(payload: NotificationSettings, user: str = Depends(require_user)) -> dict:
    return update_smtp_settings(payload.model_dump(exclude_none=True))


@router.post("/settings/notifications/test")
def test_notifications(user: str = Depends(require_user)) -> dict:
    return send_test_email()


@router.get("/settings/blocking")
def get_blocking(user: str = Depends(require_user)) -> dict:
    return get_blocking_settings()


@router.put("/settings/blocking")
def put_blocking(payload: BlockingSettings, user: str = Depends(require_user)) -> dict:
    return update_blocking_settings(payload.model_dump(exclude_none=True))


@router.post("/settings/blocking/detect-tables")
def detect_blocking_tables(user: str = Depends(require_user)) -> dict:
    """Detect the pf block tables present on the firewall (CrowdSec, Q-Feeds...)."""
    tables = refresh_detected_tables()
    return {"ok": True, "tables": tables, "settings": get_blocking_settings()}


@router.post("/settings/blocking/reconcile")
def reconcile_blocking(user: str = Depends(require_user)) -> dict:
    """Re-add recorded blocks missing from the firewall alias (drift repair)."""
    return reconcile_alias()


@router.get("/settings/blocking/allowlist")
def get_allowlist(user: str = Depends(require_user)) -> dict:
    return {"items": list_allowlist()}


@router.post("/settings/blocking/allowlist")
def add_allowlist_endpoint(payload: AllowlistAdd, user: str = Depends(require_user)) -> dict:
    added = add_allowlist(payload.ips, payload.note or "")
    return {"ok": True, "added": added, "items": list_allowlist()}


@router.delete("/settings/blocking/allowlist")
def remove_allowlist_endpoint(payload: AllowlistRemove, user: str = Depends(require_user)) -> dict:
    removed = remove_allowlist(payload.ips)
    return {"ok": True, "removed": removed, "items": list_allowlist()}


@router.get("/blocking/list")
def get_blocked(user: str = Depends(require_user)) -> dict:
    return {"items": list_blocked()}


@router.post("/blocking/apply")
def block_now(payload: BlockRequest, user: str = Depends(require_user)) -> dict:
    return apply_ips(payload.ips, rule="manual", source="manual")


@router.post("/blocking/prune")
def prune_blocked(user: str = Depends(require_user)) -> dict:
    return {"ok": True, "removed": prune_expired()}


@router.post("/blocking/remove")
def unblock_now(payload: BlockRequest, user: str = Depends(require_user)) -> dict:
    return unblock_ips(payload.ips)
