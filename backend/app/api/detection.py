"""Security detection endpoints: alerts and detection/notification settings."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ..detection.allowlist_store import add_allowlist, list_allowlist, remove_allowlist
from ..detection.blocking_store import get_blocking_settings, update_blocking_settings
from ..detection.engine import clear_alerts, list_alerts, run_cycle
from ..detection.store import get_detection_settings, update_detection_settings
from ..instances import instance_label
from ..notifications.dispatch import deliver
from ..notifications.instance_store import get_notify_settings, update_notify_settings
from ..notifications.mailer import send_test_email
from ..notifications.store import get_smtp_settings, update_smtp_settings
from ..opnsense.blocker import (
    alias_ips,
    apply_ips,
    block_permanently,
    clean_alias_orphans,
    list_blocked,
    prune_expired,
    reconcile_alias,
    refresh_detected_tables,
    unblock_ips,
)
from .deps import InstanceId, require_admin
from .schemas import (
    AllowlistAdd,
    AllowlistRemove,
    BlockingSettings,
    BlockRequest,
    DetectionSettings,
    NotificationSettings,
    NotifySettings,
)

router = APIRouter(prefix="/api", tags=["detection"])


@router.get("/alerts")
def get_alerts(
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    instance: str | None = InstanceId,
    user: str = Depends(require_admin),
) -> dict:
    return list_alerts(limit=limit, offset=offset, instance_id=instance)


@router.delete("/alerts")
def delete_alerts(instance: str | None = InstanceId, user: str = Depends(require_admin)) -> dict:
    return {"ok": True, "deleted": clear_alerts(instance_id=instance)}


@router.post("/alerts/run")
def run_detection(instance: str | None = InstanceId, user: str = Depends(require_admin)) -> dict:
    created = run_cycle(instance_id=instance)
    return {"ok": True, "created": len(created), "alerts": created}


@router.get("/settings/detection")
def get_detection(instance: str | None = InstanceId, user: str = Depends(require_admin)) -> dict:
    return get_detection_settings(instance_id=instance)


@router.put("/settings/detection")
def put_detection(
    payload: DetectionSettings,
    instance: str | None = InstanceId,
    user: str = Depends(require_admin),
) -> dict:
    return update_detection_settings(payload.model_dump(exclude_none=True), instance_id=instance)


@router.get("/settings/notifications")
def get_notifications(user: str = Depends(require_admin)) -> dict:
    return get_smtp_settings(mask_password=True)


@router.put("/settings/notifications")
def put_notifications(payload: NotificationSettings, user: str = Depends(require_admin)) -> dict:
    return update_smtp_settings(payload.model_dump(exclude_none=True))


@router.post("/settings/notifications/test")
def test_notifications(user: str = Depends(require_admin)) -> dict:
    return send_test_email()


@router.get("/settings/notify")
def get_notify(instance: str | None = InstanceId, user: str = Depends(require_admin)) -> dict:
    return get_notify_settings(instance_id=instance, mask_token=True)


@router.put("/settings/notify")
def put_notify(
    payload: NotifySettings,
    instance: str | None = InstanceId,
    user: str = Depends(require_admin),
) -> dict:
    return update_notify_settings(payload.model_dump(exclude_none=True), instance_id=instance)


@router.post("/settings/notify/test")
def test_notify(instance: str | None = InstanceId, user: str = Depends(require_admin)) -> dict:
    label = instance_label(instance)
    return deliver(
        f"[{label}] Test de notification",
        "Ceci est un message de test envoyé par l'analyseur de logs OPNsense.",
        instance_id=instance,
        title=f"[{label}] Test",
        tags=["bell"],
    )


@router.get("/settings/blocking")
def get_blocking(instance: str | None = InstanceId, user: str = Depends(require_admin)) -> dict:
    return get_blocking_settings(instance_id=instance)


@router.put("/settings/blocking")
def put_blocking(
    payload: BlockingSettings,
    instance: str | None = InstanceId,
    user: str = Depends(require_admin),
) -> dict:
    return update_blocking_settings(payload.model_dump(exclude_none=True), instance_id=instance)


@router.post("/settings/blocking/detect-tables")
def detect_blocking_tables(
    instance: str | None = InstanceId, user: str = Depends(require_admin)
) -> dict:
    """Detect the pf block tables present on the firewall (CrowdSec, Q-Feeds...)."""
    tables = refresh_detected_tables(instance_id=instance)
    return {"ok": True, "tables": tables, "settings": get_blocking_settings(instance_id=instance)}


@router.post("/settings/blocking/reconcile")
def reconcile_blocking(instance: str | None = InstanceId, user: str = Depends(require_admin)) -> dict:
    """Re-add recorded blocks missing from the firewall alias (drift repair)."""
    return reconcile_alias(instance_id=instance)


@router.get("/settings/blocking/alias")
def get_blocking_alias(instance: str | None = InstanceId, user: str = Depends(require_admin)) -> dict:
    """Show the IPs actually present in the firewall alias."""
    return alias_ips(instance_id=instance)


@router.post("/settings/blocking/clean-alias")
def clean_blocking_alias(instance: str | None = InstanceId, user: str = Depends(require_admin)) -> dict:
    """Remove from the alias the IPs no longer tracked as blocked (orphans)."""
    return clean_alias_orphans(instance_id=instance)


@router.get("/settings/blocking/allowlist")
def get_allowlist(instance: str | None = InstanceId, user: str = Depends(require_admin)) -> dict:
    return {"items": list_allowlist(instance_id=instance)}


@router.post("/settings/blocking/allowlist")
def add_allowlist_endpoint(
    payload: AllowlistAdd,
    instance: str | None = InstanceId,
    user: str = Depends(require_admin),
) -> dict:
    added = add_allowlist(payload.ips, payload.note or "", instance_id=instance)
    return {"ok": True, "added": added, "items": list_allowlist(instance_id=instance)}


@router.delete("/settings/blocking/allowlist")
def remove_allowlist_endpoint(
    payload: AllowlistRemove,
    instance: str | None = InstanceId,
    user: str = Depends(require_admin),
) -> dict:
    removed = remove_allowlist(payload.ips, instance_id=instance)
    return {"ok": True, "removed": removed, "items": list_allowlist(instance_id=instance)}


@router.get("/blocking/list")
def get_blocked(instance: str | None = InstanceId, user: str = Depends(require_admin)) -> dict:
    return {"items": list_blocked(instance_id=instance)}


@router.post("/blocking/apply")
def block_now(
    payload: BlockRequest,
    instance: str | None = InstanceId,
    user: str = Depends(require_admin),
) -> dict:
    return apply_ips(payload.ips, rule="manual", source="manual", instance_id=instance)


@router.post("/blocking/permanent")
def block_now_permanent(
    payload: BlockRequest,
    instance: str | None = InstanceId,
    user: str = Depends(require_admin),
) -> dict:
    """Block the given IPs permanently (never expiring, only a manual removal)."""
    return block_permanently(payload.ips, instance_id=instance)


@router.post("/blocking/prune")
def prune_blocked(instance: str | None = InstanceId, user: str = Depends(require_admin)) -> dict:
    return {"ok": True, "removed": prune_expired(instance_id=instance)}


@router.post("/blocking/remove")
def unblock_now(
    payload: BlockRequest,
    instance: str | None = InstanceId,
    user: str = Depends(require_admin),
) -> dict:
    return unblock_ips(payload.ips, instance_id=instance)
