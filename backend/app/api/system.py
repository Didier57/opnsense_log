"""System status and internal logs endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..config import settings
from ..core.logging import ring_handler
from ..core.stats import get_counters
from ..instances import get_instance, resolve_instance_id
from ..opnsense.settings_store import get_opnsense_settings
from ..opnsense.ssh import OPNsenseSSH
from ..storage.database import get_database
from ..syslog.server import get_syslog_server
from ..websocket.live import get_live_hub
from .deps import InstanceId, require_user

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/status")
def status(instance: str | None = InstanceId, user: str = Depends(require_user)) -> dict:
    db_ok = True
    try:
        get_database(resolve_instance_id(instance)).execute_read("SELECT 1").fetchone()
    except Exception:  # noqa: BLE001
        db_ok = False

    opnsense_ok = False
    ssh_error = ""
    cfg = get_opnsense_settings(mask_password=False, instance_id=instance)
    if cfg["opnsense_host"]:
        client = OPNsenseSSH(
            host=cfg["opnsense_host"],
            port=cfg["opnsense_ssh_port"],
            username=cfg["opnsense_username"],
            auth_type=cfg["opnsense_auth_type"],
            password=cfg.get("opnsense_password"),
            key_path=cfg["opnsense_key_path"],
        )
        try:
            opnsense_ok = client.test_connection()
        except Exception as exc:  # noqa: BLE001
            ssh_error = str(exc)

    inst = get_instance(resolve_instance_id(instance)) or {}
    return {
        "syslog": {"connected": get_syslog_server(instance).connected,
                    "protocol": inst.get("syslog_protocol") or settings.syslog_protocol,
                    "port": inst.get("syslog_port") or settings.syslog_port},
        "database": {"ok": db_ok},
        "opnsense": {"connected": opnsense_ok, "configured": bool(cfg["opnsense_host"]), "error": ssh_error},
        "websocket": {"running": True, "subscribers": get_live_hub(instance).subscriber_count},
        "storage": {"data_dir": settings.data_dir, "retention_days": settings.log_retention_days},
        "counters": get_counters(instance).snapshot(),
    }


@router.get("/logs")
def logs(limit: int = 200, user: str = Depends(require_user)) -> dict:
    items = list(reversed(ring_handler.records[-limit:]))
    return {"items": items}
