"""Application settings endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..config import settings
from ..opnsense.settings_store import get_opnsense_settings, update_opnsense_settings
from ..opnsense.ssh import OPNsenseSSH
from .deps import require_user
from .schemas import OPNsenseSettings

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
def get_settings(user: str = Depends(require_user)) -> dict:
    return {
        "syslog": {
            "port": settings.syslog_port,
            "protocol": settings.syslog_protocol,
            "queue_maxsize": settings.syslog_queue_maxsize,
            "workers": settings.parser_workers,
        },
        "storage": {
            "data_dir": settings.data_dir,
            "retention_days": settings.log_retention_days,
            "batch_size": settings.batch_size,
        },
        "application": {
            "auth_enabled": settings.auth_enabled,
            "display_timezone": settings.display_timezone,
            "log_level": settings.log_level,
        },
        "opnsense": get_opnsense_settings(mask_password=True),
    }


@router.get("/opnsense")
def get_opnsense(user: str = Depends(require_user)) -> dict:
    return get_opnsense_settings(mask_password=True)


@router.put("/opnsense")
def put_opnsense(payload: OPNsenseSettings, user: str = Depends(require_user)) -> dict:
    return update_opnsense_settings(payload.model_dump(exclude_none=True))


@router.post("/opnsense/test")
def test_opnsense(user: str = Depends(require_user)) -> dict:
    cfg = get_opnsense_settings(mask_password=False)
    client = OPNsenseSSH(
        host=cfg["host"],
        port=cfg["port"],
        username=cfg["username"],
        auth_type=cfg["auth_type"],
        password=cfg.get("password"),
        key_path=cfg["key_path"],
    )
    ok = client.test_connection()
    return {"ok": ok, "message": "connection successful" if ok else "connection failed"}
