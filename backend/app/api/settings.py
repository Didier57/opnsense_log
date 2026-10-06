"""Application settings endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..config import settings
from ..opnsense.settings_store import get_opnsense_settings, update_opnsense_settings
from ..opnsense.ssh import OPNsenseSSH
from ..settings_store import get_app_settings, update_app_settings
from .deps import require_user
from .schemas import ApplicationSettings, OPNsenseSettings

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
def get_settings(user: str = Depends(require_user)) -> dict:
    app_cfg = get_app_settings()
    return {
        "syslog": {
            "port": settings.syslog_port,
            "protocol": settings.syslog_protocol,
            "queue_maxsize": settings.syslog_queue_maxsize,
            "workers": settings.parser_workers,
        },
        "storage": {
            "data_dir": settings.data_dir,
            "retention_days": app_cfg["log_retention_days"],
            "batch_size": settings.batch_size,
        },
        "application": {
            "auth_enabled": settings.auth_enabled,
            "display_timezone": app_cfg["display_timezone"],
            "log_level": settings.log_level,
            "retention_check_interval_min": app_cfg["retention_check_interval_min"],
        },
        "opnsense": get_opnsense_settings(mask_password=True),
    }


@router.get("/application")
def get_application(user: str = Depends(require_user)) -> dict:
    return get_app_settings()


@router.put("/application")
def put_application(payload: ApplicationSettings, user: str = Depends(require_user)) -> dict:
    return update_app_settings(payload.model_dump(exclude_none=True))



@router.get("/opnsense")
def get_opnsense(user: str = Depends(require_user)) -> dict:
    return get_opnsense_settings(mask_password=True)


@router.put("/opnsense")
def put_opnsense(payload: OPNsenseSettings, user: str = Depends(require_user)) -> dict:
    return update_opnsense_settings(payload.model_dump(exclude_none=True))


@router.post("/opnsense/test")
def test_opnsense(user: str = Depends(require_user)) -> dict:
    cfg = get_opnsense_settings(mask_password=False)
    if not cfg.get("opnsense_host"):
        return {"ok": False, "message": "OPNsense host not configured"}
    client = OPNsenseSSH(
        host=cfg["opnsense_host"],
        port=cfg["opnsense_ssh_port"],
        username=cfg["opnsense_username"],
        auth_type=cfg["opnsense_auth_type"],
        password=cfg.get("opnsense_password"),
        key_path=cfg["opnsense_key_path"],
    )
    ok = client.test_connection()
    return {"ok": ok, "message": "connection successful" if ok else "connection failed"}
