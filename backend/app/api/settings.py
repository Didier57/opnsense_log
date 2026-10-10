"""Application settings endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..config import settings
from ..opnsense.api_client import OPNsenseAPI
from ..opnsense.api_keygen import generate_api_key
from ..opnsense.config_loader import parse_webgui
from ..opnsense.settings_store import get_opnsense_settings, update_opnsense_settings
from ..opnsense.ssh import OPNsenseSSH, SSHError
from ..settings_store import get_app_settings, update_app_settings
from .deps import InstanceId, require_user
from .schemas import ApplicationSettings, OPNsenseSettings

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
def get_settings(instance: str | None = InstanceId, user: str = Depends(require_user)) -> dict:
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
        "opnsense": get_opnsense_settings(mask_password=True, instance_id=instance),
    }


@router.get("/application")
def get_application(user: str = Depends(require_user)) -> dict:
    return get_app_settings()


@router.put("/application")
def put_application(payload: ApplicationSettings, user: str = Depends(require_user)) -> dict:
    return update_app_settings(payload.model_dump(exclude_none=True))



@router.get("/opnsense")
def get_opnsense(instance: str | None = InstanceId, user: str = Depends(require_user)) -> dict:
    return get_opnsense_settings(mask_password=True, instance_id=instance)


@router.put("/opnsense")
def put_opnsense(
    payload: OPNsenseSettings, instance: str | None = InstanceId, user: str = Depends(require_user)
) -> dict:
    return update_opnsense_settings(payload.model_dump(exclude_none=True), instance_id=instance)


@router.post("/opnsense/test")
def test_opnsense(instance: str | None = InstanceId, user: str = Depends(require_user)) -> dict:
    cfg = get_opnsense_settings(mask_password=False, instance_id=instance)
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


@router.post("/opnsense/generate-api-key")
def generate_opnsense_api_key(
    instance: str | None = InstanceId, user: str = Depends(require_user)
) -> dict:
    cfg = get_opnsense_settings(mask_password=False, instance_id=instance)
    if not cfg.get("opnsense_host"):
        return {"ok": False, "message": "OPNsense host not configured"}
    result = generate_api_key(cfg.get("opnsense_username") or "root", instance_id=instance)
    if not result.get("ok"):
        return {"ok": False, "message": result.get("error", "generation failed")}
    update_opnsense_settings(
        {"opnsense_api_key": result["key"], "opnsense_api_secret": result["secret"]},
        instance_id=instance,
    )
    return {"ok": True, "message": "Clé API générée et enregistrée"}


@router.post("/opnsense/detect-api")
def detect_opnsense_api(instance: str | None = InstanceId, user: str = Depends(require_user)) -> dict:
    """Detect the web GUI protocol/port over SSH (the API shares that endpoint)."""
    cfg = get_opnsense_settings(mask_password=False, instance_id=instance)
    if not cfg.get("opnsense_host"):
        return {"ok": False, "message": "OPNsense host not configured"}
    try:
        client = OPNsenseSSH(
            host=cfg["opnsense_host"],
            port=cfg["opnsense_ssh_port"],
            username=cfg["opnsense_username"],
            auth_type=cfg["opnsense_auth_type"],
            password=cfg.get("opnsense_password"),
            key_path=cfg["opnsense_key_path"],
        )
        contents = client.run("cat /conf/config.xml")
    except SSHError as exc:
        return {"ok": False, "message": str(exc)}
    webgui = parse_webgui(contents)
    update_opnsense_settings(
        {"opnsense_api_scheme": webgui["protocol"], "opnsense_api_port": webgui["port"]},
        instance_id=instance,
    )
    return {
        "ok": True,
        "message": f"Détecté : {webgui['protocol']} port {webgui['port']}",
        "protocol": webgui["protocol"],
        "port": webgui["port"],
    }


@router.post("/opnsense/api-test")
def test_opnsense_api(instance: str | None = InstanceId, user: str = Depends(require_user)) -> dict:
    cfg = get_opnsense_settings(mask_password=False, instance_id=instance)
    if not cfg.get("opnsense_host"):
        return {"ok": False, "message": "OPNsense host not configured"}
    api = OPNsenseAPI(
        host=cfg["opnsense_host"],
        port=int(cfg.get("opnsense_api_port", 443) or 443),
        scheme=cfg.get("opnsense_api_scheme", "https") or "https",
        key=cfg.get("opnsense_api_key", ""),
        secret=cfg.get("opnsense_api_secret", ""),
    )
    return api.test_connection()
