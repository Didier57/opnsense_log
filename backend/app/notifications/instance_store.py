"""Per-instance notification channel settings (e-mail vs ntfy).

SMTP itself stays application-global (see :mod:`app.notifications.store`); only
the *channel choice* and the ntfy target are per OPNsense instance, so each
firewall can notify a different phone/topic.
"""
from __future__ import annotations

from ..config import settings
from ..instances import resolve_instance_id
from ..storage.database import get_database

_STR_KEYS = ["notify_channel", "ntfy_url"]
_SECRET_KEYS = ["ntfy_token"]
_KEYS = _STR_KEYS + _SECRET_KEYS
_CHANNELS = {"email", "ntfy"}


def _overrides(instance_id: str | None = None) -> dict[str, str]:
    try:
        rows = (
            get_database(resolve_instance_id(instance_id))
            .execute_read('SELECT "key", "value" FROM app_settings')
            .fetchall()
        )
        return {row[0]: row[1] for row in rows}
    except Exception:  # noqa: BLE001 - settings must never break the caller
        return {}


def get_notify_settings(instance_id: str | None = None, mask_token: bool = True) -> dict:
    overrides = _overrides(instance_id)

    def value(key: str):
        return overrides.get(key, getattr(settings, key, ""))

    channel = str(value("notify_channel") or "email").strip().lower()
    if channel not in _CHANNELS:
        channel = "email"
    result = {
        "notify_channel": channel,
        "ntfy_url": str(value("ntfy_url") or ""),
        "has_ntfy_token": bool(value("ntfy_token")),
    }
    if not mask_token:
        result["ntfy_token"] = str(value("ntfy_token") or "")
    return result


def update_notify_settings(payload: dict, instance_id: str | None = None) -> dict:
    db = get_database(resolve_instance_id(instance_id))
    for key in _KEYS:
        if key in payload and payload[key] is not None:
            db.execute_write(
                'INSERT INTO app_settings ("key", "value", "updated_at") VALUES (?, ?, now()) '
                'ON CONFLICT ("key") DO UPDATE SET "value" = excluded."value", '
                '"updated_at" = excluded."updated_at"',
                [key, str(payload[key])],
            )
    return get_notify_settings(instance_id=instance_id)
