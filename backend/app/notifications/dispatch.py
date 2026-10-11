"""Deliver a notification through the per-instance channel (e-mail or ntfy).

Callers pass the message once; this module reads the instance's channel choice
and sends it with the matching transport. It never raises.
"""
from __future__ import annotations

from .instance_store import get_notify_settings
from .mailer import send_email
from .ntfy import send_ntfy


def deliver(
    subject: str,
    body: str,
    html: str | None = None,
    *,
    instance_id: str | None = None,
    title: str | None = None,
    priority: str = "default",
    tags: list[str] | None = None,
    actions: list[dict] | None = None,
) -> dict:
    """Send using the instance's configured channel. Returns {ok, message, channel}."""
    try:
        cfg = get_notify_settings(instance_id, mask_token=False)
    except Exception:  # noqa: BLE001 - fall back to e-mail
        cfg = {"notify_channel": "email", "ntfy_url": "", "ntfy_token": ""}
    channel = cfg.get("notify_channel") or "email"
    if channel == "ntfy":
        result = send_ntfy(
            cfg.get("ntfy_url") or "",
            title or subject,
            body,
            priority=priority,
            tags=tags,
            actions=actions,
            token=cfg.get("ntfy_token") or None,
        )
    else:
        result = send_email(subject, body, html=html)
    result["channel"] = channel
    return result
