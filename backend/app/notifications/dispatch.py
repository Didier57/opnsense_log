"""Deliver a notification through the per-instance channels.

Callers pass the message once; this module reads the instance's channel choices
(e-mail and/or ntfy, which can be enabled together) and sends it with each
enabled transport. It never raises.
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
    ntfy_body: str | None = None,
) -> dict:
    """Send using the instance's enabled channels. Returns {ok, message, channel}."""
    try:
        cfg = get_notify_settings(instance_id, mask_token=False)
    except Exception:  # noqa: BLE001 - fall back to e-mail
        cfg = {"notify_email": True, "notify_ntfy": False, "ntfy_url": "", "ntfy_token": ""}

    channels: list[str] = []
    results: list[dict] = []

    if cfg.get("notify_email"):
        channels.append("email")
        results.append(send_email(subject, body, html=html))

    ntfy_url = str(cfg.get("ntfy_url") or "").strip()
    if cfg.get("notify_ntfy") and ntfy_url:
        channels.append("ntfy")
        results.append(
            send_ntfy(
                ntfy_url,
                title or subject,
                body if ntfy_body is None else ntfy_body,
                priority=priority,
                tags=tags,
                actions=actions,
                token=cfg.get("ntfy_token") or None,
            )
        )

    if not results:
        return {"ok": False, "message": "Aucun canal de notification activé", "channel": ""}

    message = " ; ".join(str(r.get("message", "")) for r in results if r.get("message"))
    return {
        "ok": any(r.get("ok") for r in results),
        "message": message,
        "channel": "+".join(channels),
        "results": results,
    }
