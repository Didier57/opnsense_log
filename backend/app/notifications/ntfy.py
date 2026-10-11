"""Minimal ntfy.sh (or self-hosted) publisher used for notifications.

The target is a full topic URL such as ``https://ntfy.sh/mon-sujet`` (or a
self-hosted server). Messages are published with the JSON API on the server
root so that optional action buttons are supported.
"""
from __future__ import annotations

import json
import logging
from urllib.parse import urlsplit, urlunsplit

import httpx

logger = logging.getLogger("opnsense.ntfy")

_TIMEOUT = 10.0
_PRIORITY_NAMES = {"min": 1, "low": 2, "default": 3, "high": 4, "urgent": 5}


def _split_topic(url: str) -> tuple[str, str]:
    """Return ``(base_url, topic)`` for a full topic URL (topic = last segment)."""
    parts = urlsplit((url or "").strip())
    path = parts.path.rstrip("/")
    if not parts.scheme or not parts.netloc or not path:
        return "", ""
    topic = path.split("/")[-1]
    base_path = path[: len(path) - len(topic)].rstrip("/")
    return urlunsplit((parts.scheme, parts.netloc, base_path, "", "")), topic


def _priority(value: str):
    text = str(value or "").strip().lower()
    if text.isdigit():
        return int(text)
    return _PRIORITY_NAMES.get(text, 3)


def send_ntfy(
    url: str,
    title: str,
    message: str,
    priority: str = "default",
    tags: list[str] | None = None,
    actions: list[dict] | None = None,
    token: str | None = None,
) -> dict:
    """Publish a message to an ntfy topic. Never raises; returns {ok, message}."""
    base, topic = _split_topic(url)
    if not base:
        return {"ok": False, "message": "URL NTFY invalide (ex. https://ntfy.sh/mon-sujet)"}
    payload: dict = {"topic": topic, "message": message, "priority": _priority(priority)}
    if title:
        payload["title"] = title
    if tags:
        payload["tags"] = list(tags)
    if actions:
        payload["actions"] = list(actions)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        response = httpx.post(
            base,
            content=json.dumps(payload).encode("utf-8"),
            headers=headers,
            timeout=_TIMEOUT,
        )
        if response.status_code >= 400:
            return {"ok": False, "message": f"NTFY a répondu {response.status_code}"}
        return {"ok": True, "message": "Notification NTFY envoyée"}
    except Exception as exc:  # noqa: BLE001 - notifications must never raise
        logger.warning("NTFY send failed: %s", exc)
        return {"ok": False, "message": f"Échec NTFY : {exc}"}
