"""Minimal SMTP mailer supporting SSL, STARTTLS and unauthenticated relays."""
from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr, parseaddr

from .store import get_smtp_settings

logger = logging.getLogger("opnsense.mailer")

_TIMEOUT = 15


def _recipients(raw: str) -> list[str]:
    return [addr.strip() for addr in raw.replace(";", ",").split(",") if addr.strip()]


def send_email(subject: str, body: str, settings: dict | None = None, html: str | None = None) -> dict:
    """Send an email. Never raises; returns ``{"ok": bool, "message": str}``."""
    cfg = settings or get_smtp_settings(mask_password=False)
    host = cfg.get("smtp_host") or ""
    if not host:
        return {"ok": False, "message": "Serveur SMTP non configuré"}
    to_list = _recipients(cfg.get("smtp_to") or "")
    if not to_list:
        return {"ok": False, "message": "Aucun destinataire configuré"}

    from_email = cfg.get("smtp_from_email") or cfg.get("smtp_username") or "opnsense-log-analyzer@localhost"
    from_name = cfg.get("smtp_from_name") or ""
    _, from_addr = parseaddr(from_email)

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((from_name, from_addr))
    message["To"] = ", ".join(to_list)
    message.set_content(body)
    if html:
        message.add_alternative(html, subtype="html")

    port = int(cfg.get("smtp_port") or 587)
    security = str(cfg.get("smtp_security") or "starttls").lower()
    username = cfg.get("smtp_username") or ""
    password = cfg.get("smtp_password") or ""

    try:
        if security == "ssl":
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, timeout=_TIMEOUT, context=context) as server:
                if username:
                    server.login(username, password)
                server.send_message(message)
        else:
            with smtplib.SMTP(host, port, timeout=_TIMEOUT) as server:
                server.ehlo()
                if security == "starttls":
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                if username:
                    server.login(username, password)
                server.send_message(message)
    except Exception as exc:  # noqa: BLE001 - report, never crash the caller
        logger.warning("SMTP send failed: %s", exc)
        return {"ok": False, "message": f"Échec de l'envoi : {exc}"}
    return {"ok": True, "message": f"E-mail envoyé à {', '.join(to_list)}"}


def send_test_email() -> dict:
    return send_email(
        "[OPNsense Log Analyzer] Test de notification",
        "Ceci est un e-mail de test envoyé depuis l'Analyseur de logs OPNsense.\n"
        "Si vous lisez ce message, la configuration SMTP est correcte.",
    )
