"""E-mail notification when IPs are blocked, with a one-click unblock link.

The link carries a signed, expiring token (see :mod:`app.core.security`) so it
works without a login. Because some mail clients prefetch links, the link opens
a confirmation page rather than unblocking immediately.
"""
from __future__ import annotations

import html as html_lib
import logging

from ..core.security import create_unblock_token
from ..settings_store import get_public_url
from .mailer import send_email

logger = logging.getLogger("opnsense.blocking_mail")

_RULE_LABELS = {
    "port_scan": "Scan de ports",
    "bruteforce": "Force brute",
    "traffic_spike": "Pic de trafic",
    "detection": "Détection automatique",
    "manual": "Blocage manuel",
}


def _unblock_url(ip: str, days: int) -> str:
    base = get_public_url()
    if not base:
        return ""
    return f"{base}/api/blocking/unblock?token={create_unblock_token(ip, days)}"


def _html_page(rows: list[dict]) -> str:
    body = ""
    for row in rows:
        ip = html_lib.escape(row["ip"])
        reason = html_lib.escape(row["reason"])
        url = row["url"]
        if url:
            button = (
                f'<a href="{html_lib.escape(url)}" '
                'style="display:inline-block;padding:8px 16px;background:#dc2626;color:#ffffff;'
                'text-decoration:none;border-radius:6px;font-weight:600">Débloquer cette IP</a>'
            )
        else:
            button = '<span style="color:#888">URL publique non configurée</span>'
        body += (
            "<tr>"
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace">{ip}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{reason}</td>'
            f'<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb">{button}</td>'
            "</tr>"
        )
    return (
        '<html><body style="font-family:Arial,Helvetica,sans-serif;color:#111827">'
        '<h2 style="margin:0 0 12px">Adresse(s) IP bloquée(s)</h2>'
        '<p style="margin:0 0 16px;color:#374151">Une ou plusieurs adresses IP viennent d\'être ajoutées '
        'à la liste de blocage du pare-feu. Vous pouvez les débloquer en un clic ci-dessous.</p>'
        '<table style="border-collapse:collapse;width:100%;max-width:720px">'
        '<thead><tr>'
        '<th style="text-align:left;padding:8px 12px;border-bottom:2px solid #d1d5db">IP</th>'
        '<th style="text-align:left;padding:8px 12px;border-bottom:2px solid #d1d5db">Raison</th>'
        '<th style="text-align:left;padding:8px 12px;border-bottom:2px solid #d1d5db"></th>'
        '</tr></thead>'
        f"<tbody>{body}</tbody></table>"
        '<p style="margin:16px 0 0;color:#6b7280;font-size:12px">'
        "Le lien de déblocage est signé et limité dans le temps ; il n'exige aucune authentification.</p>"
        "</body></html>"
    )


def send_block_notification(ips: list[str], rule: str = "", reasons: dict | None = None, days: int = 7) -> dict:
    """Send a single e-mail listing the blocked IPs (one unblock button each)."""
    targets = [str(ip or "").strip() for ip in ips if str(ip or "").strip()]
    if not targets:
        return {"ok": False, "message": "Aucune IP à notifier"}
    reasons = reasons or {}
    default_reason = _RULE_LABELS.get(rule, rule or "Détection")

    rows: list[dict] = []
    lines: list[str] = []
    for ip in targets:
        reason = str(reasons.get(ip) or default_reason)
        url = _unblock_url(ip, days)
        rows.append({"ip": ip, "reason": reason, "url": url})
        lines.append(f"- {ip} — {reason}" + (f"\n  Débloquer : {url}" if url else ""))

    subject = "[OPNsense Log Analyzer] IP bloquée : " + ", ".join(targets)
    body = "Les adresses IP suivantes ont été bloquées :\n\n" + "\n".join(lines) + "\n"
    if not get_public_url():
        body += (
            "\n(Renseignez l'URL publique dans Paramètres → Application "
            "pour activer le lien de déblocage.)\n"
        )
    result = send_email(subject, body, html=_html_page(rows))
    if not result.get("ok"):
        logger.warning("Block notification not sent: %s", result.get("message"))
    return result
