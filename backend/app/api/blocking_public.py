"""Public (unauthenticated) unblock endpoints reached from notification e-mails.

The e-mail button opens a confirmation page; only the explicit POST actually
removes the IP, so mail-client link prefetching cannot unblock anything.
"""
from __future__ import annotations

import html
import logging

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse

from ..core.security import decode_unblock_token_data
from ..opnsense.blocker import unblock_ips

logger = logging.getLogger("opnsense.blocking_public")

router = APIRouter(prefix="/api/blocking", tags=["blocking"])

_STYLE = (
    "font-family:Arial,Helvetica,sans-serif;max-width:520px;margin:60px auto;padding:24px;"
    "border:1px solid #e5e7eb;border-radius:10px;color:#111827;text-align:center"
)
_BUTTON = (
    "display:inline-block;padding:10px 22px;background:#dc2626;color:#fff;text-decoration:none;"
    "border:none;border-radius:6px;font-size:15px;font-weight:600;cursor:pointer"
)


def _page(title: str, message: str, content: str = "") -> str:
    return (
        "<!doctype html><html lang='fr'><head><meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title></head>"
        f"<body style='background:#f9fafb'><div style='{_STYLE}'>"
        f"<h2 style='margin:0 0 12px'>{html.escape(title)}</h2>"
        f"<p style='color:#374151'>{html.escape(message)}</p>{content}</div></body></html>"
    )


@router.get("/unblock")
def unblock_page(token: str = Query(default="")) -> HTMLResponse:
    data = decode_unblock_token_data(token)
    ip = (data or {}).get("ip") or ""
    if not ip:
        return HTMLResponse(
            _page("Lien invalide", "Ce lien de déblocage est invalide ou a expiré."),
            status_code=400,
        )
    form = (
        "<form method='post' action='/api/blocking/unblock' style='margin-top:18px'>"
        f"<input type='hidden' name='token' value='{html.escape(token)}'>"
        f"<button type='submit' style='{_BUTTON}'>Débloquer {html.escape(ip)}</button>"
        "</form>"
    )
    return HTMLResponse(_page("Débloquer une IP", f"Confirmer le déblocage de l'adresse {ip} ?", form))


@router.post("/unblock")
async def unblock_confirm(request: Request) -> HTMLResponse:
    form = await request.form()
    token = str(form.get("token") or "")
    data = decode_unblock_token_data(token)
    ip = (data or {}).get("ip") or ""
    instance_id = (data or {}).get("instance_id") or None
    if not ip:
        return HTMLResponse(
            _page("Lien invalide", "Ce lien de déblocage est invalide ou a expiré."),
            status_code=400,
        )
    try:
        result = unblock_ips([ip], instance_id=instance_id)
    except Exception:  # noqa: BLE001
        logger.exception("Unblock failed")
        return HTMLResponse(
            _page("Erreur", "Le déblocage a échoué. Réessayez depuis l'application."),
            status_code=500,
        )
    if not result.get("ok"):
        return HTMLResponse(_page("Erreur", str(result.get("error") or "Le déblocage a échoué.")))
    return HTMLResponse(_page("IP débloquée", f"L'adresse {ip} a bien été retirée de la liste de blocage."))
