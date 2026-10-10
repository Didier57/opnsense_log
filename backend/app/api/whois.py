"""WHOIS lookup endpoint (integrated, no third-party web service)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..whois import lookup
from .deps import require_user

router = APIRouter(prefix="/api/whois", tags=["whois"])


@router.get("")
def whois(ip: str, user: str = Depends(require_user)) -> dict:
    try:
        text = lookup(ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except OSError as exc:
        raise HTTPException(status_code=502, detail=f"WHOIS indisponible : {exc}")
    return {"ip": ip, "text": text}
