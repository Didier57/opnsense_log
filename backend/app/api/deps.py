"""FastAPI dependencies (authentication)."""
from __future__ import annotations

from fastapi import Cookie, Depends, Header, HTTPException, status

from ..config import settings
from ..core.security import decode_token


def _extract_token(authorization: str | None, access_token: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return access_token


async def require_user(
    authorization: str | None = Header(default=None),
    access_token: str | None = Cookie(default=None),
) -> str:
    if not settings.auth_enabled:
        return settings.auth_username
    token = _extract_token(authorization, access_token)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return payload.get("sub", "")


CurrentUser = Depends(require_user)
