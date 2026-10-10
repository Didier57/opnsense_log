"""FastAPI dependencies (authentication)."""
from __future__ import annotations

from fastapi import Cookie, Depends, Header, HTTPException, status

from ..config import settings
from ..core.security import decode_token


def _extract_token(authorization: str | None, access_token: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return access_token


def _payload(authorization: str | None, access_token: str | None) -> dict:
    token = _extract_token(authorization, access_token)
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token")
    return payload


async def require_user(
    authorization: str | None = Header(default=None),
    access_token: str | None = Cookie(default=None),
) -> str:
    if not settings.auth_enabled:
        return settings.auth_username
    return _payload(authorization, access_token).get("sub", "")


async def current_identity(
    authorization: str | None = Header(default=None),
    access_token: str | None = Cookie(default=None),
) -> dict:
    """Return the authenticated identity as ``{"username", "role"}``."""
    if not settings.auth_enabled:
        return {"username": settings.auth_username, "role": "admin"}
    payload = _payload(authorization, access_token)
    return {"username": payload.get("sub", ""), "role": payload.get("role") or "admin"}


async def require_admin(
    authorization: str | None = Header(default=None),
    access_token: str | None = Cookie(default=None),
) -> str:
    identity = await current_identity(authorization, access_token)
    if identity["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required")
    return identity["username"]


CurrentUser = Depends(require_user)
AdminUser = Depends(require_admin)
CurrentIdentity = Depends(current_identity)


def pick_instance(instance: str | None = None) -> str | None:
    """Instance selector supplied by the client as the ``instance`` query param."""
    return instance


InstanceId = Depends(pick_instance)
