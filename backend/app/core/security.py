"""Authentication helpers: password hashing and JWT sessions."""
from __future__ import annotations

import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from ..config import settings

_hasher = PasswordHasher()
ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, Exception):  # noqa: BLE001
        return False


def verify_login_password(password: str) -> bool:
    """Verify a login password against the configured secret.

    An argon2 hash (AUTH_PASSWORD_HASH) takes precedence when set, otherwise the
    plain-text AUTH_PASSWORD is compared in constant time.
    """
    if settings.auth_password_hash:
        return verify_password(password, settings.auth_password_hash)
    if settings.auth_password:
        return secrets.compare_digest(password, settings.auth_password)
    return False


def create_token(username: str, role: str = "admin") -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.token_expire_minutes)
    payload = {
        "sub": username,
        "role": role or "admin",
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


COOKIE_NAME = "access_token"


def set_session_cookie(response, username: str, role: str) -> str:
    """Issue a session token and store it in the browser cookie.

    Shared by the login/setup endpoints and the sliding-refresh middleware so
    both always apply the same cookie attributes.
    """
    token = create_token(username, role)
    response.set_cookie(
        COOKIE_NAME,
        token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=settings.token_expire_minutes * 60,
    )
    return token


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None


def refresh_session_if_needed(request, response) -> bool:
    """Slide an active session forward by reissuing its cookie.

    The cookie is renewed only during the second half of the token lifetime, so
    a visitor who keeps using the site is never logged out mid-session while a
    single ``Set-Cookie`` is emitted per half-window instead of on every call.
    Returns ``True`` when a fresh cookie was written.
    """
    if not settings.auth_enabled:
        return False
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return False
    payload = decode_token(token)
    if payload is None:
        return False
    expires_at = payload.get("exp")
    if isinstance(expires_at, (int, float)) and expires_at - time.time() > (
        settings.token_expire_minutes * 60
    ) / 2:
        return False
    set_session_cookie(response, payload.get("sub", ""), payload.get("role") or "admin")
    return True


def create_unblock_token(ip: str, days: int = 7, instance_id: str | None = None) -> str:
    """Signed, expiring token authorising the unblock of a single IP.

    The token also carries the instance the IP was blocked on so the unblock
    page edits the right firewall.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "scope": "unblock",
        "ip": ip,
        "instance_id": instance_id or "",
        "exp": now + timedelta(days=max(1, int(days))),
        "iat": now,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_unblock_token_data(token: str) -> dict | None:
    """Return the full payload of a valid unblock token, else ``None``."""
    if not token:
        return None
    try:
        data = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None
    if data.get("scope") != "unblock":
        return None
    return data


def decode_unblock_token(token: str) -> str | None:
    """Return the IP carried by a valid unblock token, else ``None``."""
    data = decode_unblock_token_data(token)
    return (data.get("ip") or None) if data else None
