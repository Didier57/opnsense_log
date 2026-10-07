"""Authentication helpers: password hashing and JWT sessions."""
from __future__ import annotations

import secrets
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


def create_token(username: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.token_expire_minutes)
    payload = {"sub": username, "exp": expire, "iat": datetime.now(timezone.utc)}
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None


def create_unblock_token(ip: str, days: int = 7) -> str:
    """Signed, expiring token authorising the unblock of a single IP."""
    now = datetime.now(timezone.utc)
    payload = {
        "scope": "unblock",
        "ip": ip,
        "exp": now + timedelta(days=max(1, int(days))),
        "iat": now,
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_unblock_token(token: str) -> str | None:
    """Return the IP carried by a valid unblock token, else ``None``."""
    if not token:
        return None
    try:
        data = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None
    if data.get("scope") != "unblock":
        return None
    return data.get("ip") or None
