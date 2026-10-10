"""User accounts and roles, stored in the system database.

Accounts live in the ``users`` table of the system database (never the
per-instance databases). Passwords are stored as argon2 hashes. Two roles are
supported: ``admin`` (full management) and ``viewer`` (read-only logs/analysis).
"""
from __future__ import annotations

from ..config import settings
from ..storage.database import get_database
from .security import hash_password, verify_password

ROLES = ("admin", "viewer")
DEFAULT_ROLE = "viewer"


class UserError(ValueError):
    """Raised for invalid user management operations (mapped to HTTP 400)."""


def _db():
    return get_database()


def _norm(username: str | None) -> str:
    return (username or "").strip()


def _validate_role(role: str | None) -> str:
    value = (role or "").strip().lower() or DEFAULT_ROLE
    if value not in ROLES:
        raise UserError(f"rôle invalide : {role}")
    return value


def count_users() -> int:
    row = _db().execute_read('SELECT COUNT(*) FROM users').fetchone()
    return int(row[0]) if row else 0


def count_admins() -> int:
    row = _db().execute_read('SELECT COUNT(*) FROM users WHERE "role" = \'admin\'').fetchone()
    return int(row[0]) if row else 0


def list_users() -> list[dict]:
    rows = _db().execute_read(
        'SELECT "username", "role", "created_at", "last_login_at" FROM users '
        'ORDER BY lower("username")'
    ).fetchall()
    return [
        {
            "username": r[0],
            "role": r[1] or "admin",
            "created_at": r[2].isoformat() if r[2] else None,
            "last_login_at": r[3].isoformat() if r[3] else None,
        }
        for r in rows
    ]


def get_user(username: str) -> dict | None:
    """Return the account (including its password hash) or ``None``."""
    row = _db().execute_read(
        'SELECT "username", "password_hash", "role", "created_at", "last_login_at" '
        'FROM users WHERE "username" = ?',
        [_norm(username)],
    ).fetchone()
    if not row:
        return None
    return {
        "username": row[0],
        "password_hash": row[1] or "",
        "role": row[2] or "admin",
        "created_at": row[3].isoformat() if row[3] else None,
        "last_login_at": row[4].isoformat() if row[4] else None,
    }


def authenticate(username: str, password: str) -> dict | None:
    user = get_user(username)
    if not user or not user["password_hash"]:
        return None
    if not verify_password(password or "", user["password_hash"]):
        return None
    return user


def create_user(
    username: str,
    password: str,
    role: str = DEFAULT_ROLE,
    password_hash: str | None = None,
) -> dict:
    name = _norm(username)
    if not name:
        raise UserError("le nom d'utilisateur est obligatoire")
    if get_user(name):
        raise UserError("ce nom d'utilisateur existe déjà")
    if password_hash is None:
        if len(password or "") < 4:
            raise UserError("le mot de passe doit contenir au moins 4 caractères")
        hashed = hash_password(password)
    else:
        hashed = password_hash
    _db().execute_write(
        'INSERT INTO users ("username", "password_hash", "role", "created_at") '
        "VALUES (?, ?, ?, now())",
        [name, hashed, _validate_role(role)],
    )
    return get_user(name)


def update_user(
    username: str,
    *,
    role: str | None = None,
    password: str | None = None,
) -> dict | None:
    name = _norm(username)
    user = get_user(name)
    if not user:
        return None
    if role is not None:
        new_role = _validate_role(role)
        if user["role"] == "admin" and new_role != "admin" and count_admins() <= 1:
            raise UserError("impossible de rétrograder le dernier administrateur")
        _db().execute_write('UPDATE users SET "role" = ? WHERE "username" = ?', [new_role, name])
    if password:
        _db().execute_write(
            'UPDATE users SET "password_hash" = ? WHERE "username" = ?',
            [hash_password(password), name],
        )
    return get_user(name)


def delete_user(username: str) -> bool:
    name = _norm(username)
    user = get_user(name)
    if not user:
        return False
    if user["role"] == "admin" and count_admins() <= 1:
        raise UserError("impossible de supprimer le dernier administrateur")
    _db().execute_write('DELETE FROM users WHERE "username" = ?', [name])
    return True


def set_last_login(username: str) -> None:
    try:
        _db().execute_write('UPDATE users SET "last_login_at" = now() WHERE "username" = ?', [_norm(username)])
    except Exception:  # noqa: BLE001 - best effort
        pass


def bootstrap_env_admin() -> str | None:
    """Create the first administrator from the .env credentials, if configured.

    Only runs when no account exists yet. The default ``admin``/``admin`` pair is
    intentionally ignored so a fresh install forces the registration page.
    """
    if count_users() > 0:
        return None
    username = _norm(settings.auth_username)
    if not username:
        return None
    if settings.auth_password_hash:
        create_user(username, "", "admin", password_hash=settings.auth_password_hash)
        return username
    password = settings.auth_password or ""
    if not password or (username == "admin" and password == "admin"):
        return None
    create_user(username, password, "admin")
    return username
