"""Tests for session lifetime: token length and sliding refresh."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
from starlette.responses import Response

from app.config import settings
from app.core import security as sec


class _Request:
    def __init__(self, cookies: dict[str, str]) -> None:
        self.cookies = cookies


def test_default_token_lifetime_is_one_week(monkeypatch):
    monkeypatch.setattr(settings, "token_expire_minutes", 10080)
    token = sec.create_token("alice", "admin")

    payload = jwt.decode(token, settings.secret_key, algorithms=[sec.ALGORITHM])

    assert payload["sub"] == "alice"
    assert payload["role"] == "admin"
    # ~7 days, allowing for a few seconds of clock drift while encoding.
    assert 10080 * 60 - 60 <= payload["exp"] - payload["iat"] <= 10080 * 60 + 60


def _token(minutes_left: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=minutes_left)
    return jwt.encode(
        {"sub": "alice", "role": "admin", "exp": expire, "iat": datetime.now(timezone.utc)},
        settings.secret_key,
        algorithm=sec.ALGORITHM,
    )


def test_active_session_is_slid_forward(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "token_expire_minutes", 60)
    response = Response()

    refreshed = sec.refresh_session_if_needed(_Request({sec.COOKIE_NAME: _token(10)}), response)

    assert refreshed is True
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{sec.COOKIE_NAME}=")
    assert "Max-Age=3600" in cookie


def test_recent_token_is_not_refreshed(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "token_expire_minutes", 60)
    response = Response()

    refreshed = sec.refresh_session_if_needed(_Request({sec.COOKIE_NAME: _token(50)}), response)

    assert refreshed is False
    assert "set-cookie" not in response.headers


def test_expired_or_missing_token_is_ignored(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", True)
    response = Response()

    assert sec.refresh_session_if_needed(_Request({}), response) is False
    assert sec.refresh_session_if_needed(_Request({sec.COOKIE_NAME: _token(-5)}), response) is False
    assert "set-cookie" not in response.headers


def test_no_refresh_when_auth_disabled(monkeypatch):
    monkeypatch.setattr(settings, "auth_enabled", False)
    response = Response()

    assert sec.refresh_session_if_needed(_Request({sec.COOKIE_NAME: _token(1)}), response) is False
