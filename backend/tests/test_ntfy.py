"""Tests for the ntfy notifier, per-instance notify settings and dispatch."""
from __future__ import annotations

import json

from app.notifications import instance_store as ns
from app.notifications import ntfy
from app.notifications import dispatch


class _Resp:
    def __init__(self, status_code: int = 200) -> None:
        self.status_code = status_code


def test_split_topic_full_url() -> None:
    assert ntfy._split_topic("https://ntfy.sh/my-topic") == ("https://ntfy.sh", "my-topic")


def test_split_topic_self_hosted_path() -> None:
    assert ntfy._split_topic("https://notify.example.com/ntfy/alerts") == (
        "https://notify.example.com/ntfy",
        "alerts",
    )


def test_split_topic_invalid() -> None:
    assert ntfy._split_topic("") == ("", "")
    assert ntfy._split_topic("not-a-url") == ("", "")


def test_send_ntfy_posts_json(monkeypatch) -> None:
    captured: dict = {}

    def fake_post(url, content=None, headers=None, timeout=None):  # noqa: ANN001
        captured.update(url=url, content=content, headers=headers)
        return _Resp(200)

    monkeypatch.setattr(ntfy.httpx, "post", fake_post)
    result = ntfy.send_ntfy(
        "https://ntfy.sh/mytopic",
        "Titre",
        "Corps",
        priority="high",
        tags=["warning"],
        actions=[{"action": "view", "label": "Voir", "url": "https://x"}],
        token="abc",
    )
    assert result["ok"] is True
    payload = json.loads(captured["content"])
    assert captured["url"] == "https://ntfy.sh"
    assert payload["topic"] == "mytopic"
    assert payload["priority"] == 4
    assert payload["actions"][0]["label"] == "Voir"
    assert captured["headers"]["Authorization"] == "Bearer abc"


def test_send_ntfy_http_error(monkeypatch) -> None:
    monkeypatch.setattr(ntfy.httpx, "post", lambda *a, **k: _Resp(500))
    assert ntfy.send_ntfy("https://ntfy.sh/t", "T", "M")["ok"] is False


def test_send_ntfy_invalid_url() -> None:
    assert ntfy.send_ntfy("", "T", "M")["ok"] is False


def test_notify_settings_roundtrip(tmp_path, monkeypatch) -> None:
    from app.storage.database import Database

    db = Database(str(tmp_path / "system.duckdb"))
    monkeypatch.setattr(ns, "get_database", lambda *a, **k: db)
    monkeypatch.setattr(ns, "resolve_instance_id", lambda *a, **k: None)

    defaults = ns.get_notify_settings()
    assert defaults["notify_channel"] == "email"
    assert defaults["ntfy_url"] == ""
    assert defaults["has_ntfy_token"] is False
    assert "ntfy_token" not in defaults

    updated = ns.update_notify_settings(
        {"notify_channel": "ntfy", "ntfy_url": "https://ntfy.sh/x", "ntfy_token": "tok"}
    )
    assert updated["notify_channel"] == "ntfy"
    assert updated["ntfy_url"] == "https://ntfy.sh/x"
    assert updated["has_ntfy_token"] is True
    assert "ntfy_token" not in updated
    assert ns.get_notify_settings(mask_token=False)["ntfy_token"] == "tok"


def test_dispatch_uses_ntfy_when_selected(monkeypatch) -> None:
    monkeypatch.setattr(
        dispatch,
        "get_notify_settings",
        lambda *a, **k: {"notify_channel": "ntfy", "ntfy_url": "https://ntfy.sh/x", "ntfy_token": ""},
    )
    called: dict = {}

    def fake_ntfy(url, title, message, **kwargs):  # noqa: ANN001
        called.update(url=url, title=title, message=message, kwargs=kwargs)
        return {"ok": True, "message": "sent"}

    monkeypatch.setattr(dispatch, "send_ntfy", fake_ntfy)
    result = dispatch.deliver("Sujet", "Corps", instance_id="abc")
    assert result["ok"] is True
    assert result["channel"] == "ntfy"
    assert called["url"] == "https://ntfy.sh/x"


def test_dispatch_defaults_to_email(monkeypatch) -> None:
    monkeypatch.setattr(dispatch, "get_notify_settings", lambda *a, **k: {"notify_channel": "email"})
    called: dict = {}

    def fake_email(subject, body, **kwargs):  # noqa: ANN001
        called.update(subject=subject, body=body)
        return {"ok": True, "message": "sent"}

    monkeypatch.setattr(dispatch, "send_email", fake_email)
    result = dispatch.deliver("Sujet", "Corps")
    assert result["channel"] == "email"
    assert called["subject"] == "Sujet"
