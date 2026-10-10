from app.core.security import create_unblock_token, decode_unblock_token
import app.notifications.blocking_mail as bm


def test_unblock_token_roundtrip():
    token = create_unblock_token("1.2.3.4", days=1)
    assert decode_unblock_token(token) == "1.2.3.4"


def test_unblock_token_rejects_garbage():
    assert decode_unblock_token("not-a-token") is None
    assert decode_unblock_token("") is None


def test_unblock_token_rejects_other_scope():
    from app.core.security import ALGORITHM
    import jwt
    from app.config import settings

    token = jwt.encode({"scope": "login", "sub": "admin"}, settings.secret_key, algorithm=ALGORITHM)
    assert decode_unblock_token(token) is None


def test_block_notification_includes_unblock_link(monkeypatch):
    captured = {}

    def fake_send(subject, body, settings=None, html=None):
        captured["subject"] = subject
        captured["body"] = body
        captured["html"] = html
        return {"ok": True, "message": "sent"}

    monkeypatch.setattr(bm, "get_public_url", lambda: "https://logs.example.com")
    monkeypatch.setattr(bm, "send_email", fake_send)

    bm.send_block_notification(["1.2.3.4"], rule="port_scan", days=3)

    assert "1.2.3.4" in captured["subject"]
    assert "/api/blocking/unblock?token=" in captured["html"]
    assert "Scan de ports" in captured["html"]


def test_block_notification_includes_hits_and_expiry(monkeypatch):
    captured = {}

    def fake_send(subject, body, settings=None, html=None):
        captured["body"] = body
        captured["html"] = html
        return {"ok": True, "message": "sent"}

    monkeypatch.setattr(bm, "get_public_url", lambda: "https://logs.example.com")
    monkeypatch.setattr(bm, "send_email", fake_send)

    from datetime import datetime, timezone

    expires = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)
    bm.send_block_notification(
        ["1.2.3.4"],
        rule="bruteforce_service",
        details={"1.2.3.4": {"hits": 3, "expires_at": expires}},
    )

    assert "Force brute sur un service" in captured["html"]
    assert "blocages : 3" in captured["body"]
    assert "11/10/2026 12:00 UTC" in captured["body"]


def test_block_notification_without_public_url(monkeypatch):
    captured = {}

    def fake_send(subject, body, settings=None, html=None):
        captured["body"] = body
        captured["html"] = html
        return {"ok": True, "message": "sent"}

    monkeypatch.setattr(bm, "get_public_url", lambda: "")
    monkeypatch.setattr(bm, "send_email", fake_send)

    bm.send_block_notification(["1.2.3.4"], rule="bruteforce")

    assert "/api/blocking/unblock?token=" not in captured["html"]
    assert "URL publique non configurée" in captured["html"]
