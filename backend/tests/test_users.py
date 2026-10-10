"""Tests for the user store (accounts, roles, bootstrap)."""
from __future__ import annotations

import pytest

from app.core import users as us
from app.core.security import hash_password
from app.storage.database import Database


@pytest.fixture
def db(tmp_path, monkeypatch):
    database = Database(str(tmp_path / "system.duckdb"))
    monkeypatch.setattr(us, "get_database", lambda *a, **k: database)
    return database


def test_create_and_authenticate(db):
    user = us.create_user("alice", "secret1", "admin")
    assert user["username"] == "alice"
    assert user["role"] == "admin"
    assert us.count_users() == 1
    assert us.authenticate("alice", "secret1")["username"] == "alice"
    assert us.authenticate("alice", "wrong") is None
    assert us.authenticate("nobody", "x") is None


def test_duplicate_and_short_password(db):
    us.create_user("bob", "secret1", "viewer")
    with pytest.raises(us.UserError):
        us.create_user("bob", "secret2", "viewer")
    with pytest.raises(us.UserError):
        us.create_user("carl", "ab", "viewer")


def test_invalid_role(db):
    with pytest.raises(us.UserError):
        us.create_user("x", "secret1", "superuser")


def test_last_admin_protection(db):
    us.create_user("root", "secret1", "admin")
    with pytest.raises(us.UserError):
        us.update_user("root", role="viewer")
    with pytest.raises(us.UserError):
        us.delete_user("root")
    us.create_user("root2", "secret1", "admin")
    us.update_user("root", role="viewer")
    assert us.get_user("root")["role"] == "viewer"
    assert us.delete_user("root") is True
    assert us.get_user("root") is None
    assert us.count_admins() == 1


def test_password_hash_import(db):
    user = us.create_user("imp", "", "admin", password_hash=hash_password("secret1"))
    assert user["role"] == "admin"
    assert us.authenticate("imp", "secret1") is not None


def test_update_password(db):
    us.create_user("d", "secret1", "viewer")
    us.update_user("d", password="newpass")
    assert us.authenticate("d", "secret1") is None
    assert us.authenticate("d", "newpass") is not None


def test_set_last_login(db):
    us.create_user("e", "secret1", "viewer")
    assert us.get_user("e")["last_login_at"] is None
    us.set_last_login("e")
    assert us.get_user("e")["last_login_at"] is not None


def test_list_users_hides_hash(db):
    us.create_user("f", "secret1", "viewer")
    items = us.list_users()
    assert items and "password_hash" not in items[0]


def test_bootstrap_from_env(db, monkeypatch):
    class _S:
        auth_username = "admin"
        auth_password = "s3cret"
        auth_password_hash = ""

    monkeypatch.setattr(us, "settings", _S)
    created = us.bootstrap_env_admin()
    assert created == "admin"
    assert us.authenticate("admin", "s3cret") is not None
    # Running again is a no-op once a user exists.
    assert us.bootstrap_env_admin() is None


def test_bootstrap_skips_default_admin(db, monkeypatch):
    class _S:
        auth_username = "admin"
        auth_password = "admin"
        auth_password_hash = ""

    monkeypatch.setattr(us, "settings", _S)
    assert us.bootstrap_env_admin() is None
    assert us.count_users() == 0
