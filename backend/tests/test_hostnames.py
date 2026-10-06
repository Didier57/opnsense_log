"""Tests for the reverse-DNS hostname resolver (network mocked)."""
import pytest

from app.storage.database import Database
import app.core.hostnames as hn


@pytest.fixture()
def resolver(tmp_path, monkeypatch):
    database = Database(str(tmp_path / "hosts.duckdb"))
    monkeypatch.setattr(hn, "get_database", lambda: database)
    instance = hn.HostnameResolver()
    yield instance
    database.close()


def test_resolve_valid_ip(monkeypatch, resolver):
    calls = []

    def fake_reverse(ip):
        calls.append(ip)
        return "host-1.local"

    monkeypatch.setattr(resolver, "_reverse", fake_reverse)
    out = resolver.resolve(["10.0.0.1"])
    assert out == {"10.0.0.1": "host-1.local"}
    assert calls == ["10.0.0.1"]


def test_invalid_ips_are_skipped(monkeypatch, resolver):
    monkeypatch.setattr(resolver, "_reverse", lambda ip: "x")
    out = resolver.resolve(["not-an-ip", "", "   ", "10.0.0.2"])
    assert set(out) == {"10.0.0.2"}


def test_memory_cache_avoids_second_lookup(monkeypatch, resolver):
    calls = []

    def fake_reverse(ip):
        calls.append(ip)
        return "cached.local"

    monkeypatch.setattr(resolver, "_reverse", fake_reverse)
    resolver.resolve(["10.0.0.3"])
    resolver.resolve(["10.0.0.3"])
    assert calls == ["10.0.0.3"]


def test_negative_result_is_cached(monkeypatch, resolver):
    calls = []

    def fake_reverse(ip):
        calls.append(ip)
        return None

    monkeypatch.setattr(resolver, "_reverse", fake_reverse)
    resolver.resolve(["10.0.0.4"])
    resolver.resolve(["10.0.0.4"])
    assert calls == ["10.0.0.4"]


def test_db_cache_persists_across_instances(monkeypatch, resolver):
    monkeypatch.setattr(resolver, "_reverse", lambda ip: "persist.local")
    resolver.resolve(["10.0.0.9"])

    fresh = hn.HostnameResolver()
    calls = []
    monkeypatch.setattr(fresh, "_reverse", lambda ip: (calls.append(ip), None)[1])
    out = fresh.resolve(["10.0.0.9"])
    assert out == {"10.0.0.9": "persist.local"}
    assert calls == []
