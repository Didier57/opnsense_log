"""Tests for the GeoIP country resolver, settings store and credential parsing."""
import gzip

import pytest

from app.storage.database import Database
import app.geoip.resolver as gr
import app.geoip.store as gs
from app.opnsense.config_loader import parse_geoip_credentials


@pytest.fixture()
def database(tmp_path, monkeypatch):
    db = Database(str(tmp_path / "geo.duckdb"))
    monkeypatch.setattr(gr, "get_database", lambda *a, **k: db)
    monkeypatch.setattr("app.storage.database.get_database", lambda *a, **k: db)
    yield db
    db.close()


@pytest.fixture()
def resolver(database):
    return gr.GeoResolver()


def test_is_public_ip():
    assert gr.is_public_ip("8.8.8.8")
    assert not gr.is_public_ip("192.168.1.1")
    assert not gr.is_public_ip("10.0.0.1")
    assert not gr.is_public_ip("not-an-ip")


def test_resolve_skips_private_and_caches(resolver, monkeypatch):
    calls = []

    def fake(ip):
        calls.append(ip)
        return ("US", "United States")

    monkeypatch.setattr(resolver, "_mmdb_lookup", fake)
    out = resolver.resolve(["10.0.0.1", "8.8.8.8", "8.8.8.8"])
    assert out == {"8.8.8.8": {"country": "US", "name": "United States"}}
    assert calls == ["8.8.8.8"]
    resolver.resolve(["8.8.8.8"])
    assert calls == ["8.8.8.8"]


def test_resolve_unknown_is_none(resolver, monkeypatch):
    monkeypatch.setattr(resolver, "_mmdb_lookup", lambda ip: (None, None))
    assert resolver.resolve(["1.1.1.1"]) == {"1.1.1.1": None}


def test_db_cache_persists_across_instances(database, monkeypatch):
    first = gr.GeoResolver()
    monkeypatch.setattr(first, "_mmdb_lookup", lambda ip: ("DE", "Germany"))
    first.resolve(["9.9.9.9"])

    second = gr.GeoResolver()
    calls = []
    monkeypatch.setattr(second, "_mmdb_lookup", lambda ip: (calls.append(ip), None)[1])
    out = second.resolve(["9.9.9.9"])
    assert out == {"9.9.9.9": {"country": "DE", "name": "Germany"}}
    assert calls == []


def test_extract_mmdb_gzip():
    payload = b"mmdb-binary-content"
    assert gr._extract_mmdb(gzip.compress(payload)) == payload


def test_download_urls_default_dbip(monkeypatch):
    monkeypatch.setattr(
        gr, "get_geo_settings", lambda mask_key=True: {"geoip_license_key": "", "geoip_account_id": ""}
    )
    urls = gr._download_urls()
    assert len(urls) == 2
    assert all("db-ip.com" in url for url in urls)


def test_download_urls_maxmind(monkeypatch):
    monkeypatch.setattr(
        gr, "get_geo_settings", lambda mask_key=True: {"geoip_license_key": "KEY", "geoip_account_id": "ACC"}
    )
    urls = gr._download_urls()
    assert len(urls) == 1
    assert "ACC:KEY@download.maxmind.com" in urls[0]


def test_store_defaults_and_update(database):
    defaults = gs.get_geo_settings()
    assert defaults["geoip_enabled"] is True
    assert defaults["has_license_key"] is False

    gs.update_geo_settings({"geoip_account_id": "acc", "geoip_license_key": "secret"})
    got = gs.get_geo_settings()
    assert got["has_license_key"] is True
    assert got["geoip_license_key"] == ""

    gs.update_geo_settings({"geoip_license_key": ""})
    assert gs.get_geo_settings(mask_key=False)["geoip_license_key"] == "secret"


def test_set_geo_credentials(database):
    gs.set_geo_credentials("acc", "key")
    assert gs.get_geo_settings(mask_key=False)["geoip_license_key"] == "key"
    gs.set_geo_credentials("", "")
    assert gs.get_geo_settings(mask_key=False)["geoip_license_key"] == "key"


def test_parse_geoip_credentials_userinfo():
    xml = (
        "<opnsense><OPNsense><Firewall><Alias><geoip><url>"
        "https://123:abcDEF%40@download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=zip"
        "</url></geoip></Alias></Firewall></OPNsense></opnsense>"
    )
    creds = parse_geoip_credentials(xml)
    assert creds["account_id"] == "123"
    assert creds["license_key"] == "abcDEF@"


def test_parse_geoip_credentials_legacy():
    xml = (
        "<geoip><url>https://download.maxmind.com/app/geoip_download"
        "?edition_id=GeoLite2-Country-CSV&amp;license_key=XYZ&amp;suffix=zip</url></geoip>"
    )
    creds = parse_geoip_credentials(xml)
    assert creds["license_key"] == "XYZ"


def test_parse_geoip_credentials_none():
    xml = "<geoip><url>https://ipinfo.io/data/ipinfo_lite.csv.gz?token=T</url></geoip>"
    assert parse_geoip_credentials(xml) == {}
