import pytest

from app.storage.database import Database
import app.settings_store as store


@pytest.fixture()
def db(tmp_path, monkeypatch):
    database = Database(str(tmp_path / "app.duckdb"))
    monkeypatch.setattr(store, "get_database", lambda: database)
    yield database
    database.close()


def test_defaults_from_config(db):
    cfg = store.get_app_settings()
    assert set(cfg) == {
        "log_retention_days",
        "retention_check_interval_min",
        "display_timezone",
        "public_url",
    }
    assert cfg["log_retention_days"] >= 0
    assert cfg["retention_check_interval_min"] >= 5


def test_update_and_get(db):
    store.update_app_settings(
        {
            "log_retention_days": 90,
            "retention_check_interval_min": 15,
            "display_timezone": "Europe/Paris",
        }
    )
    cfg = store.get_app_settings()
    assert cfg["log_retention_days"] == 90
    assert cfg["retention_check_interval_min"] == 15
    assert cfg["display_timezone"] == "Europe/Paris"


def test_interval_floor_is_five(db):
    store.update_app_settings({"retention_check_interval_min": 1})
    assert store.get_app_settings()["retention_check_interval_min"] == 5
