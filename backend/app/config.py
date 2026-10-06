"""Application configuration loaded from environment variables."""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration.

    All important values are configurable via environment variables so that the
    Docker image stays generic and the ``docker-compose.yml`` drives behaviour.
    """

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    # --- Web ---
    web_host: str = "0.0.0.0"
    web_port: int = 8080
    public_url: str = "http://localhost:8080"

    # --- Syslog ---
    syslog_port: int = 5140
    syslog_protocol: str = "udp"  # udp | tcp | both
    syslog_host: str = "0.0.0.0"
    syslog_queue_maxsize: int = 100_000
    parser_workers: int = 2
    batch_size: int = 1000
    batch_flush_ms: int = 1000

    # --- Storage ---
    data_dir: str = "/data"
    db_filename: str = "opnsense.duckdb"
    log_retention_days: int = 30
    retention_check_interval_min: int = 60

    # --- OPNsense SSH ---
    opnsense_host: str = ""
    opnsense_ssh_port: int = 22
    opnsense_username: str = "root"
    opnsense_auth_type: str = "password"  # password | key
    opnsense_password: str = ""
    opnsense_key_path: str = ""
    opnsense_sync_interval_min: int = 30
    opnsense_sync_enabled: bool = True

    # --- Auth ---
    auth_enabled: bool = True
    auth_username: str = "admin"
    # Plain-text password (simplest setup: set AUTH_PASSWORD in .env).
    auth_password: str = "admin"
    # Optional argon2 hash of the password; takes precedence over auth_password.
    # Generate with scripts/hash_password.py
    auth_password_hash: str = ""
    secret_key: str = "change-me-in-production"
    token_expire_minutes: int = 480

    # --- Logging ---
    log_level: str = "INFO"

    # --- Timezone ---
    display_timezone: str = "Europe/Luxembourg"

    @property
    def syslog_protocols(self) -> list[str]:
        value = self.syslog_protocol.lower().strip()
        if value == "both":
            return ["udp", "tcp"]
        if value in {"udp", "tcp"}:
            return [value]
        return ["udp"]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
