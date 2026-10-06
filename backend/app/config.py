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
    opnsense_sync_enabled: bool = False

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
    # Timezone used to display timestamps in the UI.
    display_timezone: str = "Europe/Luxembourg"

    # --- Detection engine ---
    detection_enabled: bool = True
    detection_interval_sec: int = 60
    # Ignore alerts whose source is a private/loopback/link-local address so
    # normal LAN traffic does not raise false positives.
    detection_ignore_private: bool = True
    detection_portscan_ports: int = 20
    detection_portscan_window_sec: int = 60
    detection_bruteforce_count: int = 20
    detection_bruteforce_window_sec: int = 120
    detection_spike_threshold: int = 300
    detection_spike_window_sec: int = 60

    # --- Email notifications (SMTP) ---
    smtp_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_security: str = "starttls"  # none | ssl | starttls
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_email: str = ""
    smtp_from_name: str = "OPNsense Log Analyzer"
    smtp_to: str = ""
    # Timezone in which OPNsense emits syslog timestamps (usually the firewall
    # local time). Naive incoming timestamps are interpreted in this timezone and
    # converted to UTC for storage. Empty means "use display_timezone".
    syslog_timezone: str = ""

    # --- Hostname lookup (reverse DNS) ---
    # How long a resolved IP -> hostname mapping is kept before being looked up
    # again (minutes).
    hostname_lookup_ttl_min: int = 1440

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
