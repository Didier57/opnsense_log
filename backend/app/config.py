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
    # Import firewall logs directly from the OPNsense log files over SSH on startup.
    opnsense_import_on_start: bool = True
    opnsense_import_wait_syslog_sec: int = 120
    # OPNsense REST API credentials (used to manage firewall aliases for the
    # automatic blocking feature). Key/secret are created in the OPNsense GUI or
    # generated over SSH from the web UI.
    opnsense_api_key: str = ""
    opnsense_api_secret: str = ""
    opnsense_api_scheme: str = "https"
    opnsense_api_port: int = 443

    # --- Automatic blocking (push alert source IPs into an OPNsense alias) ---
    # When enabled, the source IPs of bruteforce / port-scan alerts are added to
    # an existing "Host(s)" firewall alias so a firewall rule can block them.
    blocking_enabled: bool = False
    blocking_alias: str = ""
    blocking_mode: str = "manual"  # manual | auto
    # IPs / CIDR that must never be blocked (gateway, DNS, admin...). Comma or
    # space separated.
    blocking_whitelist: str = ""
    # Remove blocked IPs from the alias after this many hours (0 = keep forever).
    blocking_ttl_hours: int = 0
    # E-mail the configured recipient(s) when an IP is blocked, with a one-click
    # "Unblock" link (signed token, no login required).
    blocking_notify_email: bool = True
    # Validity of the e-mail unblock link token (days).
    blocking_token_days: int = 7
    # pf tables / firewall aliases that already block IPs (CrowdSec, Q-Feeds,
    # IDS...). Comma or space separated. An IP already present in one of these is
    # not blocked again and no notification is sent.
    blocking_skip_tables: str = "crowdsec_blacklists, crowdsec6_blacklists"

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
    # Traffic-spike alerts are noisy and off by default.
    detection_spike_enabled: bool = False
    # Minimum delay before e-mailing about the same (rule, source IP) again.
    # Persisted in the database, so it also suppresses duplicates after a restart.
    detection_notify_cooldown_min: int = 60

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

    # --- Geolocation (GeoIP country) ---
    # Country lookup for public IPs. Defaults to the free DB-IP Lite database
    # (no account required). When a MaxMind account id / licence key is set
    # (in the web UI or auto-detected from the OPNsense GeoIP alias settings),
    # the MaxMind GeoLite2 database is used instead.
    geoip_enabled: bool = True
    geoip_account_id: str = ""
    geoip_license_key: str = ""
    geoip_update_interval_hours: int = 168

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
