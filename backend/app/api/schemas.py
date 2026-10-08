"""Pydantic request/response schemas for the API."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str
    password: str


class FilterClause(BaseModel):
    field: str
    op: str = "eq"
    value: str | int | list[str] | None = None


class SearchRequest(BaseModel):
    clauses: list[FilterClause] = Field(default_factory=list)
    logic: str = "AND"
    start: datetime | None = None
    end: datetime | None = None
    limit: int = 100
    offset: int = 0
    order_by: str = "event_time"
    order_dir: str = "desc"
    countries: list[str] | None = None


class SavedFilterCreate(BaseModel):
    name: str
    definition: dict


class OPNsenseSettings(BaseModel):
    opnsense_host: str | None = None
    opnsense_ssh_port: int | None = None
    opnsense_username: str | None = None
    opnsense_auth_type: str | None = None
    opnsense_password: str | None = None
    opnsense_key_path: str | None = None
    opnsense_sync_enabled: bool | None = None
    opnsense_sync_interval_min: int | None = None
    opnsense_import_on_start: bool | None = None
    opnsense_api_key: str | None = None
    opnsense_api_secret: str | None = None
    opnsense_api_scheme: str | None = None
    opnsense_api_port: int | None = None


class ApplicationSettings(BaseModel):
    log_retention_days: int | None = Field(default=None, ge=0)
    retention_check_interval_min: int | None = Field(default=None, ge=5)
    display_timezone: str | None = None
    public_url: str | None = None


class DetectionSettings(BaseModel):
    detection_enabled: bool | None = None
    detection_ignore_private: bool | None = None
    detection_interval_sec: int | None = Field(default=None, ge=15)
    detection_portscan_ports: int | None = Field(default=None, ge=2)
    detection_portscan_window_sec: int | None = Field(default=None, ge=5)
    detection_bruteforce_count: int | None = Field(default=None, ge=2)
    detection_bruteforce_window_sec: int | None = Field(default=None, ge=5)
    detection_spike_enabled: bool | None = None
    detection_spike_threshold: int | None = Field(default=None, ge=1)
    detection_spike_window_sec: int | None = Field(default=None, ge=5)
    detection_notify_cooldown_min: int | None = Field(default=None, ge=0)


class NotificationSettings(BaseModel):
    smtp_enabled: bool | None = None
    smtp_host: str | None = None
    smtp_port: int | None = Field(default=None, ge=1, le=65535)
    smtp_security: str | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None
    smtp_from_name: str | None = None
    smtp_to: str | None = None


class GeoIpSettings(BaseModel):
    geoip_enabled: bool | None = None
    geoip_account_id: str | None = None
    geoip_license_key: str | None = None


class BlockingSettings(BaseModel):
    blocking_enabled: bool | None = None
    blocking_alias: str | None = None
    blocking_mode: str | None = None
    blocking_whitelist: str | None = None
    blocking_ttl_hours: int | None = Field(default=None, ge=0)
    blocking_notify_email: bool | None = None
    blocking_token_days: int | None = Field(default=None, ge=1)
    blocking_skip_tables: str | None = None


class BlockRequest(BaseModel):
    ips: list[str] = Field(default_factory=list)
