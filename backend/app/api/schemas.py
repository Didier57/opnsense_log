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


class ApplicationSettings(BaseModel):
    log_retention_days: int | None = Field(default=None, ge=0)
    retention_check_interval_min: int | None = Field(default=None, ge=5)
    display_timezone: str | None = None
