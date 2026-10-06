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
    host: str | None = None
    port: int | None = None
    username: str | None = None
    auth_type: str | None = None
    password: str | None = None
    key_path: str | None = None
