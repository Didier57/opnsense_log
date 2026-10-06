"""API router aggregation."""
from fastapi import APIRouter

from . import (
    auth,
    export,
    filters,
    health,
    interfaces,
    live,
    logs,
    rules,
    search,
    settings,
    statistics,
    system,
)

api_router = APIRouter()
for module in (
    health, auth, logs, search, statistics, filters, rules, interfaces,
    settings, system, export, live,
):
    api_router.include_router(module.router)
