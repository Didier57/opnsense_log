"""OPNsense interfaces endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from ..opnsense import interfaces as ifaces_repo
from ..opnsense.sync import OPNSenseSync
from .deps import require_user

router = APIRouter(prefix="/api/interfaces", tags=["interfaces"])


@router.get("")
def list_interfaces(user: str = Depends(require_user)) -> dict:
    return {"items": ifaces_repo.list_interfaces()}


@router.post("/sync")
def sync_interfaces(user: str = Depends(require_user)) -> dict:
    return OPNSenseSync().sync()
