"""OPNsense instance registry endpoints (multi-instance)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..instances import (
    create_instance,
    delete_instance,
    get_instance,
    list_instances,
    update_instance,
)
from .deps import require_user
from .schemas import InstanceCreate, InstanceUpdate

router = APIRouter(prefix="/api/instances", tags=["instances"])


@router.get("")
def list_instances_endpoint(user: str = Depends(require_user)) -> dict:
    return {"items": list_instances()}


@router.post("")
def create_instance_endpoint(
    payload: InstanceCreate, user: str = Depends(require_user)
) -> dict:
    created = create_instance(name=payload.name, syslog_port=payload.syslog_port)
    if payload.syslog_protocol:
        created = update_instance(created["id"], syslog_protocol=payload.syslog_protocol) or created
    return {"ok": True, "instance": created}


@router.get("/{instance_id}")
def get_instance_endpoint(instance_id: str, user: str = Depends(require_user)) -> dict:
    inst = get_instance(instance_id)
    if inst is None:
        raise HTTPException(status_code=404, detail="Instance not found")
    return inst


@router.put("/{instance_id}")
def update_instance_endpoint(
    instance_id: str, payload: InstanceUpdate, user: str = Depends(require_user)
) -> dict:
    updated = update_instance(
        instance_id,
        name=payload.name,
        enabled=payload.enabled,
        syslog_port=payload.syslog_port,
        syslog_protocol=payload.syslog_protocol,
    )
    if updated is None:
        raise HTTPException(status_code=404, detail="Instance not found")
    return {"ok": True, "instance": updated}


@router.delete("/{instance_id}")
def delete_instance_endpoint(instance_id: str, user: str = Depends(require_user)) -> dict:
    return {"ok": delete_instance(instance_id)}
