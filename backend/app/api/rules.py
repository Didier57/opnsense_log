"""OPNsense rules endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..opnsense import rules as rules_repo
from ..opnsense.sync import OPNSenseSync
from .deps import require_user

router = APIRouter(prefix="/api/rules", tags=["rules"])


@router.get("")
def list_rules(user: str = Depends(require_user)) -> dict:
    return {"items": rules_repo.list_rules()}


@router.post("/sync")
def sync_rules(user: str = Depends(require_user)) -> dict:
    return OPNSenseSync().sync()


@router.get("/{rule_id}")
def get_rule(rule_id: str, user: str = Depends(require_user)) -> dict:
    rule = rules_repo.get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="rule not found")
    rule["history"] = rules_repo.get_rule_history(rule_id)
    return rule
