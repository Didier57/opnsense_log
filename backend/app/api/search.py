"""Advanced search endpoint supporting AND/OR logic and operators."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..storage.repository import EventRepository
from .deps import require_user
from .schemas import SearchRequest

router = APIRouter(prefix="/api/search", tags=["search"])
repo = EventRepository()


@router.post("")
def search(payload: SearchRequest, user: str = Depends(require_user)) -> dict:
    clauses = [c.model_dump() for c in payload.clauses]
    try:
        return repo.search(
            clauses=clauses,
            logic=payload.logic,
            start=payload.start,
            end=payload.end,
            limit=payload.limit,
            offset=payload.offset,
            order_by=payload.order_by,
            order_dir=payload.order_dir,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
