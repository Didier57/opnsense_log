"""Saved filters CRUD."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException

from ..storage.database import get_database
from .deps import require_user
from .schemas import SavedFilterCreate

router = APIRouter(prefix="/api/filters", tags=["filters"])


@router.get("")
def list_filters(user: str = Depends(require_user)) -> dict:
    db = get_database()
    rows = db.execute_read(
        "SELECT id, name, definition, created_at FROM saved_filters ORDER BY name"
    ).fetchall()
    items = [
        {"id": r[0], "name": r[1], "definition": json.loads(r[2]), "created_at": r[3]}
        for r in rows
    ]
    return {"items": items}


@router.post("")
def create_filter(payload: SavedFilterCreate, user: str = Depends(require_user)) -> dict:
    db = get_database()
    next_id = (db.execute_read("SELECT COALESCE(MAX(id), 0) + 1 FROM saved_filters").fetchone()[0])
    db.execute_write(
        "INSERT INTO saved_filters (id, name, definition, created_at) VALUES (?, ?, ?, ?)",
        [next_id, payload.name, json.dumps(payload.definition), datetime.now(timezone.utc)],
    )
    return {"id": next_id, "name": payload.name}


@router.delete("/{filter_id}")
def delete_filter(filter_id: int, user: str = Depends(require_user)) -> dict:
    db = get_database()
    db.execute_write("DELETE FROM saved_filters WHERE id = ?", [filter_id])
    return {"ok": True}


@router.get("/{filter_id}")
def get_filter(filter_id: int, user: str = Depends(require_user)) -> dict:
    db = get_database()
    row = db.execute_read(
        "SELECT id, name, definition, created_at FROM saved_filters WHERE id = ?", [filter_id]
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="filter not found")
    return {"id": row[0], "name": row[1], "definition": json.loads(row[2]), "created_at": row[3]}
