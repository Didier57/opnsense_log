"""User management endpoints (administrators only)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from ..core import users as users_store
from .deps import require_admin
from .schemas import UserCreate, UserUpdate

router = APIRouter(
    prefix="/api/users",
    tags=["users"],
    dependencies=[Depends(require_admin)],
)


@router.get("")
def list_users() -> dict:
    return {"items": users_store.list_users()}


@router.post("")
def create_user(payload: UserCreate) -> dict:
    try:
        user = users_store.create_user(payload.username, payload.password, payload.role)
    except users_store.UserError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return {"ok": True, "user": user}


@router.put("/{username}")
def update_user(username: str, payload: UserUpdate) -> dict:
    try:
        user = users_store.update_user(username, role=payload.role, password=payload.password)
    except users_store.UserError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur introuvable")
    return {"ok": True, "user": user}


@router.delete("/{username}")
def delete_user(username: str, admin: str = Depends(require_admin)) -> dict:
    if username.strip() == admin:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Vous ne pouvez pas supprimer votre propre compte",
        )
    try:
        ok = users_store.delete_user(username)
    except users_store.UserError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return {"ok": ok}
