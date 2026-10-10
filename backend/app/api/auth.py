"""Authentication endpoints and first-run setup."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status

from ..config import settings
from ..core import users as users_store
from ..core.security import create_token
from .deps import current_identity
from .schemas import LoginRequest

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _set_session(response: Response, username: str, role: str) -> str:
    token = create_token(username, role)
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=settings.token_expire_minutes * 60,
    )
    return token


@router.post("/login")
def login(payload: LoginRequest, response: Response) -> dict:
    user = users_store.authenticate(payload.username, payload.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    users_store.set_last_login(user["username"])
    token = _set_session(response, user["username"], user["role"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"],
    }


@router.post("/logout")
def logout(response: Response) -> dict:
    response.delete_cookie("access_token")
    return {"ok": True}


@router.get("/me")
def me(identity: dict = Depends(current_identity)) -> dict:
    return {
        "username": identity["username"],
        "role": identity["role"],
        "auth_enabled": settings.auth_enabled,
    }


@router.get("/setup-status")
def setup_status() -> dict:
    return {
        "auth_enabled": settings.auth_enabled,
        "needs_setup": settings.auth_enabled and users_store.count_users() == 0,
    }


@router.post("/setup")
def setup(payload: LoginRequest, response: Response) -> dict:
    if users_store.count_users() > 0:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Already initialised")
    if len(payload.password or "") < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Le mot de passe doit contenir au moins 6 caractères",
        )
    try:
        user = users_store.create_user(payload.username, payload.password, "admin")
    except users_store.UserError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    token = _set_session(response, user["username"], "admin")
    return {
        "access_token": token,
        "token_type": "bearer",
        "username": user["username"],
        "role": "admin",
    }
