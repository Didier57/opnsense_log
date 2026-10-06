"""Authentication endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status

from ..config import settings
from ..core.security import create_token, verify_login_password
from .deps import require_user
from .schemas import LoginRequest

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login")
def login(payload: LoginRequest, response: Response) -> dict:
    valid = payload.username == settings.auth_username and verify_login_password(
        payload.password
    )
    if not valid:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_token(payload.username)
    response.set_cookie(
        "access_token",
        token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=settings.token_expire_minutes * 60,
    )
    return {"access_token": token, "token_type": "bearer", "username": payload.username}


@router.post("/logout")
def logout(response: Response) -> dict:
    response.delete_cookie("access_token")
    return {"ok": True}


@router.get("/me")
def me(user: str = Depends(require_user)) -> dict:
    return {"username": user, "auth_enabled": settings.auth_enabled}
