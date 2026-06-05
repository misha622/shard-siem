from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel, Field
from typing import Optional
import logging
from sqlalchemy.orm import joinedload
from app.database import (get_user_by_username, get_user_by_id, create_user, update_last_login,
                          change_password, verify_password, add_refresh_token, get_user_by_refresh_token,
                          revoke_refresh_token, SessionLocal)
from app.models import User


from app.auth import create_access_token, create_refresh_token, decode_token, get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["Authentication"])

class LoginRequest(BaseModel):
    username: str
    password: str
    tenant_slug: str = 'default'

class TokenRefresh(BaseModel):
    refresh_token: str
    tenant_slug: str = "default"

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8)


from pydantic import BaseModel as PydanticBaseModel, Field

class RegisterRequest(PydanticBaseModel):
    username: str = Field(..., min_length=4)
    password: str = Field(..., min_length=8)
    email: str = ""
    first_name: str = ""
    last_name: str = ""

@router.post("/register", status_code=201)
async def register(request: RegisterRequest):
    if get_user_by_username(request.username):
        raise HTTPException(status_code=400, detail="Username already taken")
    create_user(request.model_dump())
    return {"message": "Account created"}


@router.post("/login")
async def login(request: LoginRequest):
    db = SessionLocal()
    try:
        user = db.query(User).options(joinedload(User.company)).filter(User.username == request.username).first()
        if not user or not verify_password(request.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        update_last_login(user.id)
        token_data = {"sub": str(user.id), "role": user.role, "tenant_slug": request.tenant_slug}
        if user.company_id: token_data["company_id"] = user.company_id
        
        access_token = create_access_token(data=token_data)
        refresh_token = create_refresh_token(data=token_data)
        add_refresh_token(refresh_token, user.id)
        
        return {
            "access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer",
            "expires_in": 900,
            "user": {
                "id": user.id, "username": user.username, "role": user.role,
                "company_id": user.company_id,
                "company_name": user.company.name if user.company else None
            }
        }
    finally:
        db.close()

@router.post("/refresh")
async def refresh(request: TokenRefresh):
    payload = decode_token(request.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = payload.get("sub")
    stored = get_user_by_refresh_token(request.refresh_token)
    if stored != int(user_id): raise HTTPException(status_code=401, detail="Token revoked")
    
    db = SessionLocal()
    try:
        user = db.query(User).options(joinedload(User.company)).filter(User.id == user_id).first()
        if not user: raise HTTPException(status_code=401, detail="User not found")
        revoke_refresh_token(request.refresh_token)
        token_data = {"sub": str(user.id), "role": user.role, "tenant_slug": request.tenant_slug}
        if user.company_id: token_data["company_id"] = user.company_id
        new_access = create_access_token(data=token_data)
        new_refresh = create_refresh_token(data=token_data)
        add_refresh_token(new_refresh, user.id)
        return {
            "access_token": new_access, "refresh_token": new_refresh, "token_type": "bearer",
            "expires_in": 900,
            "user": {
                "id": user.id, "username": user.username, "role": user.role,
                "company_id": user.company_id,
                "company_name": user.company.name if user.company else None
            }
        }
    finally:
        db.close()

@router.get("/me")
async def me(current_user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(User).options(joinedload(User.company)).filter(User.id == current_user["id"]).first()
        return {
            "id": user.id, "username": user.username, "role": user.role,
            "company_id": user.company_id,
            "company_name": user.company.name if user.company else None
        }
    finally:
        db.close()

@router.post("/change-password")
async def change_pwd(request: ChangePasswordRequest, current_user: dict = Depends(get_current_user)):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == current_user["id"]).first()
        if not verify_password(request.old_password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        change_password(user.id, request.new_password)
        return {"message": "Password changed"}
    finally:
        db.close()

@router.post("/logout")
async def logout(request: Request, current_user: dict = Depends(get_current_user)):
    """Logout — revoke refresh token"""
    # Отзываем refresh token если передан
    if hasattr(request, 'refresh_token') and request.refresh_token:
        from app.database import revoke_refresh_token
        revoke_refresh_token(request.refresh_token)
    return {"message": "Logged out successfully"}