from fastapi import APIRouter, Depends, HTTPException, status, Request
from app.schemas import LoginRequest, TokenRefresh, ChangePasswordRequest
from app.database import db, verify_password, hash_password
from app.email_service import email_service, EmailTemplate, EmailMessage, EmailEvent, EmailPriority
from app.auth import create_access_token, create_refresh_token, decode_token, get_current_user
from pydantic import BaseModel, Field
from typing import Optional
import re, logging
from datetime import datetime

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["Authentication"])

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=4, max_length=32)
    first_name: str = Field(..., min_length=1)
    last_name: str = Field(..., min_length=1)
    email: str = Field(..., min_length=5)
    password: str = Field(..., min_length=8)
    company: str = ""
    job_title: str = ""
    reason: str = ""
    agree_updates: bool = False

@router.post("/register")
async def register(request: RegisterRequest, req: Request):
    client_ip = req.client.host
    logger.info(f"Registration attempt: {request.username} from {client_ip}")

    existing = await db.get_user_by_username(request.username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already taken")

    user_id = await db.create_user({
        "username": request.username,
        "email": request.email,
        "password": request.password,
        "first_name": request.first_name,
        "last_name": request.last_name,
        "company": request.company,
        "job_title": request.job_title,
        "agree_updates": request.agree_updates
    })

    logger.info(f"New user registered: {request.username} ({request.email}) from {client_ip}")

    try:
        welcome_msg = EmailMessage(
            to=[request.email],
            subject="Welcome to SHARD Enterprise SIEM",
            body_html=EmailTemplate.registration_confirm(request.username, request.email),
            event_type=EmailEvent.REGISTRATION_CONFIRM,
            priority=EmailPriority.NORMAL
        )
        await email_service.send(welcome_msg)
    except Exception as e:
        logger.error(f"Failed to queue welcome email: {e}")

    return {
        "message": "Registration successful! You can now login.",
        "user": {"id": user_id, "username": request.username, "email": request.email, "role": "viewer"}
    }

@router.post("/login")
async def login(request: LoginRequest):
    user = await db.get_user_by_username(request.username)
    if not user or not verify_password(request.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    await db.update_last_login(user["id"])
    access_token = create_access_token(data={"sub": user["id"], "role": user["role"]})
    refresh_token = create_refresh_token(data={"sub": user["id"], "role": user["role"]})
    await db.add_refresh_token(refresh_token, user["id"])
    
    return {
        "access_token": access_token, "refresh_token": refresh_token,
        "token_type": "bearer", "expires_in": 86400,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]}
    }

@router.post("/refresh")
async def refresh(request: TokenRefresh):
    payload = decode_token(request.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = await db.get_user_by_id(payload.get("sub"))
    if not user: raise HTTPException(status_code=401, detail="User not found")
    await db.revoke_refresh_token(request.refresh_token)
    new_access = create_access_token(data={"sub": user["id"], "role": user["role"]})
    new_refresh = create_refresh_token(data={"sub": user["id"], "role": user["role"]})
    await db.add_refresh_token(new_refresh, user["id"])
    return {
        "access_token": new_access, "refresh_token": new_refresh,
        "token_type": "bearer", "expires_in": 86400,
        "user": {"id": user["id"], "username": user["username"], "role": user["role"]}
    }

@router.get("/me")
async def me(current_user: dict = Depends(get_current_user)):
    user = await db.get_user_by_id(current_user["id"])
    return {
        "id": user["id"], "username": user["username"], "role": user["role"],
        "created_at": user.get("created_at"), "last_login": user.get("last_login")
    }

@router.post("/change-password")
async def change_password(request: ChangePasswordRequest, current_user: dict = Depends(get_current_user)):
    user = await db.get_user_by_id(current_user["id"])
    if not verify_password(request.old_password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    await db.change_password(current_user["id"], request.new_password)
    return {"message": "Password changed"}
