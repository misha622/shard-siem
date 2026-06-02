from fastapi import APIRouter, Depends, HTTPException, status
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.schemas import LoginRequest, TokenRefresh, ChangePasswordRequest, TokenResponse
from app.database import db
from app.auth import create_access_token, create_refresh_token, decode_token, get_current_user
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["Authentication"])
limiter = Limiter(key_func=get_remote_address)


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
async def login(request: LoginRequest):
    """
    Authenticate user and return JWT tokens
    """
    user = db.get_user_by_username(request.username)

    if not user or not db.verify_password(request.password, user.hashed_password):
        logger.warning(f"Failed login attempt for user: {request.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Create tokens
    access_token = create_access_token(data={"sub": user.id, "role": user.role})
    refresh_token = create_refresh_token(data={"sub": user.id, "role": user.role})

    # Store refresh token
    db.add_refresh_token(refresh_token, user.id)

    # Update last login
    user.last_login = datetime.utcnow()

    logger.info(f"User {user.username} logged in successfully")

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=86400,  # 24 hours in seconds
        user={
            "id": user.id,
            "username": user.username,
            "role": user.role,
            "last_login": user.last_login.isoformat() if user.last_login else None
        }
    )


@router.post("/refresh")
async def refresh_token(request: TokenRefresh):
    """
    Refresh access token using refresh token
    """
    payload = decode_token(request.refresh_token)

    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )

    user_id = payload.get("sub")
    user = db.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    # Verify refresh token exists in database
    stored_user_id = db.get_user_by_refresh_token(request.refresh_token)
    if stored_user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token revoked"
        )

    # Revoke old refresh token and create new ones
    db.revoke_refresh_token(request.refresh_token)

    new_access_token = create_access_token(data={"sub": user.id, "role": user.role})
    new_refresh_token = create_refresh_token(data={"sub": user.id, "role": user.role})
    db.add_refresh_token(new_refresh_token, user.id)

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        expires_in=86400,
        user={
            "id": user.id,
            "username": user.username,
            "role": user.role
        }
    )


@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    """
    Logout and revoke tokens
    """
    # In a real implementation, add token to blacklist
    logger.info(f"User {current_user['username']} logged out")
    return {"message": "Successfully logged out"}


@router.get("/me")
async def get_current_user_info(current_user: dict = Depends(get_current_user)):
    """
    Get current user information
    """
    user = db.get_user_by_id(current_user["id"])
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "created_at": user.created_at.isoformat(),
        "last_login": user.last_login.isoformat() if user.last_login else None
    }


@router.post("/change-password")
async def change_password(
        request: ChangePasswordRequest,
        current_user: dict = Depends(get_current_user)
):
    """
    Change user password
    """
    user = db.get_user_by_id(current_user["id"])

    if not db.verify_password(request.old_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )

    db.change_password(current_user["id"], request.new_password)
    logger.info(f"Password changed for user {current_user['username']}")

    return {"message": "Password changed successfully"}