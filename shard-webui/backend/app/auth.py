from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings
from functools import wraps

security = HTTPBearer()

# RBAC: 5 ролей с разными правами
ROLES = {
    'admin':             ['read', 'write', 'block', 'export', 'manage_users', 'manage_companies', 'view_logs'],
    'soc_manager':       ['read', 'write', 'block', 'export', 'view_logs'],
    'soc_analyst':       ['read', 'write', 'block'],
    'incident_responder':['read', 'block'],
    'auditor':           ['read', 'export', 'view_logs'],
    'viewer':            ['read'],
}

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None

def require_role(action: str):
    """Декоратор для проверки прав роли"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: dict = Depends(get_current_user), **kwargs):
            role = current_user.get('role', 'viewer')
            if action not in ROLES.get(role, []):
                raise HTTPException(status_code=403, detail=f"Role '{role}' cannot '{action}'")
            return await func(*args, current_user=current_user, **kwargs)
        return wrapper
    return decorator

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    payload = decode_token(credentials.credentials)
    if payload is None or payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = int(payload.get("sub"))
    from app.database import get_user_by_id
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {
        "id": user.id, "username": user.username, "role": user.role,
        "company_id": user.company_id,
        "permissions": ROLES.get(user.role, [])
    }
