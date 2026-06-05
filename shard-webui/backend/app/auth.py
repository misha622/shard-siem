from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.config import settings

security = HTTPBearer()

ROLES = {
    'admin':             ['read', 'write', 'block', 'export', 'manage_users', 'manage_companies', 'view_logs'],
    'soc_manager':       ['read', 'write', 'block', 'export', 'view_logs'],
    'soc_analyst':       ['read', 'write', 'block'],
    'incident_responder':['read', 'block'],
    'auditor':           ['read', 'export', 'view_logs'],
    'viewer':            ['read'],
}


# Иерархия ролей (выше = больше прав)
ROLE_HIERARCHY = {
    "superadmin": 100,
    "admin": 80,
    "soc_manager": 60,
    "soc_analyst": 40,
    "incident_responder": 30,
    "auditor": 20,
    "viewer": 10
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

def require_role(action: str):
    """Dependency factory для проверки прав роли (с иерархией)"""
    async def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        role = current_user.get('role', 'viewer')
        # Проверяем права: роль выше в иерархии имеет все права нижних
        user_level = ROLE_HIERARCHY.get(role, 0)
        # Находим минимальный уровень для действия
        min_level = 0
        for r, actions in ROLES.items():
            if action in actions:
                min_level = max(min_level, ROLE_HIERARCHY.get(r, 0))
        if user_level < min_level:
            raise HTTPException(status_code=403, detail=f"Role '{role}' cannot '{action}'")
        return current_user
    return role_checker

def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    """Проверка что пользователь — admin"""
    if current_user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

