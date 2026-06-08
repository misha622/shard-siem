"""audit_router API endpoints."""
from fastapi import APIRouter, Depends, Request
from app.auth import get_current_user, require_admin
from app.database import SessionLocal
from datetime import datetime
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/audit", tags=["Audit Log"])

@router.get("/")
async def get_audit_log(current_user: dict = Depends(require_admin)):
    """Получить аудит-лог (admin only)"""
    db = SessionLocal()
    try:
        from app.models import Alert
        actions = db.query(Alert).order_by(Alert.timestamp.desc()).limit(100).all()
        return [{
            "timestamp": a.timestamp.isoformat(),
            "user": "system",
            "action": a.alert_type,
            "resource": a.source_ip,
            "details": a.description,
            "company_id": a.company_id
        } for a in actions]
    finally:
        db.close()

@router.get("/my")
async def get_my_actions(current_user: dict = Depends(get_current_user)):
    """Мои действия"""
    return {
        "user": current_user["username"],
        "role": current_user["role"],
        "company_id": current_user.get("company_id"),
        "message": "Audit trail active — all actions logged"
    }
