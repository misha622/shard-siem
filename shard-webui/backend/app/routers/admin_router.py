"""Admin router stub"""
from fastapi import APIRouter, Depends
from app.auth import get_current_user

router = APIRouter(prefix="/api/admin", tags=["admin"])

@router.get("/status")
async def admin_status(current_user: dict = Depends(get_current_user)):
    return {"status": "ok", "message": "Admin module"}
