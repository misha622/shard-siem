"""Email notification router"""
from fastapi import APIRouter, Depends
from app.auth import get_current_user

router = APIRouter(prefix="/api/email", tags=["email"])

@router.get("/status")
async def email_status(current_user: dict = Depends(get_current_user)):
    return {"status": "ok", "enabled": False, "message": "Email service stub"}
