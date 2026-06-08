"""compliance_router API endpoints."""
"""Compliance router stub"""
from fastapi import APIRouter, Depends
from app.auth import get_current_user

router = APIRouter(prefix="/api/compliance", tags=["compliance"])

@router.get("/status")
async def compliance_status(current_user: dict = Depends(get_current_user)):
    return {"status": "ok", "message": "Compliance module"}
