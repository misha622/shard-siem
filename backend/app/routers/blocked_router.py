from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.database import db
from app.auth import get_current_user, require_role
from app.models import UserRole
from typing import List

router = APIRouter(prefix="/api/blocked", tags=["Blocked IPs"])

class BlockIPRequest(BaseModel):
    ip_address: str
    reason: str
    is_permanent: bool = False

@router.get("/")
async def get_blocked(current_user: dict = Depends(get_current_user)):
    return await db.get_blocked_ips()

@router.post("/block")
async def block_ip(request: BlockIPRequest, current_user: dict = Depends(get_current_user)):
    block_id = await db.block_ip(request.ip_address, request.reason, current_user["username"], request.is_permanent)
    return {"message": f"IP {request.ip_address} blocked", "block_id": block_id}

@router.delete("/unblock/{block_id}")
async def unblock_ip(block_id: str, current_user: dict = Depends(require_role(UserRole.ADMIN))):
    ip = await db.unblock_ip(block_id)
    if not ip:
        raise HTTPException(status_code=404, detail="Block entry not found")
    return {"message": f"IP {ip} unblocked"}
