"""blocked_router API endpoints."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from app.database import get_blocked_ips, block_ip, unblock_ip
from app.auth import get_current_user

router = APIRouter(prefix="/api/blocked", tags=["Blocked IPs"])

class BlockIPRequest(BaseModel):
    ip_address: str
    reason: str
    is_permanent: bool = False

@router.get("/")
async def list_blocked(current_user: dict = Depends(get_current_user)):
    blocked = get_blocked_ips()
    return [{"id": b.id, "ip_address": b.ip_address, "reason": b.reason,
             "blocked_at": b.blocked_at.isoformat(), "blocked_by": b.blocked_by,
             "is_permanent": b.is_permanent,
             "expires_at": b.expires_at.isoformat() if b.expires_at else None} for b in blocked]

@router.post("/block")
async def block(request: BlockIPRequest, current_user: dict = Depends(get_current_user)):
    result = block_ip(request.ip_address, request.reason, current_user["username"], request.is_permanent)
    return {"message": f"IP {request.ip_address} blocked", "block_id": result["id"]}

@router.delete("/unblock/{block_id}")
async def unblock(block_id: int, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin": raise HTTPException(status_code=403, detail="Admin access required")
    ip = unblock_ip(block_id)
    if not ip: raise HTTPException(status_code=404, detail="Block entry not found")
    return {"message": f"IP {ip} unblocked"}
