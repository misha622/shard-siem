from fastapi import APIRouter, Depends, HTTPException, status
from typing import List
from app.schemas import BlockIPRequest, BlockedIPResponse
from app.database import db
from app.auth import get_current_user, require_role
from app.models import UserRole
from app.eventbus import eventbus
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/blocked", tags=["Blocked IPs"])


@router.get("/", response_model=List[BlockedIPResponse])
async def get_blocked_ips(
        current_user: dict = Depends(get_current_user)
):
    """
    Get all blocked IPs
    """
    blocked_ips = db.get_blocked_ips()
    return [
        BlockedIPResponse(
            id=b.id,
            ip_address=b.ip_address,
            reason=b.reason,
            blocked_at=b.blocked_at,
            blocked_by=b.blocked_by,
            is_permanent=b.is_permanent,
            expires_at=b.expires_at
        ) for b in blocked_ips
    ]


@router.post("/block", response_model=BlockedIPResponse)
async def block_ip(
        request: BlockIPRequest,
        current_user: dict = Depends(get_current_user)
):
    """
    Block an IP address
    """
    # Check if already blocked
    for blocked in db.get_blocked_ips():
        if blocked.ip_address == request.ip_address:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"IP {request.ip_address} is already blocked"
            )

    blocked = db.block_ip(
        ip_address=request.ip_address,
        reason=request.reason,
        blocked_by=current_user["username"],
        is_permanent=request.is_permanent
    )

    # Notify event bus
    await eventbus.publish("firewall.blocked", {
        "ip": request.ip_address,
        "reason": request.reason,
        "blocked_by": current_user["username"],
        "is_permanent": request.is_permanent
    })

    logger.info(f"IP {request.ip_address} blocked by {current_user['username']}")

    return BlockedIPResponse(
        id=blocked.id,
        ip_address=blocked.ip_address,
        reason=blocked.reason,
        blocked_at=blocked.blocked_at,
        blocked_by=blocked.blocked_by,
        is_permanent=blocked.is_permanent,
        expires_at=blocked.expires_at
    )


@router.delete("/unblock/{block_id}")
async def unblock_ip(
        block_id: str,
        current_user: dict = Depends(require_role(UserRole.ADMIN))
):
    """
    Unblock an IP address (admin only)
    """
    if block_id not in db.blocked_ips:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Block entry not found"
        )

    blocked = db.blocked_ips.pop(block_id)

    # Unblock related alerts
    for alert in db.alerts.values():
        if alert.source_ip == blocked.ip_address:
            alert.is_blocked = False
            alert.blocked_at = None

    logger.info(f"IP {blocked.ip_address} unblocked by {current_user['username']}")

    return {"message": f"IP {blocked.ip_address} unblocked successfully"}