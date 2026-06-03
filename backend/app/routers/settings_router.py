from fastapi import APIRouter, Depends
from app.auth import require_role
from app.models import UserRole
from datetime import datetime

router = APIRouter(prefix="/api/settings", tags=["Settings"])

@router.get("/logs")
async def logs(lines: int = 100, current_user: dict = Depends(require_role(UserRole.ADMIN))):
    return {"logs": [{"timestamp": datetime.utcnow().isoformat(), "level": "INFO", "message": f"Log entry {i}", "correlation_id": f"id-{i}"} for i in range(min(lines, 100))]}

@router.get("/system-info")
async def system_info(current_user: dict = Depends(require_role(UserRole.ADMIN))):
    import platform, os
    return {"os": platform.system(), "hostname": platform.node(), "cpu_count": os.cpu_count()}
