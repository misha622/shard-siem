from fastapi import APIRouter, Depends
from app.auth import get_current_user, require_admin
from datetime import datetime
import platform, os

router = APIRouter(prefix="/api/settings", tags=["Settings"])

@router.get("/logs")
async def get_logs(lines: int = 50, current_user: dict = Depends(require_admin)):
    return {"logs": [{"timestamp": datetime.utcnow().isoformat(), "level": "INFO", "message": f"Log entry {i}", "correlation_id": f"id-{i}"} for i in range(min(lines, 100))]}

@router.get("/system-info")
async def system_info(current_user: dict = Depends(get_current_user)):
    return {"os": platform.system(), "os_version": platform.version(), "hostname": platform.node(), "cpu_count": os.cpu_count(), "python_version": platform.python_version(), "current_time": datetime.utcnow().isoformat()}
