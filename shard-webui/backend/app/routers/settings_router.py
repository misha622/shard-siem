from fastapi import APIRouter, Depends, HTTPException, status
from app.auth import get_current_user, require_role
from app.models import UserRole
import logging
import os
from datetime import datetime

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/settings", tags=["Settings"])


@router.get("/logs")
async def get_system_logs(
        lines: int = 100,
        current_user: dict = Depends(require_role(UserRole.ADMIN))
):
    """
    Get system logs (admin only)
    """
    # In production, read from actual log files
    return {
        "logs": [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "level": "INFO",
                "message": f"System log entry {i}",
                "correlation_id": f"corr-{i}"
            } for i in range(min(lines, 100))
        ]
    }


@router.get("/system-info")
async def get_system_info(
        current_user: dict = Depends(require_role(UserRole.ADMIN))
):
    """
    Get system information (admin only)
    """
    import platform
    import sys

    return {
        "os": platform.system(),
        "os_version": platform.version(),
        "python_version": sys.version,
        "hostname": platform.node(),
        "cpu_count": os.cpu_count(),
        "current_time": datetime.utcnow().isoformat()
    }