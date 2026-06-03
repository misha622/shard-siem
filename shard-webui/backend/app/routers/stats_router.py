from fastapi import APIRouter, Depends
from database import get_stats
from auth import get_current_user
import psutil, logging
from datetime import datetime

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/stats", tags=["Statistics"])

@router.get("/dashboard")
async def dashboard(current_user: dict = Depends(get_current_user)):
    company_id = None if current_user["role"] == "admin" else current_user.get("company_id")
    return get_stats(company_id)

@router.get("/system")
async def system(current_user: dict = Depends(get_current_user)):
    try:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        return {"cpu_percent": cpu, "memory_percent": mem.percent, "disk_percent": disk.percent}
    except:
        return {"cpu_percent": 0, "memory_percent": 0, "disk_percent": 0}
