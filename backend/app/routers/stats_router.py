from fastapi import APIRouter, Depends
from app.database import db
from app.auth import get_current_user
import psutil, logging
from datetime import datetime

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/stats", tags=["Statistics"])

@router.get("/dashboard")
async def dashboard(current_user: dict = Depends(get_current_user)):
    return await db.get_stats()

@router.get("/system")
async def system(current_user: dict = Depends(get_current_user)):
    try:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        net = psutil.net_io_counters()
        uptime = int(psutil.boot_time())
        return {
            "cpu_percent": cpu, "memory_percent": mem.percent, "disk_percent": disk.percent,
            "network_sent_mb": round(net.bytes_sent/(1024*1024),2),
            "network_recv_mb": round(net.bytes_recv/(1024*1024),2),
            "uptime_hours": round((datetime.now().timestamp()-uptime)/3600,2),
            "timestamp": datetime.utcnow().isoformat()
        }
    except:
        return {"cpu_percent":0,"memory_percent":0,"disk_percent":0,"network_sent_mb":0,"network_recv_mb":0,"uptime_hours":0}
