from fastapi import APIRouter, Depends
from app.database import db
from app.auth import get_current_user
from app.schemas import SystemMetricsResponse
import psutil
import logging
from datetime import datetime

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/stats", tags=["Statistics"])


@router.get("/dashboard")
async def get_dashboard_stats(
        current_user: dict = Depends(get_current_user)
):
    """
    Get dashboard statistics
    """
    stats = db.get_stats()
    return stats


@router.get("/system")
async def get_system_metrics(
        current_user: dict = Depends(get_current_user)
):
    """
    Get system metrics
    """
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        network = psutil.net_io_counters()
        uptime_seconds = int(psutil.boot_time())

        return SystemMetricsResponse(
            cpu_percent=cpu_percent,
            memory_percent=memory.percent,
            disk_percent=disk.percent,
            network_sent_mb=round(network.bytes_sent / (1024 * 1024), 2),
            network_recv_mb=round(network.bytes_recv / (1024 * 1024), 2),
            uptime_hours=round((datetime.now().timestamp() - uptime_seconds) / 3600, 2),
            timestamp=datetime.utcnow()
        )
    except Exception as e:
        logger.error(f"Error getting system metrics: {e}")
        return SystemMetricsResponse(
            cpu_percent=0,
            memory_percent=0,
            disk_percent=0,
            network_sent_mb=0,
            network_recv_mb=0,
            uptime_hours=0,
            timestamp=datetime.utcnow()
        )


@router.get("/alerts-by-hour")
async def get_alerts_by_hour(
        current_user: dict = Depends(get_current_user)
):
    """
    Get alerts grouped by hour for the last 24 hours
    """
    stats = db.get_stats()
    return stats["alerts_by_hour"]


@router.get("/top-attackers")
async def get_top_attackers(
        limit: int = 10,
        current_user: dict = Depends(get_current_user)
):
    """
    Get top attacking IPs
    """
    stats = db.get_stats()
    return stats["top_attackers"][:limit]


@router.get("/top-targets")
async def get_top_targets(
        limit: int = 10,
        current_user: dict = Depends(get_current_user)
):
    """
    Get top targeted IPs
    """
    stats = db.get_stats()
    return stats["top_targets"][:limit]