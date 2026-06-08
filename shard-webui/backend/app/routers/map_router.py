"""map_router API endpoints."""
from fastapi import APIRouter, Depends
from app.auth import get_current_user
from app.database import get_alerts_for_map

router = APIRouter(prefix="/api/map", tags=["Attack Map"])

@router.get("/attacks")
async def get_attacks(current_user: dict = Depends(get_current_user)):
    alerts = get_alerts_for_map()
    points = []
    for a in alerts:
        if a.source_lat and a.source_lon:
            points.append({
                "ip": a.source_ip, "lat": a.source_lat, "lon": a.source_lon,
                "country": a.source_country or "Unknown",
                "city": a.source_city or "Unknown",
                "alert_type": a.alert_type, "severity": a.severity,
                "threat_score": a.threat_score, "timestamp": a.timestamp.isoformat()
            })
    return {"attacks": points, "total": len(points)}
