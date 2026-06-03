from fastapi import APIRouter, Depends, Query
from typing import Optional
from app.auth import get_current_user
from app.database import db
from app.geo_service import geo_service
import logging

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/map", tags=["Attack Map"])


@router.get("/attacks")
async def get_attack_map_data(current_user: dict = Depends(get_current_user)):
    """Получить данные алертов с геолокацией для карты"""
    alerts = await db.get_alerts_for_map()
    
    attack_points = []
    for alert in alerts:
        if alert.get("source_lat") and alert.get("source_lon"):
            attack_points.append({
                "ip": alert["source_ip"],
                "lat": alert["source_lat"],
                "lon": alert["source_lon"],
                "country": alert.get("source_country", "Unknown"),
                "city": alert.get("source_city", "Unknown"),
                "alert_type": alert["alert_type"],
                "severity": alert["severity"],
                "threat_score": alert["threat_score"],
                "timestamp": alert["timestamp"],
            })
    
    return {
        "attacks": attack_points,
        "total": len(attack_points)
    }


@router.get("/lookup/{ip}")
async def lookup_ip(ip: str, current_user: dict = Depends(get_current_user)):
    """Получить гео-данные для конкретного IP"""
    result = await geo_service.lookup(ip)
    if result:
        return {"ip": ip, **result}
    return {"ip": ip, "error": "Could not resolve location"}


@router.get("/stats")
async def get_map_stats(current_user: dict = Depends(get_current_user)):
    """Получить статистику по странам для карты"""
    alerts = await db.get_alerts_for_map()
    
    countries = {}
    for alert in alerts:
        country = alert.get("source_country", "Unknown")
        if country not in countries:
            countries[country] = {"count": 0, "threats": 0}
        countries[country]["count"] += 1
        if alert["severity"] in ["CRITICAL", "HIGH"]:
            countries[country]["threats"] += 1
    
    return {
        "countries": [{"name": k, **v} for k, v in sorted(countries.items(), key=lambda x: x[1]["count"], reverse=True)[:20]],
        "total_countries": len(countries)
    }
