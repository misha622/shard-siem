import logging, ipaddress
from typing import Optional, Dict
from app.database import SessionLocal
from app.models import GeoCache
import httpx

logger = logging.getLogger(__name__)

class GeoIPService:
    def __init__(self):
        self.memory_cache: Dict[str, Dict] = {}
        self.base_url = "http://ip-api.com/json"

    async def lookup(self, ip: str) -> Optional[Dict]:
        # 1. Проверить memory cache
        if ip in self.memory_cache:
            return self.memory_cache[ip]

        # 2. Проверить БД кеш
        db = SessionLocal()
        try:
            cached = db.query(GeoCache).filter(GeoCache.ip == ip).first()
            if cached:
                result = {"lat": cached.latitude, "lon": cached.longitude, "country": cached.country, "city": cached.city, "isp": cached.isp}
                self.memory_cache[ip] = result
                return result
        finally:
            db.close()

        # 3. Локальные IP
        if ip.startswith(("192.168.", "10.", "172.16.", "127.", "0.")):
            return {"lat": 55.7558, "lon": 37.6173, "country": "Local", "city": "Internal", "isp": "Local"}

        # 4. Внешний сервис
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/{ip}")
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        result = {"lat": data["lat"], "lon": data["lon"], "country": data["country"], "city": data["city"], "isp": data.get("isp", "Unknown")}
                        # Сохранить в память
                        self.memory_cache[ip] = result
                        # Сохранить в БД
                        db = SessionLocal()
                        try:
                            db.merge(GeoCache(ip=ip, latitude=data["lat"], longitude=data["lon"], country=data["country"], city=data["city"], isp=data.get("isp", "")))
                            db.commit()
                        finally:
                            db.close()
                        return result
        except Exception as e:
            logger.error(f"GeoIP lookup failed for {ip}: {e}")
        return None

geo_service = GeoIPService()
