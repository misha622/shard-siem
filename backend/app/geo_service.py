"""
Geo-IP сервис для карты атак
Использует ip-api.com (бесплатный, 45 запросов/мин)
"""
import asyncio
import logging
from typing import Optional, Dict
import httpx

logger = logging.getLogger(__name__)


class GeoIPService:
    def __init__(self):
        self.cache: Dict[str, Dict] = {}
        self.base_url = "http://ip-api.com/json"
        self.rate_limit = 45  # запросов в минуту
        self.request_count = 0
        self.last_reset = asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0
    
    async def lookup(self, ip: str) -> Optional[Dict]:
        """Получить гео-данные по IP"""
        # Проверяем кэш
        if ip in self.cache:
            return self.cache[ip]
        
        # Проверяем локальные/приватные IP
        if ip.startswith(("192.168.", "10.", "172.16.", "127.", "0.")):
            return {"lat": 55.7558, "lon": 37.6173, "country": "Local Network", "city": "Internal", "isp": "Local"}
        
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/{ip}")
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        result = {
                            "lat": data["lat"],
                            "lon": data["lon"],
                            "country": data["country"],
                            "city": data["city"],
                            "isp": data.get("isp", "Unknown")
                        }
                        self.cache[ip] = result
                        return result
        except Exception as e:
            logger.error(f"GeoIP lookup failed for {ip}: {e}")
        
        return None
    
    async def lookup_batch(self, ips: list) -> Dict[str, Dict]:
        """Массовый поиск гео-данных"""
        results = {}
        for ip in ips[:45]:  # Ограничение rate limit
            result = await self.lookup(ip)
            if result:
                results[ip] = result
            await asyncio.sleep(0.1)  # Задержка между запросами
        return results


geo_service = GeoIPService()
