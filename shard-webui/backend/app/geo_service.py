import logging
import httpx
from typing import Optional, Dict

logger = logging.getLogger(__name__)

class GeoIPService:
    def __init__(self):
        self.cache: Dict[str, Dict] = {}
        self.base_url = "http://ip-api.com/json"

    async def lookup(self, ip: str) -> Optional[Dict]:
        if ip in self.cache:
            return self.cache[ip]
        if ip.startswith(("192.168.", "10.", "172.16.", "127.", "0.")):
            return {"lat": 55.7558, "lon": 37.6173, "country": "Local Network", "city": "Internal", "isp": "Local"}
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.get(f"{self.base_url}/{ip}")
                if response.status_code == 200:
                    data = response.json()
                    if data.get("status") == "success":
                        result = {"lat": data["lat"], "lon": data["lon"], "country": data["country"], "city": data["city"], "isp": data.get("isp", "Unknown")}
                        self.cache[ip] = result
                        return result
        except Exception as e:
            logger.error(f"GeoIP lookup failed for {ip}: {e}")
        return None

geo_service = GeoIPService()
