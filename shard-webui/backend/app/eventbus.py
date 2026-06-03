import asyncio, logging, random
from datetime import datetime
from app.database import add_alert, match_alert_to_company

logger = logging.getLogger(__name__)

class SHARDEventBus:
    def __init__(self):
        self.connected = False
        self.subscribers = {"alert.detected": [], "firewall.blocked": [], "packet.processed": []}
        self._running = False

    async def connect(self):
        await asyncio.sleep(0.5)
        self.connected = True
        logger.info("Connected to SHARD EventBus")

    async def publish(self, event_type: str, data: dict):
        for cb in self.subscribers.get(event_type, []):
            try:
                if asyncio.iscoroutinefunction(cb): await cb(data)
                else: cb(data)
            except Exception as e:
                logger.error(f"Subscriber error: {e}")

    async def start_listening(self):
        self._running = True
        while self._running and self.connected:
            await asyncio.sleep(15)
            alert_data = {
                "alert_type": random.choice(["DDoS","SQL Injection","Port Scan","Malware","Brute Force"]),
                "severity": random.choice(["CRITICAL","HIGH","MEDIUM","LOW"]),
                "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "destination_ip": random.choice(["192.168.1.100","172.16.0.10","10.100.0.5"]),
                "destination_port": random.choice([22,80,443,445]),
                "protocol": random.choice(["TCP","UDP","HTTP"]),
                "description": "Automated alert from SHARD EventBus",
                "threat_score": random.uniform(10,100)
            }
            # Авто-привязка к компании по IP
            company_id = match_alert_to_company(alert_data)
            if company_id:
                alert_data["company_id"] = company_id
            add_alert(alert_data)
            await self.publish("alert.detected", alert_data)

eventbus = SHARDEventBus()
