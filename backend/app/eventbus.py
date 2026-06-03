import asyncio, logging, uuid, random
from datetime import datetime
from app.database import db
from app.email_service import email_service, EmailTemplate, EmailMessage, EmailEvent, EmailPriority

logger = logging.getLogger(__name__)

class SHARDEventBus:
    def __init__(self):
        self.connected = False
        self.subscribers = {"alert.detected":[],"firewall.blocked":[],"packet.processed":[]}
        self._running = False
        self._task = None

    async def connect(self):
        await asyncio.sleep(0.5)
        self.connected = True
        logger.info("Connected to SHARD EventBus")

    async def disconnect(self):
        self._running = False
        if self._task: self._task.cancel()
        self.connected = False

    def subscribe(self, event_type: str, callback):
        if event_type in self.subscribers:
            self.subscribers[event_type].append(callback)

    async def publish(self, event_type: str, data: dict):
        for cb in self.subscribers.get(event_type, []):
            try:
                if asyncio.iscoroutinefunction(cb): await cb(data)
                else: cb(data)
            except Exception as e:
                logger.error(f"Subscriber error: {e}")

    async def start_listening(self):
        self._running = True
        self._task = asyncio.create_task(self._event_loop())

    async def _event_loop(self):
        alert_types = ["DDoS","SQL Injection","XSS","Brute Force","Port Scan","Malware","Phishing","Ransomware","Data Exfiltration"]
        severities = ["CRITICAL","HIGH","MEDIUM","LOW"]
        geo_data = [
            (45.33,32.156,37.7749,-122.4194,"US","San Francisco"),
            (103.224,182.243,28.6139,77.2090,"IN","New Delhi"),
            (78.128,113.94,50.0755,14.4378,"CZ","Prague"),
            (185.220,101.34,52.5200,13.4050,"DE","Berlin"),
            (91.121,87.45,48.8566,2.3522,"FR","Paris"),
        ]
        while self._running and self.connected:
            await asyncio.sleep(15)
            geo = random.choice(geo_data)
            alert = {
                "alert_type": random.choice(alert_types),
                "severity": random.choice(severities),
                "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "source_lat": geo[2], "source_lon": geo[3],
                "source_country": geo[4], "source_city": geo[5],
                "destination_ip": random.choice(["192.168.1.100","192.168.1.50","10.0.0.1"]),
                "destination_port": random.choice([22,80,443,445,3389]),
                "protocol": random.choice(["TCP","UDP","HTTP","SSH"]),
                "description": "Automated alert from SHARD EventBus",
                "threat_score": random.uniform(10,100)
            }
            await db.add_alert(alert)
            await self.publish("alert.detected", alert)

            if alert["severity"] in ["CRITICAL","HIGH"]:
                try:
                    users = await db.get_all_users()
                    for u in users:
                        settings = await db.get_email_settings(u["id"])
                        event_key = f"alert.{alert['severity'].lower()}"
                        if u.get("email") and settings.get(event_key):
                            msg = EmailMessage(
                                to=[u["email"]],
                                subject=f"[{alert['severity']}] {alert['alert_type']} from {alert['source_ip']}",
                                body_html=EmailTemplate.critical_alert(alert),
                                event_type=EmailEvent.ALERT_CRITICAL if alert["severity"]=="CRITICAL" else EmailEvent.ALERT_HIGH,
                                priority=EmailPriority.CRITICAL if alert["severity"]=="CRITICAL" else EmailPriority.HIGH
                            )
                            await email_service.send(msg)
                except Exception as e:
                    logger.error(f"Failed to send alert email: {e}")

eventbus = SHARDEventBus()
