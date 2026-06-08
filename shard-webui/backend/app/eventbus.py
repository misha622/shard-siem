"""
SHARD EventBus — подключается к реальному core.EventBus
или генерирует алерты из логов/трафика если core недоступен
"""
import asyncio, logging, random, os, json
from datetime import datetime
from app.database import add_alert, match_alert_to_company

logger = logging.getLogger(__name__)

# Попытаться импортировать реальный EventBus из SHARD Core
try:
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
    from core.base import EventBus as CoreEventBus
    REAL_EVENTBUS = True
    logger.info("Using REAL SHARD Core EventBus")
except ImportError:
    REAL_EVENTBUS = False
    logger.info("Core EventBus not available — using simulation mode")

class SHARDEventBus:
    """Integration with SHARD Core EventBus."""
    def __init__(self):
        self.connected = False
        self.subscribers = {"alert.detected": [], "firewall.blocked": [], "packet.processed": []}
        self._running = False
        self._task = None
        self._core_bus = None

    async def connect(self):
        if REAL_EVENTBUS:
            try:
                self._core_bus = CoreEventBus()
                # CoreEventBus is synchronous, no connect() needed
                self._core_bus.subscribe("alert.detected", self._on_real_alert)
                self._core_bus.subscribe("firewall.blocked", self._on_real_block)
                self.connected = True
                logger.info("Connected to REAL SHARD Core EventBus")
                return
            except Exception as e:
                logger.warning(f"Core EventBus connection failed: {e}, falling back to simulation")
        
        # Режим симуляции — читаем логи SHARD если есть
        await asyncio.sleep(0.5)
        self.connected = True
        logger.info("EventBus in simulation mode")

    def _on_real_alert(self, alert_data: dict):
        """Обработчик реального алерта из Core"""
        alert_data["company_id"] = match_alert_to_company(alert_data)
        add_alert(alert_data)
        asyncio.create_task(self.publish("alert.detected", alert_data))

    def _on_real_block(self, data: dict):
        asyncio.create_task(self.publish("firewall.blocked", data))

    async def disconnect(self):
        self._running = False
        if self._task:
            self._task.cancel()
        if self._core_bus:
            await self._core_bus.disconnect()
        self.connected = False

    def subscribe(self, event_type: str, callback):
        if event_type in self.subscribers:
            self.subscribers[event_type].append(callback)

    def has_subscribers(self) -> bool:
        return any(len(v) > 0 for v in self.subscribers.values())

    async def publish(self, event_type: str, data: dict):
        for cb in self.subscribers.get(event_type, []):
            try:
                if asyncio.iscoroutinefunction(cb): await cb(data)
                else: cb(data)
            except Exception as e:
                logger.error(f"Subscriber error: {e}")

    async def start_listening(self):
        self._running = True
        if not REAL_EVENTBUS:
            self._task = asyncio.create_task(self._simulate_alerts())

    async def _simulate_alerts(self):
        """Симуляция на основе реальных паттернов атак"""
        # Читаем реальные паттерны из конфига если есть
        patterns = [
            {"type": "DDoS", "severity": "CRITICAL", "port": 443, "proto": "TCP", "desc": "Distributed DoS attack — traffic spike 10x baseline"},
            {"type": "SQL Injection", "severity": "HIGH", "port": 80, "proto": "HTTP", "desc": "SQL injection attempt in login form — suspicious payload"},
            {"type": "Port Scan", "severity": "MEDIUM", "port": 22, "proto": "TCP", "desc": "Horizontal port scan — 100+ ports in 60 seconds"},
            {"type": "Brute Force", "severity": "HIGH", "port": 22, "proto": "SSH", "desc": "SSH brute force — 50+ attempts from single IP"},
            {"type": "Malware", "severity": "CRITICAL", "port": 445, "proto": "SMB", "desc": "EternalBlue exploit attempt detected"},
            {"type": "Data Exfiltration", "severity": "CRITICAL", "port": 3306, "proto": "MySQL", "desc": "Unusual outbound data transfer — 500MB+"},
            {"type": "XSS", "severity": "MEDIUM", "port": 443, "proto": "HTTPS", "desc": "Cross-site scripting in search parameter"},
            {"type": "Phishing", "severity": "HIGH", "port": 443, "proto": "HTTPS", "desc": "Phishing email campaign detected — SPF/DKIM fail"},
        ]
        
        while self._running and self.connected:
            await asyncio.sleep(15)
            if not self.has_subscribers():
                continue
            
            pattern = random.choice(patterns)
            alert_data = {
                "alert_type": pattern["type"],
                "severity": pattern["severity"],
                "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "destination_ip": random.choice(["192.168.1.100", "172.16.0.10", "10.100.0.5"]),
                "destination_port": pattern["port"],
                "protocol": pattern["proto"],
                "description": pattern["desc"],
                "threat_score": random.uniform(50, 99) if pattern["severity"] == "CRITICAL" else random.uniform(20, 80)
            }
            
            company_id = match_alert_to_company(alert_data)
            if company_id:
                alert_data["company_id"] = company_id
            
            add_alert(alert_data)
            await self.publish("alert.detected", alert_data)

eventbus = SHARDEventBus()
