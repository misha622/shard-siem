import asyncio, logging, random, sys, os
from datetime import datetime
sys.path.insert(0, '/mnt/c/Users/user/PycharmProjects/Shard')

logger = logging.getLogger(__name__)

class SHARDEventBus:
    """Подключение к реальному SHARD EventBus"""
    def __init__(self):
        self.connected = False
        self._running = False
        self._task = None
        # Попытка подключения к SHARD
        try:
            from core.base import EventBus
            self._bus = EventBus()
            self._bus.subscribe('alert.detected', self._on_alert)
            self._bus.subscribe('firewall.blocked', self._on_block)
            logger.info("✅ Connected to SHARD EventBus")
        except Exception as e:
            logger.warning(f"SHARD EventBus unavailable: {e}")
            self._bus = None

    def _on_alert(self, alert):
        """Обработка алерта из SHARD — сохранение в БД с привязкой к компании"""
        try:
            from app.database import add_alert, match_alert_to_company
            # Матчим IP с компаниями
            company_id = match_alert_to_company(alert)
            alert['company_id'] = company_id
            add_alert(alert)
            logger.info(f"Alert saved: {alert.get('attack_type')} → company {company_id}")
        except Exception as e:
            logger.error(f"Failed to save alert: {e}")

    def _on_block(self, data):
        logger.info(f"IP blocked: {data.get('ip')}")

    async def start(self):
        self._running = True
        if self._bus:
            logger.info("🚀 SHARD EventBus listener started")
        else:
            logger.info("⚠️ Demo mode — generating sample alerts")
            self._task = asyncio.create_task(self._demo_loop())

    async def _demo_loop(self):
        """Генерация демо-алертов если SHARD не подключен"""
        from app.database import add_alert, match_alert_to_company
        while self._running:
            await asyncio.sleep(15)
            alert = {
                "alert_type": random.choice(["DDoS","SQL Injection","Port Scan","Brute Force"]),
                "severity": random.choice(["CRITICAL","HIGH","MEDIUM","LOW"]),
                "source_ip": f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                "destination_ip": random.choice(["192.168.1.100","172.16.0.10","10.100.0.5"]),
                "destination_port": random.choice([22,80,443,445]),
                "threat_score": random.uniform(10,100),
                "description": "Demo alert"
            }
            alert['company_id'] = match_alert_to_company(alert)
            add_alert(alert)

eventbus = SHARDEventBus()
