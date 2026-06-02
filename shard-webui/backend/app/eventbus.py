import asyncio
import json
import logging
from typing import Optional, Callable
from datetime import datetime
from app.models import Alert, SeverityLevel, AlertType
from app.database import db
import uuid

logger = logging.getLogger(__name__)


class SHARDEventBus:
    """
    Connector to SHARD Core EventBus
    In production, this would connect to the actual SHARD message broker
    """

    def __init__(self):
        self.connected = False
        self.subscribers: dict = {
            "alert.detected": [],
            "firewall.blocked": [],
            "packet.processed": []
        }
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def connect(self):
        """Connect to SHARD EventBus"""
        try:
            # Simulate connection to event bus
            await asyncio.sleep(0.5)
            self.connected = True
            logger.info("Connected to SHARD EventBus")
        except Exception as e:
            logger.error(f"Failed to connect to SHARD EventBus: {e}")
            self.connected = False

    async def disconnect(self):
        """Disconnect from SHARD EventBus"""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self.connected = False
        logger.info("Disconnected from SHARD EventBus")

    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to event type"""
        if event_type in self.subscribers:
            self.subscribers[event_type].append(callback)
            logger.info(f"Subscribed to {event_type}")

    async def publish(self, event_type: str, data: dict):
        """Publish event to subscribers"""
        if event_type in self.subscribers:
            for callback in self.subscribers[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                except Exception as e:
                    logger.error(f"Error in subscriber callback: {e}")

    async def start_listening(self):
        """Start listening for events"""
        self._running = True
        self._task = asyncio.create_task(self._event_loop())
        logger.info("Started listening for SHARD events")

    async def _event_loop(self):
        """Main event loop - simulates receiving events"""
        while self._running and self.connected:
            try:
                # In production, this would be actual message consumption
                # For demo, we'll simulate random events
                await asyncio.sleep(10)  # Simulate event every 10 seconds

                # Generate random event
                import random
                event_types = ["alert.detected", "packet.processed"]
                event_type = random.choice(event_types)

                if event_type == "alert.detected":
                    alert_data = self._generate_alert()
                    db.add_alert(alert_data)
                    await self.publish("alert.detected", alert_data.dict())

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in event loop: {e}")
                await asyncio.sleep(5)

    def _generate_alert(self) -> Alert:
        """Generate a simulated alert"""
        import random
        from datetime import timedelta

        alert_types = list(AlertType)
        severities = list(SeverityLevel)
        sources = [
            f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"]
        destinations = ["192.168.1.100", "192.168.1.50", "10.0.0.1"]

        return Alert(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow() - timedelta(seconds=random.randint(0, 300)),
            alert_type=random.choice(alert_types),
            severity=random.choice(severities),
            source_ip=random.choice(sources),
            destination_ip=random.choice(destinations),
            destination_port=random.choice([22, 80, 443, 445, 3389]),
            protocol=random.choice(["TCP", "UDP", "HTTP", "SSH"]),
            description=f"Automated alert from SHARD EventBus",
            threat_score=random.uniform(10, 100)
        )


# Global event bus instance
eventbus = SHARDEventBus()