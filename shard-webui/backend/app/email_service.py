"""Email service stub for SHARD Enterprise SIEM"""
import logging, os

logger = logging.getLogger(__name__)

class EmailService:
    def __init__(self):
        self.enabled = False
        logger.info("Email service disabled: not configured")
    
    async def send(self, msg): pass
    async def start_worker(self): pass
    async def stop_worker(self): pass
    def get_stats(self): return {"enabled": False}

email_service = EmailService()

# Stub classes for compatibility
class EmailMessage:
    def __init__(self, to=None, subject="", body_html="", event_type="", priority=None): pass

class EmailTemplate:
    @staticmethod
    def critical_alert(data): return ""
    @staticmethod
    def registration_confirm(u, e): return ""

class EmailEvent:
    REGISTRATION_CONFIRM = "reg"
    ALERT_CRITICAL = "alert.crit"
    ALERT_HIGH = "alert.high"
    CUSTOM = "custom"

class EmailPriority:
    CRITICAL = "crit"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"
