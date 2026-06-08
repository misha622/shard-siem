"""Email service for SHARD Enterprise SIEM."""
import logging

logger = logging.getLogger(__name__)

class EmailService:
    """Email notification service stub."""
    def __init__(self):
        self.enabled = False

    async def send(self, message):
        """Send email (stub)."""
        logger.debug("Email stub: %s", message)

    def get_stats(self):
        """Get service stats."""
        return {"enabled": False}

email_service = EmailService()
