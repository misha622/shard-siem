#!/usr/bin/env python3
"""SHARD Email Notifier — Uses EmailService"""

import logging
from modules.email_service import email_service

logger = logging.getLogger("SHARD-Email")

class EmailNotifier:
    def __init__(self):
        self.recipients = []
    
    def add_recipient(self, email):
        if email not in self.recipients:
            self.recipients.append(email)
    
    def send_alert(self, alert):
        if not self.recipients:
            return False
        
        severity = alert.get('severity', 'MEDIUM')
        attack_type = alert.get('attack_type', 'Unknown')
        details = f"""Source: {alert.get('src_ip', '?')}
Target: {alert.get('dst_ip', '?')}:{alert.get('dst_port', '?')}
Score: {alert.get('score', 0):.2f}
Confidence: {alert.get('confidence', 0):.2f}
{alert.get('explanation', '')}"""
        
        success = True
        for recipient in self.recipients:
            result = email_service.send_alert(recipient, attack_type, severity, details)
            if not result:
                success = False
        return success

email_notifier = EmailNotifier()
logger.info("✅ Email Notifier ready")
