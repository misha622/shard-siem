#!/usr/bin/env python3
"""SHARD Email Notifier — Mail.ru SMTP"""

import logging, smtplib
from email.mime.text import MIMEText

logger = logging.getLogger("SHARD-Email")

class EmailNotifier:
    def __init__(self):
        self.recipients = []
        self.mail_user = "shard019@mail.ru"
        self.mail_pass = "sjxpdwahRY8ZqVxMWX5u"
    
    def add_recipient(self, email):
        if email not in self.recipients:
            self.recipients.append(email)
    
    def send_alert(self, alert):
        if not self.recipients:
            return False
        
        severity = alert.get('severity', 'MEDIUM')
        emoji = '🔴' if severity == 'CRITICAL' else '🟠' if severity == 'HIGH' else '🟡'
        subject = f"{emoji} SHARD {severity}: {alert.get('attack_type', 'Unknown')}"
        body = f"""
SHARD Security Alert
Time: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Severity: {severity}
Attack: {alert.get('attack_type', 'Unknown')}
Code: {alert.get('explanation', '')}
"""
        success = True
        for recipient in self.recipients:
            try:
                msg = MIMEText(body)
                msg['Subject'] = subject
                msg['From'] = self.mail_user
                msg['To'] = recipient
                
                server = smtplib.SMTP_SSL('smtp.mail.ru', 465, timeout=15)
                server.login(self.mail_user, self.mail_pass)
                server.sendmail(self.mail_user, recipient, msg.as_string())
                server.quit()
                logger.info(f"📧 Sent to {recipient}")
            except Exception as e:
                logger.error(f"Email failed: {e}")
                success = False
        return success

email_notifier = EmailNotifier()
