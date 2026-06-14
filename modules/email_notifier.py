#!/usr/bin/env python3
"""SHARD Email Notifier — отправка алертов на почту"""

import smtplib, logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

logger = logging.getLogger("SHARD-Email")

class EmailNotifier:
    def __init__(self, smtp_server="smtp.mail.ru", smtp_port=465, 
                 username='mishaefremov022@gmail.com', password='astq fyqj xfhm psfo', from_email=None):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.from_email = from_email or username
        self.recipients = []
    
    def add_recipient(self, email):
        if email not in self.recipients:
            self.recipients.append(email)
    
    def send_alert(self, alert):
        if not self.recipients:
            return False
        
        severity = alert.get('severity', 'MEDIUM')
        emoji = '🔴' if severity == 'CRITICAL' else '🟠' if severity == 'HIGH' else '🟡'
        
        subject = f"{emoji} SHARD {severity} Alert: {alert.get('attack_type', 'Unknown')}"
        body = f"""
SHARD Security Alert
=====================
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Severity: {severity}
Attack: {alert.get('attack_type', 'Unknown')}
Source: {alert.get('src_ip', '?')}
Target: {alert.get('dst_ip', '?')}:{alert.get('dst_port', '?')}
Score: {alert.get('score', 0):.2f}
Confidence: {alert.get('confidence', 0):.2f}

Dashboard: http://localhost:5001/dashboard.html
"""
        msg = MIMEMultipart()
        msg['From'] = self.from_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=10) as server:
                server.starttls()
                server.login(self.username, self.password)
                for recipient in self.recipients:
                    msg['To'] = recipient
                    server.sendmail(self.from_email, recipient, msg.as_string())
            logger.info(f"📧 Alert sent to {len(self.recipients)} recipients")
            return True
        except Exception as e:
            logger.error(f"Email send failed: {e}")
            return False

email_notifier = EmailNotifier()
