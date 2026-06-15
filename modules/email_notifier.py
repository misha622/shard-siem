#!/usr/bin/env python3
"""SHARD Email Notifier — Gmail API + Mail.ru SMTP"""

import logging, base64, os
from email.mime.text import MIMEText
from pathlib import Path

logger = logging.getLogger("SHARD-Email")

class EmailNotifier:
    def __init__(self):
        self.recipients = []
        self._gmail_service = None
    
    def add_recipient(self, email):
        if email not in self.recipients:
            self.recipients.append(email)
    
    def _get_gmail_service(self):
        if self._gmail_service is None:
            from google.auth.transport.requests import Request
            from google.oauth2.credentials import Credentials
            from googleapiclient.discovery import build
            
            SCOPES = ['https://www.googleapis.com/auth/gmail.send']
            creds = None
            token_path = Path('/mnt/c/Users/user/PycharmProjects/Shard/token.json')
            
            if token_path.exists():
                creds = Credentials.from_authorized_user_file(str(token_path), SCOPES)
            
            if creds and creds.expired:
                creds.refresh(Request())
            
            self._gmail_service = build('gmail', 'v1', credentials=creds)
        
        return self._gmail_service
    
    def send_alert(self, alert):
        if not self.recipients:
            return False
        
        severity = alert.get('severity', 'MEDIUM')
        emoji = '🔴' if severity == 'CRITICAL' else '🟠' if severity == 'HIGH' else '🟡'
        
        subject = f"{emoji} SHARD {severity}: {alert.get('attack_type', 'Unknown')}"
        body = f"""
SHARD Security Alert
=====================
Time: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Severity: {severity}
Attack: {alert.get('attack_type', 'Unknown')}
Source: {alert.get('src_ip', '?')}
Target: {alert.get('dst_ip', '?')}:{alert.get('dst_port', '?')}
Score: {alert.get('score', 0):.2f}

Dashboard: http://localhost:5001/dashboard.html
"""
        success = True
        for recipient in self.recipients:
            try:
                service = self._get_gmail_service()
                msg = MIMEText(body)
                msg['Subject'] = subject
                msg['From'] = 'mishaefremov022@gmail.com'
                msg['To'] = recipient
                
                raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
                service.users().messages().send(userId='me', body={'raw': raw}).execute()
                logger.info(f"📧 Gmail API: alert sent to {recipient}")
            except Exception as e:
                logger.error(f"Email failed: {e}")
                success = False
        
        return success

email_notifier = EmailNotifier()
logger.info("✅ Email Notifier ready (Gmail API)")
