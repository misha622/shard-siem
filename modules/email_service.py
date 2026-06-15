#!/usr/bin/env python3
"""SHARD Email Service — Multi-provider with auto-fallback"""

import logging, smtplib, os
from email.mime.text import MIMEText
from datetime import datetime

logger = logging.getLogger("SHARD-EmailService")

# Настройки провайдеров (приоритет: Mail.ru → Gmail API → Gmail SMTP)
PROVIDERS = [
    {
        'name': 'Mail.ru',
        'server': 'smtp.mail.ru',
        'port': 465,
        'ssl': True,
        'user': 'shard019@mail.ru',
        'password': 'sjxpdwahRY8ZqVxMWX5u',
        'from': 'shard019@mail.ru'
    }
]

class EmailService:
    def __init__(self):
        self.last_provider = None
    
    def send(self, to: str, subject: str, body: str) -> bool:
        """Отправляет email через первый доступный провайдер"""
        for provider in PROVIDERS:
            try:
                if provider.get('ssl'):
                    server = smtplib.SMTP_SSL(provider['server'], provider['port'], timeout=15)
                else:
                    server = smtplib.SMTP(provider['server'], provider['port'], timeout=15)
                    server.starttls()
                
                server.login(provider['user'], provider['password'])
                
                msg = MIMEText(body, 'plain', 'utf-8')
                msg['Subject'] = subject
                msg['From'] = provider['from']
                msg['To'] = to
                
                server.sendmail(provider['from'], to, msg.as_string())
                server.quit()
                
                self.last_provider = provider['name']
                logger.info(f"📧 Sent via {provider['name']} to {to}")
                return True
                
            except Exception as e:
                logger.warning(f"⚠️ {provider['name']} failed: {str(e)[:80]}")
                continue
        
        logger.error(f"❌ All providers failed for {to}")
        return False
    
    def send_verification_code(self, to: str, code: str) -> bool:
        """Отправляет код верификации с красивым шаблоном"""
        subject = f"SHARD Verification Code: {code}"
        body = f"""╔══════════════════════════════════╗
║     SHARD SECURITY VERIFICATION    ║
╠══════════════════════════════════╣
║                                    ║
║     Your verification code is:     ║
║                                    ║
║          {code}                  ║
║                                    ║
║     This code expires in 10 min.   ║
║                                    ║
╚══════════════════════════════════╝

Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
IP: system

If you didn't request this, ignore this email.
"""
        return self.send(to, subject, body)
    
    def send_alert(self, to: str, alert_type: str, severity: str, details: str = "") -> bool:
        """Отправляет алерт безопасности"""
        emoji = '🔴' if severity == 'CRITICAL' else '🟠' if severity == 'HIGH' else '🟡'
        subject = f"{emoji} SHARD {severity}: {alert_type}"
        body = f"""SHARD Security Alert
=====================
Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Severity: {severity}
Type: {alert_type}
{details}

Dashboard: http://localhost:5001/dashboard.html
"""
        return self.send(to, subject, body)


# Глобальный экземпляр
email_service = EmailService()

logger.info("✅ Email Service ready (Mail.ru SMTP)")
