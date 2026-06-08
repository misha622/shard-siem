"""Email service for SHARD Enterprise SIEM — real SMTP."""
import logging
import random
import string
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# Хранилище кодов верификации (в памяти, для прода нужна БД)
_verification_codes = {}

class EmailService:
    """Real email notification service."""
    
    def __init__(self):
        self.enabled = True
        self.smtp_host = "smtp.gmail.com"
        self.smtp_port = 587
        self.smtp_user = None  # Настроить в .env
        self.smtp_password = None  # Настроить в .env
        
        # Загружаем из переменных окружения если есть
        import os
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASS", "")
        self.from_email = os.getenv("FROM_EMAIL", "shard@security.local")
        
        if self.smtp_user and self.smtp_password:
            self.enabled = True
            logger.info("Email service configured")
        else:
            logger.warning("SMTP not configured — set SMTP_USER and SMTP_PASS in .env")
    
    def generate_code(self, email: str) -> str:
        """Generate 6-digit verification code."""
        code = ''.join(random.choices(string.digits, k=6))
        _verification_codes[email] = {
            'code': code,
            'expires': datetime.utcnow() + timedelta(minutes=10)
        }
        logger.info("Verification code for %s: %s", email, code)
        return code
    
    def verify_code(self, email: str, code: str) -> bool:
        """Verify code is valid."""
        stored = _verification_codes.get(email)
        if not stored:
            return False
        if datetime.utcnow() > stored['expires']:
            del _verification_codes[email]
            return False
        if stored['code'] == code:
            del _verification_codes[email]
            return True
        return False
    
    async def send_verification(self, email: str, code: str) -> bool:
        """Send verification code email."""
        if not self.enabled:
            logger.warning("Email disabled, code: %s", code)
            return True
        
        msg = MIMEMultipart()
        msg['From'] = self.from_email
        msg['To'] = email
        msg['Subject'] = 'SHARD Enterprise — Verification Code'
        
        body = f"""
        <h2>SHARD Enterprise SIEM</h2>
        <p>Your verification code is:</p>
        <h1 style="color:#00d4ff;font-size:32px;letter-spacing:8px">{code}</h1>
        <p>This code expires in 10 minutes.</p>
        <p>If you didn't request this, ignore this email.</p>
        """
        msg.attach(MIMEText(body, 'html'))
        
        try:
            await aiosmtplib.send(
                msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                start_tls=True
            )
            logger.info("Verification email sent to %s", email)
            return True
        except Exception as e:
            logger.error("Failed to send email: %s", e)
            # Для теста — выводим код в логи
            logger.info("VERIFICATION CODE for %s: %s", email, code)
            return False
    
    async def send_alert(self, email: str, alert_type: str, source_ip: str) -> bool:
        """Send alert notification."""
        if not self.enabled:
            return False
        
        msg = MIMEMultipart()
        msg['From'] = self.from_email
        msg['To'] = email
        msg['Subject'] = f'SHARD ALERT: {alert_type} from {source_ip}'
        
        body = f"""
        <h2>🚨 SHARD Enterprise Alert</h2>
        <p><strong>Type:</strong> {alert_type}</p>
        <p><strong>Source IP:</strong> {source_ip}</p>
        <p><strong>Time:</strong> {datetime.utcnow().isoformat()}</p>
        <hr>
        <p><a href="https://shrdai.serveousercontent.com">View Dashboard</a></p>
        """
        msg.attach(MIMEText(body, 'html'))
        
        try:
            await aiosmtplib.send(
                msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                start_tls=True
            )
            return True
        except Exception as e:
            logger.error("Alert email failed: %s", e)
            return False

email_service = EmailService()
