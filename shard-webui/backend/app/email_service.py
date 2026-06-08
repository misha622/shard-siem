"""Email service for SHARD Enterprise SIEM — REAL SMTP."""
import logging
import random
import string
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from smtplib import SMTP
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)
_verification_codes = {}

class EmailService:
    """Real email notification service via SMTP."""
    
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASS", "")
        self.from_email = os.getenv("FROM_EMAIL", "shard@security.local")
        self.enabled = bool(self.smtp_user and self.smtp_password)
        
        if self.enabled:
            logger.info("📧 SMTP configured: %s", self.smtp_user)
        else:
            logger.warning("⚠️ SMTP not configured — codes in logs only")
    
    def generate_code(self, email: str) -> str:
        """Generate 6-digit verification code."""
        code = ''.join(random.choices(string.digits, k=6))
        _verification_codes[email] = {
            'code': code,
            'expires': datetime.utcnow() + timedelta(minutes=10)
        }
        logger.info("🔑 CODE for %s: %s", email, code)
        return code
    
    def verify_code(self, email: str, code: str) -> bool:
        """Verify code is valid."""
        stored = _verification_codes.get(email)
        if not stored or datetime.utcnow() > stored['expires']:
            if stored:
                del _verification_codes[email]
            return False
        if stored['code'] == code:
            del _verification_codes[email]
            return True
        return False
    
    async def send_verification(self, email: str, code: str) -> bool:
        """Send verification code via SMTP."""
        if not self.enabled:
            logger.info("📧 [NO SMTP] CODE for %s: %s", email, code)
            return True
        
        msg = MIMEMultipart()
        msg['From'] = self.from_email
        msg['To'] = email
        msg['Subject'] = 'SHARD Enterprise — Verification Code'
        
        html = f"""
        <div style="background:#0a0e17;padding:20px;font-family:Arial;">
            <h1 style="color:#00d4ff;">🛡️ SHARD Enterprise SIEM</h1>
            <p style="color:#fff;">Your verification code:</p>
            <h2 style="color:#00d4ff;font-size:32px;letter-spacing:8px;">{code}</h2>
            <p style="color:#888;">Code expires in 10 minutes.</p>
            <hr style="border-color:#333;">
            <p style="color:#666;font-size:12px;">If you didn't request this, ignore this email.</p>
        </div>
        """
        msg.attach(MIMEText(html, 'html'))
        
        try:
            with SMTP(self.smtp_host, self.smtp_port, timeout=10) as smtp:
                smtp.starttls()
                smtp.login(self.smtp_user, self.smtp_password)
                smtp.send_message(msg)
            logger.info("📧 Verification email SENT to %s", email)
            return True
        except Exception as e:
            logger.error("❌ SMTP failed: %s. Code in logs: %s", e, code)
            return False
    
    async def send_alert(self, email: str, alert_type: str, source_ip: str) -> bool:
        """Send alert notification."""
        if not self.enabled:
            return False
        
        msg = MIMEMultipart()
        msg['From'] = self.from_email
        msg['To'] = email
        msg['Subject'] = f'🚨 SHARD ALERT: {alert_type} from {source_ip}'
        
        html = f"""
        <div style="background:#0a0e17;padding:20px;font-family:Arial;">
            <h1 style="color:#ff4757;">🚨 Security Alert</h1>
            <p style="color:#fff;"><strong>Type:</strong> {alert_type}</p>
            <p style="color:#fff;"><strong>Source IP:</strong> {source_ip}</p>
            <p style="color:#fff;"><strong>Time:</strong> {datetime.utcnow().isoformat()}</p>
            <hr style="border-color:#333;">
            <a href="https://shrdai.serveousercontent.com" style="color:#00d4ff;">View Dashboard</a>
        </div>
        """
        msg.attach(MIMEText(html, 'html'))
        
        try:
            with SMTP(self.smtp_host, self.smtp_port, timeout=10) as smtp:
                smtp.starttls()
                smtp.login(self.smtp_user, self.smtp_password)
                smtp.send_message(msg)
            return True
        except Exception as e:
            logger.error("Alert email failed: %s", e)
            return False

email_service = EmailService()
