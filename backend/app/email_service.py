"""
Email Notification Service для SHARD Enterprise SIEM
Поддерживает SMTP, шаблоны писем, очереди отправки
"""
import asyncio
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum
import json
import os

logger = logging.getLogger(__name__)


class EmailPriority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class EmailEvent(str, Enum):
    ALERT_CRITICAL = "alert.critical"
    ALERT_HIGH = "alert.high"
    ALERT_MEDIUM = "alert.medium"
    IP_BLOCKED = "ip.blocked"
    IP_UNBLOCKED = "ip.unblocked"
    SYSTEM_HEALTH = "system.health"
    WEEKLY_REPORT = "report.weekly"
    LOGIN_NEW_DEVICE = "login.new_device"
    PASSWORD_CHANGED = "password.changed"
    REGISTRATION_CONFIRM = "registration.confirm"
    CUSTOM = "custom"


@dataclass
class EmailMessage:
    to: List[str]
    subject: str
    body_html: str
    body_text: str = ""
    priority: EmailPriority = EmailPriority.NORMAL
    event_type: EmailEvent = EmailEvent.CUSTOM
    attachments: List[str] = field(default_factory=list)
    cc: List[str] = field(default_factory=list)
    bcc: List[str] = field(default_factory=list)
    reply_to: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class EmailTemplate:
    """HTML шаблоны писем"""
    
    @staticmethod
    def base_template(content: str, title: str = "SHARD Enterprise SIEM") -> str:
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin:0;padding:0;background-color:#000000;font-family:'Segoe UI',Arial,sans-serif;">
            <div style="max-width:600px;margin:0 auto;padding:20px;">
                <!-- Header -->
                <div style="background:linear-gradient(135deg,#0a0a0a,#111111);border:1px solid rgba(0,212,255,0.15);border-radius:12px 12px 0 0;padding:24px;text-align:center;">
                    <h1 style="color:#00d4ff;margin:0;font-size:24px;">SHARD Enterprise</h1>
                    <p style="color:rgba(255,255,255,0.5);margin:4px 0 0;font-size:12px;">SIEM v5.2.0 — {title}</p>
                </div>
                <!-- Content -->
                <div style="background:#0a0a0a;border-left:1px solid rgba(0,212,255,0.15);border-right:1px solid rgba(0,212,255,0.15);padding:24px;">
                    {content}
                </div>
                <!-- Footer -->
                <div style="background:#0a0a0a;border:1px solid rgba(0,212,255,0.15);border-top:none;border-radius:0 0 12px 12px;padding:16px;text-align:center;">
                    <p style="color:rgba(255,255,255,0.3);font-size:11px;margin:0;">
                        This is an automated message from SHARD Enterprise SIEM.<br>
                        Sent at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC<br>
                        <a href="https://shard-enterprise.com/unsubscribe" style="color:#00d4ff;text-decoration:none;">Unsubscribe</a> | 
                        <a href="https://shard-enterprise.com/settings" style="color:#00d4ff;text-decoration:none;">Notification Settings</a>
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
    
    @staticmethod
    def critical_alert(alert: dict) -> str:
        severity_color = {"CRITICAL": "#ff4757", "HIGH": "#ffa502", "MEDIUM": "#ffd700", "LOW": "#2ed573"}
        color = severity_color.get(alert.get("severity", ""), "#00d4ff")
        
        content = f"""
        <div style="background:rgba(255,71,87,0.1);border:1px solid {color};border-radius:8px;padding:16px;margin-bottom:16px;">
            <h2 style="color:{color};margin:0 0 12px;font-size:18px;">🚨 {alert.get('severity', 'UNKNOWN')} Alert Detected</h2>
            <table style="width:100%;border-collapse:collapse;color:#ffffff;font-size:13px;">
                <tr><td style="padding:6px 8px;color:rgba(255,255,255,0.5);width:120px;">Alert Type</td><td style="padding:6px 8px;color:#00d4ff;">{alert.get('alert_type', 'N/A')}</td></tr>
                <tr style="background:rgba(255,255,255,0.02);"><td style="padding:6px 8px;color:rgba(255,255,255,0.5);">Source IP</td><td style="padding:6px 8px;font-family:monospace;">{alert.get('source_ip', 'N/A')}</td></tr>
                <tr><td style="padding:6px 8px;color:rgba(255,255,255,0.5);">Target IP</td><td style="padding:6px 8px;font-family:monospace;">{alert.get('destination_ip', 'N/A')}</td></tr>
                <tr style="background:rgba(255,255,255,0.02);"><td style="padding:6px 8px;color:rgba(255,255,255,0.5);">Threat Score</td><td style="padding:6px 8px;font-weight:bold;color:{color};">{alert.get('threat_score', 0):.0f}/100</td></tr>
                <tr><td style="padding:6px 8px;color:rgba(255,255,255,0.5);">Time</td><td style="padding:6px 8px;">{alert.get('timestamp', 'N/A')}</td></tr>
            </table>
            <p style="color:rgba(255,255,255,0.6);margin:12px 0 0;font-size:13px;">{alert.get('description', '')}</p>
        </div>
        <div style="text-align:center;margin-top:16px;">
            <a href="https://shard-enterprise.com/alerts/{alert.get('id', '')}" 
               style="display:inline-block;padding:10px 24px;background:#00d4ff;color:#000;text-decoration:none;border-radius:6px;font-weight:600;font-size:14px;">
                View Alert Details →
            </a>
        </div>
        """
        return EmailTemplate.base_template(content, "Security Alert")
    
    @staticmethod
    def ip_blocked(ip: str, reason: str, blocked_by: str) -> str:
        content = f"""
        <div style="background:rgba(46,213,115,0.08);border:1px solid rgba(46,213,115,0.2);border-radius:8px;padding:16px;margin-bottom:16px;">
            <h2 style="color:#2ed573;margin:0 0 12px;font-size:18px;">🛡️ IP Blocked Successfully</h2>
            <p style="color:#ffffff;font-size:14px;">The following IP address has been blocked:</p>
            <div style="background:rgba(0,0,0,0.3);padding:12px;border-radius:6px;margin:12px 0;text-align:center;">
                <span style="font-family:monospace;font-size:20px;color:#ff4757;">🚫 {ip}</span>
            </div>
            <table style="width:100%;color:#ffffff;font-size:13px;">
                <tr><td style="color:rgba(255,255,255,0.5);padding:4px 0;">Reason</td><td>{reason}</td></tr>
                <tr><td style="color:rgba(255,255,255,0.5);padding:4px 0;">Blocked by</td><td>{blocked_by}</td></tr>
                <tr><td style="color:rgba(255,255,255,0.5);padding:4px 0;">Time</td><td>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</td></tr>
            </table>
        </div>
        """
        return EmailTemplate.base_template(content, "IP Blocked")
    
    @staticmethod
    def registration_confirm(username: str, email: str) -> str:
        content = f"""
        <div style="background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.2);border-radius:8px;padding:16px;margin-bottom:16px;">
            <h2 style="color:#00d4ff;margin:0 0 12px;font-size:18px;">🎉 Welcome to SHARD Enterprise!</h2>
            <p style="color:#ffffff;font-size:14px;">Your account has been created successfully.</p>
            <table style="width:100%;color:#ffffff;font-size:13px;margin:16px 0;">
                <tr><td style="color:rgba(255,255,255,0.5);padding:4px 0;">Username</td><td style="color:#00d4ff;">{username}</td></tr>
                <tr><td style="color:rgba(255,255,255,0.5);padding:4px 0;">Email</td><td>{email}</td></tr>
                <tr><td style="color:rgba(255,255,255,0.5);padding:4px 0;">Role</td><td>Viewer (upgrade request available)</td></tr>
            </table>
        </div>
        <div style="text-align:center;margin-top:16px;">
            <a href="https://shard-enterprise.com/login" 
               style="display:inline-block;padding:10px 24px;background:#00d4ff;color:#000;text-decoration:none;border-radius:6px;font-weight:600;">
                Go to Dashboard →
            </a>
        </div>
        """
        return EmailTemplate.base_template(content, "Registration Complete")
    
    @staticmethod
    def weekly_report(stats: dict) -> str:
        content = f"""
        <h2 style="color:#00d4ff;font-size:18px;">📊 Weekly Security Report</h2>
        <p style="color:rgba(255,255,255,0.6);font-size:13px;">Period: Last 7 days</p>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:16px 0;">
            <div style="background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.1);border-radius:8px;padding:12px;text-align:center;">
                <div style="color:rgba(255,255,255,0.5);font-size:11px;">TOTAL ALERTS</div>
                <div style="color:#00d4ff;font-size:24px;font-weight:700;">{stats.get('total_alerts', 0)}</div>
            </div>
            <div style="background:rgba(255,71,87,0.05);border:1px solid rgba(255,71,87,0.1);border-radius:8px;padding:12px;text-align:center;">
                <div style="color:rgba(255,255,255,0.5);font-size:11px;">BLOCKED IPs</div>
                <div style="color:#ff4757;font-size:24px;font-weight:700;">{stats.get('total_blocked', 0)}</div>
            </div>
        </div>
        """
        return EmailTemplate.base_template(content, "Weekly Report")


class EmailService:
    """Сервис отправки email-уведомлений"""
    
    def __init__(self):
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = os.getenv("SMTP_USER", "")
        self.smtp_password = os.getenv("SMTP_PASSWORD", "")
        self.from_email = os.getenv("SMTP_FROM", "noreply@shard-enterprise.com")
        self.from_name = "SHARD Enterprise SIEM"
        self.enabled = bool(self.smtp_user and self.smtp_password)
        self.queue: asyncio.Queue = asyncio.Queue()
        self._worker_task: Optional[asyncio.Task] = None
        self.sent_count = 0
        self.failed_count = 0
        self._running = False
        
        # Настройки уведомлений пользователей (в реальном проекте — из БД)
        self.user_settings: Dict[str, Dict[str, bool]] = {}
        
        if not self.enabled:
            logger.warning("Email service disabled: SMTP credentials not configured")
    
    def configure(self, host: str, port: int, user: str, password: str, from_email: str):
        """Настройка SMTP"""
        self.smtp_host = host
        self.smtp_port = port
        self.smtp_user = user
        self.smtp_password = password
        self.from_email = from_email
        self.enabled = True
        logger.info("Email service configured")
    
    def get_user_settings(self, user_id: str) -> Dict[str, bool]:
        """Получить настройки уведомлений пользователя"""
        if user_id not in self.user_settings:
            self.user_settings[user_id] = {
                "alert.critical": True,
                "alert.high": True,
                "alert.medium": False,
                "ip.blocked": True,
                "ip.unblocked": False,
                "system.health": True,
                "report.weekly": False,
                "login.new_device": True,
                "password.changed": True,
            }
        return self.user_settings[user_id]
    
    def update_user_settings(self, user_id: str, settings: Dict[str, bool]):
        """Обновить настройки уведомлений"""
        current = self.get_user_settings(user_id)
        current.update(settings)
        self.user_settings[user_id] = current
    
    def should_notify(self, user_id: str, event_type: str) -> bool:
        """Проверить, нужно ли отправлять уведомление"""
        if not self.enabled:
            return False
        settings = self.get_user_settings(user_id)
        return settings.get(event_type, False)
    
    async def send(self, message: EmailMessage) -> bool:
        """Отправить email (ставит в очередь)"""
        if not self.enabled:
            logger.debug(f"Email not sent (disabled): {message.subject}")
            return False
        await self.queue.put(message)
        return True
    
    async def send_now(self, message: EmailMessage) -> bool:
        """Отправить email немедленно (минуя очередь)"""
        if not self.enabled:
            return False
        
        try:
            msg = MIMEMultipart("alternative")
            msg["From"] = f"{self.from_name} <{self.from_email}>"
            msg["To"] = ", ".join(message.to)
            msg["Subject"] = message.subject
            msg["X-Priority"] = {"low": "5", "normal": "3", "high": "2", "critical": "1"}[message.priority]
            msg["X-SHARD-Event"] = message.event_type
            
            if message.reply_to:
                msg["Reply-To"] = message.reply_to
            if message.cc:
                msg["Cc"] = ", ".join(message.cc)
            
            msg.attach(MIMEText(message.body_text or message.body_html[:100], "plain", "utf-8"))
            msg.attach(MIMEText(message.body_html, "html", "utf-8"))
            
            # В реальном проекте — использовать aiosmtplib для async
            # Здесь синхронная версия для совместимости
            loop = asyncio.get_event_loop()
            
            def _send():
                with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_password)
                    server.send_message(msg)
            
            await loop.run_in_executor(None, _send)
            
            self.sent_count += 1
            logger.info(f"Email sent: {message.subject} to {message.to}")
            return True
            
        except Exception as e:
            self.failed_count += 1
            logger.error(f"Failed to send email '{message.subject}': {e}")
            return False
    
    async def start_worker(self):
        """Запустить фоновый обработчик очереди"""
        if self._running:
            return
        self._running = True
        self._worker_task = asyncio.create_task(self._process_queue())
        logger.info("Email worker started")
    
    async def stop_worker(self):
        """Остановить обработчик очереди"""
        self._running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("Email worker stopped")
    
    async def _process_queue(self):
        """Обработка очереди писем"""
        while self._running:
            try:
                message = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                await self.send_now(message)
                self.queue.task_done()
                await asyncio.sleep(0.5)  # Защита от спама
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Queue processing error: {e}")
    
    def get_stats(self) -> dict:
        """Статистика отправки"""
        return {
            "enabled": self.enabled,
            "queue_size": self.queue.qsize(),
            "sent_count": self.sent_count,
            "failed_count": self.failed_count,
            "smtp_configured": bool(self.smtp_user),
            "worker_running": self._running,
        }


# Глобальный экземпляр сервиса
email_service = EmailService()
