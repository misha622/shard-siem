from typing import Dict, List, Optional
from datetime import datetime, timedelta
import uuid
from app.models import User, Alert, BlockedIP, UserRole, SeverityLevel, AlertType
from passlib.context import CryptContext
import random

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# In-memory databases (replace with real databases in production)
class InMemoryDB:
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.alerts: Dict[str, Alert] = {}
        self.blocked_ips: Dict[str, BlockedIP] = {}
        self.refresh_tokens: Dict[str, str] = {}  # token -> user_id
        self._init_default_data()

    def _init_default_data(self):
        """Initialize with sample data"""
        # Create admin user
        admin_id = str(uuid.uuid4())
        admin = User(
            id=admin_id,
            username="admin",
            role=UserRole.ADMIN,
            hashed_password=pwd_context.hash("admin123"),
            created_at=datetime.utcnow()
        )
        self.users[admin_id] = admin

        # Create viewer user
        viewer_id = str(uuid.uuid4())
        viewer = User(
            id=viewer_id,
            username="viewer",
            role=UserRole.VIEWER,
            hashed_password=pwd_context.hash("viewer123"),
            created_at=datetime.utcnow()
        )
        self.users[viewer_id] = viewer

        # Create sample alerts
        sample_alerts_data = [
            {
                "alert_type": AlertType.DDOS,
                "severity": SeverityLevel.CRITICAL,
                "source_ip": "45.33.32.156",
                "destination_ip": "192.168.1.100",
                "destination_port": 443,
                "protocol": "TCP",
                "description": "Large scale DDoS attack detected from multiple sources",
                "threat_score": 95.0
            },
            {
                "alert_type": AlertType.SQL_INJECTION,
                "severity": SeverityLevel.HIGH,
                "source_ip": "103.224.182.243",
                "destination_ip": "192.168.1.100",
                "destination_port": 80,
                "protocol": "HTTP",
                "description": "SQL injection attempt in login form",
                "threat_score": 85.0
            },
            {
                "alert_type": AlertType.PORT_SCAN,
                "severity": SeverityLevel.MEDIUM,
                "source_ip": "78.128.113.94",
                "destination_ip": "192.168.1.100",
                "destination_port": 22,
                "protocol": "TCP",
                "description": "Aggressive port scanning detected",
                "threat_score": 60.0
            },
            {
                "alert_type": AlertType.MALWARE,
                "severity": SeverityLevel.CRITICAL,
                "source_ip": "185.220.101.34",
                "destination_ip": "192.168.1.50",
                "destination_port": 445,
                "protocol": "SMB",
                "description": "WannaCry ransomware variant detected",
                "threat_score": 98.0
            },
            {
                "alert_type": AlertType.BRUTE_FORCE,
                "severity": SeverityLevel.HIGH,
                "source_ip": "91.121.87.45",
                "destination_ip": "192.168.1.100",
                "destination_port": 22,
                "protocol": "SSH",
                "description": "SSH brute force attack with 1000+ attempts",
                "threat_score": 80.0
            },
        ]

        for alert_data in sample_alerts_data:
            alert_id = str(uuid.uuid4())
            alert = Alert(
                id=alert_id,
                timestamp=datetime.utcnow() - timedelta(minutes=random.randint(1, 1440)),
                **alert_data
            )
            self.alerts[alert_id] = alert

    def get_user_by_username(self, username: str) -> Optional[User]:
        for user in self.users.values():
            if user.username == username:
                return user
        return None

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        return self.users.get(user_id)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)

    def hash_password(self, password: str) -> str:
        return pwd_context.hash(password)

    def change_password(self, user_id: str, new_password: str) -> bool:
        user = self.users.get(user_id)
        if user:
            user.hashed_password = self.hash_password(new_password)
            return True
        return False

    def add_refresh_token(self, token: str, user_id: str):
        self.refresh_tokens[token] = user_id

    def get_user_by_refresh_token(self, token: str) -> Optional[str]:
        return self.refresh_tokens.get(token)

    def revoke_refresh_token(self, token: str):
        self.refresh_tokens.pop(token, None)

    def add_alert(self, alert: Alert):
        self.alerts[alert.id] = alert

    def get_alerts(self, query_params: dict) -> tuple:
        alerts = list(self.alerts.values())

        # Apply filters
        if query_params.get('alert_type'):
            alerts = [a for a in alerts if a.alert_type == query_params['alert_type']]
        if query_params.get('severity'):
            alerts = [a for a in alerts if a.severity == query_params['severity']]
        if query_params.get('source_ip'):
            alerts = [a for a in alerts if query_params['source_ip'] in a.source_ip]
        if query_params.get('destination_ip'):
            alerts = [a for a in alerts if query_params['destination_ip'] in a.destination_ip]
        if query_params.get('start_time'):
            alerts = [a for a in alerts if a.timestamp >= query_params['start_time']]
        if query_params.get('end_time'):
            alerts = [a for a in alerts if a.timestamp <= query_params['end_time']]

        # Sort
        sort_by = query_params.get('sort_by', 'timestamp')
        sort_order = query_params.get('sort_order', 'desc')
        reverse = sort_order == 'desc'
        alerts.sort(key=lambda x: getattr(x, sort_by), reverse=reverse)

        total_count = len(alerts)

        # Pagination
        page = query_params.get('page', 1)
        page_size = query_params.get('page_size', 50)
        start = (page - 1) * page_size
        end = start + page_size

        return alerts[start:end], total_count

    def get_alert_by_id(self, alert_id: str) -> Optional[Alert]:
        return self.alerts.get(alert_id)

    def block_ip(self, ip_address: str, reason: str, blocked_by: str, is_permanent: bool = False) -> BlockedIP:
        # Check if already blocked
        for blocked in self.blocked_ips.values():
            if blocked.ip_address == ip_address:
                return blocked

        block_id = str(uuid.uuid4())
        blocked = BlockedIP(
            id=block_id,
            ip_address=ip_address,
            reason=reason,
            blocked_by=blocked_by,
            is_permanent=is_permanent,
            expires_at=None if is_permanent else datetime.utcnow() + timedelta(hours=24)
        )
        self.blocked_ips[block_id] = blocked

        # Mark related alerts as blocked
        for alert in self.alerts.values():
            if alert.source_ip == ip_address and not alert.is_blocked:
                alert.is_blocked = True
                alert.blocked_at = datetime.utcnow()
                blocked.alert_ids.append(alert.id)

        return blocked

    def get_blocked_ips(self) -> List[BlockedIP]:
        return list(self.blocked_ips.values())

    def get_stats(self) -> dict:
        alerts = list(self.alerts.values())
        now = datetime.utcnow()

        # Calculate stats
        alerts_by_type = {}
        alerts_by_hour = {}
        severity_dist = {}
        attackers = {}
        targets = {}

        for alert in alerts:
            # By type
            alerts_by_type[alert.alert_type] = alerts_by_type.get(alert.alert_type, 0) + 1

            # By hour
            hour_key = alert.timestamp.strftime("%H:00")
            alerts_by_hour[hour_key] = alerts_by_hour.get(hour_key, 0) + 1

            # Severity distribution
            severity_dist[alert.severity] = severity_dist.get(alert.severity, 0) + 1

            # Attackers
            attackers[alert.source_ip] = attackers.get(alert.source_ip, 0) + 1

            # Targets
            targets[alert.destination_ip] = targets.get(alert.destination_ip, 0) + 1

        # Top 10
        top_attackers = sorted([{"ip": k, "count": v} for k, v in attackers.items()],
                               key=lambda x: x["count"], reverse=True)[:10]
        top_targets = sorted([{"ip": k, "count": v} for k, v in targets.items()],
                             key=lambda x: x["count"], reverse=True)[:10]

        return {
            "total_packets": sum(a.packet_count or 0 for a in alerts),
            "total_alerts": len(alerts),
            "total_blocked": len([a for a in alerts if a.is_blocked]),
            "active_threats": len([a for a in alerts if a.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
                                   and (now - a.timestamp).seconds < 3600]),
            "alerts_by_type": alerts_by_type,
            "alerts_by_hour": alerts_by_hour,
            "severity_distribution": severity_dist,
            "top_attackers": top_attackers,
            "top_targets": top_targets
        }


# Global database instance
db = InMemoryDB()