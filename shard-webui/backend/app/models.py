from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AlertType(str, Enum):
    DDOS = "DDoS"
    SQL_INJECTION = "SQL Injection"
    XSS = "XSS"
    BRUTE_FORCE = "Brute Force"
    PORT_SCAN = "Port Scan"
    MALWARE = "Malware"
    PHISHING = "Phishing"
    RANSOMWARE = "Ransomware"
    DATA_EXFILTRATION = "Data Exfiltration"
    UNAUTHORIZED_ACCESS = "Unauthorized Access"


class UserRole(str, Enum):
    ADMIN = "admin"
    VIEWER = "viewer"


class User(BaseModel):
    id: str
    username: str
    role: UserRole
    hashed_password: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_login: Optional[datetime] = None


class Alert(BaseModel):
    id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    alert_type: AlertType
    severity: SeverityLevel
    source_ip: str
    destination_ip: str
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    description: str
    raw_payload: Optional[str] = None
    packet_count: Optional[int] = None
    bytes_transferred: Optional[int] = None
    duration: Optional[float] = None
    is_blocked: bool = False
    blocked_at: Optional[datetime] = None
    threat_score: float = Field(ge=0, le=100)


class BlockedIP(BaseModel):
    id: str
    ip_address: str
    reason: str
    blocked_at: datetime = Field(default_factory=datetime.utcnow)
    blocked_by: str
    alert_ids: List[str] = []
    expires_at: Optional[datetime] = None
    is_permanent: bool = False


class SystemMetrics(BaseModel):
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_bytes_sent: int
    network_bytes_recv: int
    uptime_seconds: int
    process_count: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class SearchQuery(BaseModel):
    query: Optional[str] = None
    alert_type: Optional[AlertType] = None
    severity: Optional[SeverityLevel] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=100)
    sort_by: str = "timestamp"
    sort_order: str = "desc"


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Dict[str, Any]


class StatsResponse(BaseModel):
    total_packets: int
    total_alerts: int
    total_blocked: int
    active_threats: int
    alerts_by_type: Dict[str, int]
    alerts_by_hour: Dict[str, int]
    alerts_by_day: Dict[str, int]
    top_attackers: List[Dict[str, Any]]
    top_targets: List[Dict[str, Any]]
    severity_distribution: Dict[str, int]