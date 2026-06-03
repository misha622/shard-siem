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
    email: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    company: Optional[str] = None
    job_title: Optional[str] = None

    class Config:
        extra = "allow"

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
