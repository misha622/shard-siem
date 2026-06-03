from pydantic import BaseModel, Field, validator
from typing import Optional, List
from datetime import datetime
import re

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6, max_length=100)

    @validator("username")
    def validate_username(cls, v):
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError("Username must be alphanumeric")
        return v

class TokenRefresh(BaseModel):
    refresh_token: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8, max_length=100)

class AlertResponse(BaseModel):
    id: str
    timestamp: datetime
    alert_type: str
    severity: str
    source_ip: str
    destination_ip: str
    description: str
    is_blocked: bool
    threat_score: float

class AlertListResponse(BaseModel):
    alerts: List[AlertResponse]
    total_count: int
    page: int
    page_size: int
    total_pages: int

class BlockIPRequest(BaseModel):
    ip_address: str
    reason: str
    is_permanent: bool = False

    @validator("ip_address")
    def validate_ip(cls, v):
        if not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", v):
            raise ValueError("Invalid IP address format")
        return v

class BlockedIPResponse(BaseModel):
    id: str
    ip_address: str
    reason: str
    blocked_at: datetime
    blocked_by: str
    is_permanent: bool
    expires_at: Optional[datetime] = None

class SystemMetricsResponse(BaseModel):
    cpu_percent: float
    memory_percent: float
    disk_percent: float
    network_sent_mb: float
    network_recv_mb: float
    uptime_hours: float
    timestamp: datetime
