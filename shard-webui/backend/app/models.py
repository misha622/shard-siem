import enum

class UserRole(str, enum.Enum):
    ADMIN = "admin"
    VIEWER = "viewer"

from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, JSON, ForeignKey, Text, create_engine
from sqlalchemy.orm import relationship, declarative_base, sessionmaker
from datetime import datetime
import secrets, os

Base = declarative_base()

class Company(Base):
    __tablename__ = "companies"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    ip_ranges = Column(JSON, default=list)
    api_key = Column(String(64), unique=True, default=lambda: secrets.token_hex(32))
    is_active = Column(Boolean, default=True)
    max_alerts_per_day = Column(Integer, default=10000)
    created_at = Column(DateTime, default=datetime.utcnow)
    users = relationship("User", back_populates="company")


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(255))
    first_name = Column(String(100))
    last_name = Column(String(100))
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="viewer")
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    company = relationship("Company", back_populates="users", foreign_keys=[company_id])

class Alert(Base):
    """Alert model — синхронизировано с shard_siem.db"""
    __tablename__ = "alerts"
    __table_args__ = {'extend_existing': True}
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(Float, index=True)
    src_ip = Column(String(45), index=True)
    dst_ip = Column(String(45), index=True)
    dst_port = Column(Integer)
    attack_type = Column(String(50), index=True)
    score = Column(Float)
    confidence = Column(Float)
    severity = Column(String(20), index=True)
    explanation = Column(Text)
    kill_chain_stage = Column(String(50))
    features_json = Column(Text)
    
    # Совместимость со старым кодом фронтенда
    @property
    def alert_type(self):
        return self.attack_type
    
    @property
    def source_ip(self):
        return self.src_ip
    
    @property
    def destination_ip(self):
        return self.dst_ip
    
    @property
    def destination_port(self):
        return self.dst_port
    
    @property
    def description(self):
        return self.explanation
    
    @property
    def threat_score(self):
        return (self.score or 0) * 100
    
    @property
    def is_blocked(self):
        return False
    
    @property
    def blocked_at(self):
        return None
    
    @property
    def protocol(self):
        return None
    
    @property
    def source_lat(self):
        return None
    
    @property
    def source_lon(self):
        return None
    
    @property
    def source_country(self):
        return None
    
    @property
    def source_city(self):
        return None
    
    company_id = Column(Integer, nullable=True, index=True)



class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False, index=True)
    reason = Column(Text)
    blocked_by = Column(String(50))
    blocked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_permanent = Column(Boolean, default=False)

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True)
    token = Column(String(500), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class EmailSettings(Base):
    __tablename__ = "email_settings"
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    alert_critical = Column(Boolean, default=True)
    alert_high = Column(Boolean, default=True)
    alert_medium = Column(Boolean, default=False)
    ip_blocked = Column(Boolean, default=True)
    system_health = Column(Boolean, default=True)
    report_weekly = Column(Boolean, default=False)


class GeoCache(Base):
    __tablename__ = "geo_cache"
    ip = Column(String(45), primary_key=True)
    latitude = Column(Float)
    longitude = Column(Float)
    country = Column(String(100))
    city = Column(String(100))
    isp = Column(String(255))
    updated_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    """Audit log for compliance"""
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    tenant_id = Column(String(50), index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(100))
    resource = Column(String(255))
    details = Column(JSON, default=dict)
    ip_address = Column(String(45))
    success = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

# Engine
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "shard_siem.db")
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
