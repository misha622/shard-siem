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
    alerts = relationship("Alert", back_populates="company")

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
    company = relationship("Company", back_populates="users")

class Alert(Base):
    """Поля синхронизированы с фронтендом: alert_type, source_ip, destination_ip, threat_score"""
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    alert_type = Column(String(50), nullable=False, index=True)
    severity = Column(String(20), nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    source_lat = Column(Float)
    source_lon = Column(Float)
    source_country = Column(String(100))
    source_city = Column(String(100))
    destination_ip = Column(String(45), index=True)
    destination_port = Column(Integer)
    protocol = Column(String(20))
    description = Column(Text)
    threat_score = Column(Float, default=0.0)
    is_blocked = Column(Boolean, default=False)
    blocked_at = Column(DateTime)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True, index=True)
    company = relationship("Company", back_populates="alerts")

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

# Engine
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "shard.db")
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
