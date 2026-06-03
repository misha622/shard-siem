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
    """Совместимо с SHARD: src_ip, dst_ip, dst_port"""
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    attack_type = Column(String(50), nullable=False)
    severity = Column(String(20), nullable=False)
    src_ip = Column(String(45), nullable=False)
    dst_ip = Column(String(45))
    dst_port = Column(Integer)
    score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    explanation = Column(Text)
    company_id = Column(Integer, ForeignKey("companies.id"), nullable=True)
    company = relationship("Company", back_populates="alerts")

class BlockedIP(Base):
    __tablename__ = "blocked_ips"
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False)
    reason = Column(Text)
    blocked_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    is_permanent = Column(Boolean, default=False)

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True)
    token = Column(String(500), unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

# Engine
DB_PATH = os.path.join(os.path.dirname(__file__), "..", "shard_webui.db")
engine = create_engine(f"sqlite:///{DB_PATH}", connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
