from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "SHARD Enterprise SIEM"
    APP_VERSION: str = "5.2.0"
    DEBUG: bool = False

    # Security
    SECRET_KEY: str = "your-super-secret-key-change-in-production-min-32-chars!!"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    ALLOWED_ORIGINS: List[str] = ["*"]
    TRUSTED_HOSTS: List[str] = ["*"]

    # Rate Limiting
    RATE_LIMIT: str = "100/minute"
    LOGIN_RATE_LIMIT: str = "5/minute"

    # Database (in-memory for demo, replace with real DB)
    DATABASE_URL: str = "sqlite:///./shard.db"

    # SHARD EventBus
    EVENTBUS_HOST: str = "localhost"
    EVENTBUS_PORT: int = 9090
    EVENTBUS_ENABLED: bool = True

    # Admin credentials (only for initial setup, change immediately)
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin123"  # Will be hashed on first run

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()