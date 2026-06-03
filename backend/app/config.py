from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    APP_NAME: str = "SHARD Enterprise SIEM"
    APP_VERSION: str = "5.2.0"
    DEBUG: bool = False
    SECRET_KEY: str = "super-secret-key-change-in-production-32chars-min"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALLOWED_ORIGINS: List[str] = ["*"]
    TRUSTED_HOSTS: List[str] = ["*"]
    RATE_LIMIT: str = "100/minute"
    LOGIN_RATE_LIMIT: str = "5/minute"
    EVENTBUS_HOST: str = "localhost"
    EVENTBUS_PORT: int = 9090
    EVENTBUS_ENABLED: bool = True
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str = "admin123"

    class Config:
        env_file = ".env"

settings = Settings()
