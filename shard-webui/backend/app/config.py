from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import List

class Settings(BaseSettings):
    APP_NAME: str = "SHARD Enterprise SIEM"
    APP_VERSION: str = "5.2.0"
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    HOST: str = "0.0.0.0"
    PORT: int = 5000
    ALLOWED_ORIGINS: List[str] = []
    RATE_LIMIT: str = "100/minute"
    LOGIN_RATE_LIMIT: str = "5/minute"
    ADMIN_USERNAME: str = "admin"
    ADMIN_PASSWORD: str

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def parse_origins(cls, v, info):
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            if not v.strip():
                port = info.data.get("PORT", 5000) if info.data else 5000
                return [f"http://localhost:{port}"]
            return [o.strip() for o in v.split(",") if o.strip()]
        return [f"http://localhost:{info.data.get('PORT', 5000) if info.data else 5000}"]

    class Config:
        env_file = ".env"

settings = Settings()
