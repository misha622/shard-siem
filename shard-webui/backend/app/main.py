from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import time, logging, os
from app.config import settings
from app.database import Base, engine, init_db
from app.middleware import setup_middleware

# Все роутеры
from app.routers.auth_router import router as auth_router
from app.routers.alerts_router import router as alerts_router
from app.routers.blocked_router import router as blocked_router
from app.routers.stats_router import router as stats_router
from app.routers.settings_router import router as settings_router
from app.routers.company_router import router as company_router
from app.routers.audit_router import router as audit_router
from app.routers.compliance_router import router as compliance_router
from app.routers.admin_router import router as admin_router
from app.routers.email_router import router as email_router
from app.routers.websocket_router import router as websocket_router
from app.routers.profile_router import router as profile_router
from app.routers.defense_router import router as defense_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    Base.metadata.create_all(bind=engine)
    init_db()
    logger.info("Database initialized")
    yield
    logger.info("Shutting down...")

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    description="""
🛡️ **SHARD Enterprise SIEM API** — Autonomous AI-powered Security Information and Event Management.

## Features
- **50 ML/DL Models** for attack detection
- **DecisionFusion** — 4-level autonomous response
- **Telegram Bot** — real-time alerts
- **AppFirewall** — blocking without root

## Authentication
`POST /api/auth/login` with username/password to get JWT token.
""",
    contact={"name": "SHARD Enterprise", "url": "https://github.com/misha622/shard-siem"},
    license_info={"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
)
setup_middleware(app)

app.include_router(auth_router)
app.include_router(alerts_router)
app.include_router(blocked_router)
app.include_router(stats_router)
app.include_router(settings_router)
app.include_router(company_router)
app.include_router(audit_router)
app.include_router(compliance_router)
app.include_router(admin_router)
app.include_router(email_router)
app.include_router(websocket_router)
app.include_router(profile_router)
app.include_router(defense_router)

@app.get("/api/health")
async def health():
    return {"status": "healthy", "version": settings.APP_VERSION}

frontend_path = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
