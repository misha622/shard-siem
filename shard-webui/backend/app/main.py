from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
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

app = FastAPI(title=settings.APP_NAME, version=settings.APP_VERSION, lifespan=lifespan)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
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

@app.get("/api/health")
async def health():
    return {"status": "healthy", "version": settings.APP_VERSION}

frontend_path = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
