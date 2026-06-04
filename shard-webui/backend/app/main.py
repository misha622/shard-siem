from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import time, logging, os
from app.config import settings
from app.database import Base, engine, init_db
from app.middleware import setup_middleware
from app.routers import auth_router, alerts_router, blocked_router, stats_router, settings_router, company_router

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
setup_middleware(app)

app.include_router(auth_router.router)
app.include_router(alerts_router.router)
app.include_router(blocked_router.router)
app.include_router(stats_router.router)
app.include_router(settings_router.router)
app.include_router(company_router.router)
app.include_router(compliance_router.router)

@app.get("/api/health")
async def health():
    return {"status": "healthy", "version": settings.APP_VERSION}

frontend_path = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
