from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import time, logging, os
from app.config import settings
from app.eventbus import eventbus
from app.email_service import email_service
from app.database import db
from app.routers import email_router, auth_router, alerts_router, blocked_router, stats_router, websocket_router, settings_router, map_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    app.state.start_time = time.time()
    
    # Инициализация базы данных
    await db.init()
    logger.info("Database initialized")
    
    if settings.EVENTBUS_ENABLED:
        await eventbus.connect()
        await eventbus.start_listening()
    
    await email_service.start_worker()
    
    yield
    
    logger.info("Shutting down...")
    await eventbus.disconnect()
    await email_service.stop_worker()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router.router)
app.include_router(alerts_router.router)
app.include_router(blocked_router.router)
app.include_router(stats_router.router)
app.include_router(websocket_router.router)
app.include_router(settings_router.router)
app.include_router(email_router.router)
app.include_router(map_router.router)

@app.get("/api/health")
async def health():
    return {"status": "healthy", "version": settings.APP_VERSION, "uptime_seconds": int(time.time() - app.state.start_time)}

frontend_path = os.path.join(os.path.dirname(__file__), "..", "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/", StaticFiles(directory=frontend_path, html=True), name="frontend")
