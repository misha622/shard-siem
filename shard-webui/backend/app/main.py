"""
SHARD Enterprise v5.2.0 - Main Application
"""
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from prometheus_fastapi_instrumentator import Instrumentator
import logging
import time

from app.config import settings
from app.middleware import setup_middleware
from app.logging_config import setup_logging, CorrelationIdFilter
from app.eventbus import eventbus
from app.routers import (
    auth_router,
    alerts_router,
    blocked_router,
    stats_router,
    websocket_router,
    settings_router
)

# Setup logging
correlation_filter = setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager
    """
    # Startup
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION}")
    app.state.start_time = time.time()

    # Connect to SHARD EventBus
    if settings.EVENTBUS_ENABLED:
        await eventbus.connect()
        await eventbus.start_listening()

    # Start Prometheus metrics
    Instrumentator().instrument(app).expose(app)

    yield

    # Shutdown
    logger.info("Shutting down application...")
    await eventbus.disconnect()
    # Close all WebSocket connections
    logger.info("Application shutdown complete")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Setup middleware
setup_middleware(app)

# Rate limit handler
app.state.limiter = None  # Will be configured per-router
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Include routers
app.include_router(auth_router.router)
app.include_router(alerts_router.router)
app.include_router(blocked_router.router)
app.include_router(stats_router.router)
app.include_router(websocket_router.router)
app.include_router(settings_router.router)


# Health check endpoint
@app.get("/api/health")
async def health_check():
    """
    Health check endpoint for monitoring
    """
    import psutil
    uptime_seconds = int(time.time() - app.state.start_time)

    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "uptime_seconds": uptime_seconds,
        "database_connected": True,  # In production, check actual DB connection
        "eventbus_connected": eventbus.connected,
        "timestamp": time.time()
    }


@app.get("/api/metrics")
async def metrics():
    """
    Prometheus metrics endpoint
    """
    from prometheus_fastapi_instrumentator import metrics as prom_metrics
    return prom_metrics()


# Exception handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "correlation_id": getattr(request.state, "correlation_id", "unknown")
        }
    )


# Serve static files in production
try:
    app.mount("/", StaticFiles(directory="../frontend", html=True), name="frontend")
except:
    logger.warning("Frontend directory not found, skipping static file mounting")

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info"
    )