from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import time
import uuid
from app.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers[
            "Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.plot.ly https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data:;"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        return response


class CorrelationIDMiddleware(BaseHTTPMiddleware):
    """Add correlation ID to requests"""

    async def dispatch(self, request: Request, call_next):
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4())[:8])
        request.state.correlation_id = correlation_id

        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id

        return response


class TimingMiddleware(BaseHTTPMiddleware):
    """Add request timing"""

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        response = await call_next(request)
        process_time = time.time() - start_time
        response.headers["X-Process-Time"] = str(process_time)
        return response


def setup_middleware(app: FastAPI):
    """Configure all middleware"""

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5000","http://localhost:8081","http://127.0.0.1:5000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Custom middleware
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(CorrelationIDMiddleware)
    app.add_middleware(TimingMiddleware)