"""FastAPI application entry point with lifespan, middleware, and routing."""

import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from server.config import get_settings
from server.database import close_db, init_db
from server.routes import audit, auth, deployments, devices, firmware

logger = logging.getLogger(__name__)
settings = get_settings()

limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Handle application startup and shutdown."""
    logger.info("Starting %s v%s [%s]", settings.app_name, settings.app_version, settings.environment)
    await init_db()
    logger.info("Database initialised")
    yield
    logger.info("Shutting down %s", settings.app_name)
    await close_db()


def create_application() -> FastAPI:
    """Construct and configure the FastAPI application."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Secure Over-The-Air firmware update server with cryptographic verification.",
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ── Rate limiting ──────────────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

    # ── Security middleware ────────────────────────────────────────────────
    if settings.is_production:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=settings.allowed_methods,
        allow_headers=settings.allowed_headers,
    )

    # ── Request logging middleware ─────────────────────────────────────────
    @app.middleware("http")
    async def request_logging_middleware(request: Request, call_next: object) -> Response:
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        start_time = time.perf_counter()
        request.state.request_id = request_id

        logger.info(
            "→ %s %s | id=%s | ip=%s",
            request.method,
            request.url.path,
            request_id,
            request.client.host if request.client else "unknown",
        )

        response: Response = await call_next(request)  # type: ignore[operator]

        duration_ms = (time.perf_counter() - start_time) * 1000
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Process-Time"] = f"{duration_ms:.2f}ms"

        logger.info(
            "← %s %s | id=%s | status=%d | %.2fms",
            request.method,
            request.url.path,
            request_id,
            response.status_code,
            duration_ms,
        )
        return response

    # ── Security headers middleware ────────────────────────────────────────
    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next: object) -> Response:
        response: Response = await call_next(request)  # type: ignore[operator]
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if settings.is_production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    # ── Routers ────────────────────────────────────────────────────────────
    api_prefix = "/api/v1"
    app.include_router(auth.router, prefix=api_prefix, tags=["Authentication"])
    app.include_router(firmware.router, prefix=api_prefix, tags=["Firmware"])
    app.include_router(devices.router, prefix=api_prefix, tags=["Devices"])
    app.include_router(deployments.router, prefix=api_prefix, tags=["Deployments"])
    app.include_router(audit.router, prefix=api_prefix, tags=["Audit"])

    # ── Health / readiness ─────────────────────────────────────────────────
    @app.get("/health", include_in_schema=False)
    async def health_check() -> JSONResponse:
        return JSONResponse(
            content={
                "status": "healthy",
                "service": settings.app_name,
                "version": settings.app_version,
                "environment": settings.environment,
            }
        )

    @app.get("/ready", include_in_schema=False)
    async def readiness_check() -> JSONResponse:
        return JSONResponse(content={"status": "ready"})

    return app


app = create_application()
