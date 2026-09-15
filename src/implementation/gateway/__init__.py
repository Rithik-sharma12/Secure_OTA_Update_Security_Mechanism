"""
SentinelOTA Edge Gateway Package

Usage:
    # As ASGI app (recommended):
    uvicorn gateway:app --host 0.0.0.0 --port 5000

    # Or run directly:
    python -m gateway
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .auth import require_write_auth  # noqa: F401  (re-exported for callers/tests)
from .config import CORS_ALLOW_CREDENTIALS, CORS_ALLOW_ORIGINS, HOST, PORT
from .state import load_state
from .routes import register_routes


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    application = FastAPI(title='SentinelOTA Edge Gateway', version='2.0.0')

    # CORS middleware. Origins come from OTA_GATEWAY_CORS_ORIGINS; credentials
    # are enabled only when the list is explicit, because '*' with credentials
    # is rejected by every browser anyway.
    application.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ALLOW_ORIGINS,
        allow_credentials=CORS_ALLOW_CREDENTIALS,
        allow_methods=['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
        allow_headers=['Content-Type', 'Authorization', 'x-api-key'],
    )

    # Route modules import the real write-auth dependency directly from
    # gateway.auth, so there is nothing to wire up here.

    # Register all routes
    register_routes(application)

    # Load persisted state
    load_state()

    return application


# Module-level app instance for ASGI servers (uvicorn gateway:app)
app = create_app()


if __name__ == '__main__':
    import uvicorn
    print(f"[*] Starting SentinelOTA FastAPI gateway on {HOST}:{PORT}...")
    uvicorn.run(app, host=HOST, port=PORT, reload=False)
