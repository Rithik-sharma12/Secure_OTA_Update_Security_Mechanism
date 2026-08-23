"""
SentinelOTA Edge Gateway — Route Registration

Registers all API routers with the FastAPI application.
"""

from __future__ import annotations

from fastapi import FastAPI

from . import dashboard, deployments, health, heartbeat, operations, releases


def register_routes(app: FastAPI) -> None:
    """Include all route modules into the FastAPI application."""
    app.include_router(health.router)
    app.include_router(heartbeat.router)
    app.include_router(dashboard.router)
    app.include_router(releases.router)
    app.include_router(deployments.router)
    app.include_router(operations.router)
