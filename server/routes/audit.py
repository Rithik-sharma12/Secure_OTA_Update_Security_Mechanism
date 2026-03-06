"""Audit log routes: immutable event history with filtering."""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.dependencies import require_admin
from server.models import AuditLog
from server.security.jwt_handler import TokenPayload

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/audit")


class AuditLogResponse(BaseModel):
    """Audit log entry returned by the API."""

    id: str
    event_type: str
    device_id: str | None
    firmware_id: str | None
    user_id: str | None
    ip_address: str | None
    details: dict
    timestamp: str


def _audit_to_response(log: AuditLog) -> AuditLogResponse:
    return AuditLogResponse(
        id=log.id,
        event_type=log.event_type.value,
        device_id=log.device_id,
        firmware_id=log.firmware_id,
        user_id=log.user_id,
        ip_address=log.ip_address,
        details=log.details,
        timestamp=log.timestamp.isoformat(),
    )


@router.get("/", response_model=list[AuditLogResponse], summary="List audit log entries")
async def list_audit_logs(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(require_admin)],
    event_type: str | None = Query(default=None, description="Filter by event type"),
    device_id: str | None = Query(default=None, description="Filter by device ID"),
    user_id: str | None = Query(default=None, description="Filter by user ID"),
    limit: int = Query(default=100, le=500, description="Maximum records to return"),
    offset: int = Query(default=0, description="Pagination offset"),
) -> list[AuditLogResponse]:
    """Retrieve audit log entries, optionally filtered by event type, device, or user.

    Results are returned in descending chronological order (newest first).
    This endpoint is restricted to administrators.
    """
    stmt = select(AuditLog)
    if event_type:
        stmt = stmt.where(AuditLog.event_type == event_type)
    if device_id:
        stmt = stmt.where(AuditLog.device_id == device_id)
    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)
    stmt = stmt.order_by(AuditLog.timestamp.desc()).limit(limit).offset(offset)

    result = await db.execute(stmt)
    return [_audit_to_response(log) for log in result.scalars().all()]


@router.get("/{log_id}", response_model=AuditLogResponse, summary="Get audit log entry")
async def get_audit_log(
    log_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(require_admin)],
) -> AuditLogResponse:
    """Retrieve a single audit log entry by ID."""
    stmt = select(AuditLog).where(AuditLog.id == log_id)
    result = await db.execute(stmt)
    log = result.scalar_one_or_none()
    if log is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Audit log entry not found")
    return _audit_to_response(log)
