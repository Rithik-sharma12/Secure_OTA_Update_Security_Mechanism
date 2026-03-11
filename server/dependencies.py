"""FastAPI dependency injection: authentication, rate limiting, database."""

import logging
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.models import Device, DeviceStatus, RevokedToken
from server.security.jwt_handler import TokenPayload, verify_access_token

logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=True)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenPayload:
    """Validate Bearer JWT and return the decoded token payload.

    Raises:
        HTTPException 401: If the token is missing, invalid, or revoked.
    """
    token = credentials.credentials
    payload = verify_access_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check server-side revocation list
    stmt = select(RevokedToken).where(RevokedToken.jti == payload.jti)
    result = await db.execute(stmt)
    if result.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return payload


async def get_current_active_device(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Device:
    """Validate device JWT and return the associated active Device record.

    Raises:
        HTTPException 401: If authentication fails.
        HTTPException 403: If the device is banned or inactive.
        HTTPException 404: If the device record is not found.
    """
    token = credentials.credentials
    payload = verify_access_token(token)
    if payload is None or payload.sub is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid device token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    stmt = select(Device).where(Device.device_id == payload.sub)
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()

    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    if device.status == DeviceStatus.BANNED:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device is banned")

    if device.status == DeviceStatus.INACTIVE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device is inactive")

    return device


async def require_admin(
    current_user: Annotated[TokenPayload, Depends(get_current_user)],
) -> TokenPayload:
    """Ensure the authenticated user has admin role.

    Raises:
        HTTPException 403: If the user lacks admin privileges.
    """
    if "admin" not in (current_user.roles or []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges required",
        )
    return current_user


def get_client_ip(request: Request) -> str:
    """Extract the real client IP, honouring X-Forwarded-For."""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


async def verify_request_id(
    x_request_id: Annotated[str | None, Header()] = None,
) -> str | None:
    """Pass through an optional request correlation ID from the header."""
    return x_request_id
