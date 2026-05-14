"""Authentication routes: login, device auth, token refresh, revocation."""

import logging
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import get_settings
from server.database import get_db
from server.dependencies import get_client_ip, get_current_user
from server.models import AuditEventType, AuditLog, Device, DeviceStatus, RevokedToken
from server.security.jwt_handler import (
    TokenPair,
    TokenPayload,
    create_access_token,
    create_token_pair,
    verify_refresh_token,
)
from server.security.pki import get_certificate_fingerprint, validate_certificate

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth")
settings = get_settings()


class LoginRequest(BaseModel):
    """Username + password login payload."""

    username: str
    password: str


class DeviceAuthRequest(BaseModel):
    """Device certificate-based authentication payload."""

    device_id: str
    certificate_pem: str


class RefreshRequest(BaseModel):
    """Refresh token payload."""

    refresh_token: str


class RevokeRequest(BaseModel):
    """Token revocation payload."""

    token: str


@router.post("/token", response_model=TokenPair, summary="Obtain JWT token pair")
async def login(
    request: Request,
    body: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenPair:
    """Authenticate with username and password to receive a JWT token pair.

    In production, validate credentials against a user store with hashed passwords.
    This implementation validates against the admin credentials in Settings.
    """
    from passlib.context import CryptContext

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    # Validate admin credentials
    valid = (
        body.username == settings.admin_username
        and settings.admin_password_hash
        and pwd_context.verify(body.password, settings.admin_password_hash)
    )
    if not valid:
        # Log failed attempt
        audit = AuditLog(
            event_type=AuditEventType.AUTH_LOGIN,
            user_id=body.username,
            ip_address=get_client_ip(request),
            details={"success": False, "reason": "invalid_credentials"},
        )
        db.add(audit)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token_pair = create_token_pair(body.username, roles=["admin"])

    audit = AuditLog(
        event_type=AuditEventType.AUTH_LOGIN,
        user_id=body.username,
        ip_address=get_client_ip(request),
        details={"success": True},
    )
    db.add(audit)
    await db.commit()
    return token_pair


@router.post(
    "/device/authenticate",
    response_model=TokenPair,
    summary="Device certificate-based authentication",
)
async def device_authenticate(
    request: Request,
    body: DeviceAuthRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenPair:
    """Authenticate a device using its X.509 certificate.

    The device presents its PEM certificate; the server verifies it against
    the registered fingerprint and issues a JWT for subsequent requests.
    """
    stmt = select(Device).where(Device.device_id == body.device_id)
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()

    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    if device.status == DeviceStatus.BANNED:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Device is banned")

    # Verify the certificate fingerprint matches what we registered
    try:
        cert_bytes = body.certificate_pem.encode()
        fingerprint = get_certificate_fingerprint(cert_bytes)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid certificate: {exc}",
        ) from exc

    if device.certificate_fingerprint and device.certificate_fingerprint != fingerprint:
        audit = AuditLog(
            event_type=AuditEventType.DEVICE_AUTH,
            device_id=device.id,
            ip_address=get_client_ip(request),
            details={"success": False, "reason": "fingerprint_mismatch"},
        )
        db.add(audit)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Certificate fingerprint mismatch"
        )

    # Update last seen
    device.last_seen = datetime.now(UTC)
    device.status = DeviceStatus.ACTIVE

    token_pair = create_token_pair(body.device_id, roles=["device"])

    audit = AuditLog(
        event_type=AuditEventType.DEVICE_AUTH,
        device_id=device.id,
        ip_address=get_client_ip(request),
        details={"success": True},
    )
    db.add(audit)
    await db.commit()
    return token_pair


@router.post("/refresh", response_model=TokenPair, summary="Refresh access token")
async def refresh_token(
    request: Request,
    body: RefreshRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> TokenPair:
    """Exchange a valid refresh token for a new token pair."""
    payload = verify_refresh_token(body.refresh_token)
    if payload is None or payload.sub is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token"
        )

    # Ensure refresh token is not revoked
    stmt = select(RevokedToken).where(RevokedToken.jti == payload.jti)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

    new_pair = create_token_pair(payload.sub, roles=payload.roles)

    audit = AuditLog(
        event_type=AuditEventType.AUTH_REFRESH,
        user_id=payload.sub,
        ip_address=get_client_ip(request),
        details={"subject": payload.sub},
    )
    db.add(audit)
    await db.commit()
    return new_pair


@router.post("/revoke", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke a token")
async def revoke_token(
    body: RevokeRequest,
    current_user: Annotated[TokenPayload, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    """Add a token's JTI to the server-side revocation list."""
    from server.security.jwt_handler import decode_token_unverified

    try:
        claims = decode_token_unverified(body.token)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot decode token"
        ) from exc

    jti = claims.get("jti", "")
    exp_ts = claims.get("exp")
    if not jti or not exp_ts:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token has no JTI or expiry")

    expires_at = datetime.fromtimestamp(exp_ts, tz=UTC)
    revoked = RevokedToken(jti=jti, expires_at=expires_at, revoked_by=current_user.sub)
    db.add(revoked)

    audit = AuditLog(
        event_type=AuditEventType.AUTH_LOGOUT,
        user_id=current_user.sub,
        details={"jti": jti},
    )
    db.add(audit)
    await db.commit()
