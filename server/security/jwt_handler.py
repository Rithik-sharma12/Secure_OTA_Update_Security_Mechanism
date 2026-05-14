"""JWT token creation, validation, and revocation management."""

import logging
import uuid
from datetime import UTC, datetime, timedelta

from jose import JWTError, jwt
from pydantic import BaseModel

from server.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class TokenPayload(BaseModel):
    """Decoded JWT payload with standard and custom claims."""

    sub: str | None = None
    jti: str = ""
    exp: datetime | None = None
    iat: datetime | None = None
    roles: list[str] = []
    token_type: str = "access"


class TokenPair(BaseModel):
    """Access + refresh token pair returned on login."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


def create_access_token(subject: str, roles: list[str] | None = None) -> str:
    """Create a signed JWT access token.

    Args:
        subject: Token subject (username or device_id).
        roles: Optional list of roles/permissions to embed.

    Returns:
        Signed JWT string.
    """
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload = {
        "sub": subject,
        "jti": str(uuid.uuid4()),
        "exp": expire,
        "iat": now,
        "roles": roles or [],
        "token_type": "access",
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_refresh_token(subject: str) -> str:
    """Create a signed JWT refresh token with a longer expiry.

    Args:
        subject: Token subject (username or device_id).

    Returns:
        Signed JWT string.
    """
    now = datetime.now(UTC)
    expire = now + timedelta(days=settings.jwt_refresh_token_expire_days)
    payload = {
        "sub": subject,
        "jti": str(uuid.uuid4()),
        "exp": expire,
        "iat": now,
        "roles": [],
        "token_type": "refresh",
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def create_token_pair(subject: str, roles: list[str] | None = None) -> TokenPair:
    """Create both access and refresh tokens for a subject.

    Args:
        subject: User identifier or device_id.
        roles: Optional list of roles to embed in the access token.

    Returns:
        TokenPair containing access token, refresh token, and expiry info.
    """
    return TokenPair(
        access_token=create_access_token(subject, roles),
        refresh_token=create_refresh_token(subject),
        expires_in=settings.jwt_access_token_expire_minutes * 60,
    )


def verify_access_token(token: str) -> TokenPayload | None:
    """Decode and validate a JWT access token.

    Args:
        token: Raw JWT string.

    Returns:
        Decoded TokenPayload on success, None on failure.
    """
    try:
        raw = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        payload = TokenPayload(**raw)
        if payload.token_type != "access":
            logger.warning("Token type mismatch: expected 'access', got '%s'", payload.token_type)
            return None
        return payload
    except JWTError as exc:
        logger.debug("JWT verification failed: %s", exc)
        return None


def verify_refresh_token(token: str) -> TokenPayload | None:
    """Decode and validate a JWT refresh token.

    Args:
        token: Raw JWT refresh token string.

    Returns:
        Decoded TokenPayload on success, None on failure.
    """
    try:
        raw = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        payload = TokenPayload(**raw)
        if payload.token_type != "refresh":
            logger.warning("Token type mismatch: expected 'refresh', got '%s'", payload.token_type)
            return None
        return payload
    except JWTError as exc:
        logger.debug("Refresh JWT verification failed: %s", exc)
        return None


def decode_token_unverified(token: str) -> dict:
    """Decode a JWT without signature verification (for inspection only).

    Warning: Do NOT use for authentication. Intended for debugging.
    """
    return jwt.get_unverified_claims(token)
