"""
SentinelOTA Edge Gateway — Write Authentication

The API key guard for every state-mutating endpoint.

This lives in its own module so route modules can import the real dependency
directly. An earlier design defined a no-op placeholder in each route module
and reassigned it from create_app(); that silently did nothing, because
`Depends(...)` captures the function object at decoration time and never sees
the later reassignment. Import the real function here instead.
"""

from __future__ import annotations

from fastapi import Header, HTTPException, Query

from .config import API_KEY


def require_write_auth(
    api_key: str | None = Query(default=None),
    x_api_key: str | None = Header(default=None, alias='x-api-key'),
    authorization: str | None = Header(default=None),
) -> None:
    """Validate the gateway API key for write operations.

    Accepts the key as an `api_key` query parameter, an `x-api-key` header, or
    an `Authorization: Bearer <key>` header. When no API_KEY is configured the
    gateway is open by design (local development).
    """
    if not API_KEY:
        return

    bearer = ''
    if authorization and authorization.lower().startswith('bearer '):
        bearer = authorization.split(' ', 1)[1].strip()

    provided = (api_key or x_api_key or bearer or '').strip()
    if provided != API_KEY:
        raise HTTPException(status_code=401, detail='Invalid or missing gateway API key.')
