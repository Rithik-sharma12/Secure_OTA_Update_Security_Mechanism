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

import hmac

from fastapi import Header, HTTPException, Query

from .config import API_KEY


def require_write_auth(
    api_key: str | None = Query(default=None),
    x_api_key: str | None = Header(default=None, alias='x-api-key'),
    authorization: str | None = Header(default=None),
) -> None:
    """Validate the gateway API key for write operations.

    Accepts the key as an `api_key` query parameter, an `x-api-key` header, or
    an `Authorization: Bearer <key>` header.

    When no API_KEY is configured every write endpoint is unauthenticated —
    publishing firmware included. config.py refuses to start in that state
    unless OTA_GATEWAY_ALLOW_OPEN_WRITES is set, so reaching this branch is a
    deliberate local-development choice rather than an oversight.
    """
    if not API_KEY:
        return

    bearer = ''
    if authorization and authorization.lower().startswith('bearer '):
        bearer = authorization.split(' ', 1)[1].strip()

    provided = (api_key or x_api_key or bearer or '').strip()

    # compare_digest rather than `!=`: a plain string comparison returns as
    # soon as two bytes differ, which leaks the length of the shared prefix
    # and lets a caller recover the key one byte at a time from response
    # timings. Both sides are encoded first because compare_digest rejects
    # str arguments containing non-ASCII.
    if not hmac.compare_digest(provided.encode('utf-8'), API_KEY.encode('utf-8')):
        raise HTTPException(status_code=401, detail='Invalid or missing gateway API key.')


# ── Per-device credentials ────────────────────────────────────
#
# The fleet key above is one secret shared by every board and the dashboard;
# anyone who extracts it from one device's flash can speak for all of them.
# A device token is issued per board by POST /api/devices/register and only
# ever authorises requests about that board. The gateway stores the SHA-256
# of the token, never the token itself.

import hashlib
import secrets
from dataclasses import dataclass

from .config import REQUIRE_DEVICE_TOKEN


def hash_device_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def new_device_token() -> str:
    # 32 random bytes, URL-safe; ~43 characters, fits easily in NVS.
    return secrets.token_urlsafe(32)


@dataclass(frozen=True)
class DeviceCaller:
    """Raw credentials presented on a device-facing request."""

    fleet_key: str
    device_token: str


def device_credentials(
    api_key: str | None = Query(default=None),
    x_api_key: str | None = Header(default=None, alias='x-api-key'),
    x_device_token: str | None = Header(default=None, alias='x-device-token'),
    authorization: str | None = Header(default=None),
) -> DeviceCaller:
    """Collect credentials; the route decides once it knows the device id.

    `Authorization: Bearer <value>` is accepted as either kind, because a
    board only ever sends one secret and the gateway can tell them apart.
    """
    bearer = ''
    if authorization and authorization.lower().startswith('bearer '):
        bearer = authorization.split(' ', 1)[1].strip()

    fleet = (api_key or x_api_key or '').strip()
    token = (x_device_token or '').strip()
    if bearer:
        if not fleet and API_KEY and hmac.compare_digest(bearer.encode('utf-8'), API_KEY.encode('utf-8')):
            fleet = bearer
        elif not token:
            token = bearer
    return DeviceCaller(fleet_key=fleet, device_token=token)


def _fleet_key_valid(provided: str) -> bool:
    if not API_KEY:
        return True
    return bool(provided) and hmac.compare_digest(provided.encode('utf-8'), API_KEY.encode('utf-8'))


def authorize_device_locked(state: dict, device_id: str, caller: DeviceCaller) -> str:
    """Decide whether `caller` may act as `device_id`. Must hold STATE_LOCK.

    Returns 'token' or 'fleet' for the accepted credential, raises 401
    otherwise. Rules:
      * a valid token for this device is always accepted;
      * a token for a *different* device is always refused, even if a fleet
        key is also present — that combination only comes from a confused or
        hostile client;
      * the fleet key is accepted unless the device already has a token and
        OTA_REQUIRE_DEVICE_TOKEN is on.
    """
    record = (state.get('deviceCredentials') or {}).get(device_id)

    if caller.device_token:
        if record and not record.get('revoked') and hmac.compare_digest(
            hash_device_token(caller.device_token), str(record.get('tokenHash', ''))
        ):
            return 'token'
        raise HTTPException(status_code=401, detail='Device token is not valid for this device.')

    if not API_KEY and not record:
        return 'fleet'

    if record and not record.get('revoked') and REQUIRE_DEVICE_TOKEN:
        raise HTTPException(status_code=401, detail='This device must authenticate with its own device token.')

    if _fleet_key_valid(caller.fleet_key):
        return 'fleet'

    raise HTTPException(status_code=401, detail='Invalid or missing device credentials.')
