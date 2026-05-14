"""Device registration and management routes."""

import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.dependencies import get_client_ip, get_current_user, require_admin
from server.models import AuditEventType, AuditLog, Device, DeviceStatus, Firmware, FirmwareStatus
from server.security.jwt_handler import TokenPayload
from server.security.pki import get_certificate_fingerprint

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/devices")


class DeviceRegisterRequest(BaseModel):
    """Payload for registering a new device."""

    device_id: str
    platform: str
    hardware_version: str | None = None
    certificate_pem: str | None = None
    metadata: dict = {}


class DeviceStatusUpdateRequest(BaseModel):
    """Payload for updating device status."""

    status: DeviceStatus


class DeviceResponse(BaseModel):
    """Device metadata returned by API endpoints."""

    id: str
    device_id: str
    platform: str
    hardware_version: str | None
    current_version: str | None
    status: str
    registered_at: str
    last_seen: str | None
    certificate_fingerprint: str | None

    model_config = {"from_attributes": True}


class FirmwareUpdateInfo(BaseModel):
    """Information about an available firmware update for a device."""

    update_available: bool
    firmware_id: str | None = None
    version: str | None = None
    hash_sha256: str | None = None
    size: int | None = None


def _device_to_response(device: Device) -> DeviceResponse:
    """Convert a Device ORM model to a DeviceResponse schema."""
    return DeviceResponse(
        id=device.id,
        device_id=device.device_id,
        platform=device.platform,
        hardware_version=device.hardware_version,
        current_version=device.current_version,
        status=device.status.value,
        registered_at=device.registered_at.isoformat(),
        last_seen=device.last_seen.isoformat() if device.last_seen else None,
        certificate_fingerprint=device.certificate_fingerprint,
    )


@router.post(
    "/register",
    response_model=DeviceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new device",
)
async def register_device(
    request: Request,
    body: DeviceRegisterRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(require_admin)],
) -> DeviceResponse:
    """Register a new IoT device with optional certificate for mTLS."""
    stmt = select(Device).where(Device.device_id == body.device_id)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Device '{body.device_id}' is already registered",
        )

    cert_fingerprint: str | None = None
    if body.certificate_pem:
        try:
            cert_fingerprint = get_certificate_fingerprint(body.certificate_pem.encode())
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid certificate PEM: {exc}",
            ) from exc

    device = Device(
        device_id=body.device_id,
        platform=body.platform,
        hardware_version=body.hardware_version,
        certificate_fingerprint=cert_fingerprint,
        status=DeviceStatus.ACTIVE,
        metadata_=body.metadata,
    )
    db.add(device)

    audit = AuditLog(
        event_type=AuditEventType.DEVICE_REGISTER,
        user_id=current_user.sub,
        ip_address=get_client_ip(request),
        details={"device_id": body.device_id, "platform": body.platform},
    )
    db.add(audit)
    await db.commit()
    await db.refresh(device)
    logger.info("Device registered: %s (%s)", body.device_id, body.platform)
    return _device_to_response(device)


@router.get("/", response_model=list[DeviceResponse], summary="List devices")
async def list_devices(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(require_admin)],
    platform: str | None = None,
    device_status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[DeviceResponse]:
    """List all registered devices with optional filtering."""
    stmt = select(Device)
    if platform:
        stmt = stmt.where(Device.platform == platform)
    if device_status:
        stmt = stmt.where(Device.status == device_status)
    stmt = stmt.order_by(Device.registered_at.desc()).limit(limit).offset(offset)
    result = await db.execute(stmt)
    return [_device_to_response(d) for d in result.scalars().all()]


@router.get("/{device_id}", response_model=DeviceResponse, summary="Get device details")
async def get_device(
    device_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(get_current_user)],
) -> DeviceResponse:
    """Retrieve metadata for a specific device by its device_id."""
    stmt = select(Device).where(Device.device_id == device_id)
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return _device_to_response(device)


@router.put("/{device_id}/status", response_model=DeviceResponse, summary="Update device status")
async def update_device_status(
    device_id: str,
    body: DeviceStatusUpdateRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(require_admin)],
) -> DeviceResponse:
    """Update the operational status of a device (active/inactive/banned)."""
    stmt = select(Device).where(Device.device_id == device_id)
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    old_status = device.status
    device.status = body.status

    audit = AuditLog(
        event_type=AuditEventType.DEVICE_UPDATE,
        device_id=device.id,
        user_id=current_user.sub,
        ip_address=get_client_ip(request),
        details={"old_status": old_status.value, "new_status": body.status.value},
    )
    db.add(audit)
    await db.commit()
    await db.refresh(device)
    return _device_to_response(device)


@router.get(
    "/{device_id}/updates",
    response_model=FirmwareUpdateInfo,
    summary="Check for available firmware updates",
)
async def check_device_updates(
    device_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(get_current_user)],
) -> FirmwareUpdateInfo:
    """Return the latest verified firmware for the device's platform if newer than current.

    Also updates the device's last_seen timestamp.
    """
    stmt = select(Device).where(Device.device_id == device_id)
    result = await db.execute(stmt)
    device = result.scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")

    device.last_seen = datetime.now(UTC)
    await db.commit()

    # Find latest verified firmware for the device's platform
    fw_stmt = (
        select(Firmware)
        .where(Firmware.platform == device.platform, Firmware.status == FirmwareStatus.VERIFIED)
        .order_by(Firmware.created_at.desc())
        .limit(1)
    )
    fw_result = await db.execute(fw_stmt)
    latest_fw = fw_result.scalar_one_or_none()

    if latest_fw is None or latest_fw.version == device.current_version:
        return FirmwareUpdateInfo(update_available=False)

    return FirmwareUpdateInfo(
        update_available=True,
        firmware_id=latest_fw.id,
        version=latest_fw.version,
        hash_sha256=latest_fw.hash_sha256,
        size=latest_fw.size,
    )
