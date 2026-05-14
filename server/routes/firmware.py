"""Firmware management routes: upload, list, download, verify, delete."""

import hashlib
import logging
import os
from pathlib import Path
from typing import Annotated

import aiofiles
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import get_settings
from server.database import get_db
from server.dependencies import get_client_ip, get_current_user, require_admin
from server.models import AuditEventType, AuditLog, Firmware, FirmwareStatus
from server.security.crypto import (
    compute_sha256,
    decode_signature_b64,
    encode_signature_b64,
    verify_rsa_sha256_signature,
)
from server.security.jwt_handler import TokenPayload

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/firmware")
settings = get_settings()


class FirmwareResponse(BaseModel):
    """Firmware metadata returned by list/get endpoints."""

    id: str
    version: str
    platform: str
    hash_sha256: str
    signature_algorithm: str
    size: int
    status: str
    created_at: str
    created_by: str | None

    model_config = {"from_attributes": True}


class FirmwareVerifyResponse(BaseModel):
    """Result of a firmware signature verification request."""

    firmware_id: str
    valid: bool
    message: str


@router.post(
    "/upload",
    response_model=FirmwareResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload signed firmware",
)
async def upload_firmware(
    request: Request,
    file: Annotated[UploadFile, File(description="Firmware binary file")],
    version: Annotated[str, Form(description="Semantic version string, e.g. 1.2.3")],
    platform: Annotated[str, Form(description="Target platform, e.g. esp32")],
    signature_b64: Annotated[str, Form(description="Base64-encoded RSA-SHA256 signature")],
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(require_admin)],
) -> FirmwareResponse:
    """Upload a firmware binary with its cryptographic signature.

    The file is hashed (SHA-256) and the signature is recorded.
    Signature verification against the server's public key is performed
    via the separate /verify endpoint or automatically if a public key is
    configured in Settings.
    """
    if file.content_type not in ("application/octet-stream", "application/x-binary", None):
        logger.info("Unusual content type: %s", file.content_type)

    if file.filename:
        ext = Path(file.filename).suffix.lower()
        if ext and ext not in settings.firmware_allowed_extensions:
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail=f"File extension '{ext}' not allowed",
            )

    upload_dir = Path(settings.firmware_upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)

    # Stream file to disk while computing SHA-256
    sha256_hash = hashlib.sha256()
    total_size = 0
    safe_name = f"{platform}_{version}_{os.urandom(8).hex()}.bin"
    dest_path = upload_dir / safe_name

    try:
        async with aiofiles.open(dest_path, "wb") as out_file:
            while chunk := await file.read(65536):
                if total_size + len(chunk) > settings.firmware_max_size_bytes:
                    await out_file.close()
                    dest_path.unlink(missing_ok=True)
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Firmware exceeds {settings.firmware_max_size_mb} MB limit",
                    )
                sha256_hash.update(chunk)
                total_size += len(chunk)
                await out_file.write(chunk)
    except HTTPException:
        raise
    except Exception as exc:
        dest_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save firmware file",
        ) from exc

    digest = sha256_hash.hexdigest()

    # Check for duplicate (same hash)
    stmt = select(Firmware).where(Firmware.hash_sha256 == digest)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        dest_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Firmware with identical content already exists",
        )

    # Check version+platform uniqueness
    stmt = select(Firmware).where(
        Firmware.version == version, Firmware.platform == platform
    )
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        dest_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Firmware {version}/{platform} already exists",
        )

    firmware = Firmware(
        version=version,
        platform=platform,
        hash_sha256=digest,
        signature=signature_b64,
        signature_algorithm="RSA-SHA256",
        file_path=str(dest_path),
        size=total_size,
        status=FirmwareStatus.PENDING,
        created_by=current_user.sub,
    )
    db.add(firmware)

    audit = AuditLog(
        event_type=AuditEventType.FIRMWARE_UPLOAD,
        firmware_id=firmware.id,
        user_id=current_user.sub,
        ip_address=get_client_ip(request),
        details={"version": version, "platform": platform, "size": total_size, "hash": digest},
    )
    db.add(audit)
    await db.commit()
    await db.refresh(firmware)
    logger.info("Firmware uploaded: %s/%s (%s)", platform, version, firmware.id)

    return FirmwareResponse(
        id=firmware.id,
        version=firmware.version,
        platform=firmware.platform,
        hash_sha256=firmware.hash_sha256,
        signature_algorithm=firmware.signature_algorithm,
        size=firmware.size,
        status=firmware.status.value,
        created_at=firmware.created_at.isoformat(),
        created_by=firmware.created_by,
    )


@router.get("/", response_model=list[FirmwareResponse], summary="List all firmware")
async def list_firmware(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(get_current_user)],
    platform: str | None = None,
    fw_status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[FirmwareResponse]:
    """List firmware with optional filtering by platform and status."""
    stmt = select(Firmware)
    if platform:
        stmt = stmt.where(Firmware.platform == platform)
    if fw_status:
        stmt = stmt.where(Firmware.status == fw_status)
    stmt = stmt.order_by(Firmware.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(stmt)
    firmwares = result.scalars().all()
    return [
        FirmwareResponse(
            id=fw.id,
            version=fw.version,
            platform=fw.platform,
            hash_sha256=fw.hash_sha256,
            signature_algorithm=fw.signature_algorithm,
            size=fw.size,
            status=fw.status.value,
            created_at=fw.created_at.isoformat(),
            created_by=fw.created_by,
        )
        for fw in firmwares
    ]


@router.get("/{firmware_id}", response_model=FirmwareResponse, summary="Get firmware details")
async def get_firmware(
    firmware_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(get_current_user)],
) -> FirmwareResponse:
    """Retrieve metadata for a specific firmware by ID."""
    stmt = select(Firmware).where(Firmware.id == firmware_id)
    result = await db.execute(stmt)
    firmware = result.scalar_one_or_none()
    if firmware is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Firmware not found")
    return FirmwareResponse(
        id=firmware.id,
        version=firmware.version,
        platform=firmware.platform,
        hash_sha256=firmware.hash_sha256,
        signature_algorithm=firmware.signature_algorithm,
        size=firmware.size,
        status=firmware.status.value,
        created_at=firmware.created_at.isoformat(),
        created_by=firmware.created_by,
    )


@router.delete(
    "/{firmware_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete firmware",
)
async def delete_firmware(
    firmware_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(require_admin)],
) -> None:
    """Delete a firmware record and its stored binary. Active deployments must be stopped first."""
    stmt = select(Firmware).where(Firmware.id == firmware_id)
    result = await db.execute(stmt)
    firmware = result.scalar_one_or_none()
    if firmware is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Firmware not found")

    file_path = Path(firmware.file_path)
    file_path.unlink(missing_ok=True)

    audit = AuditLog(
        event_type=AuditEventType.FIRMWARE_DELETE,
        firmware_id=firmware.id,
        user_id=current_user.sub,
        ip_address=get_client_ip(request),
        details={"version": firmware.version, "platform": firmware.platform},
    )
    db.add(audit)
    await db.delete(firmware)
    await db.commit()
    logger.info("Firmware deleted: %s by %s", firmware_id, current_user.sub)


@router.get("/{firmware_id}/download", summary="Download firmware binary")
async def download_firmware(
    firmware_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(get_current_user)],
) -> FileResponse:
    """Stream the firmware binary file to the client."""
    stmt = select(Firmware).where(Firmware.id == firmware_id)
    result = await db.execute(stmt)
    firmware = result.scalar_one_or_none()
    if firmware is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Firmware not found")

    file_path = Path(firmware.file_path)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Firmware binary file not found on server"
        )

    audit = AuditLog(
        event_type=AuditEventType.FIRMWARE_DOWNLOAD,
        firmware_id=firmware.id,
        user_id=current_user.sub,
        ip_address=get_client_ip(request),
        details={"version": firmware.version, "platform": firmware.platform},
    )
    db.add(audit)
    await db.commit()

    return FileResponse(
        path=str(file_path),
        filename=f"{firmware.platform}_{firmware.version}.bin",
        media_type="application/octet-stream",
        headers={"X-Firmware-Hash": firmware.hash_sha256},
    )


@router.post(
    "/{firmware_id}/verify",
    response_model=FirmwareVerifyResponse,
    summary="Verify firmware signature",
)
async def verify_firmware_signature(
    firmware_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(get_current_user)],
) -> FirmwareVerifyResponse:
    """Verify the firmware's stored signature against the configured public key.

    Reads the firmware binary from disk, computes the SHA-256 digest, and
    verifies the stored RSA-SHA256 signature. On success, marks the firmware
    as VERIFIED in the database.
    """
    stmt = select(Firmware).where(Firmware.id == firmware_id)
    result = await db.execute(stmt)
    firmware = result.scalar_one_or_none()
    if firmware is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Firmware not found")

    public_key_path = Path(settings.firmware_verify_key_path)
    if not public_key_path.exists():
        return FirmwareVerifyResponse(
            firmware_id=firmware_id,
            valid=False,
            message="Verification key not configured on server",
        )

    file_path = Path(firmware.file_path)
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Firmware binary file not found"
        )

    try:
        data = file_path.read_bytes()
        public_key_pem = public_key_path.read_bytes()
        signature = decode_signature_b64(firmware.signature)
        valid = verify_rsa_sha256_signature(public_key_pem, data, signature)
    except Exception as exc:
        logger.error("Signature verification error for %s: %s", firmware_id, exc)
        valid = False

    if valid:
        firmware.status = FirmwareStatus.VERIFIED

    audit = AuditLog(
        event_type=AuditEventType.FIRMWARE_VERIFY,
        firmware_id=firmware.id,
        user_id=current_user.sub,
        ip_address=get_client_ip(request),
        details={"valid": valid},
    )
    db.add(audit)
    await db.commit()

    return FirmwareVerifyResponse(
        firmware_id=firmware_id,
        valid=valid,
        message="Signature valid" if valid else "Signature invalid",
    )
