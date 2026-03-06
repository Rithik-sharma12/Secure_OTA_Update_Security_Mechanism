"""Staged deployment management routes."""

import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.database import get_db
from server.dependencies import get_client_ip, get_current_user, require_admin
from server.models import (
    AuditEventType,
    AuditLog,
    Deployment,
    DeploymentStatus,
    Device,
    DeviceDeployment,
    DeviceDeploymentStatus,
    DeviceStatus,
    Firmware,
    FirmwareStatus,
)
from server.security.jwt_handler import TokenPayload

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/deployments")


class DeploymentCreateRequest(BaseModel):
    """Payload for creating a new staged deployment."""

    firmware_id: str
    name: str
    description: str | None = None
    deployment_stages: list[int] = [1, 5, 25, 100]
    platform_filter: str | None = None

    @field_validator("deployment_stages")
    @classmethod
    def validate_stages(cls, v: list[int]) -> list[int]:
        if not v or v[-1] != 100:
            raise ValueError("deployment_stages must end with 100")
        if any(s < 1 or s > 100 for s in v):
            raise ValueError("Each stage percentage must be between 1 and 100")
        if v != sorted(v):
            raise ValueError("Stages must be in ascending order")
        return v


class DeploymentResponse(BaseModel):
    """Deployment metadata returned by API endpoints."""

    id: str
    firmware_id: str
    name: str
    description: str | None
    status: str
    deployment_stages: list[int]
    current_stage_index: int
    target_percentage: float
    platform_filter: str | None
    created_at: str
    completed_at: str | None


class DeploymentMetrics(BaseModel):
    """Aggregated metrics for a deployment."""

    deployment_id: str
    total_devices: int
    pending: int
    downloading: int
    applying: int
    success: int
    failed: int
    rolled_back: int
    success_rate: float


def _deployment_to_response(dep: Deployment) -> DeploymentResponse:
    return DeploymentResponse(
        id=dep.id,
        firmware_id=dep.firmware_id,
        name=dep.name,
        description=dep.description,
        status=dep.status.value,
        deployment_stages=dep.deployment_stages,
        current_stage_index=dep.current_stage_index,
        target_percentage=dep.target_percentage,
        platform_filter=dep.platform_filter,
        created_at=dep.created_at.isoformat(),
        completed_at=dep.completed_at.isoformat() if dep.completed_at else None,
    )


@router.post(
    "/",
    response_model=DeploymentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a staged deployment",
)
async def create_deployment(
    request: Request,
    body: DeploymentCreateRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(require_admin)],
) -> DeploymentResponse:
    """Create a new staged OTA deployment.

    Devices are selected based on optional platform_filter and assigned
    to the deployment with PENDING status. The deployment starts at stage 0
    (first percentage in deployment_stages).
    """
    stmt = select(Firmware).where(Firmware.id == body.firmware_id)
    result = await db.execute(stmt)
    firmware = result.scalar_one_or_none()
    if firmware is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Firmware not found")
    if firmware.status not in (FirmwareStatus.VERIFIED, FirmwareStatus.ACTIVE):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Firmware must be verified before deployment",
        )

    initial_percentage = body.deployment_stages[0]

    # Gather eligible devices
    device_stmt = select(Device).where(Device.status == DeviceStatus.ACTIVE)
    if body.platform_filter:
        device_stmt = device_stmt.where(Device.platform == body.platform_filter)
    devices_result = await db.execute(device_stmt)
    all_devices = devices_result.scalars().all()

    deployment = Deployment(
        firmware_id=body.firmware_id,
        name=body.name,
        description=body.description,
        deployment_stages=body.deployment_stages,
        current_stage_index=0,
        target_percentage=float(initial_percentage),
        platform_filter=body.platform_filter,
        status=DeploymentStatus.ACTIVE,
        created_by=current_user.sub,
    )
    db.add(deployment)
    await db.flush()  # get deployment.id

    # Assign devices for the initial stage
    count = max(1, int(len(all_devices) * initial_percentage / 100))
    for device in all_devices[:count]:
        dd = DeviceDeployment(
            device_id=device.id,
            deployment_id=deployment.id,
            status=DeviceDeploymentStatus.PENDING,
        )
        db.add(dd)

    firmware.status = FirmwareStatus.ACTIVE

    audit = AuditLog(
        event_type=AuditEventType.DEPLOYMENT_CREATE,
        firmware_id=firmware.id,
        user_id=current_user.sub,
        ip_address=get_client_ip(request),
        details={
            "name": body.name,
            "stages": body.deployment_stages,
            "initial_devices": count,
        },
    )
    db.add(audit)
    await db.commit()
    await db.refresh(deployment)
    logger.info("Deployment created: %s (%s)", deployment.name, deployment.id)
    return _deployment_to_response(deployment)


@router.get("/", response_model=list[DeploymentResponse], summary="List deployments")
async def list_deployments(
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(require_admin)],
    dep_status: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[DeploymentResponse]:
    """List all deployments with optional status filter."""
    stmt = select(Deployment)
    if dep_status:
        stmt = stmt.where(Deployment.status == dep_status)
    stmt = stmt.order_by(Deployment.created_at.desc()).limit(limit).offset(offset)
    result = await db.execute(stmt)
    return [_deployment_to_response(d) for d in result.scalars().all()]


@router.get("/{deployment_id}", response_model=DeploymentResponse, summary="Get deployment status")
async def get_deployment(
    deployment_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(get_current_user)],
) -> DeploymentResponse:
    """Get the current status and configuration of a deployment."""
    stmt = select(Deployment).where(Deployment.id == deployment_id)
    result = await db.execute(stmt)
    deployment = result.scalar_one_or_none()
    if deployment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found")
    return _deployment_to_response(deployment)


@router.put("/{deployment_id}/advance", response_model=DeploymentResponse, summary="Advance deployment stage")
async def advance_deployment(
    deployment_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(require_admin)],
) -> DeploymentResponse:
    """Advance the deployment to the next stage percentage.

    Before advancing, validates that the failure rate is below the configured
    rollback threshold. On reaching 100%, marks the deployment COMPLETED.
    """
    stmt = select(Deployment).where(Deployment.id == deployment_id)
    result = await db.execute(stmt)
    deployment = result.scalar_one_or_none()
    if deployment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found")

    if deployment.status != DeploymentStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot advance deployment in '{deployment.status.value}' state",
        )

    next_index = deployment.current_stage_index + 1
    if next_index >= len(deployment.deployment_stages):
        deployment.status = DeploymentStatus.COMPLETED
        deployment.completed_at = datetime.now(UTC)
        await db.commit()
        await db.refresh(deployment)
        return _deployment_to_response(deployment)

    # Check failure rate before advancing
    metrics = await _compute_metrics(deployment_id, db)
    if metrics.total_devices > 0 and metrics.failed > 0:
        from server.config import get_settings
        threshold = get_settings().deployment_rollback_threshold_percent
        failure_rate = metrics.failed / metrics.total_devices * 100
        if failure_rate >= threshold:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failure rate {failure_rate:.1f}% exceeds threshold {threshold}%. Rollback recommended.",
            )

    next_percentage = deployment.deployment_stages[next_index]
    deployment.current_stage_index = next_index
    deployment.target_percentage = float(next_percentage)

    # Enroll additional devices for the new percentage
    device_stmt = select(Device).where(Device.status == DeviceStatus.ACTIVE)
    if deployment.platform_filter:
        device_stmt = device_stmt.where(Device.platform == deployment.platform_filter)
    devices_result = await db.execute(device_stmt)
    all_devices = devices_result.scalars().all()

    # Find already enrolled device IDs
    enrolled_stmt = select(DeviceDeployment.device_id).where(
        DeviceDeployment.deployment_id == deployment_id
    )
    enrolled_result = await db.execute(enrolled_stmt)
    enrolled_ids = {row[0] for row in enrolled_result.all()}

    target_count = max(1, int(len(all_devices) * next_percentage / 100))
    for device in all_devices[:target_count]:
        if device.id not in enrolled_ids:
            dd = DeviceDeployment(
                device_id=device.id,
                deployment_id=deployment_id,
                status=DeviceDeploymentStatus.PENDING,
            )
            db.add(dd)

    audit = AuditLog(
        event_type=AuditEventType.DEPLOYMENT_ADVANCE,
        user_id=current_user.sub,
        ip_address=get_client_ip(request),
        details={
            "deployment_id": deployment_id,
            "new_stage_index": next_index,
            "new_percentage": next_percentage,
        },
    )
    db.add(audit)
    await db.commit()
    await db.refresh(deployment)
    return _deployment_to_response(deployment)


@router.put(
    "/{deployment_id}/rollback",
    response_model=DeploymentResponse,
    summary="Rollback deployment",
)
async def rollback_deployment(
    deployment_id: str,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(require_admin)],
) -> DeploymentResponse:
    """Mark a deployment as rolled back and update all pending/failed device records."""
    stmt = select(Deployment).where(Deployment.id == deployment_id)
    result = await db.execute(stmt)
    deployment = result.scalar_one_or_none()
    if deployment is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found")

    if deployment.status not in (DeploymentStatus.ACTIVE, DeploymentStatus.PAUSED):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot rollback deployment in '{deployment.status.value}' state",
        )

    deployment.status = DeploymentStatus.ROLLED_BACK
    deployment.completed_at = datetime.now(UTC)

    # Mark pending/downloading/applying records as rolled_back
    dd_stmt = select(DeviceDeployment).where(
        DeviceDeployment.deployment_id == deployment_id,
        DeviceDeployment.status.in_([
            DeviceDeploymentStatus.PENDING,
            DeviceDeploymentStatus.DOWNLOADING,
            DeviceDeploymentStatus.APPLYING,
        ]),
    )
    dd_result = await db.execute(dd_stmt)
    for dd in dd_result.scalars().all():
        dd.status = DeviceDeploymentStatus.ROLLED_BACK

    audit = AuditLog(
        event_type=AuditEventType.DEPLOYMENT_ROLLBACK,
        user_id=current_user.sub,
        ip_address=get_client_ip(request),
        details={"deployment_id": deployment_id},
    )
    db.add(audit)
    await db.commit()
    await db.refresh(deployment)
    logger.info("Deployment rolled back: %s by %s", deployment_id, current_user.sub)
    return _deployment_to_response(deployment)


@router.get(
    "/{deployment_id}/metrics",
    response_model=DeploymentMetrics,
    summary="Get deployment metrics",
)
async def get_deployment_metrics(
    deployment_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[TokenPayload, Depends(get_current_user)],
) -> DeploymentMetrics:
    """Return aggregated success/failure metrics for a deployment."""
    stmt = select(Deployment).where(Deployment.id == deployment_id)
    result = await db.execute(stmt)
    if result.scalar_one_or_none() is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deployment not found")
    return await _compute_metrics(deployment_id, db)


async def _compute_metrics(deployment_id: str, db: AsyncSession) -> DeploymentMetrics:
    """Compute per-status counts for a deployment's device records."""
    stmt = select(
        DeviceDeployment.status,
        func.count(DeviceDeployment.id).label("cnt"),
    ).where(DeviceDeployment.deployment_id == deployment_id).group_by(DeviceDeployment.status)
    result = await db.execute(stmt)
    counts: dict[str, int] = {row[0].value: row[1] for row in result.all()}

    total = sum(counts.values())
    success = counts.get("success", 0)
    failed = counts.get("failed", 0)
    success_rate = (success / total * 100) if total > 0 else 0.0

    return DeploymentMetrics(
        deployment_id=deployment_id,
        total_devices=total,
        pending=counts.get("pending", 0),
        downloading=counts.get("downloading", 0),
        applying=counts.get("applying", 0),
        success=success,
        failed=failed,
        rolled_back=counts.get("rolled_back", 0),
        success_rate=round(success_rate, 2),
    )
