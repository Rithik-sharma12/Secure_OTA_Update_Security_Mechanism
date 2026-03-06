"""SQLAlchemy ORM models for the Secure OTA Update Framework."""

import uuid
from datetime import datetime
from enum import Enum as PyEnum

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from server.database import Base


def generate_uuid() -> str:
    """Generate a new UUID4 string."""
    return str(uuid.uuid4())


class FirmwareStatus(str, PyEnum):
    """Lifecycle status of a firmware artifact."""

    PENDING = "pending"
    VERIFIED = "verified"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    REVOKED = "revoked"


class DeviceStatus(str, PyEnum):
    """Operational status of a registered device."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    BANNED = "banned"
    PENDING = "pending"


class DeploymentStatus(str, PyEnum):
    """Status of a staged OTA deployment."""

    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class DeviceDeploymentStatus(str, PyEnum):
    """Per-device result within a deployment."""

    PENDING = "pending"
    DOWNLOADING = "downloading"
    APPLYING = "applying"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class AuditEventType(str, PyEnum):
    """Supported audit log event categories."""

    FIRMWARE_UPLOAD = "firmware_upload"
    FIRMWARE_DELETE = "firmware_delete"
    FIRMWARE_DOWNLOAD = "firmware_download"
    FIRMWARE_VERIFY = "firmware_verify"
    DEVICE_REGISTER = "device_register"
    DEVICE_AUTH = "device_auth"
    DEVICE_UPDATE = "device_update"
    DEPLOYMENT_CREATE = "deployment_create"
    DEPLOYMENT_ADVANCE = "deployment_advance"
    DEPLOYMENT_ROLLBACK = "deployment_rollback"
    AUTH_LOGIN = "auth_login"
    AUTH_LOGOUT = "auth_logout"
    AUTH_REFRESH = "auth_refresh"
    KEY_ROTATION = "key_rotation"


class Firmware(Base):
    """Firmware artifact uploaded to the OTA server."""

    __tablename__ = "firmware"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    version: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    platform: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    hash_sha256: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    signature_algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="RSA-SHA256")
    file_path: Mapped[str] = mapped_column(String(512), nullable=False)
    size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    status: Mapped[FirmwareStatus] = mapped_column(
        Enum(FirmwareStatus), nullable=False, default=FirmwareStatus.PENDING
    )
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    created_by: Mapped[str | None] = mapped_column(String(256), nullable=True)

    __table_args__ = (UniqueConstraint("version", "platform", name="uq_firmware_version_platform"),)

    deployments: Mapped[list["Deployment"]] = relationship("Deployment", back_populates="firmware")
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog", back_populates="firmware", foreign_keys="AuditLog.firmware_id"
    )


class Device(Base):
    """IoT device registered with the OTA server."""

    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    device_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    platform: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    certificate_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True, unique=True)
    hardware_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    current_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[DeviceStatus] = mapped_column(
        Enum(DeviceStatus), nullable=False, default=DeviceStatus.PENDING
    )
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSON, nullable=False, default=dict)

    device_deployments: Mapped[list["DeviceDeployment"]] = relationship(
        "DeviceDeployment", back_populates="device"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog", back_populates="device", foreign_keys="AuditLog.device_id"
    )


class Deployment(Base):
    """Staged OTA deployment targeting a percentage of the fleet."""

    __tablename__ = "deployments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    firmware_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("firmware.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[DeploymentStatus] = mapped_column(
        Enum(DeploymentStatus), nullable=False, default=DeploymentStatus.DRAFT
    )
    deployment_stages: Mapped[list[int]] = mapped_column(JSON, nullable=False, default=lambda: [1, 5, 25, 100])
    current_stage_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    target_percentage: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    platform_filter: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(256), nullable=True)

    firmware: Mapped["Firmware"] = relationship("Firmware", back_populates="deployments")
    device_deployments: Mapped[list["DeviceDeployment"]] = relationship(
        "DeviceDeployment", back_populates="deployment", cascade="all, delete-orphan"
    )


class DeviceDeployment(Base):
    """Tracks the per-device state of a deployment."""

    __tablename__ = "device_deployments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    deployment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("deployments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[DeviceDeploymentStatus] = mapped_column(
        Enum(DeviceDeploymentStatus), nullable=False, default=DeviceDeploymentStatus.PENDING
    )
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("device_id", "deployment_id", name="uq_device_deployment"),
    )

    device: Mapped["Device"] = relationship("Device", back_populates="device_deployments")
    deployment: Mapped["Deployment"] = relationship("Deployment", back_populates="device_deployments")


class AuditLog(Base):
    """Immutable structured audit log entry."""

    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    event_type: Mapped[AuditEventType] = mapped_column(Enum(AuditEventType), nullable=False, index=True)
    device_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    firmware_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("firmware.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[str | None] = mapped_column(String(256), nullable=True, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    details: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    device: Mapped["Device | None"] = relationship(
        "Device", back_populates="audit_logs", foreign_keys=[device_id]
    )
    firmware: Mapped["Firmware | None"] = relationship(
        "Firmware", back_populates="audit_logs", foreign_keys=[firmware_id]
    )


class RevokedToken(Base):
    """Revoked JWT tokens for server-side invalidation."""

    __tablename__ = "revoked_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    jti: Mapped[str] = mapped_column(String(256), nullable=False, unique=True, index=True)
    revoked_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
