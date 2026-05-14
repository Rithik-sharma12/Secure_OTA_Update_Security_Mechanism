"""Structured audit logging with JSON output for SIEM integration."""

import json
import logging
import sys
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class AuditSeverity(str, Enum):
    """Audit event severity levels."""

    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class AuditLogger:
    """Structured audit logger that emits JSON-formatted records.

    Each log entry includes a timestamp, severity, event type, actor,
    resource identifiers, and an arbitrary details payload. Records are
    written to both the Python logging subsystem and, optionally, a
    dedicated audit log file for offline analysis.
    """

    def __init__(self, name: str = "audit", log_file: str | None = None) -> None:
        self._logger = logging.getLogger(name)
        self._file_handler: logging.FileHandler | None = None

        if log_file:
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(logging.Formatter("%(message)s"))
            self._logger.addHandler(fh)
            self._file_handler = fh

    def _emit(
        self,
        event_type: str,
        severity: AuditSeverity,
        actor: str | None = None,
        device_id: str | None = None,
        firmware_id: str | None = None,
        ip_address: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        record = {
            "timestamp": datetime.now(UTC).isoformat(),
            "severity": severity.value,
            "event_type": event_type,
            "actor": actor,
            "device_id": device_id,
            "firmware_id": firmware_id,
            "ip_address": ip_address,
            "details": details or {},
        }
        line = json.dumps(record)

        if severity == AuditSeverity.CRITICAL:
            self._logger.critical(line)
        elif severity == AuditSeverity.WARNING:
            self._logger.warning(line)
        else:
            self._logger.info(line)

    def log_firmware_upload(
        self,
        actor: str,
        firmware_id: str,
        version: str,
        platform: str,
        ip_address: str | None = None,
    ) -> None:
        """Log a firmware upload event."""
        self._emit(
            "FIRMWARE_UPLOAD",
            AuditSeverity.INFO,
            actor=actor,
            firmware_id=firmware_id,
            ip_address=ip_address,
            details={"version": version, "platform": platform},
        )

    def log_firmware_verification(
        self, actor: str, firmware_id: str, valid: bool, ip_address: str | None = None
    ) -> None:
        """Log a firmware signature verification event."""
        severity = AuditSeverity.INFO if valid else AuditSeverity.WARNING
        self._emit(
            "FIRMWARE_VERIFY",
            severity,
            actor=actor,
            firmware_id=firmware_id,
            ip_address=ip_address,
            details={"valid": valid},
        )

    def log_device_auth(
        self, device_id: str, success: bool, ip_address: str | None = None, reason: str | None = None
    ) -> None:
        """Log a device authentication attempt."""
        severity = AuditSeverity.WARNING if not success else AuditSeverity.INFO
        self._emit(
            "DEVICE_AUTH",
            severity,
            device_id=device_id,
            ip_address=ip_address,
            details={"success": success, "reason": reason},
        )

    def log_deployment_event(
        self,
        event_type: str,
        actor: str,
        deployment_id: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Log a deployment lifecycle event (create/advance/rollback)."""
        self._emit(
            event_type,
            AuditSeverity.INFO,
            actor=actor,
            details={"deployment_id": deployment_id, **(details or {})},
        )

    def log_key_rotation(
        self, actor: str, key_type: str, key_id: str | None = None
    ) -> None:
        """Log a cryptographic key rotation event."""
        self._emit(
            "KEY_ROTATION",
            AuditSeverity.CRITICAL,
            actor=actor,
            details={"key_type": key_type, "key_id": key_id},
        )

    def log_security_event(
        self,
        event_type: str,
        severity: AuditSeverity,
        details: dict[str, Any] | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Log a generic security-relevant event."""
        self._emit(event_type, severity, ip_address=ip_address, details=details)


# Module-level singleton
_audit_logger: AuditLogger | None = None


def get_audit_logger(log_file: str | None = None) -> AuditLogger:
    """Return the module-level AuditLogger singleton, creating it if needed."""
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(log_file=log_file)
    return _audit_logger
