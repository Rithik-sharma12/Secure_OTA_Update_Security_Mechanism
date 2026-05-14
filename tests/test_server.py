"""Tests for API endpoints: auth, firmware, devices, deployments."""

import io
import os
import pytest
import pytest_asyncio
from httpx import AsyncClient

from server.security.crypto import (
    generate_rsa_keypair,
    sign_rsa_sha256,
    encode_signature_b64,
    compute_sha256,
)
from server.security.jwt_handler import create_access_token


# ── Auth endpoints ────────────────────────────────────────────────────────────

class TestAuthEndpoints:
    """Tests for /api/v1/auth/* routes."""

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, client: AsyncClient) -> None:
        """POST /auth/token with wrong credentials must return 401."""
        resp = await client.post(
            "/api/v1/auth/token",
            json={"username": "wrong", "password": "wrong"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_refresh_invalid_token(self, client: AsyncClient) -> None:
        """Refreshing with a garbage token must return 401."""
        resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "not.a.valid.jwt"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_revoke_requires_auth(self, client: AsyncClient) -> None:
        """POST /auth/revoke without Authorization header must return 401 or 403."""
        resp = await client.post("/api/v1/auth/revoke", json={"token": "anything"})
        assert resp.status_code in (401, 403)


# ── Health check ──────────────────────────────────────────────────────────────

class TestHealthCheck:
    @pytest.mark.asyncio
    async def test_health_endpoint(self, client: AsyncClient) -> None:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_readiness_endpoint(self, client: AsyncClient) -> None:
        resp = await client.get("/ready")
        assert resp.status_code == 200


# ── Firmware endpoints ────────────────────────────────────────────────────────

class TestFirmwareEndpoints:
    """Tests for /api/v1/firmware/* routes."""

    @pytest.mark.asyncio
    async def test_list_firmware_requires_auth(self, client: AsyncClient) -> None:
        """GET /firmware without token must return 401 or 403."""
        resp = await client.get("/api/v1/firmware/")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_list_firmware_with_token(self, client: AsyncClient, admin_token: str) -> None:
        """Authenticated GET /firmware must return 200 with an empty list."""
        resp = await client.get(
            "/api/v1/firmware/",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_upload_firmware_success(
        self,
        client: AsyncClient,
        admin_token: str,
        sample_firmware_data: bytes,
        sample_firmware_signature: str,
    ) -> None:
        """Valid firmware upload must return 201 with the firmware metadata."""
        resp = await client.post(
            "/api/v1/firmware/upload",
            headers={"Authorization": f"Bearer {admin_token}"},
            files={"file": ("firmware.bin", io.BytesIO(sample_firmware_data), "application/octet-stream")},
            data={
                "version": "1.0.0",
                "platform": "esp32",
                "signature_b64": sample_firmware_signature,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["version"] == "1.0.0"
        assert data["platform"] == "esp32"
        assert data["status"] == "pending"
        assert len(data["hash_sha256"]) == 64

    @pytest.mark.asyncio
    async def test_upload_firmware_duplicate_rejected(
        self,
        client: AsyncClient,
        admin_token: str,
        sample_firmware_data: bytes,
        sample_firmware_signature: str,
    ) -> None:
        """Uploading identical firmware twice must return 409."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        payload = dict(version="2.0.0", platform="esp32", signature_b64=sample_firmware_signature)

        await client.post(
            "/api/v1/firmware/upload",
            headers=headers,
            files={"file": ("fw.bin", io.BytesIO(sample_firmware_data), "application/octet-stream")},
            data=payload,
        )
        resp = await client.post(
            "/api/v1/firmware/upload",
            headers=headers,
            files={"file": ("fw.bin", io.BytesIO(sample_firmware_data), "application/octet-stream")},
            data=payload,
        )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_get_firmware_not_found(self, client: AsyncClient, admin_token: str) -> None:
        """Requesting a non-existent firmware ID must return 404."""
        resp = await client.get(
            "/api/v1/firmware/nonexistent-id",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_firmware(
        self,
        client: AsyncClient,
        admin_token: str,
        sample_firmware_data: bytes,
        sample_firmware_signature: str,
    ) -> None:
        """Admin must be able to delete an uploaded firmware."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        # Upload first
        upload_resp = await client.post(
            "/api/v1/firmware/upload",
            headers=headers,
            files={"file": ("del.bin", io.BytesIO(sample_firmware_data + b"delete"), "application/octet-stream")},
            data={"version": "99.0.0", "platform": "esp32", "signature_b64": sample_firmware_signature},
        )
        fw_id = upload_resp.json()["id"]
        # Delete
        del_resp = await client.delete(f"/api/v1/firmware/{fw_id}", headers=headers)
        assert del_resp.status_code == 204
        # Verify it's gone
        get_resp = await client.get(f"/api/v1/firmware/{fw_id}", headers=headers)
        assert get_resp.status_code == 404


# ── Device endpoints ──────────────────────────────────────────────────────────

class TestDeviceEndpoints:
    """Tests for /api/v1/devices/* routes."""

    @pytest.mark.asyncio
    async def test_register_device(self, client: AsyncClient, admin_token: str) -> None:
        """Admin must be able to register a new device."""
        resp = await client.post(
            "/api/v1/devices/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"device_id": "test-device-001", "platform": "esp32"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["device_id"] == "test-device-001"
        assert data["platform"] == "esp32"
        assert data["status"] == "active"

    @pytest.mark.asyncio
    async def test_register_duplicate_device_rejected(
        self, client: AsyncClient, admin_token: str
    ) -> None:
        """Registering the same device_id twice must return 409."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        payload = {"device_id": "duplicate-device", "platform": "esp32"}
        await client.post("/api/v1/devices/register", headers=headers, json=payload)
        resp = await client.post("/api/v1/devices/register", headers=headers, json=payload)
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_list_devices(self, client: AsyncClient, admin_token: str) -> None:
        """Admin must be able to list all devices."""
        headers = {"Authorization": f"Bearer {admin_token}"}
        await client.post(
            "/api/v1/devices/register",
            headers=headers,
            json={"device_id": "list-test-device", "platform": "esp32"},
        )
        resp = await client.get("/api/v1/devices/", headers=headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    @pytest.mark.asyncio
    async def test_get_device_not_found(self, client: AsyncClient, admin_token: str) -> None:
        resp = await client.get(
            "/api/v1/devices/nonexistent-device",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 404


# ── Deployment endpoints ──────────────────────────────────────────────────────

class TestDeploymentEndpoints:
    """Tests for /api/v1/deployments/* routes."""

    @pytest.mark.asyncio
    async def test_create_deployment_invalid_firmware(
        self, client: AsyncClient, admin_token: str
    ) -> None:
        """Creating a deployment with a non-existent firmware ID must return 404."""
        resp = await client.post(
            "/api/v1/deployments/",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"firmware_id": "nonexistent", "name": "Test Deployment"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_list_deployments(self, client: AsyncClient, admin_token: str) -> None:
        """Admin must be able to list all deployments."""
        resp = await client.get(
            "/api/v1/deployments/",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    @pytest.mark.asyncio
    async def test_get_deployment_not_found(self, client: AsyncClient, admin_token: str) -> None:
        resp = await client.get(
            "/api/v1/deployments/nonexistent",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 404


# ── Audit endpoints ───────────────────────────────────────────────────────────

class TestAuditEndpoints:
    @pytest.mark.asyncio
    async def test_list_audit_logs_requires_admin(
        self, client: AsyncClient, device_token: str
    ) -> None:
        """Non-admin tokens must be forbidden from viewing audit logs."""
        resp = await client.get(
            "/api/v1/audit/",
            headers={"Authorization": f"Bearer {device_token}"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_list_audit_logs_admin_ok(
        self, client: AsyncClient, admin_token: str
    ) -> None:
        resp = await client.get(
            "/api/v1/audit/",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)
