"""Certificate lifecycle management: CA bootstrap, device provisioning, renewal."""

import logging
from datetime import UTC, datetime
from pathlib import Path

from server.security.pki import (
    generate_device_certificate,
    generate_self_signed_ca,
    get_certificate_fingerprint,
    sign_csr,
    validate_certificate,
)

logger = logging.getLogger(__name__)


class CertificateManager:
    """Manages the OTA PKI hierarchy.

    Responsibilities:
    - Bootstrap a self-signed root CA for the OTA infrastructure.
    - Issue device client certificates signed by the CA.
    - Validate device certificates and extract fingerprints.
    - Sign externally-generated CSRs for bring-your-own-key scenarios.
    """

    def __init__(self, cert_dir: str) -> None:
        self._cert_dir = Path(cert_dir)
        self._cert_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._ca_cert_path = self._cert_dir / "ca_cert.pem"
        self._ca_key_path = self._cert_dir / "ca_key.pem"

    def bootstrap_ca(
        self,
        common_name: str = "OTA Update CA",
        org: str = "OTA Framework",
        country: str = "US",
        force: bool = False,
    ) -> tuple[str, str]:
        """Create the root CA certificate and private key.

        Args:
            common_name: CA certificate CN field.
            org: Organisation name.
            country: Two-letter country code.
            force: Overwrite existing CA if True.

        Returns:
            Tuple of (ca_cert_path, ca_key_path).

        Raises:
            FileExistsError: If CA already exists and force=False.
        """
        if self._ca_cert_path.exists() and not force:
            raise FileExistsError(
                f"CA already exists at {self._ca_cert_path}. Use force=True to overwrite."
            )

        cert_pem, key_pem = generate_self_signed_ca(common_name, org, country)
        self._ca_cert_path.write_bytes(cert_pem)
        self._ca_cert_path.chmod(0o644)
        self._ca_key_path.write_bytes(key_pem)
        self._ca_key_path.chmod(0o600)

        logger.info("CA bootstrapped: %s", self._ca_cert_path)
        return str(self._ca_cert_path), str(self._ca_key_path)

    def issue_device_certificate(
        self,
        device_id: str,
        validity_days: int = 365,
    ) -> tuple[str, str, str]:
        """Issue a device certificate signed by the CA.

        Args:
            device_id: Unique device identifier (used as CN).
            validity_days: Certificate validity period.

        Returns:
            Tuple of (cert_path, key_path, fingerprint).

        Raises:
            FileNotFoundError: If the CA has not been bootstrapped.
        """
        self._require_ca()
        ca_cert_pem = self._ca_cert_path.read_bytes()
        ca_key_pem = self._ca_key_path.read_bytes()

        cert_pem, key_pem = generate_device_certificate(
            device_id, ca_cert_pem, ca_key_pem, validity_days
        )
        fingerprint = get_certificate_fingerprint(cert_pem)

        device_dir = self._cert_dir / "devices"
        device_dir.mkdir(exist_ok=True)
        cert_path = device_dir / f"{device_id}_cert.pem"
        key_path = device_dir / f"{device_id}_key.pem"

        cert_path.write_bytes(cert_pem)
        cert_path.chmod(0o644)
        key_path.write_bytes(key_pem)
        key_path.chmod(0o600)

        logger.info("Device certificate issued: %s (fingerprint: %s)", device_id, fingerprint[:16])
        return str(cert_path), str(key_path), fingerprint

    def sign_device_csr(self, csr_pem: bytes, validity_days: int = 365) -> tuple[bytes, str]:
        """Sign a device-generated CSR with the CA.

        Args:
            csr_pem: PEM-encoded CSR.
            validity_days: Signed certificate validity.

        Returns:
            Tuple of (signed_cert_pem, fingerprint).
        """
        self._require_ca()
        ca_cert_pem = self._ca_cert_path.read_bytes()
        ca_key_pem = self._ca_key_path.read_bytes()
        cert_pem = sign_csr(csr_pem, ca_cert_pem, ca_key_pem, validity_days)
        fingerprint = get_certificate_fingerprint(cert_pem)
        return cert_pem, fingerprint

    def validate_device_certificate(self, cert_pem: bytes) -> tuple[bool, str]:
        """Validate a device certificate against the CA.

        Args:
            cert_pem: PEM-encoded device certificate.

        Returns:
            Tuple of (is_valid, fingerprint).
        """
        self._require_ca()
        ca_cert_pem = self._ca_cert_path.read_bytes()
        valid = validate_certificate(cert_pem, ca_cert_pem)
        fingerprint = get_certificate_fingerprint(cert_pem) if valid else ""
        return valid, fingerprint

    def get_ca_certificate(self) -> bytes:
        """Return the CA certificate PEM bytes.

        Raises:
            FileNotFoundError: If CA has not been bootstrapped.
        """
        self._require_ca()
        return self._ca_cert_path.read_bytes()

    def _require_ca(self) -> None:
        if not self._ca_cert_path.exists() or not self._ca_key_path.exists():
            raise FileNotFoundError(
                "CA not found. Run bootstrap_ca() first."
            )
