"""PKI certificate generation, validation, and fingerprint extraction."""

import hashlib
import logging
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

logger = logging.getLogger(__name__)

CERT_VALIDITY_DAYS_CA = 3650  # 10 years
CERT_VALIDITY_DAYS_DEVICE = 365  # 1 year
CERT_VALIDITY_DAYS_SERVER = 825  # ~2.25 years (Apple limit)


def generate_self_signed_ca(
    common_name: str,
    org: str = "OTA Framework",
    country: str = "US",
    validity_days: int = CERT_VALIDITY_DAYS_CA,
) -> tuple[bytes, bytes]:
    """Generate a self-signed CA certificate and private key.

    Args:
        common_name: CA common name (CN field).
        org: Organisation name.
        country: Two-letter country code.
        validity_days: Certificate validity period in days.

    Returns:
        Tuple of (ca_cert_pem, ca_key_pem).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False
        )
        .sign(private_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def generate_device_certificate(
    device_id: str,
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    validity_days: int = CERT_VALIDITY_DAYS_DEVICE,
) -> tuple[bytes, bytes]:
    """Generate a device client certificate signed by the CA.

    Args:
        device_id: Unique device identifier (used as CN).
        ca_cert_pem: PEM-encoded CA certificate.
        ca_key_pem: PEM-encoded CA private key.
        validity_days: Certificate validity period.

    Returns:
        Tuple of (device_cert_pem, device_key_pem).
    """
    device_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "OTA Device"),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(device_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(device_id)]), critical=False
        )
        .sign(ca_key, hashes.SHA256())  # type: ignore[arg-type]
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = device_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def get_certificate_fingerprint(cert_pem: bytes) -> str:
    """Return the SHA-256 fingerprint of a PEM certificate as a hex string.

    Args:
        cert_pem: PEM-encoded X.509 certificate.

    Returns:
        Colon-separated uppercase SHA-256 fingerprint (e.g., "AB:CD:...").
    """
    cert = x509.load_pem_x509_certificate(cert_pem)
    digest = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in digest)


def validate_certificate(
    cert_pem: bytes,
    ca_cert_pem: bytes,
) -> bool:
    """Validate that a certificate was signed by the given CA.

    Args:
        cert_pem: PEM-encoded certificate to validate.
        ca_cert_pem: PEM-encoded CA certificate.

    Returns:
        True if the certificate is valid and within its validity window.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

        now = datetime.now(UTC)
        if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
            logger.warning("Certificate is outside its validity window")
            return False

        ca_public_key = ca_cert.public_key()
        if isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),  # type: ignore[arg-type]
            )
        elif isinstance(ca_public_key, rsa.RSAPublicKey):
            from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                asym_padding.PKCS1v15(),
                cert.signature_hash_algorithm,  # type: ignore[arg-type]
            )
        else:
            logger.warning("Unsupported CA key type: %s", type(ca_public_key))
            return False

        return True
    except Exception as exc:
        logger.warning("Certificate validation failed: %s", exc)
        return False


def generate_csr(
    common_name: str,
    org: str = "OTA Framework",
) -> tuple[bytes, bytes]:
    """Generate a Certificate Signing Request (CSR).

    Args:
        common_name: CSR common name.
        org: Organisation name.

    Returns:
        Tuple of (csr_pem, private_key_pem).
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                ]
            )
        )
        .sign(private_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    return csr_pem, key_pem


def sign_csr(
    csr_pem: bytes,
    ca_cert_pem: bytes,
    ca_key_pem: bytes,
    validity_days: int = CERT_VALIDITY_DAYS_DEVICE,
) -> bytes:
    """Sign a CSR with the CA to produce a signed certificate.

    Args:
        csr_pem: PEM-encoded CSR.
        ca_cert_pem: PEM-encoded CA certificate.
        ca_key_pem: PEM-encoded CA private key.
        validity_days: Signed certificate validity in days.

    Returns:
        PEM-encoded signed certificate.
    """
    csr = x509.load_pem_x509_csr(csr_pem)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())  # type: ignore[arg-type]
    )
    return cert.public_bytes(serialization.Encoding.PEM)
