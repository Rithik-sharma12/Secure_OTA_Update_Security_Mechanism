"""TLS configuration helpers for the Secure OTA server."""

import logging
import ssl
from pathlib import Path

logger = logging.getLogger(__name__)


def create_ssl_context(
    cert_file: str,
    key_file: str,
    ca_file: str | None = None,
    verify_client: bool = False,
) -> ssl.SSLContext:
    """Build an SSLContext for uvicorn / httpx with strong cipher settings.

    Args:
        cert_file: Path to the server TLS certificate (PEM).
        key_file: Path to the server TLS private key (PEM).
        ca_file: Optional path to the CA bundle for client verification.
        verify_client: If True, require and verify client certificates (mTLS).

    Returns:
        Configured ssl.SSLContext.

    Raises:
        FileNotFoundError: If cert_file or key_file do not exist.
    """
    for path in (cert_file, key_file):
        if not Path(path).exists():
            raise FileNotFoundError(f"TLS file not found: {path}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)

    # Restrict to strong cipher suites only (TLS 1.3 + selected 1.2)
    ctx.set_ciphers(
        "TLS_AES_256_GCM_SHA384:"
        "TLS_CHACHA20_POLY1305_SHA256:"
        "TLS_AES_128_GCM_SHA256:"
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-AES256-GCM-SHA384"
    )

    if ca_file:
        ctx.load_verify_locations(cafile=ca_file)
        if verify_client:
            ctx.verify_mode = ssl.CERT_REQUIRED
            logger.info("mTLS client verification enabled")

    return ctx


def create_client_ssl_context(
    ca_file: str | None = None,
    cert_file: str | None = None,
    key_file: str | None = None,
    verify_server: bool = True,
) -> ssl.SSLContext:
    """Build an SSLContext for outbound HTTPS / mTLS connections.

    Args:
        ca_file: Optional path to a custom CA bundle.
        cert_file: Optional path to client certificate for mTLS.
        key_file: Optional path to client private key for mTLS.
        verify_server: If False, disable server certificate verification (dev only).

    Returns:
        Configured ssl.SSLContext.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    if not verify_server:
        logger.warning("Server certificate verification is DISABLED – development only")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        if ca_file:
            ctx.load_verify_locations(cafile=ca_file)
        else:
            ctx.load_default_certs()

    if cert_file and key_file:
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
        logger.info("mTLS client certificate loaded from %s", cert_file)

    return ctx


def get_tls_info() -> dict[str, str]:
    """Return information about the supported TLS configuration.

    Returns:
        Dictionary with TLS version and cipher information.
    """
    return {
        "min_version": "TLSv1.2",
        "preferred_version": "TLSv1.3",
        "openssl_version": ssl.OPENSSL_VERSION,
    }
