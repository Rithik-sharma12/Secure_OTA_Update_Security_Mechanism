"""Device provisioning helpers: certificate issuance and credential packaging."""

import json
import os
from pathlib import Path


def provision_device(
    device_id: str,
    cert_dir: str,
    output_dir: str,
    server_url: str,
) -> dict:
    """Provision a new device by issuing a certificate and generating a config bundle.

    Creates:
    - A device certificate signed by the CA (via CertificateManager).
    - A JSON provisioning bundle containing connection parameters.

    Args:
        device_id:   Unique device identifier.
        cert_dir:    Directory containing the CA certificate and key.
        output_dir:  Directory to write the device credentials.
        server_url:  OTA server base URL to embed in the bundle.

    Returns:
        Dictionary with provisioning details including cert path and fingerprint.

    Raises:
        FileNotFoundError: If the CA has not been bootstrapped in cert_dir.
    """
    from security.certificate_manager import CertificateManager

    manager = CertificateManager(cert_dir)
    cert_path, key_path, fingerprint = manager.issue_device_certificate(device_id)

    out_dir = Path(output_dir) / device_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # Copy cert and key into the device output directory
    device_cert = out_dir / "device_cert.pem"
    device_key = out_dir / "device_key.pem"
    device_cert.write_bytes(Path(cert_path).read_bytes())
    device_key.write_bytes(Path(key_path).read_bytes())
    device_key.chmod(0o600)

    # Copy CA cert for server verification
    ca_cert_dest = out_dir / "ca_cert.pem"
    ca_cert_dest.write_bytes(manager.get_ca_certificate())

    bundle = {
        "device_id": device_id,
        "server_url": server_url,
        "certificate_fingerprint": fingerprint,
        "cert_file": "device_cert.pem",
        "key_file": "device_key.pem",
        "ca_file": "ca_cert.pem",
    }
    bundle_path = out_dir / "provisioning.json"
    bundle_path.write_text(json.dumps(bundle, indent=2))

    return {
        "device_id": device_id,
        "cert_path": str(device_cert),
        "key_path": str(device_key),
        "fingerprint": fingerprint,
        "bundle_path": str(bundle_path),
    }


def generate_device_config_header(device_id: str, provisioning_dir: str) -> str:
    """Generate a C header file embedding device credentials for firmware build.

    Args:
        device_id:         Device identifier.
        provisioning_dir:  Directory containing the provisioning bundle.

    Returns:
        String content of the generated C header.

    Raises:
        FileNotFoundError: If provisioning bundle is missing.
    """
    prov_path = Path(provisioning_dir) / device_id / "provisioning.json"
    if not prov_path.exists():
        raise FileNotFoundError(f"Provisioning bundle not found: {prov_path}")

    bundle = json.loads(prov_path.read_text())
    cert_pem = (Path(provisioning_dir) / device_id / bundle["cert_file"]).read_text()
    ca_pem = (Path(provisioning_dir) / device_id / bundle["ca_file"]).read_text()

    # Escape PEM strings for embedding in C
    def c_string_escape(s: str) -> str:
        return s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n\"\n    \"")

    header = f"""/**
 * @file device_credentials.h
 * @brief Auto-generated device credentials for {device_id}.
 * DO NOT commit this file to version control.
 */

#ifndef DEVICE_CREDENTIALS_H
#define DEVICE_CREDENTIALS_H

#define DEVICE_ID "{device_id}"
#define OTA_SERVER_URL "{bundle['server_url']}"

static const char DEVICE_CERT_PEM[] =
    "{c_string_escape(cert_pem.strip())}\\n";

static const char CA_CERT_PEM[] =
    "{c_string_escape(ca_pem.strip())}\\n";

#endif /* DEVICE_CREDENTIALS_H */
"""
    return header
