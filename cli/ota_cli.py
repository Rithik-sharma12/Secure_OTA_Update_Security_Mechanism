"""Click-based CLI tool for the Secure OTA Update Framework."""

import json
import sys
from pathlib import Path
from typing import Optional

import click
import requests
from rich.console import Console
from rich.table import Table

console = Console()


def _get_auth_headers(server: str, token: str | None) -> dict[str, str]:
    """Return Authorization header dict, prompting for token if not supplied."""
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def _api(
    method: str,
    server: str,
    path: str,
    token: str | None = None,
    **kwargs: object,
) -> requests.Response:
    """Perform an authenticated API request."""
    url = f"{server.rstrip('/')}{path}"
    headers = _get_auth_headers(server, token)
    resp = requests.request(method, url, headers=headers, timeout=60, **kwargs)  # type: ignore[arg-type]
    return resp


# ── Root group ──────────────────────────────────────────────────────────────

@click.group()
@click.version_option(version="1.0.0")
def cli() -> None:
    """Secure OTA Update Framework CLI.

    Manage firmware, devices, deployments, and signing keys.
    """


# ── firmware group ───────────────────────────────────────────────────────────

@cli.group()
def firmware() -> None:
    """Firmware management commands."""


@firmware.command("build")
@click.argument("binary", type=click.Path(exists=True, dir_okay=False))
@click.option("--version", required=True, help="Semantic version (e.g. 1.2.3)")
@click.option("--platform", required=True, help="Target platform (e.g. esp32)")
@click.option("--min-counter", default=0, show_default=True, help="Anti-rollback counter")
@click.option("--output", "-o", default=None, help="Output bundle path (.fw)")
def firmware_build(
    binary: str, version: str, platform: str, min_counter: int, output: Optional[str]
) -> None:
    """Build an OTA firmware bundle from a raw binary."""
    from cli.firmware_builder import build_firmware_bundle

    try:
        meta = build_firmware_bundle(binary, version, platform, min_counter, output)
        console.print(f"[green]✓[/green] Bundle created: {meta['path']}")
        console.print(f"  SHA-256  : {meta['hash_sha256']}")
        console.print(f"  Size     : {meta['bundle_size']:,} bytes")
        console.print(f"  Version  : {meta['version']}")
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


@firmware.command("sign")
@click.argument("bundle", type=click.Path(exists=True, dir_okay=False))
@click.option("--key", "-k", required=True, type=click.Path(exists=True), help="RSA private key PEM")
@click.option("--output", "-o", default=None, help="Output signature file (.sig)")
def firmware_sign(bundle: str, key: str, output: Optional[str]) -> None:
    """Sign a firmware bundle with an RSA private key."""
    from base64 import b64encode

    from server.security.crypto import sign_rsa_sha256

    try:
        data = Path(bundle).read_bytes()
        private_key_pem = Path(key).read_bytes()
        signature = sign_rsa_sha256(private_key_pem, data)
        sig_b64 = b64encode(signature).decode()

        sig_path = output or (bundle + ".sig")
        Path(sig_path).write_text(sig_b64)
        console.print(f"[green]✓[/green] Signature written to: {sig_path}")
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


@firmware.command("verify")
@click.argument("bundle", type=click.Path(exists=True, dir_okay=False))
@click.option("--sig", "-s", required=True, type=click.Path(exists=True), help="Signature file (.sig)")
@click.option("--key", "-k", required=True, type=click.Path(exists=True), help="RSA public key PEM")
def firmware_verify(bundle: str, sig: str, key: str) -> None:
    """Verify a firmware bundle's signature."""
    from base64 import b64decode

    from server.security.crypto import verify_rsa_sha256_signature

    try:
        data = Path(bundle).read_bytes()
        public_key_pem = Path(key).read_bytes()
        signature = b64decode(Path(sig).read_text().strip())
        valid = verify_rsa_sha256_signature(public_key_pem, data, signature)
        if valid:
            console.print("[green]✓ Signature valid[/green]")
        else:
            console.print("[red]✗ Signature INVALID[/red]")
            sys.exit(1)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


@firmware.command("upload")
@click.argument("bundle", type=click.Path(exists=True, dir_okay=False))
@click.option("--sig", "-s", required=True, type=click.Path(exists=True), help="Signature file (.sig)")
@click.option("--version", required=True, help="Firmware version string")
@click.option("--platform", required=True, help="Target platform")
@click.option("--server", "-S", envvar="OTA_SERVER", default="http://localhost:8000", show_default=True)
@click.option("--token", "-t", envvar="OTA_TOKEN", default=None, help="JWT access token")
def firmware_upload(
    bundle: str, sig: str, version: str, platform: str, server: str, token: Optional[str]
) -> None:
    """Upload a firmware bundle to the OTA server."""
    try:
        sig_b64 = Path(sig).read_text().strip()
        with open(bundle, "rb") as f:
            resp = _api(
                "POST",
                server,
                "/api/v1/firmware/upload",
                token=token,
                files={"file": (Path(bundle).name, f, "application/octet-stream")},
                data={"version": version, "platform": platform, "signature_b64": sig_b64},
            )
        if resp.status_code == 201:
            data = resp.json()
            console.print(f"[green]✓[/green] Firmware uploaded: {data['id']}")
            console.print(f"  Version: {data['version']} | Platform: {data['platform']}")
        else:
            console.print(f"[red]Upload failed {resp.status_code}:[/red] {resp.text}")
            sys.exit(1)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


# ── device group ─────────────────────────────────────────────────────────────

@cli.group()
def device() -> None:
    """Device management commands."""


@device.command("provision")
@click.argument("device_id")
@click.option("--cert-dir", default="certs", show_default=True, help="CA certificate directory")
@click.option("--output-dir", default="devices", show_default=True, help="Output directory")
@click.option("--server", "-S", envvar="OTA_SERVER", default="http://localhost:8000")
def device_provision(device_id: str, cert_dir: str, output_dir: str, server: str) -> None:
    """Provision a new device (issue certificate and generate config bundle)."""
    from cli.provisioning import provision_device

    try:
        result = provision_device(device_id, cert_dir, output_dir, server)
        console.print(f"[green]✓[/green] Device provisioned: {device_id}")
        console.print(f"  Fingerprint : {result['fingerprint']}")
        console.print(f"  Bundle      : {result['bundle_path']}")
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


@device.command("list")
@click.option("--server", "-S", envvar="OTA_SERVER", default="http://localhost:8000")
@click.option("--token", "-t", envvar="OTA_TOKEN", default=None)
def device_list(server: str, token: Optional[str]) -> None:
    """List registered devices."""
    try:
        resp = _api("GET", server, "/api/v1/devices/", token=token)
        if resp.status_code != 200:
            console.print(f"[red]Error {resp.status_code}:[/red] {resp.text}")
            sys.exit(1)

        devices = resp.json()
        table = Table(title="Registered Devices")
        table.add_column("Device ID", style="cyan")
        table.add_column("Platform")
        table.add_column("Status")
        table.add_column("Version")
        table.add_column("Last Seen")
        for d in devices:
            table.add_row(
                d["device_id"],
                d["platform"],
                d["status"],
                d.get("current_version") or "-",
                (d.get("last_seen") or "-")[:19],
            )
        console.print(table)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


# ── deploy group ─────────────────────────────────────────────────────────────

@cli.group()
def deploy() -> None:
    """Deployment management commands."""


@deploy.command("create")
@click.option("--firmware-id", required=True, help="Firmware UUID")
@click.option("--name", required=True, help="Deployment name")
@click.option("--description", default=None, help="Description")
@click.option("--stages", default="1,5,25,100", show_default=True, help="Comma-separated stage percentages")
@click.option("--platform", default=None, help="Platform filter")
@click.option("--server", "-S", envvar="OTA_SERVER", default="http://localhost:8000")
@click.option("--token", "-t", envvar="OTA_TOKEN", default=None)
def deploy_create(
    firmware_id: str,
    name: str,
    description: Optional[str],
    stages: str,
    platform: Optional[str],
    server: str,
    token: Optional[str],
) -> None:
    """Create a new staged deployment."""
    try:
        stage_list = [int(s.strip()) for s in stages.split(",")]
        payload = {
            "firmware_id": firmware_id,
            "name": name,
            "description": description,
            "deployment_stages": stage_list,
            "platform_filter": platform,
        }
        resp = _api("POST", server, "/api/v1/deployments/", token=token, json=payload)
        if resp.status_code == 201:
            data = resp.json()
            console.print(f"[green]✓[/green] Deployment created: {data['id']}")
            console.print(f"  Name  : {data['name']}")
            console.print(f"  Stages: {data['deployment_stages']}")
        else:
            console.print(f"[red]Error {resp.status_code}:[/red] {resp.text}")
            sys.exit(1)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


@deploy.command("advance")
@click.argument("deployment_id")
@click.option("--server", "-S", envvar="OTA_SERVER", default="http://localhost:8000")
@click.option("--token", "-t", envvar="OTA_TOKEN", default=None)
def deploy_advance(deployment_id: str, server: str, token: Optional[str]) -> None:
    """Advance a deployment to the next stage."""
    try:
        resp = _api("PUT", server, f"/api/v1/deployments/{deployment_id}/advance", token=token)
        if resp.status_code == 200:
            data = resp.json()
            console.print(f"[green]✓[/green] Advanced to stage {data['current_stage_index']}: {data['target_percentage']}%")
        else:
            console.print(f"[red]Error {resp.status_code}:[/red] {resp.text}")
            sys.exit(1)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


@deploy.command("rollback")
@click.argument("deployment_id")
@click.option("--server", "-S", envvar="OTA_SERVER", default="http://localhost:8000")
@click.option("--token", "-t", envvar="OTA_TOKEN", default=None)
def deploy_rollback(deployment_id: str, server: str, token: Optional[str]) -> None:
    """Rollback a deployment."""
    try:
        resp = _api("PUT", server, f"/api/v1/deployments/{deployment_id}/rollback", token=token)
        if resp.status_code == 200:
            console.print(f"[green]✓[/green] Deployment {deployment_id} rolled back")
        else:
            console.print(f"[red]Error {resp.status_code}:[/red] {resp.text}")
            sys.exit(1)
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


# ── keys group ───────────────────────────────────────────────────────────────

@cli.group()
def keys() -> None:
    """Cryptographic key management commands."""


@keys.command("generate")
@click.option("--name", "-n", required=True, help="Key name (used as filename prefix)")
@click.option("--type", "key_type", default="rsa", type=click.Choice(["rsa", "ec"]), show_default=True)
@click.option("--key-size", default=4096, show_default=True, help="RSA key size in bits")
@click.option("--key-dir", default="keys", show_default=True, help="Directory to store keys")
@click.option("--passphrase", default=None, help="Passphrase for private key encryption")
def keys_generate(
    name: str, key_type: str, key_size: int, key_dir: str, passphrase: Optional[str]
) -> None:
    """Generate a new signing key pair."""
    from security.key_management import KeyStore

    try:
        store = KeyStore(key_dir)
        pp = passphrase.encode() if passphrase else None
        if key_type == "ec":
            priv, pub = store.generate_ec_signing_keypair(name, pp)
        else:
            priv, pub = store.generate_rsa_signing_keypair(name, pp, key_size)
        console.print(f"[green]✓[/green] Key pair generated: {name}")
        console.print(f"  Private : {priv}")
        console.print(f"  Public  : {pub}")
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


@keys.command("rotate")
@click.option("--name", "-n", required=True, help="Key name to rotate")
@click.option("--type", "key_type", default="rsa", type=click.Choice(["rsa", "ec"]), show_default=True)
@click.option("--key-dir", default="keys", show_default=True)
@click.option("--passphrase", default=None, help="Passphrase for new private key")
def keys_rotate(name: str, key_type: str, key_dir: str, passphrase: Optional[str]) -> None:
    """Rotate a signing key pair (archives old key, generates new one)."""
    from security.key_management import KeyStore

    try:
        store = KeyStore(key_dir)
        pp = passphrase.encode() if passphrase else None
        priv, pub = store.rotate_key(name, pp, key_type)
        console.print(f"[green]✓[/green] Key rotated: {name}")
        console.print(f"  New private : {priv}")
        console.print(f"  New public  : {pub}")
    except Exception as exc:
        console.print(f"[red]Error:[/red] {exc}")
        sys.exit(1)


if __name__ == "__main__":
    cli()
