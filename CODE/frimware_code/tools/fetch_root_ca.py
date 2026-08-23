#!/usr/bin/env python3
"""
Emit the root CA that a host's TLS certificate chains to, formatted for
pasting into ota_config.h as OTA_ROOT_CA.

The ESP32 pins a single root. Cloudflare rotates issuers (Let's Encrypt,
Google Trust Services, ...), so the right root is whatever *your* hostname
actually chains to today — read it from the live endpoint rather than
guessing.

Usage:
    python fetch_root_ca.py gw.nyx-ctf.tech
    python fetch_root_ca.py gw.nyx-ctf.tech --out root_ca.h

Requires: pip install cryptography certifi
"""

from __future__ import annotations

import argparse
import socket
import ssl
import sys


def load_chain(host: str, port: int) -> list:
    """Return the certificate chain the server presents, leaf first."""
    from cryptography import x509

    context = ssl.create_default_context()
    # We want to read the chain even if we cannot verify it locally, so that
    # this still works when the local trust store is the thing that's wrong.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            try:
                der_chain = tls.get_verified_chain()
            except AttributeError:
                der_chain = None
            if der_chain:
                return [x509.load_der_x509_certificate(c) for c in der_chain]

            # Python < 3.10 has no get_verified_chain(); fall back to the leaf.
            der = tls.getpeercert(binary_form=True)
            if not der:
                raise SystemExit(f'{host}:{port} presented no certificate.')
            return [x509.load_der_x509_certificate(der)]


def find_root(chain: list):
    """Return the self-signed root for `chain`, from the system trust bundle."""
    from cryptography import x509

    top = chain[-1]
    if top.subject == top.issuer:
        return top  # server sent the root itself

    try:
        import certifi
    except ImportError:
        raise SystemExit('certifi is required to resolve the root: pip install certifi')

    with open(certifi.where(), 'rb') as bundle:
        blobs = bundle.read().split(b'-----END CERTIFICATE-----')

    for blob in blobs:
        pem = blob + b'-----END CERTIFICATE-----'
        if b'-----BEGIN CERTIFICATE-----' not in pem:
            continue
        try:
            candidate = x509.load_pem_x509_certificate(pem)
        except Exception:
            continue
        if candidate.subject == top.issuer:
            return candidate

    raise SystemExit(
        f'Could not find the root for issuer {top.issuer.rfc4514_string()} in the '
        'certifi bundle. Download it from your CA and paste it in manually.'
    )


def as_c_literal(pem: str) -> str:
    body = pem.strip()
    return 'static const char OTA_ROOT_CA[] PROGMEM = R"CERT(\n' + body + '\n)CERT";\n'


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('host', help='hostname, e.g. gw.nyx-ctf.tech')
    parser.add_argument('--port', type=int, default=443)
    parser.add_argument('--out', help='write to this file instead of stdout')
    args = parser.parse_args()

    from cryptography.hazmat.primitives import serialization

    chain = load_chain(args.host, args.port)
    leaf = chain[0]
    root = find_root(chain)

    pem = root.public_bytes(serialization.Encoding.PEM).decode('ascii')
    literal = as_c_literal(pem)

    print(f'# leaf   : {leaf.subject.rfc4514_string()}', file=sys.stderr)
    print(f'# expires: {getattr(leaf, "not_valid_after_utc", None) or leaf.not_valid_after}', file=sys.stderr)
    print(f'# root   : {root.subject.rfc4514_string()}', file=sys.stderr)
    print(f'# root exp: {getattr(root, "not_valid_after_utc", None) or root.not_valid_after}', file=sys.stderr)

    if args.out:
        with open(args.out, 'w', encoding='ascii') as handle:
            handle.write(literal)
        print(f'# written to {args.out}', file=sys.stderr)
    else:
        print(literal)

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
