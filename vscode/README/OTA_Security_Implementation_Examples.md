# OTA Security Implementation Code Examples

## 1. Firmware Signature Verification (Python)

### RSA-SHA256 Signature Verification

```python
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

class FirmwareSignatureVerifier:
    def __init__(self, public_key_path):
        """Initialize with public key path"""
        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    def verify_firmware(self, firmware_path, signature_path):
        """Verify firmware signature"""
        # Read firmware binary
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()

        # Read signature
        with open(signature_path, 'rb') as f:
            signature = f.read()

        # Compute SHA-256 hash
        firmware_hash = hashlib.sha256(firmware_data).digest()

        try:
            # Verify signature
            self.public_key.verify(
                signature,
                firmware_hash,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            print("✓ Signature verification successful")
            return True
        except Exception as e:
            print(f"✗ Signature verification failed: {e}")
            return False

    def get_firmware_hash(self, firmware_path):
        """Get SHA-256 hash of firmware"""
        with open(firmware_path, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()


# Usage Example
verifier = FirmwareSignatureVerifier('public_key.pem')
is_valid = verifier.verify_firmware('firmware.bin', 'firmware.bin.sig')
print(f"Firmware Hash: {verifier.get_firmware_hash('firmware.bin')}")
```

### EdDSA (Ed25519) Signature Verification

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.backends import default_backend
import hashlib

class FirmwareEdDSAVerifier:
    def __init__(self, public_key_path):
        """Initialize with Ed25519 public key"""
        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )

    def verify_firmware(self, firmware_path, signature_path):
        """Verify firmware with Ed25519 signature"""
        with open(firmware_path, 'rb') as f:
            firmware_data = f.read()

        with open(signature_path, 'rb') as f:
            signature = f.read()

        try:
            self.public_key.verify(signature, firmware_data)
            print("✓ EdDSA signature verification successful")
            return True
        except Exception as e:
            print(f"✗ EdDSA signature verification failed: {e}")
            return False


# Generate Ed25519 key pair
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Save keys
with open('ed25519_private.pem', 'wb') as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'password')
    ))
```

---

## 2. AES-256-GCM Encryption for Firmware

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
import os

class FirmwareEncryption:
    def __init__(self):
        self.key_size = 32  # 256-bit
        self.nonce_size = 12  # 96-bit (GCM recommendation)

    def derive_key(self, password, salt=None):
        """Derive AES-256 key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=100000,  # Minimum recommended
        )

        key = kdf.derive(password.encode() if isinstance(password, str) else password)
        return key, salt

    def encrypt_firmware(self, firmware_path, output_path, password):
        """Encrypt firmware with AES-256-GCM"""
        # Read firmware
        with open(firmware_path, 'rb') as f:
            plaintext = f.read()

        # Derive key
        key, salt = self.derive_key(password)

        # Generate random nonce
        nonce = os.urandom(self.nonce_size)

        # Encrypt with GCM (provides authentication)
        cipher = AESGCM(key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)

        # Write: salt + nonce + ciphertext
        with open(output_path, 'wb') as f:
            f.write(salt)
            f.write(nonce)
            f.write(ciphertext)

        print(f"✓ Firmware encrypted: {output_path}")
        print(f"  Salt (hex): {salt.hex()}")
        print(f"  Nonce (hex): {nonce.hex()}")
        print(f"  Ciphertext size: {len(ciphertext)} bytes")

        return salt, nonce, len(ciphertext)

    def decrypt_firmware(self, encrypted_path, output_path, password):
        """Decrypt firmware"""
        # Read encrypted file
        with open(encrypted_path, 'rb') as f:
            salt = f.read(16)
            nonce = f.read(12)
            ciphertext = f.read()

        # Derive key
        key, _ = self.derive_key(password, salt)

        try:
            # Decrypt
            cipher = AESGCM(key)
            plaintext = cipher.decrypt(nonce, ciphertext, None)

            # Write decrypted firmware
            with open(output_path, 'wb') as f:
                f.write(plaintext)

            print(f"✓ Firmware decrypted: {output_path}")
            return True
        except Exception as e:
            print(f"✗ Decryption failed: {e}")
            return False


# Usage Example
enc = FirmwareEncryption()
enc.encrypt_firmware('firmware.bin', 'firmware.bin.enc', 'secure_password')
enc.decrypt_firmware('firmware.bin.enc', 'firmware.bin.dec', 'secure_password')
```

---

## 3. Device Certificate Generation

```python
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from datetime import datetime, timedelta
import uuid

class DeviceCertificateGenerator:
    def __init__(self, ca_cert_path, ca_key_path, ca_key_password=None):
        """Initialize with CA certificate and key"""
        with open(ca_cert_path, 'rb') as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read())

        with open(ca_key_path, 'rb') as f:
            key_data = f.read()
            self.ca_key = serialization.load_pem_private_key(
                key_data,
                password=ca_key_password.encode() if ca_key_password else None
            )

    def generate_device_certificate(self, device_id=None, model=None,
                                   hardware_version=None, output_dir='./'):
        """Generate a device certificate"""
        if device_id is None:
            device_id = str(uuid.uuid4())

        # Generate RSA key pair (2048-bit minimum for devices)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"device-{device_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "YourOrg"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(self.ca_cert.subject)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.utcnow())
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365*3))

        # Add extensions
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )

        # Add custom extensions for device metadata
        device_metadata = f"DeviceID={device_id}|Model={model}|HWVer={hardware_version}"
        builder = builder.add_extension(
            x509.UnrecognizedExtension(
                oid=x509.ObjectIdentifier((1, 3, 6, 1, 4, 1, 99999, 1)),
                value=device_metadata.encode()
            ),
            critical=False,
        )

        # Sign certificate
        cert = builder.sign(
            private_key=self.ca_key,
            algorithm=hashes.SHA256(),
        )

        # Save certificate and key
        cert_path = f"{output_dir}/device-{device_id}-cert.pem"
        key_path = f"{output_dir}/device-{device_id}-key.pem"

        with open(cert_path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b'device_password')
            ))

        print(f"✓ Device certificate generated:")
        print(f"  Device ID: {device_id}")
        print(f"  Certificate: {cert_path}")
        print(f"  Private Key: {key_path}")

        return cert, private_key, device_id


# Usage Example
gen = DeviceCertificateGenerator('ca-cert.pem', 'ca-key.pem', 'ca_password')
cert, key, device_id = gen.generate_device_certificate(
    model="model-x",
    hardware_version="rev_c"
)
```

---

## 4. TLS Configuration for Firmware Download

```python
import ssl
import socket
from urllib.request import urlopen

class SecureFirmwareDownloader:
    def __init__(self, ca_cert_path, client_cert_path, client_key_path):
        """Initialize secure downloader with certificates"""
        self.ca_cert_path = ca_cert_path
        self.client_cert_path = client_cert_path
        self.client_key_path = client_key_path

    def create_ssl_context(self):
        """Create TLS 1.3 context with security settings"""
        context = ssl.create_default_context()

        # TLS 1.3 minimum
        context.minimum_version = ssl.TLSVersion.TLSv1_3

        # Load CA certificate for server verification
        context.load_verify_locations(self.ca_cert_path)

        # Load client certificate for mutual TLS
        context.load_cert_chain(
            certfile=self.client_cert_path,
            keyfile=self.client_key_path,
            password=lambda: b'device_password'
        )

        # Strong cipher suites only
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20')

        # Enable certificate pinning (optional)
        # context.check_hostname = True
        # context.verify_mode = ssl.CERT_REQUIRED

        return context

    def download_firmware(self, url, output_path,
                         chunk_size=8192, timeout=30):
        """Download firmware with resumable capability"""
        context = self.create_ssl_context()

        try:
            # Check for resume capability
            req = urllib.request.Request(url)
            req.add_header('Range', 'bytes=0-0')

            with urlopen(req, context=context, timeout=timeout) as response:
                supports_range = response.headers.get('Accept-Ranges') == 'bytes'

            # Download with resume support
            bytes_downloaded = 0

            with urlopen(url, context=context, timeout=timeout) as response:
                with open(output_path, 'wb') as f:
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        bytes_downloaded += len(chunk)

            print(f"✓ Firmware downloaded: {output_path}")
            print(f"  Bytes downloaded: {bytes_downloaded}")
            return True

        except Exception as e:
            print(f"✗ Download failed: {e}")
            return False

    def pin_certificate(self, certificate_hash):
        """Pin certificate by SHA-256 hash"""
        # This would be implemented in a subclass
        # Stores expected certificate hash for verification
        self.pinned_hash = certificate_hash


# Usage Example
downloader = SecureFirmwareDownloader(
    ca_cert_path='ca-cert.pem',
    client_cert_path='device-cert.pem',
    client_key_path='device-key.pem'
)
downloader.download_firmware(
    url='https://updates.example.com/firmware/v2.1.5.bin',
    output_path='firmware.bin'
)
```

---

## 5. JWT Device Authentication

```python
import jwt
import json
from datetime import datetime, timedelta
import uuid

class JWTDeviceAuth:
    def __init__(self, private_key_path, public_key_path, algorithm='RS256'):
        """Initialize JWT handler with device keys"""
        with open(private_key_path, 'rb') as f:
            self.private_key = f.read()

        with open(public_key_path, 'rb') as f:
            self.public_key = f.read()

        self.algorithm = algorithm

    def generate_device_token(self, device_id, device_model, scope='firmware:download'):
        """Generate JWT token for device authentication"""
        now = datetime.utcnow()

        payload = {
            'device_id': device_id,
            'device_model': device_model,
            'iat': int(now.timestamp()),
            'exp': int((now + timedelta(hours=1)).timestamp()),
            'nonce': str(uuid.uuid4()),
            'scope': scope,
            'version': '2.0.1'
        }

        token = jwt.encode(
            payload,
            self.private_key,
            algorithm=self.algorithm
        )

        return token

    def verify_device_token(self, token):
        """Verify JWT token from device"""
        try:
            payload = jwt.decode(
                token,
                self.public_key,
                algorithms=[self.algorithm]
            )

            # Verify expiration
            if payload['exp'] < datetime.utcnow().timestamp():
                print("✗ Token expired")
                return None

            print("✓ Token verified successfully")
            return payload

        except jwt.InvalidTokenError as e:
            print(f"✗ Token verification failed: {e}")
            return None


# Usage Example
auth = JWTDeviceAuth('device-key.pem', 'device-cert.pem')

# Generate token
token = auth.generate_device_token(
    device_id='device-uuid-12345',
    device_model='model-x'
)
print(f"Generated token: {token}")

# Verify token
payload = auth.verify_device_token(token)
if payload:
    print(f"Device ID: {payload['device_id']}")
    print(f"Scope: {payload['scope']}")
```

---

## 6. Rollback Protection (Monotonic Counter)

```python
import struct
import hashlib

class RollbackProtection:
    def __init__(self, counter_file='rollback_counter.bin'):
        """Initialize rollback protection"""
        self.counter_file = counter_file
        self.counter = self.load_counter()

    def load_counter(self):
        """Load monotonic counter from storage"""
        try:
            with open(self.counter_file, 'rb') as f:
                data = f.read(8)
                if len(data) == 8:
                    return struct.unpack('>Q', data)[0]  # Big-endian 64-bit
        except:
            pass
        return 0

    def save_counter(self, value):
        """Save counter to non-volatile storage"""
        with open(self.counter_file, 'wb') as f:
            f.write(struct.pack('>Q', value))

    def verify_update(self, manifest):
        """Verify update manifest against rollback protection"""
        manifest_version = manifest.get('version')
        manifest_counter = manifest.get('counter')
        manifest_timestamp = manifest.get('timestamp')

        # Verify sequence number
        if manifest_counter <= self.counter:
            print(f"✗ Rollback attempt detected!")
            print(f"  Current counter: {self.counter}")
            print(f"  Manifest counter: {manifest_counter}")
            return False

        # Verify version is greater than current
        if manifest_version <= self.load_current_version():
            print(f"✗ Version downgrade detected: {manifest_version}")
            return False

        print("✓ Rollback protection check passed")
        return True

    def commit_update(self, new_counter):
        """Commit update and increment counter"""
        self.counter = new_counter
        self.save_counter(new_counter)
        print(f"✓ Counter incremented to: {new_counter}")

    def load_current_version(self):
        """Load current firmware version"""
        # This would read from device firmware header
        return 202  # Version 2.0.1 as integer


# Usage Example
rollback_protection = RollbackProtection()

manifest = {
    'version': '2.1.5',
    'counter': 42,
    'timestamp': '2026-03-06T10:30:00Z'
}

if rollback_protection.verify_update(manifest):
    # Installation successful
    rollback_protection.commit_update(42)
```

---

## 7. Firmware Hash Verification

```python
import hashlib
import hmac

class FirmwareIntegrity:
    def __init__(self):
        self.hash_algorithm = hashlib.sha256

    def compute_hash(self, firmware_path):
        """Compute SHA-256 hash of firmware"""
        hash_obj = self.hash_algorithm()

        with open(firmware_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hash_obj.update(chunk)

        return hash_obj.hexdigest()

    def compute_hmac(self, firmware_path, secret_key):
        """Compute HMAC-SHA256 for firmware authentication"""
        hmac_obj = hmac.new(
            secret_key.encode() if isinstance(secret_key, str) else secret_key,
            digestmod=self.hash_algorithm
        )

        with open(firmware_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                hmac_obj.update(chunk)

        return hmac_obj.hexdigest()

    def verify_firmware_integrity(self, firmware_path, expected_hash):
        """Verify firmware hash matches expected value"""
        computed_hash = self.compute_hash(firmware_path)

        if computed_hash.lower() == expected_hash.lower():
            print(f"✓ Firmware integrity verified")
            print(f"  Hash: {computed_hash}")
            return True
        else:
            print(f"✗ Firmware integrity check failed!")
            print(f"  Expected: {expected_hash}")
            print(f"  Computed: {computed_hash}")
            return False

    def create_manifest_hash(self, manifest_dict):
        """Create hash of update manifest"""
        manifest_json = json.dumps(manifest_dict, sort_keys=True)
        return self.hash_algorithm(manifest_json.encode()).hexdigest()


# Usage Example
import json
integrity = FirmwareIntegrity()

# Compute hash
firmware_hash = integrity.compute_hash('firmware.bin')
print(f"Firmware SHA-256: {firmware_hash}")

# Verify integrity
manifest = {
    'version': '2.1.5',
    'hash': firmware_hash,
    'size': 2097152
}

integrity.verify_firmware_integrity('firmware.bin', firmware_hash)

# Create manifest hash
manifest_hash = integrity.create_manifest_hash(manifest)
print(f"Manifest hash: {manifest_hash}")
```

---

## 8. Device Provisioning (Zero-Touch)

```python
import requests
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

class ZeroTouchProvisioning:
    def __init__(self, provisioning_server_url, ca_cert_path):
        """Initialize ZTP client"""
        self.server_url = provisioning_server_url
        self.ca_cert_path = ca_cert_path

    def get_device_info(self):
        """Get device metadata for provisioning"""
        return {
            'mac_address': '00:1A:2B:3C:4D:5E',  # From NIC
            'serial_number': 'DEVICE-SN-12345',  # From OTP/Secure storage
            'model': 'model-x',
            'hardware_version': 'rev_c',
            'firmware_version': '1.0.0'
        }

    def request_certificate(self):
        """Request device certificate from provisioning server"""
        device_info = self.get_device_info()

        # Generate temporary CSR (Certificate Signing Request)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        csr_data = {
            'device_info': device_info,
            'public_key': private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }

        try:
            response = requests.post(
                f"{self.server_url}/api/v1/provision/certificate",
                json=csr_data,
                verify=self.ca_cert_path,
                timeout=30
            )

            if response.status_code == 200:
                cert_response = response.json()

                # Save certificate and key
                with open('device-cert.pem', 'wb') as f:
                    f.write(cert_response['certificate'].encode())

                with open('device-key.pem', 'wb') as f:
                    f.write(private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))

                print("✓ Certificate provisioned successfully")
                return True
            else:
                print(f"✗ Provisioning failed: {response.status_code}")
                return False

        except Exception as e:
            print(f"✗ Provisioning error: {e}")
            return False


# Usage Example
provisioner = ZeroTouchProvisioning(
    provisioning_server_url='https://provision.example.com',
    ca_cert_path='ca-cert.pem'
)
provisioner.request_certificate()
```

---

## 9. OTA Update State Machine

```python
from enum import Enum
from datetime import datetime

class UpdateState(Enum):
    IDLE = "idle"
    CHECKING = "checking"
    DOWNLOADING = "downloading"
    VERIFYING = "verifying"
    STAGING = "staging"
    INSTALLING = "installing"
    VALIDATING = "validating"
    SUCCESS = "success"
    FAILED = "failed"
    ROLLBACK = "rollback"

class OTAUpdateStateMachine:
    def __init__(self):
        self.current_state = UpdateState.IDLE
        self.previous_state = None
        self.error_message = None
        self.timestamps = {}
        self.firmware_path = None

    def transition(self, new_state):
        """Transition to new state"""
        self.previous_state = self.current_state
        self.current_state = new_state
        self.timestamps[new_state] = datetime.utcnow()

        print(f"State transition: {self.previous_state.value} → {new_state.value}")

        # Log state transition
        self._log_transition()

    def check_for_updates(self):
        """Check for available updates"""
        self.transition(UpdateState.CHECKING)
        # Query update server
        return {'version': '2.1.5', 'available': True}

    def download_firmware(self):
        """Download firmware"""
        if self.current_state != UpdateState.CHECKING:
            self.set_error("Invalid state for download")
            return False

        self.transition(UpdateState.DOWNLOADING)
        # Perform download
        return True

    def verify_firmware(self):
        """Verify firmware signature and hash"""
        if self.current_state != UpdateState.DOWNLOADING:
            self.set_error("Invalid state for verification")
            return False

        self.transition(UpdateState.VERIFYING)
        # Perform verification
        return True

    def stage_firmware(self):
        """Stage firmware in inactive partition"""
        if self.current_state != UpdateState.VERIFYING:
            self.set_error("Invalid state for staging")
            return False

        self.transition(UpdateState.STAGING)
        # Copy to inactive partition
        return True

    def install_firmware(self):
        """Install staged firmware"""
        if self.current_state != UpdateState.STAGING:
            self.set_error("Invalid state for installation")
            return False

        self.transition(UpdateState.INSTALLING)
        # Switch boot partition
        return True

    def validate_installation(self):
        """Validate installation after boot"""
        if self.current_state != UpdateState.INSTALLING:
            self.set_error("Invalid state for validation")
            return False

        self.transition(UpdateState.VALIDATING)
        # Perform self-checks
        return True

    def mark_success(self):
        """Mark update as successful"""
        if self.current_state != UpdateState.VALIDATING:
            self.set_error("Invalid state for success")
            return False

        self.transition(UpdateState.SUCCESS)
        print("✓ Update completed successfully")
        return True

    def mark_failed(self, error_msg):
        """Mark update as failed"""
        self.error_message = error_msg
        self.transition(UpdateState.FAILED)
        print(f"✗ Update failed: {error_msg}")

    def rollback_firmware(self):
        """Rollback to previous firmware"""
        self.transition(UpdateState.ROLLBACK)
        print("Rolling back to previous firmware version...")
        self.transition(UpdateState.IDLE)

    def set_error(self, error_msg):
        """Set error message"""
        self.error_message = error_msg
        self.transition(UpdateState.FAILED)

    def _log_transition(self):
        """Log state transition for audit trail"""
        log_entry = {
            'timestamp': self.timestamps[self.current_state].isoformat(),
            'from_state': self.previous_state.value,
            'to_state': self.current_state.value,
            'error': self.error_message
        }
        print(f"Audit: {json.dumps(log_entry)}")

    def get_status(self):
        """Get current update status"""
        return {
            'state': self.current_state.value,
            'previous_state': self.previous_state.value if self.previous_state else None,
            'error': self.error_message,
            'progress_timestamps': {
                k.value: v.isoformat()
                for k, v in self.timestamps.items()
            }
        }


# Usage Example
ota_state = OTAUpdateStateMachine()

try:
    ota_state.check_for_updates()
    ota_state.download_firmware()
    ota_state.verify_firmware()
    ota_state.stage_firmware()
    ota_state.install_firmware()
    ota_state.validate_installation()
    ota_state.mark_success()
except Exception as e:
    ota_state.mark_failed(str(e))
    ota_state.rollback_firmware()

print(json.dumps(ota_state.get_status(), indent=2))
```

---

## 10. Audit Logging

```python
import json
import logging
from datetime import datetime
from pathlib import Path

class OTAAuditLogger:
    def __init__(self, log_file='ota_audit.log'):
        """Initialize audit logger"""
        self.log_file = log_file
        self.setup_logger()

    def setup_logger(self):
        """Setup structured logging"""
        self.logger = logging.getLogger('OTA_Audit')
        self.logger.setLevel(logging.DEBUG)

        handler = logging.FileHandler(self.log_file)
        handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)

    def log_update_event(self, event_type, device_id, device_model,
                         firmware_version, status, details=None):
        """Log OTA update event"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'device_id': device_id,
            'device_model': device_model,
            'firmware_version': firmware_version,
            'status': status,
            'details': details or {}
        }

        self.logger.info(json.dumps(event))

    def log_security_event(self, event_type, device_id, severity,
                          reason, ip_address=None):
        """Log security-related event"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': f'SECURITY_{event_type}',
            'device_id': device_id,
            'severity': severity,
            'reason': reason,
            'ip_address': ip_address,
            'anonymized': True
        }

        self.logger.warning(json.dumps(event))

    def log_signature_verification(self, device_id, firmware_hash,
                                  signature_valid, key_id):
        """Log signature verification result"""
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': 'SIGNATURE_VERIFICATION',
            'device_id': device_id,
            'firmware_hash': firmware_hash,
            'signature_valid': signature_valid,
            'key_id': key_id
        }

        self.logger.info(json.dumps(event))


# Usage Example
audit_logger = OTAAuditLogger()

audit_logger.log_update_event(
    event_type='UPDATE_CHECK',
    device_id='device-uuid-12345',
    device_model='model-x',
    firmware_version='2.0.1',
    status='success',
    details={'available_version': '2.1.5'}
)

audit_logger.log_security_event(
    event_type='UNAUTHORIZED_ACCESS',
    device_id='device-uuid-67890',
    severity='high',
    reason='Invalid certificate',
    ip_address='192.168.x.x'
)

audit_logger.log_signature_verification(
    device_id='device-uuid-12345',
    firmware_hash='abc123def456...',
    signature_valid=True,
    key_id='prod-signing-key-2026'
)
```

---

**Code Examples Repository**
These examples provide starting points for implementing OTA security.
All code should be thoroughly tested and reviewed before production deployment.
