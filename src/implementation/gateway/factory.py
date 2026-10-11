"""
SentinelOTA Edge Gateway — Factory (first-flash) images

A board fresh out of the box has no bootloader and no partition table, so the
OTA app image a release serves cannot bring it up: written over USB at 0x10000
it never boots, and a secure release is an encrypted package that would put
ciphertext in flash. The first flash needs a *factory image*: bootloader,
partition table, boot_app0 and the plain app merged into one file written at
0x0 (`esptool merge_bin`, as go-online.sh build and the release workflow do).

A release may carry one. It is bound to the release by digest: in a merged
image the bytes from APP_OFFSET to the end are exactly the app image, so their
SHA-256 must equal the release's plaintext image digest (`imageSha256`). That
proves the board starts life on the same build the release's OTA package
carries, and that nobody attached the factory image of another version.

The factory image is plain firmware. It is never listed in a device manifest
and is served only to operators (see routes/releases.py), because a secure
release's OTA package exists precisely so the image is not handed out in the
clear.
"""

from __future__ import annotations

import hashlib

APP_OFFSET = 0x10000
ESP_IMAGE_MAGIC = 0xE9
MAX_FACTORY_BYTES = 16 * 1024 * 1024

# Where the second-stage bootloader sits: 0x1000 on the original ESP32, 0x0 on
# the S2/S3/C3 families. A merged image starts at 0x0 either way.
BOOTLOADER_OFFSETS = (0x1000, 0x0)


class FactoryImageError(ValueError):
    """The file is not a factory image for this release."""


def app_digest(factory: bytes) -> str:
    """SHA-256 of the app region, comparable with a release's imageSha256."""
    return hashlib.sha256(factory[APP_OFFSET:]).hexdigest()


def validate_factory_image(factory: bytes, image_sha256: str | None) -> dict[str, object]:
    """Check shape and binding; return the record stored on the release.

    `image_sha256` is the release's plaintext app digest. It is required: a
    factory image that cannot be tied to the release is refused rather than
    published on trust.
    """
    if not image_sha256:
        raise FactoryImageError(
            'The release has no plaintext image digest (imageSha256), so the factory image '
            'cannot be tied to it. Publish the release with imageSha256.'
        )
    if len(factory) <= APP_OFFSET + 1:
        raise FactoryImageError(
            f'Factory image is {len(factory)} bytes; a merged image has the app at '
            f'0x{APP_OFFSET:x}, so it must be larger than that.'
        )
    if len(factory) > MAX_FACTORY_BYTES:
        raise FactoryImageError(f'Factory image exceeds {MAX_FACTORY_BYTES // (1024 * 1024)} MB.')
    if factory[APP_OFFSET] != ESP_IMAGE_MAGIC:
        raise FactoryImageError(
            f'No ESP application image at 0x{APP_OFFSET:x}. Upload the merged image '
            '(firmware-full.bin from esptool merge_bin), not the app firmware.bin.'
        )
    if not any(factory[offset] == ESP_IMAGE_MAGIC for offset in BOOTLOADER_OFFSETS):
        raise FactoryImageError(
            'No bootloader at 0x1000 or 0x0. Upload the merged image that starts at 0x0.'
        )

    digest = app_digest(factory)
    if digest != image_sha256.lower():
        raise FactoryImageError(
            'The app inside the factory image is not this release: its SHA-256 '
            f'({digest}) differs from the release imageSha256 ({image_sha256.lower()}).'
        )

    return {
        'sha256': hashlib.sha256(factory).hexdigest(),
        'size': len(factory),
        'appSha256': digest,
    }
