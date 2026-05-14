"""pytest fixtures shared across all test modules."""

import os
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from server.app import create_application
from server.config import Settings, get_settings
from server.database import Base, get_db
from server.security.crypto import generate_rsa_keypair, sign_rsa_sha256, encode_signature_b64

# ── Settings override for tests ──────────────────────────────────────────────

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


def override_settings() -> Settings:
    """Return test-mode settings using an in-memory SQLite database."""
    return Settings(
        database_url=TEST_DATABASE_URL,
        jwt_secret_key="test-secret-key-for-testing-only-not-production",
        environment="development",
        debug=True,
        firmware_upload_dir="/tmp/ota_test_uploads",
        admin_username="admin",
        admin_password_hash="$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # "secret"
    )


# ── Database fixtures ─────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest_asyncio.fixture(scope="function")
async def test_db_engine():
    """Create a fresh in-memory SQLite engine for each test."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(test_db_engine) -> AsyncSession:
    """Yield a database session connected to the test engine."""
    session_factory = async_sessionmaker(test_db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


# ── Application fixtures ──────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="function")
async def client(test_db_engine):
    """Return an async test client wired to the test database."""
    app = create_application()

    # Override settings
    app.dependency_overrides[get_settings] = override_settings

    # Override DB dependency to use in-memory engine
    session_factory = async_sessionmaker(test_db_engine, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as ac:
        yield ac


# ── Cryptographic fixtures ────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def rsa_keypair() -> tuple[bytes, bytes]:
    """Generate a 2048-bit RSA key pair (smaller for test speed)."""
    return generate_rsa_keypair(key_size=2048)


@pytest.fixture(scope="session")
def rsa_private_key(rsa_keypair) -> bytes:
    return rsa_keypair[0]


@pytest.fixture(scope="session")
def rsa_public_key(rsa_keypair) -> bytes:
    return rsa_keypair[1]


@pytest.fixture(scope="session")
def sample_firmware_data() -> bytes:
    """Return a deterministic pseudo-firmware binary for tests."""
    return b"\x00\x01\x02\x03" * 1024 + b"OTA_TEST_FIRMWARE_PAYLOAD_END"


@pytest.fixture(scope="session")
def sample_firmware_signature(rsa_private_key, sample_firmware_data) -> str:
    """Return a valid Base64-encoded RSA-SHA256 signature of the sample firmware."""
    sig = sign_rsa_sha256(rsa_private_key, sample_firmware_data)
    return encode_signature_b64(sig)


@pytest.fixture(scope="function")
def admin_token(client) -> str:
    """Placeholder: return a hard-coded test token (tests mock auth)."""
    from server.security.jwt_handler import create_access_token
    return create_access_token("admin", roles=["admin"])


@pytest.fixture(scope="function")
def device_token() -> str:
    """Return a device JWT for test device 'test-device-001'."""
    from server.security.jwt_handler import create_access_token
    return create_access_token("test-device-001", roles=["device"])
