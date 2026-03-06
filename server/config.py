"""Configuration management using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "Secure OTA Update Server"
    app_version: str = "1.0.0"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"

    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 4
    reload: bool = False

    # Database
    database_url: str = "postgresql+asyncpg://ota:ota_password@localhost:5432/ota_db"
    database_pool_size: int = 10
    database_max_overflow: int = 20
    database_echo: bool = False

    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Security - JWT
    jwt_secret_key: str = "CHANGE_THIS_TO_A_SECURE_RANDOM_SECRET_KEY_IN_PRODUCTION"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # Security - TLS
    tls_cert_file: str = ""
    tls_key_file: str = ""
    tls_ca_file: str = ""

    # Security - Signing Keys
    firmware_signing_key_path: str = "keys/firmware_signing_key.pem"
    firmware_verify_key_path: str = "keys/firmware_verify_key.pem"

    # CORS
    allowed_origins: list[str] = ["https://localhost:3000"]
    allowed_methods: list[str] = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    allowed_headers: list[str] = ["Authorization", "Content-Type", "X-Request-ID"]

    # Rate Limiting
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60
    rate_limit_firmware_upload: int = 10

    # Firmware Storage
    firmware_upload_dir: str = "uploads/firmware"
    firmware_max_size_mb: int = 64
    firmware_allowed_extensions: list[str] = [".bin", ".hex", ".fw"]

    # Deployment
    deployment_default_stages: list[int] = [1, 5, 25, 100]
    deployment_rollback_threshold_percent: float = 5.0

    # Admin
    admin_username: str = "admin"
    admin_password_hash: str = ""

    @field_validator("firmware_upload_dir")
    @classmethod
    def create_upload_dir(cls, v: str) -> str:
        """Ensure firmware upload directory exists."""
        Path(v).mkdir(parents=True, exist_ok=True)
        return v

    @property
    def is_production(self) -> bool:
        """Check if running in production."""
        return self.environment == "production"

    @property
    def firmware_max_size_bytes(self) -> int:
        """Maximum firmware size in bytes."""
        return self.firmware_max_size_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings singleton."""
    return Settings()
