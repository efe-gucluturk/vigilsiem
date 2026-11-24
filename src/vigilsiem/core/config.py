"""Typed, validated, fail-closed application settings.

All secrets come from the environment (``VIGIL_*``). There are deliberately NO
defaults for secrets: a missing or weak ``VIGIL_JWT_SECRET`` aborts startup.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_WEAK_PREFIXES = ("changeme", "change-me", "secret", "password", "example", "test")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="VIGIL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        frozen=True,
    )

    # Required secret: no default, so startup fails closed.
    jwt_secret: Annotated[SecretStr, Field(min_length=32, max_length=512)]

    database_url: str = "sqlite+aiosqlite:///./data/vigilsiem.db"
    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    rules_dir: str = "rules"

    # Admin bootstrap (hash only, never a plaintext password).
    admin_username: str = Field(default="admin", min_length=3, max_length=64)
    admin_password_hash: SecretStr | None = None

    # Token / cookie policy.
    jwt_issuer: str = "vigilsiem"
    jwt_audience: str = "vigilsiem-dashboard"
    jwt_ttl_minutes: int = Field(default=30, ge=1, le=1440)
    cookie_secure: bool = True
    cookie_name: str = "vigil_session"

    # Deployment. X-Forwarded-For is IGNORED unless you declare how many trusted proxies
    # sit in front of the app (otherwise any client could spoof its IP past the limiter).
    trusted_proxy_count: int = Field(default=0, ge=0, le=5)
    enable_docs: bool = False  # OpenAPI/Swagger stay off unless explicitly enabled
    webhook_timeout_seconds: float = Field(default=5.0, gt=0, le=15)
    max_webhook_notifications_per_batch: int = Field(default=20, ge=0, le=100)

    # Request hardening.
    max_body_bytes: int = Field(default=512 * 1024, ge=1024, le=512 * 1024)
    max_batch_lines: int = Field(default=500, ge=1, le=5000)
    ingest_rate_per_min: int = Field(default=120, ge=1)
    login_rate_per_min: int = Field(default=5, ge=1)
    admin_rate_per_min: int = Field(default=600, ge=1)  # per authenticated analyst session

    @field_validator("jwt_secret")
    @classmethod
    def _reject_weak_secret(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if raw.lower().startswith(_WEAK_PREFIXES) or len(set(raw)) < 10:
            raise ValueError("jwt_secret is too weak; generate one with secrets.token_urlsafe(48)")
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Load settings once. Raises pydantic.ValidationError if misconfigured."""
    return Settings()  # type: ignore[call-arg]  # values come from the environment
