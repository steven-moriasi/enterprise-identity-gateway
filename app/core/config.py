from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="IDENTITY_GATEWAY_",
        extra="ignore",
    )

    environment: str = "development"
    issuer_url: str = "http://localhost:8080/realms/enterprise"
    jwks_url: str = (
        "http://localhost:8080/realms/enterprise/protocol/openid-connect/certs"
    )
    audience: str = "identity-gateway"
    client_id: str = "identity-gateway"
    upstream_url: str = "http://localhost:8001"
    jwks_cache_seconds: int = Field(default=300, ge=5, le=86400)
    unknown_kid_refresh_seconds: int = Field(default=30, ge=1, le=3600)
    allowed_clock_skew_seconds: int = Field(default=30, ge=0, le=300)
    max_access_token_age_seconds: int = Field(default=900, ge=60, le=86400)
    max_token_bytes: int = Field(default=16384, ge=1024, le=65536)
    request_timeout_seconds: float = Field(default=5, ge=0.1, le=30)
    service_client_ids: frozenset[str] = frozenset({"automation-service"})
    allowed_origins: list[str] = ["http://localhost:3000"]
    backchannel_logout_audience: str = "command-center"
    backchannel_logout_max_age_seconds: int = Field(default=120, ge=30, le=600)


@lru_cache
def get_settings() -> Settings:
    return Settings()
