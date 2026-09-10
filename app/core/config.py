from functools import lru_cache

from pydantic import Field, SecretStr
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
    internal_shared_secret: SecretStr = SecretStr("local-internal-secret")
    jwks_cache_seconds: int = Field(default=300, ge=5, le=86400)
    allowed_clock_skew_seconds: int = Field(default=30, ge=0, le=300)
    request_timeout_seconds: float = Field(default=5, ge=0.1, le=30)


@lru_cache
def get_settings() -> Settings:
    return Settings()
