from collections.abc import Iterator
from datetime import UTC, datetime

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import Settings
from app.infrastructure.jwks import JwksCache
from app.infrastructure.tokens import TokenValidator
from tests.support import TokenIssuer, public_jwk


@pytest.fixture(scope="session")
def signing_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        issuer_url="https://identity.example.test/realms/enterprise",
        jwks_url="https://identity.example.test/jwks",
        audience="identity-gateway",
        client_id="identity-gateway",
        max_access_token_age_seconds=900,
        allowed_clock_skew_seconds=0,
    )


@pytest.fixture
def issuer(signing_key: rsa.RSAPrivateKey, now: datetime) -> TokenIssuer:
    return TokenIssuer(signing_key, now=now)


@pytest.fixture
def validator(
    settings: Settings,
    signing_key: rsa.RSAPrivateKey,
    now: datetime,
) -> Iterator[TokenValidator]:
    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == settings.jwks_url
        return httpx.Response(
            200,
            json={"keys": [public_jwk(signing_key, "primary")]},
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    cache = JwksCache(
        url=settings.jwks_url,
        cache_seconds=settings.jwks_cache_seconds,
        unknown_kid_refresh_seconds=settings.unknown_kid_refresh_seconds,
        timeout_seconds=settings.request_timeout_seconds,
        client=client,
    )
    yield TokenValidator(settings, cache, now=lambda: now)
    cache.close()
