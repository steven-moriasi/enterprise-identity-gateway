from datetime import datetime, timedelta

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.config import Settings
from app.domain.errors import AuthenticationError, IdentityProviderUnavailableError
from app.domain.models import PrincipalKind
from app.infrastructure.jwks import JwksCache
from app.infrastructure.tokens import TokenValidator
from tests.support import TokenIssuer, public_jwk


def test_valid_token_builds_typed_principal(
    validator: TokenValidator,
    issuer: TokenIssuer,
) -> None:
    token = issuer.issue(
        roles=("operator",),
        scopes=("resources:read", "operations:write"),
    )

    principal = validator.validate(token)

    assert principal.subject == "user-123"
    assert principal.kind == PrincipalKind.USER
    assert principal.tenant_id == "tenant-alpha"
    assert principal.roles == frozenset({"operator"})
    assert principal.scopes == frozenset({"resources:read", "operations:write"})


def test_client_credentials_token_builds_service_principal(
    validator: TokenValidator,
    issuer: TokenIssuer,
) -> None:
    token = issuer.issue(
        subject="service-account-automation-service",
        client_id="automation-service",
        roles=("service-executor",),
        scopes=("jobs:write",),
        tenant_id="platform",
    )

    principal = validator.validate(token)

    assert principal.kind == PrincipalKind.SERVICE
    assert principal.client_id == "automation-service"


def test_rejects_wrong_issuer(
    validator: TokenValidator,
    issuer: TokenIssuer,
) -> None:
    with pytest.raises(AuthenticationError):
        validator.validate(
            issuer.issue(
                issuer="https://attacker.example.test/realms/enterprise",
            )
        )


def test_rejects_wrong_audience(
    validator: TokenValidator,
    issuer: TokenIssuer,
) -> None:
    with pytest.raises(AuthenticationError):
        validator.validate(issuer.issue(audience="another-api"))


def test_rejects_non_access_token(
    validator: TokenValidator,
    issuer: TokenIssuer,
) -> None:
    with pytest.raises(AuthenticationError):
        validator.validate(issuer.issue(credential_kind="ID"))


def test_rejects_expired_token(
    validator: TokenValidator,
    issuer: TokenIssuer,
) -> None:
    with pytest.raises(AuthenticationError):
        validator.validate(issuer.issue(expires_delta=timedelta(seconds=-1)))


def test_rejects_token_older_than_gateway_limit(
    validator: TokenValidator,
    issuer: TokenIssuer,
) -> None:
    with pytest.raises(AuthenticationError):
        validator.validate(
            issuer.issue(
                issued_delta=timedelta(minutes=-16),
                expires_delta=timedelta(minutes=1),
            )
        )


def test_rejects_algorithm_confusion_before_jwks_lookup(
    validator: TokenValidator,
    now: datetime,
) -> None:
    token = jwt.encode(
        {
            "sub": "user-123",
            "iss": "https://identity.example.test/realms/enterprise",
            "aud": "identity-gateway",
            "exp": int((now + timedelta(minutes=5)).timestamp()),
            "iat": int(now.timestamp()),
            "typ": "Bearer",
            "azp": "command-center",
        },
        "attacker-controlled-secret",
        algorithm="HS256",
        headers={"kid": "primary"},
    )

    with pytest.raises(AuthenticationError):
        validator.validate(token)


def test_unknown_kid_forces_bounded_rotation_refresh(
    settings: Settings,
    signing_key: rsa.RSAPrivateKey,
    now: datetime,
) -> None:
    rotated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        key = signing_key if requests == 1 else rotated_key
        kid = "primary" if requests == 1 else "rotated"
        return httpx.Response(200, json={"keys": [public_jwk(key, kid)]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    cache = JwksCache(
        url=settings.jwks_url,
        cache_seconds=300,
        unknown_kid_refresh_seconds=30,
        timeout_seconds=1,
        client=client,
    )
    validator = TokenValidator(settings, cache, now=lambda: now)
    cache.ensure_available()
    token = TokenIssuer(rotated_key, kid="rotated", now=now).issue()

    principal = validator.validate(token)

    assert principal.subject == "user-123"
    assert requests == 2
    cache.close()


def test_unavailable_identity_provider_fails_closed(
    settings: Settings,
    issuer: TokenIssuer,
    now: datetime,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    cache = JwksCache(
        url=settings.jwks_url,
        cache_seconds=300,
        unknown_kid_refresh_seconds=30,
        timeout_seconds=1,
        client=client,
    )
    validator = TokenValidator(settings, cache, now=lambda: now)

    with pytest.raises(IdentityProviderUnavailableError):
        validator.validate(issuer.issue())

    cache.close()
