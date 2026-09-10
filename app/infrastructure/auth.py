from dataclasses import dataclass, field
from functools import lru_cache
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.config import Settings, get_settings
from app.core.metrics import AUTHENTICATIONS
from app.domain.errors import AuthenticationError, IdentityProviderUnavailableError
from app.domain.models import Principal
from app.infrastructure.jwks import JwksCache
from app.infrastructure.logout_tokens import LogoutTokenValidator
from app.infrastructure.revocation import RevocationRegistry
from app.infrastructure.tokens import TokenValidator

bearer_scheme = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class IdentityContext:
    principal: Principal
    access_token: str = field(repr=False)


@lru_cache
def get_jwks_cache() -> JwksCache:
    settings = get_settings()
    return JwksCache(
        url=settings.jwks_url,
        cache_seconds=settings.jwks_cache_seconds,
        unknown_kid_refresh_seconds=settings.unknown_kid_refresh_seconds,
        timeout_seconds=settings.request_timeout_seconds,
    )


@lru_cache
def get_revocation_registry() -> RevocationRegistry:
    settings = get_settings()
    return RevocationRegistry(
        retention_seconds=settings.max_access_token_age_seconds,
    )


def get_token_validator(
    settings: Annotated[Settings, Depends(get_settings)],
    jwks: Annotated[JwksCache, Depends(get_jwks_cache)],
    revocations: Annotated[
        RevocationRegistry,
        Depends(get_revocation_registry),
    ],
) -> TokenValidator:
    return TokenValidator(settings, jwks, revocations)


def get_logout_token_validator(
    settings: Annotated[Settings, Depends(get_settings)],
    jwks: Annotated[JwksCache, Depends(get_jwks_cache)],
) -> LogoutTokenValidator:
    return LogoutTokenValidator(settings, jwks)


def authenticate(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
    validator: Annotated[TokenValidator, Depends(get_token_validator)],
) -> IdentityContext:
    if credentials is None or credentials.scheme.lower() != "bearer":
        AUTHENTICATIONS.labels(outcome="missing").inc()
        raise _authentication_error()
    try:
        principal = validator.validate(credentials.credentials)
    except IdentityProviderUnavailableError as error:
        AUTHENTICATIONS.labels(outcome="idp_unavailable").inc()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Identity provider is unavailable",
        ) from error
    except AuthenticationError as error:
        AUTHENTICATIONS.labels(outcome="invalid").inc()
        raise _authentication_error() from error
    AUTHENTICATIONS.labels(outcome="authenticated").inc()
    return IdentityContext(
        principal=principal,
        access_token=credentials.credentials,
    )


def _authentication_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Valid bearer access token required",
        headers={"WWW-Authenticate": "Bearer"},
    )
