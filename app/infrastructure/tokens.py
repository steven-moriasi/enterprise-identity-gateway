from collections.abc import Callable
from datetime import UTC, datetime

import jwt
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.core.config import Settings
from app.domain.errors import AuthenticationError, IdentityProviderUnavailableError
from app.domain.models import Principal, PrincipalKind
from app.infrastructure.jwks import JwksCache


class TokenHeader(BaseModel):
    model_config = ConfigDict(extra="ignore")

    alg: str
    kid: str = Field(min_length=1, max_length=255)


class RealmAccess(BaseModel):
    model_config = ConfigDict(extra="ignore")

    roles: list[str] = Field(default_factory=list)


class ClientAccess(BaseModel):
    model_config = ConfigDict(extra="ignore")

    roles: list[str] = Field(default_factory=list)


class TokenClaims(BaseModel):
    model_config = ConfigDict(extra="ignore")

    sub: str = Field(min_length=1, max_length=255)
    iss: str
    aud: str | list[str]
    exp: int
    iat: int
    nbf: int | None = None
    jti: str | None = None
    typ: str
    azp: str = Field(min_length=1, max_length=255)
    preferred_username: str | None = None
    scope: str = ""
    tenant_id: str | None = None
    realm_access: RealmAccess = Field(default_factory=RealmAccess)
    resource_access: dict[str, ClientAccess] = Field(default_factory=dict)


class TokenValidator:
    def __init__(
        self,
        settings: Settings,
        jwks: JwksCache,
        *,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._settings = settings
        self._jwks = jwks
        self._now = now

    def validate(self, token: str) -> Principal:
        if len(token.encode()) > self._settings.max_token_bytes:
            raise AuthenticationError("Access token exceeds the configured limit")
        header = self._parse_header(token)
        if header.alg != "RS256":
            raise AuthenticationError("Access token algorithm is not allowed")
        key = self._jwks.get(header.kid)
        claims = self._decode(token, key)
        if claims.typ != "Bearer":
            raise AuthenticationError("Only access tokens are accepted")
        if self._now().timestamp() - claims.iat > self._settings.max_access_token_age_seconds:
            raise AuthenticationError("Access token is older than the configured limit")
        return self._principal(claims)

    @staticmethod
    def _parse_header(token: str) -> TokenHeader:
        try:
            return TokenHeader.model_validate(jwt.get_unverified_header(token))
        except (jwt.PyJWTError, ValidationError) as error:
            raise AuthenticationError("Access token header is invalid") from error

    def _decode(self, token: str, key: jwt.PyJWK) -> TokenClaims:
        try:
            decoded = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                audience=self._settings.audience,
                issuer=self._settings.issuer_url,
                leeway=self._settings.allowed_clock_skew_seconds,
                options={"require": ["sub", "iss", "aud", "exp", "iat", "typ", "azp"]},
            )
            return TokenClaims.model_validate(decoded)
        except IdentityProviderUnavailableError:
            raise
        except (jwt.PyJWTError, ValidationError) as error:
            raise AuthenticationError("Access token is invalid") from error

    def _principal(self, claims: TokenClaims) -> Principal:
        client_roles = claims.resource_access.get(self._settings.client_id)
        roles = set(claims.realm_access.roles)
        if client_roles is not None:
            roles.update(client_roles.roles)
        kind = (
            PrincipalKind.SERVICE
            if claims.azp in self._settings.service_client_ids
            else PrincipalKind.USER
        )
        return Principal(
            subject=claims.sub,
            kind=kind,
            client_id=claims.azp,
            username=claims.preferred_username,
            tenant_id=claims.tenant_id,
            roles=frozenset(roles),
            scopes=frozenset(claims.scope.split()),
            token_id=claims.jti,
        )
