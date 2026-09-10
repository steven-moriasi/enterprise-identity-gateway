from collections.abc import Callable
from datetime import UTC, datetime

import jwt
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from app.core.config import Settings
from app.domain.errors import AuthenticationError
from app.infrastructure.jwks import JwksCache
from app.infrastructure.tokens import TokenHeader

BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


class LogoutTokenClaims(BaseModel):
    model_config = ConfigDict(extra="ignore")

    iss: str
    aud: str | list[str]
    iat: int
    jti: str = Field(min_length=1, max_length=255)
    events: dict[str, dict[str, object]]
    sid: str | None = None
    sub: str | None = None
    nonce: str | None = None

    @model_validator(mode="after")
    def validate_logout_event(self) -> "LogoutTokenClaims":
        if BACKCHANNEL_LOGOUT_EVENT not in self.events:
            raise ValueError("Back-channel logout event is missing")
        if self.sid is None and self.sub is None:
            raise ValueError("Back-channel logout subject is missing")
        if self.nonce is not None:
            raise ValueError("Back-channel logout token cannot contain a nonce")
        return self


class LogoutTokenValidator:
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

    def validate(self, token: str) -> LogoutTokenClaims:
        if len(token.encode()) > self._settings.max_token_bytes:
            raise AuthenticationError("Logout token exceeds the configured limit")
        header = self._parse_header(token)
        if header.alg != "RS256":
            raise AuthenticationError("Logout token algorithm is not allowed")
        key = self._jwks.get(header.kid)
        try:
            decoded = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                audience=self._settings.backchannel_logout_audience,
                issuer=self._settings.issuer_url,
                leeway=self._settings.allowed_clock_skew_seconds,
                options={
                    "require": ["iss", "aud", "iat", "jti", "events"],
                    "verify_exp": False,
                },
            )
            claims = LogoutTokenClaims.model_validate(decoded)
        except (jwt.PyJWTError, ValidationError) as error:
            raise AuthenticationError("Logout token is invalid") from error
        age = self._now().timestamp() - claims.iat
        if age < -self._settings.allowed_clock_skew_seconds:
            raise AuthenticationError("Logout token was issued in the future")
        if age > self._settings.backchannel_logout_max_age_seconds:
            raise AuthenticationError("Logout token is too old")
        return claims

    @staticmethod
    def _parse_header(token: str) -> TokenHeader:
        try:
            return TokenHeader.model_validate(jwt.get_unverified_header(token))
        except (jwt.PyJWTError, ValidationError) as error:
            raise AuthenticationError("Logout token header is invalid") from error
