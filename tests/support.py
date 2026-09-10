import base64
from datetime import UTC, datetime, timedelta

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from app.infrastructure.logout_tokens import BACKCHANNEL_LOGOUT_EVENT


def base64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def public_jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, str]:
    numbers = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": base64url_uint(numbers.n),
        "e": base64url_uint(numbers.e),
    }


class TokenIssuer:
    def __init__(
        self,
        key: rsa.RSAPrivateKey,
        *,
        kid: str = "primary",
        now: datetime | None = None,
    ) -> None:
        self.key = key
        self.kid = kid
        self.now = now or datetime.now(UTC)

    def issue(
        self,
        *,
        subject: str = "user-123",
        client_id: str = "command-center",
        roles: tuple[str, ...] = ("viewer",),
        scopes: tuple[str, ...] = ("resources:read",),
        tenant_id: str | None = "tenant-alpha",
        issuer: str = "https://identity.example.test/realms/enterprise",
        audience: str = "identity-gateway",
        credential_kind: str = "Bearer",
        issued_delta: timedelta = timedelta(),
        expires_delta: timedelta = timedelta(minutes=5),
        key: rsa.RSAPrivateKey | None = None,
        kid: str | None = None,
    ) -> str:
        issued_at = self.now + issued_delta
        claims: dict[str, object] = {
            "sub": subject,
            "iss": issuer,
            "aud": audience,
            "exp": int((self.now + expires_delta).timestamp()),
            "iat": int(issued_at.timestamp()),
            "nbf": int(issued_at.timestamp()),
            "jti": "token-123",
            "typ": credential_kind,
            "azp": client_id,
            "sid": "session-123",
            "preferred_username": subject,
            "scope": " ".join(scopes),
            "realm_access": {"roles": list(roles)},
            "resource_access": {
                "identity-gateway": {"roles": list(roles)},
            },
        }
        if tenant_id is not None:
            claims["tenant_id"] = tenant_id
        return jwt.encode(
            claims,
            key or self.key,
            algorithm="RS256",
            headers={"kid": kid or self.kid, "typ": "JWT"},
        )

    def issue_logout(
        self,
        *,
        audience: str = "command-center",
        subject: str | None = None,
        session_id: str | None = "session-123",
        issued_delta: timedelta = timedelta(),
        include_event: bool = True,
        nonce: str | None = None,
    ) -> str:
        claims: dict[str, object] = {
            "iss": "https://identity.example.test/realms/enterprise",
            "aud": audience,
            "iat": int((self.now + issued_delta).timestamp()),
            "jti": "logout-123",
            "events": {BACKCHANNEL_LOGOUT_EVENT: {}} if include_event else {},
        }
        if subject is not None:
            claims["sub"] = subject
        if session_id is not None:
            claims["sid"] = session_id
        if nonce is not None:
            claims["nonce"] = nonce
        return jwt.encode(
            claims,
            self.key,
            algorithm="RS256",
            headers={"kid": self.kid, "typ": "logout+jwt"},
        )
