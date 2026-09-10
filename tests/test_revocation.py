from datetime import datetime, timedelta

import pytest

from app.core.config import Settings
from app.domain.errors import AuthenticationError
from app.infrastructure.jwks import JwksCache
from app.infrastructure.logout_tokens import LogoutTokenValidator
from app.infrastructure.revocation import RevocationRegistry
from app.infrastructure.tokens import TokenValidator
from tests.support import TokenIssuer


def test_logout_token_revokes_matching_access_token(
    settings: Settings,
    jwks: JwksCache,
    issuer: TokenIssuer,
    now: datetime,
) -> None:
    revocations = RevocationRegistry(retention_seconds=900)
    validator_with_revocation = TokenValidator(
        settings,
        jwks,
        revocations,
        now=lambda: now,
    )
    logout_validator = LogoutTokenValidator(
        settings,
        jwks,
        now=lambda: now,
    )
    logout = logout_validator.validate(issuer.issue_logout())
    revocations.revoke(session_id=logout.sid, subject=logout.sub)

    with pytest.raises(AuthenticationError):
        validator_with_revocation.validate(issuer.issue())


@pytest.mark.parametrize(
    "token",
    [
        "missing-event",
        "nonce",
        "old",
        "wrong-audience",
    ],
)
def test_logout_token_rejects_invalid_security_boundary(
    token: str,
    settings: Settings,
    jwks: JwksCache,
    issuer: TokenIssuer,
    now: datetime,
) -> None:
    logout_validator = LogoutTokenValidator(
        settings,
        jwks,
        now=lambda: now,
    )
    candidates = {
        "missing-event": issuer.issue_logout(include_event=False),
        "nonce": issuer.issue_logout(nonce="not-allowed"),
        "old": issuer.issue_logout(issued_delta=timedelta(minutes=-3)),
        "wrong-audience": issuer.issue_logout(audience="another-client"),
    }

    with pytest.raises(AuthenticationError):
        logout_validator.validate(candidates[token])


def test_revocation_entries_expire() -> None:
    current = 100.0
    registry = RevocationRegistry(
        retention_seconds=60,
        monotonic=lambda: current,
    )
    registry.revoke(session_id="session-123", subject=None)
    assert registry.is_revoked(session_id="session-123", subject="user-123")

    current = 161.0

    assert not registry.is_revoked(session_id="session-123", subject="user-123")
