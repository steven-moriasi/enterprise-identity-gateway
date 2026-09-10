from typing import Annotated
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from app.core.metrics import AUTHENTICATIONS
from app.domain.errors import AuthenticationError, IdentityProviderUnavailableError
from app.infrastructure.auth import (
    get_logout_token_validator,
    get_revocation_registry,
)
from app.infrastructure.logout_tokens import LogoutTokenValidator
from app.infrastructure.revocation import RevocationRegistry

router = APIRouter(tags=["identity"])


@router.post("/oidc/backchannel-logout", status_code=status.HTTP_200_OK)
async def backchannel_logout(
    request: Request,
    validator: Annotated[
        LogoutTokenValidator,
        Depends(get_logout_token_validator),
    ],
    revocations: Annotated[
        RevocationRegistry,
        Depends(get_revocation_registry),
    ],
) -> Response:
    content_type = request.headers.get("Content-Type", "").split(";", maxsplit=1)[0]
    body = await request.body()
    if content_type != "application/x-www-form-urlencoded" or len(body) > 65536:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Valid logout token required",
        )
    token = parse_qs(body.decode(errors="replace")).get("logout_token", [""])[0]
    try:
        claims = validator.validate(token)
    except IdentityProviderUnavailableError as error:
        AUTHENTICATIONS.labels(outcome="idp_unavailable").inc()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Identity provider is unavailable",
        ) from error
    except AuthenticationError as error:
        AUTHENTICATIONS.labels(outcome="invalid_logout").inc()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Valid logout token required",
        ) from error
    revocations.revoke(session_id=claims.sid, subject=claims.sub)
    AUTHENTICATIONS.labels(outcome="session_revoked").inc()
    return Response(status_code=status.HTTP_200_OK)
