from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.domain.errors import IdentityProviderUnavailableError
from app.infrastructure.auth import get_jwks_cache
from app.infrastructure.jwks import JwksCache

router = APIRouter(tags=["operations"])


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
def ready(
    jwks: Annotated[JwksCache, Depends(get_jwks_cache)],
) -> dict[str, str]:
    try:
        jwks.ensure_available()
    except IdentityProviderUnavailableError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Identity provider is unavailable",
        ) from error
    return {"status": "ready"}


@router.get("/metrics", include_in_schema=False)
def metrics() -> Response:
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
