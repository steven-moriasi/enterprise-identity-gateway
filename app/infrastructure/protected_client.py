from functools import lru_cache

import httpx

from app.core.config import get_settings
from app.core.metrics import UPSTREAM_REQUESTS
from app.domain.schemas import ResourceListResponse


class ProtectedServiceUnavailableError(Exception):
    """The protected resource service did not return a valid response."""


class ProtectedServiceClient:
    def __init__(
        self,
        base_url: str,
        timeout_seconds: float,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        self._client = client or httpx.Client(
            base_url=base_url,
            timeout=timeout_seconds,
        )

    def tenant_resources(
        self,
        tenant_id: str,
        *,
        access_token: str,
        correlation_id: str,
    ) -> ResourceListResponse:
        try:
            response = self._client.get(
                f"/internal/tenants/{tenant_id}/resources",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "X-Correlation-ID": correlation_id,
                },
            )
            response.raise_for_status()
            result = ResourceListResponse.model_validate(response.json())
        except (httpx.HTTPError, ValueError) as error:
            UPSTREAM_REQUESTS.labels(outcome="failed").inc()
            raise ProtectedServiceUnavailableError(
                "Protected service is unavailable"
            ) from error
        UPSTREAM_REQUESTS.labels(outcome="succeeded").inc()
        return result


@lru_cache
def get_protected_service_client() -> ProtectedServiceClient:
    settings = get_settings()
    return ProtectedServiceClient(
        settings.upstream_url,
        settings.request_timeout_seconds,
    )
