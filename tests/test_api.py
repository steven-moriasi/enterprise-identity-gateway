from collections.abc import Iterator

import httpx
import pytest
from fastapi.testclient import TestClient

from app.infrastructure.auth import get_token_validator
from app.infrastructure.protected_client import (
    ProtectedServiceClient,
    get_protected_service_client,
)
from app.infrastructure.tokens import TokenValidator
from app.main import app
from tests.support import TokenIssuer


@pytest.fixture
def client(
    validator: TokenValidator,
) -> Iterator[TestClient]:
    def override_validator() -> TokenValidator:
        return validator

    app.dependency_overrides[get_token_validator] = override_validator
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_missing_token_returns_bearer_challenge(client: TestClient) -> None:
    response = client.get("/api/me")

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_profile_returns_normalized_identity(
    client: TestClient,
    issuer: TokenIssuer,
) -> None:
    response = client.get(
        "/api/me",
        headers=authorization(issuer.issue()),
    )

    assert response.status_code == 200
    assert response.json()["tenant_id"] == "tenant-alpha"
    assert response.json()["roles"] == ["viewer"]
    assert "access_token" not in response.text


def test_operation_rejects_missing_scope(
    client: TestClient,
    issuer: TokenIssuer,
) -> None:
    response = client.post(
        "/api/operations",
        headers=authorization(
            issuer.issue(
                roles=("operator",),
                scopes=("resources:read",),
            )
        ),
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Insufficient permissions"}


def test_tenant_resource_is_revalidated_by_protected_service(
    client: TestClient,
    issuer: TokenIssuer,
) -> None:
    seen_authorization = ""
    seen_correlation = ""

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal seen_authorization, seen_correlation
        seen_authorization = request.headers["Authorization"]
        seen_correlation = request.headers["X-Correlation-ID"]
        return httpx.Response(
            200,
            json={
                "resources": [
                    {
                        "id": "tenant-alpha-automation-001",
                        "tenant_id": "tenant-alpha",
                        "state": "active",
                    }
                ]
            },
        )

    upstream_http = httpx.Client(
        transport=httpx.MockTransport(handler),
        base_url="http://protected-service:8001",
    )
    protected_client = ProtectedServiceClient(
        "http://protected-service:8001",
        1,
        client=upstream_http,
    )

    def override_protected_client() -> ProtectedServiceClient:
        return protected_client

    app.dependency_overrides[get_protected_service_client] = override_protected_client
    token = issuer.issue()
    response = client.get(
        "/api/tenants/tenant-alpha/resources",
        headers={
            **authorization(token),
            "X-Correlation-ID": "request-123",
        },
    )

    assert response.status_code == 200
    assert seen_authorization == f"Bearer {token}"
    assert seen_correlation == "request-123"
    assert response.headers["X-Correlation-ID"] == "request-123"
    upstream_http.close()


def test_cross_tenant_request_is_not_forwarded(
    client: TestClient,
    issuer: TokenIssuer,
) -> None:
    response = client.get(
        "/api/tenants/tenant-beta/resources",
        headers=authorization(issuer.issue()),
    )

    assert response.status_code == 403


def test_service_job_requires_client_credentials_identity(
    client: TestClient,
    issuer: TokenIssuer,
) -> None:
    user_response = client.post(
        "/api/service/jobs",
        headers=authorization(
            issuer.issue(
                roles=("service-executor",),
                scopes=("jobs:write",),
            )
        ),
    )
    service_response = client.post(
        "/api/service/jobs",
        headers=authorization(
            issuer.issue(
                subject="service-account-automation-service",
                client_id="automation-service",
                roles=("service-executor",),
                scopes=("jobs:write",),
                tenant_id="platform",
            )
        ),
    )

    assert user_response.status_code == 403
    assert service_response.status_code == 200
    assert service_response.json()["action"] == "service_job.accepted"
