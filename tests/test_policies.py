import pytest

from app.domain.errors import AuthorizationError
from app.domain.models import Principal, PrincipalKind
from app.domain.policies import (
    OPERATIONS_WRITE,
    SERVICE_JOBS_WRITE,
    TENANT_RESOURCES_READ,
    enforce_policy,
)


def principal(
    *,
    kind: PrincipalKind = PrincipalKind.USER,
    client_id: str = "command-center",
    tenant_id: str | None = "tenant-alpha",
    roles: frozenset[str] = frozenset({"viewer"}),
    scopes: frozenset[str] = frozenset({"resources:read"}),
) -> Principal:
    return Principal(
        subject="principal-123",
        kind=kind,
        client_id=client_id,
        username="principal",
        tenant_id=tenant_id,
        roles=roles,
        scopes=scopes,
        token_id=None,
        session_id="session-123",
    )


def test_tenant_policy_accepts_matching_tenant() -> None:
    enforce_policy(
        principal(),
        TENANT_RESOURCES_READ,
        tenant_id="tenant-alpha",
    )


def test_tenant_policy_rejects_cross_tenant_access() -> None:
    with pytest.raises(AuthorizationError):
        enforce_policy(
            principal(),
            TENANT_RESOURCES_READ,
            tenant_id="tenant-beta",
        )


def test_platform_admin_can_cross_tenant_boundary() -> None:
    enforce_policy(
        principal(roles=frozenset({"platform-admin"})),
        TENANT_RESOURCES_READ,
        tenant_id="tenant-beta",
    )


def test_operation_requires_both_role_and_scope() -> None:
    with pytest.raises(AuthorizationError):
        enforce_policy(
            principal(
                roles=frozenset({"operator"}),
                scopes=frozenset(),
            ),
            OPERATIONS_WRITE,
        )


def test_service_policy_rejects_user_with_service_role() -> None:
    with pytest.raises(AuthorizationError):
        enforce_policy(
            principal(
                roles=frozenset({"service-executor"}),
                scopes=frozenset({"jobs:write"}),
            ),
            SERVICE_JOBS_WRITE,
        )


def test_service_policy_accepts_trusted_client_credentials() -> None:
    enforce_policy(
        principal(
            kind=PrincipalKind.SERVICE,
            client_id="automation-service",
            tenant_id="platform",
            roles=frozenset({"service-executor"}),
            scopes=frozenset({"jobs:write"}),
        ),
        SERVICE_JOBS_WRITE,
    )
