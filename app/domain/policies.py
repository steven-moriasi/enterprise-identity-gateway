from dataclasses import dataclass

from app.domain.errors import AuthorizationError
from app.domain.models import Principal, PrincipalKind


@dataclass(frozen=True)
class Policy:
    name: str
    roles_any: frozenset[str] = frozenset()
    scopes_all: frozenset[str] = frozenset()
    kind: PrincipalKind | None = None
    client_ids: frozenset[str] = frozenset()
    tenant_bound: bool = False


OPERATIONS_WRITE = Policy(
    name="operations.write",
    roles_any=frozenset({"operator", "platform-admin"}),
    scopes_all=frozenset({"operations:write"}),
    kind=PrincipalKind.USER,
)
AUDIT_READ = Policy(
    name="audit.read",
    roles_any=frozenset({"auditor", "operator", "platform-admin"}),
    scopes_all=frozenset({"audit:read"}),
    kind=PrincipalKind.USER,
)
TENANT_RESOURCES_READ = Policy(
    name="tenant.resources.read",
    roles_any=frozenset({"viewer", "auditor", "operator", "platform-admin"}),
    scopes_all=frozenset({"resources:read"}),
    kind=PrincipalKind.USER,
    tenant_bound=True,
)
SERVICE_JOBS_WRITE = Policy(
    name="service.jobs.write",
    roles_any=frozenset({"service-executor"}),
    scopes_all=frozenset({"jobs:write"}),
    kind=PrincipalKind.SERVICE,
    client_ids=frozenset({"automation-service"}),
)


def enforce_policy(
    principal: Principal,
    policy: Policy,
    *,
    tenant_id: str | None = None,
) -> None:
    if policy.kind is not None and principal.kind != policy.kind:
        raise AuthorizationError("Principal type is not allowed")
    if policy.client_ids and principal.client_id not in policy.client_ids:
        raise AuthorizationError("Client identity is not allowed")
    if policy.roles_any and not principal.has_any_role(policy.roles_any):
        raise AuthorizationError("Required role is missing")
    if not principal.has_scopes(policy.scopes_all):
        raise AuthorizationError("Required scope is missing")
    if (
        policy.tenant_bound
        and "platform-admin" not in principal.roles
        and (tenant_id is None or principal.tenant_id != tenant_id)
    ):
        raise AuthorizationError("Tenant boundary does not match")
