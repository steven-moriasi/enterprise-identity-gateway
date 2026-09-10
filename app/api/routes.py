from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api.dependencies import Authenticated, authorize
from app.domain.policies import (
    AUDIT_READ,
    OPERATIONS_WRITE,
    SERVICE_JOBS_WRITE,
    TENANT_RESOURCES_READ,
)
from app.domain.schemas import (
    AuthorizedActionResponse,
    PrincipalResponse,
    ResourceListResponse,
)
from app.infrastructure.protected_client import (
    ProtectedServiceClient,
    ProtectedServiceUnavailableError,
    get_protected_service_client,
)

router = APIRouter(prefix="/api", tags=["identity"])


@router.get("/me", response_model=PrincipalResponse)
def me(context: Authenticated) -> PrincipalResponse:
    principal = context.principal
    return PrincipalResponse(
        subject=principal.subject,
        kind=principal.kind,
        client_id=principal.client_id,
        username=principal.username,
        tenant_id=principal.tenant_id,
        roles=sorted(principal.roles),
        scopes=sorted(principal.scopes),
    )


@router.post("/operations", response_model=AuthorizedActionResponse)
def run_operation(context: Authenticated) -> AuthorizedActionResponse:
    authorize(context, OPERATIONS_WRITE)
    return AuthorizedActionResponse(
        action="operation.accepted",
        principal=context.principal.subject,
    )


@router.get("/audit", response_model=AuthorizedActionResponse)
def read_audit(context: Authenticated) -> AuthorizedActionResponse:
    authorize(context, AUDIT_READ)
    return AuthorizedActionResponse(
        action="audit.read",
        principal=context.principal.subject,
    )


@router.get(
    "/tenants/{tenant_id}/resources",
    response_model=ResourceListResponse,
)
def tenant_resources(
    tenant_id: str,
    request: Request,
    context: Authenticated,
    client: Annotated[
        ProtectedServiceClient,
        Depends(get_protected_service_client),
    ],
) -> ResourceListResponse:
    authorize(context, TENANT_RESOURCES_READ, tenant_id=tenant_id)
    try:
        return client.tenant_resources(
            tenant_id,
            access_token=context.access_token,
            correlation_id=request.state.correlation_id,
        )
    except ProtectedServiceUnavailableError as error:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Protected service is unavailable",
        ) from error


@router.post("/service/jobs", response_model=AuthorizedActionResponse)
def submit_service_job(context: Authenticated) -> AuthorizedActionResponse:
    authorize(context, SERVICE_JOBS_WRITE)
    return AuthorizedActionResponse(
        action="service_job.accepted",
        principal=context.principal.subject,
        tenant_id=context.principal.tenant_id,
    )
