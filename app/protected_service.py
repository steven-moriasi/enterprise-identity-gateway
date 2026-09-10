from fastapi import FastAPI

from app.api.dependencies import Authenticated, authorize
from app.core.logging import configure_logging
from app.domain.policies import TENANT_RESOURCES_READ
from app.domain.schemas import ResourceListResponse, ResourceResponse
from app.operations import router as operations_router

configure_logging()

app = FastAPI(
    title="Protected Resource Service",
    version="0.1.0",
)
app.include_router(operations_router)


@app.get(
    "/internal/tenants/{tenant_id}/resources",
    response_model=ResourceListResponse,
)
def tenant_resources(
    tenant_id: str,
    context: Authenticated,
) -> ResourceListResponse:
    authorize(context, TENANT_RESOURCES_READ, tenant_id=tenant_id)
    return ResourceListResponse(
        resources=[
            ResourceResponse(
                id=f"{tenant_id}-automation-001",
                tenant_id=tenant_id,
                state="active",
            )
        ]
    )
