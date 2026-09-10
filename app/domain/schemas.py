from pydantic import BaseModel

from app.domain.models import PrincipalKind


class PrincipalResponse(BaseModel):
    subject: str
    kind: PrincipalKind
    client_id: str
    username: str | None
    tenant_id: str | None
    roles: list[str]
    scopes: list[str]


class AuthorizedActionResponse(BaseModel):
    action: str
    principal: str
    tenant_id: str | None = None


class ResourceResponse(BaseModel):
    id: str
    tenant_id: str
    state: str


class ResourceListResponse(BaseModel):
    resources: list[ResourceResponse]
