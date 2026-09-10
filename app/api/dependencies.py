from typing import Annotated

from fastapi import Depends, HTTPException, status

from app.core.metrics import AUTHORIZATIONS
from app.domain.errors import AuthorizationError
from app.domain.policies import Policy, enforce_policy
from app.infrastructure.auth import IdentityContext, authenticate


def authorize(
    context: IdentityContext,
    policy: Policy,
    *,
    tenant_id: str | None = None,
) -> None:
    try:
        enforce_policy(context.principal, policy, tenant_id=tenant_id)
    except AuthorizationError as error:
        AUTHORIZATIONS.labels(policy=policy.name, outcome="denied").inc()
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        ) from error
    AUTHORIZATIONS.labels(policy=policy.name, outcome="allowed").inc()


Authenticated = Annotated[IdentityContext, Depends(authenticate)]
