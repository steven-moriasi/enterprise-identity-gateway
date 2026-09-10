import re
from uuid import uuid4

from fastapi import FastAPI, Request
from starlette.middleware.base import RequestResponseEndpoint
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import Response

from app.api.routes import router as identity_router
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.operations import router as operations_router

CORRELATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

configure_logging()

app = FastAPI(
    title="Enterprise Identity Gateway",
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type", "X-Correlation-ID"],
    expose_headers=["X-Correlation-ID"],
)
app.include_router(operations_router)
app.include_router(identity_router)


@app.middleware("http")
async def correlation_id(
    request: Request,
    call_next: RequestResponseEndpoint,
) -> Response:
    candidate = request.headers.get("X-Correlation-ID", "")
    request.state.correlation_id = (
        candidate if CORRELATION_ID_PATTERN.fullmatch(candidate) else str(uuid4())
    )
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = request.state.correlation_id
    return response
