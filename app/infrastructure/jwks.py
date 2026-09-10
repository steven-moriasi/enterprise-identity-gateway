import json
import threading
import time
from collections.abc import Callable

import httpx
from jwt import PyJWK
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.domain.errors import AuthenticationError, IdentityProviderUnavailableError


class JwkDocument(BaseModel):
    model_config = ConfigDict(extra="allow")

    kty: str
    kid: str = Field(min_length=1, max_length=255)
    use: str | None = None
    alg: str | None = None
    n: str
    e: str


class JwksDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    keys: list[JwkDocument]


class JwksCache:
    def __init__(
        self,
        *,
        url: str,
        cache_seconds: int,
        unknown_kid_refresh_seconds: int,
        timeout_seconds: float,
        client: httpx.Client | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = url
        self._cache_seconds = cache_seconds
        self._unknown_kid_refresh_seconds = unknown_kid_refresh_seconds
        self._client = client or httpx.Client(timeout=timeout_seconds)
        self._monotonic = monotonic
        self._keys: dict[str, PyJWK] = {}
        self._expires_at = 0.0
        self._last_unknown_kid_refresh = float("-inf")
        self._lock = threading.Lock()

    def get(self, kid: str) -> PyJWK:
        now = self._monotonic()
        with self._lock:
            if now >= self._expires_at:
                self._refresh(now)
            key = self._keys.get(kid)
            if key is not None:
                return key
            if now - self._last_unknown_kid_refresh >= self._unknown_kid_refresh_seconds:
                self._last_unknown_kid_refresh = now
                self._refresh(now)
                key = self._keys.get(kid)
                if key is not None:
                    return key
        raise AuthenticationError("Token signing key is not trusted")

    def ensure_available(self) -> None:
        now = self._monotonic()
        with self._lock:
            if now >= self._expires_at:
                self._refresh(now)

    def close(self) -> None:
        self._client.close()

    def _refresh(self, now: float) -> None:
        try:
            response = self._client.get(self._url)
            response.raise_for_status()
            document = JwksDocument.model_validate(response.json())
            keys = self._validated_keys(document)
        except (httpx.HTTPError, ValueError, ValidationError) as error:
            raise IdentityProviderUnavailableError(
                "Identity provider signing keys are unavailable"
            ) from error
        if not keys:
            raise IdentityProviderUnavailableError(
                "Identity provider returned no trusted signing keys"
            )
        self._keys = keys
        self._expires_at = now + self._cache_seconds

    @staticmethod
    def _validated_keys(document: JwksDocument) -> dict[str, PyJWK]:
        keys: dict[str, PyJWK] = {}
        for item in document.keys:
            if item.kty != "RSA":
                continue
            if item.use not in (None, "sig"):
                continue
            if item.alg not in (None, "RS256"):
                continue
            if item.kid in keys:
                raise ValueError("Duplicate signing key identifier")
            keys[item.kid] = PyJWK.from_json(json.dumps(item.model_dump()))
        return keys
