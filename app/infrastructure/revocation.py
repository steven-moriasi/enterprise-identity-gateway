import threading
import time
from collections.abc import Callable


class RevocationRegistry:
    def __init__(
        self,
        *,
        retention_seconds: int,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._retention_seconds = retention_seconds
        self._monotonic = monotonic
        self._revoked: dict[str, float] = {}
        self._lock = threading.Lock()

    def revoke(self, *, session_id: str | None, subject: str | None) -> None:
        if session_id is None and subject is None:
            raise ValueError("A session or subject is required")
        now = self._monotonic()
        expires_at = now + self._retention_seconds
        with self._lock:
            self._remove_expired(now)
            if session_id is not None:
                self._revoked[f"sid:{session_id}"] = expires_at
            if subject is not None:
                self._revoked[f"sub:{subject}"] = expires_at

    def is_revoked(self, *, session_id: str | None, subject: str) -> bool:
        now = self._monotonic()
        with self._lock:
            self._remove_expired(now)
            subject_revoked = f"sub:{subject}" in self._revoked
            session_revoked = (
                session_id is not None and f"sid:{session_id}" in self._revoked
            )
            return subject_revoked or session_revoked

    def _remove_expired(self, now: float) -> None:
        expired = [
            identifier
            for identifier, expires_at in self._revoked.items()
            if expires_at <= now
        ]
        for identifier in expired:
            del self._revoked[identifier]
