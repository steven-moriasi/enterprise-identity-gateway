from dataclasses import dataclass
from enum import StrEnum


class PrincipalKind(StrEnum):
    USER = "user"
    SERVICE = "service"


@dataclass(frozen=True)
class Principal:
    subject: str
    kind: PrincipalKind
    client_id: str
    username: str | None
    tenant_id: str | None
    roles: frozenset[str]
    scopes: frozenset[str]
    token_id: str | None

    def has_any_role(self, required: frozenset[str]) -> bool:
        return not required.isdisjoint(self.roles)

    def has_scopes(self, required: frozenset[str]) -> bool:
        return required.issubset(self.scopes)
