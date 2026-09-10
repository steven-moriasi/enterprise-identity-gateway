class IdentityError(Exception):
    """Base class for safe identity failures."""


class AuthenticationError(IdentityError):
    """The presented credential cannot establish a principal."""


class AuthorizationError(IdentityError):
    """The principal is authenticated but lacks permission."""


class IdentityProviderUnavailableError(IdentityError):
    """Identity-provider metadata cannot be obtained safely."""
