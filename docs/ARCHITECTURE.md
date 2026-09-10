# Architecture

## Scope

The repository is an authorization-gateway lab. Keycloak authenticates users and workloads and
issues tokens. The gateway validates external tokens and applies coarse-grained policy. A protected
service independently validates the same token and applies its own resource boundary.

It does not implement identity lifecycle management, credential recovery, identity governance,
fine-grained entitlement storage, or a production Keycloak deployment.

## Components

```text
┌────────────────┐       authorization code + PKCE       ┌──────────────┐
│ browser client │ ─────────────────────────────────────▶ │   Keycloak   │
└───────┬────────┘                                        └──────┬───────┘
        │ bearer token                                           │ JWKS
        ▼                                                        ▼
┌────────────────────────────────────────────────────────────────────────┐
│ FastAPI gateway                                                        │
│ correlation ID → JWT/JWKS validation → principal → policy enforcement │
└───────────────────────────────┬────────────────────────────────────────┘
                                │ original bearer token
                                ▼
                   ┌──────────────────────────┐
                   │ protected service        │
                   │ validate token + tenant  │
                   └──────────────────────────┘

automation-service ── client credentials ──▶ Keycloak ── token ──▶ gateway
Keycloak ── signed logout token ──▶ gateway revocation registry
```

### Keycloak

The imported `enterprise` realm defines user roles, client scopes, tenant mapping, a public PKCE
client, a confidential workload client, and a bearer-only API audience. The container runs
Keycloak's development mode for reproducible local review.

### Gateway

The gateway owns four boundaries:

1. syntactic bearer-token extraction and size limits;
2. cryptographic and semantic JWT validation;
3. conversion of claims into a typed user or service principal;
4. endpoint policy over principal kind, client, roles, scopes, and tenant.

Authentication failure returns `401`; insufficient policy returns `403`; unavailable JWKS returns
`503`; and unavailable protected-service transport returns `502`.

### Protected service

The protected service is not permitted to trust identity headers asserted by the gateway. It receives
the original token, runs the same cryptographic validation, and rechecks tenant access. This costs an
additional local validation but avoids making the gateway-to-service hop an implicit identity trust
channel.

### Static PKCE client

The client generates the verifier, SHA-256 challenge, and OAuth state in the browser. It exchanges
the returned code with the verifier and stores the access token only in memory. It intentionally
does not persist refresh tokens or access tokens.

## Token contract

Accepted access tokens must have:

- a protected header with `alg=RS256` and a `kid`;
- the exact configured issuer and expected API audience;
- a valid signature from a trusted RSA signing key;
- `sub`, `iss`, `aud`, `exp`, `iat`, `typ`, and `azp`;
- `typ=Bearer`;
- an issue time within the configured maximum token age;
- a non-revoked `sid` or `sub`, when those claims are present.

Roles are read from realm and gateway-client role claims. Scopes are parsed from the standard
space-separated `scope` claim. `tenant_id` is an explicit custom claim.

## Authorization model

| Policy | Principal | Client | Role | Scope | Tenant |
|---|---|---|---|---|---|
| operations write | user | any accepted interactive client | operator or platform-admin | `operations:write` | no route tenant |
| audit read | user | any accepted interactive client | auditor, operator, or platform-admin | `audit:read` | no route tenant |
| tenant resources | user | any accepted interactive client | viewer, auditor, operator, or platform-admin | `resources:read` | exact match unless platform-admin |
| service jobs | service | `automation-service` | none | `jobs:write` | claim returned for context |

The service policy deliberately uses principal type, exact client ID, and scope. The imported
Keycloak service-account role was not present in the integration-issued token, so the implementation
does not document or enforce a role it cannot demonstrate.

## JWKS and key rotation

The JWKS cache accepts only RSA signing keys compatible with `RS256`, rejects duplicate key IDs, and
atomically replaces its cache after validating the complete document. It refreshes:

- when the cache expires;
- once when a token references an unknown `kid`, subject to a refresh interval.

If a known cached key is still available, an unrelated provider refresh failure does not invalidate
it. If validation requires a provider fetch and that fetch fails, the request fails closed.

## Revocation model

Back-channel logout tokens are independently signed JWTs with a required logout event, audience,
`jti`, recent `iat`, and `sid` or `sub`. A valid event stores process-local revocation keys until no
previously issued access token should remain valid.

This bounds memory and demonstrates the protocol, but it is not correct for multiple gateway
replicas. Production needs shared low-latency revocation state, sticky routing with accepted risk, or
online token introspection.

## Trust boundaries

1. Browser or workload to Keycloak.
2. Token holder to gateway.
3. Gateway and protected service to Keycloak JWKS.
4. Gateway to protected service.
5. Keycloak to back-channel logout endpoint.
6. Operators and deployment configuration to secrets, redirect URIs, CORS, and egress policy.

See the threat model for controls and unresolved production risks.
