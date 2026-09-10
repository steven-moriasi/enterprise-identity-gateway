# Enterprise Identity Gateway

A security-focused reference implementation for this trust path:

```text
user or workload
→ Keycloak identity provider
→ OIDC/OAuth 2.0 access token
→ FastAPI authorization gateway
→ independently validating protected service
```

The project emphasizes identity boundaries rather than user-management features. It demonstrates
authorization code with PKCE, client credentials, strict JWT/JWKS validation, role/scope/tenant
policy, key rotation, and OIDC back-channel logout. It is an engineering lab, not a production
identity provider, compliance certification, or claim of a completed security assessment.

## Engineering decisions

- Only `RS256` bearer access tokens from the configured issuer and audience are accepted.
- Required claims include `sub`, `iss`, `aud`, `exp`, `iat`, `typ`, and `azp`.
- JWKS keys are cached, refreshed on expiry, and refreshed at a bounded rate for an unknown `kid`.
- User and workload principals are distinct; a service token requires a configured client ID.
- Authorization combines principal kind, client ID, role, scope, and tenant constraints.
- The gateway forwards the original access token, and the protected service validates it again.
- Back-channel logout revokes matching `sid` or `sub` values for the remaining token lifetime.
- Authentication errors are generic, and raw tokens are neither logged nor returned.

See [Architecture](docs/ARCHITECTURE.md), [Runtime Sequences](docs/SEQUENCES.md),
[Threat Model](docs/THREAT_MODEL.md), and the [ADRs](docs/adr/).

## API surface

| Method | Path | Policy |
|---|---|---|
| `GET` | `/health` | Process liveness |
| `GET` | `/ready` | Identity-provider JWKS availability |
| `GET` | `/metrics` | Prometheus authentication and authorization metrics |
| `GET` | `/api/me` | Authenticated principal |
| `POST` | `/api/operations` | User + `operator`/`platform-admin` + `operations:write` |
| `GET` | `/api/audit` | User + audit-capable role + `audit:read` |
| `GET` | `/api/tenants/{tenant_id}/resources` | User + role + `resources:read` + tenant boundary |
| `POST` | `/api/service/jobs` | Service + trusted client ID + `jobs:write` |
| `POST` | `/oidc/backchannel-logout` | Valid OIDC back-channel logout token |

## Run with Docker Compose

```bash
cp .env.example .env
docker compose up -d --build
docker compose ps
curl --fail http://localhost:8000/ready
```

Compose starts Keycloak, the gateway, an independently validating protected service, and a static
PKCE client at `http://localhost:3000`. The realm fixture contains development-only users and
secrets. Do not reuse them outside the local lab.

If the default ports are occupied:

```bash
IDENTITY_KEYCLOAK_PORT=18080 \
IDENTITY_GATEWAY_PORT=18000 \
IDENTITY_PKCE_PORT=13000 \
IDENTITY_PUBLIC_KEYCLOAK_URL=http://localhost:18080 \
docker compose -p identity-gateway-review up -d --build
```

The realm fixture allows `http://localhost:3000/*` as the browser redirect URI. If the browser host
or port changes, update the `command-center` redirect URI, web origin, gateway CORS origin, and
client configuration together.

### Development identities

| Identity | Password/secret | Intended evidence |
|---|---|---|
| `alice.operator` | `local-alice-password` | tenant-alpha operations |
| `bob.viewer` | `local-bob-password` | tenant-beta read-only access |
| `audrey.auditor` | `local-auditor-password` | tenant-alpha audit access |
| `automation-service` | `local-service-secret` | client-credentials job submission |
| Keycloak `admin` | `.env` value | local realm administration |

These values are public fixtures, not secrets suitable for deployment.

## Local development

Use Python 3.12:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload
```

Configuration uses the `IDENTITY_GATEWAY_` prefix. Important controls include:

- `IDENTITY_GATEWAY_ISSUER_URL`
- `IDENTITY_GATEWAY_JWKS_URL`
- `IDENTITY_GATEWAY_AUDIENCE`
- `IDENTITY_GATEWAY_ALLOWED_CLOCK_SKEW_SECONDS`
- `IDENTITY_GATEWAY_MAX_ACCESS_TOKEN_AGE_SECONDS`
- `IDENTITY_GATEWAY_JWKS_CACHE_SECONDS`
- `IDENTITY_GATEWAY_UNKNOWN_KID_REFRESH_SECONDS`
- `IDENTITY_GATEWAY_SERVICE_CLIENT_IDS`
- `IDENTITY_GATEWAY_ALLOWED_ORIGINS`
- `IDENTITY_GATEWAY_BACKCHANNEL_LOGOUT_AUDIENCE`

## Verification

```bash
ruff check app tests
mypy app tests
pytest --cov=app --cov-report=term-missing --cov-fail-under=80
docker compose config --quiet
docker build .
```

The integration review also verifies a PKCE user token, client credentials, same-tenant access,
cross-tenant denial, protected-service forwarding, metrics, and Keycloak-triggered back-channel
logout.

## Operations and review

- [Security Failure Catalog](docs/SECURITY_FAILURES.md)
- [Threat Model](docs/THREAT_MODEL.md)
- [SAML Federation Note](docs/SAML_FEDERATION.md)
- [Operations Runbook](docs/OPERATIONS.md)
- [Portfolio Evidence](docs/PORTFOLIO_EVIDENCE.md)
- [Principal Engineer Review](docs/PRINCIPAL_ENGINEER_REVIEW.md)
- [Roadmap](docs/ROADMAP.md)
