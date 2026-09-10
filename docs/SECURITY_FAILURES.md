# Security Failure Catalog

This catalog records common identity failures and the expected boundary in this repository.

| Failure | Expected result | Relevant control |
|---|---|---|
| Missing bearer header | `401` with bearer challenge | authentication dependency |
| Oversized bearer token | `401` | configured token byte limit |
| JWT without `kid` | `401` | protected-header validation |
| `HS256`, `none`, or another algorithm | `401` | exact `RS256` allowlist |
| Unknown `kid` | bounded JWKS refresh, then `401` | rotation-aware cache |
| JWKS unavailable when refresh is required | `503` | fail-closed provider boundary |
| Invalid or duplicate JWKS key | `503` or authentication failure | whole-document validation |
| Wrong issuer | `401` | exact issuer |
| Wrong audience | `401` | exact API audience |
| Expired token | `401` | `exp` validation |
| Future or excessively old token | `401` | clock skew and maximum age |
| ID/refresh token presented to API | `401` | `typ=Bearer` |
| User has role but lacks scope | `403` | conjunctive policy |
| User has scope but lacks role | `403` | conjunctive policy |
| User presents service scope | `403` | principal kind |
| Workload uses untrusted client | `403` | service client allowlist |
| Tenant user requests another tenant | `403` | tenant-bound policy |
| Platform administrator requests another tenant | allowed by explicit policy | role exception |
| Protected service unavailable | `502` | upstream boundary |
| Token valid at gateway but invalid at service | protected service rejects | defense-in-depth validation |
| Malformed logout request | `400` | content type, size, form parsing |
| Forged, stale, wrong-audience logout token | `400` | logout JWT validation |
| Logout token lacks event or subject/session | `400` | OIDC event validation |
| Access token matches revoked session | `401` | revocation registry |
| Gateway restarts after logout | token may validate again | documented process-local limitation |

## Error disclosure

External messages intentionally avoid revealing whether failure came from signature, issuer,
audience, claims, policy, or revocation. Operational diagnosis belongs in controlled metrics and
sanitized logs. Do not enable token or authorization-header logging to make failures easier to debug.

## Incident questions

When investigating an identity failure, establish:

1. Which issuer, audience, client ID, and key ID were expected?
2. Was the failure cryptographic authentication, semantic claim validation, or authorization policy?
3. Did Keycloak rotate keys or become unavailable?
4. Was the principal a user or workload, and which role/scope/tenant claims were present?
5. Was a logout event accepted, and is revocation state present on the serving replica?
6. Did the protected service independently reject a token accepted by the gateway?
7. Could proxy, clock, DNS, secret, redirect-URI, or CORS configuration have changed?

Claim values and tokens collected during triage must be minimized and redacted.
