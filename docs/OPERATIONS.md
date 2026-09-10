# Operations Runbook

## Process topology

- Keycloak: local identity provider and JWKS authority on port 8080.
- Gateway: public API, readiness, policy enforcement, logout, and metrics on port 8000.
- Protected service: internal example resource server on port 8001.
- PKCE client: static local demonstration on port 3000.

The default Compose topology is a single-node lab. It is not a high-availability identity platform.

## Health and readiness

```bash
curl --fail http://localhost:8000/health
curl --fail http://localhost:8000/ready
curl --fail http://localhost:8000/metrics
docker compose ps
```

`/health` reports process liveness. `/ready` requires a usable JWKS document. A failed readiness
check can therefore mean provider availability, DNS, TLS, issuer/JWKS configuration, or invalid key
material rather than a dead application process.

## Metrics

- `identity_gateway_authentications_total{outcome=...}`
- `identity_gateway_authorizations_total{policy=...,outcome=...}`

Initial alert candidates, to be calibrated under load:

- sustained `idp_unavailable`;
- any unexpected `invalid_logout`;
- a step change in invalid authentication outcomes;
- denied-policy rates above the endpoint baseline;
- readiness failure;
- protected-service transport failure from logs or edge metrics.

Labels are intentionally bounded. Do not add subject, tenant, token ID, correlation ID, or arbitrary
claim values as metric labels.

## Triage: authentication failures

1. Confirm the caller sends an access token rather than an ID or refresh token.
2. Inspect sanitized header/claims offline without copying the token into tickets or logs.
3. Compare issuer, audience, `typ`, `azp`, issue time, expiry, and `kid` with deployment policy.
4. Query Keycloak discovery and JWKS endpoints through the same network path as the service.
5. Check clock synchronization.
6. Determine whether a key rotation occurred inside the unknown-key refresh interval.
7. Check whether the session or subject was revoked on the serving replica.

Do not weaken issuer, audience, algorithm, type, or age checks as an outage workaround.

## Triage: authorization denial

1. Identify the named endpoint policy.
2. Determine whether the principal was classified as user or service.
3. Compare client ID, roles, scopes, and tenant claim with the policy.
4. For user changes, verify the caller obtained a newly issued token after entitlement updates.
5. For service changes, verify the token was issued to the intended confidential client.
6. Treat `platform-admin` and client allowlist changes as privileged configuration changes.

Do not add a role or scope merely because a similarly named claim appears in an untrusted token.

## Triage: key rotation

1. Confirm the token's `kid` exists in Keycloak JWKS.
2. Confirm the key is RSA, intended for signatures, and compatible with `RS256`.
3. Wait no longer than the configured unknown-key refresh bound before expecting discovery.
4. Check gateway and protected-service configuration together.
5. If emergency key removal is required, account for cached keys and restart or invalidate caches
   through a controlled deployment procedure.

Key compromise response may require shorter JWKS cache duration than normal availability tuning.

## Triage: logout not enforced

1. Confirm Keycloak sent `POST /oidc/backchannel-logout` and received `200`.
2. Confirm the logout token audience matches `command-center`.
3. Confirm it carries the expected back-channel logout event and `sid` or `sub`.
4. Identify which gateway replica accepted the event and which replica served the later request.
5. Check for a restart that lost process-local revocation state.

For multi-replica operation, shared revocation or introspection is a prerequisite, not a runbook
workaround.

## Local back-channel logout drill

1. Sign in as a development user through the PKCE client.
2. Call `/api/me` with the issued access token.
3. Use Keycloak administration to terminate that user's session.
4. Confirm the gateway received a successful back-channel logout.
5. Repeat `/api/me` with the old token and expect `401`.

Never paste the access token into retained shell history, screenshots, issues, or shared logs.

## Deployment checklist

- replace every fixture password and client secret;
- run Keycloak in production mode with a managed database and TLS;
- pin and validate public issuer, internal JWKS URL, redirect URIs, and CORS origins;
- restrict Keycloak administration and application network paths;
- synchronize clocks;
- select token, cache, and logout lifetimes from explicit security objectives;
- implement shared revocation or introspection for multiple replicas;
- configure rate limits and request size limits at the edge;
- keep gateway and protected-service policy compatible during rollout;
- verify key rollover, provider outage, entitlement change, and logout drills;
- define backups, restore testing, audit retention, privacy, and incident access.

## Rollback

Application rollback must preserve issuer, audience, policy, and revocation compatibility. Rolling
back to a revision that does not understand newly issued claims or logout behavior can create denial
or security gaps. Keycloak realm changes need their own export, review, and rollback plan; replacing
the realm fixture is not a production migration strategy.
