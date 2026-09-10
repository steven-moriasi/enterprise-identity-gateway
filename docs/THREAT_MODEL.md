# Threat Model

## Assets

- Keycloak signing keys and administrative credentials;
- confidential-client credentials;
- authorization codes, access tokens, refresh tokens, and logout tokens;
- role, scope, tenant, client, and session claims;
- protected tenant resources;
- gateway policy and identity-provider configuration;
- authentication and authorization telemetry.

## Adversaries

- an unauthenticated internet client;
- a valid user attempting privilege or cross-tenant escalation;
- a workload holding a token for the wrong client or audience;
- a malicious site attempting redirect, code, or token theft;
- a compromised upstream, gateway, protected service, or identity-provider component;
- an operator making an unsafe deployment or federation configuration change.

## Trust boundaries

1. Browser to Keycloak authorization and token endpoints.
2. Workload to Keycloak token endpoint.
3. Token holder to the gateway.
4. Gateway and protected service to Keycloak JWKS.
5. Gateway to protected service.
6. Keycloak to gateway back-channel logout.
7. Deployment system to secrets, issuer URLs, redirect URIs, and network policy.

## Controls present

| Threat | Control |
|---|---|
| Forged token | RSA signature verification using trusted JWKS |
| Algorithm confusion | exact `RS256` header and decoder allowlist |
| Token from another issuer | exact issuer validation |
| Token for another resource | exact API audience validation |
| ID or refresh token used as access token | required `typ=Bearer` |
| Missing identity context | required subject, client, issue, and expiry claims |
| Stale but unexpired token | configurable maximum age in addition to `exp` |
| Random-`kid` provider amplification | bounded unknown-key refresh |
| Malformed or ambiguous JWKS | schema validation, RSA/signing restrictions, duplicate-`kid` rejection |
| User impersonating a workload | typed principal plus trusted `azp` allowlist |
| Workload impersonating a user | user-only policies require `PrincipalKind.USER` and role claims |
| Cross-tenant resource access | exact tenant comparison; explicit platform-admin exception |
| Gateway-invented identity headers | protected service revalidates original bearer token |
| Session continuing after logout | signed OIDC logout event and `sid`/`sub` revocation |
| Token disclosure in API output | principal response excludes raw token |
| Provider detail disclosure | generic external authentication and availability errors |
| Unbounded token/body parsing | access-token and logout-body size limits |
| Browser origin abuse | explicit CORS origins and methods |

## Open risks before production

### Browser token exposure

The static client keeps access tokens in memory, which avoids persistent browser storage but does not
protect against script execution in the page. A production browser application should evaluate a
backend-for-frontend pattern, strict content security policy, dependency controls, and refresh-token
rotation rather than copying this demonstration unchanged.

### Revocation consistency

Revocation is process-local and disappears on restart. Multiple replicas can disagree. Use shared
revocation state or introspection before claiming immediate logout across a deployment.

### Identity-provider deployment

Compose uses Keycloak development mode, public fixture credentials, local HTTP, and a file-imported
realm. Production requires TLS, hardened hostname and proxy settings, managed database and backups,
restricted administration, key rotation, upgrade procedures, brute-force monitoring, and tested
recovery.

### Secrets

Client and administrator values in the realm and Compose files are intentionally public local
fixtures. Inject production secrets from a managed store, use dedicated least-privilege clients, and
rotate credentials without rebuilding application images.

### Network and egress policy

Application-level issuer and audience checks do not replace mTLS or workload identity, ingress
policy, DNS controls, or restricted egress. The JWKS URL and upstream URL are privileged deployment
configuration and must not be user-controlled.

### Authorization lifecycle

Token claims are snapshots. Role or tenant changes do not affect an already issued token unless it
expires, is revoked, or is introspected. Token lifetime must reflect privilege-change response
objectives. High-risk operations may require step-up authentication or current entitlement checks.

### Availability and abuse

The gateway does not implement rate limits, token replay detection for ordinary access tokens, or
capacity isolation from Keycloak. Apply gateway quotas and monitor invalid-token, unknown-key,
provider-unavailable, and denied-policy rates.

### Logging and privacy

Structured logs omit raw tokens, but deployment pipelines must still prevent authorization headers,
cookies, claims, and personal identifiers from being captured by proxies or broad debug logging.
Define retention and access policy for subject and tenant identifiers.

### Federation

Adding SAML or another upstream federation changes the threat model. See the SAML federation note;
an OIDC token issued after a federation event is only as trustworthy as the upstream assertion and
account-linking rules.

## Security non-claims

This document is design analysis, not a penetration test, formal verification, compliance mapping, or
assurance that every Keycloak and OAuth threat is covered.
