# Portfolio Evidence Map

This document maps engineering claims to inspectable implementation and verification. It does not
turn a reference repository into evidence of production identity operation.

| Claim | Implementation evidence | Verification evidence |
|---|---|---|
| Authorization code with PKCE | static client verifier, challenge, state, and code exchange | local Keycloak integration flow |
| Client-credentials identity | Keycloak confidential client and service classification by `azp` | service principal and live token tests |
| Strict JWT boundary | protected header and required-claim validation | algorithm, issuer, audience, type, expiry, age tests |
| Rotation-aware JWKS | validated cache and bounded unknown-`kid` refresh | rotation and provider-failure tests |
| User/workload separation | `PrincipalKind` and service client allowlist | user-with-service-scope rejection |
| Role and scope policy | typed policy definitions and centralized enforcement | missing role/scope and allowed-action tests |
| Tenant isolation | tenant-bound policy and explicit platform-admin exception | cross-tenant and administrator tests |
| Defense in depth | original bearer token forwarded for service revalidation | authorization and correlation forwarding test |
| Back-channel logout | logout JWT validation and bounded revocation registry | invalid-event, expiry, replay-boundary, and API tests |
| Fail-closed provider behavior | typed provider-unavailable boundary | JWKS outage and readiness behavior |
| Generic external errors | API exception mapping | authentication and authorization response assertions |
| Observability | bounded Prometheus outcome and policy labels | integration metrics smoke check |
| Runtime packaging | pinned Keycloak and Nginx images, non-root application image, health checks | Docker build and Compose startup |
| Software delivery controls | strict lint/types, coverage gate, pinned CI actions, Dependabot | `.github/` configuration |
| Threat-aware federation position | SAML control and evidence requirements without false implementation claim | design review documentation |

## Verified locally

- Ruff across application and tests.
- Strict mypy across application and tests.
- Twenty-nine deterministic tests.
- Coverage above the 80% gate.
- Docker image build and Compose configuration.
- Healthy Keycloak, gateway, and protected-service processes.
- PKCE user token containing subject, role, scopes, and tenant.
- Same-tenant protected-resource access and cross-tenant denial.
- Client-credentials token accepted only at the service policy.
- Keycloak-triggered back-channel logout followed by old-token rejection.
- Authentication and authorization metrics after live requests.

These checks describe the local revision when the review was written. CI status is a separate signal
after publication.

## Not proved by this repository

- production availability, latency, scale, recovery objectives, or breach resistance;
- complete OAuth, OIDC, Keycloak, browser, XML, or federation threat coverage;
- multi-replica logout consistency;
- secure production secret, key, certificate, or realm lifecycle;
- SAML implementation or provider interoperability;
- penetration testing, formal assurance, or compliance certification;
- historical production deployment, realized savings, or business outcomes.
