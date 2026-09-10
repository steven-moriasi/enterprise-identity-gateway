# Principal Engineer Review

## Verdict

The repository is credible as a focused identity-authorization engineering lab. Its strongest
evidence is not Keycloak configuration alone; it is the explicit resource-server contract around
algorithm, issuer, audience, token type, age, client identity, role, scope, tenant, key rotation,
service revalidation, and logout. It should not be presented as production-ready.

## Review rubric

| Area | Assessment | Evidence |
|---|---|---|
| Problem framing | Strong | narrow resource-server and authorization scope with explicit non-goals |
| Authentication | Strong for a lab | strict JWT semantics, JWKS validation, outage and rotation behavior |
| Authorization | Strong for a lab | typed user/service principals and conjunctive role/scope/tenant policy |
| Defense in depth | Strong | protected service revalidates the original token |
| Session lifecycle | Moderate | valid back-channel logout design; process-local storage is a blocker |
| Browser security | Moderate | PKCE/state and memory-only token; no production BFF or CSP evidence |
| Identity-provider operations | Weak for production | development-mode Keycloak and fixture secrets |
| Federation | Honest but unimplemented | threat-aware SAML design note without implementation claim |
| Observability | Moderate | bounded counters and correlation IDs; no traces or entitlement-change audit |
| Testing | Strong | security-negative unit/API tests and live protocol smoke checks |
| Operability | Moderate | health/readiness, runbook, Compose; no backup/restore or upgrade drill |
| Documentation | Strong | architecture, sequences, threats, failure catalog, ADRs, evidence limits |

## Material strengths

1. The decoder does not rely on signature verification alone; it constrains token purpose and
   semantic claims.
2. JWKS behavior addresses both legitimate rotation and random-key refresh amplification.
3. Workload identity is classified by a configured client ID rather than by a caller-selected scope.
4. Tenant checks occur before forwarding and again at the protected service.
5. Back-channel logout validates a separate JWT contract rather than trusting an unauthenticated
   session identifier.
6. The documentation records that the demonstrated service token does not contain a service role,
   rather than claiming a role-based control that integration evidence contradicted.

## Production blockers

### P1: distribute revocation state

Process-local state is lost on restart and cannot coordinate replicas. Use a shared, expiring store
or online introspection and test partition, latency, restart, and stale-state behavior.

### P1: harden Keycloak deployment and lifecycle

Replace development mode, fixture credentials, local HTTP, and file import with a managed database,
TLS, restricted administration, backup/restore, upgrade testing, key rotation, realm change control,
and incident procedures.

### P1: select a production browser architecture

The static client is appropriate evidence for PKCE mechanics, not a complete browser security model.
Evaluate a backend-for-frontend, session cookies, CSRF controls, CSP, refresh rotation, logout, and
compromise containment.

### P1: protect service and provider network paths

Add TLS or workload identity, ingress and egress policy, DNS controls, timeout budgets, and trust
configuration for gateway-to-service and resource-server-to-Keycloak traffic.

### P2: externalize and govern policy

Static policy is reviewable but does not address delegated administration, entitlement history,
approval, separation of duties, policy versioning, or current-state checks for sensitive actions.

### P2: complete abuse and operational telemetry

Add edge rate limits, token-failure reason telemetry in a controlled channel, traces, provider/cache
health, revocation propagation measurements, and audit events for privileged policy changes.

### P2: test failure and scale boundaries

Add multi-replica, restart, Keycloak failover, key-compromise removal, clock drift, malformed-token
fuzzing, sustained unknown-key traffic, browser security, and workload tests.

## Recommendation

Use the repository as portfolio evidence for identity architecture, OAuth/OIDC resource-server
security, authorization design, service identity, key rotation, and threat-aware engineering. Before
production use, complete every P1 boundary and validate it with an independent security review and
measured failure testing.
