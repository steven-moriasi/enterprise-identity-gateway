# ADR 0001: Validate identity at the gateway and protected service

- Status: accepted
- Date: 2026-09-09

## Context

A gateway can centralize token validation and policy, but forwarding only derived identity headers
makes every protected service depend completely on the integrity of the gateway-to-service path.

## Decision

The gateway forwards the original bearer token. The protected service independently validates the
signature, issuer, audience, token type, age, and tenant policy.

## Consequences

- A compromised or misconfigured gateway cannot create a principal by inventing identity headers.
- Key rotation and issuer configuration must remain consistent across both processes.
- Validation work occurs twice, although public-key verification requires no provider round trip when
  JWKS is cached.
- Production service-to-service transport still requires TLS, network policy, and workload identity.
