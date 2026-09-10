# ADR 0003: Use process-local revocation only as a protocol reference

- Status: accepted for the lab
- Date: 2026-09-09

## Context

JWT access tokens remain valid until expiry unless a resource server checks additional state. OIDC
back-channel logout supplies a signed event but does not prescribe distributed storage.

## Decision

Store revoked session and subject identifiers in a bounded in-memory registry until the maximum
access-token retention period has elapsed.

## Consequences

- The lab demonstrates signed logout-event validation and immediate denial in one gateway process.
- A restart loses revocation state.
- Multiple replicas can disagree.
- Production deployment is blocked until revocation uses shared state or online introspection, or
  until the accepted design explicitly relies on short-lived tokens without immediate revocation.
