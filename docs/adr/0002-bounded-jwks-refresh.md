# ADR 0002: Cache JWKS and bound unknown-key refresh

- Status: accepted
- Date: 2026-09-09

## Context

Fetching JWKS for every request adds availability and latency coupling. Caching indefinitely prevents
normal key rotation. Refreshing for every unknown `kid` allows untrusted tokens to amplify requests
to the identity provider.

## Decision

Cache a fully validated JWKS document for a configured duration. On an unknown `kid`, permit an early
refresh only after a separate configured interval. Accept only RSA signing keys compatible with
`RS256`, and reject the complete document if key IDs are duplicated or invalid.

## Consequences

- Normal requests validate without network access.
- Rotation is discovered at cache expiry or bounded unknown-key refresh.
- Invalid-key traffic cannot cause one provider request per token.
- Newly rotated keys may be unavailable for the refresh interval during sustained unknown-key
  traffic; alerting and rollout timing should account for that bound.
