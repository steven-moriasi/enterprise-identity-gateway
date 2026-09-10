# Security Policy

## Reporting

Do not open a public issue containing credentials, tokens, cookies, private keys, production realm
exports, personal data, or exploitation details. Use GitHub private vulnerability reporting for this
repository when available.

Include the affected revision, security impact, minimal reproduction, and sanitized evidence. Remove
authorization headers and replace subjects, tenants, clients, and key IDs when their exact values are
not required.

## Supported versions

This engineering lab supports the latest revision of the default branch. It is not a hosted identity
service and does not publish long-term support releases.

## Deployment warning

The Compose environment uses Keycloak development mode, local HTTP, public fixture users, and public
fixture secrets. The revocation registry is process-local. Production use requires a hardened
identity-provider deployment, managed secrets, TLS, restricted administration and egress, shared
revocation or introspection, rate limits, privacy controls, and an independent security review.
