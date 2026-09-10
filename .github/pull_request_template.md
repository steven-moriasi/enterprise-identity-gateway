## Summary

<!-- What changed and why? -->

## Identity contract and risk

<!-- Which issuer, audience, token, client, role, scope, tenant, key, or logout behavior changes? -->

## Verification

- [ ] Ruff
- [ ] mypy
- [ ] affected security-negative tests
- [ ] full test suite with coverage gate
- [ ] Docker or Compose validation, if runtime packaging changed
- [ ] Keycloak integration flow, if realm or protocol behavior changed

## Security and operations review

- [ ] User and service principals remain distinct
- [ ] Algorithm, issuer, audience, type, age, and required claims remain explicit
- [ ] Protected services do not trust caller-controlled identity headers
- [ ] Logs, errors, metrics, and fixtures contain no real credentials or tokens
- [ ] Key rotation and provider-unavailable behavior remain fail closed
- [ ] Revocation consistency and deployment limitations are documented
- [ ] Architecture, threat model, runbook, or ADRs were updated where needed
