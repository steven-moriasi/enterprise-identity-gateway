# Contributing

## Development checks

Use Python 3.12:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

Before opening a pull request:

```bash
ruff check app tests
mypy app tests
pytest --cov=app --cov-report=term-missing --cov-fail-under=80
docker compose config --quiet
docker build .
```

Changes to authentication, claim parsing, policy, Keycloak configuration, or logout behavior require
negative tests and updates to the architecture, threat model, failure catalog, runbook, or an ADR.

Do not commit real credentials, exported production realms, private keys, tokens, cookies, user
claims, or captured authorization headers. Development fixture values must remain clearly synthetic.

## Identity review checklist

- Token algorithm, issuer, audience, type, age, and required claims remain explicit.
- User and service principals cannot be substituted for one another.
- Policy changes state the required client, role, scope, and tenant behavior.
- Protected services do not trust caller-controlled identity headers.
- Unknown-key behavior remains rotation-aware and resistant to refresh amplification.
- Logout changes account for replay, audience, age, session/subject, and replica consistency.
- Logs, responses, metrics, and tests do not disclose tokens or unbounded identity values.
