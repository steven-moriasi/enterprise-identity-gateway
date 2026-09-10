# Roadmap

The roadmap describes engineering work, not delivery commitments.

## Stage 1: distributed session security

- move revocation to a shared expiring store;
- add logout-token `jti` replay tracking;
- measure propagation across replicas;
- test restart, partition, and stale-cache behavior;
- define introspection fallback for high-risk endpoints.

## Stage 2: production identity-provider operations

- use a production Keycloak topology and managed database;
- automate reviewed realm changes without destructive import;
- exercise backup, restore, upgrade, signing-key rollover, and emergency key removal;
- integrate managed secret and certificate rotation;
- restrict administration and network paths.

## Stage 3: browser and service hardening

- evaluate a backend-for-frontend and secure session-cookie model;
- add CSP, CSRF controls, refresh rotation, and logout tests;
- use workload identity or mTLS on internal paths;
- apply ingress limits, egress policy, and DNS protections;
- add step-up authentication for high-risk actions.

## Stage 4: authorization governance

- externalize versioned policy where justified;
- model delegated administration and separation of duties;
- audit entitlement and policy changes;
- add current-state checks for sensitive actions;
- define role, scope, tenant, and client compatibility during rollout.

## Stage 5: assurance and federation

- add malformed-token and claim fuzzing;
- run multi-replica fault injection and workload tests;
- complete a SAML broker only with the documented validation fixtures;
- commission independent security review and remediate findings;
- publish measured limits without extrapolating production claims.
