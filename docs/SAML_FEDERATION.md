# SAML 2.0 Federation Note

## Position

SAML is intentionally not implemented in the application. If Keycloak brokers a SAML identity
provider, the gateway should continue to consume one normalized OIDC access-token contract. Protocol
translation does not remove federation risk; it moves assertion validation and account linking into
Keycloak.

## Required federation controls

Before enabling a SAML identity provider:

- obtain metadata through an authenticated administrative process;
- pin the expected entity ID, assertion consumer destination, and trusted signing certificates;
- require signed responses and assertions according to the federation profile;
- validate audience, recipient, destination, `InResponseTo`, time bounds, and subject confirmation;
- reject duplicate XML IDs, ambiguous references, unsupported signature algorithms, and unsigned
  security-relevant elements;
- bound clock skew and assertion lifetime;
- prevent assertion replay with a shared cache sized for the assertion validity window;
- encrypt assertions when their route or contents require confidentiality;
- map an immutable upstream identifier, not a mutable email address alone;
- define collision-safe account linking and just-in-time provisioning behavior;
- allowlist attributes and values that may become roles, groups, or tenant claims;
- separate identity proof from authorization assignment;
- test certificate rollover with overlapping trust and explicit retirement;
- define single logout expectations and failure behavior across protocols.

## Role and tenant mapping

An upstream assertion must not directly grant `platform-admin`, workload identity, or arbitrary
`tenant_id` merely because a similarly named attribute exists. Use explicit mapping tables, trusted
issuer-specific rules, and an approval process for privileged entitlements. The resulting Keycloak
token must still satisfy the gateway's normal issuer, audience, type, age, client, role, scope, and
tenant checks.

## Metadata and key rollover

Automatic metadata refresh can improve availability during planned certificate rotation but also
changes trust without an application deployment. Production operation should:

1. authenticate metadata retrieval;
2. alert on entity, endpoint, algorithm, and certificate changes;
3. stage overlapping certificates;
4. verify both old and new signatures in a controlled test;
5. remove retired trust after the agreed overlap.

## Logout limitations

SAML single logout and OIDC back-channel logout have different participant and delivery semantics.
Federated logout must be tested end to end. If upstream logout cannot reliably reach Keycloak, short
access-token lifetimes or current-session checks may still be needed.

## Test evidence required for a future implementation

- signed valid response acceptance;
- unsigned response/assertion rejection;
- wrong audience, destination, recipient, and issuer rejection;
- expired and not-yet-valid assertion rejection;
- replay rejection across replicas;
- XML signature wrapping fixtures;
- certificate rollover;
- attribute allowlisting and privilege-escalation rejection;
- account-linking collision behavior;
- federated logout propagation.

Until those controls and tests exist, the repository should not claim SAML implementation.
