# Runtime Sequences

## User authorization code with PKCE

```text
Browser          Keycloak                 Gateway          Protected service
   | verifier + challenge                    |                    |
   |------ authorize(challenge,state) ------>|                    |
   |<--------- login and consent ------------|                    |
   |<------------- code,state ---------------|                    |
   |------ token(code,verifier) ------------>|                    |
   |<---------- access token ----------------|                    |
   |------------- bearer token ------------>|                    |
   |                              validate signature/claims       |
   |                              enforce role/scope/tenant       |
   |                              |------ bearer token ---------->|
   |                              |                 revalidate JWT|
   |                              |                 enforce tenant|
   |                              |<--------- resources ----------|
   |<------------- response ------------- ---|                    |
```

The authorization server binds the code to the browser's verifier through the `S256` challenge.
OAuth state binds the redirect to the initiating browser transaction. The API accepts only the
resulting access token, not an ID token.

## Workload client credentials

```text
Automation service       Keycloak                 Gateway
        |--- client ID + secret --->|                 |
        |<--- scoped access token --|                 |
        |---------------- bearer token ------------->|
        |                                  verify JWT|
        |                     classify service by azp|
        |              require client + jobs:write   |
        |<---------------- accepted -----------------|
```

A user token carrying `jobs:write` remains a user principal and is rejected. A service token from an
untrusted client ID is also rejected.

## JWKS rotation

```text
Token holder             Gateway cache                Keycloak
     | token(new kid)          |                          |
     |-----------------------> | lookup misses            |
     |                         |--- fetch JWKS ---------->|
     |                         |<-- old + new keys -------|
     |                         | validate entire document |
     |                         | verify token with new key |
     |<------------------------|                          |
```

Unknown-key refresh is rate-bounded. Repeated random `kid` values cannot force one provider call per
request. A malformed JWKS document is rejected without partially updating the cache.

## Back-channel logout

```text
Administrator/User       Keycloak                 Gateway
       | end session/logout  |                       |
       |-------------------->|                       |
       |                     |-- logout_token ------>|
       |                     |          validate event,
       |                     |          issuer, audience,
       |                     |          signature, age
       |                     |          revoke sid/sub
       |                     |<--------- 200 ----------|

Token holder             Gateway
       | old access token   |
       |------------------->| signature valid
       |                    | sid/sub revoked
       |<------- 401 -------|
```

The access token is not mutated or remotely deleted. The gateway denies it because its session or
subject appears in the local revocation registry.

## Identity-provider outage

If a request requires a JWKS refresh and Keycloak cannot be reached, readiness and authentication
fail with `503`. The gateway does not accept an unverifiable token. Known cached keys continue to be
usable until cache behavior requires refresh; deployment policy should align cache duration and
outage tolerance with key-compromise response requirements.
