# Push MFA payload binding (push v2)

Decided 2026-10-07. Status: decided, not implemented.
Repos: `KyIdentity-server` (verifier, challenge, push data) and `kyauth-android` (signer, parser).

## Why

KyAuth signs a push approval with its hardware device key. The v1 message is
`kysignon-push-v1|challengeId|verb|digits`: it says which challenge, but not which server, account,
device, purpose or deadline the user approved. v2 makes the signature state all of them, and lets
KyAuth show the purpose before the user approves. This is defence in depth: v1 already relies on
server-random challenge IDs, single-use status transitions and server-side expiry, which stay.

## Message

UTF-8, `|`-joined, no trailing separator:

```
kyidentity-push-v2|{origin}|{userId}|{deviceId}|{challengeId}|{purpose}|{expiresAtMs}|{verb}|{digits}
```

- `origin`: the KyIdentity issuer origin, normalized (below). Client: from the paired `serverUrl`.
  Server: from `KYIDENTITY_ISSUER_URL`. Never taken from the push payload or the request.
- `userId`: KyIdentity user ID. Client: paired `userId`; Server: the challenge's `UserID`.
- `deviceId`: the approving device's ID. Client: paired `deviceId`; Server: the device whose key
  verifies (named in the request).
- `challengeId`: as v1.
- `purpose`: `login` or `step_up`. Nothing else is valid.
- `expiresAtMs`: challenge expiry, Unix epoch milliseconds, decimal.
- `verb`: `approve` or `deny`.
- `digits`: the two digits the user entered on approve; empty on deny.

Any field containing `|`, or an empty `origin`/`userId`/`deviceId`/`challengeId`, is refused by
both sides.

**Origin normalization** (same on both sides): scheme and host lowercased; port dropped when it is
the scheme default (443 for https, 80 for http); path, query, fragment and userinfo dropped; no
trailing slash. Vectors:

| Input | Origin |
|---|---|
| `https://ID.Example.com/` | `https://id.example.com` |
| `https://id.example.com:443` | `https://id.example.com` |
| `https://id.example.com:8443/kyidentity` | `https://id.example.com:8443` |
| `http://127.0.0.1:8080` | `http://127.0.0.1:8080` |

**Golden vectors** — both repos assert these exact strings:

```
kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|login|1791331200000|approve|42
kyidentity-push-v2|https://id.example.com|u-123|d-456|c-789|step_up|1791331200000|deny|
```

## Server

- `mfa_challenges` gains `purpose` (`login` | `step_up`). Login (`auth_handlers.go`) creates
  `login`; step-up (`stepup_handlers.go`) creates `step_up`.
- `ExpiresAt` is truncated to whole seconds at creation, so the stored value and the value sent to
  the phone are the same millisecond count.
- The push `data` map adds `purpose` and `expiresAtEpochMs`. It still carries no digits.
- `POST /api/mfa/push/respond` adds a required `deviceId`. The server verifies only that device's
  key: it must belong to the challenge's user, be an MFA approver and hold a key. Anything else is
  the existing generic signature failure, without saying which check failed. The message is rebuilt
  from server-side values only.
- v1 is removed. There is no fallback.

## Client

- The parser requires `purpose` (`login` | `step_up`) and `expiresAtEpochMs`. An expiry in the
  past or more than 10 minutes ahead is refused, not clamped: a clamped value would never match the
  server's signature input.
- The parser refuses a push whose `deviceId` or `deviceUserId` differs from the pairing.
- The request card shows the purpose: "Sign-in request" for `login`, "Confirm a sensitive action"
  for `step_up`.
- The response body adds `deviceId`.

## Unchanged

`kysignon-push-token-v1` (push-token refresh), the device-sign-on JWT, the attestation challenge,
and the Keystore alias `kysignon-device-signing-v1`.

## Rollout

There is no public KyAuth build, so the switch is clean. A merge to KyIdentity `master` publishes
`:latest`; dev KyAuth installs need the matching build at the same time, or their push approvals
fail until updated. `E2EE_PLAN.md` reserved `kysignon-push-v2` for vault unlock; that milestone now
extends `kyidentity-push-v2` instead.
