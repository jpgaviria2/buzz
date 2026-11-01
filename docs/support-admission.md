# Support-only admission

The relay can admit a customer to one restricted three-party support DM without
creating a `relay_members` row or accepting the ordinary join policy.

## Configuration and rotation

Set `BUZZ_SUPPORT_ADMISSION_JSON` to strict JSON:

```json
{
  "community_host": "buzz.anmore.space",
  "support_pubkey": "<64-char-lowercase-hex>",
  "escalation_pubkey": "<64-char-lowercase-hex>",
  "grant_ttl_secs": 2592000,
  "capabilities": [
    {
      "generation": "2026-11-a",
      "capability": "<32-to-512-byte-opaque-public-value>",
      "expires_at": 1793491200,
      "revoked": false
    }
  ]
}
```

The support plane is accepted only on the exact canonical host
`buzz.anmore.space`; aliases and other tenant hosts return not found. One to
eight generations may be configured. Every `expires_at` must be a positive Unix
second no more than 24 hours in the future when loaded. Expired generations are
kept in configuration so already-issued grants survive relay restarts; they remain
ineligible for new admissions because capability matching rejects expiry. Both
generation identifiers and capability hashes must be unique. To rotate, deploy the
new generation alongside the old one, update clients, then set the old generation's `revoked`
field to `true` (or remove it) and reload the relay configuration. Raw capability
values are SHA-256 hashed while configuration is loaded and are not logged.
Customer grants retain their independent configured expiry (30 days by default),
but capability generation revocation or removal invalidates every active grant
issued by that generation.

## API

`POST /api/support/admit` accepts exactly:

```json
{"capability":"<configured-value>"}
```

It requires one `Authorization: Nostr <base64-event>` header. The signed NIP-98
event must be kind 27235, target the exact tenant admission URL and POST method,
match the exact request-body digest, satisfy the normal NIP-98 clock bound, and
contain exactly one two-element `nonce` tag. Nonces are durably consumed per
community.

Success is predictable JSON:

```json
{
  "status": "support_admitted",
  "scope": "support_dm",
  "expiresAt": 1793491200,
  "channelId": "00000000-0000-0000-0000-000000000000",
  "participants": [
    "<customer-pubkey>",
    "<support-pubkey>",
    "<escalation-pubkey>"
  ]
}
```

The response participant order is customer, support, escalation. Admission is
idempotent for the same canonical participant set. The endpoint applies separate
per-community IP and pubkey admission limits and a three-new-DM-per-pubkey hourly
limit.

## Relay authorization

An active support grant admits NIP-42 with only `messages:read` and
`messages:write`, bound to the returned channel. It does not admit huddle audio,
COUNT, channel enumeration, administration, moderation, membership, arbitrary DM
creation, or any ordinary community operation.

Reads are limited to kind 9 in the exact DM and kind 0 profiles for the exact
three participants. Writes must be customer-authored kind 9 events with exactly
one two-element `h` tag for the granted channel. They may have no `p` tag or one
exact two-element `p` tag for the escalation pubkey. Grant expiry, revocation,
generation status, canonical host, and the exact active three-person DM roster are
rechecked on NIP-42 admission, REQ, EVENT, and live event delivery. Support sockets
are cancelled at the grant deadline, so live subscriptions cannot continue after
expiry; delivery-time checks also stop stale subscriptions after revocation,
generation removal/revocation, participant rotation, or host aliasing. Support
sessions accept only REQ and EVENT frames; COUNT, artifact sync, AUTH, and CLOSE are
refused after support authentication.

To revoke one customer grant, call the database-layer
`Db::revoke_support_grant` operation from an operator workflow. The next support
AUTH, REQ, or EVENT fails closed. Relay callers should use
`api::support::revoke_grant`, which also broadcasts a cluster-wide disconnect for
the customer's active sockets. Ordinary relay membership and join-policy handling
are unchanged.
