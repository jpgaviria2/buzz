# Support-only admission

The relay can admit a customer to one restricted three-party support DM without
creating a `relay_members` row or accepting the ordinary join policy.

## Configuration and rotation

Set `BUZZ_SUPPORT_ADMISSION_JSON` to strict JSON:

```json
{
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

One to eight generations may be configured. To rotate, deploy the new generation
alongside the old one, update clients, then set the old generation's `revoked`
field to `true` (or remove it) and reload the relay configuration. Raw capability
values are SHA-256 hashed while configuration is loaded and are not logged.
Existing grants retain their own bounded expiry; capability revocation prevents
new admissions through that generation.

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
and the exact active three-person DM roster are rechecked on NIP-42 admission,
REQ, and EVENT.

To revoke one customer grant, call the database-layer
`Db::revoke_support_grant` operation from an operator workflow. The next support
AUTH, REQ, or EVENT fails closed. Ordinary relay membership and join-policy
handling are unchanged.
