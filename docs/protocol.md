# Implemented experimental protocol

This document describes what exists in App version 0.3. Formats may still break before the
stable compatibility boundary.

## Version identifiers

- Client HTTP API: `ha-chat-client/2`
- Federation HTTP API: `ha-chat-federation/2`
- Reserved portable message generation: `ha-chat/2`

Every `/v1/` request must include `X-HA-Chat-Protocol` with the exact identifier for
that listener. A mismatch returns HTTP 426. Health checks are exempt. JSON responses
use `Cache-Control: no-store` and include an opaque `X-Request-ID`.

## Addresses

Accepted forms are `NUMBER` and `NUMBER@IPV4[:PORT]`. `NUMBER` is exactly eight decimal
digits and cannot begin with zero. The server component must be a canonicalizable IPv4
literal. DNS names, URLs, paths, bracketed addresses, IPv6, whitespace, port zero, and
ports above 65535 are rejected.

## Client listener

`GET /healthz` is unauthenticated and returns listener role plus API version.

`POST /v1/sessions` accepts exactly:

```json
{"identity":"12345678","password":"a sufficiently long password"}
```

It returns an opaque 256-bit bearer token with a 12-hour expiry. Only its SHA-256 digest
is stored. Authentication failures are deliberately generic.

`GET /v1/status` and `GET /v1/account` require
`Authorization: Bearer TOKEN`. `DELETE /v1/session` revokes the current token.
Administrative account creation is intentionally not exposed over HTTP; the local CLI
creates accounts.

Authenticated client operations now include:

- `POST /v1/devices` to enroll a P-256 encryption device;
- `POST /v1/key-packages` to deposit bounded one-time opaque key packages;
- `POST /v1/devices/lookup` to claim local or federated device packages;
- `POST /v1/messages` to submit an opaque `ha-chat/2` encrypted direct-message event;
- `GET /v1/messages` to retrieve up to 50 pending inbox events;
- `POST /v1/messages/receipt` to mark an event delivered or read; and
- `POST /v1/messages/status` to observe queued, accepted, delivered, read, or failed.

Ciphertext is canonical standard base64 and bounded to 48 KiB in this direct-message
slice. Its envelope binds a registered device UUID, monotonic per-device counter,
12-byte nonce, key ID, AAD, and optional 32-byte key commitment. Servers validate and
route the envelope but cannot decrypt it.

Inbox retrieval does not itself claim delivery. A client sends `delivered` only after it
has received and durably accepted an event; `read` implies delivered. Both states are
monotonic, and acknowledged rows no longer occupy later inbox pages.

## Federation listener

Peers are configured locally with a peer ID, literal source/endpoint IPv4, port, and a
256-bit shared secret. The source IPv4 must match the configured peer. A TLS peer may
also specify a DNS certificate name for SNI and verification while the connection stays
pinned to the literal IPv4 endpoint.

Authenticated requests provide:

- `X-HA-Chat-Peer`
- `X-HA-Chat-Timestamp` (Unix seconds, within 300 seconds)
- `X-HA-Chat-Nonce` (16–96 base64url-style characters, never reused)
- `X-HA-Chat-Signature`

The base64url-without-padding signature is HMAC-SHA-256 over:

```text
UPPERCASE_METHOD + "\n" +
EXACT_PATH + "\n" +
TIMESTAMP + "\n" +
NONCE + "\n" +
LOWERCASE_HEX_SHA256_OF_BODY
```

Accepted nonces are persisted transactionally for the replay window. The implemented
`GET /v1/federation/status` proves plane isolation, versioning, peer authentication,
and replay behavior. `POST /v1/federation/devices`, `/events`, and `/receipts` provide
authenticated device-package discovery, idempotent ciphertext delivery, and monotonic
delivered/read receipt propagation. Outbound events and receipts are durably queued and
retried with bounded exponential backoff.

One-time key-package payloads are opaque to the server. A retry by the same authenticated
claimant returns the same reserved package instead of consuming another. Their internal signature and
cryptographic algorithm must be verified by the consuming client; the current server
prototype enforces ownership, uniqueness, size, count, and one-time consumption only.

HMAC authenticates a configured peer but provides no public verifiability or forward
secrecy. TLS is required outside loopback. The next federation phase adds mutually
authenticated TLS and asymmetric server identities.
