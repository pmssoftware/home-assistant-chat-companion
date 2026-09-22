# Architecture and phased plan

## Goals and invariants

The companion server has two independent network trust boundaries:

```text
native/mobile/desktop client -> client listener -> domain/event core -> SQLite
remote companion server      -> federation listener -> federation gateway -> same core
future MeshCore adapter       -> transport adapter -> authenticated portable events
```

The client and federation listeners have separate bind configuration, sockets, APIs,
protocol identifiers, credentials, and rate-limit buckets. Neither uses the Home
Assistant UI port. A deployment can place them on different network interfaces and
apply different firewall and TLS policy.

Message identity and encryption must live above transport. The eventual portable event
will have a stable event ID, origin server ID, author address, conversation ID, event
kind, logical ordering data, ciphertext envelope, expiry, and author/device signature.
HTTP delivery, retry, and later MeshCore fragmentation must not change those fields.

The server remains unable to decrypt message bodies, attachment metadata/content, or
recovery bundles. It is allowed to know the routing metadata needed for delivery and
policy enforcement. No fallback transport may substitute plaintext or a server-known
content key.

## Current modules

- Protocol/core: address parsing and version constants have no server dependency.
- Storage: SQLite transactions persist the server ID, accounts, sessions, peer secrets,
  and replay nonces. Schema changes will be monotonic migrations before stable release.
- Client gateway: local account sessions and status/account API.
- Federation gateway: explicit IPv4 peers and signed, expiring, nonce-protected requests.
- Prototype client: a reusable Python API client proving the non-HA authentication path.

The HMAC peer scheme is bootstrap-grade. Production federation will add mutually
authenticated TLS and rotated Ed25519 server signing keys. HMAC remains useful as an
additional request-integrity layer during the transition but must not become the
portable message authenticity mechanism.

## Phase 1 — foundation (implemented)

1. Create independent project and protocol/core package.
2. Persist server, account, and eight-digit identity records.
3. Start separate configurable client and federation IPv4 listeners.
4. Add version negotiation, health/status endpoints, client sessions, peer request
   authentication, replay rejection, limits, CLI administration, and tests.

## Phase 2 — authenticated devices and portable events (in progress)

1. Add Ed25519 account/device signing identities and signed server-issued device
   certificates. Bind device enrollment to an authenticated account session and require
   existing-device approval or a carefully scoped recovery ceremony.
2. Define canonical CBOR (or another single canonical encoding) for portable events.
   Sign event IDs, conversation IDs, sender address, epoch, counter, expiry, and
   ciphertext hash. Keep `ha-chat/1` import compatibility behind an explicit adapter.
3. Add idempotent event ingestion, transactional per-device counters, bounded dedupe,
   delivery acknowledgements, and tombstone semantics.
4. Add token rotation, session/device revocation, password changes, audit events, and
   administrator allow/deny/retention controls.

Implemented prototype subset: P-256 device enrollment, one-time opaque key packages,
`ha-chat/2` encrypted direct-message envelopes, monotonic device counters, durable
idempotent inbox/outbox storage, and separate delivered/read receipt events. Device
certificates, device signatures, verified linking, canonical binary encoding, and
reviewed ratchet semantics are still required before security claims can be upgraded.

Cryptographic choices will be documented with test vectors and reviewed before being
called secure. The current P-256/AES-GCM format will not be silently rebranded as a
federated protocol.

## Phase 3 — federation handshake and routing

1. Mutual server enrollment using literal IPv4 plus explicit/known default port,
   certificate fingerprint verification, and administrator approval.
2. Capability negotiation with hard protocol-version failure rather than downgrade.
3. Authenticated server keys, mTLS, key rotation/revocation, time-skew handling, outbound
   connection policy, private/reserved IP policy, and SSRF-safe dialing.
4. Route `NUMBER@IPV4[:PORT]`, exchange only required public device packages, enqueue
   signed encrypted events, retry with backoff, acknowledge idempotently, and expose
   bounded operator diagnostics.

## Phase 4 — offline queues and prekeys

1. Replace "recipient must already have received this channel key" with bounded,
   signed one-time prekey packages and signed-key replenishment.
2. Track reservation/consumption transactionally to prevent replay and key reuse.
3. Add per-account, per-peer, byte, count, age, and global quotas with explicit
   backpressure. Store ciphertext only.
4. Implement multi-device recovery and verified linking without allowing the server to
   mint a device silently. Decide whether to adopt a reviewed double-ratchet/MLS library
   rather than extending the experiment.

## Phase 5 — private/group state and policy

1. Give every conversation one authoritative home server for ordered membership and key
   epochs. Replicate signed membership, role, announcement, and deletion events.
2. Preserve block/mute behavior locally while preventing blocked delivery from becoming
   an oracle. Define federated administrator powers narrowly; one server must not gain
   plaintext or moderation authority over another server's local users.
3. Implement compare-and-swap group epoch changes, removal/rekey rules, conflict
   recovery, and history visibility. Evaluate MLS for group state and post-compromise
   security.

## Phase 6 — attachment relay

1. Stream opaque encrypted blobs on dedicated bounded endpoints with content hashes,
   resumable ranges, expiry, and transactional message linkage.
2. Apply per-user, per-peer, conversation, and global quotas before accepting bytes.
3. Prevent content-type interpretation, path traversal, decompression, and unsafe
   previews on clients. Relay encrypted bytes without re-encryption or plaintext
   metadata.

## Phase 7 — end-user applications

1. Extract test-vector-driven protocol, address, event, and crypto core APIs usable from
   Swift, Kotlin, and desktop. A memory-safe native core with stable FFI may replace the
   Python prototype after the protocol is settled.
2. Build one thin desktop/reference UI first, then native iOS and Android shells sharing
   vectors and state-machine behavior rather than duplicating protocol logic.
3. Add secure OS keystore storage, push-wakeup without plaintext, accessibility,
   background sync, safety-number verification, and deterministic recovery tests.

## Phase 8 — MeshCore adapter

Only after Internet federation is reliable, add MeshCore as a constrained transport:

- fragment and reassemble the same signed encrypted portable events;
- use independent transport acknowledgements and severe size/TTL/rate bounds;
- never perform offline key reset or authoritative group-state changes;
- queue operations that require the authoritative home server;
- surface delivery state honestly and never downgrade encryption or authentication.

## Compatibility policy

Breaking changes are allowed during the current owner-only experimental phase when they
remove architectural debt. Before roadmap completion and any stable release, add
versioned migrations, compatibility fixtures, deprecation windows, backup/restore
tests, and a published support matrix. Stable eight-digit identities and federated
addresses then become permanent data.
