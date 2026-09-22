# Threat model

Status: experimental foundation, September 2026. This is an engineering threat model,
not a security audit.

## Protected assets

- Account credentials, session tokens, device private keys, recovery secrets, channel
  keys, and future server signing keys.
- Message and attachment plaintext and integrity.
- Correct binding between eight-digit identities, devices, servers, and conversations.
- Group membership/epoch ordering, deletion intent, block/mute policy, offline queues,
  and service availability within configured limits.

## Trust boundaries

Clients trust their own device runtime and eventually a verified device/core build.
They trust the home server for account membership, metadata routing, quotas, and policy,
but not for plaintext. Federation peers are mutually untrusted until explicitly enrolled
and cryptographically authenticated. Network paths, DNS, reverse proxies, attachments,
all request fields, peer events, clocks, and future MeshCore frames are untrusted.

The operator and host OS can observe metadata and control availability. A malicious
server or client must not be able to forge another device's portable signed event or
decrypt content, though this property is not implemented in the foundation slice yet.

## Current controls

- Separate sockets and protocol identifiers prevent accidental client/federation route
  sharing. Listeners accept IPv4 configuration only.
- Passwords use salted scrypt; bearer tokens carry 256 bits of randomness and only
  their digests are persisted. The database is chmod 0600 where supported.
- Federation calls bind method, exact path, timestamp, nonce, and body hash under a
  256-bit peer secret. Nonces are persisted and single-use; peer source IP is checked.
- Direct-message ciphertext is bounded, tied to an enrolled device and monotonic
  counter, durably queued, idempotent by event ID, and expired after 30 days. One-time
  opaque key packages are transactionally consumed.
- Delivered and read states are separate monotonic receipt events. Federation receipts
  are peer-authenticated and retryable; device-signed receipts remain future work.
- JSON bodies, fields, identities, names, secrets, ports, clocks, timeouts, listener
  backlog, rate-limit keys, authentication attempts, and session lifetimes are bounded.
- SQLite constraints and transactions enforce uniqueness and replay insertion.
- Errors do not reveal whether an account or peer exists. Responses are non-cacheable.

## Threats and planned mitigations

**Credential theft and brute force.** TLS is mandatory outside loopback, login attempts
are rate limited, and passwords are memory-hard. Add password changes, session inventory,
device-bound tokens, optional platform passkeys, stronger distributed throttling, and
operator alerts.

**Peer spoofing, replay, downgrade, and request tampering.** Current HMAC and nonces
address a single server but shared secrets are hard to rotate and compromise either
side. Add mTLS, pinned server signing keys, signed capability negotiation, rotation and
revocation, durable outbound counters, and no downgrade path.

**Malicious server or enrolled device.** The baseline browser scheme does not provide
federated author signatures, forward secrecy, or post-compromise security. Add signed
device certificates, verified enrollment, canonical signed events, one-time prekeys,
and a reviewed ratchet/MLS design. Never give a server content keys.

**Replay, reordering, duplication, and equivocation.** Add signed event IDs, per-device
counters, bounded dedupe, expiry, acknowledgements, authoritative conversation ordering,
and client detection of conflicting group/epoch statements. Current HTTP request replay
protection is necessary but not sufficient for message replay protection.

**SSRF and unsafe peer dialing.** Outbound federation dials only an explicitly configured
literal IPv4 address and port, does not follow redirects, and can verify a separately
configured TLS DNS name without changing the pinned destination. Operators remain
responsible for approving private/reserved destinations.

**Resource exhaustion.** Extend current limits with durable per-account/per-peer message,
prekey, attachment, bandwidth, concurrency, and disk quotas; bounded cleanup; admission
control; retry backoff; and metrics that contain no secrets. SQLite has a practical
single-writer ceiling that must be measured.

**Input and attachment attacks.** Treat event bodies and blobs as opaque bounded bytes.
Use canonical parsers, reject unknown fields by version, stream to non-executable storage,
verify ciphertext hashes, never trust filenames/MIME, and sandbox client previews.

**Deletion and backups.** Deletion is a signed state transition and cannot guarantee
removal from remote devices or backups. Clients must communicate that limitation. Key
erasure may improve future confidentiality but cannot retract plaintext already seen.

**Metadata privacy and traffic analysis.** Servers necessarily see identities, peers,
conversation routing, timing, sizes, devices, and IP addresses in the initial design.
Document this honestly; minimize retention, pad only through an explicit future protocol,
and avoid logging credentials, plaintext, ciphertext, or full user addresses.

**MeshCore downgrade or split brain.** The adapter may carry only already authorized,
signed, encrypted events. It cannot reset keys or invent authoritative group state while
offline. Size constraints, fragmentation, replay, jamming, and stale delivery need their
own review before enablement.

## Known foundation gaps

- TLS is not automatically provisioned. A non-loopback plain-HTTP bind requires an
  explicit unsafe override intended for a same-host TLS proxy; operators must not expose
  it directly.
- Federation uses shared HMAC secrets rather than mTLS/asymmetric server identities.
- The HTTP server is suitable for a prototype, not Internet hardening or load.
- Account recovery, device enrollment, audit logs, secret rotation, and backup tooling
  are absent.
- Direct opaque-message routing and key-package exchange now exist, but the server does
  not yet verify device signatures or implement a reviewed ratchet. Group, attachment,
  deletion, block/mute, and full policy endpoints remain absent.
