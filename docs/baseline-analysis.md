# Existing integration baseline

Reference inspected read-only:
`/home/admin/Documents/Codex/2026-09-17/home-assistant-chat` at version 0.4.5.

## Architecture

The integration separates serializable chat rules in `domain.py` from Home Assistant
storage and WebSocket adapters. Home Assistant supplies account authentication,
administrator status, user enumeration, and same-origin transport. The domain stores
channels, ciphertext messages, identities, blocks, mutes, devices, wrapped channel
keys, key requests, key commitments, seen markers, replay counters, and opaque recovery
bundles. Media ciphertext is stored separately on disk.

Its local message envelope is `ha-chat/1`. It includes a device UUID, monotonically
increasing device counter, 12-byte AES-GCM nonce, channel/epoch key ID, AAD, and an
optional channel-key commitment. The domain rejects unknown devices, stale counters,
wrong channel AAD, malformed base64, commitment conflicts, and oversized ciphertext.

## Identity and conversations

Each Home Assistant user gets a persistent random integer from 10000000 through
99999999 with a reverse uniqueness index. Private-chat lookup accepts the number and,
during migration, an exact display name. The old parser reserves
`NUMBER@HOST[:PORT]` but reports federation as unsupported. Its QR configuration also
accepts DNS names; this new project intentionally tightens the agreed federated address
format to literal IPv4 only.

Channels have `public`, `announcement`, `group`, or `private` semantics. Private
channels have exactly two members. Restricted group membership gates viewing and
posting. Announcements are visible according to policy but only administrators can
post. Users can block contacts and personally silence private chats. Administrators
can mute posting, restrict access, manage channels/devices, and optionally delete other
users' messages. Message deletion can retain a tombstone; deleting an entire private
chat removes its channel and associated crypto metadata.

## Experimental encryption and recovery

The browser generates an extractable P-256 ECDH device key pair and stores it in
IndexedDB, scoped to server and user. Each channel epoch uses an extractable AES-256-GCM
key. Devices derive an AES-GCM wrapping key from P-256 ECDH and deposit independently
wrapped channel-key offers for target devices. The server sees public keys, routing,
key IDs, commitments, and wrapped offers but not channel keys or plaintext.

Recovery exports channel keys into a JSON bundle and encrypts it with AES-GCM under a
key derived from a 43-character recovery code using PBKDF2-SHA-256 (200,000 iterations).
Only ciphertext, salt, nonce, and KDF metadata are stored server-side. Key reset uses
compare-and-swap on the observed epoch, preserving older ciphertext, but there is no
forward secrecy, post-compromise security, signed device certificate, or audited MLS
group state.

This scheme is a compatibility baseline, not a final federated cryptographic design.
In particular, server-authenticated device registration and counters do not by
themselves prove a device signature to a remote server.

## Offline delivery and attachments

Offline private delivery is possible only after recipient devices register and senders
deposit wrapped channel keys for all required recipients. Pending key requests are
bounded and expire. Recovery bundles support a new device when the user possesses its
recovery code.

Photos and videos up to 25 MiB are encrypted in the browser with the channel epoch key.
The encrypted blob is uploaded in bounded chunks; its filename, MIME type, size, ID,
and nonce are embedded inside the encrypted message metadata. The server sees encrypted
blob size, owner, channel, and message association. Per-user active/pending quotas and
a global one-GiB storage cap exist.

## Tests and roadmap carried forward

The reference tests cover migration, identities, channel policy, block/mute/delete,
replay counters, epoch reset races, key-offer conflicts, recovery validation, bounded
history/key requests/attachments, frontend storage scoping, and offline-key deposit.

Its roadmap calls for device certificates, federation, reliable delivery, server
administration, and only then optional MeshCore fallback. The new project preserves
that order while moving transport authentication and native-client support into a
dedicated backend.

