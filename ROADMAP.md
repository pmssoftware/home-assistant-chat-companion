# Roadmap

See [docs/architecture.md](docs/architecture.md) for design detail and phase exit
criteria.

- [x] Separate repository and read-only analysis of integration 0.4.5.
- [x] Reusable address/protocol core and strict IPv4 federated addresses.
- [x] Separate configurable client and federation listeners.
- [x] Persistent server ID, accounts, eight-digit identities, sessions, and peers.
- [x] Protocol negotiation, health/status, replay-protected peer authentication, CLI,
  prototype client, threat model, and tests.
- [x] One-command ephemeral server demo, dual-plane operator check, and hardened
  loopback-only Compose packaging.
- [ ] **Partial:** Device enrollment and one-time opaque key packages work; signed device
  certificates and verified linking remain.
- [ ] **Partial:** Versioned portable encrypted direct-message events, counters, idempotency, and
  delivered/read receipts work; canonical signatures and published vectors remain.
- [ ] **Partial:** Authenticated IPv4 federation routing and durable retries work; mTLS enrollment,
  capability negotiation, key rotation, and revocation remain.
- [ ] **Partial:** Stored one-time key packages and bounded offline queues work for direct messages;
  ratchet integration and queue administration remain.
- [ ] Private/group/announcement state, authoritative epochs, moderation, blocks, mutes,
  tombstones, and deletion replication.
- [ ] Opaque attachment relay with streaming, hashes, resumability, expiry, and quotas.
- [ ] Shared production protocol/crypto core plus desktop reference, native iOS, and
  native Android clients.
- [ ] Compatibility migrations, backup/restore, security review, and stable release.
- [ ] Only then: optional MeshCore transport of the same signed encrypted events.
