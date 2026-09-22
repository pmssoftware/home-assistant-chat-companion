# Changelog

## 0.3.1

- Automatically generate and persist a self-signed TLS certificate when the configured
  Home Assistant `/ssl` files are unavailable.
- Automatically prefer configured Supervisor-managed certificates when they appear.

## 0.3.0

- Add idempotent Home Assistant App configuration for federation peers.
- Make delivery acknowledgements explicit and receipt states monotonic.
- Add inbox progression, expiry cleanup, storage quotas, resilient bounded dispatch,
  private SQLite sidecars, safe migrations, and P-256 point validation.
- Add pinned IPv4 dialing with an optional DNS certificate name.

## 0.2.0

- Initial Home Assistant App package.
- Separate client and federation port mappings.
- Persistent `/data` database and first-admin bootstrap.
- Optional Supervisor-managed `/ssl` certificate use.
- Encrypted direct-message federation, offline queues, device packages, and receipts.
