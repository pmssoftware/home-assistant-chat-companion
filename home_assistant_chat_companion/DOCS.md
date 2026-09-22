# Home Assistant Chat Companion

This experimental Home Assistant App runs the companion backend used by Home Assistant
Chat clients and federated servers. It does not replace the Home Assistant Chat
integration or provide another chat interface.

## Before first start

Set `bootstrap_admin_password` to a unique password of at least 12 characters. The App
creates one administrator account only when its persistent database is empty. Its
eight-digit identity and the persistent `srv_...` federation server ID appear in the
App log after startup.

The bootstrap password remains in the App configuration so the same configuration can
restart cleanly; it is ignored after the first account exists. Treat App configuration
and backups as sensitive.

TLS is enabled by default. If the selected certificate and key do not exist in `/ssl`,
the App automatically creates a persistent self-signed certificate in `/data`; no
manual file copying is required. Clients must explicitly trust that certificate. When
the configured `/ssl` files become available, the App automatically uses them after a
restart. For an isolated LAN-only test without TLS, disable `ssl` and explicitly
enable `allow_insecure_test_http`; clients must opt in to plaintext HTTP as well.

## Network

- `8210/tcp` is the separate native/local client API.
- `8211/tcp` is the server-to-server federation API.

Neither service uses the normal Home Assistant UI port. In the App's **Network** panel,
keep both ports on a trusted network during testing. Federation addresses use literal
IPv4 only: `NUMBER@IPV4[:PORT]`.

Configure federation peers in the App's `federation_peers` list. On both servers, enter
the other server's exact `srv_...` ID, pinned IPv4 endpoint, port, and the same 256-bit
base64url shared secret. Generate one on a trusted machine with
`python3 -c 'import secrets; print(secrets.token_urlsafe(32))'`.

For a DNS certificate, set `tls_server_name` to the certificate name while leaving
`address` as the pinned IPv4 destination. Set `insecure_http: true` only for isolated
testing. Removing a peer from the list disables it on the next restart. Automatic
discovery remains intentionally absent.

Example peer entry:

```yaml
- peer_id: srv_0123456789abcdef0123456789abcdef
  address: 192.0.2.20
  port: 8211
  shared_secret: REPLACE_WITH_43_CHARACTER_BASE64URL_SECRET
  insecure_http: false
  tls_server_name: chat.example.net
```

## Current test scope

The App currently supports persistent accounts and identities, client sessions, device
enrollment, one-time opaque key packages, encrypted direct-message envelopes, durable
offline queues, server-to-server retry, and accepted/delivered/read receipts.

Groups, announcements, attachment relay, deletion replication, block/mute policy,
verified device certificates, and production mTLS enrollment remain experimental work.

Do not use this version for emergency or sensitive communication.
