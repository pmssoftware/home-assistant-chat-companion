# Home Assistant Chat Companion

Experimental companion backend for Home Assistant Chat federation and standalone
clients. This repository is deliberately separate from the existing Home Assistant
integration and does not modify it.

[![Add this repository to Home Assistant](https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg)](https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fpmssoftware%2Fhome-assistant-chat-companion)

## Add to Home Assistant OS

Once this GitHub repository is public, click the button above. Home Assistant opens the
App repository dialog with this repository pre-filled. Add it, close the dialog, then
select **Home Assistant Chat Companion** from **Settings → Apps → App store** and choose
**Install**.

Repository URL for manual installation:

```text
https://github.com/pmssoftware/home-assistant-chat-companion
```

Before the first start, configure a bootstrap password and either select working TLS
certificate files; if they are unavailable, the App automatically generates and
persists a self-signed certificate. Alternatively, explicitly enable insecure HTTP
for an isolated test LAN. The
complete peer and network setup is documented in
[`home_assistant_chat_companion/DOCS.md`](home_assistant_chat_companion/DOCS.md).

## Test as a local Home Assistant App

This repository now contains the self-contained Home Assistant App folder
`home_assistant_chat_companion`, following the same Supervisor packaging model as
HTTPS Onboarding.

For local testing on Home Assistant OS or Supervised:

1. Copy the `home_assistant_chat_companion` folder into `/addons` using the SSH or
   Samba App.
2. Open **Settings → Apps → App store** and select **Check for updates** from the
   three-dot menu.
3. Install **Home Assistant Chat Companion** from **Local apps**.
4. In its Configuration tab, set an initial administrator password of at least 12
   characters and choose TLS or explicitly enable isolated-LAN test HTTP.
5. Review the two independent port mappings under **Network**, then start the App.
6. Open its logs to find the assigned eight-digit administrator identity and persistent
   `srv_...` federation server ID.

Port `8210/tcp` is for messenger/native clients. Port `8211/tcp` is exclusively for
server federation. Neither reuses Home Assistant's normal UI port. Detailed App-specific
instructions are in `home_assistant_chat_companion/DOCS.md`.

The current federation prototype is runnable now:

- separate IPv4 client and federation listeners;
- persistent server identity and eight-digit user identities in SQLite;
- local account creation, scrypt password verification, expiring bearer sessions,
  logout, and authenticated account/status APIs;
- explicitly versioned client, federation, and portable message protocols;
- authenticated federation status using a configured peer, request HMAC, timestamp,
  and persistent one-use nonce;
- strict JSON shapes and body bounds, rate limits, database permissions, and TLS
  configuration hooks;
- a small reusable Python client and end-to-end tests;
- P-256 device enrollment and one-time opaque key-package exchange;
- durable local and federated opaque ciphertext delivery with retry; and
- distinct accepted, delivered, and read states propagated as receipt events.

It routes encrypted direct-message envelopes but does not encrypt or decrypt them;
encryption belongs to the messenger/client. Groups, attachments, full moderation,
device signatures, and native apps remain in [ROADMAP.md](ROADMAP.md). This prototype
is unaudited and must not be used for sensitive or emergency messaging.

## Technology choice

The prototype uses Python 3.12+ and SQLite with no third-party runtime dependency.
That makes it easy to run on small Home Assistant-adjacent systems while keeping the
address parser, protocol constants, authentication primitives, storage, and client
library reusable. The listeners can move to a production ASGI or Rust implementation
without changing the portable event or encryption formats.

SQLite is suitable for one owner-operated server and gives transactional identities,
sessions, replay nonces, migrations, and later offline queues. It is not presented as
the final high-scale federation store.

## Fast test run

The companion server itself is the application. Start a disposable instance with:

```bash
python3 companion_server.py demo
```

This starts isolated client and federation listeners on `127.0.0.1:8210` and
`127.0.0.1:8211`, creates a temporary account, and prints its test credentials. All
demo data disappears when the process exits. In another terminal, verify both planes:

```bash
python3 companion_server.py check
```

The demo proves server startup, plane separation, storage, identity allocation, and
health APIs. It is not a chat UI; use the federation acceptance test below to exercise
cross-server delivery.

Run the complete disposable two-server federation acceptance test with:

```bash
python3 federation_test.py
```

It starts two isolated servers on random loopback ports, enrolls accounts/devices,
claims a one-time opaque key package, routes an opaque encrypted envelope, and verifies
that delivered/read receipts return to the sender. The payload is intentionally opaque:
the server never receives a plaintext message or content key.

## Persistent local run

All commands below run from this repository root.

```bash
export PYTHONPATH=src
python3 -m hachat_companion --database data/companion.sqlite3 create-account \
  --name Owner --admin
python3 -m hachat_companion --database data/companion.sqlite3 serve \
  --client-listen 127.0.0.1:8210 \
  --federation-listen 127.0.0.1:8211
```

The account command prompts twice for a password of at least 12 UTF-8 bytes and then
prints the assigned eight-digit identity. In a second terminal, exercise the client
API with:

```bash
export PYTHONPATH=src
python3 -m hachat_companion.client --server http://127.0.0.1:8210 \
  --identity YOUR_EIGHT_DIGIT_ID
```

For a deliberately plaintext Home Assistant App on an isolated LAN, use an `http://`
App address together with `--allow-insecure-http`. Remote HTTP remains rejected unless
that explicit test flag is present.

## Container test run

When Docker or Podman Compose is available:

```bash
docker compose build
docker compose run --rm companion create-account --name Owner --admin
docker compose up
```

The Compose configuration stores the database in a named volume, runs as an unprivileged
user with all Linux capabilities dropped, and publishes both container listeners only
on host loopback. TLS should be added before changing those host bindings to a LAN or
public address.

Plain HTTP is accepted by the prototype client only for loopback. For a LAN or public
deployment, configure `--client-tls-cert/--client-tls-key` and
`--federation-tls-cert/--federation-tls-key`, or terminate TLS at separate hardened
proxies. A non-loopback listener without its own certificate is rejected unless the
corresponding `--allow-insecure-*-http` flag is deliberately supplied (for example,
behind a same-host TLS proxy). Never publish the normal Home Assistant UI port as a
federation endpoint.

To inspect a server's persistent federation ID:

```bash
python3 companion_server.py --database data/companion.sqlite3 info
```

Add the other server on each side using its exact `srv_...` ID, IPv4 federation
endpoint, and the same shared secret. `--tls-server-name` may name a DNS certificate
while the connection remains pinned to the configured IPv4 endpoint:

```bash
export PYTHONPATH=src
python3 -m hachat_companion --database data/companion.sqlite3 add-peer \
  --peer-id srv_0123456789abcdef0123456789abcdef \
  --address 192.0.2.20 --port 8211 --tls-server-name chat.example.net
```

The first command generates and displays a shared secret once. Transfer it through a
separate secure channel and supply it with `--secret` when adding the reverse peer.
Use `--insecure-http` only for deliberate loopback/private testing. Both peers must be
configured explicitly; ambient discovery and DNS are not used.

## Test

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The API tests bind two loopback ports. Sandboxed environments may need permission to
open local sockets.

## Repository map

- `src/hachat_companion/address.py`: canonical `NUMBER` / `NUMBER@IPV4[:PORT]` parser.
- `src/hachat_companion/protocol.py`: version and bounded-input constants.
- `src/hachat_companion/storage.py`: SQLite schema and persistent state.
- `src/hachat_companion/security.py`: sessions, passwords, and signed peer requests.
- `src/hachat_companion/api.py`: plane-specific APIs and authentication boundaries.
- `src/hachat_companion/client.py`: reusable first-slice client.
- `src/hachat_companion/health.py`: bounded role-aware operator health probes.
- `companion_server.py`: source-checkout launcher for demo, checks, and persistent use.
- `federation_test.py`: one-command two-server federation acceptance test.
- `Dockerfile` and `compose.yaml`: isolated test deployment of the server application.
- `docs/architecture.md`: target architecture and phased implementation plan.
- `docs/protocol.md`: currently implemented wire contract.
- `docs/threat-model.md`: assets, trust boundaries, threats, and known gaps.
- `docs/baseline-analysis.md`: behavior inherited from the existing integration.
