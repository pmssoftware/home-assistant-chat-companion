"""Administrative CLI. Account and peer creation are intentionally local-only."""

from __future__ import annotations

import argparse
import getpass
import logging
import secrets
import signal
import sys
import tempfile
from pathlib import Path

from .config import ListenerConfig, ServiceConfig
from .health import probe_health
from .protocol import STORAGE_SCHEMA_VERSION
from .server import CompanionService
from .storage import Store


def _listener(value: str) -> tuple[str, int]:
    if value.count(":") != 1:
        raise argparse.ArgumentTypeError("expected IPv4:PORT")
    host, raw_port = value.rsplit(":", 1)
    try:
        port = int(raw_port)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    return host, port


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="hachat-companion")
    root.add_argument("--database", type=Path, default=Path("data/companion.sqlite3"))
    commands = root.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="run both isolated HTTP listeners")
    serve.add_argument("--client-listen", type=_listener, default=("127.0.0.1", 8210))
    serve.add_argument("--federation-listen", type=_listener, default=("127.0.0.1", 8211))
    serve.add_argument("--client-tls-cert", type=Path)
    serve.add_argument("--client-tls-key", type=Path)
    serve.add_argument("--federation-tls-cert", type=Path)
    serve.add_argument("--federation-tls-key", type=Path)
    serve.add_argument(
        "--log-level", choices=("debug", "info", "warning", "error"), default="info"
    )
    serve.add_argument(
        "--allow-insecure-client-http",
        action="store_true",
        help="explicitly allow a non-loopback client listener without TLS",
    )
    serve.add_argument(
        "--allow-insecure-federation-http",
        action="store_true",
        help="explicitly allow a non-loopback federation listener without TLS",
    )

    demo = commands.add_parser(
        "demo", help="run an ephemeral loopback test server with a temporary account"
    )
    demo.add_argument("--client-port", type=int, default=8210)
    demo.add_argument("--federation-port", type=int, default=8211)

    check = commands.add_parser("check", help="probe both listeners of a running server")
    check.add_argument("--client-url", default="http://127.0.0.1:8210")
    check.add_argument("--federation-url", default="http://127.0.0.1:8211")

    commands.add_parser("info", help="show this server's persistent identity and account count")

    account = commands.add_parser("create-account", help="create a persistent local account")
    account.add_argument("--name", required=True)
    account.add_argument("--admin", action="store_true")
    account.add_argument(
        "--password-stdin",
        action="store_true",
        help="read one password line from stdin instead of prompting",
    )

    bootstrap = commands.add_parser(
        "bootstrap-account", help="create the first admin account only when storage is empty"
    )
    bootstrap.add_argument("--name", required=True)
    bootstrap.add_argument("--password-stdin", action="store_true", required=True)

    peer = commands.add_parser("add-peer", help="authorize one IPv4 federation peer")
    peer.add_argument("--peer-id", required=True)
    peer.add_argument("--address", required=True)
    peer.add_argument("--port", required=True, type=int)
    peer.add_argument("--secret", help="shared 32-byte base64url secret; generated if omitted")
    peer.add_argument(
        "--tls-server-name",
        help="DNS certificate name to verify while dialing the pinned IPv4 endpoint",
    )
    peer.add_argument(
        "--insecure-http",
        action="store_true",
        help="allow this peer over HTTP; intended only for loopback/private testing",
    )
    configured_peer = commands.add_parser(
        "configure-peer", help="idempotently apply one operator-managed peer"
    )
    configured_peer.add_argument("--peer-id", required=True)
    configured_peer.add_argument("--address", required=True)
    configured_peer.add_argument("--port", required=True, type=int)
    configured_secret = configured_peer.add_mutually_exclusive_group(required=True)
    configured_secret.add_argument("--secret")
    configured_secret.add_argument("--secret-stdin", action="store_true")
    configured_peer.add_argument("--tls-server-name")
    configured_peer.add_argument("--insecure-http", action="store_true")
    commands.add_parser("disable-peers", help="disable every configured federation peer")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "check":
        try:
            client = probe_health(args.client_url, "client")
            federation = probe_health(args.federation_url, "federation")
        except (ConnectionError, ValueError) as error:
            print(f"Server check failed: {error}", file=sys.stderr)
            return 1
        print(f"Client listener OK: {client.url} (API {client.api_version})")
        print(f"Federation listener OK: {federation.url} (API {federation.api_version})")
        return 0
    if args.command == "info":
        store = Store(args.database)
        try:
            print(f"Server ID: {store.server_id}")
            print(f"Accounts: {store.account_count()}")
            print(f"Storage schema: {STORAGE_SCHEMA_VERSION}")
        finally:
            store.close()
        return 0
    if args.command in {"create-account", "bootstrap-account"}:
        if args.password_stdin:
            password = sys.stdin.readline().rstrip("\r\n")
        else:
            password = getpass.getpass("Password (minimum 12 bytes): ")
            if password != getpass.getpass("Confirm password: "):
                print("Passwords do not match", file=sys.stderr)
                return 2
        store = Store(args.database)
        try:
            if args.command == "bootstrap-account" and store.account_count() > 0:
                print("Bootstrap skipped: an account already exists")
                return 0
            account = store.create_account(
                args.name, password, admin=True if args.command == "bootstrap-account" else args.admin
            )
            print(f"Created {account.display_name}: {account.identity:08d}")
        finally:
            store.close()
        return 0
    if args.command == "add-peer":
        store = Store(args.database)
        try:
            peer = store.add_peer(
                args.peer_id,
                args.address,
                args.port,
                secret=args.secret,
                use_tls=not args.insecure_http,
                tls_server_name=args.tls_server_name,
            )
            print(f"Peer {peer.peer_id} at {peer.address}:{peer.port}")
            print(f"Shared secret (store securely on both peers): {peer.shared_secret}")
        finally:
            store.close()
        return 0
    if args.command == "configure-peer":
        secret = sys.stdin.readline().rstrip("\r\n") if args.secret_stdin else args.secret
        store = Store(args.database)
        try:
            peer = store.configure_peer(
                args.peer_id,
                args.address,
                args.port,
                secret=secret,
                use_tls=not args.insecure_http,
                tls_server_name=args.tls_server_name,
            )
            print(f"Configured peer {peer.peer_id} at {peer.address}:{peer.port}")
        finally:
            store.close()
        return 0
    if args.command == "disable-peers":
        store = Store(args.database)
        try:
            store.disable_all_peers()
            print("Disabled all federation peers")
        finally:
            store.close()
        return 0

    log_level = getattr(logging, getattr(args, "log_level", "info").upper())
    logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(message)s")
    temporary: tempfile.TemporaryDirectory[str] | None = None
    if args.command == "demo":
        if (
            isinstance(args.client_port, bool)
            or isinstance(args.federation_port, bool)
            or not 1 <= args.client_port <= 65535
            or not 1 <= args.federation_port <= 65535
            or args.client_port == args.federation_port
        ):
            print("Demo ports must be distinct values from 1 to 65535", file=sys.stderr)
            return 2
        temporary = tempfile.TemporaryDirectory(prefix="ha-chat-companion-demo-")
        config = ServiceConfig(
            Path(temporary.name) / "companion.sqlite3",
            ListenerConfig("127.0.0.1", args.client_port),
            ListenerConfig("127.0.0.1", args.federation_port),
        )
        service = CompanionService(config)
        password = "demo-" + secrets.token_urlsafe(18)
        account = service.store.create_account("Demo owner", password, admin=True)
        print("Home Assistant Chat companion server — ephemeral demo")
        print(f"Client endpoint:     http://127.0.0.1:{args.client_port}")
        print(f"Federation endpoint: http://127.0.0.1:{args.federation_port}")
        print(f"Demo identity:       {account.identity:08d}")
        print(f"Demo password:       {password}")
        print("All demo data is deleted when this process exits.")
        print("Run `python3 companion_server.py check` in another terminal.")
    else:
        client_host, client_port = args.client_listen
        federation_host, federation_port = args.federation_listen
        config = ServiceConfig(
            args.database,
            ListenerConfig(
                client_host,
                client_port,
                args.client_tls_cert,
                args.client_tls_key,
                args.allow_insecure_client_http,
            ),
            ListenerConfig(
                federation_host,
                federation_port,
                args.federation_tls_cert,
                args.federation_tls_key,
                args.allow_insecure_federation_http,
            ),
        )
        service = CompanionService(config)

    def stop(_signum: int, _frame: object) -> None:
        # Shutdown runs outside the signal handler's thread to avoid self-deadlock.
        import threading

        threading.Thread(target=service.request_shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    service.start()
    try:
        service.wait()
    finally:
        service.close()
        if temporary is not None:
            temporary.cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
