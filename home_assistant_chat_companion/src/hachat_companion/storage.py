"""SQLite persistence for server identity, accounts, sessions, and peers."""

from __future__ import annotations

import os
import json
import re
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .address import parse_ipv4
from .protocol import (
    MAX_ACCOUNT_EVENT_BYTES,
    MAX_ACCOUNT_EVENTS,
    MAX_INBOX_PAGE,
    MAX_OUTBOX_ATTEMPTS,
    MAX_OUTBOX_PER_PEER,
    MESSAGE_TTL_SECONDS,
    SESSION_LIFETIME_SECONDS,
    STORAGE_SCHEMA_VERSION,
)
from .security import hash_password, new_peer_secret, new_session_token, token_digest, verify_password

_PEER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$")
_TLS_NAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def _tls_name(value: str | None) -> str | None:
    if value in {None, ""}:
        return None
    if not isinstance(value, str) or not _TLS_NAME_RE.fullmatch(value):
        raise ValueError("invalid_tls_server_name")
    return value.rstrip(".").lower()


@dataclass(frozen=True, slots=True)
class Account:
    id: str
    identity: int
    display_name: str
    is_admin: bool
    enabled: bool
    created_at: int

    def public_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "identity": f"{self.identity:08d}",
            "display_name": self.display_name,
            "is_admin": self.is_admin,
            "enabled": self.enabled,
            "created_at": self.created_at,
        }


@dataclass(frozen=True, slots=True)
class Peer:
    peer_id: str
    address: str
    port: int
    shared_secret: str
    enabled: bool
    use_tls: bool = True
    tls_server_name: str | None = None


class Store:
    """Small locked connection wrapper; one instance is shared by listener threads."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        # SQLite copies the database mode to WAL/SHM sidecars. Set it before
        # enabling WAL so secrets do not briefly land in world-readable files.
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        try:
            with self._lock:
                self._connection.execute("PRAGMA foreign_keys = ON")
                self._migrate()
                self._connection.execute("PRAGMA journal_mode = WAL")
                self._connection.execute("PRAGMA busy_timeout = 5000")
        except Exception:
            self._connection.close()
            raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _migrate(self) -> None:
        metadata_exists = self._connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'metadata'"
        ).fetchone()
        if metadata_exists:
            version_row = self._connection.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
            if version_row is not None:
                try:
                    existing_version = int(version_row["value"])
                except (TypeError, ValueError) as error:
                    raise RuntimeError("invalid_database_schema_version") from error
                if existing_version > STORAGE_SCHEMA_VERSION:
                    raise RuntimeError("database_schema_is_newer_than_server")
        self._connection.executescript(
            """
            BEGIN IMMEDIATE;
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                identity INTEGER NOT NULL UNIQUE CHECK(identity BETWEEN 10000000 AND 99999999),
                display_name TEXT NOT NULL CHECK(length(display_name) BETWEEN 1 AND 80),
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL CHECK(is_admin IN (0, 1)),
                enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
                created_at INTEGER NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash BLOB PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                last_seen_at INTEGER NOT NULL
            ) STRICT;
            CREATE INDEX IF NOT EXISTS sessions_account_idx ON sessions(account_id);
            CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions(expires_at);
            CREATE TABLE IF NOT EXISTS federation_peers (
                peer_id TEXT PRIMARY KEY,
                address TEXT NOT NULL,
                port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
                shared_secret TEXT NOT NULL,
                enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),
                created_at INTEGER NOT NULL,
                UNIQUE(address, port)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS federation_nonces (
                peer_id TEXT NOT NULL REFERENCES federation_peers(peer_id) ON DELETE CASCADE,
                nonce TEXT NOT NULL,
                seen_at INTEGER NOT NULL,
                PRIMARY KEY(peer_id, nonce)
            ) STRICT;
            CREATE INDEX IF NOT EXISTS federation_nonces_seen_idx ON federation_nonces(seen_at);
            CREATE TABLE IF NOT EXISTS federation_peer_transport (
                peer_id TEXT PRIMARY KEY REFERENCES federation_peers(peer_id) ON DELETE CASCADE,
                use_tls INTEGER NOT NULL CHECK(use_tls IN (0, 1)),
                tls_server_name TEXT
            ) STRICT;
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                public_key TEXT NOT NULL,
                label TEXT NOT NULL CHECK(length(label) <= 80),
                last_counter INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
                created_at INTEGER NOT NULL
            ) STRICT;
            CREATE INDEX IF NOT EXISTS devices_account_idx ON devices(account_id);
            CREATE TABLE IF NOT EXISTS key_packages (
                package_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
                package_json TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                consumed_at INTEGER,
                claimed_by TEXT
            ) STRICT;
            CREATE INDEX IF NOT EXISTS key_packages_available_idx
                ON key_packages(device_id, consumed_at, created_at);
            CREATE TABLE IF NOT EXISTS sent_events (
                event_id TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                client_event_id TEXT NOT NULL,
                target TEXT NOT NULL,
                event_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('queued', 'accepted', 'delivered', 'read', 'failed')),
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(account_id, client_event_id)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS inbox_events (
                event_id TEXT PRIMARY KEY,
                recipient_account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                origin_server_id TEXT NOT NULL,
                event_json TEXT NOT NULL,
                accepted_at INTEGER NOT NULL,
                delivered_at INTEGER,
                read_at INTEGER
            ) STRICT;
            CREATE INDEX IF NOT EXISTS inbox_account_idx
                ON inbox_events(recipient_account_id, accepted_at, event_id);
            CREATE TABLE IF NOT EXISTS federation_outbox (
                event_id TEXT PRIMARY KEY REFERENCES sent_events(event_id) ON DELETE CASCADE,
                peer_id TEXT NOT NULL REFERENCES federation_peers(peer_id),
                event_json TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL,
                last_error TEXT
            ) STRICT;
            CREATE INDEX IF NOT EXISTS federation_outbox_due_idx
                ON federation_outbox(next_attempt_at, attempts);
            CREATE TABLE IF NOT EXISTS event_routes (
                event_id TEXT PRIMARY KEY REFERENCES sent_events(event_id) ON DELETE CASCADE,
                peer_id TEXT NOT NULL REFERENCES federation_peers(peer_id)
            ) STRICT;
            CREATE TABLE IF NOT EXISTS federation_receipt_outbox (
                receipt_id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('delivered', 'read')),
                peer_id TEXT NOT NULL REFERENCES federation_peers(peer_id),
                receipt_json TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL,
                last_error TEXT,
                UNIQUE(event_id, state, peer_id)
            ) STRICT;
            CREATE INDEX IF NOT EXISTS federation_receipt_due_idx
                ON federation_receipt_outbox(next_attempt_at, attempts);
            COMMIT;
            """
        )
        transport_columns = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(federation_peer_transport)")
        }
        if "tls_server_name" not in transport_columns:
            self._connection.execute(
                "ALTER TABLE federation_peer_transport ADD COLUMN tls_server_name TEXT"
            )
        package_columns = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(key_packages)")
        }
        if "claimed_by" not in package_columns:
            self._connection.execute("ALTER TABLE key_packages ADD COLUMN claimed_by TEXT")
        self._connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS key_packages_claimant_idx "
            "ON key_packages(device_id, claimed_by) WHERE claimed_by IS NOT NULL"
        )
        self._connection.execute(
            "INSERT INTO metadata(key, value) VALUES('schema_version', ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (str(STORAGE_SCHEMA_VERSION),),
        )
        self._connection.execute(
            "INSERT OR IGNORE INTO metadata(key, value) VALUES('server_id', ?)",
            (f"srv_{uuid.uuid4().hex}",),
        )

    @property
    def server_id(self) -> str:
        with self._lock:
            row = self._connection.execute(
                "SELECT value FROM metadata WHERE key = 'server_id'"
            ).fetchone()
        return str(row["value"])

    def account_count(self) -> int:
        with self._lock:
            row = self._connection.execute("SELECT count(*) AS count FROM accounts").fetchone()
        return int(row["count"])

    def create_account(self, display_name: str, password: str, *, admin: bool = False) -> Account:
        display_name = display_name.strip() if isinstance(display_name, str) else ""
        if not display_name or len(display_name) > 80 or any(ord(char) < 32 for char in display_name):
            raise ValueError("invalid_display_name")
        password_hash = hash_password(password)
        now = int(time.time())
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                for _ in range(128):
                    identity = secrets.randbelow(90_000_000) + 10_000_000
                    try:
                        self._connection.execute(
                            "INSERT INTO accounts(id, identity, display_name, password_hash, "
                            "is_admin, enabled, created_at) VALUES(?, ?, ?, ?, ?, 1, ?)",
                            (uuid.uuid4().hex, identity, display_name, password_hash, int(admin), now),
                        )
                    except sqlite3.IntegrityError:
                        continue
                    row = self._connection.execute(
                        "SELECT * FROM accounts WHERE identity = ?", (identity,)
                    ).fetchone()
                    self._connection.execute("COMMIT")
                    return self._account(row)
                raise RuntimeError("identity_space_exhausted")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def authenticate(self, identity: str, password: str) -> Account | None:
        if not isinstance(password, str):
            verify_password("", None)
            return None
        try:
            password_size = len(password.encode("utf-8"))
        except UnicodeError:
            password_size = 0
        if not 1 <= password_size <= 1024:
            verify_password("", None)
            return None
        if not isinstance(identity, str) or not re.fullmatch(r"[1-9][0-9]{7}", identity):
            verify_password(password, None)
            return None
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM accounts WHERE identity = ?", (int(identity),)
            ).fetchone()
        encoded = str(row["password_hash"]) if row is not None else None
        valid = verify_password(password, encoded)
        if not valid or row is None or not bool(row["enabled"]):
            return None
        return self._account(row)

    def create_session(self, account_id: str, lifetime: int = SESSION_LIFETIME_SECONDS) -> tuple[str, int]:
        token = new_session_token()
        now = int(time.time())
        expires = now + lifetime
        with self._lock:
            self._connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))
            self._connection.execute(
                "INSERT INTO sessions(token_hash, account_id, created_at, expires_at, last_seen_at) "
                "VALUES(?, ?, ?, ?, ?)",
                (token_digest(token), account_id, now, expires, now),
            )
        return token, expires

    def account_for_token(self, token: str) -> Account | None:
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return None
        now = int(time.time())
        with self._lock:
            row = self._connection.execute(
                "SELECT a.* FROM sessions s JOIN accounts a ON a.id = s.account_id "
                "WHERE s.token_hash = ? AND s.expires_at > ? AND a.enabled = 1",
                (token_digest(token), now),
            ).fetchone()
            if row is not None:
                self._connection.execute(
                    "UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?",
                    (now, token_digest(token)),
                )
        return self._account(row) if row is not None else None

    def revoke_session(self, token: str) -> None:
        try:
            digest = token_digest(token)
        except (AttributeError, UnicodeError):
            return
        with self._lock:
            self._connection.execute("DELETE FROM sessions WHERE token_hash = ?", (digest,))

    def add_peer(
        self,
        peer_id: str,
        address: str,
        port: int,
        *,
        secret: str | None = None,
        use_tls: bool = True,
        tls_server_name: str | None = None,
    ) -> Peer:
        if not isinstance(peer_id, str) or not _PEER_ID_RE.fullmatch(peer_id):
            raise ValueError("invalid_peer_id")
        address = parse_ipv4(address)
        if isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("invalid_peer_port")
        if not isinstance(use_tls, bool):
            raise ValueError("invalid_peer_transport")
        tls_server_name = _tls_name(tls_server_name)
        if not use_tls and tls_server_name is not None:
            raise ValueError("tls_name_requires_tls")
        shared_secret = secret or new_peer_secret()
        # Validate caller-provided secrets using the signing primitive's format.
        from .security import sign_federation_request

        sign_federation_request(shared_secret, "GET", "/", "0", "A" * 16)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute(
                    "INSERT INTO federation_peers(peer_id, address, port, shared_secret, enabled, created_at) "
                    "VALUES(?, ?, ?, ?, 1, ?)",
                    (peer_id, address, port, shared_secret, int(time.time())),
                )
                self._connection.execute(
                    "INSERT INTO federation_peer_transport(peer_id, use_tls, tls_server_name) "
                    "VALUES(?, ?, ?)",
                    (peer_id, int(use_tls), tls_server_name),
                )
            except sqlite3.IntegrityError as error:
                self._connection.execute("ROLLBACK")
                raise ValueError("peer_already_exists") from error
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
            else:
                self._connection.execute("COMMIT")
        return Peer(peer_id, address, port, shared_secret, True, use_tls, tls_server_name)

    def configure_peer(
        self,
        peer_id: str,
        address: str,
        port: int,
        *,
        secret: str,
        use_tls: bool = True,
        tls_server_name: str | None = None,
    ) -> Peer:
        """Create or update one operator-managed peer configuration."""
        if not isinstance(peer_id, str) or not _PEER_ID_RE.fullmatch(peer_id):
            raise ValueError("invalid_peer_id")
        address = parse_ipv4(address)
        if isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError("invalid_peer_port")
        if not isinstance(use_tls, bool):
            raise ValueError("invalid_peer_transport")
        tls_server_name = _tls_name(tls_server_name)
        if not use_tls and tls_server_name is not None:
            raise ValueError("tls_name_requires_tls")
        from .security import sign_federation_request

        sign_federation_request(secret, "GET", "/", "0", "A" * 16)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                conflict = self._connection.execute(
                    "SELECT peer_id FROM federation_peers WHERE address = ? AND port = ? "
                    "AND peer_id <> ?",
                    (address, port, peer_id),
                ).fetchone()
                if conflict is not None:
                    raise ValueError("peer_endpoint_conflict")
                self._connection.execute(
                    "INSERT INTO federation_peers(peer_id, address, port, shared_secret, enabled, created_at) "
                    "VALUES(?, ?, ?, ?, 1, ?) ON CONFLICT(peer_id) DO UPDATE SET "
                    "address = excluded.address, port = excluded.port, "
                    "shared_secret = excluded.shared_secret, enabled = 1",
                    (peer_id, address, port, secret, int(time.time())),
                )
                self._connection.execute(
                    "INSERT INTO federation_peer_transport(peer_id, use_tls, tls_server_name) "
                    "VALUES(?, ?, ?) ON CONFLICT(peer_id) DO UPDATE SET "
                    "use_tls = excluded.use_tls, tls_server_name = excluded.tls_server_name",
                    (peer_id, int(use_tls), tls_server_name),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return Peer(peer_id, address, port, secret, True, use_tls, tls_server_name)

    def get_peer(self, peer_id: str) -> Peer | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT p.*, COALESCE(t.use_tls, 1) AS use_tls, t.tls_server_name "
                "FROM federation_peers p "
                "LEFT JOIN federation_peer_transport t ON t.peer_id = p.peer_id "
                "WHERE p.peer_id = ?", (peer_id,)
            ).fetchone()
        if row is None:
            return None
        return Peer(
            str(row["peer_id"]),
            str(row["address"]),
            int(row["port"]),
            str(row["shared_secret"]),
            bool(row["enabled"]),
            bool(row["use_tls"]),
            str(row["tls_server_name"]) if row["tls_server_name"] is not None else None,
        )

    def disable_all_peers(self) -> None:
        with self._lock:
            self._connection.execute("UPDATE federation_peers SET enabled = 0")

    def resolve_peer(self, address: str, port: int | None) -> Peer | None:
        address = parse_ipv4(address)
        with self._lock:
            if port is None:
                rows = self._connection.execute(
                    "SELECT p.*, COALESCE(t.use_tls, 1) AS use_tls, t.tls_server_name "
                    "FROM federation_peers p "
                    "LEFT JOIN federation_peer_transport t ON t.peer_id = p.peer_id "
                    "WHERE p.address = ? AND p.enabled = 1", (address,)
                ).fetchall()
                if len(rows) != 1:
                    return None
                row = rows[0]
            else:
                row = self._connection.execute(
                    "SELECT p.*, COALESCE(t.use_tls, 1) AS use_tls, t.tls_server_name "
                    "FROM federation_peers p "
                    "LEFT JOIN federation_peer_transport t ON t.peer_id = p.peer_id "
                    "WHERE p.address = ? AND p.port = ? AND p.enabled = 1", (address, port)
                ).fetchone()
        if row is None:
            return None
        return Peer(
            str(row["peer_id"]), str(row["address"]), int(row["port"]),
            str(row["shared_secret"]), bool(row["enabled"]), bool(row["use_tls"]),
            str(row["tls_server_name"]) if row["tls_server_name"] is not None else None,
        )

    def record_federation_nonce(self, peer_id: str, nonce: str, seen_at: int) -> bool:
        cutoff = int(time.time()) - 600
        with self._lock:
            self._connection.execute("DELETE FROM federation_nonces WHERE seen_at < ?", (cutoff,))
            try:
                self._connection.execute(
                    "INSERT INTO federation_nonces(peer_id, nonce, seen_at) VALUES(?, ?, ?)",
                    (peer_id, nonce, seen_at),
                )
            except sqlite3.IntegrityError:
                return False
        return True

    def register_device(
        self, account_id: str, device_id: str, public_key: str, label: str
    ) -> dict[str, object]:
        now = int(time.time())
        if not isinstance(label, str) or len(label) > 80 or any(ord(char) < 32 for char in label):
            raise ValueError("invalid_device_label")
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM devices WHERE id = ?", (device_id,)
            ).fetchone()
            if row is not None:
                if row["account_id"] != account_id or row["public_key"] != public_key:
                    raise ValueError("device_key_conflict")
                if bool(row["revoked"]):
                    raise ValueError("device_revoked")
            else:
                count = self._connection.execute(
                    "SELECT count(*) AS count FROM devices WHERE account_id = ? AND revoked = 0",
                    (account_id,),
                ).fetchone()["count"]
                if int(count) >= 32:
                    raise ValueError("device_limit")
                self._connection.execute(
                    "INSERT INTO devices(id, account_id, public_key, label, created_at) "
                    "VALUES(?, ?, ?, ?, ?)",
                    (device_id, account_id, public_key, label, now),
                )
                row = self._connection.execute(
                    "SELECT * FROM devices WHERE id = ?", (device_id,)
                ).fetchone()
        return self._device_dict(row)

    def devices_for_identity(self, identity: int) -> list[dict[str, object]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT d.* FROM devices d JOIN accounts a ON a.id = d.account_id "
                "WHERE a.identity = ? AND a.enabled = 1 AND d.revoked = 0 ORDER BY d.created_at, d.id",
                (identity,),
            ).fetchall()
        return [self._device_dict(row) for row in rows]

    def add_key_packages(
        self, account_id: str, device_id: str, packages: list[dict[str, str]]
    ) -> int:
        if not 1 <= len(packages) <= 100:
            raise ValueError("invalid_key_packages")
        now = int(time.time())
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                device = self._connection.execute(
                    "SELECT id FROM devices WHERE id = ? AND account_id = ? AND revoked = 0",
                    (device_id, account_id),
                ).fetchone()
                if device is None:
                    raise ValueError("unknown_device")
                available = int(self._connection.execute(
                    "SELECT count(*) AS count FROM key_packages WHERE device_id = ? AND consumed_at IS NULL",
                    (device_id,),
                ).fetchone()["count"])
                if available + len(packages) > 100:
                    raise ValueError("key_package_limit")
                added = 0
                for package in packages:
                    encoded = json.dumps(package, sort_keys=True, separators=(",", ":"))
                    existing = self._connection.execute(
                        "SELECT device_id, package_json FROM key_packages WHERE package_id = ?",
                        (package["package_id"],),
                    ).fetchone()
                    if existing is not None:
                        if existing["device_id"] != device_id or existing["package_json"] != encoded:
                            raise ValueError("key_package_conflict")
                        continue
                    self._connection.execute(
                        "INSERT INTO key_packages(package_id, device_id, package_json, created_at) "
                        "VALUES(?, ?, ?, ?)",
                        (package["package_id"], device_id, encoded, now),
                    )
                    added += 1
                self._connection.execute("COMMIT")
                return added
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def claim_device_packages(self, identity: int, claimant: str) -> list[dict[str, object]]:
        if not isinstance(claimant, str) or not 1 <= len(claimant) <= 160:
            raise ValueError("invalid_key_package_claimant")
        now = int(time.time())
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                rows = self._connection.execute(
                    "SELECT d.* FROM devices d JOIN accounts a ON a.id = d.account_id "
                    "WHERE a.identity = ? AND a.enabled = 1 AND d.revoked = 0 "
                    "ORDER BY d.created_at, d.id",
                    (identity,),
                ).fetchall()
                result = []
                for row in rows:
                    package = self._connection.execute(
                        "SELECT package_id, package_json FROM key_packages WHERE device_id = ? "
                        "AND claimed_by = ? ORDER BY created_at, package_id LIMIT 1",
                        (row["id"], claimant),
                    ).fetchone()
                    if package is None:
                        package = self._connection.execute(
                            "SELECT package_id, package_json FROM key_packages WHERE device_id = ? "
                            "AND consumed_at IS NULL AND claimed_by IS NULL "
                            "ORDER BY created_at, package_id LIMIT 1",
                            (row["id"],),
                        ).fetchone()
                    item = self._device_dict(row)
                    item["key_package"] = json.loads(package["package_json"]) if package else None
                    if package:
                        self._connection.execute(
                            "UPDATE key_packages SET consumed_at = COALESCE(consumed_at, ?), "
                            "claimed_by = COALESCE(claimed_by, ?) WHERE package_id = ?",
                            (now, claimant, package["package_id"]),
                        )
                    result.append(item)
                self._connection.execute("COMMIT")
                return result
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def _cleanup_expired_locked(self, now: int) -> None:
        self._connection.execute(
            "DELETE FROM inbox_events WHERE "
            "CAST(json_extract(event_json, '$.expires_at') AS INTEGER) <= ?",
            (now,),
        )
        self._connection.execute(
            "DELETE FROM sent_events WHERE "
            "CAST(json_extract(event_json, '$.expires_at') AS INTEGER) <= ?",
            (now,),
        )
        self._connection.execute(
            "DELETE FROM federation_receipt_outbox WHERE attempts >= ? OR "
            "CAST(json_extract(receipt_json, '$.created_at') AS INTEGER) <= ?",
            (MAX_OUTBOX_ATTEMPTS, now - MESSAGE_TTL_SECONDS),
        )
        self._connection.execute(
            "DELETE FROM key_packages WHERE consumed_at IS NOT NULL AND consumed_at <= ?",
            (now - MESSAGE_TTL_SECONDS,),
        )
        self._connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now,))

    def _ensure_event_quota_locked(
        self, table: str, account_column: str, account_id: str, incoming_bytes: int
    ) -> None:
        if table not in {"sent_events", "inbox_events"} or account_column not in {
            "account_id", "recipient_account_id"
        }:
            raise ValueError("invalid_quota_table")
        row = self._connection.execute(
            f"SELECT count(*) AS count, COALESCE(sum(length(event_json)), 0) AS bytes "
            f"FROM {table} WHERE {account_column} = ?",
            (account_id,),
        ).fetchone()
        if int(row["count"]) >= MAX_ACCOUNT_EVENTS:
            raise ValueError("event_quota_exceeded")
        if int(row["bytes"]) + incoming_bytes > MAX_ACCOUNT_EVENT_BYTES:
            raise ValueError("event_quota_exceeded")

    def create_outgoing_event(
        self,
        *,
        account: Account,
        device_id: str,
        counter: int,
        client_event_id: str,
        target: str,
        event: dict[str, object],
        local_recipient: int | None = None,
        peer_id: str | None = None,
    ) -> tuple[dict[str, object], str, bool]:
        """Persist an outgoing event and either local-deliver or enqueue it atomically."""
        if (local_recipient is None) == (peer_id is None):
            raise ValueError("invalid_route")
        encoded = json.dumps(event, sort_keys=True, separators=(",", ":"))
        now = int(time.time())
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._cleanup_expired_locked(now)
                existing = self._connection.execute(
                    "SELECT target, event_json, state FROM sent_events "
                    "WHERE account_id = ? AND client_event_id = ?",
                    (account.id, client_event_id),
                ).fetchone()
                if existing is not None:
                    prior = json.loads(existing["event_json"])
                    comparable = ("origin_server_id", "client_event_id", "kind", "sender_number",
                                  "recipient_number", "ciphertext", "envelope")
                    if existing["target"] != target or any(prior.get(key) != event.get(key) for key in comparable):
                        raise ValueError("idempotency_conflict")
                    self._connection.execute("COMMIT")
                    return json.loads(existing["event_json"]), str(existing["state"]), True
                updated = self._connection.execute(
                    "UPDATE devices SET last_counter = ? WHERE id = ? AND account_id = ? "
                    "AND revoked = 0 AND last_counter < ?",
                    (counter, device_id, account.id, counter),
                ).rowcount
                if updated != 1:
                    device = self._connection.execute(
                        "SELECT last_counter FROM devices WHERE id = ? AND account_id = ? AND revoked = 0",
                        (device_id, account.id),
                    ).fetchone()
                    raise ValueError("replayed_message" if device is not None else "unknown_device")
                state = "accepted" if local_recipient is not None else "queued"
                self._ensure_event_quota_locked(
                    "sent_events", "account_id", account.id, len(encoded.encode("utf-8"))
                )
                self._connection.execute(
                    "INSERT INTO sent_events(event_id, account_id, client_event_id, target, event_json, "
                    "state, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                    (event["event_id"], account.id, client_event_id, target, encoded, state, now, now),
                )
                if local_recipient is not None:
                    recipient = self._connection.execute(
                        "SELECT id FROM accounts WHERE identity = ? AND enabled = 1",
                        (local_recipient,),
                    ).fetchone()
                    if recipient is None:
                        raise ValueError("recipient_not_found")
                    self._ensure_event_quota_locked(
                        "inbox_events",
                        "recipient_account_id",
                        str(recipient["id"]),
                        len(encoded.encode("utf-8")),
                    )
                    self._connection.execute(
                        "INSERT INTO inbox_events(event_id, recipient_account_id, origin_server_id, "
                        "event_json, accepted_at) VALUES(?, ?, ?, ?, ?)",
                        (event["event_id"], recipient["id"], event["origin_server_id"], encoded, now),
                    )
                else:
                    self._connection.execute(
                        "INSERT INTO event_routes(event_id, peer_id) VALUES(?, ?)",
                        (event["event_id"], peer_id),
                    )
                    self._connection.execute(
                        "INSERT INTO federation_outbox(event_id, peer_id, event_json, next_attempt_at) "
                        "VALUES(?, ?, ?, ?)",
                        (event["event_id"], peer_id, encoded, now),
                    )
                self._connection.execute("COMMIT")
                return event, state, False
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def accept_federated_event(self, peer_id: str, event: dict[str, object]) -> bool:
        """Store an authenticated remote event. Return True when it was already present."""
        encoded = json.dumps(event, sort_keys=True, separators=(",", ":"))
        now = int(time.time())
        with self._lock:
            self._cleanup_expired_locked(now)
            recipient = self._connection.execute(
                "SELECT id FROM accounts WHERE identity = ? AND enabled = 1",
                (event["recipient_number"],),
            ).fetchone()
            if recipient is None:
                raise ValueError("recipient_not_found")
            self._ensure_event_quota_locked(
                "inbox_events",
                "recipient_account_id",
                str(recipient["id"]),
                len(encoded.encode("utf-8")),
            )
            try:
                self._connection.execute(
                    "INSERT INTO inbox_events(event_id, recipient_account_id, origin_server_id, "
                    "event_json, accepted_at) VALUES(?, ?, ?, ?, ?)",
                    (event["event_id"], recipient["id"], peer_id, encoded, now),
                )
            except sqlite3.IntegrityError:
                existing = self._connection.execute(
                    "SELECT origin_server_id, event_json FROM inbox_events WHERE event_id = ?",
                    (event["event_id"],),
                ).fetchone()
                if existing and existing["origin_server_id"] == peer_id and existing["event_json"] == encoded:
                    return True
                raise ValueError("event_conflict") from None
        return False

    def inbox(self, account_id: str, limit: int = MAX_INBOX_PAGE) -> list[dict[str, object]]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_INBOX_PAGE:
            raise ValueError("invalid_limit")
        now = int(time.time())
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._cleanup_expired_locked(now)
                rows = self._connection.execute(
                    "SELECT event_json, origin_server_id, delivered_at, read_at FROM inbox_events "
                    "WHERE recipient_account_id = ? AND delivered_at IS NULL "
                    "AND CAST(json_extract(event_json, '$.expires_at') AS INTEGER) > ? "
                    "ORDER BY accepted_at, event_id LIMIT ?",
                    (account_id, now, limit),
                ).fetchall()
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return [
            {**json.loads(row["event_json"]), "delivery_state": "accepted"}
            for row in rows
        ]

    def mark_receipt(self, account_id: str, event_id: str, state: str) -> bool:
        if state not in {"delivered", "read"}:
            raise ValueError("invalid_receipt_state")
        now = int(time.time())
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                inbox_row = self._connection.execute(
                    "SELECT origin_server_id, event_json, delivered_at, read_at FROM inbox_events "
                    "WHERE recipient_account_id = ? AND event_id = ?",
                    (account_id, event_id),
                ).fetchone()
                if inbox_row is None:
                    self._connection.execute("COMMIT")
                    return False
                prior = "read" if inbox_row["read_at"] is not None else (
                    "delivered" if inbox_row["delivered_at"] is not None else "accepted"
                )
                rank = {"accepted": 0, "delivered": 1, "read": 2}
                progressed = rank[state] > rank[prior]
                if progressed:
                    if state == "read":
                        self._connection.execute(
                            "UPDATE inbox_events SET delivered_at = COALESCE(delivered_at, ?), "
                            "read_at = COALESCE(read_at, ?) WHERE recipient_account_id = ? "
                            "AND event_id = ?",
                            (now, now, account_id, event_id),
                        )
                    else:
                        self._connection.execute(
                            "UPDATE inbox_events SET delivered_at = COALESCE(delivered_at, ?) "
                            "WHERE recipient_account_id = ? AND event_id = ?",
                            (now, account_id, event_id),
                        )
                    sent_row = self._connection.execute(
                        "SELECT state FROM sent_events WHERE event_id = ?", (event_id,)
                    ).fetchone()
                    sent_rank = {"queued": 0, "failed": 0, "accepted": 1,
                                 "delivered": 2, "read": 3}
                    desired_rank = sent_rank[state]
                    if sent_row is not None and desired_rank > sent_rank[str(sent_row["state"])]:
                        self._connection.execute(
                            "UPDATE sent_events SET state = ?, updated_at = ? WHERE event_id = ?",
                            (state, now, event_id),
                        )
                    if inbox_row["origin_server_id"] != self.server_id:
                        if state == "read" and prior == "accepted":
                            self._queue_receipt_locked(
                                str(inbox_row["origin_server_id"]),
                                json.loads(inbox_row["event_json"]),
                                "delivered",
                                now,
                            )
                        self._queue_receipt_locked(
                            str(inbox_row["origin_server_id"]),
                            json.loads(inbox_row["event_json"]),
                            state,
                            now,
                        )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return True

    def due_outbox(self, limit: int = 25) -> list[dict[str, object]]:
        now = int(time.time())
        with self._lock:
            self._cleanup_expired_locked(now)
            rows = self._connection.execute(
                "SELECT event_id, peer_id, event_json, attempts FROM ("
                "SELECT event_id, peer_id, event_json, attempts, next_attempt_at, "
                "row_number() OVER (PARTITION BY peer_id ORDER BY next_attempt_at, event_id) AS rn "
                "FROM federation_outbox WHERE next_attempt_at <= ? AND attempts < ?) "
                "WHERE rn <= ? ORDER BY next_attempt_at, event_id LIMIT ?",
                (now, MAX_OUTBOX_ATTEMPTS, MAX_OUTBOX_PER_PEER, limit),
            ).fetchall()
        return [{"event_id": row["event_id"], "peer_id": row["peer_id"],
                 "event": json.loads(row["event_json"]), "attempts": int(row["attempts"])}
                for row in rows]

    def mark_outbox_delivered(self, event_id: str) -> None:
        now = int(time.time())
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute("DELETE FROM federation_outbox WHERE event_id = ?", (event_id,))
                self._connection.execute(
                    "UPDATE sent_events SET state = 'accepted', updated_at = ? WHERE event_id = ? "
                    "AND state IN ('queued', 'failed')",
                    (now, event_id),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise

    def mark_outbox_failed(self, event_id: str, attempts: int, error: str) -> None:
        now = int(time.time())
        next_attempt = now + min(300, 2 ** min(attempts, 8))
        safe_error = error[:200]
        with self._lock:
            self._connection.execute(
                "UPDATE federation_outbox SET attempts = ?, next_attempt_at = ?, last_error = ? "
                "WHERE event_id = ?",
                (attempts, next_attempt, safe_error, event_id),
            )
            if attempts >= MAX_OUTBOX_ATTEMPTS:
                self._connection.execute(
                    "UPDATE sent_events SET state = 'failed', updated_at = ? WHERE event_id = ?",
                    (now, event_id),
                )

    def delivery_status(self, account_id: str, event_id: str) -> str | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT state FROM sent_events WHERE account_id = ? AND event_id = ?",
                (account_id, event_id),
            ).fetchone()
        return str(row["state"]) if row else None

    def _queue_receipt_locked(
        self, peer_id: str, event: dict[str, object], state: str, now: int
    ) -> None:
        receipt = {
            "version": "ha-chat/2",
            "receipt_id": f"rcp_{uuid.uuid4().hex}",
            "event_id": event["event_id"],
            "state": state,
            "recipient_number": event["recipient_number"],
            "created_at": now,
        }
        encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        self._connection.execute(
            "INSERT OR IGNORE INTO federation_receipt_outbox(receipt_id, event_id, state, "
            "peer_id, receipt_json, next_attempt_at) VALUES(?, ?, ?, ?, ?, ?)",
            (receipt["receipt_id"], receipt["event_id"], state, peer_id, encoded, now),
        )

    def due_receipts(self, limit: int = 25) -> list[dict[str, object]]:
        now = int(time.time())
        with self._lock:
            self._cleanup_expired_locked(now)
            rows = self._connection.execute(
                "SELECT receipt_id, peer_id, receipt_json, attempts FROM ("
                "SELECT receipt_id, peer_id, receipt_json, attempts, next_attempt_at, "
                "row_number() OVER (PARTITION BY peer_id ORDER BY next_attempt_at, receipt_id) AS rn "
                "FROM federation_receipt_outbox r WHERE next_attempt_at <= ? AND attempts < ? "
                "AND NOT (state = 'read' AND EXISTS ("
                "SELECT 1 FROM federation_receipt_outbox d WHERE d.event_id = r.event_id "
                "AND d.peer_id = r.peer_id AND d.state = 'delivered'))) "
                "WHERE rn <= ? ORDER BY next_attempt_at, receipt_id LIMIT ?",
                (now, MAX_OUTBOX_ATTEMPTS, MAX_OUTBOX_PER_PEER, limit),
            ).fetchall()
        return [{"receipt_id": row["receipt_id"], "peer_id": row["peer_id"],
                 "receipt": json.loads(row["receipt_json"]), "attempts": int(row["attempts"])}
                for row in rows]

    def mark_receipt_outbox_delivered(self, receipt_id: str) -> None:
        with self._lock:
            self._connection.execute(
                "DELETE FROM federation_receipt_outbox WHERE receipt_id = ?", (receipt_id,)
            )

    def mark_receipt_outbox_failed(self, receipt_id: str, attempts: int, error: str) -> None:
        next_attempt = int(time.time()) + min(300, 2 ** min(attempts, 8))
        with self._lock:
            self._connection.execute(
                "UPDATE federation_receipt_outbox SET attempts = ?, next_attempt_at = ?, last_error = ? "
                "WHERE receipt_id = ?",
                (attempts, next_attempt, error[:200], receipt_id),
            )

    def accept_federated_receipt(self, peer_id: str, receipt: dict[str, object]) -> bool:
        desired = str(receipt["state"])
        with self._lock:
            row = self._connection.execute(
                "SELECT s.state, s.event_json FROM sent_events s "
                "JOIN event_routes r ON r.event_id = s.event_id "
                "WHERE s.event_id = ? AND r.peer_id = ?",
                (receipt["event_id"], peer_id),
            ).fetchone()
            if row is None:
                raise ValueError("event_not_found")
            event = json.loads(row["event_json"])
            if event.get("recipient_number") != receipt.get("recipient_number"):
                raise ValueError("receipt_conflict")
            current = str(row["state"])
            rank = {"queued": 0, "accepted": 1, "delivered": 2, "read": 3, "failed": 0}
            if rank[desired] > rank[current]:
                self._connection.execute(
                    "UPDATE sent_events SET state = ?, updated_at = ? WHERE event_id = ?",
                    (desired, int(time.time()), receipt["event_id"]),
                )
                return False
        return True

    @staticmethod
    def _device_dict(row: sqlite3.Row) -> dict[str, object]:
        return {"id": str(row["id"]), "public_key": str(row["public_key"]),
                "label": str(row["label"]), "created_at": int(row["created_at"])}

    @staticmethod
    def _account(row: sqlite3.Row) -> Account:
        return Account(
            str(row["id"]),
            int(row["identity"]),
            str(row["display_name"]),
            bool(row["is_admin"]),
            bool(row["enabled"]),
            int(row["created_at"]),
        )
