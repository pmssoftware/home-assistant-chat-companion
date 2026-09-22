import base64
import json
import os
import sqlite3
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from hachat_companion.address import parse_user_address
from hachat_companion.events import ClientMessage, build_federated_event, validate_public_jwk
from hachat_companion.protocol import MESSAGE_TTL_SECONDS
from hachat_companion.storage import Store


PUBLIC_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "_EFaiOShryGXKUj1-JxABWtIOpjR2D7cWDyNx0hnJMI",
    "y": "n-B-Q7GXGPjWGAzfLV2oyEUpZksgBILRinwXcwlgDKY",
    "ext": True,
    "key_ops": [],
}


class RegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "companion.sqlite3"
        self.store = Store(self.path)
        self.sender = self.store.create_account("Sender", "sender audit password")
        self.recipient = self.store.create_account("Recipient", "recipient audit password")
        self.device_id = str(uuid.uuid4())
        self.store.register_device(
            self.sender.id,
            self.device_id,
            validate_public_jwk(PUBLIC_JWK),
            "Sender device",
        )

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def _put(self, counter: int, *, now: int | None = None) -> dict[str, object]:
        message = ClientMessage(
            str(uuid.uuid4()),
            parse_user_address(str(self.recipient.identity)),
            base64.b64encode(b"x" * 16).decode(),
            {
                "version": "ha-chat/2",
                "device_id": self.device_id,
                "counter": counter,
                "nonce": base64.b64encode(b"n" * 12).decode(),
                "key_id": "regression-test",
                "aad": base64.b64encode(b"route").decode(),
            },
        )
        event = build_federated_event(
            server_id=self.store.server_id,
            sender_number=self.sender.identity,
            message=message,
            now=now,
        )
        self.store.create_outgoing_event(
            account=self.sender,
            device_id=self.device_id,
            counter=counter,
            client_event_id=message.client_event_id,
            target=str(self.recipient.identity),
            event=event,
            local_recipient=self.recipient.identity,
        )
        return event

    def test_inbox_pages_progress_and_local_receipts_are_monotonic(self) -> None:
        events = [self._put(counter) for counter in range(1, 52)]
        first = self.store.inbox(self.recipient.id)
        self.assertEqual(len(first), 50)
        for event in first:
            self.assertTrue(self.store.mark_receipt(
                self.recipient.id, str(event["event_id"]), "delivered"
            ))
        second = self.store.inbox(self.recipient.id)
        self.assertEqual(len(second), 1)
        self.assertEqual(
            len({str(event["event_id"]) for event in first + second}), 51
        )
        event_id = str(events[0]["event_id"])
        self.assertEqual(self.store.delivery_status(self.sender.id, event_id), "delivered")
        self.store.mark_receipt(self.recipient.id, event_id, "read")
        self.store.mark_receipt(self.recipient.id, event_id, "delivered")
        self.assertEqual(self.store.delivery_status(self.sender.id, event_id), "read")

    def test_expired_events_are_removed_before_delivery(self) -> None:
        event = self._put(1, now=int(time.time()) - MESSAGE_TTL_SECONDS - 1)
        self.assertEqual(self.store.inbox(self.recipient.id), [])
        self.assertIsNone(self.store.delivery_status(self.sender.id, str(event["event_id"])))

    def test_invalid_curve_point_is_rejected(self) -> None:
        invalid = {**PUBLIC_JWK, "x": "A" * 43, "y": "A" * 43}
        with self.assertRaisesRegex(ValueError, "invalid_device_key"):
            validate_public_jwk(invalid)

    def test_sqlite_sidecars_are_private(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX permission assertion")
        self.store._connection.execute("CREATE TABLE permission_probe(value INTEGER)")
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.path) + suffix)
            if path.exists():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class MigrationSafetyTests(unittest.TestCase):
    def test_newer_database_is_not_modified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "future.sqlite3"
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            connection.execute("INSERT INTO metadata VALUES('schema_version', '999')")
            connection.commit()
            connection.close()
            with self.assertRaisesRegex(RuntimeError, "database_schema_is_newer"):
                Store(path)
            connection = sqlite3.connect(path)
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            connection.close()
            self.assertEqual(tables, {"metadata"})


if __name__ == "__main__":
    unittest.main()
