import os
import tempfile
import time
import unittest
from pathlib import Path

from hachat_companion.storage import Store
from hachat_companion.security import new_peer_secret


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "companion.sqlite3"
        self.store = Store(self.path)

    def tearDown(self) -> None:
        self.store.close()
        self.temp.cleanup()

    def test_identity_account_and_session_persist(self) -> None:
        account = self.store.create_account(
            "Owner", "correct horse battery staple", admin=True
        )
        self.assertRegex(str(account.identity), r"^[1-9][0-9]{7}$")
        authenticated = self.store.authenticate(
            str(account.identity), "correct horse battery staple"
        )
        self.assertEqual(authenticated, account)
        self.assertIsNone(self.store.authenticate(str(account.identity), "wrong password"))
        token, _ = self.store.create_session(account.id)
        server_id = self.store.server_id
        self.store.close()

        self.store = Store(self.path)
        self.assertEqual(self.store.server_id, server_id)
        self.assertEqual(self.store.account_for_token(token), account)
        self.assertEqual(self.store.account_count(), 1)
        if os.name == "posix":
            self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_peer_nonce_is_single_use_and_peer_is_ipv4_only(self) -> None:
        peer = self.store.add_peer("peer-one", "127.0.0.1", 8211)
        self.assertEqual(self.store.get_peer("peer-one"), peer)
        now = int(time.time())
        self.assertTrue(self.store.record_federation_nonce("peer-one", "A" * 16, now))
        self.assertFalse(self.store.record_federation_nonce("peer-one", "A" * 16, now))
        with self.assertRaises(ValueError):
            self.store.add_peer("peer-two", "example.org", 8211)

    def test_configured_peer_can_be_updated_and_disabled(self) -> None:
        secret = new_peer_secret()
        peer = self.store.configure_peer(
            "srv_0123456789abcdef0123456789abcdef",
            "192.0.2.20",
            8211,
            secret=secret,
            tls_server_name="Chat.Example.NET",
        )
        self.assertEqual(peer.tls_server_name, "chat.example.net")
        updated = self.store.configure_peer(
            peer.peer_id,
            "192.0.2.21",
            9443,
            secret=secret,
            tls_server_name="chat.example.net",
        )
        self.assertEqual((updated.address, updated.port), ("192.0.2.21", 9443))
        self.store.disable_all_peers()
        self.assertFalse(self.store.get_peer(peer.peer_id).enabled)


if __name__ == "__main__":
    unittest.main()
