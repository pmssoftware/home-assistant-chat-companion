import base64
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from hachat_companion.client import CompanionClient
from hachat_companion.config import ListenerConfig, ServiceConfig
from hachat_companion.security import new_peer_secret
from hachat_companion.server import CompanionService


PUBLIC_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "_EFaiOShryGXKUj1-JxABWtIOpjR2D7cWDyNx0hnJMI",
    "y": "n-B-Q7GXGPjWGAzfLV2oyEUpZksgBILRinwXcwlgDKY",
    "ext": True,
    "key_ops": [],
}


def envelope(device_id: str, counter: int) -> dict:
    return {
        "version": "ha-chat/2",
        "device_id": device_id,
        "counter": counter,
        "nonce": base64.b64encode(b"n" * 12).decode(),
        "key_id": "direct:test:1",
        "aad": base64.b64encode(b"test-route").decode(),
    }


class FederatedMessageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.a = CompanionService(
            ServiceConfig(
                root / "a.sqlite3",
                ListenerConfig("127.0.0.1", 0),
                ListenerConfig("127.0.0.1", 0),
            ),
            allow_ephemeral=True,
        )
        self.b = CompanionService(
            ServiceConfig(
                root / "b.sqlite3",
                ListenerConfig("127.0.0.1", 0),
                ListenerConfig("127.0.0.1", 0),
            ),
            allow_ephemeral=True,
        )
        alice = self.a.store.create_account("Alice", "alice correct horse battery", admin=True)
        bob = self.b.store.create_account("Bob", "bob correct horse battery", admin=True)
        secret = new_peer_secret()
        self.a.store.add_peer(
            self.b.store.server_id,
            "127.0.0.1",
            self.b.federation_address[1],
            secret=secret,
            use_tls=False,
        )
        self.b.store.add_peer(
            self.a.store.server_id,
            "127.0.0.1",
            self.a.federation_address[1],
            secret=secret,
            use_tls=False,
        )
        self.a.start()
        self.b.start()
        self.alice = CompanionClient(f"http://127.0.0.1:{self.a.client_address[1]}")
        self.bob = CompanionClient(f"http://127.0.0.1:{self.b.client_address[1]}")
        self.alice.login(str(alice.identity), "alice correct horse battery")
        self.bob.login(str(bob.identity), "bob correct horse battery")
        self.alice_identity = alice.identity
        self.bob_identity = bob.identity
        self.alice_device = str(uuid.uuid4())
        self.bob_device = str(uuid.uuid4())
        self.alice.register_device(self.alice_device, PUBLIC_JWK, "Alice test device")
        self.bob.register_device(self.bob_device, PUBLIC_JWK, "Bob test device")

    def tearDown(self) -> None:
        self.a.close()
        self.b.close()
        self.temp.cleanup()

    def test_remote_device_lookup_and_offline_ciphertext_delivery(self) -> None:
        bob_address = f"{self.bob_identity}@127.0.0.1:{self.b.federation_address[1]}"
        package_id = str(uuid.uuid4())
        package_payload = base64.b64encode(b"opaque-signed-prekey-package-value").decode()
        self.assertEqual(
            self.bob.upload_key_packages(
                self.bob_device,
                [{"package_id": package_id, "payload": package_payload}],
            )["added"],
            1,
        )
        lookup = self.alice.lookup_devices(bob_address)
        self.assertEqual([item["id"] for item in lookup["devices"]], [self.bob_device])
        self.assertEqual(lookup["devices"][0]["key_package"]["package_id"], package_id)
        # A retry by the same authenticated claimant returns the same reservation
        # instead of burning another one-time package.
        retried = self.alice.lookup_devices(bob_address)["devices"][0]["key_package"]
        self.assertEqual(retried["package_id"], package_id)

        sent = self.alice.send_message(
            client_event_id=str(uuid.uuid4()),
            recipient=bob_address,
            ciphertext=base64.b64encode(b"x" * 16).decode(),
            envelope=envelope(self.alice_device, 1),
        )
        self.assertEqual(sent["state"], "queued")

        deadline = time.monotonic() + 5
        inbox = []
        while time.monotonic() < deadline:
            inbox = self.bob.inbox()
            if inbox:
                break
            time.sleep(0.05)
        self.assertEqual(len(inbox), 1)
        self.assertEqual(inbox[0]["event_id"], sent["event_id"])
        self.assertEqual(inbox[0]["ciphertext"], base64.b64encode(b"x" * 16).decode())
        self.assertEqual(
            inbox[0]["sender"],
            f"{self.alice_identity}@127.0.0.1:{self.a.federation_address[1]}",
        )
        self.assertIn(
            self.alice.message_status(sent["event_id"])["state"], {"accepted", "delivered"}
        )
        self.assertEqual(self.bob.receipt(sent["event_id"], "delivered")["state"], "delivered")
        self.assertEqual(self.bob.receipt(sent["event_id"], "read")["state"], "read")
        deadline = time.monotonic() + 5
        state = None
        while time.monotonic() < deadline:
            state = self.alice.message_status(sent["event_id"])["state"]
            if state == "read":
                break
            time.sleep(0.05)
        self.assertEqual(state, "read")

    def test_device_counter_replay_is_rejected(self) -> None:
        bob_address = f"{self.bob_identity}@127.0.0.1:{self.b.federation_address[1]}"
        self.alice.send_message(
            client_event_id=str(uuid.uuid4()),
            recipient=bob_address,
            ciphertext=base64.b64encode(b"a" * 16).decode(),
            envelope=envelope(self.alice_device, 1),
        )
        with self.assertRaisesRegex(Exception, "Message could not be accepted"):
            self.alice.send_message(
                client_event_id=str(uuid.uuid4()),
                recipient=bob_address,
                ciphertext=base64.b64encode(b"b" * 16).decode(),
                envelope=envelope(self.alice_device, 1),
            )


if __name__ == "__main__":
    unittest.main()
