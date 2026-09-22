"""Disposable two-server federation acceptance test for operators."""

from __future__ import annotations

import base64
import secrets
import tempfile
import time
import uuid
from pathlib import Path

from .client import CompanionClient
from .config import ListenerConfig, ServiceConfig
from .security import new_peer_secret
from .server import CompanionService

_TEST_JWK = {
    "kty": "EC",
    "crv": "P-256",
    "x": "_EFaiOShryGXKUj1-JxABWtIOpjR2D7cWDyNx0hnJMI",
    "y": "n-B-Q7GXGPjWGAzfLV2oyEUpZksgBILRinwXcwlgDKY",
    "ext": True,
    "key_ops": [],
}


def _service(path: Path) -> CompanionService:
    return CompanionService(
        ServiceConfig(
            path,
            ListenerConfig("127.0.0.1", 0),
            ListenerConfig("127.0.0.1", 0),
        ),
        allow_ephemeral=True,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="ha-chat-federation-test-") as directory:
        root = Path(directory)
        first, second = _service(root / "first.sqlite3"), _service(root / "second.sqlite3")
        try:
            alice = first.store.create_account("Alice", "alice federation test password", admin=True)
            bob = second.store.create_account("Bob", "bob federation test password", admin=True)
            shared_secret = new_peer_secret()
            first.store.add_peer(
                second.store.server_id,
                "127.0.0.1",
                second.federation_address[1],
                secret=shared_secret,
                use_tls=False,
            )
            second.store.add_peer(
                first.store.server_id,
                "127.0.0.1",
                first.federation_address[1],
                secret=shared_secret,
                use_tls=False,
            )
            first.start()
            second.start()
            alice_client = CompanionClient(f"http://127.0.0.1:{first.client_address[1]}")
            bob_client = CompanionClient(f"http://127.0.0.1:{second.client_address[1]}")
            alice_client.login(str(alice.identity), "alice federation test password")
            bob_client.login(str(bob.identity), "bob federation test password")
            alice_device, bob_device = str(uuid.uuid4()), str(uuid.uuid4())
            alice_client.register_device(alice_device, _TEST_JWK, "Alice self-test")
            bob_client.register_device(bob_device, _TEST_JWK, "Bob self-test")
            package_id = str(uuid.uuid4())
            bob_client.upload_key_packages(
                bob_device,
                [{"package_id": package_id,
                  "payload": base64.b64encode(secrets.token_bytes(48)).decode()}],
            )
            address = f"{bob.identity}@127.0.0.1:{second.federation_address[1]}"
            devices = alice_client.lookup_devices(address)["devices"]
            if not devices or devices[0].get("key_package", {}).get("package_id") != package_id:
                raise RuntimeError("remote_key_package_lookup_failed")
            sent = alice_client.send_message(
                client_event_id=str(uuid.uuid4()),
                recipient=address,
                ciphertext=base64.b64encode(secrets.token_bytes(32)).decode(),
                envelope={
                    "version": "ha-chat/2",
                    "device_id": alice_device,
                    "counter": 1,
                    "nonce": base64.b64encode(secrets.token_bytes(12)).decode(),
                    "key_id": "self-test:1",
                    "aad": base64.b64encode(b"federation-self-test").decode(),
                },
            )
            deadline = time.monotonic() + 8
            inbox = []
            while time.monotonic() < deadline:
                inbox = bob_client.inbox()
                if inbox:
                    break
                time.sleep(0.05)
            if not inbox or inbox[0]["event_id"] != sent["event_id"]:
                raise RuntimeError("federated_delivery_failed")
            bob_client.receipt(sent["event_id"], "delivered")
            bob_client.receipt(sent["event_id"], "read")
            state = None
            while time.monotonic() < deadline:
                state = alice_client.message_status(sent["event_id"])["state"]
                if state == "read":
                    break
                time.sleep(0.05)
            if state != "read":
                raise RuntimeError("read_receipt_failed")
            print("PASS: two companion servers authenticated each other")
            print("PASS: remote one-time key package was claimed")
            print("PASS: opaque encrypted envelope was queued and delivered")
            print("PASS: delivered/read receipt returned to the sender")
            print(f"Event: {sent['event_id']}")
            return 0
        finally:
            first.close()
            second.close()


if __name__ == "__main__":
    raise SystemExit(main())
