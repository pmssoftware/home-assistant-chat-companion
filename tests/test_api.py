import json
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from hachat_companion.client import ClientError, CompanionClient
from hachat_companion.config import ListenerConfig, ServiceConfig
from hachat_companion.health import probe_health
from hachat_companion.protocol import CLIENT_PROTOCOL, FEDERATION_PROTOCOL, PROTOCOL_HEADER
from hachat_companion.security import sign_federation_request
from hachat_companion.server import CompanionService


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        config = ServiceConfig(
            Path(self.temp.name) / "companion.sqlite3",
            ListenerConfig("127.0.0.1", 0),
            ListenerConfig("127.0.0.1", 0),
        )
        self.service = CompanionService(config, allow_ephemeral=True)
        self.account = self.service.store.create_account(
            "Owner", "correct horse battery staple", admin=True
        )
        self.peer = self.service.store.add_peer("peer-one", "127.0.0.1", 8211)
        self.service.start()
        self.client_url = f"http://127.0.0.1:{self.service.client_address[1]}"
        self.federation_url = f"http://127.0.0.1:{self.service.federation_address[1]}"

    def tearDown(self) -> None:
        self.service.close()
        self.temp.cleanup()

    def request(self, base, method, path, *, headers=None, payload=None):
        body = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            base + path,
            data=body,
            method=method,
            headers={"Content-Type": "application/json", **(headers or {})},
        )
        try:
            with urllib.request.urlopen(request, timeout=3) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                return error.code, json.loads(error.read())
            finally:
                error.close()

    def test_separate_health_endpoints_report_their_plane(self) -> None:
        status, client = self.request(self.client_url, "GET", "/healthz")
        self.assertEqual((status, client["service"]), (200, "client"))
        status, federation = self.request(self.federation_url, "GET", "/healthz")
        self.assertEqual((status, federation["service"]), (200, "federation"))
        self.assertNotEqual(self.service.client_address, self.service.federation_address)

    def test_operator_health_probe_validates_both_listener_roles(self) -> None:
        client = probe_health(self.client_url, "client")
        federation = probe_health(self.federation_url, "federation")
        self.assertEqual((client.service, federation.service), ("client", "federation"))
        with self.assertRaisesRegex(ValueError, "unexpected_health_response"):
            probe_health(self.client_url, "federation")

    def test_client_login_status_and_logout(self) -> None:
        headers = {PROTOCOL_HEADER: CLIENT_PROTOCOL}
        status, login = self.request(
            self.client_url,
            "POST",
            "/v1/sessions",
            headers=headers,
            payload={
                "identity": str(self.account.identity),
                "password": "correct horse battery staple",
            },
        )
        self.assertEqual(status, 201)
        authenticated = {**headers, "Authorization": f"Bearer {login['token']}"}
        status, result = self.request(
            self.client_url, "GET", "/v1/status", headers=authenticated
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["account"]["identity"], str(self.account.identity))
        self.assertEqual(result["message_protocol"], "ha-chat/2")
        status, _ = self.request(
            self.client_url, "DELETE", "/v1/session", headers=authenticated
        )
        self.assertEqual(status, 200)
        status, result = self.request(
            self.client_url, "GET", "/v1/status", headers=authenticated
        )
        self.assertEqual((status, result["error"]["code"]), (401, "invalid_session"))

    def test_reusable_prototype_client(self) -> None:
        client = CompanionClient(self.client_url)
        self.assertEqual(client.health()["service"], "client")
        login = client.login(str(self.account.identity), "correct horse battery staple")
        self.assertEqual(login["account"]["display_name"], "Owner")
        self.assertEqual(client.status()["plane"], "client")
        client.logout()
        with self.assertRaises(ClientError):
            client.status()

    def test_protocol_version_is_mandatory(self) -> None:
        status, result = self.request(
            self.client_url,
            "POST",
            "/v1/sessions",
            payload={"identity": str(self.account.identity), "password": "irrelevant"},
        )
        self.assertEqual((status, result["error"]["code"]), (426, "unsupported_protocol"))

    def test_federation_status_authentication_and_replay_rejection(self) -> None:
        path = "/v1/federation/status"
        timestamp = str(int(time.time()))
        nonce = "federation_nonce_12345"
        signature = sign_federation_request(
            self.peer.shared_secret, "GET", path, timestamp, nonce
        )
        headers = {
            PROTOCOL_HEADER: FEDERATION_PROTOCOL,
            "X-HA-Chat-Peer": self.peer.peer_id,
            "X-HA-Chat-Timestamp": timestamp,
            "X-HA-Chat-Nonce": nonce,
            "X-HA-Chat-Signature": signature,
        }
        status, result = self.request(self.federation_url, "GET", path, headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(result["authenticated_peer"], self.peer.peer_id)
        status, result = self.request(self.federation_url, "GET", path, headers=headers)
        self.assertEqual((status, result["error"]["code"]), (409, "replayed_request"))


if __name__ == "__main__":
    unittest.main()
