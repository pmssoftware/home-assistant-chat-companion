"""Tiny reusable client for exercising the first client-API vertical slice."""

from __future__ import annotations

import argparse
import getpass
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .protocol import CLIENT_PROTOCOL, PROTOCOL_HEADER


class ClientError(RuntimeError):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code


class CompanionClient:
    def __init__(
        self,
        base_url: str,
        *,
        tls_context: ssl.SSLContext | None = None,
        allow_insecure_loopback: bool = True,
        allow_insecure_remote: bool = False,
    ) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.path not in {"", "/"}:
            raise ValueError("invalid_server_url")
        if parsed.scheme == "http" and not (
            allow_insecure_remote
            or (allow_insecure_loopback and parsed.hostname in {"127.0.0.1", "localhost"})
        ):
            raise ValueError("https_required_for_remote_server")
        self.base_url = base_url.rstrip("/")
        self.tls_context = tls_context
        self.token: str | None = None

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/healthz", authenticated=False, protocol=False)

    def login(self, identity: str, password: str) -> dict[str, Any]:
        response = self._request(
            "POST",
            "/v1/sessions",
            {"identity": identity, "password": password},
            authenticated=False,
        )
        token = response.get("token")
        if not isinstance(token, str):
            raise ClientError(500, "invalid_server_response", "Server did not return a token")
        self.token = token
        return response

    def status(self) -> dict[str, Any]:
        return self._request("GET", "/v1/status")

    def account(self) -> dict[str, Any]:
        return self._request("GET", "/v1/account")

    def register_device(self, device_id: str, public_key: dict[str, Any], label: str) -> dict[str, Any]:
        return self._request(
            "POST",
            "/v1/devices",
            {"device_id": device_id, "public_key": public_key, "label": label},
        )

    def lookup_devices(self, address: str) -> dict[str, Any]:
        return self._request("POST", "/v1/devices/lookup", {"address": address})

    def upload_key_packages(
        self, device_id: str, packages: list[dict[str, str]]
    ) -> dict[str, Any]:
        return self._request(
            "POST", "/v1/key-packages", {"device_id": device_id, "packages": packages}
        )

    def send_message(
        self,
        *,
        client_event_id: str,
        recipient: str,
        ciphertext: str,
        envelope: dict[str, Any],
    ) -> dict[str, Any]:
        return self._request(
            "POST",
            "/v1/messages",
            {
                "client_event_id": client_event_id,
                "recipient": recipient,
                "ciphertext": ciphertext,
                "envelope": envelope,
            },
        )

    def inbox(self) -> list[dict[str, Any]]:
        return self._request("GET", "/v1/messages")["events"]

    def receipt(self, event_id: str, state: str) -> dict[str, Any]:
        return self._request(
            "POST", "/v1/messages/receipt", {"event_id": event_id, "state": state}
        )

    def message_status(self, event_id: str) -> dict[str, Any]:
        return self._request("POST", "/v1/messages/status", {"event_id": event_id})

    def logout(self) -> None:
        self._request("DELETE", "/v1/session")
        self.token = None

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        authenticated: bool = True,
        protocol: bool = True,
    ) -> dict[str, Any]:
        body = None
        headers = {"Accept": "application/json"}
        if protocol:
            headers[PROTOCOL_HEADER] = CLIENT_PROTOCOL
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if authenticated:
            if self.token is None:
                raise ClientError(401, "authentication_required", "Log in first")
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(
            self.base_url + path, data=body, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=10, context=self.tls_context) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            try:
                try:
                    payload = json.loads(error.read()).get("error", {})
                except (json.JSONDecodeError, AttributeError):
                    payload = {}
            finally:
                error.close()
            raise ClientError(
                error.code,
                str(payload.get("code", "http_error")),
                str(payload.get("message", error.reason)),
            ) from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hachat-prototype-client")
    parser.add_argument("--server", default="http://127.0.0.1:8210")
    parser.add_argument("--identity", required=True)
    parser.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="allow plain HTTP to a non-loopback test server",
    )
    args = parser.parse_args(argv)
    client = CompanionClient(args.server, allow_insecure_remote=args.allow_insecure_http)
    password = getpass.getpass("Password: ")
    try:
        login = client.login(args.identity, password)
        print(json.dumps(login["account"], indent=2))
        print(json.dumps(client.status(), indent=2))
    finally:
        if client.token:
            client.logout()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
