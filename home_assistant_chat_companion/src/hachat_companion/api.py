"""Strict JSON HTTP APIs for the client and federation planes."""

from __future__ import annotations

import json
import base64
import logging
import re
import time
import uuid
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Any, Callable

from .address import parse_user_address
from .events import (
    build_federated_event,
    validate_client_message,
    validate_device_id,
    validate_federated_event,
    validate_public_jwk,
    validate_receipt,
)
from .federation import FederationDeliveryError, fetch_devices
from .protocol import (
    API_VERSION,
    CAPABILITIES,
    CLIENT_PROTOCOL,
    CONTENT_TYPE,
    FEDERATION_PROTOCOL,
    MAX_JSON_BODY,
    MESSAGE_PROTOCOL,
    PROTOCOL_HEADER,
    SESSION_LIFETIME_SECONDS,
    STORAGE_SCHEMA_VERSION,
)
from .ratelimit import RateLimiter
from .security import verify_federation_signature
from .storage import Account, Store

LOGGER = logging.getLogger(__name__)
_BEARER_RE = re.compile(r"^Bearer ([A-Za-z0-9_-]{43})$")


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message


class CompanionRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HAChatCompanion/0.1"
    sys_version = ""

    store: Store
    plane: str
    general_limiter: RateLimiter
    login_limiter: RateLimiter

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, format: str, *args: object) -> None:
        LOGGER.info("%s %s", self.address_string(), format % args)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")

    def do_DELETE(self) -> None:  # noqa: N802
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        request_id = self.headers.get("X-Request-ID", "")
        if not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", request_id):
            import secrets

            request_id = secrets.token_hex(12)
        try:
            if not self.general_limiter.allow(self.client_address[0]):
                raise ApiError(429, "rate_limited", "Too many requests")
            transfer_encoding = self.headers.get("Transfer-Encoding")
            if transfer_encoding is not None:
                raise ApiError(400, "unsupported_transfer_encoding", "Transfer-Encoding is unsupported")
            if method != "POST" and self.headers.get("Content-Length") not in {None, "0"}:
                raise ApiError(400, "unexpected_body", "This request must not contain a body")
            body = self._read_body() if method == "POST" else b""
            if self.path == "/healthz" and method == "GET":
                self._json(
                    200,
                    {
                        "status": "ok",
                        "service": self.plane,
                        "api_version": API_VERSION,
                    },
                    request_id,
                )
                return
            if self.path.startswith("/v1/"):
                self._require_protocol()
            if self.plane == "client":
                self._dispatch_client(method, body, request_id)
            else:
                self._dispatch_federation(method, body, request_id)
        except ApiError as error:
            self._json(
                error.status,
                {"error": {"code": error.code, "message": error.message}},
                request_id,
            )
        except (ConnectionError, TimeoutError):
            self.close_connection = True
        except Exception:
            LOGGER.exception("Unhandled API error (request_id=%s)", request_id)
            self._json(
                500,
                {"error": {"code": "internal_error", "message": "Internal server error"}},
                request_id,
            )

    def _dispatch_client(self, method: str, body: bytes, request_id: str) -> None:
        if method == "POST" and self.path == "/v1/sessions":
            if not self.login_limiter.allow(self.client_address[0]):
                raise ApiError(429, "rate_limited", "Too many authentication attempts")
            payload = self._json_object(body, {"identity", "password"}, {"identity", "password"})
            account = self.store.authenticate(payload["identity"], payload["password"])
            if account is None:
                raise ApiError(401, "invalid_credentials", "Invalid identity or password")
            token, expires = self.store.create_session(account.id)
            self._json(
                201,
                {
                    "token": token,
                    "token_type": "Bearer",
                    "expires_at": expires,
                    "expires_in": SESSION_LIFETIME_SECONDS,
                    "account": account.public_dict(),
                },
                request_id,
            )
            return
        account, token = self._client_account()
        if method == "POST" and self.path == "/v1/devices":
            payload = self._parse_json(body)
            if not isinstance(payload, dict) or set(payload) != {"device_id", "public_key", "label"}:
                raise ApiError(400, "invalid_device", "Device fields are invalid")
            try:
                device_id = validate_device_id(payload["device_id"])
                public_key = validate_public_jwk(payload["public_key"])
                device = self.store.register_device(account.id, device_id, public_key, payload["label"])
            except (TypeError, ValueError) as error:
                raise ApiError(400, str(error), "Device registration is invalid") from None
            self._json(201, {"device": device}, request_id)
            return
        if method == "POST" and self.path == "/v1/devices/lookup":
            payload = self._json_object(body, {"address"}, {"address"})
            try:
                address = parse_user_address(payload["address"])
            except ValueError as error:
                raise ApiError(400, str(error), "Address is invalid") from None
            if address.is_local:
                devices = self.store.claim_device_packages(
                    address.number, f"local-account:{account.id}"
                )
            else:
                peer = self.store.resolve_peer(str(address.server), address.port)
                if peer is None:
                    raise ApiError(404, "peer_not_found", "Federation peer is not configured")
                try:
                    devices = fetch_devices(
                        self.store.server_id, peer, address.number, account.identity
                    )
                except FederationDeliveryError:
                    raise ApiError(502, "peer_unavailable", "Federation peer is unavailable") from None
            self._json(200, {"address": str(address), "devices": devices}, request_id)
            return
        if method == "POST" and self.path == "/v1/key-packages":
            payload = self._parse_json(body)
            if (
                not isinstance(payload, dict)
                or set(payload) != {"device_id", "packages"}
                or not isinstance(payload.get("packages"), list)
            ):
                raise ApiError(400, "invalid_key_packages", "Key package fields are invalid")
            try:
                device_id = validate_device_id(payload["device_id"])
                packages = []
                for item in payload["packages"]:
                    if not isinstance(item, dict) or set(item) != {"package_id", "payload"}:
                        raise ValueError("invalid_key_packages")
                    package_id = str(uuid.UUID(item["package_id"]))
                    if package_id != item["package_id"] or not isinstance(item["payload"], str):
                        raise ValueError("invalid_key_packages")
                    raw = base64.b64decode(item["payload"], validate=True)
                    if not 32 <= len(raw) <= 4_096 or base64.b64encode(raw).decode() != item["payload"]:
                        raise ValueError("invalid_key_packages")
                    packages.append({"package_id": package_id, "payload": item["payload"]})
                added = self.store.add_key_packages(account.id, device_id, packages)
            except (ValueError, TypeError, base64.binascii.Error):
                raise ApiError(400, "invalid_key_packages", "Key packages are invalid") from None
            self._json(201, {"added": added}, request_id)
            return
        if method == "POST" and self.path == "/v1/messages":
            try:
                message = validate_client_message(self._parse_json(body))
                event = build_federated_event(
                    server_id=self.store.server_id, sender_number=account.identity, message=message
                )
                if message.recipient.is_local:
                    peer_id = None
                    local_recipient = message.recipient.number
                else:
                    peer = self.store.resolve_peer(str(message.recipient.server), message.recipient.port)
                    if peer is None:
                        raise ValueError("peer_not_found")
                    peer_id, local_recipient = peer.peer_id, None
                stored, state, duplicate = self.store.create_outgoing_event(
                    account=account,
                    device_id=message.envelope["device_id"],
                    counter=message.envelope["counter"],
                    client_event_id=message.client_event_id,
                    target=str(message.recipient),
                    event=event,
                    local_recipient=local_recipient,
                    peer_id=peer_id,
                )
            except ValueError as error:
                code = str(error)
                status = (
                    404 if code in {"peer_not_found", "recipient_not_found"}
                    else 429 if code == "event_quota_exceeded"
                    else 400
                )
                raise ApiError(status, code, "Message could not be accepted") from None
            self._json(200 if duplicate else 202, {
                "event_id": stored["event_id"], "state": state, "duplicate": duplicate
            }, request_id)
            return
        if method == "GET" and self.path == "/v1/messages":
            events = self.store.inbox(account.id)
            for event in events:
                if event["origin_server_id"] == self.store.server_id:
                    event["sender"] = str(event["sender_number"])
                else:
                    peer = self.store.get_peer(str(event["origin_server_id"]))
                    event["sender"] = (
                        f"{event['sender_number']}@{peer.address}:{peer.port}" if peer else None
                    )
            self._json(200, {"events": events}, request_id)
            return
        if method == "POST" and self.path == "/v1/messages/receipt":
            payload = self._parse_json(body)
            if (
                not isinstance(payload, dict)
                or set(payload) != {"event_id", "state"}
                or not isinstance(payload.get("event_id"), str)
                or payload.get("state") not in {"delivered", "read"}
            ):
                raise ApiError(400, "invalid_receipt", "Receipt fields are invalid")
            if not self.store.mark_receipt(account.id, payload["event_id"], payload["state"]):
                raise ApiError(404, "event_not_found", "Message event was not found")
            self._json(200, {"event_id": payload["event_id"], "state": payload["state"]}, request_id)
            return
        if method == "POST" and self.path == "/v1/messages/status":
            payload = self._json_object(body, {"event_id"}, {"event_id"})
            state = self.store.delivery_status(account.id, payload["event_id"])
            if state is None:
                raise ApiError(404, "event_not_found", "Message event was not found")
            self._json(200, {"event_id": payload["event_id"], "state": state}, request_id)
            return
        if method == "GET" and self.path == "/v1/status":
            self._json(
                200,
                self._status("client", account=account),
                request_id,
            )
            return
        if method == "GET" and self.path == "/v1/account":
            self._json(200, {"account": account.public_dict()}, request_id)
            return
        if method == "DELETE" and self.path == "/v1/session":
            self.store.revoke_session(token)
            self._json(200, {"revoked": True}, request_id)
            return
        raise ApiError(404, "not_found", "Endpoint not found")

    def _dispatch_federation(self, method: str, body: bytes, request_id: str) -> None:
        peer_id = self._federation_peer(method, body)
        if method == "POST" and self.path == "/v1/federation/events":
            try:
                event = validate_federated_event(self._parse_json(body), expected_origin=peer_id)
                duplicate = self.store.accept_federated_event(peer_id, event)
            except ValueError as error:
                code = str(error)
                status = (
                    404 if code == "recipient_not_found"
                    else 429 if code == "event_quota_exceeded"
                    else 400
                )
                raise ApiError(status, code, "Federated event was rejected") from None
            self._json(200 if duplicate else 201, {
                "event_id": event["event_id"], "accepted": True, "duplicate": duplicate
            }, request_id)
            return
        if method == "POST" and self.path == "/v1/federation/devices":
            payload = self._parse_json(body)
            identity = payload.get("identity") if isinstance(payload, dict) else None
            requester = payload.get("requester_number") if isinstance(payload, dict) else None
            if set(payload) != {"identity", "requester_number"} if isinstance(payload, dict) else True:
                raise ApiError(400, "invalid_identity", "Identity request is invalid")
            if (
                isinstance(identity, bool) or not isinstance(identity, int)
                or not 10_000_000 <= identity <= 99_999_999
                or isinstance(requester, bool) or not isinstance(requester, int)
                or not 10_000_000 <= requester <= 99_999_999
            ):
                raise ApiError(400, "invalid_identity", "Identity request is invalid")
            self._json(200, {"identity": str(identity),
                             "devices": self.store.claim_device_packages(
                                 identity, f"peer:{peer_id}:{requester}"
                             )}, request_id)
            return
        if method == "POST" and self.path == "/v1/federation/receipts":
            try:
                receipt = validate_receipt(self._parse_json(body))
                duplicate = self.store.accept_federated_receipt(peer_id, receipt)
            except ValueError as error:
                code = str(error)
                status = 404 if code == "event_not_found" else 400
                raise ApiError(status, code, "Federated receipt was rejected") from None
            self._json(200, {"receipt_id": receipt["receipt_id"], "accepted": True,
                             "duplicate": duplicate}, request_id)
            return
        if method == "GET" and self.path == "/v1/federation/status":
            self._json(200, self._status("federation", peer_id=peer_id), request_id)
            return
        raise ApiError(404, "not_found", "Endpoint not found")

    def _status(
        self, plane: str, *, account: Account | None = None, peer_id: str | None = None
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "status": "ok",
            "plane": plane,
            "server_id": self.store.server_id,
            "api_version": API_VERSION,
            "storage_schema": STORAGE_SCHEMA_VERSION,
            "message_protocol": MESSAGE_PROTOCOL,
            "client_protocol": CLIENT_PROTOCOL,
            "federation_protocol": FEDERATION_PROTOCOL,
            "capabilities": list(CAPABILITIES),
            "server_time": int(time.time()),
        }
        if account is not None:
            result["account"] = account.public_dict()
        if peer_id is not None:
            result["authenticated_peer"] = peer_id
        return result

    def _client_account(self) -> tuple[Account, str]:
        match = _BEARER_RE.fullmatch(self.headers.get("Authorization", ""))
        if match is None:
            raise ApiError(401, "authentication_required", "Bearer authentication required")
        token = match.group(1)
        account = self.store.account_for_token(token)
        if account is None:
            raise ApiError(401, "invalid_session", "Session is invalid or expired")
        return account, token

    def _federation_peer(self, method: str, body: bytes) -> str:
        peer_id = self.headers.get("X-HA-Chat-Peer", "")
        peer = self.store.get_peer(peer_id)
        # Keep failure details intentionally generic at the network boundary.
        if peer is None or not peer.enabled:
            raise ApiError(401, "peer_authentication_failed", "Peer authentication failed")
        if self.client_address[0] != peer.address:
            raise ApiError(401, "peer_authentication_failed", "Peer authentication failed")
        try:
            verified = verify_federation_signature(
                secret=peer.shared_secret,
                peer_id=peer.peer_id,
                method=method,
                path=self.path,
                timestamp=self.headers.get("X-HA-Chat-Timestamp", ""),
                nonce=self.headers.get("X-HA-Chat-Nonce", ""),
                signature=self.headers.get("X-HA-Chat-Signature", ""),
                body=body,
            )
        except ValueError:
            raise ApiError(401, "peer_authentication_failed", "Peer authentication failed") from None
        if not self.store.record_federation_nonce(
            verified.peer_id, verified.nonce, verified.timestamp
        ):
            raise ApiError(409, "replayed_request", "Request nonce was already used")
        return peer.peer_id

    def _require_protocol(self) -> None:
        expected = CLIENT_PROTOCOL if self.plane == "client" else FEDERATION_PROTOCOL
        if self.headers.get(PROTOCOL_HEADER) != expected:
            raise ApiError(426, "unsupported_protocol", f"Required protocol: {expected}")

    def _read_body(self) -> bytes:
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            raise ApiError(415, "unsupported_media_type", "Content-Type must be application/json")
        raw_length = self.headers.get("Content-Length")
        try:
            length = int(raw_length or "")
        except ValueError as error:
            raise ApiError(411, "content_length_required", "Valid Content-Length required") from error
        if not 1 <= length <= MAX_JSON_BODY:
            raise ApiError(413, "request_too_large", "Request body is outside allowed bounds")
        body = self.rfile.read(length)
        if len(body) != length:
            raise ApiError(400, "incomplete_body", "Incomplete request body")
        return body

    @staticmethod
    def _parse_json(body: bytes) -> Any:
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ApiError(400, "invalid_json", "Request body must be valid JSON") from error

    @staticmethod
    def _json_object(body: bytes, allowed: set[str], required: set[str]) -> dict[str, Any]:
        payload = CompanionRequestHandler._parse_json(body)
        if not isinstance(payload, dict) or set(payload) - allowed or not required <= set(payload):
            raise ApiError(400, "invalid_request", "Request fields are invalid")
        if any(not isinstance(value, str) for value in payload.values()):
            raise ApiError(400, "invalid_request", "Request fields are invalid")
        return payload

    def _json(self, status: int, payload: dict[str, object], request_id: str) -> None:
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", CONTENT_TYPE)
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Request-ID", request_id)
        if status == HTTPStatus.UNAUTHORIZED:
            self.send_header("WWW-Authenticate", 'Bearer realm="ha-chat"')
        self.end_headers()
        self.wfile.write(encoded)


def handler_for(store: Store, plane: str) -> Callable[..., CompanionRequestHandler]:
    if plane not in {"client", "federation"}:
        raise ValueError("invalid_plane")

    class BoundHandler(CompanionRequestHandler):
        pass

    BoundHandler.store = store
    BoundHandler.plane = plane
    BoundHandler.general_limiter = RateLimiter(240, 60)
    BoundHandler.login_limiter = RateLimiter(10, 300)
    BoundHandler.__name__ = f"{plane.title()}RequestHandler"
    return BoundHandler
