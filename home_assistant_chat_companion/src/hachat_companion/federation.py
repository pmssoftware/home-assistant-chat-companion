"""Authenticated outbound federation transport and durable retry dispatcher."""

from __future__ import annotations

import http.client
import json
import logging
import secrets
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .events import canonical_json
from .protocol import FEDERATION_PROTOCOL, PROTOCOL_HEADER
from .security import sign_federation_request
from .storage import Peer, Store

LOGGER = logging.getLogger(__name__)


class FederationDeliveryError(RuntimeError):
    pass


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Verify/SNI a DNS name while dialing the operator-pinned IPv4 endpoint."""

    def __init__(
        self,
        address: str,
        port: int,
        server_name: str,
        *,
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(server_name, port, timeout=timeout, context=context)
        self._pinned_address = address

        def connect_pinned(
            _address: tuple[str, int],
            connect_timeout: float | object = socket._GLOBAL_DEFAULT_TIMEOUT,
            source_address: tuple[str, int] | None = None,
            *args: object,
            **kwargs: object,
        ) -> socket.socket:
            return socket.create_connection(
                (self._pinned_address, port), connect_timeout, source_address
            )

        self._create_connection = connect_pinned


def signed_json_request(
    local_server_id: str,
    peer: Peer,
    path: str,
    payload: dict[str, Any],
    *,
    timeout: float = 8,
) -> dict[str, Any]:
    body = canonical_json(payload)
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    signature = sign_federation_request(peer.shared_secret, "POST", path, timestamp, nonce, body)
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        PROTOCOL_HEADER: FEDERATION_PROTOCOL,
        "X-HA-Chat-Peer": local_server_id,
        "X-HA-Chat-Timestamp": timestamp,
        "X-HA-Chat-Nonce": nonce,
        "X-HA-Chat-Signature": signature,
    }
    connection: http.client.HTTPConnection
    if peer.use_tls:
        context = ssl.create_default_context()
        if peer.tls_server_name:
            connection = _PinnedHTTPSConnection(
                peer.address,
                peer.port,
                peer.tls_server_name,
                timeout=timeout,
                context=context,
            )
        else:
            connection = http.client.HTTPSConnection(
                peer.address, peer.port, timeout=timeout, context=context
            )
    else:
        connection = http.client.HTTPConnection(peer.address, peer.port, timeout=timeout)
    try:
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        response_body = response.read(262_145)
        if len(response_body) > 262_144:
            raise FederationDeliveryError("response_too_large")
        if response.status not in {200, 201}:
            try:
                code = json.loads(response_body).get("error", {}).get("code", "remote_error")
            except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
                code = "remote_error"
            raise FederationDeliveryError(f"remote_{response.status}:{code}")
        try:
            result = json.loads(response_body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise FederationDeliveryError("invalid_remote_response") from error
        if not isinstance(result, dict):
            raise FederationDeliveryError("invalid_remote_response")
        return result
    except (OSError, TimeoutError, http.client.HTTPException) as error:
        raise FederationDeliveryError(type(error).__name__) from error
    finally:
        connection.close()


def post_event(local_server_id: str, peer: Peer, event: dict[str, Any], *, timeout: float = 8) -> None:
    signed_json_request(local_server_id, peer, "/v1/federation/events", event, timeout=timeout)


def fetch_devices(
    local_server_id: str,
    peer: Peer,
    identity: int,
    requester_number: int,
    *,
    timeout: float = 8,
) -> list[dict[str, Any]]:
    result = signed_json_request(
        local_server_id,
        peer,
        "/v1/federation/devices",
        {"identity": identity, "requester_number": requester_number},
        timeout=timeout,
    )
    devices = result.get("devices")
    if not isinstance(devices, list) or len(devices) > 32 or any(not isinstance(item, dict) for item in devices):
        raise FederationDeliveryError("invalid_device_response")
    return devices


class OutboxDispatcher:
    def __init__(self, store: Store, *, interval: float = 1.0) -> None:
        self.store = store
        self.interval = interval
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="ha-chat-outbox", daemon=True)
        self._thread.start()

    def wake(self) -> None:
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=20)
            if self._thread.is_alive():
                LOGGER.error("Federation dispatcher did not stop before timeout")

    def flush_once(self) -> int:
        work = [
            (self._deliver_event, item) for item in self.store.due_outbox()
        ] + [
            (self._deliver_receipt, item) for item in self.store.due_receipts()
        ]
        if not work:
            return 0
        delivered = 0
        with ThreadPoolExecutor(max_workers=8, thread_name_prefix="ha-chat-delivery") as pool:
            futures = [pool.submit(operation, item) for operation, item in work]
            for future in as_completed(futures):
                try:
                    delivered += int(future.result())
                except Exception:
                    LOGGER.exception("Unexpected federation delivery failure")
        return delivered

    def _deliver_event(self, item: dict[str, object]) -> bool:
        if self._stop.is_set():
            return False
        attempts = int(item["attempts"]) + 1
        peer = self.store.get_peer(str(item["peer_id"]))
        if peer is None or not peer.enabled:
            self.store.mark_outbox_failed(str(item["event_id"]), attempts, "peer_unavailable")
            return False
        try:
            post_event(self.store.server_id, peer, item["event"])
        except FederationDeliveryError as error:
            self.store.mark_outbox_failed(str(item["event_id"]), attempts, str(error))
            return False
        self.store.mark_outbox_delivered(str(item["event_id"]))
        return True

    def _deliver_receipt(self, item: dict[str, object]) -> bool:
        if self._stop.is_set():
            return False
        attempts = int(item["attempts"]) + 1
        peer = self.store.get_peer(str(item["peer_id"]))
        if peer is None or not peer.enabled:
            self.store.mark_receipt_outbox_failed(
                str(item["receipt_id"]), attempts, "peer_unavailable"
            )
            return False
        try:
            signed_json_request(
                self.store.server_id, peer, "/v1/federation/receipts", item["receipt"]
            )
        except FederationDeliveryError as error:
            self.store.mark_receipt_outbox_failed(
                str(item["receipt_id"]), attempts, str(error)
            )
            return False
        self.store.mark_receipt_outbox_delivered(str(item["receipt_id"]))
        return True

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.flush_once()
            except Exception:
                LOGGER.exception("Federation dispatcher iteration failed")
            self._wake.wait(self.interval)
            self._wake.clear()
