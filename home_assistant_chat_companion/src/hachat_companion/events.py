"""Validation and construction of transport-independent encrypted events."""

from __future__ import annotations

import base64
import json
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .address import UserAddress, parse_user_address
from .protocol import MAX_CIPHERTEXT_BYTES, MESSAGE_PROTOCOL, MESSAGE_TTL_SECONDS

_SERVER_ID_RE = re.compile(r"^srv_[0-9a-f]{32}$")
_EVENT_ID_RE = re.compile(r"^evt_[0-9a-f]{32}$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}$")
_P256_FIELD = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _b64(value: Any, field: str, maximum: int, *, exact: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or len(value) % 4 or not _B64_RE.fullmatch(value):
        raise ValueError(f"invalid_{field}")
    if len(value) > ((maximum + 2) // 3) * 4:
        raise ValueError(f"invalid_{field}")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError, base64.binascii.Error) as error:
        raise ValueError(f"invalid_{field}") from error
    if len(decoded) > maximum or (exact is not None and len(decoded) != exact):
        raise ValueError(f"invalid_{field}")
    if base64.b64encode(decoded).decode() != value:
        raise ValueError(f"invalid_{field}")
    return decoded


def validate_public_jwk(value: Any) -> str:
    try:
        key = json.loads(value) if isinstance(value, str) else value
    except json.JSONDecodeError as error:
        raise ValueError("invalid_device_key") from error
    if (
        not isinstance(key, dict)
        or set(key) != {"kty", "crv", "x", "y", "ext", "key_ops"}
        or key.get("kty") != "EC"
        or key.get("crv") != "P-256"
        or key.get("ext") is not True
        or key.get("key_ops") != []
    ):
        raise ValueError("invalid_device_key")
    coordinates: dict[str, int] = {}
    for field in ("x", "y"):
        coordinate = key[field]
        if not isinstance(coordinate, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", coordinate):
            raise ValueError("invalid_device_key")
        try:
            raw = base64.urlsafe_b64decode(coordinate + "==")
        except (ValueError, TypeError, base64.binascii.Error) as error:
            raise ValueError("invalid_device_key") from error
        if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != coordinate:
            raise ValueError("invalid_device_key")
        coordinates[field] = int.from_bytes(raw, "big")
    x, y = coordinates["x"], coordinates["y"]
    if x >= _P256_FIELD or y >= _P256_FIELD:
        raise ValueError("invalid_device_key")
    if (y * y - (pow(x, 3, _P256_FIELD) - 3 * x + _P256_B)) % _P256_FIELD != 0:
        raise ValueError("invalid_device_key")
    return json.dumps(key, sort_keys=True, separators=(",", ":"))


def validate_device_id(value: Any) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError("invalid_device_id") from error
    if not isinstance(value, str) or str(parsed) != value or parsed.version != 4:
        raise ValueError("invalid_device_id")
    return value


def validate_envelope(ciphertext: Any, envelope: Any) -> dict[str, Any]:
    raw_ciphertext = _b64(ciphertext, "ciphertext", MAX_CIPHERTEXT_BYTES)
    if len(raw_ciphertext) < 16:
        raise ValueError("invalid_ciphertext")
    if not isinstance(envelope, dict):
        raise ValueError("invalid_envelope")
    required = {"version", "device_id", "counter", "nonce", "key_id", "aad"}
    allowed = required | {"key_commitment"}
    if set(envelope) - allowed or not required <= set(envelope):
        raise ValueError("invalid_envelope")
    if envelope["version"] != MESSAGE_PROTOCOL:
        raise ValueError("unsupported_message_protocol")
    device_id = validate_device_id(envelope["device_id"])
    counter = envelope["counter"]
    if isinstance(counter, bool) or not isinstance(counter, int) or not 1 <= counter <= 2**53 - 1:
        raise ValueError("invalid_counter")
    _b64(envelope["nonce"], "nonce", 12, exact=12)
    _b64(envelope["aad"], "aad", 2048)
    key_id = envelope["key_id"]
    if not isinstance(key_id, str) or not 1 <= len(key_id) <= 256 or any(ord(c) < 33 for c in key_id):
        raise ValueError("invalid_key_id")
    if "key_commitment" in envelope:
        _b64(envelope["key_commitment"], "key_commitment", 32, exact=32)
    return {**envelope, "device_id": device_id, "counter": counter}


@dataclass(frozen=True, slots=True)
class ClientMessage:
    client_event_id: str
    recipient: UserAddress
    ciphertext: str
    envelope: dict[str, Any]


def validate_client_message(payload: Any) -> ClientMessage:
    required = {"client_event_id", "recipient", "ciphertext", "envelope"}
    if not isinstance(payload, dict) or set(payload) != required:
        raise ValueError("invalid_message")
    try:
        client_event_id = str(uuid.UUID(payload["client_event_id"]))
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError("invalid_client_event_id") from error
    if client_event_id != payload["client_event_id"]:
        raise ValueError("invalid_client_event_id")
    recipient = parse_user_address(payload["recipient"])
    envelope = validate_envelope(payload["ciphertext"], payload["envelope"])
    return ClientMessage(client_event_id, recipient, payload["ciphertext"], envelope)


def build_federated_event(
    *, server_id: str, sender_number: int, message: ClientMessage, now: int | None = None
) -> dict[str, Any]:
    created = int(time.time()) if now is None else now
    return {
        "version": MESSAGE_PROTOCOL,
        "event_id": f"evt_{uuid.uuid4().hex}",
        "origin_server_id": server_id,
        "client_event_id": message.client_event_id,
        "kind": "direct_message",
        "sender_number": sender_number,
        "recipient_number": message.recipient.number,
        "created_at": created,
        "expires_at": created + MESSAGE_TTL_SECONDS,
        "ciphertext": message.ciphertext,
        "envelope": message.envelope,
    }


def validate_federated_event(value: Any, *, expected_origin: str, now: int | None = None) -> dict[str, Any]:
    required = {
        "version", "event_id", "origin_server_id", "client_event_id", "kind",
        "sender_number", "recipient_number", "created_at", "expires_at", "ciphertext", "envelope",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("invalid_event")
    if value["version"] != MESSAGE_PROTOCOL or value["kind"] != "direct_message":
        raise ValueError("unsupported_event")
    if value["origin_server_id"] != expected_origin or not _SERVER_ID_RE.fullmatch(expected_origin):
        raise ValueError("invalid_event_origin")
    if not isinstance(value["event_id"], str) or not _EVENT_ID_RE.fullmatch(value["event_id"]):
        raise ValueError("invalid_event_id")
    try:
        parsed_client_id = str(uuid.UUID(value["client_event_id"]))
    except (ValueError, TypeError, AttributeError) as error:
        raise ValueError("invalid_client_event_id") from error
    if parsed_client_id != value["client_event_id"]:
        raise ValueError("invalid_client_event_id")
    for field in ("sender_number", "recipient_number"):
        number = value[field]
        if isinstance(number, bool) or not isinstance(number, int) or not 10_000_000 <= number <= 99_999_999:
            raise ValueError("invalid_event_identity")
    current = int(time.time()) if now is None else now
    created, expires = value["created_at"], value["expires_at"]
    if (
        isinstance(created, bool) or not isinstance(created, int)
        or isinstance(expires, bool) or not isinstance(expires, int)
        or created > current + 300 or expires <= current or expires - created > MESSAGE_TTL_SECONDS
    ):
        raise ValueError("invalid_event_time")
    validate_envelope(value["ciphertext"], value["envelope"])
    return value


def validate_receipt(value: Any, *, now: int | None = None) -> dict[str, Any]:
    required = {"version", "receipt_id", "event_id", "state", "recipient_number", "created_at"}
    if not isinstance(value, dict) or set(value) != required or value["version"] != MESSAGE_PROTOCOL:
        raise ValueError("invalid_receipt")
    if not isinstance(value["receipt_id"], str) or not re.fullmatch(r"rcp_[0-9a-f]{32}", value["receipt_id"]):
        raise ValueError("invalid_receipt")
    if not isinstance(value["event_id"], str) or not _EVENT_ID_RE.fullmatch(value["event_id"]):
        raise ValueError("invalid_receipt")
    if value["state"] not in {"delivered", "read"}:
        raise ValueError("invalid_receipt")
    number = value["recipient_number"]
    if isinstance(number, bool) or not isinstance(number, int) or not 10_000_000 <= number <= 99_999_999:
        raise ValueError("invalid_receipt")
    current = int(time.time()) if now is None else now
    created = value["created_at"]
    if (
        isinstance(created, bool)
        or not isinstance(created, int)
        or created > current + 300
        or current - created > MESSAGE_TTL_SECONDS
    ):
        raise ValueError("invalid_receipt")
    return value
