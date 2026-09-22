"""Password, token, and federation request authentication primitives."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass

from .protocol import FEDERATION_CLOCK_SKEW_SECONDS, MAX_NONCE_LENGTH

_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16," + str(MAX_NONCE_LENGTH) + r"}$")
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_FAKE_SALT = b"ha-chat-auth-fake"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode_b64url(value: str) -> bytes:
    if not value or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise ValueError("invalid_base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str) -> str:
    if not isinstance(password, str) or not 12 <= len(password.encode("utf-8")) <= 1024:
        raise ValueError("password_must_be_12_to_1024_bytes")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_b64url(salt)}${_b64url(digest)}"


def verify_password(password: str, encoded: str | None) -> bool:
    try:
        scheme, n, r, p, salt, expected = (encoded or "").split("$")
        if scheme != "scrypt":
            raise ValueError
        parameters = (int(n), int(r), int(p))
        if parameters != (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P):
            raise ValueError
        raw_salt = _decode_b64url(salt)
        raw_expected = _decode_b64url(expected)
    except (TypeError, ValueError):
        raw_salt = _FAKE_SALT
        raw_expected = b"\x00" * 64
    try:
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=raw_salt,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
        )
    except (AttributeError, UnicodeError):
        return False
    return hmac.compare_digest(actual, raw_expected)


def new_session_token() -> str:
    return _b64url(secrets.token_bytes(32))


def token_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("ascii", "strict")).digest()


def new_peer_secret() -> str:
    return _b64url(secrets.token_bytes(32))


def canonical_federation_request(
    method: str, path: str, timestamp: str, nonce: str, body: bytes
) -> bytes:
    body_digest = hashlib.sha256(body).hexdigest()
    return "\n".join((method.upper(), path, timestamp, nonce, body_digest)).encode("ascii")


def sign_federation_request(
    secret: str, method: str, path: str, timestamp: str, nonce: str, body: bytes = b""
) -> str:
    key = _decode_b64url(secret)
    if len(key) != 32:
        raise ValueError("invalid_peer_secret")
    message = canonical_federation_request(method, path, timestamp, nonce, body)
    return _b64url(hmac.new(key, message, hashlib.sha256).digest())


@dataclass(frozen=True, slots=True)
class VerifiedFederationRequest:
    peer_id: str
    timestamp: int
    nonce: str


def verify_federation_signature(
    *,
    secret: str,
    peer_id: str,
    method: str,
    path: str,
    timestamp: str,
    nonce: str,
    signature: str,
    body: bytes,
    now: int | None = None,
) -> VerifiedFederationRequest:
    try:
        parsed_time = int(timestamp)
    except (TypeError, ValueError) as error:
        raise ValueError("invalid_federation_timestamp") from error
    current = int(time.time()) if now is None else now
    if abs(current - parsed_time) > FEDERATION_CLOCK_SKEW_SECONDS:
        raise ValueError("stale_federation_request")
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
        raise ValueError("invalid_federation_nonce")
    try:
        expected = sign_federation_request(secret, method, path, timestamp, nonce, body)
    except ValueError as error:
        raise ValueError("invalid_federation_signature") from error
    if not isinstance(signature, str) or not hmac.compare_digest(expected, signature):
        raise ValueError("invalid_federation_signature")
    return VerifiedFederationRequest(peer_id, parsed_time, nonce)

