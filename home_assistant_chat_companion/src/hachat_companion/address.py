"""Canonical local and federated user addresses."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

_ADDRESS_RE = re.compile(r"^([1-9][0-9]{7})(?:@([^:]+)(?::([0-9]{1,5}))?)?$")


@dataclass(frozen=True, slots=True)
class UserAddress:
    """An eight-digit identity, optionally scoped to an IPv4 federation server."""

    number: int
    server: ipaddress.IPv4Address | None = None
    port: int | None = None

    @property
    def is_local(self) -> bool:
        return self.server is None

    def __str__(self) -> str:
        value = str(self.number)
        if self.server is not None:
            value += f"@{self.server.compressed}"
            if self.port is not None:
                value += f":{self.port}"
        return value


def parse_user_address(value: str) -> UserAddress:
    """Parse NUMBER or NUMBER@IPV4[:PORT], rejecting DNS names and IPv6."""
    if not isinstance(value, str) or len(value) > 64 or value != value.strip():
        raise ValueError("invalid_address")
    match = _ADDRESS_RE.fullmatch(value)
    if not match:
        raise ValueError("invalid_address")
    number = int(match.group(1))
    raw_server = match.group(2)
    raw_port = match.group(3)
    if raw_server is None:
        if raw_port is not None:
            raise ValueError("invalid_address")
        return UserAddress(number)
    try:
        server = ipaddress.ip_address(raw_server)
    except ValueError as error:
        raise ValueError("invalid_server_address") from error
    if not isinstance(server, ipaddress.IPv4Address):
        raise ValueError("invalid_server_address")
    port = int(raw_port) if raw_port is not None else None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("invalid_server_port")
    return UserAddress(number, server, port)


def parse_ipv4(value: str) -> str:
    """Return a canonical IPv4 string for listener and peer configuration."""
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError("invalid_ipv4_address") from error
    if not isinstance(parsed, ipaddress.IPv4Address):
        raise ValueError("invalid_ipv4_address")
    return parsed.compressed

