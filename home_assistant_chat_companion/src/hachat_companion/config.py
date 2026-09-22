"""Validated runtime configuration."""

from __future__ import annotations

import ssl
import ipaddress
from dataclasses import dataclass
from pathlib import Path

from .address import parse_ipv4


@dataclass(frozen=True, slots=True)
class ListenerConfig:
    host: str
    port: int
    tls_cert: Path | None = None
    tls_key: Path | None = None
    allow_insecure_http: bool = False

    def validated(self, *, allow_ephemeral: bool = False) -> "ListenerConfig":
        host = parse_ipv4(self.host)
        minimum = 0 if allow_ephemeral else 1
        if isinstance(self.port, bool) or not minimum <= self.port <= 65535:
            raise ValueError("invalid_listener_port")
        if (self.tls_cert is None) != (self.tls_key is None):
            raise ValueError("tls_cert_and_key_required")
        for path in (self.tls_cert, self.tls_key):
            if path is not None and not path.is_file():
                raise ValueError(f"tls_file_not_found:{path}")
        if (
            self.tls_cert is None
            and not ipaddress.ip_address(host).is_loopback
            and not self.allow_insecure_http
        ):
            raise ValueError("tls_required_for_non_loopback_listener")
        return ListenerConfig(
            host, self.port, self.tls_cert, self.tls_key, self.allow_insecure_http
        )

    def ssl_context(self) -> ssl.SSLContext | None:
        if self.tls_cert is None or self.tls_key is None:
            return None
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.tls_cert, self.tls_key)
        return context


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    database: Path
    client: ListenerConfig
    federation: ListenerConfig

    def validated(self, *, allow_ephemeral: bool = False) -> "ServiceConfig":
        client = self.client.validated(allow_ephemeral=allow_ephemeral)
        federation = self.federation.validated(allow_ephemeral=allow_ephemeral)
        if client.host == federation.host and client.port == federation.port and client.port != 0:
            raise ValueError("listeners_must_be_separate")
        if not str(self.database):
            raise ValueError("database_path_required")
        return ServiceConfig(self.database, client, federation)
