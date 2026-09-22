"""Operator health probes for independently running server planes."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class HealthResult:
    url: str
    service: str
    api_version: int


def probe_health(base_url: str, expected_service: str, *, timeout: float = 5) -> HealthResult:
    """Probe one listener without credentials and validate its declared role."""
    parsed = urllib.parse.urlparse(base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.path not in {"", "/"}
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("invalid_health_url")
    if parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise ValueError("https_required_for_remote_health_check")
    if expected_service not in {"client", "federation"}:
        raise ValueError("invalid_expected_service")
    request = urllib.request.Request(
        base_url.rstrip("/") + "/healthz",
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(4097)
    except (urllib.error.URLError, TimeoutError) as error:
        raise ConnectionError(f"health_check_failed:{expected_service}") from error
    if len(raw) > 4096:
        raise ValueError("health_response_too_large")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid_health_response") from error
    if (
        not isinstance(payload, dict)
        or payload.get("status") != "ok"
        or payload.get("service") != expected_service
        or not isinstance(payload.get("api_version"), int)
    ):
        raise ValueError("unexpected_health_response")
    return HealthResult(base_url.rstrip("/"), expected_service, payload["api_version"])

