"""Unit tests for mcp_striker/modules/transport_probes.py."""

from __future__ import annotations

import pytest

from mcp_striker.models import (
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    TransportExchange,
)
from mcp_striker.modules.transport_probes import (
    ORIGIN_PROBE,
    PROTOCOL_VERSION_PROBE,
    SESSION_REUSE_PROBE,
    TRANSPORT_PROBES,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _req() -> JsonRpcRequest:
    return JsonRpcRequest(id=1, method="initialize", params={})


def _ok_exchange(http_status: int = 200) -> TransportExchange:
    return TransportExchange(
        request=_req(),
        response=JsonRpcResponse(
            jsonrpc="2.0",
            id=1,
            result={"protocolVersion": "2025-03-26"},
        ),
        http_status=http_status,
    )


def _error_exchange(http_status: int) -> TransportExchange:
    return TransportExchange(
        request=_req(),
        response=JsonRpcResponse(
            jsonrpc="2.0",
            id=1,
            error=JsonRpcError(code=-32600, message="rejected"),
        ),
        http_status=http_status,
    )


def _failed_exchange(http_status: int = 403) -> TransportExchange:
    return TransportExchange(
        request=_req(),
        probe_failed=True,
        failure_reason="HTTP 403",
        http_status=http_status,
    )


# ---------------------------------------------------------------------------
# ORIGIN_PROBE
# ---------------------------------------------------------------------------


def test_origin_probe_fires_on_200_success() -> None:
    """Server accepts hostile Origin — vulnerability confirmed."""
    exchange = _ok_exchange(http_status=200)
    assert ORIGIN_PROBE.matches(exchange) is True
    assert "http_success_on_hostile_origin" in ORIGIN_PROBE.matchers_hit(exchange)


def test_origin_probe_no_fire_on_403() -> None:
    """Server correctly rejected the hostile Origin."""
    exchange = _failed_exchange(http_status=403)
    assert ORIGIN_PROBE.matches(exchange) is False


def test_origin_probe_no_fire_on_jsonrpc_error() -> None:
    """HTTP 200 but JSON-RPC error body — not a confirmed vulnerability."""
    exchange = _error_exchange(http_status=200)
    assert ORIGIN_PROBE.matches(exchange) is False


# ---------------------------------------------------------------------------
# PROTOCOL_VERSION_PROBE
# ---------------------------------------------------------------------------


def test_version_probe_fires_on_success() -> None:
    """Server accepts invalid protocol version — vulnerability confirmed."""
    exchange = _ok_exchange(http_status=200)
    assert PROTOCOL_VERSION_PROBE.matches(exchange) is True


def test_version_probe_no_fire_on_jsonrpc_error() -> None:
    """Server returns error for invalid version — correct behaviour."""
    exchange = _error_exchange(http_status=200)
    assert PROTOCOL_VERSION_PROBE.matches(exchange) is False


def test_version_probe_no_fire_on_400() -> None:
    exchange = _failed_exchange(http_status=400)
    assert PROTOCOL_VERSION_PROBE.matches(exchange) is False


# ---------------------------------------------------------------------------
# SESSION_REUSE_PROBE
# ---------------------------------------------------------------------------


def test_session_probe_fires_when_server_accepts_bogus_session() -> None:
    """Server processed a request with a fabricated session ID."""
    exchange = _ok_exchange(http_status=200)
    assert SESSION_REUSE_PROBE.matches(exchange) is True


def test_session_probe_no_fire_on_401() -> None:
    """Server correctly rejected the fabricated session."""
    exchange = TransportExchange(
        request=_req(),
        http_status=401,
        probe_failed=True,
        failure_reason="HTTP 401",
    )
    assert SESSION_REUSE_PROBE.matches(exchange) is False


def test_session_probe_no_fire_on_404() -> None:
    exchange = TransportExchange(
        request=_req(),
        http_status=404,
        probe_failed=True,
        failure_reason="HTTP 404",
    )
    assert SESSION_REUSE_PROBE.matches(exchange) is False


# ---------------------------------------------------------------------------
# TRANSPORT_PROBES list completeness
# ---------------------------------------------------------------------------


def test_transport_probes_list_has_three_probes() -> None:
    assert len(TRANSPORT_PROBES) == 3


def test_all_probes_have_unique_names() -> None:
    names = [p.name for p in TRANSPORT_PROBES]
    assert len(names) == len(set(names))
