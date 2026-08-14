"""Transport security probes for Streamable HTTP MCP servers.

Design: same Option A pattern as ``resource_path_traversal.py``.
Each ``TransportProbe`` carries its own ``Matcher`` list.
``TransportProbeEngine`` is completely dumb: it fires each probe and
calls ``probe.matches(exchange)``.

The three probes implemented here:

1. **Origin** — sends a hostile ``Origin`` header.  A vulnerable server
   completes the handshake instead of rejecting the request (CORS /
   DNS-rebinding risk).

2. **Protocol version mismatch** — sends a nonsensical protocol version.
   A vulnerable server accepts it; a correct one returns a JSON-RPC error
   or 400.

3. **Session reuse** — injects a fabricated ``MCP-Session-Id`` header on
   a fresh connection.  A vulnerable server accepts the bogus session
   instead of rejecting it.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from mcp_striker.models import TransportExchange

# ---------------------------------------------------------------------------
# Matcher primitive (identical contract to resource_path_traversal.Matcher)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Matcher:
    name: str
    fn: Callable[[TransportExchange], bool]

    def evaluate(self, exchange: TransportExchange) -> bool:
        return self.fn(exchange)


# ---------------------------------------------------------------------------
# TransportProbe
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TransportProbe:
    """A single transport-layer security probe with self-contained matchers."""

    name: str
    description: str
    payload_label: str  # human-readable description of the injected anomaly
    matchers: list[Matcher]

    def matches(self, exchange: TransportExchange) -> bool:
        """Return ``True`` if every matcher fires — probe confirmed a vulnerability."""
        return all(m.evaluate(exchange) for m in self.matchers)

    def matchers_hit(self, exchange: TransportExchange) -> list[str]:
        return [m.name for m in self.matchers if m.evaluate(exchange)]


# ---------------------------------------------------------------------------
# Matcher factories
# ---------------------------------------------------------------------------


def _http_success(exchange: TransportExchange) -> bool:
    """True when the server returned HTTP 200 or 202."""
    return exchange.http_status in (200, 202)


def _jsonrpc_success(exchange: TransportExchange) -> bool:
    """True when the response contains a JSON-RPC result (no error)."""
    return (
        not exchange.probe_failed
        and exchange.response is not None
        and exchange.response.is_success
    )


def _http_rejected(exchange: TransportExchange) -> bool:
    """True when the server rejected the request (4xx)."""
    return 400 <= exchange.http_status < 500


def _session_accepted(exchange: TransportExchange) -> bool:
    """True when the server accepted a bogus session ID (processed the request)."""
    return (
        not exchange.probe_failed
        and exchange.response is not None
        # The server processed the request — it should have rejected it.
        and exchange.http_status not in (400, 401, 404)
    )


# ---------------------------------------------------------------------------
# Probe definitions
# ---------------------------------------------------------------------------

ORIGIN_PROBE = TransportProbe(
    name="origin-missing-check",
    description=(
        "Send a hostile Origin header during initialize. "
        "A vulnerable server completes the handshake (CORS / DNS-rebinding risk)."
    ),
    payload_label="Origin: http://evil.attacker.example.com",
    matchers=[
        Matcher(name="http_success_on_hostile_origin", fn=_http_success),
        Matcher(name="jsonrpc_success_on_hostile_origin", fn=_jsonrpc_success),
    ],
)

PROTOCOL_VERSION_PROBE = TransportProbe(
    name="protocol-version-mismatch",
    description=(
        "Send MCP-Protocol-Version: 1900-01-01 during initialize. "
        "A vulnerable server accepts the invalid version instead of rejecting it."
    ),
    payload_label="MCP-Protocol-Version: 1900-01-01",
    matchers=[
        Matcher(name="http_success_on_invalid_version", fn=_http_success),
        Matcher(name="jsonrpc_success_on_invalid_version", fn=_jsonrpc_success),
    ],
)

SESSION_REUSE_PROBE = TransportProbe(
    name="session-reuse",
    description=(
        "Inject a fabricated MCP-Session-Id header on a fresh connection. "
        "A vulnerable server accepts the bogus session."
    ),
    payload_label="MCP-Session-Id: 00000000-0000-0000-0000-000000000000",
    matchers=[
        Matcher(name="server_accepted_fabricated_session", fn=_session_accepted),
    ],
)

TRANSPORT_PROBES: list[TransportProbe] = [
    ORIGIN_PROBE,
    PROTOCOL_VERSION_PROBE,
    SESSION_REUSE_PROBE,
]
