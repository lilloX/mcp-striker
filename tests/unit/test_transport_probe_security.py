"""Security regression tests for the HTTP transport layer.

Covers three fixes:
  #1 credential leak on cross-origin redirect (StreamableHttpTransport)
  #2 --no-verify-ssl ignored by http-probe (TransportProbeEngine)
  #3 --path ignored by http-probe (TransportProbeEngine)
"""

from __future__ import annotations

import httpx

from mcp_striker.engine.transport_probe import TransportProbeEngine
from mcp_striker.models import JsonRpcRequest, TransportContext
from mcp_striker.transport.streamable_http import StreamableHttpTransport


def _engine(**kwargs: object) -> TransportProbeEngine:
    # recorder / evidence_generator are unused by _probe_transport_pairs().
    return TransportProbeEngine(
        base_url="https://target.example",
        recorder=None,  # type: ignore[arg-type]
        evidence_generator=None,  # type: ignore[arg-type]
        session_id="session-1",
        **kwargs,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# #2 / #3 — http-probe must forward verify_ssl and path to each transport
# ---------------------------------------------------------------------------


def test_probe_transports_forward_verify_ssl_and_path() -> None:
    engine = _engine(verify_ssl=False, path="/custom-mcp")
    pairs = engine._probe_transport_pairs()
    assert len(pairs) == 3
    for _probe, transport, _request in pairs:
        assert transport._verify_ssl is False
        assert transport._endpoint == "https://target.example/custom-mcp"


def test_probe_transports_default_to_verify_and_mcp_path() -> None:
    engine = _engine()
    for _probe, transport, _request in engine._probe_transport_pairs():
        assert transport._verify_ssl is True
        assert transport._endpoint == "https://target.example/mcp"


# ---------------------------------------------------------------------------
# #1 — sensitive headers must not follow a cross-origin redirect
# ---------------------------------------------------------------------------

_SENSITIVE = {
    "Authorization": "Bearer operator-secret",
    "Cookie": "session=1",
    "MCP-Session-Id": "abc123",
    "X-API-Key": "operator-api-key",  # custom credential header via --header
    "X-Auth-Token": "operator-token",
    "Content-Type": "application/json",
}


def _transport() -> StreamableHttpTransport:
    return StreamableHttpTransport(base_url="https://target.example")


def test_same_origin_redirect_keeps_all_headers() -> None:
    t = _transport()
    kept = t._headers_for_url("https://target.example/gateway", dict(_SENSITIVE))
    assert kept == _SENSITIVE


def test_cross_origin_host_strips_credentials() -> None:
    t = _transport()
    out = t._headers_for_url("https://evil.example/collect", dict(_SENSITIVE))
    # Every operator-supplied header is dropped cross-origin, including custom
    # credential headers not on any hard-coded denylist.
    assert "Authorization" not in out
    assert "Cookie" not in out
    assert "MCP-Session-Id" not in out
    assert "X-API-Key" not in out
    assert "X-Auth-Token" not in out
    # Only protocol-safe headers survive.
    assert out["Content-Type"] == "application/json"


def test_scheme_downgrade_is_cross_origin() -> None:
    t = _transport()
    out = t._headers_for_url("http://target.example/mcp", dict(_SENSITIVE))
    assert "Authorization" not in out


def test_different_port_is_cross_origin() -> None:
    t = _transport()
    out = t._headers_for_url("https://target.example:8443/mcp", dict(_SENSITIVE))
    assert "Authorization" not in out


# ---------------------------------------------------------------------------
# #1 — exactly one HTTP request per hop (no throwaway pre-flight POST)
# ---------------------------------------------------------------------------


def _json_rpc_ok() -> httpx.Response:
    return httpx.Response(
        200,
        json={"jsonrpc": "2.0", "id": 1, "result": {}},
        headers={"content-type": "application/json"},
    )


async def _send_with_mock(handler: object) -> object:
    t = StreamableHttpTransport(base_url="http://server")
    t._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))  # type: ignore[arg-type]
    try:
        req = JsonRpcRequest(jsonrpc="2.0", id=1, method="tools/call", params={})
        ctx = TransportContext(session_id="s", target_url="http://server")
        return await t.send(req, ctx)
    finally:
        await t._client.aclose()


async def test_no_redirect_sends_exactly_one_post() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return _json_rpc_ok()

    exchange = await _send_with_mock(handler)
    # Was 2 before the fix (pre-flight POST in _resolve_redirects + stream POST).
    assert len(calls) == 1
    assert exchange.response is not None  # type: ignore[attr-defined]


async def test_redirect_is_one_request_per_hop() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        calls.append(url)
        if url.endswith("/mcp"):
            return httpx.Response(307, headers={"location": "http://server/mcp2"})
        return _json_rpc_ok()

    exchange = await _send_with_mock(handler)
    # One redirect hop + one final request. Was 3 before the fix.
    assert len(calls) == 2
    assert exchange.response is not None  # type: ignore[attr-defined]


async def test_oversized_response_is_capped(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import mcp_striker.transport.streamable_http as sh

    monkeypatch.setattr(sh, "_MAX_RESPONSE_BYTES", 10)

    def handler(request: httpx.Request) -> httpx.Response:
        big = {"jsonrpc": "2.0", "id": 1, "result": {"x": "y" * 100}}
        return httpx.Response(
            200, json=big, headers={"content-type": "application/json"}
        )

    exchange = await _send_with_mock(handler)
    assert exchange.probe_failed  # type: ignore[attr-defined]
    assert "limit" in (exchange.failure_reason or "")  # type: ignore[attr-defined]


async def test_cross_origin_redirect_is_refused() -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        calls.append(url)
        # The target tries to bounce us (and the request body) to another origin.
        return httpx.Response(307, headers={"location": "http://evil.example/collect"})

    exchange = await _send_with_mock(handler)
    assert exchange.probe_failed  # type: ignore[attr-defined]  # refused, not followed
    # The body was never replayed to the attacker origin.
    assert not any("evil.example" in c for c in calls)
