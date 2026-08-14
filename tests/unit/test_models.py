"""Unit tests for mcp_striker/models.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_striker.models import (
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    TransportExchange,
)

# ---------------------------------------------------------------------------
# JsonRpcResponse.is_success
# ---------------------------------------------------------------------------


def test_is_success_true_when_no_error() -> None:
    r = JsonRpcResponse(jsonrpc="2.0", id=1, result={"ok": True})
    assert r.is_success is True


def test_response_rejects_non_2_0_jsonrpc() -> None:
    with pytest.raises(Exception):
        JsonRpcResponse(jsonrpc="1.0", id=1, result={})


def test_response_rejects_both_result_and_error() -> None:
    with pytest.raises(Exception):
        JsonRpcResponse(
            jsonrpc="2.0", id=1, result={"x": 1},
            error=JsonRpcError(code=-1, message="e"),
        )


def test_is_success_false_when_neither_result_nor_error() -> None:
    r = JsonRpcResponse(jsonrpc="2.0", id=1)
    assert r.is_success is False


def test_is_success_false_when_tool_is_error() -> None:
    """is_success must be False when result.isError is True (tool-level error).

    This prevents tool validation errors ('Required field missing', 'Invalid enum')
    from being mistaken for security findings by the jsonrpc_success matcher.
    """
    resp = JsonRpcResponse(
        jsonrpc="2.0", id=1,
        result={
            "content": [{"type": "text", "text": "MCP error -32602: Input validation error"}],
            "isError": True,
        },
    )
    assert resp.is_success is False


def test_is_success_true_when_is_error_false() -> None:
    """is_success must be True when isError is explicitly False."""
    resp = JsonRpcResponse(
        jsonrpc="2.0", id=1,
        result={"content": [{"type": "text", "text": "ok"}], "isError": False},
    )
    assert resp.is_success is True


def test_is_success_false_when_error_present() -> None:
    r = JsonRpcResponse(
        jsonrpc="2.0",
        id=1,
        error=JsonRpcError(code=-32600, message="Invalid Request"),
    )
    assert r.is_success is False


# ---------------------------------------------------------------------------
# JsonRpcResponse.get_text_content
# ---------------------------------------------------------------------------


def test_get_text_content_extracts_text() -> None:
    r = JsonRpcResponse(
        jsonrpc="2.0",
        id=1,
        result={
            "contents": [
                {"uri": "file:///etc/passwd", "text": "root:x:0:0:root:/root:/bin/bash"}
            ]
        },
    )
    assert "root:x:0:0" in r.get_text_content()


def test_get_text_content_multiple_items() -> None:
    r = JsonRpcResponse(
        jsonrpc="2.0",
        id=1,
        result={
            "contents": [
                {"uri": "a", "text": "line1"},
                {"uri": "b", "text": "line2"},
            ]
        },
    )
    text = r.get_text_content()
    assert "line1" in text
    assert "line2" in text


def test_get_text_content_returns_empty_for_error_response() -> None:
    r = JsonRpcResponse(
        jsonrpc="2.0",
        id=1,
        error=JsonRpcError(code=-32001, message="Not found"),
    )
    assert r.get_text_content() == ""


def test_get_text_content_returns_empty_for_non_dict_result() -> None:
    r = JsonRpcResponse(jsonrpc="2.0", id=1, result="just a string")
    assert r.get_text_content() == ""


# ---------------------------------------------------------------------------
# TransportExchange defaults
# ---------------------------------------------------------------------------


def test_exchange_defaults() -> None:
    req = JsonRpcRequest(id=1, method="resources/read", params={"uri": "file:///x"})
    ex = TransportExchange(request=req)
    assert ex.probe_failed is False
    assert ex.response is None
    assert ex.stderr_transcript == ""


# ---------------------------------------------------------------------------
# Regression tests for bug fixes
# ---------------------------------------------------------------------------


def test_substitute_windows_payload_not_corrupted() -> None:
    r"""Regression: re.sub without lambda interprets backslashes in the
    replacement string as backreferences, corrupting Windows payloads.
    E.g. r'..\..\..\windows\win.ini' would become '..\..\..\windowsin.ini'
    because \w and \n are treated as escape sequences.
    """
    from mcp_striker.engine.strike import _substitute

    windows_payload = r"..\..\..\windows\win.ini"
    result = _substitute("file://{path}", windows_payload)
    assert result == f"file://{windows_payload}", (
        f"Payload was corrupted by regex backreference expansion: {result!r}"
    )


def test_substitute_windows_absolute_payload() -> None:
    """Regression: absolute Windows path with backslash must survive substitution."""
    from mcp_striker.engine.strike import _substitute

    payload = r"C:\windows\win.ini"
    result = _substitute("file://{path}", payload)
    assert result == f"file://{payload}"


def test_protocol_client_enumerate_persists_target_url(tmp_path: Path) -> None:
    """Regression: target_url must be stored in CapabilityRegistry so that
    ``strike --from-enum`` can reconnect to HTTP servers without extra flags.
    """
    from mcp_striker.registry import CapabilityRegistry

    # Simulate what ProtocolClient.enumerate_capabilities() now produces.
    registry = CapabilityRegistry(
        server_name="test",
        server_version="0.1.0",
        protocol_version="2025-03-26",
        target_cmd="",
        target_url="http://localhost:9999",
    )
    snapshot = tmp_path / "snap.json"
    registry.save(snapshot)

    loaded = CapabilityRegistry.load(snapshot)
    assert loaded.target_url == "http://localhost:9999", (
        "target_url was not persisted or loaded correctly from snapshot"
    )
