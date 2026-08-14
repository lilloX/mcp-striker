"""Regression tests for review findings #12 (protocol-version validation) and
#13 (shlex parsing of --cmd)."""

from __future__ import annotations

import pytest
import typer

from mcp_striker.cli import _build_transport, _strike
from mcp_striker.models import (
    JsonRpcResponse,
    TransportContext,
    TransportExchange,
)
from mcp_striker.protocol.client import ProtocolClient, ProtocolError
from mcp_striker.transport.stdio import StdioTransport

# ---------------------------------------------------------------------------
# #13 — --cmd is split with shlex (quoted paths/args preserved)
# ---------------------------------------------------------------------------


def test_build_transport_stdio_uses_shlex() -> None:
    transport = _build_transport(
        "stdio",
        cmd="python '/path with spaces/server.py' --flag 'a b'",
        url=None,
        timeout=5.0,
    )
    assert isinstance(transport, StdioTransport)
    assert transport._cmd == [
        "python",
        "/path with spaces/server.py",
        "--flag",
        "a b",
    ]


# ---------------------------------------------------------------------------
# #12 — an unsupported negotiated protocol version is rejected
# ---------------------------------------------------------------------------


class _FakeTransport:
    def __init__(self, protocol_version: str) -> None:
        self._pv = protocol_version

    async def connect(self) -> None:  # pragma: no cover - not used
        pass

    async def close(self) -> None:  # pragma: no cover - not used
        pass

    async def send(self, request, context):  # type: ignore[no-untyped-def]
        return TransportExchange(
            request=request,
            response=JsonRpcResponse(
                jsonrpc="2.0",
                id=request.id,
                result={
                    "protocolVersion": self._pv,
                    "capabilities": {},
                    "serverInfo": {"name": "x", "version": "1"},
                },
            ),
        )


async def test_initialize_rejects_unsupported_protocol_version() -> None:
    client = ProtocolClient(
        transport=_FakeTransport("1999-01-01"),  # type: ignore[arg-type]
        context=TransportContext(session_id="t"),
    )
    with pytest.raises(ProtocolError, match="unsupported protocol version"):
        await client.initialize()


async def test_initialize_accepts_supported_protocol_version() -> None:
    client = ProtocolClient(
        transport=_FakeTransport("2024-11-05"),  # type: ignore[arg-type]
        context=TransportContext(session_id="t"),
    )
    await client.initialize()  # must not raise


# ---------------------------------------------------------------------------
# #11 — enumeration follows nextCursor pagination
# ---------------------------------------------------------------------------


class _PagedToolsTransport:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    async def connect(self) -> None:  # pragma: no cover - not used
        pass

    async def close(self) -> None:  # pragma: no cover - not used
        pass

    async def send(self, request, context):  # type: ignore[no-untyped-def]
        cursor = (request.params or {}).get("cursor")
        self.calls.append((request.method, cursor))
        if request.method == "tools/list" and cursor is None:
            result = {"tools": [{"name": "t1"}], "nextCursor": "c2"}
        elif request.method == "tools/list" and cursor == "c2":
            result = {"tools": [{"name": "t2"}]}
        else:
            result = {"tools": []}
        return TransportExchange(
            request=request,
            response=JsonRpcResponse(jsonrpc="2.0", id=request.id, result=result),
        )


async def test_list_tools_follows_pagination() -> None:
    transport = _PagedToolsTransport()
    client = ProtocolClient(
        transport=transport,  # type: ignore[arg-type]
        context=TransportContext(session_id="t"),
    )
    tools = await client._list_tools()
    assert [t.name for t in tools] == ["t1", "t2"]
    # The second page was requested with the server-provided cursor.
    assert ("tools/list", "c2") in transport.calls


# ---------------------------------------------------------------------------
# #10 — CLI input validation
# ---------------------------------------------------------------------------


def test_build_transport_rejects_unknown_transport() -> None:
    with pytest.raises(typer.Exit):
        _build_transport("htpp", cmd="python x.py", url=None, timeout=5.0)


def test_build_transport_rejects_nonpositive_timeout() -> None:
    with pytest.raises(typer.Exit):
        _build_transport("stdio", cmd="python x.py", url=None, timeout=0.0)


async def test_strike_rejects_zero_concurrency() -> None:
    from pathlib import Path

    with pytest.raises(typer.Exit):
        await _strike(
            from_enum=Path("/nonexistent.json"),
            allow_mutating=False,
            concurrency=0,
            timeout=5.0,
            output_dir=None,
        )


class _CyclingToolsTransport:
    def __init__(self) -> None:
        self.count = 0

    async def connect(self) -> None:  # pragma: no cover - not used
        pass

    async def close(self) -> None:  # pragma: no cover - not used
        pass

    async def send(self, request, context):  # type: ignore[no-untyped-def]
        self.count += 1
        return TransportExchange(
            request=request,
            response=JsonRpcResponse(
                jsonrpc="2.0", id=request.id,
                result={"tools": [{"name": f"t{self.count}"}], "nextCursor": "same"},
            ),
        )


async def test_pagination_stops_on_cursor_cycle() -> None:
    transport = _CyclingToolsTransport()
    client = ProtocolClient(
        transport=transport,  # type: ignore[arg-type]
        context=TransportContext(session_id="t"),
    )
    tools = await client._list_tools()
    # A repeated cursor must stop the loop after the 2nd request, not run to the
    # 100-page cap.
    assert transport.count == 2
    assert len(tools) == 2
