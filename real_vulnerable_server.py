#!/usr/bin/env python3
"""Realistic vulnerable MCP document server — built with the official Python MCP SDK.

Scenario
--------
A developer has written a "document server" that exposes company files over
MCP.  The server registers a resource template ``file://{path}`` and calls
``pathlib.Path(path).read_text()`` without any sanitisation.

This is the classic mistake: the developer tested only with paths like
``file://docs/report.txt`` and never considered that a malicious MCP client
could send ``file://../../../../etc/passwd``.

The server is built with the *official* low-level ``mcp.server.Server`` API
so it behaves exactly like a real production server — including correct
``resources/templates/list`` registration that mcp-striker will detect.

Usage
-----
    # from the mcp-striker directory (the mcp SDK is an optional extra):
    pip install -e ".[demo]"
    venv/bin/python real_vulnerable_server.py

    mcp-striker enum  --cmd "venv/bin/python real_vulnerable_server.py"
    mcp-striker strike --from-enum .mcp-striker/sessions/document-server.json
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from mcp.server import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

# ---------------------------------------------------------------------------
# Seed a fake company document directory
# ---------------------------------------------------------------------------

_BASE = Path(__file__).resolve().parent / "company_docs"
_BASE.mkdir(exist_ok=True)
(_BASE / "report_q1.txt").write_text(
    "Q1 2026 Financial Report\nRevenue: 2.4M (+12% YoY)\n[CONFIDENTIAL]"
)
(_BASE / "readme.txt").write_text(
    "Document Server v1.0\nUse file://<path> to access documents."
)
(_BASE / "api_keys.txt").write_text(
    "STRIPE_KEY=sk_live_XXXXXXXXXXXXXXXX\nSENDGRID_KEY=SG.XXXXXXXXX"
)

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

server = Server("document-server")


@server.list_resources()
async def list_resources() -> list[types.Resource]:
    return [
        types.Resource(
            uri=f"file://{_BASE}/{f.name}",  # type: ignore[arg-type]
            name=f.name,
            mimeType="text/plain",
        )
        for f in sorted(_BASE.iterdir())
        if f.is_file()
    ]


@server.list_resource_templates()
async def list_resource_templates() -> list[types.ResourceTemplate]:
    return [
        types.ResourceTemplate(
            uriTemplate="file://{path}",  # type: ignore[arg-type]
            name="file-reader",
            description="Read any file by path. Accepts relative and absolute paths.",
            mimeType="text/plain",
        )
    ]


@server.read_resource()
async def read_resource(uri: types.AnyUrl) -> str:
    """VULNERABILITY: no path sanitisation — path traversal succeeds."""
    path_str = str(uri).removeprefix("file://")
    return Path(path_str).read_text(errors="replace")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


async def main() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
