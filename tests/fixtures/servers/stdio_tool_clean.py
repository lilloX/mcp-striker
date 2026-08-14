#!/usr/bin/env python3
"""Clean STDIO MCP fixture server — path traversal via tools/call prevented.

Exposes a ``read_file`` tool that sanitises the path: resolves it against
a fixed safe root and rejects any request that would escape it.

Used to verify that mcp-striker produces zero findings against a correctly
implemented server (false-positive guard for tool probe modules).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

_SAFE_ROOT = Path(tempfile.gettempdir()) / "mcp-clean-tool-server"
_SAFE_ROOT.mkdir(exist_ok=True)
(_SAFE_ROOT / "hello.txt").write_text("Hello from the clean tool server!\n")


def _write(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _handle(msg: dict) -> None:
    method = str(msg.get("method", ""))
    msg_id = msg.get("id")

    if method == "initialize":
        _write({
            "jsonrpc": "2.0", "id": msg_id,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "clean-tool-server", "version": "0.1.0"},
            },
        })

    elif method == "notifications/initialized":
        pass

    elif method == "tools/list":
        _write({
            "jsonrpc": "2.0", "id": msg_id,
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "description": "Safely read a file from the allowed directory.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                            },
                            "required": ["path"],
                        },
                    }
                ]
            },
        })

    elif method == "resources/list":
        _write({"jsonrpc": "2.0", "id": msg_id, "result": {"resources": [], "resourceTemplates": []}})

    elif method == "tools/call":
        params = msg.get("params") or {}
        tool_name = str(params.get("name", ""))
        arguments = params.get("arguments") or {}

        if tool_name == "read_file":
            path_str = str(arguments.get("path", ""))
            try:
                # Resolve against safe root and reject escapes.
                requested = (_SAFE_ROOT / path_str).resolve()
                if not str(requested).startswith(str(_SAFE_ROOT.resolve())):
                    _write({
                        "jsonrpc": "2.0", "id": msg_id,
                        "error": {"code": -32001, "message": "Access denied: path outside safe root"},
                    })
                    return
                content = requested.read_text(errors="replace")
                _write({
                    "jsonrpc": "2.0", "id": msg_id,
                    "result": {"content": [{"type": "text", "text": content}], "isError": False},
                })
            except OSError as exc:
                _write({
                    "jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32001, "message": str(exc)},
                })
        else:
            _write({
                "jsonrpc": "2.0", "id": msg_id,
                "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
            })

    elif msg_id is not None:
        _write({
            "jsonrpc": "2.0", "id": msg_id,
            "error": {"code": -32601, "message": "Method not found"},
        })


def main() -> None:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            _handle(json.loads(line))
        except json.JSONDecodeError:
            pass


if __name__ == "__main__":
    main()
