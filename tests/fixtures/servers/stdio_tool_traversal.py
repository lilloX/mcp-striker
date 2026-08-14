#!/usr/bin/env python3
"""Vulnerable STDIO MCP fixture server — path traversal via tools/call.

Exposes a ``read_file`` tool that passes the user-controlled ``path``
argument directly to ``pathlib.Path.read_text`` without sanitisation.

This mirrors the pattern used by many real-world MCP filesystem servers
(2025-2026 ecosystem), where filesystem access is exposed as tools rather
than resources.

Used by integration tests to verify that mcp-striker's tool probe modules
detect the vulnerability.  NEVER deploy in production.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


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
                "capabilities": {"tools": {}, "resources": {}},
                "serverInfo": {"name": "vulnerable-tool-server", "version": "0.1.0"},
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
                        "description": "Read the contents of a file at the given path.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string", "description": "Path to the file"},
                            },
                            "required": ["path"],
                        },
                    },
                    {
                        "name": "list_directory",
                        "description": "List files in a directory.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                            },
                        },
                    },
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
            # VULNERABILITY: no path sanitisation.
            try:
                content = Path(path_str).read_text(errors="replace")
                _write({
                    "jsonrpc": "2.0", "id": msg_id,
                    "result": {
                        "content": [{"type": "text", "text": content}],
                        "isError": False,
                    },
                })
            except OSError as exc:
                _write({
                    "jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32001, "message": str(exc)},
                })

        elif tool_name == "list_directory":
            path_str = str(arguments.get("path", "."))
            try:
                entries = [p.name for p in Path(path_str).iterdir()]
                _write({
                    "jsonrpc": "2.0", "id": msg_id,
                    "result": {"content": [{"type": "text", "text": "\n".join(entries)}]},
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
