#!/usr/bin/env python3
"""Clean (non-vulnerable) MCP fixture server.

``resources/read`` sanitises the path: it resolves the requested path
against a fixed safe root and rejects any request that would escape it.

Used to verify that ``mcp-striker`` produces **zero** findings against a
correctly implemented server (false-positive guard).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# All reads are confined to this directory.
_SAFE_ROOT = Path(tempfile.gettempdir()) / "mcp-clean-server"
_SAFE_ROOT.mkdir(exist_ok=True)

# Seed with a harmless file so resources/read can succeed on safe paths.
(_SAFE_ROOT / "hello.txt").write_text("Hello from the clean server!\n")


def _write(obj: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _handle(msg: dict[str, object]) -> None:
    method = str(msg.get("method", ""))
    msg_id = msg.get("id")

    if method == "initialize":
        _write(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"resources": {}},
                    "serverInfo": {
                        "name": "clean-server",
                        "version": "0.1.0",
                    },
                },
            }
        )

    elif method == "notifications/initialized":
        pass

    elif method == "resources/list":
        _write(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "resources": [],
                    "resourceTemplates": [
                        {
                            "uriTemplate": "file://{path}",
                            "name": "safe-reader",
                            "description": "Reads files only within the safe root",
                        }
                    ],
                },
            }
        )

    elif method == "resources/read":
        params = msg.get("params") or {}
        uri = str(params.get("uri", "")) if isinstance(params, dict) else ""  # type: ignore[union-attr]
        path_str = uri.removeprefix("file://")

        try:
            # Resolve against safe root and reject escapes.
            requested = (_SAFE_ROOT / path_str).resolve()
            if not str(requested).startswith(str(_SAFE_ROOT)):
                _write(
                    {
                        "jsonrpc": "2.0",
                        "id": msg_id,
                        "error": {
                            "code": -32001,
                            "message": "Access denied: path outside safe root",
                        },
                    }
                )
                return

            content = requested.read_text(errors="replace")
            _write(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"contents": [{"uri": uri, "text": content}]},
                }
            )
        except OSError as exc:
            _write(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32001, "message": str(exc)},
                }
            )

    elif msg_id is not None:
        _write(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": "Method not found"},
            }
        )


def main() -> None:
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg: dict[str, object] = json.loads(line)
            _handle(msg)
        except json.JSONDecodeError:
            pass


if __name__ == "__main__":
    main()
