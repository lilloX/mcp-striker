#!/usr/bin/env python3
"""Deliberately vulnerable MCP fixture server.

Vulnerability: ``resources/read`` passes the URI path directly to
``pathlib.Path.read_text`` without any sanitisation.  Any path traversal
sequence (``../../``, absolute paths, etc.) will succeed if the OS permits.

Used by the integration tests to verify that ``mcp-striker`` detects and
reports the vulnerability.  NEVER deploy this in production.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


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
                        "name": "vulnerable-fs-server",
                        "version": "0.1.0",
                    },
                },
            }
        )

    elif method == "notifications/initialized":
        pass  # No response for notifications.

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
                            "name": "file-reader",
                            "description": "Reads a file from the filesystem",
                        }
                    ],
                },
            }
        )

    elif method == "resources/read":
        params = msg.get("params") or {}
        uri = str(params.get("uri", "")) if isinstance(params, dict) else ""  # type: ignore[union-attr]
        # VULNERABILITY: no sanitisation — path traversal succeeds.
        path_str = uri.removeprefix("file://")
        try:
            content = Path(path_str).read_text(errors="replace")
            _write(
                {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "contents": [{"uri": uri, "text": content}]
                    },
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
