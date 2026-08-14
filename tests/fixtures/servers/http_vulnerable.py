#!/usr/bin/env python3
"""Vulnerable HTTP MCP fixture server (Streamable HTTP transport).

Vulnerabilities implemented deliberately:
    1. No ``Origin`` header validation — accepts any origin (CORS / DNS rebinding).
    2. No ``MCP-Session-Id`` validation — accepts fabricated session IDs.
    3. No ``MCP-Protocol-Version`` validation — accepts any version string.
    4. ``resources/read`` has no path sanitisation (path traversal).

Used by integration tests to verify that ``mcp-striker http-probe`` and
``mcp-striker strike --transport http`` detect all issues.
NEVER deploy this in production.

Usage:
    python http_vulnerable.py [--port PORT]
"""

from __future__ import annotations

import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# ---------------------------------------------------------------------------
# Request counter for unique response IDs
# ---------------------------------------------------------------------------

_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------


class VulnerableHandler(BaseHTTPRequestHandler):
    """Handles POST /mcp — no security checks whatsoever."""

    def log_message(self, format: str, *args: object) -> None:
        pass  # suppress access log noise during tests

    def do_POST(self) -> None:
        if self.path != "/mcp":
            self._send(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        try:
            msg: dict[str, object] = json.loads(body)
        except json.JSONDecodeError:
            self._send(400, {"error": "bad json"})
            return

        response = self._dispatch(msg)
        self._send(200, response)

    def _dispatch(self, msg: dict[str, object]) -> dict[str, object]:
        method = str(msg.get("method", ""))
        msg_id = msg.get("id")

        if method == "initialize":
            # VULNERABILITY 1 & 3: no Origin or version check.
            self.server.session_id = "server-session-abc123"  # type: ignore[attr-defined]
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"resources": {}},
                    "serverInfo": {"name": "vulnerable-http-server", "version": "0.1.0"},
                },
            }

        if method == "notifications/initialized":
            return {}  # no response body for notifications

        if method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "resources": [],
                    "resourceTemplates": [
                        {"uriTemplate": "file://{path}", "name": "file-reader"},
                    ],
                },
            }

        if method == "resources/read":
            params = msg.get("params") or {}
            uri = str(params.get("uri", "")) if isinstance(params, dict) else ""  # type: ignore[union-attr]
            path_str = uri.removeprefix("file://")
            # VULNERABILITY 4: no path sanitisation.
            try:
                content = Path(path_str).read_text(errors="replace")
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {"contents": [{"uri": uri, "text": content}]},
                }
            except OSError as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32001, "message": str(exc)},
                }

        if msg_id is not None:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": "Method not found"},
            }
        return {}

    def _send(self, status: int, body: dict[str, object]) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        # VULNERABILITY 2: session ID always returned, never validated on input.
        self.send_header("MCP-Session-Id", "server-session-abc123")
        self.end_headers()
        self.wfile.write(raw)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)  # 0 = OS assigns free port
    args = parser.parse_args()

    server = HTTPServer(("127.0.0.1", args.port), VulnerableHandler)
    # Print the actual port so the test harness can read it.
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
