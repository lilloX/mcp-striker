#!/usr/bin/env python3
"""Clean (non-vulnerable) HTTP MCP fixture server.

Security controls implemented:
    1. ``Origin`` validation — only ``http://localhost`` and ``http://127.0.0.1``
       are accepted; all others receive 403.
    2. ``MCP-Session-Id`` validation — only the session ID issued by this server
       is accepted on post-initialize requests; fabricated IDs receive 401.
    3. ``MCP-Protocol-Version`` validation — only ``2025-03-26`` is accepted;
       others receive a JSON-RPC error.
    4. ``resources/read`` confines reads to a safe temp directory.

Used as a false-positive guard: ``mcp-striker http-probe`` must produce
zero findings against this server.
"""

from __future__ import annotations

import argparse
import json
import secrets
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

_ALLOWED_ORIGINS = {"http://localhost", "http://127.0.0.1"}
_SUPPORTED_VERSION = "2025-03-26"

_SAFE_ROOT = Path(tempfile.gettempdir()) / "mcp-clean-http-server"
_SAFE_ROOT.mkdir(exist_ok=True)
(_SAFE_ROOT / "hello.txt").write_text("Hello from the clean HTTP server!\n")


class CleanHandler(BaseHTTPRequestHandler):
    """Handles POST /mcp with full security validation."""

    # Shared state across requests (single-threaded server).
    _issued_session_id: str | None = None

    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_POST(self) -> None:
        if self.path != "/mcp":
            self._send(404, None)
            return

        # 1. Origin check.
        origin = self.headers.get("Origin", "")
        if origin and origin not in _ALLOWED_ORIGINS:
            self._send_raw(403, b"Forbidden: invalid Origin")
            return

        # 2. Session check (skip for initialize and notifications).
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            msg: dict[str, object] = json.loads(body)
        except json.JSONDecodeError:
            self._send(400, None)
            return

        method = str(msg.get("method", ""))
        incoming_session = self.headers.get("MCP-Session-Id", "")

        if method not in ("initialize", "notifications/initialized"):
            if CleanHandler._issued_session_id is None:
                self._send(401, {"jsonrpc": "2.0", "id": msg.get("id"),
                                 "error": {"code": -32001, "message": "No active session"}})
                return
            if incoming_session != CleanHandler._issued_session_id:
                self._send_raw(401, b"Unauthorized: invalid session ID")
                return

        response = self._dispatch(msg)
        self._send(200, response)

    def _dispatch(self, msg: dict[str, object]) -> dict[str, object] | None:
        method = str(msg.get("method", ""))
        msg_id = msg.get("id")

        if method == "initialize":
            # 3. Protocol version check.
            params = msg.get("params") or {}
            version = str(params.get("protocolVersion", "")) if isinstance(params, dict) else ""  # type: ignore[union-attr]
            if version != _SUPPORTED_VERSION:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32600, "message": f"Unsupported protocol version: {version!r}"},
                }
            CleanHandler._issued_session_id = secrets.token_hex(16)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": _SUPPORTED_VERSION,
                    "capabilities": {"resources": {}},
                    "serverInfo": {"name": "clean-http-server", "version": "0.1.0"},
                },
            }

        if method == "notifications/initialized":
            return None

        if method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "resources": [],
                    "resourceTemplates": [
                        {"uriTemplate": "file://{path}", "name": "safe-reader"},
                    ],
                },
            }

        if method == "resources/read":
            params = msg.get("params") or {}
            uri = str(params.get("uri", "")) if isinstance(params, dict) else ""  # type: ignore[union-attr]
            path_str = uri.removeprefix("file://")
            try:
                requested = (_SAFE_ROOT / path_str).resolve()
                if not str(requested).startswith(str(_SAFE_ROOT)):
                    return {"jsonrpc": "2.0", "id": msg_id,
                            "error": {"code": -32001, "message": "Access denied"}}
                content = requested.read_text(errors="replace")
                return {"jsonrpc": "2.0", "id": msg_id,
                        "result": {"contents": [{"uri": uri, "text": content}]}}
            except OSError as exc:
                return {"jsonrpc": "2.0", "id": msg_id,
                        "error": {"code": -32001, "message": str(exc)}}

        if msg_id is not None:
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32601, "message": "Method not found"}}
        return None

    def _send(self, status: int, body: dict[str, object] | None) -> None:
        if body is None:
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if CleanHandler._issued_session_id:
            self.send_header("MCP-Session-Id", CleanHandler._issued_session_id)
        self.end_headers()
        self.wfile.write(raw)

    def _send_raw(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()

    server = HTTPServer(("127.0.0.1", args.port), CleanHandler)
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
