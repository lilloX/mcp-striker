#!/usr/bin/env python3
"""Vulnerable HTTP MCP fixture server — IDOR (token present but not validated).

Resources:
    ``resource://tenant-a/secret.txt``  → "Alice's secret: TOP SECRET DATA"
    ``resource://tenant-a/private.key`` → "Alice's private key: -----BEGIN..."

Authentication:
    Checks that ``Authorization: Bearer <token>`` is present.

VULNERABILITY:
    Validates only that a token exists — does NOT verify that the token
    belongs to the resource's owner.  Bob's token lets him read Alice's
    resources.

Usage:
    python http_idor.py [--port PORT]
    (prints bound port to stdout)
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

_VALID_TOKENS = {"alice-secret-token", "bob-secret-token"}
_RESOURCES: dict[str, str] = {
    "resource://tenant-a/secret.txt":  "Alice's secret: TOP SECRET DATA",
    "resource://tenant-a/private.key": "Alice's private key: -----BEGIN RSA PRIVATE KEY-----",
}


class IdorHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/mcp":
            self._send(404, {"error": "not found"})
            return

        # VULNERABILITY: only checks token presence, not ownership.
        auth = self.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip()
        if token not in _VALID_TOKENS:
            self._send_raw(401, b"Unauthorized")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            msg: dict[str, object] = json.loads(body)
        except json.JSONDecodeError:
            self._send(400, {"error": "bad json"})
            return

        self._send(200, self._dispatch(msg))

    def _dispatch(self, msg: dict[str, object]) -> dict[str, object]:
        method = str(msg.get("method", ""))
        msg_id = msg.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0", "id": msg_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"resources": {}},
                    "serverInfo": {"name": "idor-http-server", "version": "0.1.0"},
                },
            }

        if method == "notifications/initialized":
            return {}

        if method == "resources/list":
            return {
                "jsonrpc": "2.0", "id": msg_id,
                "result": {
                    "resources": [
                        {"uri": uri, "name": uri.split("/")[-1]}
                        for uri in _RESOURCES
                    ],
                    "resourceTemplates": [],
                },
            }

        if method == "resources/read":
            params = msg.get("params") or {}
            uri = str(params.get("uri", "")) if isinstance(params, dict) else ""  # type: ignore[union-attr]
            # VULNERABILITY: no ownership check.
            if uri in _RESOURCES:
                return {
                    "jsonrpc": "2.0", "id": msg_id,
                    "result": {"contents": [{"uri": uri, "text": _RESOURCES[uri]}]},
                }
            return {
                "jsonrpc": "2.0", "id": msg_id,
                "error": {"code": -32001, "message": f"Resource not found: {uri}"},
            }

        if msg_id is not None:
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32601, "message": "Method not found"}}
        return {}

    def _send(self, status: int, body: dict[str, object]) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("MCP-Session-Id", "idor-session")
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
    server = HTTPServer(("127.0.0.1", args.port), IdorHandler)
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
