#!/usr/bin/env python3
"""Vulnerable HTTP MCP fixture server — path traversal via tools/call.

HTTP analog of ``stdio_tool_traversal.py``: exposes a ``read_file`` tool
over Streamable HTTP transport with no path sanitisation.

Usage:
    python http_tool_traversal.py [--port PORT]
    (prints bound port to stdout)
"""

from __future__ import annotations

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


class VulnerableToolHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_POST(self) -> None:
        if self.path != "/mcp":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            msg: dict = json.loads(body)
        except json.JSONDecodeError:
            self._send(400, {"error": "bad json"})
            return
        self._send(200, self._dispatch(msg))

    def _dispatch(self, msg: dict) -> dict:
        method = str(msg.get("method", ""))
        msg_id = msg.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0", "id": msg_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "vulnerable-http-tool-server", "version": "0.1.0"},
                },
            }
        if method == "notifications/initialized":
            return {}
        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": msg_id,
                    "result": {"resources": [], "resourceTemplates": []}}
        if method == "tools/list":
            return {
                "jsonrpc": "2.0", "id": msg_id,
                "result": {
                    "tools": [{
                        "name": "read_file",
                        "description": "Read file contents.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}},
                            "required": ["path"],
                        },
                    }]
                },
            }
        if method == "tools/call":
            params = msg.get("params") or {}
            tool_name = str(params.get("name", ""))
            arguments = params.get("arguments") or {}
            if tool_name == "read_file":
                path_str = str(arguments.get("path", ""))
                try:
                    content = Path(path_str).read_text(errors="replace")
                    return {
                        "jsonrpc": "2.0", "id": msg_id,
                        "result": {"content": [{"type": "text", "text": content}]},
                    }
                except OSError as exc:
                    return {
                        "jsonrpc": "2.0", "id": msg_id,
                        "error": {"code": -32001, "message": str(exc)},
                    }
        if msg_id is not None:
            return {"jsonrpc": "2.0", "id": msg_id,
                    "error": {"code": -32601, "message": "Method not found"}}
        return {}

    def _send(self, status: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("MCP-Session-Id", "tool-session")
        self.end_headers()
        self.wfile.write(raw)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), VulnerableToolHandler)
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
