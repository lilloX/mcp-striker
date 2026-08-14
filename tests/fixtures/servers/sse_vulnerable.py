#!/usr/bin/env python3
"""Vulnerable SSE MCP fixture server (protocol 2024-11-05).

Implements the legacy HTTP+SSE transport:
  GET  /sse       → SSE stream; sends 'endpoint' event immediately
  POST /messages  → receives JSON-RPC requests; sends responses via SSE

Has a deliberate path traversal vulnerability in read_file tool.
Used to verify that SseTransport + FlowEngine work correctly against
a real SSE server.
"""

from __future__ import annotations

import argparse
import json
import queue
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path


class SseVulnerableHandler(BaseHTTPRequestHandler):
    # Shared state: session_id → queue of SSE messages
    sessions: dict[str, queue.Queue] = {}
    lock = threading.Lock()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass

    # ------------------------------------------------------------------
    # GET /sse — open SSE stream
    # ------------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        if not self.path.startswith("/sse"):
            self.send_error(404)
            return

        session_id = str(uuid.uuid4())[:8]
        q: queue.Queue = queue.Queue()
        with self.lock:
            self.sessions[session_id] = q

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        # Send endpoint event immediately
        endpoint = f"/messages?sessionId={session_id}"
        self._write_sse("endpoint", endpoint)

        # Stream responses as they arrive
        try:
            while True:
                try:
                    msg = q.get(timeout=1.0)
                    self._write_sse("message", json.dumps(msg))
                except queue.Empty:
                    # Heartbeat
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with self.lock:
                self.sessions.pop(session_id, None)

    def _write_sse(self, event: str, data: str) -> None:
        line = f"event: {event}\ndata: {data}\n\n".encode()
        self.wfile.write(line)
        self.wfile.flush()

    # ------------------------------------------------------------------
    # POST /messages — receive JSON-RPC requests
    # ------------------------------------------------------------------
    def do_POST(self) -> None:  # noqa: N802
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/messages"):
            self.send_error(404)
            return

        qs = parse_qs(parsed.query)
        session_ids = qs.get("sessionId", [])
        if not session_ids:
            self.send_error(400, "Missing sessionId")
            return
        session_id = session_ids[0]

        with self.lock:
            q = self.sessions.get(session_id)
        if q is None:
            self.send_error(404, "Session not found")
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            msg = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "Bad JSON")
            return

        # Dispatch and queue the response
        response = self._dispatch(msg)
        if response:
            q.put(response)

        # Return 202 Accepted
        self.send_response(202)
        self.end_headers()

    def _dispatch(self, msg: dict) -> dict | None:
        method = str(msg.get("method", ""))
        msg_id = msg.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0", "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}, "resources": {}},
                    "serverInfo": {"name": "sse-vulnerable-server", "version": "0.1.0"},
                },
            }

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            return {
                "jsonrpc": "2.0", "id": msg_id,
                "result": {
                    "tools": [{
                        "name": "read_file",
                        "description": "Read a file from the filesystem.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string", "description": "File path"},
                            },
                            "required": ["path"],
                        },
                    }]
                },
            }

        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": []}}

        if method == "tools/call":
            params = msg.get("params") or {}
            tool = str(params.get("name", ""))
            args = params.get("arguments") or {}

            if tool == "read_file":
                path_str = str(args.get("path", ""))
                try:
                    # VULNERABILITY: no path sanitisation
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
            return {
                "jsonrpc": "2.0", "id": msg_id,
                "error": {"code": -32601, "message": "Method not found"},
            }
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), SseVulnerableHandler)
    import sys
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
