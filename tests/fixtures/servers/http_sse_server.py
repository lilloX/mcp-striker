#!/usr/bin/env python3
"""Legacy HTTP+SSE MCP fixture server (protocol 2024-11-05).

Implements the old SSE transport:
  GET /sse   → opens SSE stream, sends endpoint event
  POST /msg  → receives JSON-RPC requests, sends responses via SSE stream

Usage: python http_sse_server.py [--port PORT]
Prints the bound port to stdout on startup.
"""
from __future__ import annotations

import argparse
import json
import queue
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer

# Per-session response queues: session_id → queue of json strings
_sessions: dict[str, queue.Queue] = {}
_sessions_lock = threading.Lock()


class SseHandler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def do_GET(self):
        if self.path != "/sse":
            self.send_response(404)
            self.end_headers()
            return

        session_id = str(uuid.uuid4())[:8]
        q: queue.Queue = queue.Queue()
        with _sessions_lock:
            _sessions[session_id] = q

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()

        # Send endpoint event
        endpoint = f"/msg?session={session_id}"
        self.wfile.write(f"event: endpoint\ndata: {endpoint}\n\n".encode())
        self.wfile.flush()

        # Stream responses until client disconnects
        try:
            while True:
                try:
                    msg = q.get(timeout=30)
                    if msg is None:
                        break
                    self.wfile.write(f"event: message\ndata: {msg}\n\n".encode())
                    self.wfile.flush()
                except queue.Empty:
                    # Heartbeat
                    self.wfile.write(b": heartbeat\n\n")
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with _sessions_lock:
                _sessions.pop(session_id, None)

    def do_POST(self):
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(self.path)
        if parsed.path != "/msg":
            self.send_response(404)
            self.end_headers()
            return

        params = parse_qs(parsed.query)
        session_id = params.get("session", [None])[0]

        with _sessions_lock:
            q = _sessions.get(session_id)
        if q is None:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b'{"error": "unknown session"}')
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            msg = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return

        response = self._dispatch(msg)
        if response:
            q.put(json.dumps(response))

        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _dispatch(self, msg: dict) -> dict | None:
        method = msg.get("method", "")
        mid = msg.get("id")

        if method == "initialize":
            return {
                "jsonrpc": "2.0", "id": mid,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"resources": {}},
                    "serverInfo": {"name": "sse-fixture-server", "version": "0.1.0"},
                },
            }
        if method == "notifications/initialized":
            return None
        if method == "resources/list":
            return {
                "jsonrpc": "2.0", "id": mid,
                "result": {"resources": [], "resourceTemplates": [
                    {"uriTemplate": "file://{path}", "name": "files"},
                ]},
            }
        if method == "resources/read":
            uri = (msg.get("params") or {}).get("uri", "")
            try:
                from pathlib import Path
                text = Path(uri.removeprefix("file://")).read_text(errors="replace")
                return {
                    "jsonrpc": "2.0", "id": mid,
                    "result": {"contents": [{"uri": uri, "text": text}]},
                }
            except Exception as exc:
                return {"jsonrpc": "2.0", "id": mid,
                        "error": {"code": -32001, "message": str(exc)}}
        if mid is not None:
            return {"jsonrpc": "2.0", "id": mid,
                    "error": {"code": -32601, "message": "Method not found"}}
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=0)
    args = parser.parse_args()
    server = HTTPServer(("127.0.0.1", args.port), SseHandler)
    print(server.server_address[1], flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
