#!/usr/bin/env python3
"""Vulnerable STDIO MCP fixture server — IDOR (no access control).

Resources:
    ``resource://tenant-a/secret.txt``  → "Alice's secret: TOP SECRET DATA"
    ``resource://tenant-a/private.key`` → "Alice's private key: -----BEGIN..."

Authentication:
    Reads ``MCP_AUTH_TOKEN`` from the environment to identify the caller
    (for logging purposes only).

VULNERABILITY:
    No authorisation check — any caller with any (or no) token can read any
    resource.  ``resources/read`` returns the content regardless of identity.

Used by integration tests to verify that ``AuthDiffEngine`` detects IDOR
over STDIO transport.
"""

from __future__ import annotations

import json
import sys

_RESOURCES: dict[str, str] = {
    "resource://tenant-a/secret.txt":  "Alice's secret: TOP SECRET DATA",
    "resource://tenant-a/private.key": "Alice's private key: -----BEGIN RSA PRIVATE KEY-----",
}


def _write(obj: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _handle(msg: dict[str, object]) -> None:
    method = str(msg.get("method", ""))
    msg_id = msg.get("id")

    if method == "initialize":
        _write({
            "jsonrpc": "2.0", "id": msg_id,
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"resources": {}},
                "serverInfo": {"name": "idor-stdio-server", "version": "0.1.0"},
            },
        })

    elif method == "notifications/initialized":
        pass

    elif method == "resources/list":
        _write({
            "jsonrpc": "2.0", "id": msg_id,
            "result": {
                "resources": [
                    {"uri": uri, "name": uri.split("/")[-1]}
                    for uri in _RESOURCES
                ],
                "resourceTemplates": [],
            },
        })

    elif method == "resources/read":
        params = msg.get("params") or {}
        uri = str(params.get("uri", "")) if isinstance(params, dict) else ""  # type: ignore[union-attr]
        # VULNERABILITY: no token or tenant check.
        if uri in _RESOURCES:
            _write({
                "jsonrpc": "2.0", "id": msg_id,
                "result": {"contents": [{"uri": uri, "text": _RESOURCES[uri]}]},
            })
        else:
            _write({
                "jsonrpc": "2.0", "id": msg_id,
                "error": {"code": -32001, "message": f"Resource not found: {uri}"},
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
            msg: dict[str, object] = json.loads(line)
            _handle(msg)
        except json.JSONDecodeError:
            pass


if __name__ == "__main__":
    main()
