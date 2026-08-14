#!/usr/bin/env python3
"""Malformed MCP fixture server.

``initialize`` and ``resources/list`` behave correctly so the
``enum`` flow can complete.  All ``resources/read`` responses are
intentionally broken JSON to verify that the Strike Engine never
crashes on garbage input from a target server.
"""

from __future__ import annotations

import json
import sys


def _write_json(obj: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _write_raw(text: str) -> None:
    """Write a raw (potentially broken) line to stdout."""
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def _handle(msg: dict[str, object]) -> None:
    method = str(msg.get("method", ""))
    msg_id = msg.get("id")

    if method == "initialize":
        _write_json(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {"resources": {}},
                    "serverInfo": {
                        "name": "malformed-server",
                        "version": "0.1.0",
                    },
                },
            }
        )

    elif method == "notifications/initialized":
        pass

    elif method == "resources/list":
        _write_json(
            {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "resources": [],
                    "resourceTemplates": [
                        {
                            "uriTemplate": "file://{path}",
                            "name": "broken-reader",
                            "description": "Always returns malformed JSON",
                        }
                    ],
                },
            }
        )

    elif method == "resources/read":
        # Return deliberately broken JSON — no valid id field either,
        # so the reader loop's Future will time out.
        _write_raw("{this is: not, valid} json!!!")

    elif msg_id is not None:
        _write_json(
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
