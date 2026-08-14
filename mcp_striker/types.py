"""Strict JSON type hierarchy.

All untrusted bytes from MCP servers enter the codebase through
``parse_json_value``.  No ``Any`` escapes this module.
"""

from __future__ import annotations

import json
from typing import cast

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

JsonScalar = str | int | float | bool | None
JsonValue = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject = dict[str, JsonValue]


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate(obj: object) -> JsonValue:
    """Recursively validate that *obj* contains only JSON-compatible types.

    Raises:
        TypeError: if an unexpected Python type (e.g. ``set``, ``bytes``) is
            encountered anywhere in the structure.
    """
    # bool must be checked before int because bool is a subclass of int.
    if obj is None or isinstance(obj, bool):
        return cast(JsonValue, obj)
    if isinstance(obj, (int, float, str)):
        return cast(JsonValue, obj)
    if isinstance(obj, list):
        return [_validate(item) for item in obj]
    if isinstance(obj, dict):
        if not all(isinstance(k, str) for k in obj):
            raise TypeError("JSON object keys must all be strings")
        return {k: _validate(v) for k, v in obj.items()}
    raise TypeError(
        f"Unexpected Python type in JSON payload: {type(obj).__name__!r}"
    )


def parse_json_value(raw: bytes) -> JsonValue:
    """Parse *raw* bytes as JSON and return a strictly-typed ``JsonValue``.

    Raises:
        ValueError: if *raw* cannot be decoded as UTF-8 or is not valid JSON.
        TypeError: if the parsed structure contains non-JSON Python types.
    """
    try:
        parsed: object = json.loads(raw)
    except UnicodeDecodeError as exc:
        raise ValueError(f"Invalid UTF-8 in server response: {exc}") from exc
    return _validate(parsed)
