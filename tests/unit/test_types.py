"""Unit tests for mcp_striker/types.py."""

from __future__ import annotations

import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from mcp_striker.types import _validate, parse_json_value

# ---------------------------------------------------------------------------
# parse_json_value
# ---------------------------------------------------------------------------


def test_parse_null() -> None:
    assert parse_json_value(b"null") is None


def test_parse_bool_true() -> None:
    assert parse_json_value(b"true") is True


def test_parse_bool_false() -> None:
    assert parse_json_value(b"false") is False


def test_parse_int() -> None:
    result = parse_json_value(b"42")
    assert result == 42


def test_parse_float() -> None:
    result = parse_json_value(b"3.14")
    assert abs(float(result) - 3.14) < 1e-9  # type: ignore[arg-type]


def test_parse_string() -> None:
    assert parse_json_value(b'"hello"') == "hello"


def test_parse_list() -> None:
    assert parse_json_value(b"[1, 2, 3]") == [1, 2, 3]


def test_parse_nested_object() -> None:
    raw = b'{"a": {"b": [1, null, true]}}'
    result = parse_json_value(raw)
    assert result == {"a": {"b": [1, None, True]}}


def test_parse_invalid_json_raises() -> None:
    with pytest.raises(json.JSONDecodeError):
        parse_json_value(b"{broken")


def test_parse_empty_bytes_raises() -> None:
    with pytest.raises(json.JSONDecodeError):
        parse_json_value(b"")


# ---------------------------------------------------------------------------
# _validate — unexpected types
# ---------------------------------------------------------------------------


def test_validate_rejects_set() -> None:
    with pytest.raises(TypeError, match="Unexpected Python type"):
        _validate({1, 2, 3})


def test_validate_rejects_bytes() -> None:
    with pytest.raises(TypeError, match="Unexpected Python type"):
        _validate(b"bytes")


def test_validate_rejects_nested_bytes() -> None:
    with pytest.raises(TypeError):
        _validate({"key": b"value"})


def test_validate_bool_not_confused_with_int() -> None:
    # bool is a subclass of int; _validate must preserve the bool type.
    result = _validate(True)
    assert result is True
    assert isinstance(result, bool)


# ---------------------------------------------------------------------------
# Hypothesis: the boundary never raises an unhandled exception
# ---------------------------------------------------------------------------


@given(st.binary(max_size=512))
def test_parse_json_value_never_crashes(raw: bytes) -> None:
    """parse_json_value raises only JSONDecodeError, ValueError, or TypeError — never anything else."""
    try:
        parse_json_value(raw)
    except (json.JSONDecodeError, ValueError, TypeError):
        pass
