"""Unit tests for the http-probe CLI command.

Covers:
  - --from-enum inherits target_url and output_dir from the registry snapshot
  - --url overrides the URL from --from-enum
  - missing --url and missing --from-enum raises Exit(1)
  - --from-enum with a STDIO-only registry (no target_url) raises Exit(1)
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import typer

from mcp_striker.cli import _http_probe
from mcp_striker.registry import CapabilityRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_registry(path: Path, target_url: str = "http://localhost:8080") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    registry = CapabilityRegistry(
        server_name="test-server",
        server_version="1.0",
        protocol_version="2025-03-26",
        target_url=target_url,
        target_cmd="",
        target_transport="http",
    )
    registry.save(path)


def _mock_engine() -> MagicMock:
    engine = MagicMock()
    engine.run = AsyncMock(return_value=[])
    return engine


# ---------------------------------------------------------------------------
# from-enum inherits URL and output dir
# ---------------------------------------------------------------------------


async def test_from_enum_inherits_url_and_output_dir(tmp_path: Path) -> None:
    snapshot = tmp_path / "sessions" / "test-server.json"
    _write_registry(snapshot)

    captured: dict = {}

    with patch("mcp_striker.cli.TransportProbeEngine") as MockEngine:
        MockEngine.return_value = _mock_engine()

        def capture(**kwargs):  # type: ignore[no-untyped-def]
            captured.update(kwargs)
            return _mock_engine()

        MockEngine.side_effect = capture
        await _http_probe(url=None, from_enum=snapshot, timeout=5.0, output_dir=None)

    assert captured["base_url"] == "http://localhost:8080"


async def test_from_enum_output_dir_uses_server_slug(tmp_path: Path) -> None:
    snapshot = tmp_path / "sessions" / "test-server.json"
    _write_registry(snapshot)

    written_dirs: list[Path] = []

    original_recorder = __import__(
        "mcp_striker.recorder", fromlist=["SessionRecorder"]
    ).SessionRecorder

    with patch("mcp_striker.cli.TransportProbeEngine") as MockEngine, \
         patch("mcp_striker.cli.SessionRecorder") as MockRecorder:
        MockEngine.return_value = _mock_engine()
        MockRecorder.side_effect = lambda session_dir: (
            written_dirs.append(session_dir) or original_recorder(session_dir=session_dir)
        )
        await _http_probe(url=None, from_enum=snapshot, timeout=5.0, output_dir=None)

    assert written_dirs, "SessionRecorder was not called"
    # output_dir should be .mcp-striker/test-server/
    assert written_dirs[0].parts[-3] == "test-server"


async def test_from_enum_url_can_be_overridden(tmp_path: Path) -> None:
    snapshot = tmp_path / "sessions" / "test-server.json"
    _write_registry(snapshot, target_url="http://original:8080")

    captured: dict = {}

    with patch("mcp_striker.cli.TransportProbeEngine") as MockEngine:
        def capture(**kwargs):  # type: ignore[no-untyped-def]
            captured.update(kwargs)
            return _mock_engine()
        MockEngine.side_effect = capture
        await _http_probe(
            url="http://override:9090", from_enum=snapshot,
            timeout=5.0, output_dir=None,
        )

    assert captured["base_url"] == "http://override:9090"


# ---------------------------------------------------------------------------
# from-enum with STDIO-only registry raises Exit(1)
# ---------------------------------------------------------------------------


async def test_from_enum_stdio_registry_exits(tmp_path: Path) -> None:
    snapshot = tmp_path / "sessions" / "stdio-server.json"
    _write_registry(snapshot, target_url="")  # no URL

    with pytest.raises(typer.Exit) as exc_info:
        await _http_probe(url=None, from_enum=snapshot, timeout=5.0, output_dir=None)

    assert exc_info.value.exit_code == 1


# ---------------------------------------------------------------------------
# Neither --url nor --from-enum → CLI guard raises Exit(1)
# ---------------------------------------------------------------------------


def test_missing_url_and_from_enum_exits() -> None:
    from typer.testing import CliRunner
    from mcp_striker.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["http-probe"])
    assert result.exit_code == 1
    assert "--url" in result.output or "required" in result.output.lower()
