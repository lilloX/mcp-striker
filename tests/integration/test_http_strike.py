"""Integration tests for Milestone 2 — Streamable HTTP transport.

Test matrix:
    Python vulnerable HTTP server:
        - enum + path traversal via HTTP finds vulnerability
        - origin probe detects missing check
        - session-reuse probe detects missing check
        - protocol-version probe detects missing check

    Python clean HTTP server:
        - all probes produce zero findings (false-positive guard)

    TypeScript vulnerable HTTP server:
        - enum works (cross-language fixture validation)
        - at least one transport probe fires
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcp_striker.engine.strike import StrikeEngine
from mcp_striker.engine.transport_probe import TransportProbeEngine
from mcp_striker.evidence import EvidenceGenerator
from mcp_striker.models import SafetyContext, TransportContext
from mcp_striker.protocol.client import ProtocolClient
from mcp_striker.recorder import SessionRecorder
from mcp_striker.transport.streamable_http import StreamableHttpTransport

SERVERS_DIR = Path(__file__).parent.parent / "fixtures" / "servers"
TS_DIST = SERVERS_DIR / "ts_server" / "dist"


# ---------------------------------------------------------------------------
# Fixture: start an HTTP server subprocess, yield its URL, then stop it
# ---------------------------------------------------------------------------


def _start_server(cmd: list[str]) -> tuple[subprocess.Popen[str], str]:
    """Start *cmd*, read the port from its first stdout line, return (proc, url)."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    # Give the server up to 5 s to print its port.
    for _ in range(50):
        line = proc.stdout.readline().strip()  # type: ignore[union-attr]
        if line.isdigit():
            return proc, f"http://127.0.0.1:{line}"
        time.sleep(0.1)
    proc.kill()
    raise RuntimeError(f"Server did not print a port within 5 s: {cmd}")


@pytest.fixture()
def python_vulnerable_server():
    proc, url = _start_server([sys.executable, str(SERVERS_DIR / "http_vulnerable.py")])
    yield url
    proc.kill()
    proc.wait()


@pytest.fixture()
def python_clean_server():
    proc, url = _start_server([sys.executable, str(SERVERS_DIR / "http_clean.py")])
    yield url
    proc.kill()
    proc.wait()


@pytest.fixture()
def ts_vulnerable_server():
    js_path = TS_DIST / "http_vulnerable.js"
    if not js_path.exists():
        pytest.skip("TypeScript fixture not compiled — run tsc in ts_server/")
    proc, url = _start_server(["node", str(js_path)])
    yield url
    proc.kill()
    proc.wait()


# ---------------------------------------------------------------------------
# Helper: run full enum + strike against an HTTP server
# ---------------------------------------------------------------------------


async def _enum_and_strike(
    url: str,
    tmp_path: Path,
) -> tuple[object, list[str]]:
    transport = StreamableHttpTransport(base_url=url, timeout=10.0)
    context = TransportContext(session_id="test", target_url=url)

    await transport.connect()
    try:
        client = ProtocolClient(transport=transport, context=context)
        await client.initialize()
        registry = await client.enumerate_capabilities()

        recorder = SessionRecorder(session_dir=tmp_path / "session")
        evidence_gen = EvidenceGenerator(findings_dir=tmp_path / "findings")

        engine = StrikeEngine(
            transport=transport,
            registry=registry,
            recorder=recorder,
            evidence_generator=evidence_gen,
            safety_engine=__import__("mcp_striker.safety", fromlist=["SafetyPolicyEngine"]).SafetyPolicyEngine(),
            safety_context=SafetyContext(),
            transport_context=context,
            concurrency=3,
        )
        finding_ids = await engine.run()
    finally:
        await transport.close()

    return registry, finding_ids


async def _run_transport_probes(url: str, tmp_path: Path) -> list[str]:
    recorder = SessionRecorder(session_dir=tmp_path / "session")
    evidence_gen = EvidenceGenerator(findings_dir=tmp_path / "findings")
    engine = TransportProbeEngine(
        base_url=url,
        recorder=recorder,
        evidence_generator=evidence_gen,
        session_id="test",
        timeout=5.0,
    )
    return await engine.run()


# ---------------------------------------------------------------------------
# Python vulnerable server tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_enum_finds_templates(python_vulnerable_server: str, tmp_path: Path) -> None:
    registry, _ = await _enum_and_strike(python_vulnerable_server, tmp_path)
    assert registry.server_name == "vulnerable-http-server"  # type: ignore[attr-defined]
    assert len(registry.resource_templates) == 1  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_http_strike_finds_path_traversal(python_vulnerable_server: str, tmp_path: Path) -> None:
    _, finding_ids = await _enum_and_strike(python_vulnerable_server, tmp_path)
    assert finding_ids, "Expected at least one path-traversal finding via HTTP"


@pytest.mark.asyncio
async def test_origin_probe_detects_missing_check(python_vulnerable_server: str, tmp_path: Path) -> None:
    finding_ids = await _run_transport_probes(python_vulnerable_server, tmp_path)
    names = [fid for fid in finding_ids]  # all IDs
    assert names, "Origin probe should detect the missing Origin check"


@pytest.mark.asyncio
async def test_transport_probes_find_all_three_issues(python_vulnerable_server: str, tmp_path: Path) -> None:
    finding_ids = await _run_transport_probes(python_vulnerable_server, tmp_path)
    # All three transport probes should fire against the vulnerable server.
    assert len(finding_ids) == 3, (
        f"Expected 3 transport probe findings, got {len(finding_ids)}"
    )


# ---------------------------------------------------------------------------
# Python clean server — false-positive guard
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_clean_server_no_transport_probe_findings(python_clean_server: str, tmp_path: Path) -> None:
    finding_ids = await _run_transport_probes(python_clean_server, tmp_path)
    assert finding_ids == [], f"False positive(s) on clean HTTP server: {finding_ids}"


@pytest.mark.asyncio
async def test_clean_server_no_path_traversal_findings(python_clean_server: str, tmp_path: Path) -> None:
    _, finding_ids = await _enum_and_strike(python_clean_server, tmp_path)
    assert finding_ids == [], f"False positive(s) on clean HTTP server: {finding_ids}"


# ---------------------------------------------------------------------------
# TypeScript server — cross-language fixture
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ts_server_enum_works(ts_vulnerable_server: str, tmp_path: Path) -> None:
    registry, _ = await _enum_and_strike(ts_vulnerable_server, tmp_path)
    assert registry.server_name == "vulnerable-ts-http-server"  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_ts_server_transport_probes_fire(ts_vulnerable_server: str, tmp_path: Path) -> None:
    finding_ids = await _run_transport_probes(ts_vulnerable_server, tmp_path)
    assert finding_ids, "Expected transport probe findings against the TS server"
