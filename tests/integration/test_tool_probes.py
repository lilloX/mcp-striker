"""Integration tests for Milestone 5 — Tool Call Probes."""

from __future__ import annotations

import asyncio
import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcp_striker.dsl.parser import YAMLFlowParser
from mcp_striker.dsl.selector import ModuleSelector
from mcp_striker.engine.flow import FlowEngine
from mcp_striker.evidence import EvidenceGenerator
from mcp_striker.models import SafetyContext, TransportContext
from mcp_striker.protocol.client import ProtocolClient
from mcp_striker.recorder import SessionRecorder
from mcp_striker.safety import SafetyPolicyEngine
from mcp_striker.transport.stdio import StdioTransport
from mcp_striker.transport.streamable_http import StreamableHttpTransport

SERVERS_DIR = Path(__file__).parent.parent / "fixtures" / "servers"
MODULES_DIR = Path(__file__).parent.parent.parent / "modules"
parser = YAMLFlowParser()
selector = ModuleSelector()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _build_stdio_engine(
    server_script: Path,
    tmp_path: Path,
    allow_mutating: bool = False,
    timeout: float = 10.0,
) -> tuple[FlowEngine, StdioTransport]:
    cmd = [sys.executable, str(server_script)]
    transport = StdioTransport(cmd=cmd, timeout=timeout)
    context = TransportContext(session_id="test", target_cmd=" ".join(cmd))
    await transport.connect()
    client = ProtocolClient(transport=transport, context=context)
    await client.initialize()
    registry = await client.enumerate_capabilities()

    engine = FlowEngine(
        transport=transport,
        registry=registry,
        recorder=SessionRecorder(session_dir=tmp_path / "session"),
        evidence_generator=EvidenceGenerator(findings_dir=tmp_path / "findings"),
        safety_engine=SafetyPolicyEngine(),
        safety_context=SafetyContext(allow_mutating=allow_mutating),
        transport_context=context,
        semaphore=asyncio.Semaphore(5),
    )
    return engine, transport


def _start_http_server(script: Path) -> tuple[subprocess.Popen, str]:
    proc = subprocess.Popen(
        [sys.executable, str(script)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    for _ in range(50):
        line = proc.stdout.readline().strip()
        if line.isdigit():
            return proc, f"http://127.0.0.1:{line}"
        time.sleep(0.1)
    proc.kill()
    raise RuntimeError(f"Server {script} did not print port in time")


@pytest.fixture()
def http_tool_server():
    proc, url = _start_http_server(SERVERS_DIR / "http_tool_traversal.py")
    yield url
    proc.kill()
    proc.wait()


# ---------------------------------------------------------------------------
# STDIO enum populates registry.tools
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stdio_enum_discovers_tools(tmp_path: Path) -> None:
    engine, transport = await _build_stdio_engine(
        SERVERS_DIR / "stdio_tool_traversal.py", tmp_path
    )
    try:
        assert len(engine._registry.tools) >= 1
        tool_names = [t.name for t in engine._registry.tools]
        assert "read_file" in tool_names
    finally:
        await transport.close()


# ---------------------------------------------------------------------------
# STDIO — path traversal via tool
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tool_path_traversal_finds_vuln_stdio(tmp_path: Path) -> None:
    engine, transport = await _build_stdio_engine(
        SERVERS_DIR / "stdio_tool_traversal.py", tmp_path
    )
    try:
        module = parser.load(MODULES_DIR / "basic/tools/tool_path_traversal.yaml")
        selected = selector.select([module], engine._registry)
        assert selected, "tool_path_traversal module must be selected for vulnerable server"
        finding_ids = await engine.run_module(module)
    finally:
        await transport.close()

    assert finding_ids, "Expected path traversal findings via tools/call on STDIO server"


@pytest.mark.asyncio
async def test_tool_clean_server_no_findings(tmp_path: Path) -> None:
    engine, transport = await _build_stdio_engine(
        SERVERS_DIR / "stdio_tool_clean.py", tmp_path
    )
    try:
        module = parser.load(MODULES_DIR / "basic/tools/tool_path_traversal.yaml")
        selected = selector.select([module], engine._registry)
        assert selected, "tool_path_traversal must be selected for clean server too"
        finding_ids = await engine.run_module(module)
    finally:
        await transport.close()

    assert finding_ids == [], f"False positives on clean tool server: {finding_ids}"


# ---------------------------------------------------------------------------
# HTTP — path traversal via tool
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tool_path_traversal_finds_vuln_http(
    http_tool_server: str, tmp_path: Path
) -> None:
    transport = StreamableHttpTransport(base_url=http_tool_server, timeout=10.0)
    context = TransportContext(session_id="test", target_url=http_tool_server)
    await transport.connect()
    try:
        client = ProtocolClient(transport=transport, context=context)
        await client.initialize()
        registry = await client.enumerate_capabilities()

        engine = FlowEngine(
            transport=transport,
            registry=registry,
            recorder=SessionRecorder(session_dir=tmp_path / "session"),
            evidence_generator=EvidenceGenerator(findings_dir=tmp_path / "findings"),
            safety_engine=SafetyPolicyEngine(),
            safety_context=SafetyContext(allow_mutating=False),
            transport_context=context,
            semaphore=asyncio.Semaphore(5),
        )
        module = parser.load(MODULES_DIR / "basic/tools/tool_path_traversal.yaml")
        selected = selector.select([module], registry)
        assert selected
        finding_ids = await engine.run_module(module)
    finally:
        await transport.close()

    assert finding_ids, "Expected path traversal findings via tools/call on HTTP server"


# ---------------------------------------------------------------------------
# Safety: read_only tools allowed, mutating blocked by default
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_read_only_tool_probe_runs_without_allow_mutating(
    tmp_path: Path,
) -> None:
    """read_file is classified READ_ONLY — no --allow-mutating needed."""
    engine, transport = await _build_stdio_engine(
        SERVERS_DIR / "stdio_tool_traversal.py", tmp_path, allow_mutating=False
    )
    try:
        module = parser.load(MODULES_DIR / "basic/tools/tool_path_traversal.yaml")
        # Should not raise — read_file is safe by classification.
        finding_ids = await engine.run_module(module)
    finally:
        await transport.close()
    # We care that it ran without error; findings are a bonus.
    assert isinstance(finding_ids, list)


# ---------------------------------------------------------------------------
# ModuleSelector: tool modules not selected if tool absent
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tool_module_not_selected_for_resource_only_server(
    tmp_path: Path,
) -> None:
    """The resource-only STDIO server has no tools — tool modules must be skipped."""
    cmd = [sys.executable, str(SERVERS_DIR / "stdio_path_traversal.py")]
    transport = StdioTransport(cmd=cmd, timeout=10.0)
    context = TransportContext(session_id="test", target_cmd=" ".join(cmd))
    await transport.connect()
    try:
        client = ProtocolClient(transport=transport, context=context)
        await client.initialize()
        registry = await client.enumerate_capabilities()
    finally:
        await transport.close()

    module = parser.load(MODULES_DIR / "basic/tools/tool_path_traversal.yaml")
    selected, skipped = selector.select_with_report([module], registry)
    assert module not in selected
    assert any(m is module for m, _ in skipped)
