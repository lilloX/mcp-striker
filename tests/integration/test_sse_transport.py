"""Integration tests for the legacy HTTP+SSE transport (protocol 2024-11-05)."""

from __future__ import annotations

import asyncio
import json
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
from mcp_striker.transport.sse import SseTransport

SERVERS_DIR = Path(__file__).parent.parent / "fixtures" / "servers"
MODULES_DIR = Path(__file__).parent.parent.parent / "modules"
parser = YAMLFlowParser()
selector = ModuleSelector()


@pytest.fixture()
def sse_server():
    proc = subprocess.Popen(
        [sys.executable, str(SERVERS_DIR / "sse_vulnerable.py")],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    for _ in range(50):
        line = proc.stdout.readline().strip()
        if line.isdigit():
            yield f"http://127.0.0.1:{line}"
            proc.kill()
            proc.wait()
            return
        time.sleep(0.1)
    proc.kill()
    pytest.fail("SSE server did not print port in time")


@pytest.mark.asyncio
async def test_sse_transport_initialize(sse_server: str) -> None:
    transport = SseTransport(base_url=sse_server, timeout=10.0)
    context = TransportContext(session_id="test", target_url=sse_server, transport_type="sse")
    await transport.connect()
    try:
        client = ProtocolClient(transport=transport, context=context)
        await client.initialize()
        assert client._protocol_version == "2024-11-05"
        assert client._server_name == "sse-vulnerable-server"
    finally:
        await transport.close()


@pytest.mark.asyncio
async def test_sse_transport_enum(sse_server: str) -> None:
    transport = SseTransport(base_url=sse_server, timeout=10.0)
    context = TransportContext(session_id="test", target_url=sse_server, transport_type="sse")
    await transport.connect()
    try:
        client = ProtocolClient(transport=transport, context=context)
        await client.initialize()
        registry = await client.enumerate_capabilities()
        assert registry.target_transport == "sse"
        assert len(registry.tools) >= 1
        assert "read_file" in [t.name for t in registry.tools]
    finally:
        await transport.close()


@pytest.mark.asyncio
async def test_sse_tool_path_traversal(sse_server: str, tmp_path: Path) -> None:
    transport = SseTransport(base_url=sse_server, timeout=10.0)
    context = TransportContext(session_id="test", target_url=sse_server, transport_type="sse")
    await transport.connect()
    try:
        client = ProtocolClient(transport=transport, context=context)
        await client.initialize()
        registry = await client.enumerate_capabilities()

        findings_dir = tmp_path / "findings"
        engine = FlowEngine(
            transport=transport,
            registry=registry,
            recorder=SessionRecorder(session_dir=tmp_path / "session"),
            evidence_generator=EvidenceGenerator(findings_dir=findings_dir),
            safety_engine=SafetyPolicyEngine(),
            safety_context=SafetyContext(allow_mutating=False),
            transport_context=context,
            semaphore=asyncio.Semaphore(3),
        )
        module = parser.load(MODULES_DIR / "basic" / "tools" / "tool_path_traversal.yaml")
        selected = selector.select([module], registry)
        assert selected
        finding_ids = await engine.run_module(module)
    finally:
        await transport.close()

    assert finding_ids, "Expected path traversal findings via SSE transport"
    finding = json.loads((findings_dir / f"{finding_ids[0]}.json").read_text())
    assert finding["transport"] == "sse"


@pytest.mark.asyncio
async def test_sse_registry_saves_target_transport(sse_server: str, tmp_path: Path) -> None:
    transport = SseTransport(base_url=sse_server, timeout=10.0)
    context = TransportContext(session_id="test", target_url=sse_server, transport_type="sse")
    await transport.connect()
    try:
        client = ProtocolClient(transport=transport, context=context)
        await client.initialize()
        registry = await client.enumerate_capabilities()
    finally:
        await transport.close()

    assert registry.target_transport == "sse"
    snap = tmp_path / "snap.json"
    registry.save(snap)
    from mcp_striker.registry import CapabilityRegistry
    loaded = CapabilityRegistry.load(snap)
    assert loaded.target_transport == "sse"
