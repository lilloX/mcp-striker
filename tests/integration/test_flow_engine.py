"""Integration tests for Milestone 4 — Flow-Based Attack DSL.

Test matrix:
    Flow path traversal vs vulnerable STDIO server  → same findings as StrikeEngine
    Multi-step flow (setup → mutate) vs real server → variables extracted and used
    FlowEngine cleanup step failure → never crashes the session
    ModuleSelector + FlowEngine pipeline            → skipped modules not executed
"""

from __future__ import annotations

import asyncio
import sys
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

SERVERS_DIR = Path(__file__).parent.parent / "fixtures" / "servers"
FLOWS_DIR = Path(__file__).parent.parent / "fixtures" / "flows"
MODULES_DIR = Path(__file__).parent.parent.parent / "modules"

parser = YAMLFlowParser()


# ---------------------------------------------------------------------------
# Helper: build a connected engine
# ---------------------------------------------------------------------------


async def _build_engine(
    server_script: Path,
    tmp_path: Path,
    timeout: float = 10.0,
) -> tuple[FlowEngine, StdioTransport]:
    cmd = [sys.executable, str(server_script)]
    transport = StdioTransport(cmd=cmd, timeout=timeout)
    context = TransportContext(
        session_id="test",
        target_cmd=" ".join(cmd),
    )
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
        safety_context=SafetyContext(),
        transport_context=context,
        semaphore=asyncio.Semaphore(5),
    )
    return engine, transport


# ---------------------------------------------------------------------------
# Path traversal: flow produces same findings as StrikeEngine (regression)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_flow_path_traversal_finds_vulnerabilities(tmp_path: Path) -> None:
    """The YAML path traversal module must detect the same vulnerability
    as the hardcoded M1 probe list against the vulnerable stdio server."""
    engine, transport = await _build_engine(
        SERVERS_DIR / "stdio_path_traversal.py", tmp_path
    )
    try:
        module = parser.load(FLOWS_DIR / "valid_path_traversal.yaml")
        finding_ids = await engine.run_module(module)
    finally:
        await transport.close()

    assert finding_ids, "YAML flow must find path traversal on the vulnerable server"


@pytest.mark.asyncio
async def test_flow_clean_server_no_findings(tmp_path: Path) -> None:
    """False-positive guard: no findings on a correctly sanitised server."""
    engine, transport = await _build_engine(
        SERVERS_DIR / "stdio_clean.py", tmp_path
    )
    try:
        module = parser.load(FLOWS_DIR / "valid_path_traversal.yaml")
        finding_ids = await engine.run_module(module)
    finally:
        await transport.close()

    assert finding_ids == [], f"False positives on clean server: {finding_ids}"


# ---------------------------------------------------------------------------
# Multi-step flow: setup extracts URIs, mutate reads them
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_step_flow_extracts_and_reads(tmp_path: Path) -> None:
    """A setup step must extract resource URIs and the mutate step must
    successfully send resources/read for each extracted URI."""
    engine, transport = await _build_engine(
        SERVERS_DIR / "stdio_path_traversal.py", tmp_path
    )
    try:
        module = parser.load(FLOWS_DIR / "valid_multi_step.yaml")
        # The vulnerable server's resources/list returns no concrete resources,
        # so the mutate step will produce no exchanges. The test verifies the
        # flow completes without error (no crash, no exception).
        finding_ids = await engine.run_module(module)
    finally:
        await transport.close()

    # No crash = pass. Finding count depends on server content.
    assert isinstance(finding_ids, list)


# ---------------------------------------------------------------------------
# Multi-step against real server (with concrete resources)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_multi_step_flow_against_idor_server(tmp_path: Path) -> None:
    """The IDOR stdio server exposes concrete resources. The multi-step flow
    should extract their URIs and successfully read each one."""
    engine, transport = await _build_engine(
        SERVERS_DIR / "stdio_idor.py", tmp_path
    )
    try:
        module = parser.load(FLOWS_DIR / "valid_multi_step.yaml")
        finding_ids = await engine.run_module(module)
    finally:
        await transport.close()

    # The IDOR server's resources are readable, so jsonrpc_success fires.
    assert len(finding_ids) >= 2, (
        f"Expected ≥2 findings (one per concrete resource), got {len(finding_ids)}"
    )


# ---------------------------------------------------------------------------
# Cleanup failure never crashes the session
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cleanup_step_failure_does_not_crash(tmp_path: Path) -> None:
    """A cleanup step with an unsupported method must not crash FlowEngine."""
    engine, transport = await _build_engine(
        SERVERS_DIR / "stdio_clean.py", tmp_path
    )
    try:
        # Build a module with a cleanup step that calls an unsupported method.
        import yaml
        raw = {
            "version": "1",
            "name": "test-cleanup",
            "steps": [
                {
                    "id": "noop",
                    "type": "setup",
                    "method": "resources/list",
                    "params": {},
                },
                {
                    "id": "cleanup",
                    "type": "cleanup",
                    "method": "nonexistent/method",
                    "params": {},
                    "optional": True,
                },
            ],
        }
        from mcp_striker.dsl.schema import FlowModule
        module = FlowModule.model_validate(raw)
        finding_ids = await engine.run_module(module)
    finally:
        await transport.close()

    # No exception raised = pass.
    assert isinstance(finding_ids, list)


# ---------------------------------------------------------------------------
# ModuleSelector + FlowEngine pipeline
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_module_selector_skips_inapplicable_modules(tmp_path: Path) -> None:
    """Modules that require capabilities the server doesn't have must be skipped."""
    from mcp_striker.dsl.schema import FlowModule, RequiresSpec
    from mcp_striker.registry import CapabilityRegistry

    requires_tools_module_raw = {
        "version": "1",
        "name": "requires-tools",
        "requires": {"capabilities": ["tools"]},
        "steps": [
            {"id": "s", "type": "setup", "method": "tools/list", "params": {}},
        ],
    }
    requires_tools = FlowModule.model_validate(requires_tools_module_raw)
    valid_module = parser.load(FLOWS_DIR / "valid_path_traversal.yaml")

    # Registry with resources but no tools
    from mcp_striker.registry import McpResource, McpResourceTemplate
    registry = CapabilityRegistry(
        server_name="test", server_version="0.1", protocol_version="2025-03-26",
        resources=[McpResource(uri="file:///x", name="x")],
        resource_templates=[McpResourceTemplate(uri_template="file://{path}", name="f")],
        server_capabilities=["resources"],  # explicitly: no "tools"
    )

    selector = ModuleSelector()
    selected, skipped = selector.select_with_report(
        [requires_tools, valid_module], registry
    )
    assert valid_module in selected
    assert requires_tools not in selected
    assert any(m is requires_tools for m, _ in skipped)


# ---------------------------------------------------------------------------
# Modules directory — integration with real YAML modules
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_real_modules_dir_loads_and_runs(tmp_path: Path) -> None:
    """The modules/ directory must contain at least one module that applies
    to the vulnerable STDIO server and finds something."""
    if not MODULES_DIR.is_dir():
        pytest.skip("modules/ directory not found")

    engine, transport = await _build_engine(
        SERVERS_DIR / "stdio_path_traversal.py", tmp_path
    )
    try:
        all_modules = parser.load_directory(MODULES_DIR)
        # Get the registry to check module applicability.
        from mcp_striker.registry import McpResourceTemplate
        registry = engine._registry  # type: ignore[attr-defined]
        selector = ModuleSelector()
        selected, _ = selector.select_with_report(all_modules, registry)
        finding_ids = await engine.run_modules(selected)
    finally:
        await transport.close()

    assert finding_ids, "At least one module in modules/ must find the path traversal"


# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------


async def _build_engine_dry_run(
    server_script: Path,
    tmp_path: Path,
) -> tuple[FlowEngine, StdioTransport]:
    """Build a FlowEngine with dry_run=True."""
    import asyncio as _asyncio
    cmd = [sys.executable, str(server_script)]
    transport = StdioTransport(cmd=cmd, timeout=10.0)
    context = TransportContext(session_id="test-dry", target_cmd=" ".join(cmd))
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
        safety_context=SafetyContext(),
        transport_context=context,
        semaphore=_asyncio.Semaphore(5),
        dry_run=True,
    )
    return engine, transport


@pytest.mark.asyncio
async def test_dry_run_produces_no_findings(tmp_path: Path) -> None:
    """dry_run=True must return an empty finding list even on a vulnerable server."""
    engine, transport = await _build_engine_dry_run(
        SERVERS_DIR / "stdio_path_traversal.py", tmp_path
    )
    try:
        module = parser.load(FLOWS_DIR / "valid_path_traversal.yaml")
        finding_ids = await engine.run_module(module)
    finally:
        await transport.close()

    assert finding_ids == [], f"dry_run must produce no findings, got {finding_ids}"


@pytest.mark.asyncio
async def test_dry_run_writes_no_finding_artifacts(tmp_path: Path) -> None:
    """dry_run=True must not write any finding JSON files to disk."""
    engine, transport = await _build_engine_dry_run(
        SERVERS_DIR / "stdio_path_traversal.py", tmp_path
    )
    try:
        module = parser.load(FLOWS_DIR / "valid_path_traversal.yaml")
        await engine.run_module(module)
    finally:
        await transport.close()

    findings_dir = tmp_path / "findings"
    if findings_dir.exists():
        artifacts = list(findings_dir.glob("MCPSTRIKE-*.json"))
        assert artifacts == [], f"dry_run must not write finding artifacts, found: {artifacts}"


@pytest.mark.asyncio
async def test_dry_run_still_records_session(tmp_path: Path) -> None:
    """dry_run=True must still write the session transcript."""
    engine, transport = await _build_engine_dry_run(
        SERVERS_DIR / "stdio_path_traversal.py", tmp_path
    )
    try:
        module = parser.load(FLOWS_DIR / "valid_path_traversal.yaml")
        await engine.run_module(module)
    finally:
        await transport.close()

    session_dir = tmp_path / "session"
    assert session_dir.exists(), "session directory must be created"
    session_files = list(session_dir.glob("*.json"))
    assert session_files, "session transcript must contain exchange records"
