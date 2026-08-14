"""Integration tests — full end-to-end flows against fixture servers.

Each test uses a real subprocess and a real ``StdioTransport``.

Test matrix (as per ENGINEERING_GUIDELINES.md):
    stdio_path_traversal.py → must produce ≥1 finding
    stdio_malformed.py      → must not crash; must produce 0 findings
    stdio_clean.py          → must produce 0 findings (false-positive guard)
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from mcp_striker.engine.strike import StrikeEngine
from mcp_striker.evidence import EvidenceGenerator
from mcp_striker.models import SafetyContext, TransportContext
from mcp_striker.protocol.client import ProtocolClient
from mcp_striker.recorder import SessionRecorder
from mcp_striker.registry import CapabilityRegistry
from mcp_striker.safety import SafetyPolicyEngine
from mcp_striker.transport.stdio import StdioTransport

SERVERS_DIR = Path(__file__).parent.parent / "fixtures" / "servers"

# Short timeout to keep the malformed-server test fast.
_SHORT_TIMEOUT = 2.0


async def _run_full_flow(
    server_script: Path,
    tmp_path: Path,
    timeout: float = 10.0,
) -> tuple[CapabilityRegistry, list[str]]:
    """Run enum + strike against *server_script* and return (registry, finding_ids)."""
    cmd = [sys.executable, str(server_script)]
    transport = StdioTransport(cmd=cmd, timeout=timeout)
    context = TransportContext(session_id="test-session", target_cmd=" ".join(cmd))

    await transport.connect()
    try:
        client = ProtocolClient(transport=transport, context=context)
        await client.initialize()
        registry = await client.enumerate_capabilities()

        recorder = SessionRecorder(session_dir=tmp_path / "session")
        evidence_gen = EvidenceGenerator(findings_dir=tmp_path / "findings")
        safety_engine = SafetyPolicyEngine()
        safety_context = SafetyContext(allow_mutating=False)

        engine = StrikeEngine(
            transport=transport,
            registry=registry,
            recorder=recorder,
            evidence_generator=evidence_gen,
            safety_engine=safety_engine,
            safety_context=safety_context,
            transport_context=context,
            concurrency=3,
        )
        finding_ids = await engine.run()
    finally:
        await transport.close()

    return registry, finding_ids


# ---------------------------------------------------------------------------
# Vulnerable server
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_vulnerable_server_produces_findings(tmp_path: Path) -> None:
    """The path-traversal fixture must trigger at least one confirmed finding."""
    registry, finding_ids = await _run_full_flow(
        SERVERS_DIR / "stdio_path_traversal.py",
        tmp_path,
    )

    assert registry.server_name == "vulnerable-fs-server"
    assert len(registry.resource_templates) == 1
    assert finding_ids, "Expected at least one finding against the vulnerable server"

    # Verify the artifact is valid JSON with the expected schema.
    artifact = tmp_path / "findings" / f"{finding_ids[0]}.json"
    assert artifact.exists()
    import json
    data = json.loads(artifact.read_text())
    assert data["schema_version"] == "mcp-striker.finding/v1"
    assert data["module"] == "resource-path-traversal"
    assert data["transport"] == "stdio"


# ---------------------------------------------------------------------------
# Malformed server
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_malformed_server_does_not_crash(tmp_path: Path) -> None:
    """The engine must survive a server that returns broken JSON for every probe."""
    registry, finding_ids = await _run_full_flow(
        SERVERS_DIR / "stdio_malformed.py",
        tmp_path,
        timeout=_SHORT_TIMEOUT,
    )

    assert registry.server_name == "malformed-server"
    # Malformed responses must not be mistakenly promoted to findings.
    assert finding_ids == [], f"Unexpected findings: {finding_ids}"


# ---------------------------------------------------------------------------
# Clean server
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_clean_server_produces_no_findings(tmp_path: Path) -> None:
    """A correctly sanitised server must produce zero findings (no false positives)."""
    registry, finding_ids = await _run_full_flow(
        SERVERS_DIR / "stdio_clean.py",
        tmp_path,
    )

    assert registry.server_name == "clean-server"
    assert finding_ids == [], (
        f"False positive(s) detected against clean server: {finding_ids}"
    )
