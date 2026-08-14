"""Integration tests for Milestone 3 — Auth-Differential Engine.

Test matrix:
    STDIO IDOR server   → AuthDiffEngine detects IDOR (2 resources = 2 findings)
    HTTP IDOR server    → AuthDiffEngine detects IDOR (2 resources = 2 findings)
    Clean STDIO server  → AuthDiffEngine produces zero findings (false-positive guard)
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

import pytest

from mcp_striker.engine.auth_diff import AuthDiffEngine
from mcp_striker.evidence import EvidenceGenerator
from mcp_striker.identity import IdentityManager
from mcp_striker.models import DiffVerdict
from mcp_striker.ownership import OwnershipRegistry
from mcp_striker.recorder import SessionRecorder

SERVERS_DIR = Path(__file__).parent.parent / "fixtures" / "servers"
IDENTITIES_YAML = Path(__file__).parent.parent / "fixtures" / "identities" / "two_tenants.yaml"
OWNERSHIP_YAML = Path(__file__).parent.parent / "fixtures" / "ownership" / "tenant_resources.yaml"


# ---------------------------------------------------------------------------
# HTTP server fixture helper
# ---------------------------------------------------------------------------


def _start_http_server(script: Path) -> tuple[subprocess.Popen[str], str]:
    proc = subprocess.Popen(
        [sys.executable, str(script)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    for _ in range(50):
        line = proc.stdout.readline().strip()  # type: ignore[union-attr]
        if line.isdigit():
            return proc, f"http://127.0.0.1:{line}"
        time.sleep(0.1)
    proc.kill()
    raise RuntimeError(f"Server {script} did not print port within 5s")


@pytest.fixture()
def http_idor_server():
    proc, url = _start_http_server(SERVERS_DIR / "http_idor.py")
    yield url
    proc.kill()
    proc.wait()


# ---------------------------------------------------------------------------
# Engine builder helper
# ---------------------------------------------------------------------------


def _build_engine(
    tmp_path: Path,
    transport_type: str,
    base_url: str = "",
    target_cmd: str = "",
) -> AuthDiffEngine:
    identity_manager = IdentityManager()
    identity_manager.load(IDENTITIES_YAML)

    ownership_registry = OwnershipRegistry()
    ownership_registry.load(OWNERSHIP_YAML)

    return AuthDiffEngine(
        identity_manager=identity_manager,
        ownership_registry=ownership_registry,
        recorder=SessionRecorder(session_dir=tmp_path / "session"),
        evidence_generator=EvidenceGenerator(findings_dir=tmp_path / "findings"),
        session_id="test",
        base_url=base_url,
        target_cmd=target_cmd,
        transport_type=transport_type,
        timeout=10.0,
        concurrency=2,
    )


# ---------------------------------------------------------------------------
# STDIO IDOR server
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stdio_idor_detected(tmp_path: Path) -> None:
    """AuthDiffEngine must find IDOR on both resources via STDIO."""
    cmd = f"{sys.executable} {SERVERS_DIR / 'stdio_idor.py'}"
    engine = _build_engine(tmp_path, transport_type="stdio", target_cmd=cmd)
    finding_ids = await engine.run()
    assert len(finding_ids) == 2, (
        f"Expected 2 IDOR findings (one per resource), got {len(finding_ids)}"
    )


@pytest.mark.asyncio
async def test_stdio_idor_findings_have_correct_schema(tmp_path: Path) -> None:
    import json
    cmd = f"{sys.executable} {SERVERS_DIR / 'stdio_idor.py'}"
    engine = _build_engine(tmp_path, transport_type="stdio", target_cmd=cmd)
    finding_ids = await engine.run()

    for fid in finding_ids:
        artifact = json.loads(
            (tmp_path / "findings" / f"{fid}.json").read_text()
        )
        assert artifact["schema_version"] == "mcp-striker.finding/v1"
        assert artifact["type"] == "auth_differential"
        assert artifact["verdict"] == "idor_confirmed"
        # Credentials must never appear in the artifact.
        assert "alice-secret-token" not in json.dumps(artifact)
        assert "bob-secret-token" not in json.dumps(artifact)


# ---------------------------------------------------------------------------
# HTTP IDOR server
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_http_idor_detected(http_idor_server: str, tmp_path: Path) -> None:
    """AuthDiffEngine must find IDOR on both resources via HTTP."""
    engine = _build_engine(tmp_path, transport_type="http", base_url=http_idor_server)
    finding_ids = await engine.run()
    assert len(finding_ids) == 2, (
        f"Expected 2 IDOR findings via HTTP, got {len(finding_ids)}"
    )


@pytest.mark.asyncio
async def test_http_idor_tokens_redacted_in_artifacts(
    http_idor_server: str, tmp_path: Path
) -> None:
    import json
    engine = _build_engine(tmp_path, transport_type="http", base_url=http_idor_server)
    finding_ids = await engine.run()
    for fid in finding_ids:
        raw = (tmp_path / "findings" / f"{fid}.json").read_text()
        assert "alice-secret-token" not in raw
        assert "bob-secret-token" not in raw


# ---------------------------------------------------------------------------
# False-positive guard: clean STDIO server
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_clean_stdio_server_no_idor_findings(tmp_path: Path) -> None:
    """A server that correctly enforces access control must produce zero findings.

    We use a custom ownership fixture pointing at URIs the clean server knows
    and that it correctly gates behind identity checks.
    """
    import tempfile, yaml as _yaml  # type: ignore[import]

    # The clean STDIO server (stdio_clean.py) has no multi-tenant resources
    # at all — any resources/read will fail for both identities, producing
    # INCONCLUSIVE verdicts (not IDOR_CONFIRMED).
    custom_ownership = tmp_path / "ownership_clean.yaml"
    custom_ownership.write_text(
        _yaml.dump({
            "version": "1",
            "resources": [
                {
                    "uri": "file://nonexistent-resource-xyz",
                    "owner": "alice",
                    "denied": ["bob"],
                }
            ],
        })
    )

    identity_manager = IdentityManager()
    identity_manager.load(IDENTITIES_YAML)

    ownership_registry = OwnershipRegistry()
    ownership_registry.load(custom_ownership)

    cmd = f"{sys.executable} {SERVERS_DIR / 'stdio_clean.py'}"
    engine = AuthDiffEngine(
        identity_manager=identity_manager,
        ownership_registry=ownership_registry,
        recorder=SessionRecorder(session_dir=tmp_path / "session"),
        evidence_generator=EvidenceGenerator(findings_dir=tmp_path / "findings"),
        session_id="test",
        target_cmd=cmd,
        transport_type="stdio",
        timeout=10.0,
    )
    finding_ids = await engine.run()
    assert finding_ids == [], f"False positive(s) on clean server: {finding_ids}"
