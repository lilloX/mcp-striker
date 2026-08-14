"""Unit tests for mcp_striker/evidence.py."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from mcp_striker.evidence import EvidenceGenerator, Finding, _redact
from mcp_striker.models import JsonRpcRequest, JsonRpcResponse, TransportExchange

# ---------------------------------------------------------------------------
# _redact
# ---------------------------------------------------------------------------


def test_redact_authorization_header() -> None:
    data = {"Authorization": "Bearer secret-token"}
    result = _redact(data)
    assert isinstance(result, dict)
    assert result["Authorization"] == "[REDACTED]"


def test_redact_token_key() -> None:
    data = {"API_TOKEN": "abc123", "value": "keep-me"}
    result = _redact(data)
    assert isinstance(result, dict)
    assert result["API_TOKEN"] == "[REDACTED]"
    assert result["value"] == "keep-me"


def test_redact_secret_key() -> None:
    data = {"DB_SECRET": "p@ssw0rd"}
    result = _redact(data)
    assert isinstance(result, dict)
    assert result["DB_SECRET"] == "[REDACTED]"


def test_redact_cookie() -> None:
    data = {"cookie": "session=xyz"}
    result = _redact(data)
    assert isinstance(result, dict)
    assert result["cookie"] == "[REDACTED]"


def test_redact_nested() -> None:
    data = {"headers": {"Authorization": "Bearer x", "Content-Type": "application/json"}}
    result = _redact(data)
    assert isinstance(result, dict)
    headers = result["headers"]
    assert isinstance(headers, dict)
    assert headers["Authorization"] == "[REDACTED]"
    assert headers["Content-Type"] == "application/json"


def test_redact_safe_keys_untouched() -> None:
    data = {"method": "resources/read", "params": {"uri": "file:///etc/passwd"}}
    result = _redact(data)
    assert result == data


def test_redact_broadened_credential_keys() -> None:
    data = {
        "password": "p", "apiKey": "k", "X-API-Key": "h",
        "client_secret": "s", "access_key": "a", "private_key": "pk",
        "bearer": "b", "session_id": "sid",
        "username": "alice", "value": "keep",
    }
    result = _redact(data)
    assert isinstance(result, dict)
    for key in (
        "password", "apiKey", "X-API-Key", "client_secret",
        "access_key", "private_key", "bearer", "session_id",
    ):
        assert result[key] == "[REDACTED]", key
    assert result["username"] == "alice"
    assert result["value"] == "keep"


# ---------------------------------------------------------------------------
# EvidenceGenerator
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_findings(tmp_path: Path) -> Path:
    return tmp_path / "findings"


def _make_exchange(payload: str, content: str) -> TransportExchange:
    request = JsonRpcRequest(
        id=1,
        method="resources/read",
        params={"uri": payload},
    )
    response = JsonRpcResponse(
        jsonrpc="2.0",
        id=1,
        result={"contents": [{"uri": payload, "text": content}]},
    )
    return TransportExchange(request=request, response=response)


@pytest.mark.asyncio
async def test_promote_creates_finding_file(tmp_findings: Path) -> None:
    gen = EvidenceGenerator(findings_dir=tmp_findings)
    exchange = _make_exchange("/etc/passwd", "root:x:0:0:root:/root:/bin/bash")

    finding_id = await gen.promote(
        exchange=exchange,
        matchers_hit=["jsonrpc_success", "regex:root:x:0:0"],
        module="resource-path-traversal",
        transport="stdio",
        protocol_version="2025-03-26",
    )

    assert finding_id == "MCPSTRIKE-001"
    artifact = tmp_findings / "MCPSTRIKE-001.json"
    assert artifact.exists()

    data = json.loads(artifact.read_text())
    assert data["schema_version"] == "mcp-striker.finding/v1"
    assert data["finding_id"] == "MCPSTRIKE-001"
    assert "jsonrpc_success" in data["matchers_hit"]


@pytest.mark.asyncio
async def test_promote_increments_id(tmp_findings: Path) -> None:
    gen = EvidenceGenerator(findings_dir=tmp_findings)
    exchange = _make_exchange("/etc/passwd", "root:x:0:0")

    id1 = await gen.promote(
        exchange=exchange,
        matchers_hit=["jsonrpc_success"],
        module="resource-path-traversal",
        transport="stdio",
        protocol_version="2025-03-26",
    )
    id2 = await gen.promote(
        exchange=exchange,
        matchers_hit=["jsonrpc_success"],
        module="resource-path-traversal",
        transport="stdio",
        protocol_version="2025-03-26",
    )

    assert id1 == "MCPSTRIKE-001"
    assert id2 == "MCPSTRIKE-002"


@pytest.mark.asyncio
async def test_redaction_applied_to_artifact(tmp_findings: Path) -> None:
    request = JsonRpcRequest(
        id=1,
        method="resources/read",
        params={"uri": "file:///etc/passwd", "Authorization": "Bearer secret"},
    )
    response = JsonRpcResponse(
        jsonrpc="2.0",
        id=1,
        result={"contents": [{"uri": "file:///etc/passwd", "text": "root:x:0:0"}]},
    )
    exchange = TransportExchange(request=request, response=response)

    gen = EvidenceGenerator(findings_dir=tmp_findings)
    finding_id = await gen.promote(
        exchange=exchange,
        matchers_hit=["jsonrpc_success"],
        module="resource-path-traversal",
        transport="stdio",
        protocol_version="2025-03-26",
    )

    data = json.loads((tmp_findings / f"{finding_id}.json").read_text())
    raw_request = data["raw_request"]
    assert raw_request.get("params", {}).get("Authorization") == "[REDACTED]"


# ---------------------------------------------------------------------------
# Artifact permissions (R#14) and race-safe IDs (R#15)
# ---------------------------------------------------------------------------


def _dummy_finding(finding_id: str) -> Finding:
    return Finding(
        finding_id=finding_id,
        module="m",
        transport="stdio",
        protocol_version="2025-03-26",
        method="tools/call",
        payload="p",
        matchers_hit=[],
        raw_request={},
    )


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions only")
def test_findings_dir_and_file_are_owner_only(tmp_path: Path) -> None:
    import stat

    findings_dir = tmp_path / "findings"
    gen = EvidenceGenerator(findings_dir=findings_dir)
    finding_id = gen._write_artifact(_dummy_finding)

    assert stat.S_IMODE(findings_dir.stat().st_mode) == 0o700
    file_path = findings_dir / f"{finding_id}.json"
    assert stat.S_IMODE(file_path.stat().st_mode) == 0o600


def test_write_artifact_does_not_overwrite_existing_id(tmp_path: Path) -> None:
    """O_EXCL: a colliding id (another process) is skipped, not overwritten."""
    findings_dir = tmp_path / "findings"
    gen = EvidenceGenerator(findings_dir=findings_dir)
    # Counter is 0 at init; pre-create the file the next id would use.
    findings_dir.mkdir(parents=True, exist_ok=True)
    (findings_dir / "MCPSTRIKE-001.json").write_text('{"pre": "existing"}')

    finding_id = gen._write_artifact(_dummy_finding)
    assert finding_id == "MCPSTRIKE-002"
    # The pre-existing file was not clobbered.
    existing = json.loads((findings_dir / "MCPSTRIKE-001.json").read_text())
    assert existing == {"pre": "existing"}
