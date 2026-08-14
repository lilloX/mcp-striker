"""Unit tests for Milestone 3 — Auth-Differential Engine."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from mcp_striker.engine.auth_diff import DiffMatcher
from mcp_striker.evidence import EvidenceGenerator, _redact
from mcp_striker.identity import IdentityManager, IdentityManagerError
from mcp_striker.models import (
    DiffResult,
    DiffVerdict,
    JsonRpcError,
    JsonRpcRequest,
    JsonRpcResponse,
    TransportExchange,
)
from mcp_striker.ownership import OwnershipRegistry, OwnershipError

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
IDENTITIES_YAML = FIXTURES_DIR / "identities" / "two_tenants.yaml"
OWNERSHIP_YAML = FIXTURES_DIR / "ownership" / "tenant_resources.yaml"


# ---------------------------------------------------------------------------
# IdentityManager
# ---------------------------------------------------------------------------


def test_identity_manager_loads_yaml() -> None:
    mgr = IdentityManager()
    mgr.load(IDENTITIES_YAML)
    assert "alice" in mgr.all_names()
    assert "bob" in mgr.all_names()


def test_identity_manager_get_alice() -> None:
    mgr = IdentityManager()
    mgr.load(IDENTITIES_YAML)
    alice = mgr.get("alice")
    assert alice.name == "alice"
    assert alice.auth.bearer == "alice-secret-token"


def test_identity_manager_get_unknown_raises() -> None:
    mgr = IdentityManager()
    mgr.load(IDENTITIES_YAML)
    with pytest.raises(IdentityManagerError, match="not found"):
        mgr.get("charlie")


def test_identity_manager_build_http_headers_bearer() -> None:
    mgr = IdentityManager()
    mgr.load(IDENTITIES_YAML)
    headers = mgr.build_http_headers(mgr.get("alice"))
    assert headers["Authorization"] == "Bearer alice-secret-token"


def test_identity_manager_build_env_vars() -> None:
    mgr = IdentityManager()
    mgr.load(IDENTITIES_YAML)
    env = mgr.build_env_vars(mgr.get("alice"))
    assert env["MCP_AUTH_TOKEN"] == "alice-secret-token"


def test_identity_manager_sensitive_keys() -> None:
    mgr = IdentityManager()
    mgr.load(IDENTITIES_YAML)
    keys = mgr.sensitive_keys()
    # Bearer → Authorization header
    assert "Authorization" in keys
    # Env key from YAML
    assert "MCP_AUTH_TOKEN" in keys


def test_identity_manager_missing_file_raises() -> None:
    mgr = IdentityManager()
    with pytest.raises(IdentityManagerError, match="not found"):
        mgr.load(Path("/nonexistent/identities.yaml"))


def test_identity_manager_invalid_yaml_raises(tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("{invalid: yaml: content: [")
    mgr = IdentityManager()
    with pytest.raises(IdentityManagerError):
        mgr.load(bad)


# ---------------------------------------------------------------------------
# OwnershipRegistry
# ---------------------------------------------------------------------------


def test_ownership_registry_loads_yaml() -> None:
    reg = OwnershipRegistry()
    reg.load(OWNERSHIP_YAML)
    assert len(reg.resources) == 2


def test_ownership_registry_all_pairs() -> None:
    reg = OwnershipRegistry()
    reg.load(OWNERSHIP_YAML)
    pairs = reg.all_pairs()
    # 2 resources × 1 denied identity each = 2 pairs
    assert len(pairs) == 2
    uris = {r.uri for r, _, _ in pairs}
    assert "resource://tenant-a/secret.txt" in uris
    owners = {owner for _, owner, _ in pairs}
    assert owners == {"alice"}
    attackers = {attacker for _, _, attacker in pairs}
    assert attackers == {"bob"}


def test_ownership_registry_missing_file_raises() -> None:
    reg = OwnershipRegistry()
    with pytest.raises(OwnershipError, match="not found"):
        reg.load(Path("/nonexistent/ownership.yaml"))


# ---------------------------------------------------------------------------
# DiffMatcher
# ---------------------------------------------------------------------------


def _ok_exchange(content: str) -> TransportExchange:
    req = JsonRpcRequest(id=10, method="resources/read", params={"uri": "resource://x"})
    resp = JsonRpcResponse(
        jsonrpc="2.0", id=10,
        result={"contents": [{"uri": "resource://x", "text": content}]},
    )
    return TransportExchange(request=req, response=resp)


def _error_exchange(code: int = -32001, http_status: int = -1) -> TransportExchange:
    req = JsonRpcRequest(id=10, method="resources/read", params={"uri": "resource://x"})
    resp = JsonRpcResponse(
        jsonrpc="2.0", id=10,
        error=JsonRpcError(code=code, message="Access denied"),
    )
    return TransportExchange(request=req, response=resp, http_status=http_status)


def _failed_exchange() -> TransportExchange:
    req = JsonRpcRequest(id=10, method="resources/read", params={"uri": "resource://x"})
    return TransportExchange(request=req, probe_failed=True, failure_reason="error")


matcher = DiffMatcher()


def test_diff_matcher_idor_confirmed_same_content() -> None:
    owner = _ok_exchange("TOP SECRET DATA")
    attacker = _ok_exchange("TOP SECRET DATA")
    result = matcher.compare(owner, attacker, "resource://x", "alice", "bob")
    assert result.verdict == DiffVerdict.IDOR_CONFIRMED
    assert result.similarity_score >= 0.8


def test_diff_matcher_idor_confirmed_different_content() -> None:
    """IDOR is confirmed even if content differs — authorization boundary is broken."""
    owner = _ok_exchange("TOP SECRET DATA")
    attacker = _ok_exchange("something completely different")
    result = matcher.compare(owner, attacker, "resource://x", "alice", "bob")
    assert result.verdict == DiffVerdict.IDOR_CONFIRMED
    assert result.similarity_score < 0.8


def test_diff_matcher_correctly_denied_jsonrpc_error() -> None:
    owner = _ok_exchange("TOP SECRET DATA")
    attacker = _error_exchange(code=-32001)
    result = matcher.compare(owner, attacker, "resource://x", "alice", "bob")
    assert result.verdict == DiffVerdict.CORRECTLY_DENIED


def test_diff_matcher_correctly_denied_http_4xx() -> None:
    owner = _ok_exchange("TOP SECRET DATA")
    # HTTP 403 — server rejected at transport level.
    attacker = _failed_exchange()
    attacker_with_403 = attacker.model_copy(update={"http_status": 403})
    result = matcher.compare(owner, attacker_with_403, "resource://x", "alice", "bob")
    assert result.verdict == DiffVerdict.CORRECTLY_DENIED


def test_diff_matcher_inconclusive_when_owner_errors() -> None:
    owner = _error_exchange()
    attacker = _ok_exchange("some content")
    result = matcher.compare(owner, attacker, "resource://x", "alice", "bob")
    assert result.verdict == DiffVerdict.INCONCLUSIVE


def test_diff_matcher_inconclusive_when_owner_fails() -> None:
    owner = _failed_exchange()
    attacker = _ok_exchange("some content")
    result = matcher.compare(owner, attacker, "resource://x", "alice", "bob")
    assert result.verdict == DiffVerdict.INCONCLUSIVE


def test_inconclusive_pair_counts_as_failure() -> None:
    """An INCONCLUSIVE pair (owner baseline failed) increments the engine failure
    counter, so an auth-diff run that established no baseline is not clean (#2)."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    from mcp_striker.engine.auth_diff import AuthDiffEngine

    engine = AuthDiffEngine(
        identity_manager=MagicMock(),
        ownership_registry=MagicMock(),
        recorder=MagicMock(record_diff=AsyncMock()),
        evidence_generator=MagicMock(),
        session_id="t",
    )
    # Owner baseline fails → compare() yields INCONCLUSIVE.
    engine._send_as = AsyncMock(return_value=_failed_exchange())  # type: ignore[method-assign]

    resource = MagicMock(uri="resource://x")
    result = asyncio.run(engine._run_pair(resource, "alice", "bob"))

    assert result is None
    assert engine.failures == 1


# ---------------------------------------------------------------------------
# Evidence — dynamic redaction with extra_sensitive_keys
# ---------------------------------------------------------------------------


def test_redact_extra_key_by_name() -> None:
    """Custom header names from identity YAML must be redacted."""
    data: dict = {"MCP_AUTH_TOKEN": "super-secret", "method": "resources/read"}
    result = _redact(data, extra_keys=frozenset({"MCP_AUTH_TOKEN"}))
    assert isinstance(result, dict)
    assert result["MCP_AUTH_TOKEN"] == "[REDACTED]"
    assert result["method"] == "resources/read"


def test_redact_extra_key_not_leaked_in_diff_finding(tmp_path: Path) -> None:
    """promote_diff must redact identity credentials from BOTH exchanges."""
    from mcp_striker.models import DiffResult, DiffVerdict

    owner = _ok_exchange("TOP SECRET DATA")
    # Simulate the owner exchange having a custom auth header in the request.
    owner_req = JsonRpcRequest(
        id=10, method="resources/read",
        params={"uri": "resource://x", "MCP_AUTH_TOKEN": "alice-secret-token"},
    )
    owner = owner.model_copy(update={"request": owner_req})

    attacker = _ok_exchange("TOP SECRET DATA")

    diff = DiffResult(
        verdict=DiffVerdict.IDOR_CONFIRMED,
        resource_uri="resource://x",
        owner_name="alice",
        attacker_name="bob",
        owner_exchange=owner,
        attacker_exchange=attacker,
        similarity_score=1.0,
    )

    gen = EvidenceGenerator(findings_dir=tmp_path / "findings")

    import asyncio
    finding_id = asyncio.run(
        gen.promote_diff(
            diff_result=diff,
            extra_sensitive_keys=frozenset({"MCP_AUTH_TOKEN"}),
            transport="stdio",
            protocol_version="2025-03-26",
        )
    )

    artifact = json.loads((tmp_path / "findings" / f"{finding_id}.json").read_text())
    raw_owner_req = artifact["raw_owner_request"]
    # Token must be redacted in the artifact.
    assert raw_owner_req.get("params", {}).get("MCP_AUTH_TOKEN") == "[REDACTED]"


@pytest.mark.asyncio
async def test_promote_diff_idor_produces_correct_schema(tmp_path: Path) -> None:
    from mcp_striker.models import DiffResult, DiffVerdict

    diff = DiffResult(
        verdict=DiffVerdict.IDOR_CONFIRMED,
        resource_uri="resource://tenant-a/secret.txt",
        owner_name="alice",
        attacker_name="bob",
        owner_exchange=_ok_exchange("TOP SECRET DATA"),
        attacker_exchange=_ok_exchange("TOP SECRET DATA"),
        similarity_score=1.0,
    )
    gen = EvidenceGenerator(findings_dir=tmp_path / "findings")
    finding_id = await gen.promote_diff(
        diff_result=diff,
        extra_sensitive_keys=frozenset(),
        transport="stdio",
        protocol_version="2025-03-26",
    )
    artifact = json.loads((tmp_path / "findings" / f"{finding_id}.json").read_text())
    assert artifact["schema_version"] == "mcp-striker.finding/v1"
    assert artifact["type"] == "auth_differential"
    assert artifact["verdict"] == "idor_confirmed"
    assert artifact["data_leaked"] is True


@pytest.mark.asyncio
async def test_promote_diff_data_leaked_flag_false_when_low_similarity(tmp_path: Path) -> None:
    """data_leaked must be False when similarity < 0.8 even if verdict is IDOR."""
    from mcp_striker.models import DiffResult, DiffVerdict

    diff = DiffResult(
        verdict=DiffVerdict.IDOR_CONFIRMED,
        resource_uri="resource://x",
        owner_name="alice",
        attacker_name="bob",
        owner_exchange=_ok_exchange("Alice TOP SECRET"),
        attacker_exchange=_ok_exchange("completely different content xyz"),
        similarity_score=0.1,
    )
    gen = EvidenceGenerator(findings_dir=tmp_path / "findings")
    finding_id = await gen.promote_diff(
        diff_result=diff,
        extra_sensitive_keys=frozenset(),
        transport="stdio",
        protocol_version="2025-03-26",
    )
    artifact = json.loads((tmp_path / "findings" / f"{finding_id}.json").read_text())
    assert artifact["verdict"] == "idor_confirmed"
    assert artifact["data_leaked"] is False
