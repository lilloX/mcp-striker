"""Unit tests for Milestone 6 — Report Engine."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_striker.report import FindingRecord, ProbeMetrics, ReportData, ReportGenerator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_finding(findings_dir: Path, finding_id: str, severity: str = "high", module: str = "tool-path-traversal") -> None:
    findings_dir.mkdir(parents=True, exist_ok=True)
    artifact = {
        "schema_version": "mcp-striker.finding/v1",
        "finding_id": finding_id,
        "severity": severity,
        "session_id": "abc123",
        "type": "server_vulnerability",
        "module": module,
        "transport": "stdio",
        "protocol_version": "2025-03-26",
        "method": "tools/call",
        "payload": "/etc/passwd",
        "matchers_hit": ["jsonrpc_success", "regex:root:x:0:0"],
        "raw_request": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                        "params": {"name": "read_file", "arguments": {"path": "/etc/passwd"}}},
        "raw_response": {"jsonrpc": "2.0", "id": 1,
                         "result": {"content": [{"type": "text", "text": "root:x:0:0:root:/root:/bin/bash"}]}},
    }
    (findings_dir / f"{finding_id}.json").write_text(json.dumps(artifact))


def _write_exchange(session_dir: Path, exchange_id: str, blocked: bool = False, failed: bool = False) -> None:
    session_dir.mkdir(parents=True, exist_ok=True)
    exchange = {
        "request": {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {}},
        "response": None if failed else {"jsonrpc": "2.0", "id": 1, "result": {}},
        "safety_decision": {"verdict": "blocked", "reason": "blocked"} if blocked
                           else {"verdict": "allowed", "reason": "ok"},
        "probe_failed": failed,
        "failure_reason": "timeout" if failed else "",
        "stderr_transcript": "",
        "http_status": -1,
        "http_response_headers": {},
    }
    (session_dir / f"{exchange_id}.json").write_text(json.dumps(exchange))


def _write_registry(sessions_dir: Path, server_name: str = "test-server") -> None:
    sessions_dir.mkdir(parents=True, exist_ok=True)
    registry = {
        "server_name": server_name,
        "server_version": "1.0.0",
        "protocol_version": "2025-03-26",
        "target_cmd": "node server.js",
        "target_url": "",
        "server_capabilities": ["tools"],
        "tools": [
            {"name": "read_file", "description": "Read a file", "input_schema": {}},
            {"name": "list_dir", "description": "List directory", "input_schema": {}},
        ],
        "resources": [],
        "resource_templates": [],
    }
    (sessions_dir / f"{server_name}.json").write_text(json.dumps(registry))


gen = ReportGenerator()


# ---------------------------------------------------------------------------
# Severity field in FlowModule
# ---------------------------------------------------------------------------


def test_flow_module_severity_default() -> None:
    from mcp_striker.dsl.schema import FlowModule
    module = FlowModule.model_validate({
        "version": "1", "name": "test",
        "steps": [{"id": "s", "type": "setup", "method": "tools/list", "params": {}}],
    })
    assert module.severity == "medium"


def test_flow_module_severity_custom() -> None:
    from mcp_striker.dsl.schema import FlowModule
    module = FlowModule.model_validate({
        "version": "1", "name": "test", "severity": "critical",
        "steps": [{"id": "s", "type": "setup", "method": "tools/list", "params": {}}],
    })
    assert module.severity == "critical"


def test_flow_module_severity_invalid_raises() -> None:
    from mcp_striker.dsl.schema import FlowModule
    with pytest.raises(Exception):
        FlowModule.model_validate({
            "version": "1", "name": "test", "severity": "extreme",
            "steps": [{"id": "s", "type": "setup", "method": "tools/list", "params": {}}],
        })


# ---------------------------------------------------------------------------
# ReportGenerator.load()
# ---------------------------------------------------------------------------


def test_render_html_escapes_server_controlled_values(tmp_path: Path) -> None:
    """A malicious server can supply hostile tool names / metadata; the HTML
    report must escape them (autoescape) to prevent stored XSS."""
    _write_finding(tmp_path / "findings", "MCPSTRIKE-001", "high")
    sessions = tmp_path / "sessions"
    sessions.mkdir(parents=True, exist_ok=True)
    registry = {
        "server_name": "evil-server",
        "server_version": "1.0.0",
        "protocol_version": "2025-03-26",
        "target_cmd": "node server.js",
        "target_url": "",
        "server_capabilities": ["tools"],
        "tools": [
            {
                "name": "<script>alert(1)</script>",
                "description": "x",
                "input_schema": {},
            },
        ],
        "resources": [],
        "resource_templates": [],
    }
    (sessions / "evil-server.json").write_text(json.dumps(registry))
    data = gen.load(tmp_path)
    html = gen.render_html(data)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_auth_diff_finding_rendered_with_evidence(tmp_path: Path) -> None:
    """An auth_differential artifact must render with its proof (identities,
    verdict, similarity, attacker exchange), not empty generic fields (R#4)."""
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir(parents=True)
    exch = {"jsonrpc": "2.0", "id": 2, "method": "resources/read",
            "params": {"uri": "secret://user/2/data"}}
    resp = {"jsonrpc": "2.0", "id": 2, "result": {"contents": [{"text": "bob-secret"}]}}
    artifact = {
        "schema_version": "mcp-striker.finding/v1",
        "finding_id": "MCPSTRIKE-001",
        "severity": "high",
        "type": "auth_differential",
        "module": "auth-diff",
        "transport": "stdio",
        "protocol_version": "2025-03-26",
        "resource_uri": "secret://user/2/data",
        "owner_name": "bob",
        "attacker_name": "alice",
        "verdict": "IDOR",
        "data_leaked": True,
        "similarity_score": 0.95,
        "raw_owner_request": exch,
        "raw_owner_response": resp,
        "raw_attacker_request": exch,
        "raw_attacker_response": resp,
    }
    (findings_dir / "MCPSTRIKE-001.json").write_text(json.dumps(artifact))
    _write_registry(tmp_path / "sessions")

    data = gen.load(tmp_path)
    assert len(data.findings) == 1
    rec = data.findings[0]
    assert rec.finding_type == "auth_differential"
    assert rec.raw_request  # attacker request preserved (not empty)
    assert rec.raw_response is not None
    assert "alice" in rec.payload and "bob" in rec.payload
    assert any("verdict:IDOR" in h for h in rec.matchers_hit)

    html = gen.render_html(data)
    assert "secret://user/2/data" in html


def test_all_findings_rendered_not_deduped_per_module(tmp_path: Path) -> None:
    """Every finding is rendered, not one representative per module (R#13b)."""
    findings_dir = tmp_path / "findings"
    _write_finding(findings_dir, "MCPSTRIKE-001", "high", module="tool-path-traversal")
    _write_finding(findings_dir, "MCPSTRIKE-002", "high", module="tool-path-traversal")
    _write_finding(findings_dir, "MCPSTRIKE-003", "high", module="tool-path-traversal")
    _write_registry(tmp_path / "sessions")

    data = gen.load(tmp_path)
    assert len(data.findings) == 3
    assert len(data.sorted_findings) == 3  # not deduped to 1
    html = gen.render_html(data)
    for fid in ("MCPSTRIKE-001", "MCPSTRIKE-002", "MCPSTRIKE-003"):
        assert fid in html


def test_load_findings(tmp_path: Path) -> None:
    _write_finding(tmp_path / "findings", "MCPSTRIKE-001", "critical", module="tool-path-traversal")
    _write_finding(tmp_path / "findings", "MCPSTRIKE-002", "high", module="tool-command-injection")
    _write_registry(tmp_path / "sessions")
    data = gen.load(tmp_path)
    assert len(data.findings) == 2


def test_load_empty_findings(tmp_path: Path) -> None:
    _write_registry(tmp_path / "sessions")
    (tmp_path / "findings").mkdir()
    data = gen.load(tmp_path)
    assert data.findings == []


def test_load_missing_dir_returns_empty(tmp_path: Path) -> None:
    data = gen.load(tmp_path)
    assert data.findings == []
    assert data.metrics.total == 0


def test_load_server_name_from_registry(tmp_path: Path) -> None:
    _write_registry(tmp_path / "sessions", server_name="chrome_devtools")
    data = gen.load(tmp_path)
    assert data.server_name == "chrome_devtools"


def test_load_custom_title(tmp_path: Path) -> None:
    data = gen.load(tmp_path, title="ACME Corp Assessment")
    assert data.title == "ACME Corp Assessment"


def test_load_default_title_includes_server_name(tmp_path: Path) -> None:
    _write_registry(tmp_path / "sessions", server_name="my-server")
    data = gen.load(tmp_path)
    assert "my-server" in data.title


# ---------------------------------------------------------------------------
# Probe metrics from session exchanges
# ---------------------------------------------------------------------------


def test_metrics_counts_exchanges(tmp_path: Path) -> None:
    session_dir = tmp_path / "sessions" / "sess-abc"
    _write_exchange(session_dir, "ex1")
    _write_exchange(session_dir, "ex2")
    _write_exchange(session_dir, "ex3", blocked=True)
    _write_exchange(session_dir, "ex4", failed=True)
    _write_registry(tmp_path / "sessions")
    data = gen.load(tmp_path)
    assert data.metrics.total == 4
    assert data.metrics.blocked == 1
    assert data.metrics.failed == 1
    assert data.metrics.successful == 2


def test_metrics_counts_sessions(tmp_path: Path) -> None:
    for name in ("sess-a", "sess-b", "sess-c"):
        _write_exchange(tmp_path / "sessions" / name, "ex1")
    _write_registry(tmp_path / "sessions")
    data = gen.load(tmp_path)
    assert data.metrics.sessions == 3


def test_metrics_zero_when_no_sessions(tmp_path: Path) -> None:
    data = gen.load(tmp_path)
    assert data.metrics.total == 0
    assert data.metrics.sessions == 0


# ---------------------------------------------------------------------------
# severity_counts and sorted_findings
# ---------------------------------------------------------------------------


def test_severity_counts(tmp_path: Path) -> None:
    _write_finding(tmp_path / "findings", "MCPSTRIKE-001", "critical", module="tool-path-traversal")
    _write_finding(tmp_path / "findings", "MCPSTRIKE-002", "critical", module="tool-command-injection")
    _write_finding(tmp_path / "findings", "MCPSTRIKE-003", "high", module="tool-ssrf")
    _write_finding(tmp_path / "findings", "MCPSTRIKE-004", "medium", module="resource-enumeration")
    data = gen.load(tmp_path)
    counts = data.severity_counts
    assert counts["critical"] == 2
    assert counts["high"] == 1
    assert counts["medium"] == 1


def test_sorted_findings_severity_order(tmp_path: Path) -> None:
    _write_finding(tmp_path / "findings", "MCPSTRIKE-001", "low", module="tool-path-traversal")
    _write_finding(tmp_path / "findings", "MCPSTRIKE-002", "critical", module="tool-command-injection")
    _write_finding(tmp_path / "findings", "MCPSTRIKE-003", "high", module="tool-ssrf")
    data = gen.load(tmp_path)
    sevs = [f.severity for f in data.sorted_findings]
    assert sevs == ["critical", "high", "low"]


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------


def test_render_html_contains_finding(tmp_path: Path) -> None:
    _write_finding(tmp_path / "findings", "MCPSTRIKE-001", "critical")
    _write_registry(tmp_path / "sessions")
    data = gen.load(tmp_path)
    html = gen.render_html(data)
    assert "MCPSTRIKE-001" in html
    assert "critical" in html.lower()
    assert "/etc/passwd" in html


def test_render_html_valid_structure(tmp_path: Path) -> None:
    _write_registry(tmp_path / "sessions")
    data = gen.load(tmp_path)
    html = gen.render_html(data)
    assert "<!DOCTYPE html>" in html
    assert "<html" in html
    assert "Executive Summary" in html
    assert "</html>" in html


def test_render_html_no_findings_shows_clean(tmp_path: Path) -> None:
    # A genuine clean run: a registry loaded AND at least one probe produced a
    # response (none matched). Without a completed probe the run is inconclusive.
    _write_exchange(tmp_path / "sessions" / "sess-1", "ex1")
    _write_registry(tmp_path / "sessions")
    data = gen.load(tmp_path)
    assert not data.is_inconclusive
    html = gen.render_html(data)
    assert "clean" in html.lower() or "No vulnerabilities" in html


def test_corrupt_artifact_makes_report_inconclusive(tmp_path: Path) -> None:
    """A corrupt finding artifact must not be silently skipped into a clean
    report — it counts as a parse error and makes the report inconclusive (R#5)."""
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir(parents=True)
    (findings_dir / "MCPSTRIKE-001.json").write_text("{ this is not valid json")
    _write_registry(tmp_path / "sessions")

    data = gen.load(tmp_path)
    assert data.metrics.parse_errors >= 1
    assert data.is_inconclusive
    assert "Inconclusive" in gen.render_html(data)
    assert "Inconclusive" in gen.render_markdown(data)


def test_empty_run_is_inconclusive_not_clean(tmp_path: Path) -> None:
    """An empty base dir (no registry, no probes) must never read as clean (R#5/#2)."""
    data = gen.load(tmp_path)
    assert not data.findings
    assert data.is_inconclusive
    assert not data.has_registry
    html = gen.render_html(data)
    assert "Inconclusive" in html
    assert "found clean" not in html
    assert "Inconclusive" in gen.render_markdown(data)


def test_enum_only_run_is_inconclusive_not_clean(tmp_path: Path) -> None:
    """A registry with zero probes executed proves nothing — inconclusive (R#5/#2)."""
    _write_registry(tmp_path / "sessions")
    data = gen.load(tmp_path)
    assert not data.findings
    assert data.has_registry
    assert data.metrics.successful == 0
    assert data.is_inconclusive
    assert "Inconclusive" in gen.render_html(data)


def test_all_blocked_run_is_inconclusive_not_clean(tmp_path: Path) -> None:
    """A run where every probe was safety-blocked exercised nothing — inconclusive."""
    _write_exchange(tmp_path / "sessions" / "sess-1", "ex1", blocked=True)
    _write_registry(tmp_path / "sessions")
    data = gen.load(tmp_path)
    assert data.metrics.blocked == 1
    assert data.metrics.successful == 0
    assert data.is_inconclusive


def test_failed_probes_are_not_reported_clean(tmp_path: Path) -> None:
    """No findings + failed probes → INCONCLUSIVE, never 'found clean' (#9)."""
    _write_exchange(tmp_path / "sessions" / "sess-1", "ex1", failed=True)
    _write_registry(tmp_path / "sessions")
    data = gen.load(tmp_path)
    assert not data.findings
    assert data.metrics.failed >= 1

    html = gen.render_html(data)
    assert "Inconclusive" in html
    assert "found clean" not in html

    md = gen.render_markdown(data)
    assert "Inconclusive" in md
    assert "found clean" not in md


def test_render_html_no_secrets_leaked(tmp_path: Path) -> None:
    """Finding artifacts are already redacted; report must not introduce secrets."""
    findings_dir = tmp_path / "findings"
    findings_dir.mkdir(parents=True)
    artifact = {
        "schema_version": "mcp-striker.finding/v1",
        "finding_id": "MCPSTRIKE-001",
        "severity": "high",
        "session_id": "",
        "type": "server_vulnerability",
        "module": "test",
        "transport": "stdio",
        "protocol_version": "2025-03-26",
        "method": "tools/call",
        "payload": "/etc/passwd",
        "matchers_hit": [],
        "raw_request": {"Authorization": "[REDACTED]"},
        "raw_response": None,
    }
    (findings_dir / "MCPSTRIKE-001.json").write_text(json.dumps(artifact))
    data = gen.load(tmp_path)
    html = gen.render_html(data)
    assert "eyJ" not in html  # no JWT leak
    assert "[REDACTED]" in html  # redaction marker preserved


def test_render_html_tools_section(tmp_path: Path) -> None:
    _write_registry(tmp_path / "sessions")
    data = gen.load(tmp_path)
    html = gen.render_html(data)
    assert "read_file" in html
    assert "list_dir" in html


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


def test_render_markdown_contains_finding(tmp_path: Path) -> None:
    _write_finding(tmp_path / "findings", "MCPSTRIKE-001", "high")
    data = gen.load(tmp_path)
    md = gen.render_markdown(data)
    assert "MCPSTRIKE-001" in md
    assert "HIGH" in md
    assert "/etc/passwd" in md


def test_render_markdown_executive_summary(tmp_path: Path) -> None:
    data = gen.load(tmp_path)
    md = gen.render_markdown(data)
    assert "Executive Summary" in md
    assert "Probes sent" in md


def test_render_markdown_no_findings(tmp_path: Path) -> None:
    data = gen.load(tmp_path)
    md = gen.render_markdown(data)
    assert "clean" in md.lower() or "No vulnerabilities" in md
