"""ReportGenerator — produces professional PT deliverables from mcp-striker artifacts.

Takes the entire ``.mcp-striker/`` directory as input:

    .mcp-striker/
    ├── findings/           ← MCPSTRIKE-*.json  (finding artifacts)
    └── sessions/
        ├── <server>.json   ← CapabilityRegistry enum snapshot
        └── <session-id>/
            └── *.json      ← TransportExchange records (all probes)

Produces:
    - HTML report: self-contained, print-to-PDF friendly, no external deps
    - Markdown report: for GitLab/GitHub issues or pandoc pipelines

Template is embedded as a Python string to avoid packaging issues with
non-Python files in wheel distributions.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment

# Autoescaping environment: server-controlled values (names, tool names,
# payloads, matcher labels) are interpolated into the HTML report, so HTML
# metacharacters must be escaped to prevent stored XSS when the operator opens
# a report generated from a malicious server. The `tojson` filter remains
# HTML-safe under autoescape.
_JINJA_ENV = Environment(autoescape=True)

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_COLOURS = {
    "critical": "#dc2626",
    "high":     "#ea580c",
    "medium":   "#d97706",
    "low":      "#65a30d",
    "info":     "#2563eb",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class FindingRecord:
    finding_id: str
    severity: str
    module: str
    method: str
    payload: str
    matchers_hit: list[str]
    raw_request: dict[str, Any]
    raw_response: dict[str, Any] | None
    session_id: str
    transport: str
    protocol_version: str
    finding_type: str = "server_vulnerability"

    @property
    def severity_order(self) -> int:
        return _SEVERITY_ORDER.get(self.severity, 99)

    @property
    def severity_colour(self) -> str:
        return _SEVERITY_COLOURS.get(self.severity, "#6b7280")

    @property
    def vuln_class(self) -> str:
        """Human-readable vulnerability class derived from module name."""
        _LABELS = {
            "resource-path-traversal":    "Path Traversal (Resource)",
            "resource-enumeration":        "Sensitive Data Exposure",
            "ssrf-via-resource":           "Server-Side Request Forgery (Resource)",
            "tool-path-traversal":         "Path Traversal (Tool Call)",
            "tool-ssrf":                   "Server-Side Request Forgery (Tool)",
            "tool-command-injection":      "Command Injection",
            "allowed-paths-prefix-bypass": "Path Prefix Bypass",
            "git-tool-probes":             "Git Repository Boundary Bypass",
            "chrome-navigate-ssrf":        "File Read / SSRF via navigate_page",
            "chrome-evaluate-script-rce":  "JavaScript Sandbox Evaluation",
            "chrome-filepath-traversal":   "Arbitrary File Write via filePath",
            "auth-diff":                   "Broken Access Control (IDOR)",
            "origin-missing-check":        "Missing Origin Validation",
            "protocol-version-mismatch":   "Protocol Version Not Validated",
            "session-reuse":               "Session ID Reuse Accepted",
        }
        return _LABELS.get(self.module, self.module.replace("-", " ").title())


@dataclass
class ProbeMetrics:
    total: int = 0
    successful: int = 0   # response received (may or may not match)
    blocked: int = 0      # blocked by SafetyPolicyEngine
    failed: int = 0       # transport or protocol error
    sessions: int = 0     # number of distinct session directories
    parse_errors: int = 0  # corrupt finding/session artifacts that were skipped


@dataclass
class ReportData:
    title: str
    server_name: str
    server_version: str
    protocol_version: str
    transport: str
    generated_at: str
    findings: list[FindingRecord]
    metrics: ProbeMetrics
    tools_enumerated: list[str] = field(default_factory=list)
    # False when no capability registry could be loaded (enum never ran or the
    # snapshot was unreadable). A run with no registry established nothing.
    has_registry: bool = True

    @property
    def inconclusive_reason(self) -> str:
        """Human-readable reason the run cannot be read as clean, or '' if it can.

        A report is a clean result only when enum established an attack surface
        (a registry loaded) AND at least one probe actually produced a response,
        AND nothing failed or was unreadable. Empty directories, enum-only runs,
        fully-blocked runs, transport failures and corrupt artifacts all make the
        absence of findings meaningless."""
        if self.metrics.failed > 0 or self.metrics.parse_errors > 0:
            return (
                f"the run did not complete cleanly "
                f"({self.metrics.failed} failed probe(s), "
                f"{self.metrics.parse_errors} unreadable artifact(s))"
            )
        if not self.has_registry:
            return (
                "no capability registry was loaded — enum did not complete, so "
                "no attack surface was established"
            )
        if self.metrics.successful == 0:
            return (
                "no probe produced a response — nothing was actually exercised "
                "against the target"
            )
        return ""

    @property
    def is_inconclusive(self) -> bool:
        """True when the run did not complete cleanly and must not be read as a
        clean result. See ``inconclusive_reason`` for the exact condition."""
        return bool(self.inconclusive_reason)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    @property
    def sorted_findings(self) -> list[FindingRecord]:
        """Every finding, ordered by severity then id.

        All confirmed findings are rendered (not one representative per module)
        so distinct tools, resources, and payloads are visible and the rendered
        evidence reconciles with the totals. Findings are grouped by severity,
        and by finding id within a severity.
        """
        return sorted(self.findings, key=lambda f: (f.severity_order, f.finding_id))


# ---------------------------------------------------------------------------
# ReportGenerator
# ---------------------------------------------------------------------------


class ReportGenerator:
    """Loads artifacts from base_dir and renders a report."""

    def load(
        self,
        base_dir: Path,
        title: str | None = None,
    ) -> ReportData:
        """Load findings and session data from *base_dir*.

        Args:
            base_dir: The ``.mcp-striker/`` directory.
            title:    Optional custom report title.
        """
        findings_dir = base_dir / "findings"
        sessions_dir = base_dir / "sessions"

        findings, findings_parse_errors = self._load_findings(findings_dir)
        metrics = self._load_metrics(sessions_dir)
        metrics.parse_errors += findings_parse_errors
        registry = self._load_latest_registry(sessions_dir)

        server_name = registry.get("server_name", "unknown")
        server_version = registry.get("server_version", "unknown")
        protocol_version = registry.get("protocol_version", "unknown")
        # Prefer the transport actually saved during enum; fall back to a guess.
        transport = registry.get("target_transport") or (
            "stdio" if registry.get("target_cmd") else "streamable-http"
        )
        tools = [t.get("name", "") for t in (registry.get("tools") or [])]

        generated_at = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        report_title = title or f"mcp-striker Security Assessment — {server_name}"

        # Warn if findings reference multiple different server names.
        # This happens when --output-dir was not used to separate test runs.
        if findings:
            unique_modules = {f.module for f in findings}
            # Check if session exchanges come from multiple distinct server registries
            server_names = self._load_all_server_names(sessions_dir)
            if len(server_names) > 1:
                import warnings
                warnings.warn(
                    f"Report contains findings from multiple server sessions: "
                    f"{sorted(server_names)}. "
                    f"Use --output-dir to keep test runs separate.",
                    stacklevel=2,
                )

        return ReportData(
            title=report_title,
            server_name=server_name,
            server_version=server_version,
            protocol_version=protocol_version,
            transport=transport,
            generated_at=generated_at,
            findings=findings,
            metrics=metrics,
            tools_enumerated=tools,
            has_registry=bool(registry),
        )

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def render_html(self, data: ReportData) -> str:
        """Render the HTML report from the embedded template (autoescaped)."""
        return _JINJA_ENV.from_string(_HTML_TEMPLATE).render(data=data)

    def render_markdown(self, data: ReportData) -> str:
        """Render a Markdown report."""
        lines: list[str] = []
        lines += [
            f"# {data.title}",
            f"",
            f"**Server:** {data.server_name} v{data.server_version}  ",
            f"**Protocol:** {data.protocol_version}  ",
            f"**Transport:** {data.transport}  ",
            f"**Generated:** {data.generated_at}  ",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Findings confirmed | {len(data.findings)} |",
            f"| Probes sent | {data.metrics.total} |",
            f"| Probes blocked (SafetyPolicy) | {data.metrics.blocked} |",
            f"| Probes failed | {data.metrics.failed} |",
            f"| Sessions run | {data.metrics.sessions} |",
            f"| Tools enumerated | {len(data.tools_enumerated)} |",
            f"",
        ]

        # Severity summary
        counts = data.severity_counts
        lines += [
            f"### Findings by Severity",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev in ("critical", "high", "medium", "low", "info"):
            if counts.get(sev, 0) > 0:
                lines.append(f"| {sev.upper()} | {counts[sev]} |")
        lines.append("")

        if not data.findings:
            if data.is_inconclusive:
                lines += [
                    f"**Inconclusive.** No vulnerabilities were confirmed, but "
                    f"{data.inconclusive_reason} — so absence of findings is not "
                    f"proof the target is clean.",
                    "",
                ]
            else:
                lines += [
                    "No vulnerabilities confirmed. Attack surface tested and "
                    "found clean.",
                    "",
                ]
        else:
            lines += [f"---", f"", f"## Findings", f""]
            for i, finding in enumerate(data.sorted_findings, 1):
                lines += [
                    f"### [{finding.severity.upper()}] {finding.finding_id} — {finding.vuln_class}",
                    f"",
                    f"**Module:** `{finding.module}`  ",
                    f"**Method:** `{finding.method}`  ",
                ]
                if finding.payload:
                    lines += [f"**Payload:** `{finding.payload}`  "]
                lines += [
                    f"**Matchers:** {', '.join(f'`{m}`' for m in finding.matchers_hit)}  ",
                    f"",
                    f"<details><summary>Request</summary>",
                    f"",
                    f"```json",
                    json.dumps(finding.raw_request, indent=2),
                    f"```",
                    f"",
                    f"</details>",
                    f"",
                ]
                if finding.raw_response:
                    lines += [
                        f"<details><summary>Response (proof)</summary>",
                        f"",
                        f"```json",
                        json.dumps(finding.raw_response, indent=2)[:4000],
                        f"```",
                        f"",
                        f"</details>",
                        f"",
                    ]

        if data.tools_enumerated:
            lines += [
                f"---",
                f"",
                f"## Tested Surface",
                f"",
                f"**Tools enumerated ({len(data.tools_enumerated)}):**",
                f"",
            ]
            for t in data.tools_enumerated:
                lines.append(f"- `{t}`")
            lines.append("")

        lines += [
            f"---",
            f"",
            f"*Report generated by [mcp-striker](https://github.com/anthropics/mcp-striker)*",
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Internal loaders
    # ------------------------------------------------------------------

    def _load_findings(self, findings_dir: Path) -> tuple[list[FindingRecord], int]:
        if not findings_dir.is_dir():
            return [], 0
        records: list[FindingRecord] = []
        parse_errors = 0
        for path in sorted(findings_dir.glob("MCPSTRIKE-*.json")):
            try:
                raw = json.loads(path.read_text())
                if raw.get("type") == "auth_differential":
                    # DiffFinding has a different schema; map it so its proof
                    # (identities, verdict, similarity, attacker exchange) is
                    # rendered instead of empty generic fields.
                    records.append(self._diff_record(raw, path.stem))
                else:
                    records.append(FindingRecord(
                        finding_id=raw.get("finding_id", path.stem),
                        severity=raw.get("severity", "medium"),
                        module=raw.get("module", "unknown"),
                        method=raw.get("method", ""),
                        payload=raw.get("payload", ""),
                        matchers_hit=raw.get("matchers_hit", []),
                        raw_request=raw.get("raw_request") or {},
                        raw_response=raw.get("raw_response"),
                        session_id=raw.get("session_id", ""),
                        transport=raw.get("transport", ""),
                        protocol_version=raw.get("protocol_version", ""),
                        finding_type=raw.get("type", "server_vulnerability"),
                    ))
            except Exception:
                parse_errors += 1
                continue
        return records, parse_errors

    @staticmethod
    def _diff_record(raw: dict[str, Any], fallback_id: str) -> "FindingRecord":
        """Map an ``auth_differential`` artifact into a renderable record.

        The attacker exchange (unauthorized access to the owner's resource) is
        the proof, so it becomes raw_request/raw_response; the identities,
        verdict and similarity are surfaced in the payload and matchers.
        """
        similarity = raw.get("similarity_score", 0.0)
        owner = raw.get("owner_name", "?")
        attacker = raw.get("attacker_name", "?")
        uri = raw.get("resource_uri", "")
        verdict = raw.get("verdict", "")
        hits = [f"verdict:{verdict}", f"similarity:{similarity}"]
        if raw.get("data_leaked"):
            hits.append("data_leaked")
        return FindingRecord(
            finding_id=raw.get("finding_id", fallback_id),
            severity=raw.get("severity", "high"),
            module=raw.get("module", "auth-diff"),
            method="resources/read (auth-diff)",
            payload=(
                f"{uri} — attacker '{attacker}' accessed owner '{owner}' "
                f"resource (verdict {verdict}, similarity {similarity})"
            ),
            matchers_hit=hits,
            raw_request=raw.get("raw_attacker_request") or {},
            raw_response=raw.get("raw_attacker_response"),
            session_id=raw.get("session_id", ""),
            transport=raw.get("transport", ""),
            protocol_version=raw.get("protocol_version", ""),
            finding_type="auth_differential",
        )

    def _load_metrics(self, sessions_dir: Path) -> ProbeMetrics:
        """Aggregate probe metrics from all session exchange files."""
        metrics = ProbeMetrics()
        if not sessions_dir.is_dir():
            return metrics

        session_dirs = [
            p for p in sessions_dir.iterdir()
            if p.is_dir() and not p.name.endswith(".json")
        ]
        metrics.sessions = len(session_dirs)

        for session_dir in session_dirs:
            for exchange_file in session_dir.glob("*.json"):
                try:
                    raw = json.loads(exchange_file.read_text())
                except Exception:
                    metrics.parse_errors += 1
                    continue
                metrics.total += 1
                safety = raw.get("safety_decision") or {}
                if safety.get("verdict") == "blocked":
                    metrics.blocked += 1
                elif raw.get("probe_failed"):
                    metrics.failed += 1
                else:
                    metrics.successful += 1

        return metrics

    def _load_all_server_names(self, sessions_dir: Path) -> set[str]:
        """Return the set of distinct server_name values across all snapshots."""
        if not sessions_dir.is_dir():
            return set()
        names: set[str] = set()
        for snap in sessions_dir.glob("*.json"):
            try:
                data = json.loads(snap.read_text())
                name = data.get("server_name", "")
                if name:
                    names.add(name)
            except Exception:
                continue
        return names

    def _load_latest_registry(self, sessions_dir: Path) -> dict[str, Any]:

        """Load the most recently modified CapabilityRegistry snapshot."""
        if not sessions_dir.is_dir():
            return {}
        snapshots = sorted(
            sessions_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for snap in snapshots:
            try:
                data = json.loads(snap.read_text())
                if "server_name" in data:
                    return data
            except Exception:
                continue
        return {}


# ---------------------------------------------------------------------------
# HTML template (inline — avoids packaging issues with non-Python files)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{ data.title }}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           font-size: 14px; line-height: 1.6; color: #1f2937; background: #f9fafb; }
    .page { max-width: 960px; margin: 0 auto; padding: 40px 24px; }
    /* Header */
    .header { background: #111827; color: #f9fafb; padding: 32px; border-radius: 8px;
               margin-bottom: 32px; }
    .header h1 { font-size: 22px; font-weight: 700; margin-bottom: 8px; }
    .header .meta { font-size: 12px; color: #9ca3af; }
    .header .meta span { margin-right: 20px; }
    /* Section */
    .section { background: white; border: 1px solid #e5e7eb; border-radius: 8px;
                padding: 24px; margin-bottom: 24px; }
    .section h2 { font-size: 16px; font-weight: 700; color: #111827;
                  border-bottom: 2px solid #e5e7eb; padding-bottom: 8px; margin-bottom: 16px; }
    /* Metrics grid */
    .metrics { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; }
    .metric { background: #f3f4f6; border-radius: 6px; padding: 12px 16px; }
    .metric .value { font-size: 28px; font-weight: 800; color: #111827; }
    .metric .label { font-size: 11px; color: #6b7280; text-transform: uppercase;
                     letter-spacing: .05em; }
    /* Severity badges */
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px;
             font-size: 11px; font-weight: 700; text-transform: uppercase;
             letter-spacing: .05em; color: white; }
    .sev-critical { background: #dc2626; }
    .sev-high     { background: #ea580c; }
    .sev-medium   { background: #d97706; }
    .sev-low      { background: #65a30d; }
    .sev-info     { background: #2563eb; }
    /* Severity bar */
    .sev-bar { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 8px; }
    .sev-bar .item { display: flex; align-items: center; gap: 6px; font-size: 13px; }
    .sev-bar .dot { width: 12px; height: 12px; border-radius: 50%; }
    /* Finding card */
    .finding { border: 1px solid #e5e7eb; border-radius: 6px; margin-bottom: 16px;
               overflow: hidden; }
    .finding-header { display: flex; align-items: center; gap: 10px;
                      padding: 12px 16px; background: #f9fafb;
                      border-bottom: 1px solid #e5e7eb; }
    .finding-id { font-weight: 700; color: #111827; font-size: 13px; }
    .finding-title { color: #374151; font-size: 13px; font-weight: 600; }
    .payload { background: #fef3c7; border: 1px solid #fbbf24; color: #92400e;
               padding: 2px 7px; border-radius: 3px; font-size: 12px;
               font-family: monospace; word-break: break-all; max-width: 100%; display:inline-block; }
    .finding-body { padding: 16px; }
    .kv { margin-bottom: 6px; font-size: 13px; }
    .kv .key { color: #6b7280; min-width: 90px; display: inline-block; }
    .kv code { background: #f3f4f6; padding: 1px 5px; border-radius: 3px;
               font-family: 'SF Mono', Consolas, monospace; font-size: 12px;
               word-break: break-all; }
    /* Collapsible proof */
    details { margin-top: 12px; }
    details summary { cursor: pointer; color: #4b5563; font-size: 12px;
                      user-select: none; padding: 4px 0; }
    details summary:hover { color: #111827; }
    pre { background: #1f2937; color: #d1fae5; padding: 12px 16px; border-radius: 6px;
          font-size: 11px; overflow-x: auto; margin-top: 8px; white-space: pre-wrap;
          word-break: break-all; }
    /* Tools list */
    .tool-grid { display: flex; flex-wrap: wrap; gap: 6px; }
    .tool-chip { background: #f3f4f6; border: 1px solid #e5e7eb; border-radius: 4px;
                 padding: 2px 8px; font-size: 11px; font-family: monospace; }
    /* No findings */
    .clean { text-align: center; padding: 32px; color: #6b7280; }
    .clean .icon { font-size: 40px; margin-bottom: 8px; }
    /* Print */
    @media print {
      body { background: white; }
      .page { padding: 20px; }
      details { display: block; }
      details summary { display: none; }
    }
  </style>
</head>
<body>
<div class="page">

  <div class="header">
    <h1>{{ data.title }}</h1>
    <div class="meta">
      <span>🖥 {{ data.server_name }} v{{ data.server_version }}</span>
      <span>🔌 {{ data.transport }}</span>
      <span>📡 Protocol {{ data.protocol_version }}</span>
      <span>🕐 {{ data.generated_at }}</span>
    </div>
  </div>

  <!-- Executive Summary -->
  <div class="section">
    <h2>Executive Summary</h2>
    <div class="metrics">
      <div class="metric">
        <div class="value">{{ data.findings|length }}</div>
        <div class="label">Findings</div>
      </div>
      <div class="metric">
        <div class="value">{{ data.metrics.total }}</div>
        <div class="label">Probes sent</div>
      </div>
      <div class="metric">
        <div class="value">{{ data.metrics.blocked }}</div>
        <div class="label">Blocked</div>
      </div>
      <div class="metric">
        <div class="value">{{ data.metrics.failed }}</div>
        <div class="label">Failed</div>
      </div>
      <div class="metric">
        <div class="value">{{ data.metrics.sessions }}</div>
        <div class="label">Sessions</div>
      </div>
      <div class="metric">
        <div class="value">{{ data.tools_enumerated|length }}</div>
        <div class="label">Tools found</div>
      </div>
    </div>
    {% set counts = data.severity_counts %}
    {% if data.findings %}
    <div class="sev-bar" style="margin-top:16px;">
      {% for sev, colour in [('critical','#dc2626'),('high','#ea580c'),('medium','#d97706'),('low','#65a30d'),('info','#2563eb')] %}
        {% if counts.get(sev, 0) > 0 %}
        <div class="item">
          <div class="dot" style="background:{{ colour }}"></div>
          <strong>{{ counts[sev] }}</strong>&nbsp;{{ sev }}
        </div>
        {% endif %}
      {% endfor %}
    </div>
    {% endif %}
  </div>

  <!-- Findings -->
  <div class="section">
    <h2>Findings ({{ data.findings|length }})</h2>
    {% if data.sorted_findings %}
      {% for finding in data.sorted_findings %}
      <div class="finding">
        <div class="finding-header">
          <span class="badge sev-{{ finding.severity }}">{{ finding.severity }}</span>
          <span class="finding-id">{{ finding.finding_id }}</span>
          <span class="finding-title">{{ finding.vuln_class }}</span>
        </div>
        <div class="finding-body">
          <div class="kv">
            <span class="key">Vulnerability</span>
            <strong>{{ finding.vuln_class }}</strong>
            <span style="color:#6b7280;margin-left:8px;font-size:11px;">({{ finding.module }})</span>
          </div>
          {% if finding.payload %}
          <div class="kv">
            <span class="key">Payload</span>
            <code class="payload">{{ finding.payload }}</code>
          </div>
          {% endif %}
          <div class="kv">
            <span class="key">Method</span>
            <code>{{ finding.method }}</code>
          </div>
          <div class="kv">
            <span class="key">Matchers hit</span>
            {% for m in finding.matchers_hit %}<code>{{ m }}</code> {% endfor %}
          </div>
          <details>
            <summary>▶ Proof — Request &amp; Response</summary>
            <pre>{{ finding.raw_request | tojson(indent=2) }}</pre>
            {% if finding.raw_response %}
            <pre>{{ finding.raw_response | tojson(indent=2) }}</pre>
            {% endif %}
          </details>
        </div>
      </div>
      {% endfor %}
    {% else %}
      {% if data.is_inconclusive %}
      <div class="clean">
        <div class="icon">⚠️</div>
        <p><strong>Inconclusive.</strong> No vulnerabilities were confirmed, but
           {{ data.inconclusive_reason }} — so absence of findings is not proof
           the target is clean.</p>
      </div>
      {% else %}
      <div class="clean">
        <div class="icon">✅</div>
        <p>No vulnerabilities confirmed. Attack surface tested and found clean.</p>
      </div>
      {% endif %}
    {% endif %}
  </div>

  <!-- Tested Surface -->
  {% if data.tools_enumerated %}
  <div class="section">
    <h2>Tested Surface — Tools ({{ data.tools_enumerated|length }})</h2>
    <div class="tool-grid">
      {% for tool in data.tools_enumerated %}
      <span class="tool-chip">{{ tool }}</span>
      {% endfor %}
    </div>
  </div>
  {% endif %}

  <p style="text-align:center;color:#9ca3af;font-size:11px;margin-top:24px;">
    Report generated by mcp-striker
  </p>
</div>
</body>
</html>
"""
