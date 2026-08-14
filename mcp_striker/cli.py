"""CLI layer — mcp-striker commands.

Commands:
    enum          Enumerate capabilities (STDIO or HTTP).
    strike        Path traversal probes against enumerated surface.
    http-probe    Transport-layer security probes (HTTP only).
    auth-diff     Broken access control (IDOR) probes.
    replay        Not available in this release (planned post-v1.0).
    validate-modules  Not available in this release (planned post-v1.0).
"""

from __future__ import annotations

import asyncio
import re
import shlex
import uuid
from pathlib import Path
from typing import Annotated

import sys

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from mcp_striker.engine.strike import StrikeEngine
from mcp_striker.engine.transport_probe import TransportProbeEngine
from mcp_striker.evidence import EvidenceGenerator
from mcp_striker.models import SafetyContext, TransportContext
from mcp_striker.protocol.client import ProtocolClient
from mcp_striker.recorder import SessionRecorder
from mcp_striker.registry import CapabilityRegistry
from mcp_striker.safety import SafetyPolicyEngine
from mcp_striker.transport.stdio import StdioTransport
from mcp_striker.transport.sse import SseTransport
from mcp_striker.transport.streamable_http import StreamableHttpTransport
from mcp_striker.engine.auth_diff import AuthDiffEngine
from mcp_striker.engine.flow import FlowEngine
from mcp_striker.report import ReportGenerator
from mcp_striker.scaffold import ScaffoldGenerator, SAMPLE_BLOCKED
from mcp_striker.dsl.parser import YAMLFlowParser, FlowParseError
from mcp_striker.dsl.selector import ModuleSelector
from mcp_striker.identity import IdentityManager
from mcp_striker.ownership import OwnershipRegistry

app = typer.Typer(
    name="mcp-striker",
    help="⚡ Deterministic exploit validation for MCP servers.",
    add_completion=False,
)
def _console() -> Console:
    """Return a Console bound to the current sys.stdout.

    Created lazily per-call so output always follows the active stdout
    (important when mcp-striker is invoked as a subprocess with pipes).
    """
    return Console(file=sys.stdout, highlight=False)


def _stderr_console() -> Console:
    """Return a Console bound to sys.stderr, for warnings and diagnostics."""
    return Console(file=sys.stderr, highlight=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_filename(name: str) -> str:
    slug = re.sub(r"[^\w\-]", "-", name.lower())
    return re.sub(r"-{2,}", "-", slug).strip("-") or "server"


def _update_gitignore(output_dir: Path) -> None:
    """Ensure the runtime output dir is gitignored, without duplicating entries.

    No-op when the output dir is already covered by an existing directory
    pattern in .gitignore — in particular the canonical ``.mcp-striker/`` entry
    covers every per-server subdirectory, so we must not append a fresh line for
    each one. Also a no-op when the dir resolves outside the repository (nothing
    sensible to add there).
    """
    cwd = Path.cwd()
    if not (cwd / ".git").is_dir():
        return
    try:
        rel = output_dir.resolve().relative_to(cwd.resolve())
    except ValueError:
        return  # output dir is outside the repo — leave .gitignore untouched
    gitignore = cwd / ".gitignore"
    lines = gitignore.read_text().splitlines() if gitignore.exists() else []
    # Directory patterns already present (lines ending in "/", comments skipped).
    ignored: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and stripped.endswith("/"):
            ignored.add(stripped.rstrip("/"))
    # Covered if the dir itself or any ancestor is already an ignored directory.
    covered = {rel.as_posix(), *(parent.as_posix() for parent in rel.parents)}
    if ignored & covered:
        return
    with gitignore.open("a") as fh:
        fh.write(f"\n# mcp-striker runtime output\n{rel.as_posix()}/\n")


def _warn_if_relative_cmd(cmd: str) -> None:
    """Warn if --cmd contains a relative path to the server script.

    StdioTransport spawns the subprocess with a temporary directory as its
    working directory (sandbox isolation). A relative path in cmd resolves
    against that temp dir, not the caller cwd, causing FileNotFoundError.

    Correct:   --cmd "python /absolute/path/to/server.py"
    Incorrect: --cmd "python server.py"  (breaks inside the sandbox)
    """
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return
    for part in parts[1:]:  # skip the interpreter itself
        if part.startswith("-"):
            continue
        # Looks like a file (has an extension or a path separator) but is not absolute.
        looks_like_file = "." in part or "/" in part or part.startswith(".")
        if looks_like_file and not part.startswith("/"):
            _console().print(
                f"[bold yellow][!] WARNING:[/] --cmd contains a relative path: [bold]{part!r}[/]\n"
                f"    StdioTransport runs the subprocess in a temp dir.\n"
                f"    Use an absolute path, e.g.:\n"
                f"    [dim]--cmd \"python $(pwd)/{part}\"[/]"
            )
            return  # warn once per command


def _parse_key_value(items: list[str], flag: str) -> dict[str, str]:
    """Parse a list of KEY=VALUE strings into a dict.

    Raises a clear error for malformed entries so the operator knows
    immediately rather than getting a cryptic transport failure.
    """
    result: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            _console().print(
                f"[bold red][!][/] Malformed {flag} entry: [bold]{item!r}[/]\n"
                f"    Expected format: KEY=VALUE"
            )
            raise typer.Exit(1)
        key, _, value = item.partition("=")
        result[key.strip()] = value
    return result


def _build_transport(
    transport_type: str,
    cmd: str | None,
    url: str | None,
    timeout: float,
    origin: str | None = None,
    extra_headers: dict[str, str] | None = None,
    extra_env: dict[str, str] | None = None,
    verify_ssl: bool = True,
    path: str | None = None,
) -> StdioTransport | StreamableHttpTransport | SseTransport:
    _VALID_TRANSPORTS = {"stdio", "http", "streamable-http", "sse"}
    if transport_type not in _VALID_TRANSPORTS:
        _console().print(
            f"[bold red][!][/] Unknown --transport '{transport_type}'. "
            f"Use one of: stdio, http, sse."
        )
        raise typer.Exit(2)
    if timeout <= 0:
        _console().print("[bold red][!][/] --timeout must be greater than 0.")
        raise typer.Exit(2)
    if transport_type == "sse":
        if not url:
            _console().print("[bold red][!][/] --url is required for SSE transport.")
            raise typer.Exit(1)
        return SseTransport(
            base_url=url, timeout=timeout,
            path=path or "/sse",
            extra_headers=extra_headers or {},
            verify_ssl=verify_ssl,
        )
    if transport_type in ("http", "streamable-http"):
        if not url:
            _console().print("[bold red][!][/] --url is required for HTTP transport.")
            raise typer.Exit(1)
        return StreamableHttpTransport(
            base_url=url, timeout=timeout, origin=origin,
            extra_headers=extra_headers or {},
            verify_ssl=verify_ssl,
            path=path,
        )
    # Default: stdio
    if not cmd:
        _console().print("[bold red][!][/] --cmd is required for STDIO transport.")
        raise typer.Exit(1)
    return StdioTransport(cmd=shlex.split(cmd), timeout=timeout, extra_env=extra_env or {})


# ---------------------------------------------------------------------------
# enum
# ---------------------------------------------------------------------------


@app.command()
def enum(
    cmd: Annotated[str | None, typer.Option("--cmd", help="STDIO: command to launch the server")] = None,
    url: Annotated[str | None, typer.Option("--url", help="HTTP: base URL of the server")] = None,
    transport: Annotated[str, typer.Option("--transport", help="Transport type: stdio | http | sse (legacy HTTP+SSE 2024-11-05)")] = "stdio",
    timeout: Annotated[float, typer.Option("--timeout")] = 30.0,
    header: Annotated[list[str], typer.Option("--header", help="HTTP extra header as KEY=VALUE (repeatable)")] = [],
    extra_env: Annotated[list[str], typer.Option("--extra-env", help="STDIO extra env var as KEY=VALUE (repeatable)")] = [],
    no_verify_ssl: Annotated[bool, typer.Option("--no-verify-ssl/--verify-ssl", help="Disable TLS certificate verification")] = False,
    path: Annotated[str | None, typer.Option("--path", help="Override MCP endpoint path (default: /mcp)")] = None,
    output_dir: Annotated[Path | None, typer.Option("--output-dir", help="Output dir (default: .mcp-striker/<server-name>/")] = None,
) -> None:
    """Enumerate capabilities of an MCP server."""
    asyncio.run(_enum(
        cmd=cmd, url=url, transport_type=transport, timeout=timeout,
        output_dir=output_dir,  # None = auto-derive from server name
        extra_headers=_parse_key_value(header, "--header"),
        extra_env=_parse_key_value(extra_env, "--extra-env"),
        verify_ssl=not no_verify_ssl,
        path=path,
    ))


async def _enum(
    cmd: str | None,
    url: str | None,
    transport_type: str,
    timeout: float,
    output_dir: Path | None,
    extra_headers: dict[str, str] | None = None,
    extra_env: dict[str, str] | None = None,
    verify_ssl: bool = True,
    path: str | None = None,
) -> None:
    session_id = str(uuid.uuid4())[:8]
    if cmd:
        _warn_if_relative_cmd(cmd)
    mcp_transport = _build_transport(
        transport_type, cmd, url, timeout,
        extra_headers=extra_headers, extra_env=extra_env,
        verify_ssl=verify_ssl, path=path,
    )

    context = TransportContext(
        session_id=session_id,
        target_cmd=cmd or "",
        target_url=url or "",
        transport_type=transport_type,
    )

    try:
        await mcp_transport.connect()
        client = ProtocolClient(transport=mcp_transport, context=context)
        _console().print("[bold cyan][~][/] Connecting to MCP server…")
        await client.initialize()
        registry = await client.enumerate_capabilities()
    finally:
        await mcp_transport.close()

    # Auto-derive output dir from server name if not explicitly set.
    slug = _safe_filename(registry.server_name)
    if output_dir is None:
        output_dir = Path(".mcp-striker") / slug

    # Persist snapshot
    snapshot_path = output_dir / "sessions" / f"{slug}.json"
    registry.save(snapshot_path)

    _console().print(
        f"\n[bold green][+][/] Connected to [bold]{registry.server_name}[/] "
        f"(Protocol {registry.protocol_version})"
    )
    if registry.resource_templates:
        _console().print(f"[bold yellow][!][/] Found [bold]{len(registry.resource_templates)}[/] resource template(s):")
        for t in registry.resource_templates:
            _console().print(f"    - {t.uri_template}  [dim]({t.description or 'no description'})[/]")
    if registry.resources:
        _console().print(f"[bold cyan][+][/] Found [bold]{len(registry.resources)}[/] resource(s):")
        for r in registry.resources:
            _console().print(f"    - {r.uri}")
    if not registry.resource_templates and not registry.resources:
        _console().print("[dim]    No resources or templates found.[/]")

    if registry.tools:
        _console().print(
            f"[bold cyan][+][/] Found [bold]{len(registry.tools)}[/] tool(s):"
        )
        from mcp_striker.tool_classifier import ToolClassifier
        clf = ToolClassifier()
        for t in registry.tools:
            cls = clf.classify(t.name, t.description)
            colour = {"read_only": "green", "mutating": "red", "unknown": "yellow"}[cls.value]
            params = list((t.input_schema.get("properties") or {}).keys())
            param_str = f"  params: {params}" if params else ""
            _console().print(
                f"    [{colour}]{t.name}[/] [{colour}]({cls.value})[/]"
                f"{param_str}"
            )

    _console().print(f"\n[bold green][+][/] Snapshot saved: {snapshot_path}")
    _update_gitignore(output_dir)


# ---------------------------------------------------------------------------
# strike
# ---------------------------------------------------------------------------


@app.command()
def strike(
    from_enum: Annotated[Path, typer.Option("--from-enum")],
    allow_mutating: Annotated[bool, typer.Option("--allow-mutating/--no-allow-mutating")] = False,
    concurrency: Annotated[int, typer.Option("--concurrency")] = 5,
    timeout: Annotated[float, typer.Option("--timeout")] = 30.0,
    output_dir: Annotated[Path | None, typer.Option("--output-dir", help="Output dir (default: .mcp-striker/<server-name>/)")] = None,
    module: Annotated[Path | None, typer.Option("--module", help="Path to a single YAML flow module")] = None,
    modules_dir: Annotated[list[Path], typer.Option("--modules-dir", help="Directory of YAML flow modules (repeatable)")] = [],
    header: Annotated[list[str], typer.Option("--header", help="HTTP extra header as KEY=VALUE (repeatable)")] = [],
    extra_env: Annotated[list[str], typer.Option("--extra-env", help="STDIO extra env var as KEY=VALUE (repeatable)")] = [],
    no_verify_ssl: Annotated[bool, typer.Option("--no-verify-ssl/--verify-ssl", help="Disable TLS certificate verification")] = False,
    path: Annotated[str | None, typer.Option("--path", help="Override MCP endpoint path (default: /mcp)")] = None,
    transport: Annotated[str | None, typer.Option("--transport", help="Override transport from registry: stdio | http | sse")] = None,
    dry_run: Annotated[bool, typer.Option("--dry-run/--no-dry-run", help="Print probe results without saving findings")] = False,
) -> None:
    """Execute probes against an enumerated MCP server.

    Without --module / --modules-dir: runs the hardcoded path traversal probes (M1 behaviour).
    With --module or --modules-dir: runs the specified YAML flow module(s).
    """
    asyncio.run(_strike(
        from_enum=from_enum, allow_mutating=allow_mutating,
        concurrency=concurrency, timeout=timeout, output_dir=output_dir,
        module=module, modules_dirs=modules_dir,
        extra_headers=_parse_key_value(header, "--header"),
        extra_env=_parse_key_value(extra_env, "--extra-env"),
        verify_ssl=not no_verify_ssl,
        path=path,
        transport_override=transport,
        dry_run=dry_run,
    ))


async def _strike(
    from_enum: Path,
    allow_mutating: bool,
    concurrency: int,
    timeout: float,
    output_dir: Path | None,
    module: Path | None = None,
    modules_dirs: list[Path] | None = None,
    extra_headers: dict[str, str] | None = None,
    extra_env: dict[str, str] | None = None,
    verify_ssl: bool = True,
    path: str | None = None,
    transport_override: str | None = None,
    dry_run: bool = False,
) -> None:
    if concurrency < 1:
        _console().print("[bold red][!][/] --concurrency must be at least 1.")
        raise typer.Exit(2)
    registry = CapabilityRegistry.load(from_enum)
    session_id = str(uuid.uuid4())[:8]

    # Auto-derive output dir from server name if not explicitly set.
    if output_dir is None:
        server_slug = _safe_filename(registry.server_name)
        output_dir = Path(".mcp-striker") / server_slug

    # Pick transport based on what was stored in the registry.
    # --transport overrides the saved value (useful when enum was run with wrong transport).
    effective_transport = transport_override or registry.target_transport
    if registry.target_url:
        if effective_transport == "sse":
            mcp_transport = SseTransport(
                base_url=registry.target_url, timeout=timeout,
                path=path or "/sse",
                extra_headers=extra_headers or {},
                verify_ssl=verify_ssl,
            )
            transport_type = "sse"
        else:
            mcp_transport = StreamableHttpTransport(
                base_url=registry.target_url, timeout=timeout,
                extra_headers=extra_headers or {},
                verify_ssl=verify_ssl,
                path=path,
            )
            transport_type = "streamable-http"
    else:
        if registry.target_cmd:
            _warn_if_relative_cmd(registry.target_cmd)
        mcp_transport = StdioTransport(
            cmd=shlex.split(registry.target_cmd), timeout=timeout,
            extra_env=extra_env or {},
        )
        transport_type = "stdio"

    context = TransportContext(
        session_id=session_id,
        target_cmd=registry.target_cmd,
        target_url=registry.target_url,
        protocol_version=registry.protocol_version,
        transport_type=transport_type,
    )
    safety_context = SafetyContext(allow_mutating=allow_mutating)

    session_dir = output_dir / "sessions" / session_id
    findings_dir = output_dir / "findings"

    recorder = SessionRecorder(session_dir=session_dir)
    evidence_gen = EvidenceGenerator(findings_dir=findings_dir)
    safety_engine = SafetyPolicyEngine(
        tool_descriptions={t.name: t.description for t in registry.tools}
    )

    _console().print(f"[bold cyan][~][/] Reconnecting to [bold]{registry.server_name}[/]…")

    try:
        await mcp_transport.connect()
        client = ProtocolClient(transport=mcp_transport, context=context)
        await client.initialize()

        semaphore = asyncio.Semaphore(concurrency)

        if dry_run:
            _console().print(
                "[bold yellow][~] DRY-RUN mode — matchers disabled, "
                "no findings will be saved[/]"
            )

        run_failures = 0
        if module or modules_dirs:
            # --- YAML flow mode ---
            parser = YAMLFlowParser()
            selector = ModuleSelector()
            try:
                if module:
                    raw_modules = [parser.load(module)]
                else:
                    raw_modules = []
                    for d in (modules_dirs or []):
                        raw_modules.extend(parser.load_directory(d))
            except FlowParseError as exc:
                _console().print(f"[bold red][!] Flow parse error:[/] {exc}")
                raise typer.Exit(1)

            selected, skipped = selector.select_with_report(raw_modules, registry)
            for mod, reason in skipped:
                _console().print(f"[dim][~] Skipping '{mod.name}': {reason}[/]")

            if not selected:
                _console().print("[bold yellow][!][/] No applicable modules for this server.")
                finding_ids = []
            else:
                flow_engine = FlowEngine(
                    transport=mcp_transport,
                    registry=registry,
                    recorder=recorder,
                    evidence_generator=evidence_gen,
                    safety_engine=safety_engine,
                    safety_context=safety_context,
                    transport_context=context,
                    semaphore=semaphore,
                    dry_run=dry_run,
                )
                for mod in selected:
                    _console().print(f"[bold cyan][~][/] Running flow: [bold]{mod.name}[/]")
                finding_ids = await flow_engine.run_modules(selected)
                run_failures = flow_engine.failures
        else:
            # --- Hardcoded probe mode (default, M1-compatible) ---
            engine = StrikeEngine(
                transport=mcp_transport,
                registry=registry,
                recorder=recorder,
                evidence_generator=evidence_gen,
                safety_engine=safety_engine,
                safety_context=safety_context,
                transport_context=context,
                concurrency=concurrency,
            )
            _console().print(
                f"[bold cyan][~][/] Running module: [bold]resource-path-traversal[/] "
                f"({len(registry.resource_templates)} template(s) × probes)"
            )
            finding_ids = await engine.run()
            run_failures = engine.failures
    finally:
        await mcp_transport.close()

    _print_findings(finding_ids, findings_dir)
    _console().print(f"[dim]Session transcript: {session_dir}[/]")

    if run_failures:
        # The scan did not complete cleanly: exit non-zero and warn, so a broken
        # run is not mistaken for a clean result.
        _console().print(
            f"[bold yellow][!] Inconclusive:[/] {run_failures} probe(s) failed to "
            f"complete — results may be incomplete."
        )
        raise typer.Exit(2)


# ---------------------------------------------------------------------------
# http-probe
# ---------------------------------------------------------------------------


@app.command(name="http-probe")
def http_probe(
    url: Annotated[str | None, typer.Option("--url", help="Base URL of the HTTP MCP server")] = None,
    from_enum: Annotated[Path | None, typer.Option("--from-enum", help="Enum snapshot — inherits URL and output dir")] = None,
    timeout: Annotated[float, typer.Option("--timeout")] = 10.0,
    output_dir: Annotated[Path | None, typer.Option("--output-dir", help="Output dir (default: .mcp-striker/<server-name>/)")] = None,
    header: Annotated[list[str], typer.Option("--header", help="Extra header as KEY=VALUE (repeatable)")] = [],
    no_verify_ssl: Annotated[bool, typer.Option("--no-verify-ssl/--verify-ssl", help="Disable TLS certificate verification")] = False,
    path: Annotated[str | None, typer.Option("--path", help="Override MCP endpoint path (default: /mcp)")] = None,
) -> None:
    """Execute HTTP transport security probes (Origin, session reuse, version mismatch).

    Either --url or --from-enum is required. When --from-enum is provided the
    target URL and output directory are inherited from the enum snapshot so that
    http-probe findings land in the same directory as strike findings and are
    included in the same report.
    """
    if not url and not from_enum:
        _console().print(
            "[bold red][!][/] Either --url or --from-enum is required."
        )
        raise typer.Exit(1)
    asyncio.run(_http_probe(
        url=url, from_enum=from_enum, timeout=timeout, output_dir=output_dir,
        extra_headers=_parse_key_value(header, "--header"),
        verify_ssl=not no_verify_ssl,
        path=path,
    ))


async def _http_probe(
    url: str | None,
    timeout: float,
    output_dir: Path | None,
    from_enum: Path | None = None,
    extra_headers: dict[str, str] | None = None,
    verify_ssl: bool = True,
    path: str | None = None,
) -> None:
    session_id = str(uuid.uuid4())[:8]

    # If --from-enum is provided, inherit URL and output dir from the registry.
    if from_enum is not None:
        registry = CapabilityRegistry.load(from_enum)
        if not url:
            url = registry.target_url
        if not url:
            _console().print(
                "[bold red][!][/] The enum snapshot has no target URL. "
                "Pass --url explicitly."
            )
            raise typer.Exit(1)
        if output_dir is None:
            server_slug = _safe_filename(registry.server_name)
            output_dir = Path(".mcp-striker") / server_slug
    else:
        # Auto-derive output dir from URL hostname if not explicitly set.
        if output_dir is None:
            from urllib.parse import urlparse
            hostname = urlparse(url).hostname or "http-server"  # type: ignore[arg-type]
            output_dir = Path(".mcp-striker") / _safe_filename(hostname)

    assert url is not None  # guaranteed by the checks above
    session_dir = output_dir / "sessions" / session_id
    findings_dir = output_dir / "findings"

    recorder = SessionRecorder(session_dir=session_dir)
    evidence_gen = EvidenceGenerator(findings_dir=findings_dir)

    _console().print(f"[bold cyan][~][/] Running transport probes against [bold]{url}[/]")

    engine = TransportProbeEngine(
        base_url=url,
        recorder=recorder,
        evidence_generator=evidence_gen,
        session_id=session_id,
        timeout=timeout,
        extra_headers=extra_headers or {},
        verify_ssl=verify_ssl,
        path=path,
    )
    finding_ids = await engine.run()

    _print_findings(finding_ids, findings_dir)
    _console().print(f"[dim]Session transcript: {session_dir}[/]")
    _update_gitignore(output_dir)


# ---------------------------------------------------------------------------
# Shared output helper
# ---------------------------------------------------------------------------


_VULN_LABELS: dict[str, str] = {
    "resource-path-traversal":    "Path Traversal (Resource)",
    "resource-enumeration":       "Sensitive Data Exposure",
    "ssrf-via-resource":          "SSRF (Resource)",
    "tool-path-traversal":        "Path Traversal (Tool)",
    "tool-ssrf":                  "SSRF (Tool)",
    "tool-command-injection":     "Command Injection",
    "allowed-paths-prefix-bypass": "Path Prefix Bypass",
    "git-tool-probes":            "Git Boundary Bypass",
    "chrome-navigate-ssrf":       "File Read / SSRF (navigate_page)",
    "chrome-evaluate-script-rce": "JS Sandbox Escape",
    "chrome-filepath-traversal":  "Arbitrary File Write",
    "auth-diff":                  "Broken Access Control (IDOR)",
    "origin-missing-check":       "Missing Origin Validation",
    "protocol-version-mismatch":  "Protocol Version Not Validated",
    "session-reuse":              "Session ID Reuse Accepted",
}


def _print_findings(finding_ids: list[str], findings_dir: Path) -> None:
    if not finding_ids:
        _console().print("[bold green][+][/] No findings confirmed.")
        return

    import json as _json

    table = Table(title="Findings", style="bold red")
    table.add_column("ID", style="red", no_wrap=True)
    table.add_column("Category")
    table.add_column("Payload")
    table.add_column("File", style="dim")

    for fid in finding_ids:
        path = findings_dir / f"{fid}.json"
        try:
            data = _json.loads(path.read_text())
            module  = data.get("module", "")
            payload = data.get("payload", "")
        except Exception:
            module, payload = "", ""

        label       = _VULN_LABELS.get(module, module.replace("-", " ").title())
        payload_str = (payload[:60] + "…") if len(payload) > 61 else payload

        table.add_row(fid, label, payload_str, str(path))

    _console().print(table)
    _console().print(f"\n[bold red][!][/] {len(finding_ids)} finding(s) confirmed.")


# ---------------------------------------------------------------------------
# Post-MVP placeholders
# ---------------------------------------------------------------------------


@app.command(name="auth-diff")
def auth_diff(
    identities: Annotated[Path, typer.Option("--identities", help="Path to identities YAML file")],
    ownership: Annotated[Path, typer.Option("--ownership", help="Path to ownership fixtures YAML file")],
    cmd: Annotated[str | None, typer.Option("--cmd", help="STDIO: command to launch the server")] = None,
    url: Annotated[str | None, typer.Option("--url", help="HTTP: base URL of the server")] = None,
    transport: Annotated[str, typer.Option("--transport")] = "stdio",
    timeout: Annotated[float, typer.Option("--timeout")] = 15.0,
    concurrency: Annotated[int, typer.Option("--concurrency")] = 3,
    output_dir: Annotated[Path | None, typer.Option("--output-dir", help="Output dir (default: .mcp-striker/<server-name>/)")] = None,
) -> None:
    """Detect IDOR and Tenant Breakout via two-pass differential probing."""
    asyncio.run(_auth_diff(
        identities=identities, ownership=ownership,
        cmd=cmd, url=url, transport_type=transport,
        timeout=timeout, concurrency=concurrency, output_dir=output_dir,
    ))


async def _auth_diff(
    identities: Path,
    ownership: Path,
    cmd: str | None,
    url: str | None,
    transport_type: str,
    timeout: float,
    concurrency: int,
    output_dir: Path | None,
) -> None:
    if concurrency < 1:
        _console().print("[bold red][!][/] --concurrency must be at least 1.")
        raise typer.Exit(2)
    if timeout <= 0:
        _console().print("[bold red][!][/] --timeout must be greater than 0.")
        raise typer.Exit(2)
    if transport_type not in ("stdio", "http"):
        _console().print(
            f"[bold red][!][/] auth-diff supports --transport stdio or http, "
            f"not '{transport_type}'."
        )
        raise typer.Exit(2)
    session_id = str(uuid.uuid4())[:8]

    # Resolve the default output dir BEFORE deriving child paths — otherwise the
    # documented default (no --output-dir) would evaluate `None / "sessions"`
    # and raise TypeError.
    if output_dir is None:
        if url:
            from urllib.parse import urlparse
            slug = _safe_filename(urlparse(url).hostname or "server")
        else:
            slug = _safe_filename((cmd or "server").split()[-1].split("/")[-1].split(".")[0])
        output_dir = Path(".mcp-striker") / slug

    session_dir = output_dir / "sessions" / session_id
    findings_dir = output_dir / "findings"

    identity_manager = IdentityManager()
    identity_manager.load(identities)

    ownership_registry = OwnershipRegistry()
    ownership_registry.load(ownership)

    recorder = SessionRecorder(session_dir=session_dir)
    evidence_gen = EvidenceGenerator(findings_dir=findings_dir)

    n_pairs = len(ownership_registry.all_pairs())
    _console().print(
        f"[bold cyan][~][/] Running [bold]auth-diff[/] — "
        f"{n_pairs} pair(s) via [bold]{transport_type}[/]"
    )

    if cmd:
        _warn_if_relative_cmd(cmd)

    engine = AuthDiffEngine(
        identity_manager=identity_manager,
        ownership_registry=ownership_registry,
        recorder=recorder,
        evidence_generator=evidence_gen,
        session_id=session_id,
        base_url=url or "",
        target_cmd=cmd or "",
        transport_type=transport_type,
        timeout=timeout,
        concurrency=concurrency,
    )
    finding_ids = await engine.run()

    _print_findings(finding_ids, findings_dir)
    _console().print(f"[dim]Session transcript: {session_dir}[/]")
    _update_gitignore(output_dir)

    if engine.failures:
        _console().print(
            f"[bold yellow][!] Inconclusive:[/] {engine.failures} pair(s) failed "
            f"to complete — results may be incomplete."
        )
        raise typer.Exit(2)


@app.command()
def replay() -> None:
    """Replay a recorded finding (not available in this release)."""
    _console().print(Panel(
        "Not available in this release — planned for a future version.",
        title="replay", style="yellow",
    ))
    raise typer.Exit(1)


@app.command()
def scaffold(
    from_enum: Annotated[Path, typer.Option("--from-enum", help="Snapshot from mcp-striker enum")],
    output_dir: Annotated[Path | None, typer.Option("--output-dir", help="Output dir (default: modules/servers/<server-name>/)")] = None,
    allow_mutating: Annotated[bool, typer.Option("--allow-mutating/--no-allow-mutating", help="Allow probing mutating tools for sample responses")] = False,
    timeout: Annotated[float, typer.Option("--timeout", help="Connection timeout for sample probes")] = 10.0,
    header: Annotated[list[str], typer.Option("--header", help="HTTP extra header as KEY=VALUE (repeatable)")] = [],
    extra_env: Annotated[list[str], typer.Option("--extra-env", help="STDIO extra env var as KEY=VALUE (repeatable)")] = [],
    no_verify_ssl: Annotated[bool, typer.Option("--no-verify-ssl/--verify-ssl", help="Disable TLS certificate verification")] = False,
) -> None:
    """Generate YAML module skeletons from an enum snapshot.

    Reads the CapabilityRegistry produced by mcp-striker enum and creates
    one editable YAML file per tool that has injectable string parameters.
    The generated files are NOT runnable as-is — they are starting points
    that the operator customises with appropriate payloads and matchers.

    By default, skeletons are saved to modules/servers/<server-name>/ so
    they are co-located with other server-specific modules.  Payloads are
    commented out — running an unedited scaffold produces zero probes.

    When --allow-mutating is passed, a probe call with an empty value is sent
    for each scaffolded tool and the response is included as a comment in the
    generated YAML to help calibrate regex matchers.
    """
    asyncio.run(_scaffold(
        from_enum=from_enum,
        output_dir=output_dir,
        allow_mutating=allow_mutating,
        timeout=timeout,
        extra_headers=_parse_key_value(header, "--header"),
        extra_env=_parse_key_value(extra_env, "--extra-env"),
        verify_ssl=not no_verify_ssl,
    ))


async def _scaffold(
    from_enum: Path,
    output_dir: Path | None,
    allow_mutating: bool,
    timeout: float,
    extra_headers: dict[str, str] | None = None,
    extra_env: dict[str, str] | None = None,
    verify_ssl: bool = True,
) -> None:
    try:
        registry = CapabilityRegistry.load(from_enum)
    except Exception as exc:
        _console().print(f"[bold red][!][/] Cannot load snapshot: {exc}")
        raise typer.Exit(1)

    # Auto-derive output dir: modules/servers/<server-slug>/
    if output_dir is None:
        server_slug = _safe_filename(registry.server_name)
        output_dir = Path("modules") / "servers" / server_slug

    sample_responses = await _collect_sample_responses(
        registry=registry,
        allow_mutating=allow_mutating,
        timeout=timeout,
        extra_headers=extra_headers,
        extra_env=extra_env,
        verify_ssl=verify_ssl,
    )

    generator = ScaffoldGenerator()
    written = generator.generate_all(registry, output_dir, sample_responses=sample_responses)

    if not written:
        _console().print(
            "[bold yellow][!][/] No injectable string parameters found in any tool. "
            "Nothing to scaffold."
        )
        raise typer.Exit(0)

    _console().print(
        f"[bold green][+][/] Generated [bold]{len(written)}[/] scaffold(s) "
        f"in [bold]{output_dir}/[/]:"
    )
    for path in written:
        _console().print(f"    {path}")

    _console().print(
        f"\n[dim]Edit each file: uncomment payloads, adjust matchers, then run:[/]"
        f"\n[dim]  mcp-striker strike --from-enum {from_enum} --modules-dir {output_dir}[/]"
    )


async def _collect_sample_responses(
    registry: CapabilityRegistry,
    allow_mutating: bool,
    timeout: float,
    extra_headers: dict[str, str] | None = None,
    extra_env: dict[str, str] | None = None,
    verify_ssl: bool = True,
) -> dict[str, str] | None:
    """Probe each injectable tool with empty values and return compact JSON responses.

    Returns None if there is nothing to probe (no tools with string params).
    Returns a dict mapping tool_name → response JSON string (or SAMPLE_BLOCKED).
    Connection errors are caught silently — scaffold proceeds without samples.
    """
    import json as _json
    from mcp_striker.scaffold import ScaffoldGenerator as _SG
    from mcp_striker.tool_classifier import ToolClassifier
    from mcp_striker.models import JsonRpcRequest

    sg = _SG()
    clf = ToolClassifier()
    scaffold_tools = sg._analyze(registry)
    if not scaffold_tools:
        return None

    results: dict[str, str] = {}
    needs_connection = False

    for st in scaffold_tools:
        classification = clf.classify(st.tool.name, st.tool.description)
        if classification.value == "mutating" and not allow_mutating:
            results[st.tool.name] = SAMPLE_BLOCKED
        else:
            needs_connection = True

    if not needs_connection:
        return results

    # Only connect if at least one tool needs probing.
    transport_type = registry.target_transport
    try:
        mcp_transport = _build_transport(
            transport_type,
            cmd=registry.target_cmd or None,
            url=registry.target_url or None,
            timeout=timeout,
            extra_headers=extra_headers,
            extra_env=extra_env,
            verify_ssl=verify_ssl,
        )
        context = TransportContext(
            session_id="scaffold-probe",
            target_cmd=registry.target_cmd,
            target_url=registry.target_url,
            transport_type=transport_type,
        )
        await mcp_transport.connect()
        try:
            client = ProtocolClient(transport=mcp_transport, context=context)
            await client.initialize()

            from mcp_striker.models import SafetyContext
            safety_engine = SafetyPolicyEngine(
                tool_descriptions={t.name: t.description for t in registry.tools}
            )
            safety_ctx = SafetyContext(allow_mutating=allow_mutating)

            for st in scaffold_tools:
                tool_name = st.tool.name
                if tool_name in results:
                    continue  # already marked SAMPLE_BLOCKED

                primary = st.primary_param
                if primary is None:
                    continue

                # Build arguments with empty string for all string params.
                props: dict = (st.tool.input_schema or {}).get("properties") or {}
                arguments: dict[str, str] = {
                    k: "" for k, v in props.items()
                    if isinstance(v, dict) and v.get("type", "string") in ("string", "")
                }

                request = JsonRpcRequest(
                    id=9000 + len(results),
                    method="tools/call",
                    params={"name": tool_name, "arguments": arguments},
                )
                decision = safety_engine.evaluate_request(request, safety_ctx)
                from mcp_striker.models import SafetyVerdict
                if decision.verdict == SafetyVerdict.BLOCKED:
                    results[tool_name] = SAMPLE_BLOCKED
                    continue

                try:
                    exchange = await mcp_transport.send(request, context)
                    if exchange.response is not None:
                        resp_dict = exchange.response.model_dump(mode="json", exclude_none=True)
                        inner = resp_dict.get("result") or resp_dict.get("error") or resp_dict
                        results[tool_name] = _json.dumps(inner, separators=(",", ":"))
                    else:
                        results[tool_name] = "[no response]"
                except Exception as exc:
                    results[tool_name] = f"[probe error: {exc}]"

        finally:
            await mcp_transport.close()

    except Exception as exc:
        _console().print(
            f"[dim][~] Could not connect for sample probes ({exc}). "
            f"Scaffold will be generated without sample responses.[/]"
        )
        return results if results else None

    return results or None


@app.command()
def report(
    base_dir: Annotated[Path | None, typer.Option("--base-dir", help="mcp-striker output dir (default: auto-detect)")] = None,
    output: Annotated[Path, typer.Option("--output")] = Path("report.html"),
    fmt: Annotated[str, typer.Option("--format", help="html or markdown")] = "html",
    title: Annotated[str | None, typer.Option("--title")] = None,
) -> None:
    """Generate a PT report from mcp-striker finding artifacts.

    Reads findings and session exchange records from BASE_DIR and produces
    a self-contained HTML or Markdown report ready to share with the client.

    Examples::

        mcp-striker report
        mcp-striker report --format markdown --output report.md
        mcp-striker report --title "ACME Corp MCP Assessment"
    """
    # Auto-detect base_dir if not specified.
    if base_dir is None:
        mcp_root = Path(".mcp-striker")
        if mcp_root.is_dir():
            candidates = [
                p for p in mcp_root.iterdir()
                if p.is_dir() and (p / "sessions").is_dir()
            ]
            if len(candidates) == 1:
                base_dir = candidates[0]
                _console().print(f"[dim][~] Using: {base_dir}[/]")
            elif len(candidates) > 1:
                _console().print(
                    "[bold yellow][!][/] Multiple test runs found — specify one with --base-dir:\n"
                    + "\n".join(f"    {c}" for c in sorted(candidates))
                )
                raise typer.Exit(1)
            else:
                base_dir = mcp_root   # fallback: use .mcp-striker/ directly
        else:
            base_dir = mcp_root       # will trigger "not found" below

    if not base_dir.is_dir():
        _console().print(
            f"[bold red][!][/] Base directory not found: [bold]{base_dir}[/]\n"
            f"    Run [bold]mcp-striker enum[/] first."
        )
        raise typer.Exit(1)

    gen = ReportGenerator()
    data = gen.load(base_dir, title=title)

    if fmt.lower() == "markdown":
        content_out = gen.render_markdown(data)
        if output.suffix not in (".md", ".markdown"):
            output = output.with_suffix(".md")
    else:
        content_out = gen.render_html(data)
        if output.suffix not in (".html", ".htm"):
            output = output.with_suffix(".html")

    output.write_text(content_out, encoding="utf-8")

    findings_count = len(data.findings)
    colour = "red" if findings_count else "green"
    _console().print(
        f"[bold green][+][/] Report written: [bold]{output}[/]  "
        f"([{colour}]{findings_count} finding(s)[/{colour}], "
        f"{data.metrics.total} probes, "
        f"{len(data.tools_enumerated)} tools)"
    )

    # The report embeds raw evidence (payloads, verbatim responses, and any
    # secrets they contain — see the redaction note in the docs). It is written
    # to the operator-chosen path with ordinary permissions; protecting and
    # sharing it is the operator's responsibility. Warn on stderr so pipelines
    # and operators are not surprised.
    _stderr_console().print(
        f"[bold yellow][!][/] {output} contains unredacted evidence "
        f"(payloads, raw responses, possibly secrets). Treat it as confidential "
        f"and restrict access before sharing."
    )

    if data.is_inconclusive:
        _console().print(
            f"[bold yellow][!] Inconclusive report:[/] "
            f"{data.inconclusive_reason} — "
            f"absence of findings is not proof the target is clean."
        )
        raise typer.Exit(2)


@app.command(name="validate-modules")
def validate_modules() -> None:
    """Validate YAML attack module files (not available in this release)."""
    _console().print(Panel(
        "Not available in this release — planned for a future version.",
        title="validate-modules", style="yellow",
    ))
    raise typer.Exit(1)


if __name__ == "__main__":
    app()
