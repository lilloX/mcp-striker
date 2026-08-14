"""ScaffoldGenerator — generates YAML module skeletons from ``enum`` data.

Given a ``CapabilityRegistry`` snapshot produced by ``mcp-striker enum``,
this module produces one editable YAML file per tool that has at least one
injectable string parameter, and one file per resource template.

The generated skeletons are NOT runnable as-is.  They are a starting point
for the operator: the tool name, parameter name, and suggested payloads are
pre-filled; the operator removes the comment markers from the payloads they
want to test and adds appropriate matchers.

This removes the mechanical boilerplate of writing modules from scratch while
preserving the human decision on what to actually probe.

Classification heuristics
-------------------------
Parameter names (tools) and URI template placeholders (resource templates)
are classified into attack categories to suggest relevant payloads.
The classification is intentionally coarse — it surfaces the most likely
attack surface for a given name, not a definitive verdict.

  path-traversal : path, file, filepath, file_path, filename, dir, folder,
                   src, source, dest, destination, location
  ssrf           : url, uri, endpoint, href, link, address, host, server,
                   remote, target (URL context)
  code-eval      : function, code, script, expr, expression, template
  injection      : command, cmd, args, arg, shell, exec, query (non-SQL),
                   instruction
  idor           : id, user_id, account, account_id, tenant, tenant_id,
                   owner, owner_id, org, org_id, uid
  unknown        : everything else

Resource template scaffolds
----------------------------
For each resource template (e.g. ``secret://user/{id}/data``), the scaffold
generates a ``resources/read`` step with ``uri: "${payload}"`` as the
injection point.  Placeholders in the URI template are extracted and
classified to suggest relevant payloads.  When the placeholder suggests
IDOR (``{id}``, ``{user_id}``, …), numeric and string ID payloads are
suggested.  For ``{path}`` / ``{file}``, path traversal payloads are used.

Sample responses
----------------
``generate_all()`` accepts an optional ``sample_responses`` dict mapping
tool name → compact JSON string of the observed response (or the sentinel
``SAMPLE_BLOCKED`` when the tool is mutating and probing was not allowed).
The sample is embedded as a comment block above the ``matchers:`` section,
giving the operator concrete evidence to calibrate the regex pattern.
Resource template scaffolds do not collect sample responses (the URI is
unknown at scaffold time).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from mcp_striker.registry import CapabilityRegistry, McpResourceTemplate, McpTool


def _yaml_dq(value: str) -> str:
    """Return *value* as a safe YAML double-quoted scalar.

    Server-supplied metadata (tool/param names, URIs) is interpolated into the
    generated YAML; without escaping, a quote/newline/backslash could break out
    of the scalar and alter the module. Double-quoted YAML supports these escapes.
    """
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _yaml_key(name: str) -> str:
    """A safe YAML mapping key: bare for plain identifiers, quoted otherwise.

    Keeps the common case (``path``, ``count``) readable while preventing a
    crafted parameter name from injecting YAML structure as a key.
    """
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", name):
        return name
    return _yaml_dq(name)


def _yaml_comment(text: str) -> str:
    """Collapse *text* to a single safe line for embedding in a YAML comment.

    A comment ends at the first newline, so a newline in server-supplied
    metadata would terminate the comment and let the remainder inject YAML
    structure. Strip ANSI/control sequences and fold any newline, carriage
    return or tab into a single space.
    """
    cleaned = _ANSI_ESCAPE_RE.sub("", text)
    return re.sub(r"[\r\n\t]+", " ", cleaned).strip()


def _yaml_id(name: str) -> str:
    """Return a safe step-id fragment built from *name* (identifier chars only).

    Step ids are emitted bare (``id: probe_<name>``); a newline, colon or space
    in a server-supplied name would break out of the mapping. Reduce to a
    readable identifier, replacing every other character with ``_``.
    """
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", name)
    return safe or "param"


def _is_valid_yaml(content: str) -> bool:
    """True if *content* parses as YAML (a generated scaffold must be valid)."""
    try:
        yaml.safe_load(content)
        return True
    except yaml.YAMLError:
        return False

# Sentinel value for sample_responses: tool is mutating and probing was blocked.
SAMPLE_BLOCKED = "__BLOCKED_MUTATING__"

# Maximum length for request / response lines in the sample comment block.
_SAMPLE_MAX_LEN = 200


# ---------------------------------------------------------------------------
# Payload suggestions per category (shown as YAML comments in the scaffold)
# ---------------------------------------------------------------------------

_PAYLOAD_SUGGESTIONS: dict[str, list[str]] = {
    "idor": [
        "0",
        "1",
        "2",
        "3",
        "100",
        "admin",
        "root",
        "guest",
        "test",
    ],
    "path-traversal": [
        "/etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "/etc/shadow",
        "/proc/version",
        "/etc/hosts",
        "C:\\\\windows\\\\win.ini",
        "..\\\\..\\\\..\\\\windows\\\\win.ini",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://127.0.0.1/",
        "http://127.0.0.1:6379/",
        "http://127.0.0.1:8080/",
        "file:///etc/passwd",
    ],
    "code-eval": [
        "() => document.title",
        "() => typeof require",
        "() => { try { return require('os').hostname() } catch(e) { return 'SAFE:'+e.message } }",
        "() => { try { return require('child_process').execSync('id').toString() } catch(e) { return 'SAFE:'+e.message } }",
    ],
    "injection": [
        "id",
        "whoami",
        "$(id)",
        "`id`",
        "id && echo PWNED",
        "id ; echo PWNED",
        "| id",
        "cat /etc/passwd",
    ],
    "unknown": [
        "test",
        "../../../etc/passwd",
        "http://127.0.0.1/",
    ],
}

_MATCHER_SUGGESTIONS: dict[str, list[str]] = {
    "idor": [
        "secret|token|password|key|data|content",
    ],
    "path-traversal": [
        "root:x:0:0|Linux version|localhost|127\\.0\\.0\\.1|\\[fonts\\]",
    ],
    "ssrf": [
        "ami-id|instance-id|AccessKeyId|computeMetadata|DOCTYPE html|redis_version",
    ],
    "code-eval": [
        "uid=|gid=|root|SAFE:|hostname",
    ],
    "injection": [
        "uid=|gid=|root|PWNED|root:x:0:0",
    ],
    "unknown": [
        "your-expected-pattern-here",
    ],
}

# Parameter name → attack category
_PARAM_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"^(path|file|file_?path|file_?name|dir(ectory)?|folder|src|source|dest(ination)?|location)$", re.I), "path-traversal"),
    (re.compile(r"^(url|uri|endpoint|href|link|address|host|server|remote|base_?url|target_?url)$", re.I), "ssrf"),
    (re.compile(r"^(function|code|script|expr(ession)?|template|snippet)$", re.I), "code-eval"),
    (re.compile(r"^(command|cmd|args?|shell|exec|run|instruction|query)$", re.I), "injection"),
    (re.compile(r"^(id|user_?id|account_?id?|tenant_?id?|owner_?id?|org_?id?|uid)$", re.I), "idor"),
]


def _classify_param(name: str) -> str:
    """Return the attack category for a parameter name."""
    for pattern, category in _PARAM_PATTERNS:
        if pattern.match(name.strip()):
            return category
    return "unknown"


# Placeholder name (from URI template) → attack category.
# Same logic as _classify_param but also handles URI scheme prefixes as a hint.
def _classify_placeholder(placeholder: str, uri_template: str) -> str:
    """Return the attack category for a URI template placeholder.

    First tries to classify by placeholder name (same rules as tool params).
    Falls back to URI scheme heuristic: ``file://`` → path-traversal,
    ``http://`` / ``https://`` → ssrf.
    """
    category = _classify_param(placeholder)
    if category != "unknown":
        return category
    # Scheme-level fallback
    if uri_template.startswith("file://"):
        return "path-traversal"
    if uri_template.startswith(("http://", "https://")):
        return "ssrf"
    return "idor"  # default for opaque schemes with unknown placeholder names


_PLACEHOLDER_RE = re.compile(r"\{([^}]+)\}")


# ---------------------------------------------------------------------------
# ScaffoldTool — intermediate representation
# ---------------------------------------------------------------------------


@dataclass
class ScaffoldParam:
    name: str
    param_type: str  # "string" or other json schema type
    description: str
    category: str


@dataclass
class ScaffoldExtraParam:
    """A non-injectable parameter included in the arguments block."""
    name: str
    param_type: str   # json schema type: string, integer, number, boolean, object, array
    required: bool


@dataclass
class ScaffoldTool:
    tool: McpTool
    injectable_params: list[ScaffoldParam] = field(default_factory=list)
    extra_params: list[ScaffoldExtraParam] = field(default_factory=list)

    @property
    def primary_param(self) -> ScaffoldParam | None:
        """Return the most interesting injectable parameter."""
        # Prefer non-unknown categories
        for p in self.injectable_params:
            if p.category != "unknown":
                return p
        return self.injectable_params[0] if self.injectable_params else None


@dataclass
class ScaffoldResourceTemplate:
    """Intermediate representation of a resource template to scaffold."""

    template: McpResourceTemplate
    # Placeholders extracted from the URI template, with their categories.
    placeholders: list[ScaffoldParam] = field(default_factory=list)

    @property
    def primary_placeholder(self) -> ScaffoldParam | None:
        """Return the most attack-relevant placeholder."""
        for p in self.placeholders:
            if p.category != "unknown":
                return p
        return self.placeholders[0] if self.placeholders else None


# ---------------------------------------------------------------------------
# ScaffoldGenerator
# ---------------------------------------------------------------------------


class ScaffoldGenerator:
    """Generates YAML module skeletons from a ``CapabilityRegistry``."""

    def generate_all(
        self,
        registry: CapabilityRegistry,
        output_dir: Path,
        sample_responses: dict[str, str] | None = None,
    ) -> list[Path]:
        """Generate scaffold files for all injectable tools.

        Args:
            registry: capability snapshot from ``mcp-striker enum``.
            output_dir: directory where YAML files are written.
            sample_responses: optional map of tool name → compact JSON response
                string (or ``SAMPLE_BLOCKED`` sentinel). When provided, each
                scaffold includes a comment block with the observed response
                to help calibrate regex matchers.

        Returns the list of written file paths.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        server_slug = _slugify(registry.server_name)

        tool_dir = output_dir / "tool"
        template_dir = output_dir / "template"

        written: list[Path] = []

        # Tool scaffolds → output_dir/tool/
        for st in self._analyze(registry):
            tool_dir.mkdir(parents=True, exist_ok=True)
            sample = (sample_responses or {}).get(st.tool.name)
            content = self._render(st, registry, sample_response=sample)
            if not _is_valid_yaml(content):
                continue  # never write a malformed scaffold
            tool_slug = _slugify(st.tool.name)
            path = tool_dir / f"{server_slug}-{tool_slug}.yaml"
            path.write_text(content, encoding="utf-8")
            written.append(path)

        # Resource template scaffolds → output_dir/template/
        for srt in self._analyze_resource_templates(registry):
            template_dir.mkdir(parents=True, exist_ok=True)
            content = self._render_resource_template(srt, registry)
            if not _is_valid_yaml(content):
                continue  # never write a malformed scaffold
            tpl_slug = _slugify(srt.template.name or srt.template.uri_template)
            path = template_dir / f"{server_slug}-{tpl_slug}.yaml"
            path.write_text(content, encoding="utf-8")
            written.append(path)

        return written

    # ------------------------------------------------------------------
    # Analysis
    # ------------------------------------------------------------------

    def _analyze(self, registry: CapabilityRegistry) -> list[ScaffoldTool]:
        """Return tools that have at least one injectable string parameter."""
        result: list[ScaffoldTool] = []
        for tool in registry.tools:
            injectable = self._find_injectable_params(tool)
            if injectable:
                # extra_params covers ALL non-injectable parameters plus the
                # injectable string params that are NOT the primary one.
                # The primary param is the injection point; every other param
                # (including other string params) must appear in the arguments
                # block so the call is structurally valid.
                st = ScaffoldTool(tool=tool, injectable_params=injectable)
                primary_name = st.primary_param.name if st.primary_param else ""
                # Exclude only the primary injection param from extra_params.
                extra = self._find_extra_params(tool, injectable_names={primary_name} if primary_name else set())
                st.extra_params = extra
                result.append(st)
        return result

    def _find_injectable_params(self, tool: McpTool) -> list[ScaffoldParam]:
        """Return all string-typed parameters for a tool."""
        props: dict[str, Any] = (tool.input_schema or {}).get("properties") or {}
        params: list[ScaffoldParam] = []
        for name, schema in props.items():
            if not isinstance(schema, dict):
                continue
            # Accept string params or params without explicit type (assume string)
            ptype = schema.get("type", "string")
            if ptype not in ("string", ""):
                continue
            desc = schema.get("description", "")
            category = _classify_param(name)
            params.append(ScaffoldParam(
                name=name,
                param_type=ptype,
                description=desc if isinstance(desc, str) else "",
                category=category,
            ))
        return params

    def _find_extra_params(
        self,
        tool: McpTool,
        injectable_names: set[str],
    ) -> list[ScaffoldExtraParam]:
        """Return non-injectable parameters (required first, then optional)."""
        props: dict[str, Any] = (tool.input_schema or {}).get("properties") or {}
        required_set: set[str] = set((tool.input_schema or {}).get("required") or [])
        params: list[ScaffoldExtraParam] = []
        for name, schema in props.items():
            if name in injectable_names or not isinstance(schema, dict):
                continue
            ptype = schema.get("type", "string") or "string"
            params.append(ScaffoldExtraParam(
                name=name,
                param_type=str(ptype),
                required=name in required_set,
            ))
        # required parameters first
        params.sort(key=lambda p: (not p.required, p.name))
        return params

    def _analyze_resource_templates(
        self, registry: CapabilityRegistry
    ) -> list[ScaffoldResourceTemplate]:
        """Return a ScaffoldResourceTemplate for each resource template in the registry."""
        result: list[ScaffoldResourceTemplate] = []
        for tpl in registry.resource_templates:
            placeholders = []
            for match in _PLACEHOLDER_RE.finditer(tpl.uri_template):
                ph_name = match.group(1)
                category = _classify_placeholder(ph_name, tpl.uri_template)
                placeholders.append(ScaffoldParam(
                    name=ph_name,
                    param_type="string",
                    description="",
                    category=category,
                ))
            # Generate a scaffold even with no placeholders: the operator can
            # still test the raw URI for access-control issues.
            result.append(ScaffoldResourceTemplate(template=tpl, placeholders=placeholders))
        return result

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def _render(
        self,
        st: ScaffoldTool,
        registry: CapabilityRegistry,
        sample_response: str | None = None,
    ) -> str:
        """Render a YAML scaffold for a single tool.

        Generates one ``mutate`` step per injectable string parameter so that
        every parameter is independently tested as an injection point.  Each
        step hardcodes the injection parameter by name (no ``${matched_param}``
        indirection) and keeps the remaining required parameters as active
        placeholders so the call is structurally valid.

        Args:
            st: analyzed tool with injectable parameters.
            registry: capability snapshot (used for server metadata).
            sample_response: compact JSON string of the observed response from
                a probe call with empty values, ``SAMPLE_BLOCKED`` if the tool
                is mutating and probing was not allowed, or ``None`` if no
                sample was collected.
        """
        tool = st.tool
        primary = st.primary_param

        if primary is None:
            return ""

        injectable_names = [p.name for p in st.injectable_params]

        lines: list[str] = []

        # Header comment
        lines += [
            "# AUTO-GENERATED SCAFFOLD — review and customize before running",
            f"# Server : {_yaml_comment(registry.server_name)} (Protocol {registry.protocol_version})",
            f"# Tool   : {_yaml_comment(tool.name)}",
        ]
        if tool.description:
            desc_oneline = _sanitize_desc(tool.description)[:120]
            lines.append(f"# Desc   : {desc_oneline}")
        lines.append(f"# Injectable params: {', '.join(repr(n) for n in injectable_names)}")
        lines += [
            "#",
            "# HOW TO USE:",
            "#   1. Fill in required placeholder values (marked '# required')",
            "#   2. Uncomment the payloads you want to test",
            "#   3. Adjust the regex matcher pattern",
            "#   4. Run: mcp-striker strike --from-enum <snapshot.json> \\",
            "#            --module <this-file> [--allow-mutating]",
            "#",
            "# NOTE: One step per injectable parameter — each tests a different injection point.",
            "#       Not all suggested payloads may be applicable to every parameter.",
            "",
        ]

        # Module body
        lines += [
            "version: \"1\"",
            f"name: \"{_slugify(registry.server_name)}-{_slugify(tool.name)}-probe\"",
            "description: >",
            f"  Custom probe for {_yaml_comment(tool.name)}.",
        ]
        if tool.description:
            desc_wrapped = _sanitize_desc(tool.description)[:200]
            lines.append(f"  Tool description: {desc_wrapped}")
        lines.append("  Edit payloads and matchers before running.")
        lines.append("")

        lines += [
            "requires:",
            "  tools:",
            f"    - {_yaml_dq(re.escape(tool.name))}",
            "",
            "steps:",
        ]

        # One mutate step per injectable parameter.
        for i, inj_param in enumerate(st.injectable_params):
            step_category = inj_param.category
            step_payloads = _PAYLOAD_SUGGESTIONS.get(step_category, _PAYLOAD_SUGGESTIONS["unknown"])
            step_matchers = _MATCHER_SUGGESTIONS.get(step_category, _MATCHER_SUGGESTIONS["unknown"])
            step_id = f"probe_{_yaml_id(inj_param.name)}"

            is_first = i == 0
            lines += [
                f"  - id: {step_id}",
                "    type: mutate",
                "    method: tools/call",
                "    params:",
                f"      name: {_yaml_dq(tool.name)}",
                "      arguments:",
                f"        {_yaml_key(inj_param.name)}: \"${{payload}}\"  # injection point",
            ]

            # Other injectable string params: emit as required placeholders.
            injectable_placeholder_names: set[str] = set()
            for other in st.injectable_params:
                if other.name == inj_param.name:
                    continue
                lines.append(f"        {_yaml_key(other.name)}: \"\"  # required — replace with a real value")
                injectable_placeholder_names.add(other.name)

            # Non-injectable extra params (skip injection point and already-emitted params).
            for ep in st.extra_params:
                if ep.name in injectable_placeholder_names or ep.name == inj_param.name:
                    continue
                ph = _placeholder(ep.param_type)
                if ep.required:
                    lines.append(f"        {_yaml_key(ep.name)}: {ph}  # required — replace with a real value")
                else:
                    lines.append(f"        # {_yaml_comment(ep.name)}: {ph}  # optional")

            # Payloads block (comments inside the block).
            lines.append("    payloads:")
            lines.append(f"      # Suggested for '{_yaml_comment(inj_param.name)}' ({step_category}) -- uncomment and edit:")
            for p in step_payloads:
                lines.append(f"      # - \"{p}\"")

            # Sample response block only on the first step (primary param).
            if is_first:
                lines += self._render_sample_block(tool.name, inj_param, sample_response)

            # Matchers — all commented out (safe starting point).
            lines += [
                "    matchers:",
                "      # - type: jsonrpc_success",
                "      # Uncomment jsonrpc_success and add a content-evidence matcher:",
            ]
            for m in step_matchers:
                lines.append("      # - type: regex")
                lines.append(f"      #   pattern: \"{m}\"")
            lines.append("")

        return "\n".join(lines)

    def _render_resource_template(
        self,
        srt: ScaffoldResourceTemplate,
        registry: CapabilityRegistry,
    ) -> str:
        """Render a YAML scaffold for a single resource template.

        Generates one ``mutate`` step per placeholder in the URI template.
        Each step injects ``${payload}`` as the full URI, with payload
        suggestions based on the placeholder category.  When the template
        has no placeholders, a single step probes the raw template URI.
        """
        tpl = srt.template

        lines: list[str] = []

        # Header comment
        lines += [
            "# AUTO-GENERATED SCAFFOLD — review and customize before running",
            f"# Server   : {_yaml_comment(registry.server_name)} (Protocol {registry.protocol_version})",
            f"# Template : {_yaml_comment(tpl.uri_template)}",
        ]
        if tpl.name:
            lines.append(f"# Name     : {_yaml_comment(tpl.name)}")
        if srt.placeholders:
            ph_names = ", ".join(repr(p.name) for p in srt.placeholders)
            lines.append(f"# Placeholders: {ph_names}")
        lines += [
            "#",
            "# HOW TO USE:",
            "#   1. Uncomment the payloads you want to test",
            "#   2. Adjust the regex matcher pattern",
            "#   3. Run: mcp-striker strike --from-enum <snapshot.json> \\",
            "#            --module <this-file> [--allow-mutating]",
            "#",
            f"# NOTE: ${'{payload}'} is injected as the full URI for resources/read.",
            "#       Replace payload URIs with the correct scheme/format for this server.",
            "",
        ]

        tpl_slug = _slugify(tpl.name or tpl.uri_template)
        server_slug = _slugify(registry.server_name)

        lines += [
            "version: \"1\"",
            f"name: \"{server_slug}-{tpl_slug}-probe\"",
            "description: >",
            f"  Custom probe for resource template {_yaml_comment(tpl.uri_template)}.",
            "  Edit payloads and matchers before running.",
            "",
            "requires:",
            "  capabilities:",
            "    - resources",
            "  resource_templates:",
            f"    - {_yaml_dq(re.escape(tpl.uri_template.split('{')[0]))}",
            "",
            "steps:",
        ]

        if srt.placeholders:
            # One step per placeholder.
            for ph in srt.placeholders:
                step_category = ph.category
                step_payloads = _PAYLOAD_SUGGESTIONS.get(step_category, _PAYLOAD_SUGGESTIONS["idor"])
                step_matchers = _MATCHER_SUGGESTIONS.get(step_category, _MATCHER_SUGGESTIONS["idor"])
                # Build an example URI for this step, substituting the active
                # placeholder with ${payload} and others with their names.
                example_uri = tpl.uri_template
                for other_ph in srt.placeholders:
                    if other_ph.name == ph.name:
                        example_uri = example_uri.replace(f"{{{ph.name}}}", "${payload}")
                    else:
                        example_uri = example_uri.replace(f"{{{other_ph.name}}}", other_ph.name)

                lines += [
                    f"  - id: probe_{_yaml_id(ph.name)}",
                    "    type: mutate",
                    "    method: resources/read",
                    "    params:",
                    f"      uri: {_yaml_dq(example_uri)}  # injection point: {_yaml_comment(ph.name)} ({step_category})",
                    "    payloads:",
                    f"      # Suggested for '{'{'}{_yaml_comment(ph.name)}{'}'}' ({step_category}) -- uncomment and edit:",
                ]
                for p in step_payloads:
                    lines.append(f"      # - \"{p}\"")
                lines += [
                    "    matchers:",
                    "      # - type: jsonrpc_success",
                    "      # Uncomment jsonrpc_success and add a content-evidence matcher:",
                ]
                for m in step_matchers:
                    lines.append("      # - type: regex")
                    lines.append(f"      #   pattern: \"{m}\"")
                lines.append("")
        else:
            # No placeholders — probe the raw template URI.
            lines += [
                "  - id: probe",
                "    type: mutate",
                "    method: resources/read",
                "    params:",
                f"      uri: {_yaml_dq(tpl.uri_template)}",
                "    payloads: []",
                "    matchers:",
                "      # - type: jsonrpc_success",
                "      # - type: regex",
                "      #   pattern: \"your-expected-pattern-here\"",
                "",
            ]

        return "\n".join(lines)

    def _render_sample_block(
        self,
        tool_name: str,
        primary: ScaffoldParam,
        sample_response: str | None,
    ) -> list[str]:
        """Return comment lines for the sample response block (may be empty list)."""
        if sample_response is None:
            return []

        lines: list[str] = ["    #"]

        if sample_response == SAMPLE_BLOCKED:
            lines += [
                "    # SAMPLE RESPONSE: not collected — tool classified as mutating.",
                "    # Run scaffold with --allow-mutating to collect a sample response.",
            ]
            return lines

        req_obj = {"name": tool_name, "arguments": {primary.name: ""}}
        req_str = json.dumps(req_obj, separators=(",", ":"))
        if len(req_str) > _SAMPLE_MAX_LEN:
            req_str = req_str[:_SAMPLE_MAX_LEN] + "…"

        res_str = sample_response
        if len(res_str) > _SAMPLE_MAX_LEN:
            res_str = res_str[:_SAMPLE_MAX_LEN] + "…"

        lines += [
            "    # SAMPLE RESPONSE (probe with empty value \"\"):",
            f"    # REQ: {_yaml_comment(req_str)}",
            f"    # RES: {_yaml_comment(res_str)}",
            "    # NOTE: isError:true responses are NOT findings (filtered by is_success).",
            "    # Configure the regex matcher to match the SUCCESS case, not the error case.",
        ]
        return lines


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[mGKHF]|\x1b[@-Z\\-_]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


def _sanitize_desc(text: str) -> str:
    """Strip ANSI escape sequences and non-printable control characters, collapse newlines."""
    cleaned = _ANSI_ESCAPE_RE.sub("", text)
    return cleaned.replace("\n", " ").strip()


def _slugify(name: str) -> str:
    """Convert a server/tool name to a safe filename slug."""
    slug = re.sub(r"[^\w\-]", "-", name.lower())
    slug = re.sub(r"-{2,}", "-", slug)
    return slug.strip("-") or "server"


def _placeholder(param_type: str) -> str:
    """Return a YAML-safe default placeholder value for a given JSON Schema type."""
    mapping = {
        "string": '""',
        "integer": "0",
        "number": "0",
        "boolean": "false",
        "object": "{}",
        "array": "[]",
    }
    return mapping.get(param_type.lower(), '""')
