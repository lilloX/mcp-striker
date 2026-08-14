"""Unit tests for the scaffold generator."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from mcp_striker.registry import CapabilityRegistry, McpResourceTemplate, McpTool
from mcp_striker.scaffold import (
    SAMPLE_BLOCKED,
    ScaffoldGenerator,
    _classify_param,
    _classify_placeholder,
    _slugify,
)

# ---------------------------------------------------------------------------
# _classify_param
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,expected", [
    ("path", "path-traversal"),
    ("file_path", "path-traversal"),
    ("filepath", "path-traversal"),
    ("filename", "path-traversal"),
    ("directory", "path-traversal"),
    ("src", "path-traversal"),
    ("source", "path-traversal"),
    ("url", "ssrf"),
    ("uri", "ssrf"),
    ("endpoint", "ssrf"),
    ("href", "ssrf"),
    ("base_url", "ssrf"),
    ("function", "code-eval"),
    ("code", "code-eval"),
    ("script", "code-eval"),
    ("command", "injection"),
    ("cmd", "injection"),
    ("args", "injection"),
    ("instruction", "injection"),
    ("value", "unknown"),
    ("content", "unknown"),
    ("name", "unknown"),
    ("data", "unknown"),
])
def test_classify_param(name: str, expected: str) -> None:
    assert _classify_param(name) == expected


def test_classify_param_case_insensitive() -> None:
    assert _classify_param("Path") == "path-traversal"
    assert _classify_param("URL") == "ssrf"
    assert _classify_param("COMMAND") == "injection"


# ---------------------------------------------------------------------------
# _slugify
# ---------------------------------------------------------------------------


def test_slugify_basic() -> None:
    assert _slugify("chrome_devtools") == "chrome_devtools"
    assert _slugify("@commercehub/cimpress-ui-mcp") == "commercehub-cimpress-ui-mcp"
    assert _slugify("My Server!") == "my-server"


# ---------------------------------------------------------------------------
# ScaffoldGenerator
# ---------------------------------------------------------------------------


def _make_registry(*tools: tuple[str, dict]) -> CapabilityRegistry:
    return CapabilityRegistry(
        server_name="test-server",
        server_version="0.1",
        protocol_version="2025-03-26",
        server_capabilities=["tools"],
        tools=[
            McpTool(
                name=name,
                description=f"Tool {name}",
                input_schema={
                    "type": "object",
                    "properties": schema,
                },
            )
            for name, schema in tools
        ],
    )


gen = ScaffoldGenerator()


def test_generates_file_for_tool_with_string_param(tmp_path: Path) -> None:
    registry = _make_registry(
        ("read_file", {"path": {"type": "string", "description": "File path"}}),
    )
    written = gen.generate_all(registry, tmp_path)
    assert len(written) == 1
    assert written[0].parent.name == "tool"
    assert written[0].name == "test-server-read_file.yaml"


def test_skips_tools_without_string_params(tmp_path: Path) -> None:
    registry = _make_registry(
        ("resize_page", {"width": {"type": "integer"}, "height": {"type": "integer"}}),
    )
    written = gen.generate_all(registry, tmp_path)
    assert written == []


def test_generates_multiple_files(tmp_path: Path) -> None:
    registry = _make_registry(
        ("read_file", {"path": {"type": "string"}}),
        ("fetch_url", {"url": {"type": "string"}}),
        ("close_page", {"pageId": {"type": "integer"}}),
    )
    written = gen.generate_all(registry, tmp_path)
    assert len(written) == 2


def test_scaffold_contains_tool_name(tmp_path: Path) -> None:
    registry = _make_registry(
        ("read_file", {"path": {"type": "string"}}),
    )
    written = gen.generate_all(registry, tmp_path)
    content = written[0].read_text()
    assert "read_file" in content
    # scaffold now hardcodes tool name and param name — no ${matched_*} variables
    assert "${payload}" in content
    assert "path:" in content or 'path: "${payload}"' in content


def test_scaffold_path_traversal_suggests_payloads(tmp_path: Path) -> None:
    registry = _make_registry(
        ("read_file", {"path": {"type": "string"}}),
    )
    written = gen.generate_all(registry, tmp_path)
    content = written[0].read_text()
    assert "/etc/passwd" in content
    assert "../../../etc/passwd" in content


def test_scaffold_ssrf_suggests_payloads(tmp_path: Path) -> None:
    registry = _make_registry(
        ("fetch", {"url": {"type": "string"}}),
    )
    written = gen.generate_all(registry, tmp_path)
    content = written[0].read_text()
    assert "169.254.169.254" in content


def test_scaffold_injection_suggests_payloads(tmp_path: Path) -> None:
    registry = _make_registry(
        ("run_command", {"command": {"type": "string"}}),
    )
    written = gen.generate_all(registry, tmp_path)
    content = written[0].read_text()
    assert "whoami" in content or "id" in content


def test_scaffold_classify_appears_in_comment(tmp_path: Path) -> None:
    registry = _make_registry(
        ("read_file", {"path": {"type": "string"}}),
    )
    written = gen.generate_all(registry, tmp_path)
    content = written[0].read_text()
    # classification now appears in step comment ("path-traversal"), not a header line
    assert "path-traversal" in content


def test_scaffold_payloads_are_commented_out(tmp_path: Path) -> None:
    """Payloads must appear as comments, not active YAML."""
    registry = _make_registry(
        ("read_file", {"path": {"type": "string"}}),
    )
    written = gen.generate_all(registry, tmp_path)
    content = written[0].read_text()

    # Parse the YAML — payloads list should be empty (all commented out)
    parsed = yaml.safe_load(content)
    step = parsed["steps"][0]
    assert step.get("payloads", []) == [] or step.get("payloads") is None, (
        "Payloads must be commented out in the scaffold, not active"
    )


def test_scaffold_is_valid_yaml(tmp_path: Path) -> None:
    registry = _make_registry(
        ("evaluate_script", {"function": {"type": "string"}}),
        ("navigate_page", {"url": {"type": "string"}}),
    )
    written = gen.generate_all(registry, tmp_path)
    for path in written:
        # Should parse without errors
        parsed = yaml.safe_load(path.read_text())
        assert parsed["version"] == "1"
        assert "name" in parsed
        assert "steps" in parsed


def test_scaffold_each_injectable_param_has_own_step(tmp_path: Path) -> None:
    """Each injectable string param must produce its own mutate step."""
    registry = _make_registry(
        ("read_file", {"path": {"type": "string"}, "encoding": {"type": "string"}}),
    )
    written = gen.generate_all(registry, tmp_path)
    parsed = yaml.safe_load(written[0].read_text())
    step_ids = [s["id"] for s in parsed["steps"]]
    assert "probe_path" in step_ids
    assert "probe_encoding" in step_ids
    assert len(step_ids) == 2


def test_scaffold_creates_output_dir(tmp_path: Path) -> None:
    output = tmp_path / "new" / "nested" / "dir"
    registry = _make_registry(
        ("read_file", {"path": {"type": "string"}}),
    )
    gen.generate_all(registry, output)
    assert output.is_dir()


def test_scaffold_with_real_chrome_devtools_tools(tmp_path: Path) -> None:
    """Simulate a chrome-devtools-mcp registry and check scaffold output."""
    registry = CapabilityRegistry(
        server_name="chrome_devtools",
        server_version="0.1",
        protocol_version="2025-03-26",
        server_capabilities=["tools"],
        tools=[
            McpTool(name="evaluate_script", description="Evaluate JS function",
                    input_schema={"type": "object", "properties": {
                        "function": {"type": "string"},
                        "args": {"type": "array"},
                    }}),
            McpTool(name="navigate_page", description="Navigate to URL",
                    input_schema={"type": "object", "properties": {
                        "url": {"type": "string"},
                        "type": {"type": "string"},
                    }}),
            McpTool(name="take_screenshot", description="Take screenshot",
                    input_schema={"type": "object", "properties": {
                        "filePath": {"type": "string"},
                        "format": {"type": "string"},
                    }}),
            McpTool(name="resize_page", description="Resize page",
                    input_schema={"type": "object", "properties": {
                        "width": {"type": "integer"},
                        "height": {"type": "integer"},
                    }}),
        ],
    )
    written = gen.generate_all(registry, tmp_path)
    # resize_page has no string params → 3 files, not 4
    assert len(written) == 3
    names = {p.name for p in written}
    assert "chrome_devtools-evaluate_script.yaml" in names
    assert "chrome_devtools-navigate_page.yaml" in names
    assert "chrome_devtools-take_screenshot.yaml" in names
    assert "chrome_devtools-resize_page.yaml" not in names


# ---------------------------------------------------------------------------
# Sample response block
# ---------------------------------------------------------------------------




def test_scaffold_sample_response_in_yaml(tmp_path: Path) -> None:
    """When a sample response is provided, the YAML includes the SAMPLE RESPONSE comment."""
    registry = _make_registry(
        ("read_file", {"path": {"type": "string"}}),
    )
    sample = '{"content":[{"type":"text","text":"Error: file not found"}],"isError":true}'
    written = gen.generate_all(registry, tmp_path, sample_responses={"read_file": sample})
    content = written[0].read_text()
    assert "SAMPLE RESPONSE" in content
    assert "REQ:" in content
    assert "RES:" in content
    assert "isError:true" in content
    assert "isError:true responses are NOT findings" in content


def test_scaffold_sample_response_truncated(tmp_path: Path) -> None:
    """Responses longer than 200 characters are truncated with an ellipsis."""
    registry = _make_registry(
        ("read_file", {"path": {"type": "string"}}),
    )
    long_response = '{"content":[{"type":"text","text":"' + "A" * 300 + '"}]}'
    written = gen.generate_all(registry, tmp_path, sample_responses={"read_file": long_response})
    content = written[0].read_text()
    assert "…" in content
    # The full 300-char string must not appear verbatim.
    assert "A" * 300 not in content


def test_scaffold_sample_blocked_comment(tmp_path: Path) -> None:
    """SAMPLE_BLOCKED sentinel produces the 'not collected — mutating' comment."""
    registry = _make_registry(
        ("delete_file", {"path": {"type": "string"}}),
    )
    written = gen.generate_all(
        registry, tmp_path, sample_responses={"delete_file": SAMPLE_BLOCKED}
    )
    content = written[0].read_text()
    assert "not collected" in content
    assert "mutating" in content
    assert "--allow-mutating" in content


def test_scaffold_no_sample_no_comment(tmp_path: Path) -> None:
    """When sample_responses is None, no SAMPLE RESPONSE block appears."""
    registry = _make_registry(
        ("read_file", {"path": {"type": "string"}}),
    )
    written = gen.generate_all(registry, tmp_path, sample_responses=None)
    content = written[0].read_text()
    assert "SAMPLE RESPONSE" not in content


def test_scaffold_sample_is_still_valid_yaml(tmp_path: Path) -> None:
    """A scaffold with a sample response must still parse as valid YAML."""
    registry = _make_registry(
        ("read_file", {"path": {"type": "string"}}),
    )
    sample = '{"content":[{"type":"text","text":"err"}],"isError":true}'
    written = gen.generate_all(registry, tmp_path, sample_responses={"read_file": sample})
    parsed = yaml.safe_load(written[0].read_text())
    assert parsed["version"] == "1"
    assert "steps" in parsed


# ---------------------------------------------------------------------------
# Extra parameters (required active, optional commented)
# ---------------------------------------------------------------------------


def _make_registry_full(tool_name: str, properties: dict, required: list[str] | None = None) -> CapabilityRegistry:
    schema: dict = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return CapabilityRegistry(
        server_name="test-server",
        server_version="0.1",
        protocol_version="2025-03-26",
        server_capabilities=["tools"],
        tools=[McpTool(name=tool_name, description=f"Tool {tool_name}", input_schema=schema)],
    )


def test_scaffold_required_non_primary_params_are_active(tmp_path: Path) -> None:
    """Required non-primary params appear as active YAML lines with placeholder."""
    registry = _make_registry_full(
        "get_prices",
        {
            "productId":      {"type": "string"},
            "country":        {"type": "string"},
            "productVersion": {"type": "string"},
        },
        required=["productId", "country", "productVersion"],
    )
    written = gen.generate_all(registry, tmp_path)
    content = written[0].read_text()
    # country and productVersion must appear as active (not commented) lines
    assert 'country: ""  # required' in content
    assert 'productVersion: ""  # required' in content
    # and NOT as comments
    assert "# country:" not in content
    assert "# productVersion:" not in content


def test_scaffold_optional_non_primary_params_are_commented(tmp_path: Path) -> None:
    """Optional non-primary params appear as commented lines."""
    registry = _make_registry_full(
        "search",
        {
            "query":   {"type": "string"},
            "limit":   {"type": "integer"},
            "offset":  {"type": "integer"},
        },
        required=["query"],
    )
    written = gen.generate_all(registry, tmp_path)
    content = written[0].read_text()
    assert "# limit: 0  # optional" in content
    assert "# offset: 0  # optional" in content


def test_scaffold_mixed_types_placeholder(tmp_path: Path) -> None:
    """Placeholders are typed correctly for each JSON Schema type."""
    registry = _make_registry_full(
        "create_item",
        {
            "name":     {"type": "string"},
            "count":    {"type": "integer"},
            "price":    {"type": "number"},
            "active":   {"type": "boolean"},
            "meta":     {"type": "object"},
            "tags":     {"type": "array"},
        },
        required=["name", "count", "price", "active", "meta", "tags"],
    )
    written = gen.generate_all(registry, tmp_path)
    content = written[0].read_text()
    assert "count: 0  # required" in content
    assert "price: 0  # required" in content
    assert "active: false  # required" in content
    assert "meta: {}  # required" in content
    assert "tags: []  # required" in content


def test_scaffold_extra_params_valid_yaml(tmp_path: Path) -> None:
    """A scaffold with extra parameters must still be valid YAML."""
    registry = _make_registry_full(
        "get_prices",
        {
            "productId":      {"type": "string"},
            "country":        {"type": "string"},
            "selections":     {"type": "object"},
            "quantities":     {"type": "array"},
        },
        required=["productId", "country"],
    )
    written = gen.generate_all(registry, tmp_path)
    parsed = yaml.safe_load(written[0].read_text())
    step = parsed["steps"][0]
    args = step["params"]["arguments"]
    # country must be an active key in the parsed arguments
    assert "country" in args
    assert args["country"] == ""


# ---------------------------------------------------------------------------
# Resource template scaffolds
# ---------------------------------------------------------------------------


def _make_registry_with_templates(*templates: tuple[str, str]) -> CapabilityRegistry:
    """Create a registry with only resource templates (no tools)."""
    return CapabilityRegistry(
        server_name="test-server",
        server_version="0.1",
        protocol_version="2025-03-26",
        server_capabilities=["resources"],
        resource_templates=[
            McpResourceTemplate(uri_template=uri, name=name)
            for uri, name in templates
        ],
    )


@pytest.mark.parametrize("placeholder,uri,expected", [
    ("id", "secret://user/{id}/data", "idor"),
    ("user_id", "data://{user_id}", "idor"),
    ("path", "file://{path}", "path-traversal"),
    ("file", "file://{file}", "path-traversal"),
    ("url", "http://{url}", "ssrf"),
    ("anything", "file://data/{anything}", "path-traversal"),  # scheme fallback
    ("anything", "http://x/{anything}", "ssrf"),               # scheme fallback
    ("anything", "custom://{anything}", "idor"),               # opaque fallback
])
def test_classify_placeholder(placeholder: str, uri: str, expected: str) -> None:
    assert _classify_placeholder(placeholder, uri) == expected


def test_generates_file_for_resource_template(tmp_path: Path) -> None:
    registry = _make_registry_with_templates(("secret://user/{id}/data", "user-secret"))
    written = gen.generate_all(registry, tmp_path)
    assert len(written) == 1
    assert written[0].parent.name == "template"
    assert written[0].name == "test-server-user-secret.yaml"


def test_resource_template_scaffold_is_valid_yaml(tmp_path: Path) -> None:
    registry = _make_registry_with_templates(("secret://user/{id}/data", "user-secret"))
    written = gen.generate_all(registry, tmp_path)
    parsed = yaml.safe_load(written[0].read_text())
    assert parsed["version"] == "1"
    assert "steps" in parsed
    assert parsed["steps"][0]["method"] == "resources/read"


def test_resource_template_payloads_are_commented_out(tmp_path: Path) -> None:
    registry = _make_registry_with_templates(("secret://user/{id}/data", "user-secret"))
    written = gen.generate_all(registry, tmp_path)
    parsed = yaml.safe_load(written[0].read_text())
    step = parsed["steps"][0]
    assert step.get("payloads", []) == [] or step.get("payloads") is None


def test_resource_template_idor_suggests_numeric_payloads(tmp_path: Path) -> None:
    registry = _make_registry_with_templates(("secret://user/{id}/data", "user-secret"))
    written = gen.generate_all(registry, tmp_path)
    content = written[0].read_text()
    assert "# - \"0\"" in content or "# - \"1\"" in content
    assert "admin" in content


def test_resource_template_path_suggests_traversal_payloads(tmp_path: Path) -> None:
    registry = _make_registry_with_templates(("file://data/{path}", "data-file"))
    written = gen.generate_all(registry, tmp_path)
    content = written[0].read_text()
    assert "/etc/passwd" in content


def test_resource_template_uri_contains_payload_injection(tmp_path: Path) -> None:
    """The generated URI in params must reference ${payload}."""
    registry = _make_registry_with_templates(("secret://user/{id}/data", "user-secret"))
    written = gen.generate_all(registry, tmp_path)
    content = written[0].read_text()
    assert "${payload}" in content


def test_resource_template_one_step_per_placeholder(tmp_path: Path) -> None:
    """A template with two placeholders produces two steps."""
    registry = _make_registry_with_templates(("data://{tenant}/{id}", "tenant-data"))
    written = gen.generate_all(registry, tmp_path)
    parsed = yaml.safe_load(written[0].read_text())
    step_ids = [s["id"] for s in parsed["steps"]]
    assert "probe_tenant" in step_ids
    assert "probe_id" in step_ids
    assert len(step_ids) == 2


def test_resource_template_no_placeholder_produces_single_step(tmp_path: Path) -> None:
    """A template with no placeholders produces a single raw-URI probe step."""
    registry = _make_registry_with_templates(("config://server/settings", "config"))
    written = gen.generate_all(registry, tmp_path)
    parsed = yaml.safe_load(written[0].read_text())
    assert len(parsed["steps"]) == 1
    assert parsed["steps"][0]["params"]["uri"] == "config://server/settings"


def test_generate_all_produces_tools_and_templates(tmp_path: Path) -> None:
    """When the registry has both tools and templates, both are scaffolded."""
    registry = CapabilityRegistry(
        server_name="mixed-server",
        server_version="0.1",
        protocol_version="2025-03-26",
        server_capabilities=["tools", "resources"],
        tools=[McpTool(
            name="read_file",
            description="Read a file",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
        )],
        resource_templates=[
            McpResourceTemplate(uri_template="secret://user/{id}/data", name="user-secret"),
        ],
    )
    written = gen.generate_all(registry, tmp_path)
    names = {p.name for p in written}
    assert "mixed-server-read_file.yaml" in names
    assert "mixed-server-user-secret.yaml" in names
    assert len(written) == 2


# ---------------------------------------------------------------------------
# R#12 — server-supplied names must not break out of the generated YAML
# ---------------------------------------------------------------------------


def test_malicious_tool_and_param_names_produce_valid_yaml(tmp_path: Path) -> None:
    """A hostile server returning crafted names still yields parseable YAML.

    Tool/param names are attacker-controlled metadata. If interpolated raw they
    could inject YAML structure (quotes, newlines, colons). Every generated file
    must still parse as a single YAML document.
    """
    registry = _make_registry(
        (
            'evil": {injected: true}\nrogue_key: "pwned',
            {
                'path": "x\ninjected_param: true': {"type": "string"},
                "normal_id": {"type": "string"},
            },
        ),
    )
    written = gen.generate_all(registry, tmp_path)
    # File must have been written (not dropped by the validity gate) AND parse.
    assert len(written) == 1
    parsed = yaml.safe_load(written[0].read_text())
    assert isinstance(parsed, dict)
    assert parsed.get("version") == "1"


def test_malicious_optional_param_name_does_not_inject_arguments(tmp_path: Path) -> None:
    """An optional non-string param name cannot inject keys via its comment line.

    Optional non-injectable params are emitted as commented-out placeholders
    (``# name: value  # optional``). A newline in the name would otherwise
    terminate the comment and turn the remainder into a live ``arguments`` key.
    The generated YAML must parse AND expose no attacker-added argument key.
    """
    registry = CapabilityRegistry(
        server_name="s",
        server_version="0.1",
        protocol_version="2025-03-26",
        server_capabilities=["tools"],
        tools=[
            McpTool(
                name="read_file",
                description="d",
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        # optional, non-injectable, crafted to break out of its comment
                        "n\n        injected: true #": {"type": "integer"},
                        "flag\n        also_injected: 1 #": {"type": "boolean"},
                    },
                    "required": ["path"],
                },
            )
        ],
    )
    written = gen.generate_all(registry, tmp_path)
    assert len(written) == 1
    doc = yaml.safe_load(written[0].read_text())
    for step in doc["steps"]:
        arg_keys = set(step["params"]["arguments"].keys())
        assert "injected" not in arg_keys
        assert "also_injected" not in arg_keys


def test_malicious_template_placeholder_produces_valid_yaml(tmp_path: Path) -> None:
    """A crafted resource-template URI stays contained in its YAML scalar."""
    registry = CapabilityRegistry(
        server_name="hostile",
        server_version="0.1",
        protocol_version="2025-03-26",
        server_capabilities=["resources"],
        resource_templates=[
            McpResourceTemplate(
                uri_template='secret://{id}"\ninjected: true\n#{x}',
                name="rogue",
            ),
        ],
    )
    written = gen.generate_all(registry, tmp_path)
    assert len(written) == 1
    parsed = yaml.safe_load(written[0].read_text())
    assert isinstance(parsed, dict)
    assert parsed.get("version") == "1"
