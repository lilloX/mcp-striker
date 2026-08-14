"""Unit tests for Milestone 5 — Tool Call Probes."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_striker.dsl.context import MATCHED_TOOL_VAR, FlowContext
from mcp_striker.dsl.parser import YAMLFlowParser
from mcp_striker.dsl.selector import ModuleSelector
from mcp_striker.models import (
    JsonRpcRequest,
    JsonRpcResponse,
    SafetyContext,
    TransportExchange,
)
from mcp_striker.registry import CapabilityRegistry, McpTool
from mcp_striker.safety import SafetyPolicyEngine
from mcp_striker.tool_classifier import ToolClassification, ToolClassifier

MODULES_DIR = Path(__file__).parent.parent.parent / "modules"
parser = YAMLFlowParser()
clf = ToolClassifier()
safety = SafetyPolicyEngine()


# ---------------------------------------------------------------------------
# ToolClassifier
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", [
    "read_file", "readFile", "read_text_file", "get_file", "getFile",
    "list_directory", "list_files", "search_files", "find_file",
    "fetch_url", "fetch", "get_url",
])
def test_read_only_tools_classified_correctly(name: str) -> None:
    assert clf.classify(name) == ToolClassification.READ_ONLY


@pytest.mark.parametrize("name", [
    "write_file", "create_file", "delete_file", "remove_file",
    "execute_command", "exec", "run_shell", "bash", "cmd",
    "edit_file", "update_record",
])
def test_mutating_tools_classified_correctly(name: str) -> None:
    assert clf.classify(name) == ToolClassification.MUTATING


@pytest.mark.parametrize("name", [
    "process_data", "transform", "handle", "action",
])
def test_unknown_tools_classified_correctly(name: str) -> None:
    assert clf.classify(name) == ToolClassification.UNKNOWN


def test_description_elevates_unknown_to_mutating() -> None:
    """An unknown name with a description containing 'delete' → MUTATING."""
    result = clf.classify("process_item", description="This tool will delete the item.")
    assert result == ToolClassification.MUTATING


def test_description_mutating_keyword_overrides_read_only_name() -> None:
    """A read-only *name* must NOT override a description that says it writes.
    Mutating signals take precedence (safe default), so this is MUTATING."""
    result = clf.classify("read_file", description="Reads and writes files.")
    assert result == ToolClassification.MUTATING


def test_compound_name_with_mutating_token_is_mutating() -> None:
    """A read-prefixed compound name hiding a mutating verb (read_and_delete)
    must be classified MUTATING, not read-only."""
    assert clf.classify("read_and_delete") == ToolClassification.MUTATING
    assert clf.classify("get_or_create") == ToolClassification.MUTATING


# ---------------------------------------------------------------------------
# SafetyPolicyEngine — tools/call rules
# ---------------------------------------------------------------------------


def test_safety_allows_read_only_tool_without_flag() -> None:
    req = JsonRpcRequest(
        id=1, method="tools/call", params={"name": "read_file", "arguments": {}}
    )
    ctx = SafetyContext(allow_mutating=False)
    decision = safety.evaluate_request(req, ctx)
    assert decision.verdict.value == "allowed"


def test_safety_blocks_mutating_tool_without_flag() -> None:
    req = JsonRpcRequest(
        id=1, method="tools/call", params={"name": "write_file", "arguments": {}}
    )
    ctx = SafetyContext(allow_mutating=False)
    decision = safety.evaluate_request(req, ctx)
    assert decision.verdict.value == "blocked"


def test_safety_blocks_unknown_tool_without_flag() -> None:
    req = JsonRpcRequest(
        id=1, method="tools/call", params={"name": "process_data", "arguments": {}}
    )
    ctx = SafetyContext(allow_mutating=False)
    decision = safety.evaluate_request(req, ctx)
    assert decision.verdict.value == "blocked"


def test_safety_allows_mutating_tool_with_flag() -> None:
    req = JsonRpcRequest(
        id=1, method="tools/call", params={"name": "execute_command", "arguments": {}}
    )
    ctx = SafetyContext(allow_mutating=True)
    decision = safety.evaluate_request(req, ctx)
    assert decision.verdict.value == "allowed"


def test_safety_extracts_tool_name_from_params() -> None:
    """SafetyPolicyEngine extracts tool name from request.params when not passed explicitly."""
    req = JsonRpcRequest(
        id=1, method="tools/call", params={"name": "write_file", "arguments": {"path": "/x"}}
    )
    ctx = SafetyContext(allow_mutating=False)
    decision = safety.evaluate_request(req, ctx)
    assert decision.verdict.value == "blocked"
    assert "write_file" in decision.reason


# ---------------------------------------------------------------------------
# CapabilityRegistry — McpTool storage
# ---------------------------------------------------------------------------


def test_registry_stores_tools() -> None:
    registry = CapabilityRegistry(
        server_name="test", server_version="0.1",
        protocol_version="2025-03-26",
        tools=[
            McpTool(name="read_file", description="Read a file."),
            McpTool(name="write_file", description="Write a file."),
        ],
    )
    assert len(registry.tools) == 2
    assert registry.tools[0].name == "read_file"


def test_registry_saves_and_loads_tools(tmp_path: Path) -> None:
    registry = CapabilityRegistry(
        server_name="test", server_version="0.1",
        protocol_version="2025-03-26",
        tools=[McpTool(
            name="read_file",
            description="Read a file.",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
        )],
    )
    snapshot = tmp_path / "snap.json"
    registry.save(snapshot)
    loaded = CapabilityRegistry.load(snapshot)
    assert len(loaded.tools) == 1
    assert loaded.tools[0].name == "read_file"
    assert loaded.tools[0].input_schema["type"] == "object"


# ---------------------------------------------------------------------------
# ModuleSelector — tool pattern matching
# ---------------------------------------------------------------------------


def _registry_with_tools(*names: str) -> CapabilityRegistry:
    return CapabilityRegistry(
        server_name="test", server_version="0.1",
        protocol_version="2025-03-26",
        server_capabilities=["tools"],
        tools=[McpTool(name=n) for n in names],
    )


selector = ModuleSelector()


def test_selector_matches_tool_pattern() -> None:
    from mcp_striker.dsl.schema import FlowModule
    module = FlowModule.model_validate({
        "version": "1", "name": "test",
        "requires": {"tools": ["read_file|readFile"]},
        "steps": [{"id": "s", "type": "setup", "method": "tools/list", "params": {}}],
    })
    registry = _registry_with_tools("read_file", "write_file")
    selected = selector.select([module], registry)
    assert module in selected


def test_selector_skips_if_no_matching_tool() -> None:
    from mcp_striker.dsl.schema import FlowModule
    module = FlowModule.model_validate({
        "version": "1", "name": "test",
        "requires": {"tools": ["read_file|readFile"]},
        "steps": [{"id": "s", "type": "setup", "method": "tools/list", "params": {}}],
    })
    registry = _registry_with_tools("write_file", "delete_file")
    selected, skipped = selector.select_with_report([module], registry)
    assert module not in selected
    assert any(m is module for m, _ in skipped)


def test_selector_matched_tool_for() -> None:
    from mcp_striker.dsl.schema import FlowModule
    module = FlowModule.model_validate({
        "version": "1", "name": "test",
        "requires": {"tools": ["read_file|readFile|get_file"]},
        "steps": [{"id": "s", "type": "setup", "method": "tools/list", "params": {}}],
    })
    registry = _registry_with_tools("readFile", "write_file")
    matched = selector.matched_tool_for(module, registry)
    assert matched == "readFile"


def test_selector_matched_tool_case_insensitive() -> None:
    from mcp_striker.dsl.schema import FlowModule
    module = FlowModule.model_validate({
        "version": "1", "name": "test",
        "requires": {"tools": ["read_file"]},
        "steps": [{"id": "s", "type": "setup", "method": "tools/list", "params": {}}],
    })
    registry = _registry_with_tools("Read_File")
    matched = selector.matched_tool_for(module, registry)
    assert matched == "Read_File"


def test_selector_multi_pattern_and_semantics() -> None:
    """All tool patterns in requires.tools must be satisfied."""
    from mcp_striker.dsl.schema import FlowModule
    module = FlowModule.model_validate({
        "version": "1", "name": "test",
        "requires": {"tools": ["read_file", "fetch|http_get"]},
        "steps": [{"id": "s", "type": "setup", "method": "tools/list", "params": {}}],
    })
    # Only has read_file — missing fetch → should be skipped
    registry = _registry_with_tools("read_file")
    selected, skipped = selector.select_with_report([module], registry)
    assert module not in selected


# ---------------------------------------------------------------------------
# matched_tool system variable in FlowContext
# ---------------------------------------------------------------------------


def test_matched_tool_resolves_in_params() -> None:
    ctx = FlowContext()
    ctx.set(MATCHED_TOOL_VAR, "read_file")
    result = ctx.resolve_params({"name": "${matched_tool}", "arguments": {"path": "/x"}})
    assert result == [{"name": "read_file", "arguments": {"path": "/x"}}]


# ---------------------------------------------------------------------------
# get_text_content — tool response format
# ---------------------------------------------------------------------------


def test_get_text_content_handles_tool_response() -> None:
    """tools/call returns 'content' not 'contents'."""
    resp = JsonRpcResponse(
        jsonrpc="2.0", id=1,
        result={"content": [{"type": "text", "text": "root:x:0:0:root:/root:/bin/bash"}]},
    )
    assert "root:x:0:0" in resp.get_text_content()


def test_get_text_content_handles_resource_response() -> None:
    """resources/read returns 'contents' — existing behaviour unchanged."""
    resp = JsonRpcResponse(
        jsonrpc="2.0", id=1,
        result={"contents": [{"uri": "file:///etc/passwd", "text": "root:x:0:0"}]},
    )
    assert "root:x:0:0" in resp.get_text_content()


# ---------------------------------------------------------------------------
# Real YAML modules load and validate
# ---------------------------------------------------------------------------


def test_tool_path_traversal_module_loads() -> None:
    if not (MODULES_DIR / "basic/tools/tool_path_traversal.yaml").exists():
        pytest.skip("modules/ not found")
    module = parser.load(MODULES_DIR / "basic/tools/tool_path_traversal.yaml")
    assert module.name == "tool-path-traversal"
    assert module.requires.tools


def test_tool_ssrf_module_loads() -> None:
    if not (MODULES_DIR / "basic/tools/tool_ssrf.yaml").exists():
        pytest.skip("modules/ not found")
    module = parser.load(MODULES_DIR / "basic/tools/tool_ssrf.yaml")
    assert module.name == "tool-ssrf"


def test_tool_command_injection_module_loads() -> None:
    if not (MODULES_DIR / "basic/tools/tool_command_injection.yaml").exists():
        pytest.skip("modules/ not found")
    module = parser.load(MODULES_DIR / "basic/tools/tool_command_injection.yaml")
    assert module.name == "tool-command-injection"


# ---------------------------------------------------------------------------
# matched_param_for — parameter schema matching
# ---------------------------------------------------------------------------


def _registry_with_tool_schema(tool_name: str, properties: dict) -> CapabilityRegistry:
    return CapabilityRegistry(
        server_name="test", server_version="0.1",
        protocol_version="2025-03-26",
        server_capabilities=["tools"],
        tools=[McpTool(
            name=tool_name,
            input_schema={"type": "object", "properties": properties},
        )],
    )


def test_matched_param_finds_path_parameter() -> None:
    from mcp_striker.dsl.schema import FlowModule
    module = FlowModule.model_validate({
        "version": "1", "name": "test",
        "requires": {
            "tools": ["read_file"],
            "inject_into": "path|file|filename",
        },
        "steps": [{"id": "s", "type": "setup", "method": "tools/list", "params": {}}],
    })
    registry = _registry_with_tool_schema("read_file", {
        "path": {"type": "string", "description": "File path"},
        "encoding": {"type": "string"},
    })
    param = selector.matched_param_for(module, registry)
    assert param == "path"


def test_matched_param_finds_file_path_parameter() -> None:
    from mcp_striker.dsl.schema import FlowModule
    module = FlowModule.model_validate({
        "version": "1", "name": "test",
        "requires": {
            "tools": ["read_file"],
            "inject_into": "path|file|filename|file_path",
        },
        "steps": [{"id": "s", "type": "setup", "method": "tools/list", "params": {}}],
    })
    registry = _registry_with_tool_schema("read_file", {
        "file_path": {"type": "string"},
        "mode": {"type": "string"},
    })
    param = selector.matched_param_for(module, registry)
    assert param == "file_path"


def test_matched_param_case_insensitive() -> None:
    from mcp_striker.dsl.schema import FlowModule
    module = FlowModule.model_validate({
        "version": "1", "name": "test",
        "requires": {
            "tools": ["read_file"],
            "inject_into": "path",
        },
        "steps": [{"id": "s", "type": "setup", "method": "tools/list", "params": {}}],
    })
    registry = _registry_with_tool_schema("read_file", {
        "Path": {"type": "string"},
    })
    param = selector.matched_param_for(module, registry)
    assert param == "Path"


def test_matched_param_empty_when_no_inject_into() -> None:
    from mcp_striker.dsl.schema import FlowModule
    module = FlowModule.model_validate({
        "version": "1", "name": "test",
        "requires": {"tools": ["read_file"]},
        "steps": [{"id": "s", "type": "setup", "method": "tools/list", "params": {}}],
    })
    registry = _registry_with_tool_schema("read_file", {"path": {"type": "string"}})
    param = selector.matched_param_for(module, registry)
    assert param == ""


def test_matched_param_empty_when_no_matching_property() -> None:
    from mcp_striker.dsl.schema import FlowModule
    module = FlowModule.model_validate({
        "version": "1", "name": "test",
        "requires": {
            "tools": ["read_file"],
            "inject_into": "path|file",
        },
        "steps": [{"id": "s", "type": "setup", "method": "tools/list", "params": {}}],
    })
    registry = _registry_with_tool_schema("read_file", {
        "content": {"type": "string"},
        "encoding": {"type": "string"},
    })
    param = selector.matched_param_for(module, registry)
    assert param == ""


def test_matched_param_resolves_in_flow_context() -> None:
    """${matched_param} resolves correctly as an argument key in params."""
    from mcp_striker.dsl.context import MATCHED_PARAM_VAR, FlowContext
    ctx = FlowContext()
    ctx.set("matched_tool", "read_file_tool")
    ctx.set(MATCHED_PARAM_VAR, "file_path")
    ctx.set("payload", "/etc/passwd")   # payload must be set for resolve_params
    result = ctx.resolve_params({
        "name": "${matched_tool}",
        "arguments": {"${matched_param}": "${payload}"},
    })
    # After substitution: {"name": "read_file_tool", "arguments": {"file_path": "/etc/passwd"}}
    assert result[0]["name"] == "read_file_tool"
    assert "${matched_param}" not in str(result[0])
    assert result[0]["arguments"]["file_path"] == "/etc/passwd"
