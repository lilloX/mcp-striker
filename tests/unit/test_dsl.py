"""Unit tests for Milestone 4 — Flow-Based Attack DSL."""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_striker.dsl.context import FlowContext, _collect_var_names, _substitute_all
from mcp_striker.dsl.parser import FlowParseError, YAMLFlowParser
from mcp_striker.dsl.schema import FlowModule, MatcherSpec, RequiresSpec, StepSpec
from mcp_striker.dsl.selector import ModuleSelector
from mcp_striker.registry import CapabilityRegistry, McpResource, McpResourceTemplate

FLOWS_DIR = Path(__file__).parent.parent / "fixtures" / "flows"
parser = YAMLFlowParser()


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def test_valid_path_traversal_yaml_loads() -> None:
    module = parser.load(FLOWS_DIR / "valid_path_traversal.yaml")
    assert module.name == "test-path-traversal"
    assert len(module.steps) == 1
    assert module.steps[0].type == "mutate"
    assert len(module.steps[0].payloads) == 2


def test_valid_multi_step_yaml_loads() -> None:
    module = parser.load(FLOWS_DIR / "valid_multi_step.yaml")
    assert len(module.steps) == 3
    assert module.steps[0].type == "setup"
    assert module.steps[1].type == "mutate"
    assert module.steps[2].type == "cleanup"
    assert module.steps[2].optional is True


def test_empty_payloads_scaffold_is_valid() -> None:
    """A scaffold-generated module with empty payloads must parse without errors.
    The FlowEngine will silently skip mutate steps with no payloads.
    """
    module = parser.load(FLOWS_DIR / "invalid_missing_payloads.yaml")
    # Empty payloads → step is valid, engine skips it at runtime
    assert module.steps[0].payloads == []


def test_missing_file_raises() -> None:
    with pytest.raises(FlowParseError, match="not found"):
        parser.load(Path("/nonexistent/flow.yaml"))


def test_duplicate_step_ids_raises() -> None:
    raw = {
        "version": "1",
        "name": "test",
        "steps": [
            {"id": "probe", "type": "mutate", "method": "resources/read",
             "params": {"uri": "${payload}"}, "payloads": ["x"],
             "matchers": [{"type": "jsonrpc_success"},
                          {"type": "regex", "pattern": "x"}]},
            {"id": "probe", "type": "setup", "method": "resources/list", "params": {}},
        ],
    }
    with pytest.raises(Exception, match="duplicate step ids"):
        FlowModule.model_validate(raw)


def test_jsonrpc_success_only_mutate_step_rejected() -> None:
    """A mutate step whose only matcher is jsonrpc_success has no content
    evidence and must be rejected at parse time."""
    raw = {
        "version": "1", "name": "t",
        "steps": [
            {"id": "p", "type": "mutate", "method": "tools/call",
             "params": {"x": "${payload}"}, "payloads": ["a"],
             "matchers": [{"type": "jsonrpc_success"}]},
        ],
    }
    with pytest.raises(Exception, match="only a 'jsonrpc_success'"):
        FlowModule.model_validate(raw)


def test_jsonrpc_success_plus_content_matcher_ok() -> None:
    """jsonrpc_success combined with a content matcher is valid."""
    raw = {
        "version": "1", "name": "t",
        "steps": [
            {"id": "p", "type": "mutate", "method": "tools/call",
             "params": {"x": "${payload}"}, "payloads": ["a"],
             "matchers": [{"type": "jsonrpc_success"},
                          {"type": "regex", "pattern": "x"}]},
        ],
    }
    module = FlowModule.model_validate(raw)
    assert len(module.steps) == 1


def test_matchers_on_setup_step_raises() -> None:
    with pytest.raises(Exception, match="matchers"):
        StepSpec(
            id="s",
            type="setup",
            method="resources/list",
            matchers=[MatcherSpec(type="jsonrpc_success")],
        )


def test_payloads_on_setup_step_raises() -> None:
    with pytest.raises(Exception, match="payloads"):
        StepSpec(id="s", type="setup", method="resources/list", payloads=["x"])


def test_regex_matcher_requires_pattern() -> None:
    with pytest.raises(Exception, match="pattern"):
        MatcherSpec(type="regex")


def test_http_status_matcher_requires_code() -> None:
    with pytest.raises(Exception, match="code"):
        MatcherSpec(type="http_status")


# ---------------------------------------------------------------------------
# FlowContext — variable resolution
# ---------------------------------------------------------------------------


def test_context_scalar_resolve() -> None:
    ctx = FlowContext()
    ctx.set("target", "file:///etc/passwd")
    result = ctx.resolve_params({"uri": "${target}"})
    assert result == [{"uri": "file:///etc/passwd"}]


def test_context_list_expand() -> None:
    ctx = FlowContext()
    ctx.set("uris", ["file:///a", "file:///b"])
    result = ctx.resolve_params({"uri": "${uris}"})
    assert result == [{"uri": "file:///a"}, {"uri": "file:///b"}]


def test_context_cartesian_product() -> None:
    ctx = FlowContext()
    ctx.set("uris", ["a", "b"])
    ctx.set("payload", ["x", "y"])
    result = ctx.resolve_params({"uri": "${uris}/${payload}"})
    assert len(result) == 4
    uris = {r["uri"] for r in result}
    assert uris == {"a/x", "a/y", "b/x", "b/y"}


def test_context_payload_variable() -> None:
    """${payload} is treated like any other variable."""
    ctx = FlowContext()
    ctx.set("payload", "../../../etc/passwd")
    result = ctx.resolve_params({"uri": "file://${payload}"})
    assert result == [{"uri": "file://../../../etc/passwd"}]


def test_context_undefined_variable_raises() -> None:
    ctx = FlowContext()
    with pytest.raises(KeyError):
        ctx.resolve_params({"uri": "${undefined_var}"})


def test_context_nested_params() -> None:
    """Variable substitution works in nested dict params."""
    ctx = FlowContext()
    ctx.set("token", "abc123")
    result = ctx.resolve_params({"headers": {"Authorization": "Bearer ${token}"}})
    assert result == [{"headers": {"Authorization": "Bearer abc123"}}]


def test_collect_var_names() -> None:
    names = _collect_var_names({"uri": "${uris}/${payload}", "x": "static"})
    assert names == {"uris", "payload"}


def test_substitute_all_scalar() -> None:
    result = _substitute_all({"uri": "${path}"}, {"path": "/etc/passwd"})
    assert result == {"uri": "/etc/passwd"}


def test_substitute_all_preserves_unresolved() -> None:
    """Unknown variables are left as-is in the output."""
    result = _substitute_all("${known}/${unknown}", {"known": "val"})
    assert result == "val/${unknown}"


# ---------------------------------------------------------------------------
# YAMLFlowParser — compiler
# ---------------------------------------------------------------------------


def test_compile_matchers_returns_callable_matchers() -> None:
    module = parser.load(FLOWS_DIR / "valid_path_traversal.yaml")
    compiled = parser.compile_matchers(module)
    assert "probe" in compiled
    matchers = compiled["probe"]
    assert len(matchers) == 2
    assert matchers[0].name == "jsonrpc_success"
    assert matchers[1].name.startswith("regex:")


def test_compile_matchers_empty_for_setup_steps() -> None:
    module = parser.load(FLOWS_DIR / "valid_multi_step.yaml")
    compiled = parser.compile_matchers(module)
    # Only 'read' (mutate) step has matchers; 'list' (setup) and 'done' (cleanup) do not.
    assert "list" not in compiled
    assert "done" not in compiled
    assert "read" in compiled


def test_load_directory(tmp_path: Path) -> None:
    """load_directory loads all parseable modules including scaffold files."""
    import shutil
    shutil.copy(FLOWS_DIR / "valid_path_traversal.yaml", tmp_path / "valid.yaml")
    # invalid_missing_payloads.yaml now parses as valid (empty payloads = skip at runtime)
    shutil.copy(FLOWS_DIR / "invalid_missing_payloads.yaml", tmp_path / "scaffold.yaml")
    modules = parser.load_directory(tmp_path)
    assert len(modules) == 2
    names = {m.name for m in modules}
    assert "test-path-traversal" in names
    assert "invalid-missing-payloads" in names


# ---------------------------------------------------------------------------
# ModuleSelector
# ---------------------------------------------------------------------------


def _make_registry(
    has_resources: bool = True,
    templates: list[str] | None = None,
) -> CapabilityRegistry:
    return CapabilityRegistry(
        server_name="test",
        server_version="0.1",
        protocol_version="2025-03-26",
        resources=[McpResource(uri="file:///x", name="x")] if has_resources else [],
        resource_templates=[
            McpResourceTemplate(uri_template=t, name=t)
            for t in (templates or [])
        ],
    )


selector = ModuleSelector()


def test_selector_accepts_module_with_matching_capability() -> None:
    module = parser.load(FLOWS_DIR / "valid_path_traversal.yaml")
    # Provide a registry with both resources and a file:// template.
    registry = _make_registry(has_resources=True, templates=["file://{path}"])
    selected = selector.select([module], registry)
    assert module in selected


def test_selector_skips_module_when_no_resources() -> None:
    module = parser.load(FLOWS_DIR / "valid_path_traversal.yaml")
    registry = _make_registry(has_resources=False)
    selected, skipped = selector.select_with_report([module], registry)
    assert module not in selected
    assert any(m is module for m, _ in skipped)


def test_selector_skips_module_when_template_pattern_not_matched() -> None:
    """Module requiring file:// template is skipped if server has no file:// templates."""
    module = parser.load(FLOWS_DIR / "valid_path_traversal.yaml")
    # valid_path_traversal requires resource_templates matching "file://"
    registry = _make_registry(has_resources=True, templates=["resource://{id}"])
    selected, skipped = selector.select_with_report([module], registry)
    assert module not in selected


def test_selector_accepts_when_template_pattern_matched() -> None:
    module = parser.load(FLOWS_DIR / "valid_path_traversal.yaml")
    registry = _make_registry(has_resources=True, templates=["file://{path}"])
    selected = selector.select([module], registry)
    assert module in selected


def test_selector_module_without_requirements_always_selected() -> None:
    """A module with no requires block is always applicable."""
    module = parser.load(FLOWS_DIR / "valid_multi_step.yaml")
    # valid_multi_step has no resource_templates requirement
    registry = _make_registry(has_resources=True, templates=[])
    selected = selector.select([module], registry)
    assert module in selected


# ---------------------------------------------------------------------------
# FlowEngine dry_run parameter — unit-level verification
# ---------------------------------------------------------------------------


def test_flow_engine_accepts_dry_run_parameter() -> None:
    """FlowEngine can be constructed with dry_run=True without error."""
    import asyncio
    from unittest.mock import MagicMock
    from mcp_striker.engine.flow import FlowEngine
    from mcp_striker.models import SafetyContext, TransportContext

    engine = FlowEngine(
        transport=MagicMock(),
        registry=MagicMock(),
        recorder=MagicMock(),
        evidence_generator=MagicMock(),
        safety_engine=MagicMock(),
        safety_context=SafetyContext(),
        transport_context=TransportContext(session_id="test", target_cmd=""),
        semaphore=asyncio.Semaphore(1),
        dry_run=True,
    )
    assert engine._dry_run is True
    assert engine._probe_counter == 0


def _safety_engine(transport, recorder):  # type: ignore[no-untyped-def]
    import asyncio
    from unittest.mock import MagicMock
    from mcp_striker.engine.flow import FlowEngine
    from mcp_striker.models import SafetyContext, TransportContext
    from mcp_striker.safety import SafetyPolicyEngine

    return FlowEngine(
        transport=transport,
        registry=MagicMock(),
        recorder=recorder,
        evidence_generator=MagicMock(),
        safety_engine=SafetyPolicyEngine(),
        safety_context=SafetyContext(),  # allow_mutating defaults to False
        transport_context=TransportContext(session_id="t"),
        semaphore=asyncio.Semaphore(1),
    )


def test_setup_step_tools_call_blocked_by_safety() -> None:
    """A setup step invoking a mutating tools/call must be blocked (never sent)
    without --allow-mutating."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock
    from mcp_striker.dsl.context import FlowContext

    transport = MagicMock()
    transport.send = AsyncMock()
    recorder = MagicMock()
    recorder.record = AsyncMock()
    engine = _safety_engine(transport, recorder)

    step = StepSpec(id="s", type="setup", method="tools/call",
                    params={"name": "delete_everything"})
    asyncio.run(engine._run_setup_step(step, FlowContext()))

    transport.send.assert_not_called()       # blocked before sending
    recorder.record.assert_awaited()         # a blocked exchange was recorded


def test_cleanup_step_tools_call_blocked_by_safety() -> None:
    """A cleanup step invoking a mutating tools/call must be blocked too."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    transport = MagicMock()
    transport.send = AsyncMock()
    recorder = MagicMock()
    recorder.record = AsyncMock()
    engine = _safety_engine(transport, recorder)

    step = StepSpec(id="c", type="cleanup", method="tools/call",
                    params={"name": "wipe"})
    asyncio.run(engine._run_cleanup_step(step))

    transport.send.assert_not_called()


def test_cleanup_exchange_is_recorded() -> None:
    """A cleanup that actually runs must be recorded in the transcript (R#11)."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock
    from mcp_striker.models import JsonRpcRequest, TransportExchange

    exchange = TransportExchange(request=JsonRpcRequest(id=1, method="tools/list"))
    transport = MagicMock()
    transport.send = AsyncMock(return_value=exchange)
    recorder = MagicMock()
    recorder.record = AsyncMock()
    engine = _safety_engine(transport, recorder)

    step = StepSpec(id="c", type="cleanup", method="tools/list", params={})
    asyncio.run(engine._run_cleanup_step(step))

    transport.send.assert_awaited()   # allowlisted method is sent
    recorder.record.assert_awaited()  # and the exchange is recorded


def test_matcher_exception_counts_as_failure() -> None:
    """A matcher that raises must not vanish: it is counted as a failure and
    recorded, so the run is not silently reported clean (R#5)."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    from mcp_striker.models import JsonRpcRequest, JsonRpcResponse, TransportExchange
    from mcp_striker.modules.resource_path_traversal import Matcher

    exchange = TransportExchange(
        request=JsonRpcRequest(id=1, method="tools/list"),
        response=JsonRpcResponse(jsonrpc="2.0", id=1, result={"ok": 1}),
    )
    transport = MagicMock()
    transport.send = AsyncMock(return_value=exchange)
    recorder = MagicMock()
    recorder.record = AsyncMock()
    engine = _safety_engine(transport, recorder)

    def boom(_ex: object) -> bool:
        raise RuntimeError("matcher boom")

    matcher = Matcher(name="boom", fn=boom)
    result = asyncio.run(
        engine._run_single_probe(
            method="tools/list", params={}, matchers=[matcher], module_name="m"
        )
    )
    assert result is None
    assert engine.failures == 1


def test_returned_probe_failed_counts_as_failure() -> None:
    """A transport that REPORTS a failure by returning probe_failed=True (timeout,
    parse error, oversized response, HTTP failure) — instead of raising — must
    still increment failures, so a run drowned in such failures is not clean (#2)."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock

    from mcp_striker.models import JsonRpcRequest, TransportExchange

    exchange = TransportExchange(
        request=JsonRpcRequest(id=1, method="resources/list"),
        probe_failed=True,
        failure_reason="transport timeout",
    )
    transport = MagicMock()
    transport.send = AsyncMock(return_value=exchange)
    recorder = MagicMock()
    recorder.record = AsyncMock()
    engine = _safety_engine(transport, recorder)

    result = asyncio.run(
        engine._run_single_probe(
            method="resources/list", params={}, matchers=[], module_name="m"
        )
    )
    assert result is None
    assert engine.failures == 1


def test_setup_step_allowlisted_method_is_sent() -> None:
    """An allowlisted read method (resources/list) still goes out."""
    import asyncio
    from unittest.mock import AsyncMock, MagicMock
    from mcp_striker.dsl.context import FlowContext
    from mcp_striker.models import JsonRpcRequest, TransportExchange

    exchange = TransportExchange(
        request=JsonRpcRequest(id=1, method="resources/list"),
        probe_failed=True,  # no response → setup returns after recording
    )
    transport = MagicMock()
    transport.send = AsyncMock(return_value=exchange)
    recorder = MagicMock()
    recorder.record = AsyncMock()
    engine = _safety_engine(transport, recorder)

    step = StepSpec(id="ok", type="setup", method="resources/list", params={})
    asyncio.run(engine._run_setup_step(step, FlowContext()))

    transport.send.assert_awaited()          # allowlisted method IS sent
