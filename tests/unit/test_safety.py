"""Unit tests for mcp_striker/safety.py."""

from __future__ import annotations

import pytest

from mcp_striker.models import JsonRpcRequest, SafetyContext, SafetyVerdict
from mcp_striker.safety import SafetyPolicyEngine


@pytest.fixture()
def engine() -> SafetyPolicyEngine:
    return SafetyPolicyEngine()


@pytest.fixture()
def strict_ctx() -> SafetyContext:
    return SafetyContext(allow_mutating=False)


@pytest.fixture()
def permissive_ctx() -> SafetyContext:
    return SafetyContext(allow_mutating=True)


def test_runtime_classifies_tools_call_using_registry_description(
    strict_ctx: SafetyContext,
) -> None:
    """A benignly-named tool whose enumerated description reveals mutation must
    be BLOCKED at call time without --allow-mutating (runtime must use the same
    description that `enum` classifies with)."""
    engine = SafetyPolicyEngine(
        tool_descriptions={
            "read_records": "Reads then permanently deletes the records.",
        }
    )
    request = JsonRpcRequest(id=1, method="tools/call", params={"name": "read_records"})
    decision = engine.evaluate_request(request, strict_ctx)
    assert decision.verdict == SafetyVerdict.BLOCKED


# ---------------------------------------------------------------------------
# Read-only allowlist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method",
    [
        "initialize",
        "notifications/initialized",
        "resources/list",
        "resources/read",
        "tools/list",
        "prompts/list",
    ],
)
def test_allowlisted_methods_are_always_allowed(
    engine: SafetyPolicyEngine,
    strict_ctx: SafetyContext,
    method: str,
) -> None:
    request = JsonRpcRequest(id=1, method=method)
    decision = engine.evaluate_request(request, strict_ctx)
    assert decision.verdict == SafetyVerdict.ALLOWED


# ---------------------------------------------------------------------------
# Blocked by default
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "method",
    ["tools/call", "resources/create", "resources/delete", "prompts/run"],
)
def test_mutating_methods_blocked_without_flag(
    engine: SafetyPolicyEngine,
    strict_ctx: SafetyContext,
    method: str,
) -> None:
    request = JsonRpcRequest(id=1, method=method)
    decision = engine.evaluate_request(request, strict_ctx)
    assert decision.verdict == SafetyVerdict.BLOCKED
    assert "--allow-mutating" in decision.reason


# ---------------------------------------------------------------------------
# --allow-mutating override
# ---------------------------------------------------------------------------


def test_mutating_method_allowed_with_flag(
    engine: SafetyPolicyEngine,
    permissive_ctx: SafetyContext,
) -> None:
    request = JsonRpcRequest(id=1, method="tools/call")
    decision = engine.evaluate_request(request, permissive_ctx)
    assert decision.verdict == SafetyVerdict.ALLOWED
