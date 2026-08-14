"""StrikeEngine failure-counting regressions (#2).

A transport reports timeouts, parse errors, oversized responses and HTTP
failures by RETURNING ``TransportExchange(probe_failed=True)`` rather than
raising. Those returned failures must increment the engine failure counter so a
run drowned in them is never mistaken for a clean result.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

from mcp_striker.engine.strike import StrikeEngine
from mcp_striker.models import (
    JsonRpcRequest,
    SafetyContext,
    TransportContext,
    TransportExchange,
)
from mcp_striker.registry import CapabilityRegistry, McpResourceTemplate
from mcp_striker.safety import SafetyPolicyEngine


def _engine(transport: MagicMock) -> StrikeEngine:
    registry = CapabilityRegistry(
        server_name="s",
        server_version="0.1",
        protocol_version="2025-03-26",
        server_capabilities=["resources"],
        resource_templates=[McpResourceTemplate(uri_template="file://{path}", name="f")],
    )
    recorder = MagicMock(record=AsyncMock())
    return StrikeEngine(
        transport=transport,
        registry=registry,
        recorder=recorder,
        evidence_generator=MagicMock(),
        safety_engine=SafetyPolicyEngine(),
        safety_context=SafetyContext(),
        transport_context=TransportContext(session_id="t"),
    )


def test_returned_probe_failed_counts_as_failure() -> None:
    """send() returning probe_failed=True (no exception) increments failures."""
    exchange = TransportExchange(
        request=JsonRpcRequest(id=1, method="resources/read", params={"uri": "x"}),
        probe_failed=True,
        failure_reason="transport timeout",
    )
    transport = MagicMock(send=AsyncMock(return_value=exchange))
    engine = _engine(transport)

    template = engine._registry.resource_templates[0]
    from mcp_striker.engine.strike import PROBES

    result = asyncio.run(engine._run_probe(template, PROBES[0]))

    assert result is None
    assert engine.failures == 1


def test_raised_transport_error_counts_as_failure() -> None:
    """send() raising also increments failures (caught, recorded, counted)."""
    transport = MagicMock(send=AsyncMock(side_effect=RuntimeError("boom")))
    engine = _engine(transport)

    template = engine._registry.resource_templates[0]
    from mcp_striker.engine.strike import PROBES

    result = asyncio.run(engine._run_probe(template, PROBES[0]))

    assert result is None
    assert engine.failures == 1
