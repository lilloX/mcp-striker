"""StrikeEngine — the dumb orchestrator.

Responsibilities:
    1. Iterate over every (resource template × probe) combination.
    2. Substitute the probe payload into the URI template.
    3. Ask ``SafetyPolicyEngine`` for permission.
    4. Send via transport (if allowed) or record a blocked exchange.
    5. Ask the probe itself whether it matched (``probe.matches(exchange)``).
    6. On a match, delegate to ``EvidenceGenerator``.

The engine knows **nothing** about regex patterns, JSON-RPC error codes, or
the content of any payload.  All of that logic lives in the probe objects.
"""

from __future__ import annotations

import asyncio
import re
import sys

from mcp_striker.evidence import EvidenceGenerator
from mcp_striker.models import (
    JsonRpcRequest,
    SafetyContext,
    SafetyVerdict,
    TransportContext,
    TransportExchange,
)
from mcp_striker.modules.resource_path_traversal import PROBES, PathTraversalProbe
from mcp_striker.recorder import SessionRecorder
from mcp_striker.registry import CapabilityRegistry, McpResourceTemplate
from mcp_striker.safety import SafetyPolicyEngine
from mcp_striker.transport.base import McpTransport


def _substitute(uri_template: str, payload: str) -> str:
    """Replace every ``{variable}`` placeholder in *uri_template* with *payload*."""
    return re.sub(r"\{[^}]+\}", lambda m: payload, uri_template)


class StrikeEngine:
    """Executes path traversal probes against a ``CapabilityRegistry``."""

    # IDs for probe requests start high to avoid collisions with the
    # protocol-level IDs used by ProtocolClient (1, 2, 3 …).
    _BASE_ID = 1000

    def __init__(
        self,
        transport: McpTransport,
        registry: CapabilityRegistry,
        recorder: SessionRecorder,
        evidence_generator: EvidenceGenerator,
        safety_engine: SafetyPolicyEngine,
        safety_context: SafetyContext,
        transport_context: TransportContext,
        concurrency: int = 5,
    ) -> None:
        self._transport: McpTransport = transport
        self._registry = registry
        self._recorder = recorder
        self._evidence = evidence_generator
        self._safety = safety_engine
        self._safety_ctx = safety_context
        self._transport_ctx = transport_context
        self._semaphore = asyncio.Semaphore(concurrency)
        self._request_id = self._BASE_ID
        # Probes that crashed unexpectedly. Non-zero → run is inconclusive.
        self.failures = 0

    def _next_id(self) -> int:
        # Atomically safe in asyncio (no await between read and increment).
        self._request_id += 1
        return self._request_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> list[str]:
        """Run all probes concurrently and return the list of finding IDs."""
        tasks: list[asyncio.Task[str | None]] = [
            asyncio.create_task(self._run_probe(template, probe))
            for template in self._registry.resource_templates
            for probe in PROBES
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        finding_ids: list[str] = []
        errors = 0
        for result in results:
            if isinstance(result, str):
                finding_ids.append(result)
            elif isinstance(result, Exception):
                # A probe crashed unexpectedly. Never crash the session, but do
                # not swallow it silently — surface the count so a broken scan is
                # not mistaken for a clean result.
                errors += 1
        if errors:
            self.failures += errors
            print(
                f"[!] {errors} probe(s) raised an unexpected error and were skipped",
                file=sys.stderr,
            )
        return finding_ids

    # ------------------------------------------------------------------
    # Per-probe execution
    # ------------------------------------------------------------------

    async def _run_probe(
        self,
        template: McpResourceTemplate,
        probe: PathTraversalProbe,
    ) -> str | None:
        uri = _substitute(template.uri_template, probe.payload)
        request = JsonRpcRequest(
            id=self._next_id(),
            method="resources/read",
            params={"uri": uri},
        )
        safety_decision = self._safety.evaluate_request(request, self._safety_ctx)

        async with self._semaphore:
            if safety_decision.verdict == SafetyVerdict.BLOCKED:
                exchange = TransportExchange(
                    request=request,
                    safety_decision=safety_decision,
                    probe_failed=True,
                    failure_reason=f"blocked: {safety_decision.reason}",
                )
                await self._recorder.record(exchange)
                return None

            try:
                exchange = await self._transport.send(request, self._transport_ctx)
            except Exception as exc:
                self.failures += 1
                exchange = TransportExchange(
                    request=request,
                    safety_decision=safety_decision,
                    probe_failed=True,
                    failure_reason=f"transport error: {exc}",
                )
                await self._recorder.record(exchange)
                return None

        # A transport that reports timeouts, parse errors, oversized responses or
        # HTTP failures returns probe_failed=True instead of raising. Count it too
        # so a run drowned in such failures is never mistaken for a clean result.
        # Safety-BLOCKED exchanges are handled above and never reach here.
        if exchange.probe_failed:
            self.failures += 1

        # Attach the safety decision to the recorded exchange.
        exchange = exchange.model_copy(update={"safety_decision": safety_decision})
        await self._recorder.record(exchange)

        if probe.matches(exchange):
            finding_id = await self._evidence.promote(
                exchange=exchange,
                matchers_hit=probe.matchers_hit(exchange),
                module="resource-path-traversal",
                transport=self._transport_ctx.transport_type,
                protocol_version=self._registry.protocol_version,
                severity="high",
                session_id=self._transport_ctx.session_id,
            )
            return finding_id

        return None
