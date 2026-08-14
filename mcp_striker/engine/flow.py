"""FlowEngine — executes YAML flow modules.

Execution model
---------------
Steps run **sequentially** within a flow: setup → mutate → cleanup.
State (extracted variables) flows forward through a ``FlowContext``.

Within a **mutate** step, all (param_set × payload) combinations run
**concurrently** using the ``asyncio.Semaphore`` passed at construction.
This mirrors the StrikeEngine concurrency model.

Multiple flows from ``--modules-dir`` also run sequentially — one complete
flow before the next — so findings are grouped by module in the output.

JSONPath extraction
-------------------
Variables are extracted using ``jsonpath-ng``.  The response is converted
with ``model_dump(mode='json')`` (Pydantic v2 native, no JSON round-trip)
before being passed to the JSONPath engine.

``${payload}`` variable
-----------------------
Before resolving params for a mutate step, ``FlowEngine`` populates the
``payload`` variable in the context with the current payload string.
``FlowContext.resolve_params`` treats it like any other variable.

Dry-run mode
------------
When ``dry_run=True`` is passed at construction, the engine executes all
probes normally (requests are sent, responses received, session is recorded)
but matchers are only *evaluated* — no finding artifacts are written to disk.
Each probe's request and response are printed to stdout in compact JSON form,
with a per-matcher WOULD MATCH / would NOT match indication.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from jsonpath_ng import parse as jp_parse

from mcp_striker.dsl.context import FlowContext
from mcp_striker.dsl.parser import YAMLFlowParser
from mcp_striker.dsl.schema import FlowModule, StepSpec
from mcp_striker.dsl.context import MATCHED_PARAM_VAR, MATCHED_TOOL_VAR
from mcp_striker.dsl.selector import ModuleSelector
from mcp_striker.evidence import EvidenceGenerator
from mcp_striker.models import (
    JsonRpcRequest,
    SafetyContext,
    SafetyVerdict,
    TransportContext,
    TransportExchange,
)
from mcp_striker.modules.resource_path_traversal import Matcher
from mcp_striker.recorder import SessionRecorder
from mcp_striker.registry import CapabilityRegistry
from mcp_striker.safety import SafetyPolicyEngine
from mcp_striker.transport.base import McpTransport
from mcp_striker.types import JsonValue

_BASE_REQUEST_ID = 2000


_DRY_RUN_RES_MAX = 300  # max chars for response preview in dry-run output


class FlowEngine:
    """Executes one or more ``FlowModule`` objects against a target server."""

    def __init__(
        self,
        transport: McpTransport,
        registry: CapabilityRegistry,
        recorder: SessionRecorder,
        evidence_generator: EvidenceGenerator,
        safety_engine: SafetyPolicyEngine,
        safety_context: SafetyContext,
        transport_context: TransportContext,
        semaphore: asyncio.Semaphore,
        dry_run: bool = False,
    ) -> None:
        self._transport = transport
        self._registry = registry
        self._recorder = recorder
        self._evidence = evidence_generator
        self._safety = safety_engine
        self._safety_ctx = safety_context
        self._transport_ctx = transport_context
        self._transport_label = transport_context.transport_type
        self._semaphore = semaphore
        self._dry_run = dry_run
        # Count of probes that failed to complete (transport error, matcher or
        # evidence-write exception). Non-zero means the run is inconclusive.
        self.failures = 0
        self._request_id = _BASE_REQUEST_ID
        self._probe_counter = 0
        self._probe_lock = asyncio.Lock()
        self._parser = YAMLFlowParser()
        self._selector = ModuleSelector()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_module(self, module: FlowModule) -> list[str]:
        """Execute a single flow module and return confirmed finding IDs."""
        compiled_matchers = self._parser.compile_matchers(module)
        context = FlowContext()
        finding_ids: list[str] = []
        # Expose module severity to _run_single_probe via instance state.
        self._current_severity: str = module.severity

        # Populate ${matched_tool} so YAML modules can reference the tool name.
        matched = self._selector.matched_tool_for(module, self._registry)
        if matched:
            context.set(MATCHED_TOOL_VAR, matched)

        # Populate ${matched_param} so YAML modules can reference the
        # injectable parameter name without hardcoding it.
        matched_param = self._selector.matched_param_for(module, self._registry)
        if matched_param:
            context.set(MATCHED_PARAM_VAR, matched_param)

        for step in module.steps:
            step_matchers = compiled_matchers.get(step.id, [])
            ids = await self._run_step(step, step_matchers, context, module.name)
            finding_ids.extend(ids)

        return finding_ids

    async def run_modules(self, modules: list[FlowModule]) -> list[str]:
        """Execute multiple modules sequentially and return all finding IDs."""
        finding_ids: list[str] = []
        for module in modules:
            ids = await self.run_module(module)
            finding_ids.extend(ids)
        return finding_ids

    @classmethod
    def load_and_select(
        cls,
        paths: list[Path],
        registry: CapabilityRegistry,
    ) -> tuple[list[FlowModule], list[tuple[FlowModule, str]]]:
        """Load modules from *paths*, select applicable ones, return (selected, skipped)."""
        parser = YAMLFlowParser()
        selector = ModuleSelector()
        modules = [parser.load(p) for p in paths]
        return selector.select_with_report(modules, registry)

    # ------------------------------------------------------------------
    # Step dispatch
    # ------------------------------------------------------------------

    async def _run_step(
        self,
        step: StepSpec,
        matchers: list[Matcher],
        context: FlowContext,
        module_name: str,
    ) -> list[str]:
        if step.type in ("setup", "extract"):
            await self._run_setup_step(step, context)
            return []
        if step.type == "mutate":
            return await self._run_mutate_step(step, matchers, context, module_name)
        if step.type == "cleanup":
            await self._run_cleanup_step(step)
            return []
        return []

    # ------------------------------------------------------------------
    # Safety-checked send (single choke point for setup/extract/cleanup)
    # ------------------------------------------------------------------

    async def _send_checked(
        self, request: JsonRpcRequest
    ) -> TransportExchange | None:
        """Evaluate the SafetyPolicy, then send. Returns ``None`` (and records a
        blocked exchange) when the policy blocks the request — so a setup,
        extract, or cleanup step cannot invoke ``tools/call`` or any other
        non-allowlisted method without ``--allow-mutating``. On a successful
        send, the returned exchange carries the safety decision.
        """
        safety_decision = self._safety.evaluate_request(request, self._safety_ctx)
        if safety_decision.verdict == SafetyVerdict.BLOCKED:
            exchange = TransportExchange(
                request=request,
                safety_decision=safety_decision,
                probe_failed=True,
                failure_reason=f"blocked: {safety_decision.reason}",
            )
            await self._recorder.record(exchange)
            return None
        exchange = await self._transport.send(request, self._transport_ctx)
        return exchange.model_copy(update={"safety_decision": safety_decision})

    # ------------------------------------------------------------------
    # Setup / Extract
    # ------------------------------------------------------------------

    async def _run_setup_step(self, step: StepSpec, context: FlowContext) -> None:
        """Send the request and store extracted variables in *context*."""
        request = JsonRpcRequest(
            id=self._next_id(),
            method=step.method,
            params=step.params if step.params else None,
        )
        try:
            exchange = await self._send_checked(request)
        except Exception as exc:
            if not step.optional:
                raise
            return

        if exchange is None:  # blocked by the safety policy
            return

        await self._recorder.record(exchange)

        if exchange.probe_failed or exchange.response is None:
            return

        # Extract variables using JSONPath on the model_dump dict.
        # model_dump(mode='json') avoids the json.dumps/loads round-trip.
        response_dict: dict[str, Any] = exchange.response.model_dump(
            mode="json", exclude_none=True
        )
        for var_name, jsonpath_expr in step.extract.items():
            try:
                expr = jp_parse(jsonpath_expr)
                matches = [m.value for m in expr.find(response_dict)]
                # Scalar if single match, list if multiple.
                value: JsonValue = matches[0] if len(matches) == 1 else matches
                context.set(var_name, value)
            except Exception:
                # Bad JSONPath or no match — variable not set; downstream
                # steps that reference it will raise KeyError.
                pass

    # ------------------------------------------------------------------
    # Mutate
    # ------------------------------------------------------------------

    async def _run_mutate_step(
        self,
        step: StepSpec,
        matchers: list[Matcher],
        context: FlowContext,
        module_name: str,
    ) -> list[str]:
        """Expand param sets × payloads, run concurrently, collect findings.

        If ``step.payloads`` is empty (e.g. an unedited scaffold file), the
        step is silently skipped — zero probes are sent.  This is the
        intended fail-safe behaviour for scaffold-generated modules.
        """
        # If the step references ${payload} but has no payloads defined,
        # skip silently — this is the intended behaviour for unedited scaffold
        # files.  Steps that use other variables (e.g. ${uris}) without
        # ${payload} must still run even if payloads is empty.
        uses_payload_var = "payload" in step.referenced_variables()
        if uses_payload_var and not step.payloads:
            return []

        tasks: list[asyncio.Task[str | None]] = []

        # Iterate over payloads if defined; otherwise a single empty-string
        # pass is used so that steps relying only on context variables
        # (not ${payload}) still execute once.
        for payload in (step.payloads if step.payloads else [""]):
            # Populate ${payload} in context before resolving.
            context.set("payload", payload)
            try:
                param_sets = context.resolve_params(dict(step.params))
            except KeyError as exc:
                # A referenced variable has not been extracted yet.
                # Skip this payload — the setup step probably failed.
                continue

            for params in param_sets:
                tasks.append(
                    asyncio.create_task(
                        self._run_single_probe(
                            method=step.method,
                            params=params,
                            matchers=matchers,
                            module_name=module_name,
                        )
                    )
                )

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        errors = sum(1 for r in results if isinstance(r, Exception))
        if errors:  # backstop: _run_single_probe should catch its own errors
            self.failures += errors
            print(
                f"[!] {errors} probe(s) raised an unexpected error and were skipped",
                file=sys.stderr,
            )
        return [r for r in results if isinstance(r, str)]

    async def _run_single_probe(
        self,
        method: str,
        params: dict[str, Any],
        matchers: list[Matcher],
        module_name: str,
    ) -> str | None:
        """Send one probe request and promote to finding if all matchers fire."""
        request = JsonRpcRequest(
            id=self._next_id(),
            method=method,
            params=params if params else None,
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
        # HTTP failures returns probe_failed=True instead of raising. The except
        # branch above only catches raised errors, so count the returned ones too;
        # otherwise a run drowned in such failures looks clean. Safety-BLOCKED
        # exchanges return early above and never reach here.
        if exchange.probe_failed:
            self.failures += 1

        exchange = exchange.model_copy(update={"safety_decision": safety_decision})
        await self._recorder.record(exchange)

        if self._dry_run:
            await self._print_dry_run_probe(request, exchange, matchers)
            return None

        # Matcher evaluation and evidence writing can raise; a failure here must
        # not vanish (it would leave the run silently "clean"). Record a probe
        # failure and count it.
        try:
            hits = [m.name for m in matchers if m.evaluate(exchange)]
            if matchers and len(hits) == len(matchers):
                return await self._evidence.promote(
                    exchange=exchange,
                    matchers_hit=hits,
                    module=module_name,
                    transport=self._transport_label,
                    protocol_version=self._registry.protocol_version,
                    severity=self._current_severity,
                    session_id=self._transport_ctx.session_id,
                )
        except Exception as exc:
            self.failures += 1
            await self._recorder.record(TransportExchange(
                request=request,
                probe_failed=True,
                failure_reason=f"probe post-processing error: {exc}",
            ))
            return None

        return None

    async def _print_dry_run_probe(
        self,
        request: JsonRpcRequest,
        exchange: TransportExchange,
        matchers: list[Matcher],
    ) -> None:
        """Print dry-run probe output: request, response, and matcher verdicts."""
        async with self._probe_lock:
            self._probe_counter += 1
            counter = self._probe_counter

        params = request.params or {}
        method = request.method
        tool_name = params.get("name", "") if isinstance(params, dict) else ""
        label = f"{method} → {tool_name}" if tool_name else method

        req_params = params if isinstance(params, dict) else {}
        req_str = json.dumps(req_params, separators=(",", ":"))

        res_str = ""
        if exchange.probe_failed:
            res_str = f"[probe failed: {exchange.failure_reason}]"
        elif exchange.response is not None:
            result = exchange.response.model_dump(mode="json", exclude_none=True)
            # Show result or error, not the full envelope.
            inner = result.get("result") or result.get("error") or result
            res_str = json.dumps(inner, separators=(",", ":"))
        if len(res_str) > _DRY_RUN_RES_MAX:
            res_str = res_str[:_DRY_RUN_RES_MAX] + "…"

        lines = [
            f"\n[probe {counter}] {label}",
            f"  REQ: {req_str}",
            f"  RES: {res_str}",
        ]
        for m in matchers:
            hit = m.evaluate(exchange)
            verdict = "WOULD MATCH" if hit else "would NOT match"
            lines.append(f"  → {m.name}: {verdict}")

        print("\n".join(lines), file=sys.stdout, flush=True)

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    async def _run_cleanup_step(self, step: StepSpec) -> None:
        """Fire-and-forget: never raises, never records as a failure.

        Still goes through the safety policy (``_send_checked``): a cleanup step
        cannot invoke a mutating method without ``--allow-mutating``.
        """
        request = JsonRpcRequest(
            id=self._next_id(),
            method=step.method,
            params=step.params if step.params else None,
        )
        # Best-effort execution, but record every outcome so the transcript is a
        # complete audit trail (a destructive cleanup or a failed rollback must
        # not be invisible). _send_checked already records a policy-blocked
        # request (returns None); record success and transport failures here.
        try:
            exchange = await self._send_checked(request)
        except Exception as exc:
            exchange = TransportExchange(
                request=request,
                probe_failed=True,
                failure_reason=f"cleanup transport error: {exc}",
            )
        if exchange is not None:
            await self._recorder.record(exchange)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id
