"""Auth-Differential Engine — detects IDOR and Tenant Breakout.

Algorithm
---------
For each (resource, owner, attacker) triple in the ownership registry:

1. Open a fresh transport authenticated as **owner**.
2. Send ``resources/read`` for the resource URI → owner_exchange.
3. Close the owner transport.
4. Open a fresh transport authenticated as **attacker**.
5. Send ``resources/read`` for the same URI → attacker_exchange.
6. Close the attacker transport.
7. Pass both exchanges to ``DiffMatcher.compare()``.
8. If verdict is ``IDOR_CONFIRMED`` → promote to a ``DiffFinding`` artifact.

Verdict logic (per refined M3 plan)
------------------------------------
* ``IDOR_CONFIRMED``   — both owner AND attacker received ``is_success=True``.
                         The authorization boundary is broken regardless of
                         content similarity.  ``similarity_score`` is an
                         informational severity flag only.
* ``CORRECTLY_DENIED`` — owner got content; attacker got a JSON-RPC error or
                         HTTP 4xx.
* ``INCONCLUSIVE``     — owner also got an error (fixture may be wrong, or
                         resource does not exist).

Concurrency
-----------
The two passes for a single resource are **sequential** (owner first, then
attacker) to avoid session cross-contamination.  Different resource pairs
run concurrently up to ``asyncio.Semaphore(concurrency)``.
"""

from __future__ import annotations

import asyncio
import difflib
import shlex
import sys

from mcp_striker.evidence import EvidenceGenerator
from mcp_striker.identity import Identity, IdentityManager
from mcp_striker.models import (
    DiffResult,
    DiffVerdict,
    JsonRpcRequest,
    TransportContext,
    TransportExchange,
)
from mcp_striker.ownership import OwnedResource, OwnershipRegistry
from mcp_striker.protocol.client import ProtocolClient
from mcp_striker.recorder import SessionRecorder
from mcp_striker.transport.base import McpTransport
from mcp_striker.transport.stdio import StdioTransport
from mcp_striker.transport.streamable_http import StreamableHttpTransport

_READ_REQUEST_ID = 10


# ---------------------------------------------------------------------------
# DiffMatcher
# ---------------------------------------------------------------------------


class DiffMatcher:
    """Compares two ``TransportExchange`` objects and produces a ``DiffResult``."""

    def compare(
        self,
        owner_exchange: TransportExchange,
        attacker_exchange: TransportExchange,
        resource_uri: str,
        owner_name: str,
        attacker_name: str,
    ) -> DiffResult:
        """Evaluate the two exchanges and return a ``DiffResult``.

        Verdict rules (applied in order, first match wins):

        1. Owner exchange failed or errored → ``INCONCLUSIVE``.
           We cannot establish a baseline; the fixture may be wrong.
        2. Both succeeded (``is_success == True``) → ``IDOR_CONFIRMED``.
           The authorization boundary is violated regardless of content.
        3. Attacker was denied (error or HTTP 4xx) → ``CORRECTLY_DENIED``.
        """
        owner_ok = self._is_success(owner_exchange)
        attacker_ok = self._is_success(attacker_exchange)

        # Rule 1: cannot establish baseline.
        if not owner_ok:
            return DiffResult(
                verdict=DiffVerdict.INCONCLUSIVE,
                resource_uri=resource_uri,
                owner_name=owner_name,
                attacker_name=attacker_name,
                owner_exchange=owner_exchange,
                attacker_exchange=attacker_exchange,
                similarity_score=0.0,
            )

        # Rule 2: IDOR — authorization boundary broken.
        if attacker_ok:
            similarity = self._similarity(owner_exchange, attacker_exchange)
            return DiffResult(
                verdict=DiffVerdict.IDOR_CONFIRMED,
                resource_uri=resource_uri,
                owner_name=owner_name,
                attacker_name=attacker_name,
                owner_exchange=owner_exchange,
                attacker_exchange=attacker_exchange,
                similarity_score=similarity,
            )

        # Rule 3: attacker was correctly denied.
        return DiffResult(
            verdict=DiffVerdict.CORRECTLY_DENIED,
            resource_uri=resource_uri,
            owner_name=owner_name,
            attacker_name=attacker_name,
            owner_exchange=owner_exchange,
            attacker_exchange=attacker_exchange,
            similarity_score=0.0,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_success(exchange: TransportExchange) -> bool:
        """True when the exchange carries a JSON-RPC success result."""
        return (
            not exchange.probe_failed
            and exchange.response is not None
            and exchange.response.is_success
            # HTTP 4xx also counts as denial even if body is empty.
            and exchange.http_status not in range(400, 500)
        )

    @staticmethod
    def _similarity(a: TransportExchange, b: TransportExchange) -> float:
        """Return a 0.0-1.0 text similarity score between the two responses."""
        text_a = a.response.get_text_content() if a.response else ""
        text_b = b.response.get_text_content() if b.response else ""
        if not text_a and not text_b:
            return 1.0
        if not text_a or not text_b:
            return 0.0
        return difflib.SequenceMatcher(None, text_a, text_b).ratio()


# ---------------------------------------------------------------------------
# AuthDiffEngine
# ---------------------------------------------------------------------------


class AuthDiffEngine:
    """Executes two-pass differential probes against an MCP server."""

    def __init__(
        self,
        identity_manager: IdentityManager,
        ownership_registry: OwnershipRegistry,
        recorder: SessionRecorder,
        evidence_generator: EvidenceGenerator,
        session_id: str,
        protocol_version: str = "2025-03-26",
        # One of the following must be provided depending on transport type.
        base_url: str = "",
        target_cmd: str = "",
        transport_type: str = "stdio",
        timeout: float = 15.0,
        concurrency: int = 3,
    ) -> None:
        self._identity_manager = identity_manager
        self._ownership_registry = ownership_registry
        self._recorder = recorder
        self._evidence = evidence_generator
        self._session_id = session_id
        self._protocol_version = protocol_version
        self._base_url = base_url
        self._target_cmd = target_cmd
        self._transport_type = transport_type
        self._timeout = timeout
        self._semaphore = asyncio.Semaphore(concurrency)
        self._diff_matcher = DiffMatcher()
        # Pairs that crashed unexpectedly. Non-zero → run is inconclusive.
        self.failures = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> list[str]:
        """Execute all differential pairs and return confirmed finding IDs."""
        pairs = self._ownership_registry.all_pairs()
        tasks = [
            asyncio.create_task(
                self._run_pair(resource, owner_name, attacker_name)
            )
            for resource, owner_name, attacker_name in pairs
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        finding_ids: list[str] = []
        errors = 0
        for result in results:
            if isinstance(result, str):
                finding_ids.append(result)
            elif isinstance(result, Exception):
                errors += 1
        if errors:
            self.failures += errors
            print(
                f"[!] {errors} auth-diff pair(s) raised an unexpected error and "
                f"were skipped",
                file=sys.stderr,
            )
        return finding_ids

    # ------------------------------------------------------------------
    # Per-pair execution
    # ------------------------------------------------------------------

    async def _run_pair(
        self,
        resource: OwnedResource,
        owner_name: str,
        attacker_name: str,
    ) -> str | None:
        owner_identity = self._identity_manager.get(owner_name)
        attacker_identity = self._identity_manager.get(attacker_name)

        async with self._semaphore:
            # Pass 1: owner baseline. Sequential on purpose — running both passes
            # concurrently under the same semaphore slot risks session
            # cross-contamination when the transport reuses connections.
            owner_exchange = await self._send_as(
                identity=owner_identity,
                uri=resource.uri,
                request_id=_READ_REQUEST_ID,
            )
            # Pass 2: attacker attempt (owner transport already closed).
            attacker_exchange = await self._send_as(
                identity=attacker_identity,
                uri=resource.uri,
                request_id=_READ_REQUEST_ID,
            )

        diff = self._diff_matcher.compare(
            owner_exchange=owner_exchange,
            attacker_exchange=attacker_exchange,
            resource_uri=resource.uri,
            owner_name=owner_name,
            attacker_name=attacker_name,
        )

        await self._recorder.record_diff(diff)

        # An INCONCLUSIVE verdict means the owner baseline itself failed (transport
        # error, or the resource does not exist) — the pair proved nothing. Count
        # it so a run that could not establish any baseline is not read as clean.
        if diff.verdict == DiffVerdict.INCONCLUSIVE:
            self.failures += 1

        if diff.verdict == DiffVerdict.IDOR_CONFIRMED:
            finding_id = await self._evidence.promote_diff(
                diff_result=diff,
                extra_sensitive_keys=self._identity_manager.sensitive_keys(),
                transport=self._transport_type,
                protocol_version=self._protocol_version,
            )
            return finding_id

        return None

    # ------------------------------------------------------------------
    # Transport helpers
    # ------------------------------------------------------------------

    def _build_transport(self, identity: Identity) -> McpTransport:
        """Return a fresh, pre-configured transport for *identity*."""
        if self._transport_type == "http":
            headers = self._identity_manager.build_http_headers(identity)
            return StreamableHttpTransport(
                base_url=self._base_url,
                timeout=self._timeout,
                extra_headers=headers,
            )
        # STDIO
        env_vars = self._identity_manager.build_env_vars(identity)
        return StdioTransport(
            cmd=shlex.split(self._target_cmd),
            timeout=self._timeout,
            extra_env=env_vars,
        )

    async def _send_as(
        self,
        identity: Identity,
        uri: str,
        request_id: int,
    ) -> TransportExchange:
        """Open a fresh transport as *identity*, send resources/read, close."""
        transport = self._build_transport(identity)
        context = TransportContext(
            session_id=self._session_id,
            target_cmd=self._target_cmd,
            target_url=self._base_url,
            protocol_version=self._protocol_version,
        )
        request = JsonRpcRequest(
            id=request_id,
            method="resources/read",
            params={"uri": uri},
        )

        try:
            await transport.connect()
            client = ProtocolClient(transport=transport, context=context)
            await client.initialize()
            exchange = await transport.send(request, context)
        except Exception as exc:
            exchange = TransportExchange(
                request=request,
                probe_failed=True,
                failure_reason=f"transport error: {exc}",
            )
        finally:
            try:
                await transport.close()
            except Exception:
                pass

        return exchange
