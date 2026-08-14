"""TransportProbeEngine — executes HTTP transport security probes.

Unlike ``StrikeEngine`` (which iterates over CapabilityRegistry entries),
``TransportProbeEngine`` tests the HTTP layer itself.  Each probe launches
a dedicated ``StreamableHttpTransport`` instance with specific header
overrides to simulate an attacker's request.

The engine is intentionally dumb: it constructs the right transport config
for each probe, fires a minimal ``initialize`` request, and asks the probe
whether the server's response confirms a vulnerability.
"""

from __future__ import annotations

from mcp_striker.evidence import EvidenceGenerator
from mcp_striker.models import JsonRpcRequest, TransportContext
from mcp_striker.modules.transport_probes import (
    ORIGIN_PROBE,
    PROTOCOL_VERSION_PROBE,
    SESSION_REUSE_PROBE,
    TransportProbe,
)
from mcp_striker.recorder import SessionRecorder
from mcp_striker.transport.streamable_http import StreamableHttpTransport

_HOSTILE_ORIGIN = "http://evil.attacker.example.com"
_INVALID_VERSION = "1900-01-01"
_FAKE_SESSION_ID = "00000000-0000-0000-0000-000000000000"

# Client info sent during initialize probes.
_CLIENT_INFO: dict[str, str] = {"name": "mcp-striker-probe", "version": "1.0.0"}


class TransportProbeEngine:
    """Executes transport-layer security probes against an HTTP MCP server."""

    def __init__(
        self,
        base_url: str,
        recorder: SessionRecorder,
        evidence_generator: EvidenceGenerator,
        session_id: str,
        protocol_version: str = "2025-03-26",
        timeout: float = 10.0,
        extra_headers: dict[str, str] | None = None,
        verify_ssl: bool = True,
        path: str | None = None,
    ) -> None:
        self._base_url = base_url
        self._recorder = recorder
        self._evidence = evidence_generator
        self._session_id = session_id
        self._protocol_version = protocol_version
        self._timeout = timeout
        self._extra_headers: dict[str, str] = extra_headers or {}
        self._verify_ssl = verify_ssl
        self._path = path

    def _headers_for_probe(self, overrides: dict[str, str]) -> dict[str, str]:
        """Merge operator headers while keeping probe controls authoritative."""
        overridden = {key.lower() for key in overrides}
        headers = {
            key: value
            for key, value in self._extra_headers.items()
            if key.lower() not in overridden
        }
        headers.update(overrides)
        return headers

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(self) -> list[str]:
        """Execute all transport probes and return confirmed finding IDs."""
        finding_ids: list[str] = []
        for probe, transport, request in self._probe_transport_pairs():
            finding_id = await self._run_probe(probe, transport, request)
            if finding_id:
                finding_ids.append(finding_id)
        return finding_ids

    # ------------------------------------------------------------------
    # Probe / transport pairing
    # ------------------------------------------------------------------

    def _probe_transport_pairs(
        self,
    ) -> list[tuple[TransportProbe, StreamableHttpTransport, JsonRpcRequest]]:
        """Return (probe, transport, request) triples, each configured for its probe.

        Each probe uses a specific request type chosen to exercise the target
        security control without triggering false positives on correct servers:

        * ORIGIN   — initialize with hostile Origin: a correct server rejects
                     the connection outright (403/400) regardless of method.
        * VERSION  — initialize with invalid protocolVersion in the JSON body:
                     a correct server returns a JSON-RPC error or 400.
        * SESSION  — resources/list with a fabricated MCP-Session-Id: a correct
                     server rejects 401/404 because no valid session exists.
                     Using a non-initialize method is essential — initialize does
                     not require an existing session by spec.
        """
        init_request = JsonRpcRequest(
            id=1,
            method="initialize",
            params={
                "protocolVersion": self._protocol_version,
                "capabilities": {},
                "clientInfo": _CLIENT_INFO,
            },
        )
        # Invalid version injected into the JSON body, not just the HTTP header.
        bad_version_request = JsonRpcRequest(
            id=1,
            method="initialize",
            params={
                "protocolVersion": _INVALID_VERSION,
                "capabilities": {},
                "clientInfo": _CLIENT_INFO,
            },
        )
        # Non-initialize method: requires a valid session — a fabricated one
        # must be rejected by a correct server.
        session_probe_request = JsonRpcRequest(
            id=1,
            method="resources/list",
            params={},
        )
        return [
            (
                ORIGIN_PROBE,
                StreamableHttpTransport(
                    base_url=self._base_url,
                    timeout=self._timeout,
                    path=self._path,
                    verify_ssl=self._verify_ssl,
                    extra_headers=self._headers_for_probe(
                        {"Origin": _HOSTILE_ORIGIN}
                    ),
                ),
                init_request,
            ),
            (
                PROTOCOL_VERSION_PROBE,
                StreamableHttpTransport(
                    base_url=self._base_url,
                    timeout=self._timeout,
                    path=self._path,
                    verify_ssl=self._verify_ssl,
                    extra_headers=self._headers_for_probe(
                        {"MCP-Protocol-Version": _INVALID_VERSION}
                    ),
                ),
                bad_version_request,
            ),
            (
                SESSION_REUSE_PROBE,
                StreamableHttpTransport(
                    base_url=self._base_url,
                    timeout=self._timeout,
                    path=self._path,
                    verify_ssl=self._verify_ssl,
                    extra_headers=self._headers_for_probe(
                        {"MCP-Session-Id": _FAKE_SESSION_ID}
                    ),
                ),
                session_probe_request,
            ),
        ]

    # ------------------------------------------------------------------
    # Per-probe execution
    # ------------------------------------------------------------------

    async def _run_probe(
        self,
        probe: TransportProbe,
        transport: StreamableHttpTransport,
        request: JsonRpcRequest,
    ) -> str | None:
        """Connect, fire the probe-specific request, evaluate, record, promote."""
        context = TransportContext(
            session_id=self._session_id,
            target_url=self._base_url,
            protocol_version=self._protocol_version,
        )

        try:
            await transport.connect()
            exchange = await transport.send(request, context)
        except Exception as exc:
            from mcp_striker.models import TransportExchange
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

        await self._recorder.record(exchange)

        if probe.matches(exchange):
            finding_id = await self._evidence.promote(
                exchange=exchange,
                matchers_hit=probe.matchers_hit(exchange),
                module=probe.name,
                transport="streamable-http",
                protocol_version=self._protocol_version,
                severity="medium",
                session_id=self._session_id,
                payload_hint=probe.payload_label,
                probe_description=probe.description,
            )
            return finding_id

        return None
