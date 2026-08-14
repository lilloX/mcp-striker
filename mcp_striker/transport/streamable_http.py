"""Streamable HTTP transport for MCP servers exposed over HTTP.

Spec reference: MCP 2025-03-26 — Streamable HTTP transport.

Key behaviours implemented
--------------------------
* Every request is a POST to ``{base_url}/mcp``.
* The ``MCP-Protocol-Version`` header is sent on every request.
* After ``initialize``, the server returns a ``MCP-Session-Id`` header that
  **must** be injected into all subsequent requests.
* Responses can be either ``application/json`` (single response) or
  ``text/event-stream`` (SSE stream).  Both cases are handled; only the
  first ``message`` event of an SSE stream is consumed per request.
* The ``Origin`` header is configurable so transport probes can test
  CORS / DNS-rebinding protection by sending a hostile origin.

Error handling
--------------
Transport errors raise ``TransportConnectionError`` immediately (fail fast).
Timeouts and HTTP-level errors are surfaced via ``TransportExchange.probe_failed``.
"""

from __future__ import annotations

import httpx

from mcp_striker.models import (
    JsonRpcRequest,
    JsonRpcResponse,
    TransportContext,
    TransportExchange,
)
from mcp_striker.transport.base import McpTransport
from mcp_striker.transport.stdio import TransportConnectionError  # reuse same exception
from mcp_striker.types import parse_json_value

_DEFAULT_TIMEOUT = 30.0
_MCP_PATH = "/mcp"
_MAX_REDIRECTS = 10
# Cap on a single response body / SSE event, so a malicious server cannot
# exhaust the assessment host's memory with an unbounded response.
_MAX_RESPONSE_BYTES = 32 * 1024 * 1024  # 32 MiB

# On a cross-origin redirect, ONLY these protocol-safe headers are re-sent.
# Every operator-supplied header — Authorization, Cookie, MCP-Session-Id, and
# any custom credential header such as X-API-Key / X-Auth-Token — is dropped, so
# credentials are never forwarded to a host the (untrusted) target redirected
# to. Allowlist (not denylist) so unknown custom headers fail safe. Compared
# case-insensitively.
_CROSS_ORIGIN_ALLOWED_HEADERS: frozenset[str] = frozenset(
    {"content-type", "accept", "mcp-protocol-version"}
)


def _origin(url: str) -> tuple[str | None, str | None, int | None]:
    """Return the (scheme, host, effective-port) origin tuple for *url*."""
    parsed = httpx.URL(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return (parsed.scheme, parsed.host, port)


class StreamableHttpTransport(McpTransport):
    """MCP transport over Streamable HTTP (POST + optional SSE)."""

    def __init__(
        self,
        base_url: str,
        timeout: float = _DEFAULT_TIMEOUT,
        origin: str | None = None,
        extra_headers: dict[str, str] | None = None,
        verify_ssl: bool = True,
        path: str | None = None,
    ) -> None:
        """
        Args:
            base_url:      Base URL of the MCP server, e.g. ``http://localhost:8080``.
            timeout:       Per-request timeout in seconds.
            origin:        Value for the ``Origin`` header.  When ``None`` the
                           header is omitted.  Pass a hostile value for CORS probes.
            extra_headers: Additional headers merged into every request.
            verify_ssl:    Verify TLS certificates.  Set to ``False`` for targets
                           with self-signed or mismatched certificates.
            path:          Override the default MCP endpoint path (default: ``/mcp``).
                           Use when the server exposes MCP at a different path, e.g.
                           ``/``, ``/sse``, ``/api/mcp``.
        """
        self._base_url = base_url.rstrip("/")
        self._endpoint = self._base_url + (path or _MCP_PATH)
        self._timeout = timeout
        self._origin = origin
        self._extra_headers = extra_headers or {}
        self._verify_ssl = verify_ssl
        self._session_id: str | None = None
        self._client: httpx.AsyncClient | None = None
        self._current_context: TransportContext | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Create the underlying ``httpx.AsyncClient``."""
        self._client = httpx.AsyncClient(timeout=self._timeout, verify=self._verify_ssl)

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
            self._session_id = None

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    async def send(
        self,
        request: JsonRpcRequest,
        context: TransportContext,
    ) -> TransportExchange:
        """POST *request* to the MCP endpoint and return a ``TransportExchange``.

        Handles both ``application/json`` and ``text/event-stream`` responses.
        Notifications (``id`` is ``None``) are fire-and-forget.
        """
        if self._client is None:
            raise TransportConnectionError("Transport is not connected")

        # Store context so helpers (e.g. _read_sse_response) can access it.
        self._current_context = context
        headers = self._build_headers(context)
        body = request.model_dump_json(exclude_none=True)

        try:
            url = self._endpoint
            for _hop in range(_MAX_REDIRECTS + 1):
                # Exactly ONE request per hop: we open the streaming POST and, if
                # this hop is a redirect, move to the next URL and open a fresh
                # stream. There is no throwaway pre-flight POST, so a request
                # with no redirect hits the server exactly once (a mutating
                # tool is never executed twice).
                send_headers = self._headers_for_url(url, headers)
                async with self._client.stream(
                    "POST",
                    url,
                    content=body,
                    headers=send_headers,
                ) as http_response:
                    location = http_response.headers.get("location", "")
                    if http_response.status_code in (301, 302, 307, 308) and location:
                        next_url = self._next_url(url, location)
                        # Refuse to follow a redirect that leaves the original
                        # origin (a different host/scheme/port, which includes an
                        # HTTPS->HTTP downgrade). We never replay the request
                        # body — resource URIs, tool arguments, probe payloads —
                        # to a host the (untrusted) target redirected us to.
                        if _origin(next_url) != _origin(self._endpoint):
                            return TransportExchange(
                                request=request,
                                http_status=http_response.status_code,
                                http_response_headers=dict(http_response.headers),
                                probe_failed=True,
                                failure_reason=f"refusing cross-origin redirect to {next_url}",
                            )
                        url = next_url
                        continue

                    # Capture session ID from the initialize response.
                    if request.method == "initialize" and "mcp-session-id" in http_response.headers:
                        self._session_id = http_response.headers["mcp-session-id"]

                    # Notifications: fire-and-forget, no response body expected.
                    if request.id is None:
                        return TransportExchange(
                            request=request,
                            http_status=http_response.status_code,
                            http_response_headers=dict(http_response.headers),
                        )

                    # Non-2xx (incl. a 3xx without a usable Location): record it.
                    if http_response.status_code not in (200, 202):
                        try:
                            error_body = (
                                await self._read_capped(http_response)
                            ).decode(errors="replace")
                        except ValueError:
                            error_body = "<response body too large>"
                        return TransportExchange(
                            request=request,
                            http_status=http_response.status_code,
                            http_response_headers=dict(http_response.headers),
                            probe_failed=True,
                            failure_reason=f"HTTP {http_response.status_code}: {error_body[:200]}",
                        )

                    content_type = http_response.headers.get("content-type", "")

                    try:
                        if content_type.startswith("text/event-stream"):
                            rpc_response = await self._read_sse_from_response(http_response)
                        else:
                            rpc_response = self._parse_json_response(
                                await self._read_capped(http_response)
                            )
                    except Exception as exc:
                        return TransportExchange(
                            request=request,
                            http_status=http_response.status_code,
                            http_response_headers=dict(http_response.headers),
                            probe_failed=True,
                            failure_reason=f"response parse error: {exc}",
                        )

                    # Correlate: a response id that does not match the request id
                    # cannot be trusted as this probe's answer.
                    if rpc_response.id != request.id:
                        return TransportExchange(
                            request=request,
                            http_status=http_response.status_code,
                            http_response_headers=dict(http_response.headers),
                            probe_failed=True,
                            failure_reason=(
                                f"response id {rpc_response.id!r} does not match "
                                f"request id {request.id!r}"
                            ),
                        )

                    return TransportExchange(
                        request=request,
                        response=rpc_response,
                        http_status=http_response.status_code,
                        http_response_headers=dict(http_response.headers),
                    )

            # Redirect budget exhausted without a final (non-3xx) response.
            return TransportExchange(
                request=request,
                probe_failed=True,
                failure_reason=f"too many redirects (>{_MAX_REDIRECTS})",
            )

        except httpx.TimeoutException:
            return TransportExchange(
                request=request,
                probe_failed=True,
                failure_reason=f"HTTP request timed out after {self._timeout}s",
            )
        except httpx.RequestError as exc:
            return TransportExchange(
                request=request,
                probe_failed=True,
                failure_reason=f"HTTP request error: {exc}",
            )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _headers_for_url(self, url: str, headers: dict[str, str]) -> dict[str, str]:
        """Return the headers to send to *url*.

        On a same-origin request the full header set is preserved (this is why
        we follow redirects manually instead of via httpx: it keeps custom
        headers across same-origin hops, e.g. an auth-aware API gateway). On a
        cross-origin hop, sensitive headers are stripped so the operator's
        credentials are never sent to a host the (untrusted) target redirected
        to — the same protection httpx applies by default.
        """
        if _origin(url) == _origin(self._endpoint):
            return headers
        return {
            k: v
            for k, v in headers.items()
            if k.lower() in _CROSS_ORIGIN_ALLOWED_HEADERS
        }

    @staticmethod
    def _next_url(current: str, location: str) -> str:
        """Resolve a redirect ``Location`` against the current URL.

        Uses RFC-compliant URL joining so absolute, root-relative (``/mcp``),
        path-relative (``../mcp``), and query-only references all resolve
        correctly.
        """
        return str(httpx.URL(current).join(location))

    def _build_headers(self, context: TransportContext) -> dict[str, str]:
        """Assemble the headers for a single request."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": context.protocol_version,
        }
        if self._session_id is not None:
            headers["MCP-Session-Id"] = self._session_id
        if self._origin is not None:
            headers["Origin"] = self._origin
        headers.update(self._extra_headers)
        return headers

    def _parse_json_response(self, content: bytes) -> JsonRpcResponse:
        parsed = parse_json_value(content)
        return JsonRpcResponse.model_validate(parsed)

    @staticmethod
    async def _read_capped(response: httpx.Response) -> bytes:
        """Read a streamed response body, aborting past ``_MAX_RESPONSE_BYTES``."""
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > _MAX_RESPONSE_BYTES:
                raise ValueError(
                    f"response exceeds the {_MAX_RESPONSE_BYTES}-byte limit"
                )
            chunks.append(chunk)
        return b"".join(chunks)

    async def _read_sse_from_response(
        self, http_response: httpx.Response
    ) -> JsonRpcResponse:
        """Read the first ``message`` event from an already-open SSE response stream."""
        from httpx_sse import EventSource

        async for event in EventSource(http_response).aiter_sse():
            if event.event == "message" and event.data:
                if len(event.data) > _MAX_RESPONSE_BYTES:
                    raise ValueError(
                        f"SSE event exceeds the {_MAX_RESPONSE_BYTES}-byte limit"
                    )
                return self._parse_json_response(event.data.encode())

        raise ValueError("SSE stream ended without a 'message' event")


