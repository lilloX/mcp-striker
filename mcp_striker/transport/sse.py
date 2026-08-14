"""SseTransport — legacy HTTP+SSE transport (MCP protocol 2024-11-05).

Connection flow
---------------
1. Client opens a persistent GET to the SSE endpoint (default: /sse).
2. Server sends an 'endpoint' SSE event whose data is the POST URL
   (e.g. /messages?sessionId=abc123).
3. Client POSTs every JSON-RPC request to that URL.
4. Server sends responses back through the SSE stream as 'message' events.
   The POST response body is IGNORED.

Implementation notes
--------------------
Two separate httpx.AsyncClient instances are used:
  _sse_client  -- for the persistent GET /sse stream (stays open forever)
  _post_client -- for individual POST requests (short-lived, pooled normally)

Using a single client caused connection pool exhaustion: the GET stream
held the connection open, leaving no connections available for POSTs.

asyncio.get_running_loop() is used instead of the deprecated
asyncio.get_event_loop() to obtain the running event loop.
"""

from __future__ import annotations

import asyncio
import json

import httpx
from httpx_sse import aconnect_sse

from mcp_striker.models import (
    JsonRpcRequest,
    JsonRpcResponse,
    TransportContext,
    TransportExchange,
)
from mcp_striker.transport.base import McpTransport


# Cap on a single SSE event, so a malicious server cannot exhaust memory.
_MAX_EVENT_BYTES = 32 * 1024 * 1024  # 32 MiB


def _origin(url: str) -> tuple[str | None, str | None, int | None]:
    """Return the (scheme, host, effective-port) origin tuple for *url*."""
    parsed = httpx.URL(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return (parsed.scheme, parsed.host, port)


class SseTransportError(Exception):
    pass


class SseTransport(McpTransport):
    """Legacy HTTP+SSE MCP transport (protocol 2024-11-05)."""

    def __init__(
        self,
        base_url: str,
        timeout: float = 30.0,
        path: str = "/sse",
        extra_headers: dict[str, str] | None = None,
        verify_ssl: bool = True,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._sse_url = self._base_url + path
        self._timeout = timeout
        self._extra_headers: dict[str, str] = extra_headers or {}
        self._verify_ssl = verify_ssl

        # Two separate clients: SSE stream (GET) and message transport (POST).
        self._sse_client: httpx.AsyncClient | None = None
        self._post_client: httpx.AsyncClient | None = None

        self._message_endpoint: str | None = None
        self._endpoint_ready: asyncio.Event | None = None
        self._pending: dict[int | str, asyncio.Future] = {}
        self._sse_task: asyncio.Task | None = None

    async def connect(self) -> None:
        """Open the SSE stream and wait for the server to send the endpoint URL."""
        self._endpoint_ready = asyncio.Event()
        self._sse_client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            verify=self._verify_ssl,
        )
        self._post_client = httpx.AsyncClient(
            timeout=httpx.Timeout(self._timeout),
            verify=self._verify_ssl,
        )
        self._sse_task = asyncio.create_task(self._read_sse_stream())
        try:
            await asyncio.wait_for(
                self._endpoint_ready.wait(),
                timeout=self._timeout,
            )
        except asyncio.TimeoutError:
            self._sse_task.cancel()
            raise SseTransportError(
                f"SSE endpoint event not received within {self._timeout}s — "
                f"verify that {self._sse_url} is a valid SSE endpoint"
            )
        if self._message_endpoint is None:
            raise SseTransportError(
                "SSE stream closed without sending an endpoint event"
            )

    def _resolve_message_endpoint(self, raw: str) -> str | None:
        """Resolve a server-supplied ``endpoint`` event value.

        Uses RFC-compliant URL joining (so ``/messages``, ``messages`` and
        absolute URLs all resolve correctly). Returns ``None`` to REJECT the
        endpoint when it is not same-origin as base_url (a different
        host/scheme/port, which includes an HTTPS->HTTP downgrade): we never
        POST the request body — resource URIs, tool arguments, probe payloads —
        to a host the (untrusted) SSE server pointed us at.
        """
        endpoint = str(httpx.URL(self._base_url).join(raw.strip()))
        if _origin(endpoint) != _origin(self._base_url):
            return None
        return endpoint

    def _message_headers(self) -> dict[str, str]:
        """Headers for a POST to the (same-origin) message endpoint."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        headers.update(self._extra_headers)
        return headers

    async def send(
        self,
        request: JsonRpcRequest,
        context: TransportContext,
    ) -> TransportExchange:
        """POST request to the message endpoint and await the SSE response."""
        assert self._post_client is not None and self._message_endpoint is not None

        # Notifications (id=None) are fire-and-forget — no response expected.
        if request.id is None:
            payload = request.model_dump_json(exclude_none=True).encode()
            headers = self._message_headers()
            try:
                await self._post_client.post(
                    self._message_endpoint,
                    content=payload,
                    headers=headers,
                )
            except (httpx.TimeoutException, httpx.RequestError):
                pass
            return TransportExchange(request=request)

        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        req_id = request.id
        self._pending[req_id] = fut

        payload = request.model_dump_json(exclude_none=True).encode()
        headers = self._message_headers()

        http_status = -1
        try:
            resp = await self._post_client.post(
                self._message_endpoint,
                content=payload,
                headers=headers,
            )
            http_status = resp.status_code
            if resp.status_code not in (200, 202):
                self._pending.pop(req_id, None)
                return TransportExchange(
                    request=request,
                    probe_failed=True,
                    failure_reason=f"HTTP {resp.status_code}: {resp.reason_phrase}",
                    http_status=http_status,
                )
        except httpx.TimeoutException:
            self._pending.pop(req_id, None)
            return TransportExchange(
                request=request,
                probe_failed=True,
                failure_reason=f"HTTP POST timed out after {self._timeout}s",
            )
        except httpx.RequestError as exc:
            self._pending.pop(req_id, None)
            return TransportExchange(
                request=request,
                probe_failed=True,
                failure_reason=f"HTTP request error: {exc}",
            )

        # Wait for the SSE response correlated by request id.
        try:
            raw = await asyncio.wait_for(fut, timeout=self._timeout)
        except asyncio.TimeoutError:
            self._pending.pop(req_id, None)
            return TransportExchange(
                request=request,
                probe_failed=True,
                failure_reason=f"SSE response not received within {self._timeout}s",
                http_status=http_status,
            )

        try:
            response = JsonRpcResponse.model_validate(raw)
        except Exception as exc:
            return TransportExchange(
                request=request,
                probe_failed=True,
                failure_reason=f"Response parse error: {exc}",
                http_status=http_status,
            )

        return TransportExchange(
            request=request,
            response=response,
            http_status=http_status,
        )

    async def close(self) -> None:
        if self._sse_task and not self._sse_task.done():
            self._sse_task.cancel()
            try:
                await self._sse_task
            except (asyncio.CancelledError, Exception):
                pass
        if self._sse_client is not None:
            await self._sse_client.aclose()
            self._sse_client = None
        if self._post_client is not None:
            await self._post_client.aclose()
            self._post_client = None

    async def _read_sse_stream(self) -> None:
        assert self._sse_client is not None
        headers: dict[str, str] = {
            "Accept": "text/event-stream",
            "Cache-Control": "no-cache",
        }
        headers.update(self._extra_headers)
        try:
            async with aconnect_sse(
                self._sse_client, "GET", self._sse_url, headers=headers,
            ) as event_source:
                async for event in event_source.aiter_sse():
                    if event.event == "endpoint":
                        resolved = self._resolve_message_endpoint(event.data)
                        if resolved is None:
                            # Rejected (HTTPS->HTTP downgrade) — fail safe.
                            continue
                        self._message_endpoint = resolved
                        if self._endpoint_ready is not None:
                            self._endpoint_ready.set()
                    elif event.event == "message":
                        if len(event.data) > _MAX_EVENT_BYTES:
                            continue  # drop an oversized event (DoS guard)
                        try:
                            data = json.loads(event.data)
                        except json.JSONDecodeError:
                            continue
                        req_id = data.get("id")
                        if req_id is not None and req_id in self._pending:
                            fut = self._pending.pop(req_id)
                            if not fut.done():
                                fut.set_result(data)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            if self._endpoint_ready is not None and not self._endpoint_ready.is_set():
                self._endpoint_ready.set()
            for fut in list(self._pending.values()):
                if not fut.done():
                    fut.set_exception(exc)
            self._pending.clear()
