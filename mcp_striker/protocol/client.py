"""ProtocolClient — MCP session lifecycle and capability enumeration.

The client is *stateful*: ``initialize()`` must be called before
``enumerate_capabilities()``.  This mirrors the MCP spec requirement that
``notifications/initialized`` is sent before any capability request.
"""

from __future__ import annotations

import sys
from typing import Any

from mcp_striker.models import JsonRpcRequest, TransportContext
from mcp_striker.registry import (
    CapabilityRegistry,
    McpResource,
    McpResourceTemplate,
    McpTool,
)
from mcp_striker.transport.base import McpTransport

_PROTOCOL_VERSION = "2025-03-26"
# MCP protocol versions this client can speak: modern Streamable HTTP and the
# legacy HTTP+SSE transport. A server that negotiates anything else is rejected.
_SUPPORTED_PROTOCOL_VERSIONS: frozenset[str] = frozenset({"2025-03-26", "2024-11-05"})
# Defensive cap on paginated */list responses (nextCursor follow).
_MAX_PAGES = 100
_CLIENT_INFO: dict[str, Any] = {"name": "mcp-striker", "version": "1.0.0"}


# ---------------------------------------------------------------------------
# Exceptions (fail-fast contract — same tier as transport)
# ---------------------------------------------------------------------------


class ProtocolError(Exception):
    """Raised when the MCP handshake or enumeration fails unrecoverably."""


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class ProtocolClient:
    """Manages MCP session lifecycle against a connected ``StdioTransport``."""

    def __init__(
        self,
        transport: McpTransport,
        context: TransportContext,
    ) -> None:
        self._transport: McpTransport = transport
        self._context = context
        self._request_id = 0
        # Populated by initialize()
        self._server_name = "unknown"
        self._server_version = "unknown"
        self._protocol_version = _PROTOCOL_VERSION
        self._server_capabilities: list[str] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def initialize(self) -> None:
        """Perform the MCP handshake.

        Sends ``initialize`` and, on success, ``notifications/initialized``.
        Stores server name/version for use by ``enumerate_capabilities``.

        Raises:
            ProtocolError: if the server rejects the handshake or the
                response cannot be understood.
        """
        request = JsonRpcRequest(
            id=self._next_id(),
            method="initialize",
            params={
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": _CLIENT_INFO,
            },
        )
        exchange = await self._transport.send(request, self._context)

        if exchange.probe_failed or exchange.response is None:
            raise ProtocolError(
                f"initialize failed: {exchange.failure_reason}"
            )
        if exchange.response.error is not None:
            raise ProtocolError(
                f"server rejected initialize: {exchange.response.error.message}"
            )

        result = exchange.response.result
        if not isinstance(result, dict):
            raise ProtocolError("initialize result is not a JSON object")

        # Negotiate protocol version: reject a version we do not support rather
        # than blindly adopting whatever the server returns.
        proto = result.get("protocolVersion", _PROTOCOL_VERSION)
        if not isinstance(proto, str):
            raise ProtocolError(
                f"initialize returned a non-string protocolVersion: {proto!r}"
            )
        if proto not in _SUPPORTED_PROTOCOL_VERSIONS:
            raise ProtocolError(
                f"server negotiated unsupported protocol version {proto!r}; "
                f"supported: {sorted(_SUPPORTED_PROTOCOL_VERSIONS)}"
            )
        self._protocol_version = proto

        # Capture advertised capabilities
        caps = result.get("capabilities", {})
        if isinstance(caps, dict):
            self._server_capabilities = [k for k in caps if isinstance(k, str)]

        # Capture server identity
        server_info = result.get("serverInfo", {})
        if isinstance(server_info, dict):
            name = server_info.get("name", "unknown")
            version = server_info.get("version", "unknown")
            if isinstance(name, str):
                self._server_name = name
            if isinstance(version, str):
                self._server_version = version

        # Complete the handshake
        notif = JsonRpcRequest(method="notifications/initialized", params={})
        await self._transport.send(notif, self._context)

    async def enumerate_capabilities(self) -> CapabilityRegistry:
        """Enumerate server capabilities and return an immutable snapshot.

        Must be called after ``initialize()``.
        """
        resources, templates = await self._list_resources()
        tools = await self._list_tools()
        return CapabilityRegistry(
            server_name=self._server_name,
            server_version=self._server_version,
            protocol_version=self._protocol_version,
            target_cmd=self._context.target_cmd,
            target_url=self._context.target_url,
            server_capabilities=list(self._server_capabilities),
            tools=tools,
            resources=resources,
            resource_templates=templates,
            target_transport=self._context.transport_type,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _list_pages(self, method: str) -> list[dict[str, Any]]:
        """Call a ``*/list`` *method* repeatedly, following ``nextCursor``, and
        return every page's ``result`` dict.

        A defensive cap (``_MAX_PAGES``) bounds pathological/looping servers.
        On any transport/protocol failure, pagination stops and the pages
        collected so far are returned.
        """
        pages: list[dict[str, Any]] = []
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _ in range(_MAX_PAGES):
            params: dict[str, Any] = {"cursor": cursor} if cursor else {}
            req = JsonRpcRequest(id=self._next_id(), method=method, params=params)
            exchange = await self._transport.send(req, self._context)
            if (
                exchange.probe_failed
                or exchange.response is None
                or exchange.response.error is not None
                or not isinstance(exchange.response.result, dict)
            ):
                print(
                    f"[!] {method}: pagination stopped after a failed/invalid "
                    f"page; enumeration may be incomplete.",
                    file=sys.stderr,
                )
                break
            pages.append(exchange.response.result)
            next_cursor = exchange.response.result.get("nextCursor")
            if not isinstance(next_cursor, str) or not next_cursor:
                break  # normal completion — no more pages
            if next_cursor in seen_cursors:
                print(
                    f"[!] {method}: server returned a repeating pagination "
                    f"cursor; stopping. Enumeration may be incomplete.",
                    file=sys.stderr,
                )
                break
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        else:
            print(
                f"[!] {method}: pagination cap ({_MAX_PAGES} pages) reached; "
                f"enumeration may be incomplete.",
                file=sys.stderr,
            )
        return pages

    async def _list_tools(self) -> list[McpTool]:
        """Call ``tools/list`` (all pages) and return the advertised tools."""
        tools: list[McpTool] = []
        for result in await self._list_pages("tools/list"):
            for item in (result.get("tools") or []):
                if not isinstance(item, dict):
                    continue
                name = item.get("name", "")
                if not isinstance(name, str) or not name:
                    continue
                description = item.get("description", "")
                input_schema = item.get("inputSchema", {})
                tools.append(McpTool(
                    name=name,
                    description=description if isinstance(description, str) else "",
                    input_schema=input_schema if isinstance(input_schema, dict) else {},
                ))
        return tools

    async def _list_resources(
        self,
    ) -> tuple[list[McpResource], list[McpResourceTemplate]]:
        """Call both ``resources/list`` and ``resources/templates/list``.

        The MCP spec defines two separate endpoints:
        - ``resources/list``           → concrete resources
        - ``resources/templates/list`` → URI templates

        Some non-standard servers (including our own fixture servers) return
        both under ``resources/list`` for convenience.  We handle both cases:
        templates found in ``resources/list`` are merged with the results of
        ``resources/templates/list`` so either convention works.
        """
        resources: list[McpResource] = []
        templates: list[McpResourceTemplate] = []

        # --- resources/list (all pages) ---
        for result in await self._list_pages("resources/list"):
            for item in (result.get("resources") or []):
                if isinstance(item, dict):
                    uri = item.get("uri", "")
                    name = item.get("name", "")
                    if isinstance(uri, str) and isinstance(name, str) and uri:
                        # Some servers return URI templates under resources/list
                        # instead of resources/templates/list (non-standard but
                        # common). Detect them by the {placeholder} syntax so
                        # ModuleSelector can match resource_templates correctly.
                        if "{" in uri:
                            templates.append(
                                McpResourceTemplate(uri_template=uri, name=name)
                            )
                        else:
                            resources.append(McpResource(uri=uri, name=name))
            # Non-standard: some servers embed templates here too.
            for item in (result.get("resourceTemplates") or []):
                if isinstance(item, dict):
                    tpl = item.get("uriTemplate", "")
                    name = item.get("name", "")
                    if isinstance(tpl, str) and isinstance(name, str) and tpl:
                        templates.append(
                            McpResourceTemplate(uri_template=tpl, name=name)
                        )

        # --- resources/templates/list (MCP spec standard endpoint, all pages) ---
        for result_t in await self._list_pages("resources/templates/list"):
            for item in (result_t.get("resourceTemplates") or []):
                if isinstance(item, dict):
                    tpl = item.get("uriTemplate", "")
                    name = item.get("name", "")
                    if isinstance(tpl, str) and isinstance(name, str) and tpl:
                        # Deduplicate: skip if already found via resources/list.
                        existing = {t.uri_template for t in templates}
                        if tpl not in existing:
                            templates.append(
                                McpResourceTemplate(uri_template=tpl, name=name)
                            )

        return resources, templates
