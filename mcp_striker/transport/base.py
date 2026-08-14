"""Abstract base class for MCP transports.

All transport implementations (``StdioTransport``, ``StreamableHttpTransport``,
…) must subclass ``McpTransport``.  The ``ProtocolClient`` and ``StrikeEngine``
accept ``McpTransport`` so they are transport-agnostic.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from mcp_striker.models import JsonRpcRequest, TransportContext, TransportExchange


class McpTransport(ABC):
    """Common interface for all MCP transport implementations."""

    @abstractmethod
    async def connect(self) -> None:
        """Establish the connection to the server."""
        ...

    @abstractmethod
    async def send(
        self,
        request: JsonRpcRequest,
        context: TransportContext,
    ) -> TransportExchange:
        """Send *request* and return the server's response as a ``TransportExchange``."""
        ...

    @abstractmethod
    async def close(self) -> None:
        """Tear down the connection and release all resources."""
        ...
