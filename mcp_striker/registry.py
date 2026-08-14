"""CapabilityRegistry — immutable snapshot of an MCP server's attack surface."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel


class McpTool(BaseModel):
    """An MCP tool advertised by the server in ``tools/list``."""

    name: str
    description: str = ""
    # Raw JSON Schema of the tool's input parameters (from inputSchema field).
    input_schema: dict[str, Any] = {}


class McpResource(BaseModel):
    uri: str
    name: str
    description: str = ""
    mime_type: str = ""


class McpResourceTemplate(BaseModel):
    """URI template (RFC 6570 subset) exposed by the server."""

    uri_template: str   # e.g. "file://{path}"
    name: str
    description: str = ""


class CapabilityRegistry(BaseModel):
    """Read-only snapshot produced at the end of ``mcp-striker enum``."""

    server_name: str
    server_version: str
    protocol_version: str
    target_cmd: str = ""                   # STDIO: command used to spawn the server
    target_url: str = ""                   # HTTP: base URL of the server
    # Transport type: "stdio" | "streamable-http" | "sse"
    target_transport: str = "stdio"
    # Capability names advertised by the server in the initialize result.
    # e.g. ["resources", "tools", "prompts"]
    server_capabilities: list[str] = []
    # Tools advertised by the server in tools/list.
    tools: list[McpTool] = []
    resources: list[McpResource] = []
    resource_templates: list[McpResourceTemplate] = []

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: Path) -> None:
        """Serialise to *path*, creating parent directories as needed."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2))

    @classmethod
    def load(cls, path: Path) -> CapabilityRegistry:
        """Deserialise from a JSON file previously written by ``save``."""
        return cls.model_validate_json(path.read_text())
