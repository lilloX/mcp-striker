"""Shared Pydantic v2 models.

These are the data contracts between tiers.  No tier may define its own
ad-hoc dicts for cross-tier communication.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, model_validator

# NOTE: JsonValue / JsonObject are NOT used as Pydantic field types here.
# Pydantic v2 cannot handle implicit recursive type aliases.
# The validation boundary is parse_json_value() in mcp_striker/types.py;
# by the time data reaches these models it has already been validated.
# These models are pure data holders.


# ---------------------------------------------------------------------------
# JSON-RPC primitives
# ---------------------------------------------------------------------------


class JsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str | None = None
    method: str
    params: dict[str, Any] | None = None


class JsonRpcError(BaseModel):
    code: int
    message: str
    data: Any = None


class JsonRpcResponse(BaseModel):
    jsonrpc: Literal["2.0"]
    id: int | str | None
    result: Any = None
    error: JsonRpcError | None = None

    @model_validator(mode="after")
    def _exactly_one_of_result_or_error(self) -> JsonRpcResponse:
        # JSON-RPC 2.0: a response has EITHER result OR error, never both.
        if self.result is not None and self.error is not None:
            raise ValueError("JSON-RPC response has both 'result' and 'error'")
        return self

    @property
    def is_success(self) -> bool:
        """True when the response carries a successful result.

        Requires BOTH:
        - No JSON-RPC protocol error (``response.error is None``)
        - No tool-level error (``result.isError != True``)

        MCP distinguishes two error levels:
          Protocol level: ``{"error": {"code": -32601, "message": "..."}}``
          Tool level:     ``{"result": {"content": [...], "isError": true}}``

        A tool-level error (isError=true) means the invocation reached the
        tool but the tool reported failure.  This is NOT a security finding
        — it is typically a validation error (wrong argument type, missing
        required field, etc.).  Only responses where the tool actually
        processed the input and returned data are relevant for security probes.
        """
        if self.error is not None:
            return False
        if self.result is None:
            # Neither result nor error — not a valid successful response.
            return False
        if isinstance(self.result, dict) and self.result.get("isError") is True:
            return False
        return True

    def get_text_content(self) -> str:
        """Extract text from a ``resources/read`` result (``contents`` field).

        Also handles ``tools/call`` result format (``content`` field).
        Returns an empty string for unrecognised result shapes.
        """
        if not isinstance(self.result, dict):
            return ""
        # resources/read → result.contents[*].text
        contents = self.result.get("contents")
        if isinstance(contents, list):
            parts: list[str] = []
            for item in contents:
                if isinstance(item, dict):
                    text = item.get("text", "")
                    if isinstance(text, str):
                        parts.append(text)
            if parts:
                return "\n".join(parts)
        # tools/call → result.content[*].text
        content = self.result.get("content")
        if isinstance(content, list):
            parts = []
            for item in content:
                if isinstance(item, dict):
                    text = item.get("text", "")
                    if isinstance(text, str):
                        parts.append(text)
            return "\n".join(parts)
        return ""


# ---------------------------------------------------------------------------
# Safety
# ---------------------------------------------------------------------------


class SafetyVerdict(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"


class SafetyDecision(BaseModel):
    verdict: SafetyVerdict
    reason: str


class SafetyContext(BaseModel):
    """Operator-supplied runtime flags that influence safety policy."""

    allow_mutating: bool = False


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


class TransportContext(BaseModel):
    """Session-level metadata attached to every outgoing request."""

    session_id: str
    # STDIO: shell command used to spawn the server subprocess.
    target_cmd: str = ""
    # HTTP: base URL of the MCP server (e.g. "http://localhost:8080").
    target_url: str = ""
    protocol_version: str = "2025-03-26"
    # Transport type: "stdio" | "streamable-http" | "sse"
    transport_type: str = "stdio"


class TransportExchange(BaseModel):
    """A single probe round-trip (or a blocked attempt)."""

    request: JsonRpcRequest
    response: JsonRpcResponse | None = None
    safety_decision: SafetyDecision | None = None
    # STDIO: captured stderr lines for this exchange.
    stderr_transcript: str = ""
    # HTTP: status code of the HTTP response (-1 when not applicable).
    http_status: int = -1
    # HTTP: response headers (empty dict for STDIO exchanges).
    http_response_headers: dict[str, str] = {}
    probe_failed: bool = False
    failure_reason: str = ""


# ---------------------------------------------------------------------------
# Auth-Differential
# ---------------------------------------------------------------------------


class DiffVerdict(str, Enum):
    # Both owner and attacker received is_success=True.
    # The authorization boundary is broken regardless of content similarity.
    IDOR_CONFIRMED = "idor_confirmed"
    # Owner received content; attacker was rejected (JSON-RPC error or HTTP 4xx).
    CORRECTLY_DENIED = "correctly_denied"
    # Owner also received an error — fixture may be wrong, or resource does
    # not exist.  Cannot draw a conclusion.
    INCONCLUSIVE = "inconclusive"


class DiffResult(BaseModel):
    """Result of a single two-pass differential probe."""

    verdict: DiffVerdict
    resource_uri: str
    owner_name: str
    attacker_name: str
    owner_exchange: TransportExchange
    attacker_exchange: TransportExchange
    # 0.0–1.0 text similarity between the two responses.
    # Informational only — does NOT gate the verdict.
    # >= 0.8 → data_leaked flag is set in the finding artifact.
    similarity_score: float = 0.0
