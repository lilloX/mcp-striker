"""Safety & Policy tier.

``SafetyPolicyEngine`` is the single choke-point that decides whether a
request is allowed to leave the process.

Rules (applied in order):
1. Methods on the always-allowed list are permitted unconditionally.
2. ``tools/call`` requests are evaluated by ``ToolClassifier``:
     - ``READ_ONLY``  → allowed without any flag.
     - ``MUTATING``   → blocked unless ``--allow-mutating``.
     - ``UNKNOWN``    → blocked unless ``--allow-mutating``.
3. All other methods are blocked unless ``--allow-mutating``.
"""

from __future__ import annotations

from mcp_striker.models import (
    JsonRpcRequest,
    SafetyContext,
    SafetyDecision,
    SafetyVerdict,
)
from mcp_striker.tool_classifier import ToolClassification, ToolClassifier

# Methods that are always permitted regardless of --allow-mutating.
_ALWAYS_ALLOWED: frozenset[str] = frozenset(
    {
        "initialize",
        "notifications/initialized",
        "resources/list",
        "resources/read",
        "resources/templates/list",
        "tools/list",
        "prompts/list",
    }
)

_classifier = ToolClassifier()


class SafetyPolicyEngine:
    """Evaluates every ``JsonRpcRequest`` and returns a ``SafetyDecision``."""

    def __init__(self, tool_descriptions: dict[str, str] | None = None) -> None:
        # name → description, from the enumerated registry. Lets runtime
        # enforcement classify tools/call with the SAME description enum used,
        # so a benign name with a mutating description is not allowed as
        # read-only at call time.
        self._tool_descriptions: dict[str, str] = tool_descriptions or {}

    def evaluate_request(
        self,
        request: JsonRpcRequest,
        context: SafetyContext,
        # Optional: tool name + description for tools/call classification.
        # When omitted, the description is looked up from the registry map.
        tool_name: str = "",
        tool_description: str = "",
    ) -> SafetyDecision:
        method = request.method

        # Rule 1: always-allowed list.
        if method in _ALWAYS_ALLOWED:
            return SafetyDecision(
                verdict=SafetyVerdict.ALLOWED,
                reason=f"'{method}' is on the read-only allowlist",
            )

        # Rule 2: tools/call — classify the tool.
        if method == "tools/call":
            name = tool_name
            # Fallback: extract tool name from request params if not supplied.
            if not name and request.params:
                raw_name = request.params.get("name", "")
                if isinstance(raw_name, str):
                    name = raw_name

            # Use the enumerated description so runtime enforcement matches the
            # classification shown by `enum`.
            description = tool_description or self._tool_descriptions.get(name, "")
            classification = _classifier.classify(name, description)

            if classification == ToolClassification.READ_ONLY:
                return SafetyDecision(
                    verdict=SafetyVerdict.ALLOWED,
                    reason=(
                        f"tool '{name}' classified as read-only "
                        f"and is safe to probe without --allow-mutating"
                    ),
                )

            if context.allow_mutating:
                return SafetyDecision(
                    verdict=SafetyVerdict.ALLOWED,
                    reason=(
                        f"tool '{name}' is {classification.value} — "
                        f"allowed by --allow-mutating flag"
                    ),
                )

            return SafetyDecision(
                verdict=SafetyVerdict.BLOCKED,
                reason=(
                    f"tool '{name}' is {classification.value}. "
                    f"Pass --allow-mutating to probe mutating or unknown tools."
                ),
            )

        # Rule 3: everything else.
        if context.allow_mutating:
            return SafetyDecision(
                verdict=SafetyVerdict.ALLOWED,
                reason=f"'{method}' allowed by --allow-mutating flag",
            )

        return SafetyDecision(
            verdict=SafetyVerdict.BLOCKED,
            reason=(
                f"'{method}' is not on the read-only allowlist. "
                "Pass --allow-mutating to override."
            ),
        )
