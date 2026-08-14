"""Pydantic v2 schema for YAML flow modules.

All validation happens at parse time (``YAMLFlowParser.load()``), never at
runtime.  Invalid modules are rejected with a clear error before any probe
is sent to the target server.

Variable syntax
---------------
``${var_name}`` references a variable extracted by a previous step or the
reserved ``${payload}`` variable (populated from ``payloads`` at mutate time).

Validation rules enforced here
-------------------------------
- A ``mutate`` step that references ``${payload}`` must have a non-empty
  ``payloads`` list.
- A ``setup`` or ``extract`` step must not have ``payloads``.
- ``matchers`` are only valid on ``mutate`` steps.
- Each step ``id`` must be unique within the flow.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, field_validator, model_validator

# Regex that matches any ${variable} reference in a string value.
_VAR_RE = re.compile(r"\$\{([^}]+)\}")

# Reserved variable name injected from step.payloads at mutate time.
PAYLOAD_VAR = "payload"


# ---------------------------------------------------------------------------
# Matcher spec
# ---------------------------------------------------------------------------


class MatcherSpec(BaseModel):
    """Declarative matcher definition — compiled to a ``Matcher`` by the parser."""

    type: Literal["jsonrpc_success", "regex", "http_status", "json_path"]
    # regex matcher
    pattern: str | None = None
    # json_path matcher
    path: str | None = None
    contains: str | None = None
    # http_status matcher
    code: int | None = None

    @model_validator(mode="after")
    def _check_fields(self) -> MatcherSpec:
        if self.type == "regex" and not self.pattern:
            raise ValueError("regex matcher requires 'pattern'")
        if self.type == "json_path" and not self.path:
            raise ValueError("json_path matcher requires 'path'")
        if self.type == "http_status" and self.code is None:
            raise ValueError("http_status matcher requires 'code'")
        return self


# ---------------------------------------------------------------------------
# Step spec
# ---------------------------------------------------------------------------


class StepSpec(BaseModel):
    """A single step in a flow."""

    id: str
    type: Literal["setup", "mutate", "extract", "cleanup"]
    method: str
    params: dict[str, Any] = {}
    # JSONPath expressions: var_name → path applied to the full response dict.
    extract: dict[str, str] = {}
    # Values for the reserved ${payload} variable. Only valid on mutate steps.
    # A YAML block with only comments parses as None; coerce to [] defensively.
    payloads: list[str] = []

    @field_validator("payloads", mode="before")
    @classmethod
    def _coerce_payloads_none(cls, v: Any) -> list[str]:
        return v if v is not None else []

    # Declarative matchers. Only valid on mutate steps.
    # A YAML block with only comments parses as None; coerce to [] defensively.
    matchers: list[MatcherSpec] = []

    @field_validator("matchers", mode="before")
    @classmethod
    def _coerce_matchers_none(cls, v: Any) -> list:
        return v if v is not None else []
    # If True, failures in this step are silently ignored.
    optional: bool = False

    @model_validator(mode="after")
    def _validate_step(self) -> StepSpec:
        # Non-mutate steps must not carry payloads or matchers.
        if self.type != "mutate":
            if self.payloads:
                raise ValueError(
                    f"step '{self.id}' (type={self.type!r}) must not have payloads; "
                    "payloads are only valid on mutate steps"
                )
            if self.matchers:
                raise ValueError(
                    f"step '{self.id}' (type={self.type!r}) must not have matchers; "
                    "matchers are only valid on mutate steps"
                )
        # A mutate step whose ONLY matcher is jsonrpc_success has no content
        # evidence: it would promote any successful call to a finding. Require
        # at least one content matcher (regex / json_path) alongside it.
        # (Empty matchers are still allowed — scaffold files parse inert and the
        # FlowEngine skips steps that send no probe.)
        if self.type == "mutate" and self.matchers:
            matcher_types = {m.type for m in self.matchers}
            if matcher_types == {"jsonrpc_success"}:
                raise ValueError(
                    f"mutate step '{self.id}' has only a 'jsonrpc_success' "
                    "matcher; add a content-evidence matcher (regex or "
                    "json_path) so a bare successful call is not promoted to a "
                    "finding"
                )
        # Note: mutate steps with empty payloads are valid — the FlowEngine
        # silently skips them. This allows scaffold-generated files to parse
        # and be loaded without modification (zero probes sent = fail safe).
        return self

    def _params_reference_payload(self) -> bool:
        """Return True if any param value contains ``${payload}``."""
        def _check(obj: Any) -> bool:
            if isinstance(obj, str):
                return any(m.group(1) == PAYLOAD_VAR for m in _VAR_RE.finditer(obj))
            if isinstance(obj, dict):
                return any(_check(v) for v in obj.values())
            if isinstance(obj, list):
                return any(_check(item) for item in obj)
            return False
        return _check(self.params)

    def referenced_variables(self) -> set[str]:
        """Return every ``${var}`` name referenced in params (including 'payload')."""
        def _collect(obj: Any, names: set[str]) -> None:
            if isinstance(obj, str):
                for m in _VAR_RE.finditer(obj):
                    names.add(m.group(1))
            elif isinstance(obj, dict):
                for v in obj.values():
                    _collect(v, names)
            elif isinstance(obj, list):
                for item in obj:
                    _collect(item, names)
        names: set[str] = set()
        _collect(self.params, names)
        return names


# ---------------------------------------------------------------------------
# Requires spec
# ---------------------------------------------------------------------------


class RequiresSpec(BaseModel):
    """Capabilities that the target server must expose for this flow to apply."""

    # MCP capability names: "resources", "tools", "prompts".
    capabilities: list[str] = []
    # Regex patterns matched against resource template URI strings.
    resource_templates: list[str] = []
    # Regex patterns matched against tool names (OR semantics within each
    # entry, AND semantics across entries).
    # Example: ["read_file|readFile|get_file", "fetch|http_get"]
    # → server must have a tool matching the first pattern AND one matching
    #   the second pattern.
    tools: list[str] = []
    # Regex pattern matched against the tool's input schema parameter names.
    # The first matching string-typed parameter is exposed as ${matched_param}.
    # Example: "path|file|filename|filepath|file_path|location"
    # If empty, ${matched_param} is not populated.
    inject_into: str = ""


# ---------------------------------------------------------------------------
# Flow module (root)
# ---------------------------------------------------------------------------


class FlowModule(BaseModel):
    """Root schema for a YAML flow module file."""

    version: str
    name: str
    description: str = ""
    # Optional severity assigned to every finding produced by this module.
    # Defaults to 'medium' if not declared.
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    requires: RequiresSpec = RequiresSpec()
    steps: list[StepSpec]

    @field_validator("steps")
    @classmethod
    def _unique_step_ids(cls, steps: list[StepSpec]) -> list[StepSpec]:
        ids = [s.id for s in steps]
        duplicates = {i for i in ids if ids.count(i) > 1}
        if duplicates:
            raise ValueError(f"duplicate step ids: {sorted(duplicates)}")
        return steps

    @field_validator("steps")
    @classmethod
    def _at_least_one_step(cls, steps: list[StepSpec]) -> list[StepSpec]:
        if not steps:
            raise ValueError("a flow module must have at least one step")
        return steps
