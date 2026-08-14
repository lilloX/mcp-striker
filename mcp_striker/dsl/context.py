"""FlowContext — variable store for a single flow execution.

Variable resolution
-------------------
``resolve_params`` takes a params dict (possibly containing ``${var}``
references) and returns a list of fully-resolved param dicts.

Scalar variable:
    variables = {"target": "file:///etc/passwd"}
    params    = {"uri": "${target}"}
    → [{"uri": "file:///etc/passwd"}]         (1 dict)

List variable (from a JSONPath [*] extraction):
    variables = {"uris": ["file:///a", "file:///b"]}
    params    = {"uri": "${uris}"}
    → [{"uri": "file:///a"},                  (2 dicts — one per element)
       {"uri": "file:///b"}]

Cartesian product (multiple list variables):
    variables = {"uris": ["a", "b"], "payload": ["x", "y"]}
    params    = {"uri": "${uris}/${payload}"}
    → [{"uri": "a/x"}, {"uri": "a/y"},        (4 dicts)
       {"uri": "b/x"}, {"uri": "b/y"}]

The reserved ``${payload}`` variable is populated by ``FlowEngine`` from
``StepSpec.payloads`` before calling ``resolve_params``.
"""

from __future__ import annotations

import itertools
import json
import re
from copy import deepcopy
from typing import Any

from mcp_striker.dsl.schema import _VAR_RE
from mcp_striker.types import JsonValue

# Reserved variable populated by ModuleSelector with the first tool that
# matched the module's requires.tools pattern. Available as ${matched_tool}.
MATCHED_TOOL_VAR = "matched_tool"
# Reserved variable populated by FlowEngine with the first parameter name
# from the matched tool's input schema that matches requires.inject_into.
MATCHED_PARAM_VAR = "matched_param"

# ---------------------------------------------------------------------------
# FlowContext
# ---------------------------------------------------------------------------


class FlowContext:
    """Mutable variable store passed between steps in a flow."""

    def __init__(self) -> None:
        self._vars: dict[str, JsonValue] = {}

    def set(self, name: str, value: JsonValue) -> None:
        """Store or overwrite a variable."""
        self._vars[name] = value

    def get(self, name: str) -> JsonValue:
        """Return the value of *name*, or raise ``KeyError``."""
        return self._vars[name]

    def has(self, name: str) -> bool:
        return name in self._vars

    # ------------------------------------------------------------------
    # Param resolution
    # ------------------------------------------------------------------

    def resolve_params(self, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Return a list of fully-resolved param dicts.

        Each ``${var}`` reference is replaced with the corresponding value.
        When a variable holds a list, the output is expanded (one dict per
        list element).  Multiple list variables produce the cartesian product.

        Raises:
            KeyError: if a referenced variable has not been set.
        """
        # 1. Collect all variable names referenced in params.
        names = _collect_var_names(params)

        # 2. For each name, determine if it's a scalar or a list.
        scalars: dict[str, str] = {}
        lists: dict[str, list[str]] = {}

        for name in names:
            value = self._vars[name]  # raises KeyError if missing
            if isinstance(value, list):
                lists[name] = [json.dumps(item) if isinstance(item, (dict, list)) else str(item) for item in value]
            else:
                scalars[name] = str(value) if value is not None else ""

        # 3. Cartesian product over all list variables.
        if not lists:
            # Fast path: no lists, single substitution.
            return [_substitute_all(deepcopy(params), scalars)]

        list_names = list(lists.keys())
        list_values = [lists[n] for n in list_names]
        result: list[dict[str, Any]] = []
        for combo in itertools.product(*list_values):
            bindings = dict(scalars)
            bindings.update(dict(zip(list_names, combo)))
            result.append(_substitute_all(deepcopy(params), bindings))
        return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _collect_var_names(obj: Any) -> set[str]:
    """Return all ``${var}`` names referenced anywhere in *obj*.

    Scans both dict keys and values so that patterns like
    ``{"${matched_param}": "${payload}"}`` are correctly detected.
    """
    names: set[str] = set()
    if isinstance(obj, str):
        for m in _VAR_RE.finditer(obj):
            names.add(m.group(1))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            names.update(_collect_var_names(k))
            names.update(_collect_var_names(v))
    elif isinstance(obj, list):
        for item in obj:
            names.update(_collect_var_names(item))
    return names


def _substitute_all(obj: Any, bindings: dict[str, str]) -> Any:
    """Replace every ``${var}`` reference in *obj* with the bound value.

    Substitution applies to both values AND dictionary keys, enabling
    patterns like ``{"${matched_param}": "${payload}"}`` where the key
    itself is a variable (e.g. the injectable parameter name).
    """
    if isinstance(obj, str):
        def _replace(m: re.Match[str]) -> str:
            return bindings.get(m.group(1), m.group(0))
        return _VAR_RE.sub(_replace, obj)
    if isinstance(obj, dict):
        return {
            _substitute_all(k, bindings): _substitute_all(v, bindings)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_substitute_all(item, bindings) for item in obj]
    return obj
