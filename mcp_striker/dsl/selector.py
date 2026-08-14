"""ModuleSelector — filters flow modules against a CapabilityRegistry.

A flow module is applicable if ALL of these conditions hold:

1. Every capability in ``requires.capabilities`` is present in the registry.
2. Every pattern in ``requires.resource_templates`` matches at least one
   URI template in the registry.
3. Every pattern in ``requires.tools`` matches at least one tool name in
   the registry (OR semantics within a single pattern string, AND across
   entries).

When a module is selected, the selector also determines the *first matching
tool* for each ``requires.tools`` entry and returns it alongside the module.
The ``FlowEngine`` injects this as the ``${matched_tool}`` system variable
in the ``FlowContext`` before running the module's steps.
"""

from __future__ import annotations

import re
from typing import Any

from mcp_striker.dsl.schema import FlowModule
from mcp_striker.registry import CapabilityRegistry

_STRUCTURAL_CAPS = {
    "resources": lambda r: bool(r.resources or r.resource_templates),
}


class ModuleSelector:
    """Selects applicable flow modules for a given ``CapabilityRegistry``."""

    def select(
        self,
        modules: list[FlowModule],
        registry: CapabilityRegistry,
    ) -> list[FlowModule]:
        selected, _ = self.select_with_report(modules, registry)
        return selected

    def select_with_report(
        self,
        modules: list[FlowModule],
        registry: CapabilityRegistry,
    ) -> tuple[list[FlowModule], list[tuple[FlowModule, str]]]:
        """Return ``(selected, skipped)`` where skipped is ``(module, reason)``."""
        selected: list[FlowModule] = []
        skipped: list[tuple[FlowModule, str]] = []

        for module in modules:
            ok, reason = self._check(module, registry)
            if ok:
                selected.append(module)
            else:
                skipped.append((module, reason))

        return selected, skipped

    def matched_tool_for(
        self,
        module: FlowModule,
        registry: CapabilityRegistry,
    ) -> str:
        """Return the first tool name that matched the first tools pattern.

        Returns an empty string if the module has no tools requirements or
        no tool matched (should not happen after a successful ``select``).
        """
        if not module.requires.tools:
            return ""
        tool_names = [t.name for t in registry.tools]
        for pattern_str in module.requires.tools:
            compiled = re.compile(pattern_str, re.IGNORECASE)
            for name in tool_names:
                if compiled.search(name):
                    return name
        return ""

    def matched_param_for(
        self,
        module: FlowModule,
        registry: CapabilityRegistry,
    ) -> str:
        """Return the first parameter name that matches ``requires.inject_into``.

        Scans the input schema of the matched tool and returns the first
        string-typed parameter whose name matches the ``inject_into`` regex.
        Returns an empty string if ``inject_into`` is not set or no parameter
        matches.
        """
        pattern_str = module.requires.inject_into
        if not pattern_str:
            return ""
        # Find the matched tool
        tool_name = self.matched_tool_for(module, registry)
        if not tool_name:
            return ""
        # Look up the tool's input schema
        tool = next((t for t in registry.tools if t.name == tool_name), None)
        if tool is None:
            return ""
        properties: dict[str, Any] = (
            (tool.input_schema or {}).get("properties") or {}
        )
        compiled = re.compile(pattern_str, re.IGNORECASE)
        for param_name, param_schema in properties.items():
            # Only inject into string-typed parameters.
            if not isinstance(param_schema, dict):
                continue
            param_type = param_schema.get("type", "")
            if param_type != "string":
                continue
            if compiled.search(param_name):
                return param_name
        # Fallback: some servers omit "type" from parameter schemas entirely.
        # Try matching by name alone so modules aren't silently skipped on
        # non-standard servers that don't declare parameter types.
        for param_name in properties:
            if compiled.search(param_name):
                return param_name
        return ""

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _check(
        self,
        module: FlowModule,
        registry: CapabilityRegistry,
    ) -> tuple[bool, str]:
        req = module.requires

        # Check capability requirements.
        for cap in req.capabilities:
            if registry.server_capabilities:
                if cap not in registry.server_capabilities:
                    return False, (
                        f"requires capability '{cap}' but server did not advertise it "
                        f"(server capabilities: {registry.server_capabilities})"
                    )
                continue
            checker = _STRUCTURAL_CAPS.get(cap)
            if checker is not None and not checker(registry):
                return False, (
                    f"requires capability '{cap}' but server does not expose it"
                )

        # Check resource template pattern requirements.
        template_uris = [t.uri_template for t in registry.resource_templates]
        for pattern in req.resource_templates:
            compiled = re.compile(pattern)
            if not any(compiled.search(uri) for uri in template_uris):
                return False, (
                    f"requires resource template matching '{pattern}' "
                    f"but none found in registry"
                )

        # Check tool name pattern requirements.
        tool_names = [t.name for t in registry.tools]
        for pattern_str in req.tools:
            compiled = re.compile(pattern_str, re.IGNORECASE)
            if not any(compiled.search(name) for name in tool_names):
                return False, (
                    f"requires a tool matching '{pattern_str}' "
                    f"but none found in registry (available: {tool_names})"
                )

        return True, ""
