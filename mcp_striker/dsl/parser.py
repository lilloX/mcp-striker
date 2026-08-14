"""YAMLFlowParser — loads YAML flow modules and compiles them for the engine.

The parser is the boundary between untrusted YAML on disk and the typed
objects used by ``FlowEngine``.  It performs two passes:

1. Structural validation via Pydantic v2 (``FlowModule``).
2. Matcher compilation: ``MatcherSpec`` → runtime ``Matcher`` dataclasses
   that the engine can evaluate against ``TransportExchange`` objects.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from mcp_striker.dsl.schema import FlowModule, MatcherSpec
from mcp_striker.models import TransportExchange
from mcp_striker.modules.resource_path_traversal import Matcher


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class FlowParseError(Exception):
    """Raised when a YAML flow file is missing, malformed, or schema-invalid."""


# ---------------------------------------------------------------------------
# Matcher compilation
# ---------------------------------------------------------------------------


def _compile_matcher(spec: MatcherSpec) -> Matcher:
    """Convert a ``MatcherSpec`` into a runtime ``Matcher``."""

    if spec.type == "jsonrpc_success":
        def _fn(exchange: TransportExchange) -> bool:
            return (
                not exchange.probe_failed
                and exchange.response is not None
                and exchange.response.is_success
            )
        return Matcher(name="jsonrpc_success", fn=_fn)

    if spec.type == "regex":
        assert spec.pattern is not None
        compiled = re.compile(spec.pattern)

        def _fn(exchange: TransportExchange) -> bool:
            if exchange.response is None:
                return False
            return bool(compiled.search(exchange.response.get_text_content()))

        return Matcher(name=f"regex:{spec.pattern}", fn=_fn)

    if spec.type == "http_status":
        assert spec.code is not None
        code = spec.code

        def _fn(exchange: TransportExchange) -> bool:
            return exchange.http_status == code

        return Matcher(name=f"http_status:{code}", fn=_fn)

    if spec.type == "json_path":
        assert spec.path is not None
        from jsonpath_ng import parse as jp_parse
        expr = jp_parse(spec.path)
        contains = spec.contains

        def _fn(exchange: TransportExchange) -> bool:
            if exchange.response is None:
                return False
            # model_dump(mode='json') produces a pure dict without
            # the json.dumps/loads round-trip (Pydantic v2 optimisation).
            data: dict[str, Any] = exchange.response.model_dump(
                mode="json", exclude_none=True
            )
            matches = [m.value for m in expr.find(data)]
            if not matches:
                return False
            if contains is not None:
                return any(contains in str(v) for v in matches)
            return True

        path_label = f"json_path:{spec.path}"
        if contains:
            path_label += f":contains:{contains}"
        return Matcher(name=path_label, fn=_fn)

    raise FlowParseError(f"Unknown matcher type: {spec.type!r}")


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


class YAMLFlowParser:
    """Loads and validates YAML flow module files."""

    def load(self, path: Path) -> FlowModule:
        """Parse *path* and return a validated ``FlowModule``.

        Raises:
            FlowParseError: if the file is missing, not valid YAML, or fails
                schema validation.
        """
        try:
            raw: Any = yaml.safe_load(path.read_text())
        except FileNotFoundError as exc:
            raise FlowParseError(f"Flow module not found: {path}") from exc
        except yaml.YAMLError as exc:
            raise FlowParseError(f"YAML parse error in {path}: {exc}") from exc

        if not isinstance(raw, dict):
            raise FlowParseError(f"Flow module must be a YAML mapping, got {type(raw).__name__}")

        try:
            module = FlowModule.model_validate(raw)
        except Exception as exc:
            raise FlowParseError(
                f"Schema validation failed for {path}:\n{exc}"
            ) from exc

        return module

    def load_directory(self, directory: Path) -> list[FlowModule]:
        """Load all ``*.yaml`` and ``*.yml`` files from *directory*.

        Files that fail validation are skipped with a warning printed to
        stderr.  At least one valid module must be found.

        Raises:
            FlowParseError: if the directory does not exist or contains no
                valid modules.
        """
        import sys

        if not directory.is_dir():
            raise FlowParseError(f"Modules directory not found: {directory}")

        modules: list[FlowModule] = []
        # rglob includes subdirectories recursively.
        for path in sorted(directory.rglob("*.yaml")) + sorted(directory.rglob("*.yml")):
            try:
                modules.append(self.load(path))
            except FlowParseError as exc:
                print(f"[!] Skipping {path.name}: {exc}", file=sys.stderr)

        if not modules:
            raise FlowParseError(f"No valid flow modules found in {directory}")

        return modules

    def compile_matchers(self, module: FlowModule) -> dict[str, list[Matcher]]:
        """Return a map of step_id → compiled ``Matcher`` list.

        Only ``mutate`` steps have matchers.
        """
        result: dict[str, list[Matcher]] = {}
        for step in module.steps:
            if step.matchers:
                result[step.id] = [_compile_matcher(spec) for spec in step.matchers]
        return result
