"""ToolClassifier — heuristic safety classification of MCP tools.

Classification is based on tool name and description patterns.  The classifier
is deliberately conservative: anything that is not clearly read-only is either
``MUTATING`` or ``UNKNOWN``, and both are blocked by ``SafetyPolicyEngine``
unless the operator passes ``--allow-mutating``.

This is not a perfect classifier — tool authors can choose any name they like.
Its purpose is to make the common case safe by default, not to replace human
judgement.  Operators who understand their target server can always override
with ``--allow-mutating``.
"""

from __future__ import annotations

import re
from enum import Enum


class ToolClassification(str, Enum):
    # Clearly read-only by name/description; safe to probe without operator opt-in.
    READ_ONLY = "read_only"
    # Clearly mutating (writes, deletes, executes); requires --allow-mutating.
    MUTATING = "mutating"
    # Cannot be determined from name/description alone; blocked by default.
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Pattern sets (applied to the lowercased tool name)
# ---------------------------------------------------------------------------

_READ_ONLY_PATTERNS = re.compile(
    r"""
    ^(
        read | get | list | search | find | fetch | show | view |
        describe | inspect | info | stat | check | look | browse |
        query | select | scan | peek | examine | analyze | analyse |
        count | summarize | summarise | diff | compare | preview
    )
    [_\-]?          # optional separator
    """,
    re.VERBOSE,
)

_MUTATING_VERBS = (
    "write", "create", "insert", "add", "put", "post", "upload",
    "delete", "remove", "drop", "truncate", "purge", "clear", "reset",
    "edit", "update", "modify", "patch", "change", "set", "replace",
    "execute", "exec", "run", "shell", "bash", "cmd", "spawn", "invoke",
    "move", "rename", "copy", "clone", "fork", "merge", "commit", "push",
)

_MUTATING_PATTERNS = re.compile(
    r"^(" + "|".join(_MUTATING_VERBS) + r")[_\-]?",
    re.VERBOSE,
)

# Same verbs as a token set, to catch a mutating verb anywhere inside a
# compound name (e.g. "read_and_delete", "get_or_create") rather than only as
# a prefix. This closes the bypass where a read-prefixed name hides a mutating
# operation.
_MUTATING_WORDS = frozenset(_MUTATING_VERBS)

# Strong mutating signals in a tool description (fallback when the name alone
# is ambiguous).
_MUTATING_KEYWORDS = (
    "write", "create", "delete", "remove", "execute",
    "run", "modify", "update", "edit", "overwrite",
)


class ToolClassifier:
    """Classifies an MCP tool as READ_ONLY, MUTATING, or UNKNOWN."""

    def classify(self, name: str, description: str = "") -> ToolClassification:
        """Return the classification for a tool with *name* and *description*.

        Mutating signals take precedence over a read-only prefix: a compound
        name such as ``read_and_delete`` (or a read-named tool whose
        description says it deletes) must NOT be classified read-only, or it
        would run without ``--allow-mutating``.
        """
        low = name.lower().strip()
        desc_low = description.lower()

        # 1. A mutating verb as a prefix (write_*, delete_*, …).
        if _MUTATING_PATTERNS.match(low):
            return ToolClassification.MUTATING

        # 2. A mutating verb as any token in a compound name.
        tokens = {tok for tok in re.split(r"[^a-z0-9]+", low) if tok}
        if tokens & _MUTATING_WORDS:
            return ToolClassification.MUTATING

        # 3. A strong mutating keyword in the description.
        if desc_low and any(kw in desc_low for kw in _MUTATING_KEYWORDS):
            return ToolClassification.MUTATING

        # 4. Only now is a read-only prefix trusted.
        if _READ_ONLY_PATTERNS.match(low):
            return ToolClassification.READ_ONLY

        return ToolClassification.UNKNOWN
