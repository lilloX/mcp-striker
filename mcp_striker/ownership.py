"""Ownership fixtures for Auth-Differential probing.

An ownership file declares which MCP resources belong to which identity and
which identities must NOT be able to read them.

Example YAML
------------
::

    version: "1"
    resources:
      - uri: "resource://tenant-a/documents/secret.txt"
        owner: alice
        denied:
          - bob
      - uri: "file:///home/alice/private.key"
        owner: alice
        denied: [bob]

Each entry in ``denied`` produces one (owner, attacker) test pair in
``OwnershipRegistry.all_pairs()``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class OwnedResource(BaseModel):
    """A single resource with its owner and the identities that must be denied."""

    uri: str
    owner: str           # must match a name in IdentityManager
    denied: list[str]    # each must match a name in IdentityManager


class OwnershipFixtureFile(BaseModel):
    """Root schema for an ownership YAML file."""

    version: str
    resources: list[OwnedResource]


# ---------------------------------------------------------------------------
# OwnershipRegistry
# ---------------------------------------------------------------------------


class OwnershipError(Exception):
    """Raised when an ownership file is malformed."""


class OwnershipRegistry:
    """Loads resource ownership fixtures and enumerates test pairs."""

    def __init__(self) -> None:
        self._resources: list[OwnedResource] = []

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self, path: Path) -> None:
        """Parse *path* and register all owned resources.

        Raises:
            OwnershipError: if the file is missing, unparseable, or fails
                schema validation.
        """
        try:
            raw: Any = yaml.safe_load(path.read_text())
        except FileNotFoundError as exc:
            raise OwnershipError(f"Ownership file not found: {path}") from exc
        except yaml.YAMLError as exc:
            raise OwnershipError(f"YAML parse error in {path}: {exc}") from exc

        try:
            fixture = OwnershipFixtureFile.model_validate(raw)
        except Exception as exc:
            raise OwnershipError(
                f"Ownership fixture validation failed ({path}): {exc}"
            ) from exc

        self._resources.extend(fixture.resources)

    # ------------------------------------------------------------------
    # Test pair enumeration
    # ------------------------------------------------------------------

    def all_pairs(self) -> list[tuple[OwnedResource, str, str]]:
        """Return every (resource, owner_name, denied_name) test pair.

        Each element is ``(resource, owner_name, denied_name)`` where
        *denied_name* iterates over ``resource.denied``.
        """
        pairs: list[tuple[OwnedResource, str, str]] = []
        for resource in self._resources:
            for denied_name in resource.denied:
                pairs.append((resource, resource.owner, denied_name))
        return pairs

    @property
    def resources(self) -> list[OwnedResource]:
        return list(self._resources)
