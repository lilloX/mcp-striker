"""Identity management for Auth-Differential probing.

An identity profile is a YAML file that declares the credentials for each
user involved in a differential test (owner and attacker).

Example YAML
------------
::

    version: "1"
    identities:
      - name: alice
        description: "Tenant A — resource owner"
        auth:
          bearer: "alice-token-secret"
      - name: bob
        description: "Tenant B — attacker"
        auth:
          bearer: "bob-token-different"
          headers:
            X-Tenant-Id: "tenant-b"
          env:
            MCP_AUTH_TOKEN: "bob-token-different"

Security note
-------------
``IdentityManager.sensitive_keys()`` returns every header / env key name
that holds a secret value.  ``EvidenceGenerator.promote_diff()`` uses this
set to redact credentials from finding artifacts before writing to disk.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class AuthConfig(BaseModel):
    """Credentials for a single identity."""

    # HTTP: injected as "Authorization: Bearer <token>"
    bearer: str | None = None
    # HTTP: arbitrary custom headers merged into every request.
    headers: dict[str, str] = {}
    # STDIO: merged into the subprocess environment after scrubbing.
    env: dict[str, str] = {}


class Identity(BaseModel):
    """A named actor used in differential probing."""

    name: str
    description: str = ""
    auth: AuthConfig = AuthConfig()


class IdentityProfileFile(BaseModel):
    """Root schema for an identities YAML file."""

    version: str
    identities: list[Identity]


# ---------------------------------------------------------------------------
# IdentityManager
# ---------------------------------------------------------------------------


class IdentityManagerError(Exception):
    """Raised when an identity file is malformed or a name is not found."""


class IdentityManager:
    """Loads identity profiles from YAML and provides auth helpers."""

    def __init__(self) -> None:
        self._identities: dict[str, Identity] = {}

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load(self, path: Path) -> None:
        """Parse *path* and register all identities.

        Raises:
            IdentityManagerError: if the file is missing, unparseable, or
                fails schema validation.
        """
        try:
            raw: Any = yaml.safe_load(path.read_text())
        except FileNotFoundError as exc:
            raise IdentityManagerError(f"Identity file not found: {path}") from exc
        except yaml.YAMLError as exc:
            raise IdentityManagerError(f"YAML parse error in {path}: {exc}") from exc

        try:
            profile = IdentityProfileFile.model_validate(raw)
        except Exception as exc:
            raise IdentityManagerError(
                f"Identity profile validation failed ({path}): {exc}"
            ) from exc

        for identity in profile.identities:
            self._identities[identity.name] = identity

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get(self, name: str) -> Identity:
        """Return the identity registered under *name*.

        Raises:
            IdentityManagerError: if *name* has not been loaded.
        """
        try:
            return self._identities[name]
        except KeyError:
            known = list(self._identities.keys())
            raise IdentityManagerError(
                f"Identity {name!r} not found. Known identities: {known}"
            )

    def all_names(self) -> list[str]:
        """Return all registered identity names."""
        return list(self._identities.keys())

    # ------------------------------------------------------------------
    # Transport auth helpers
    # ------------------------------------------------------------------

    def build_http_headers(self, identity: Identity) -> dict[str, str]:
        """Return the HTTP headers that carry this identity's credentials.

        Bearer token → ``Authorization: Bearer <token>``
        Custom headers → merged in after.
        """
        headers: dict[str, str] = {}
        if identity.auth.bearer:
            headers["Authorization"] = f"Bearer {identity.auth.bearer}"
        headers.update(identity.auth.headers)
        return headers

    def build_env_vars(self, identity: Identity) -> dict[str, str]:
        """Return the environment variables for STDIO subprocess injection."""
        return dict(identity.auth.env)

    # ------------------------------------------------------------------
    # Redaction support
    # ------------------------------------------------------------------

    def sensitive_keys(self) -> frozenset[str]:
        """Return every header / env key name that holds a secret value.

        This set is passed to ``EvidenceGenerator.promote_diff()`` so that
        credentials from the identity file are redacted from finding artifacts
        regardless of whether the key name matches the built-in regex patterns.

        The ``Authorization`` header is always included if any identity uses
        a bearer token, because it is the canonical header name produced by
        ``build_http_headers()``.
        """
        keys: set[str] = set()
        for identity in self._identities.values():
            if identity.auth.bearer:
                keys.add("Authorization")
            keys.update(identity.auth.headers.keys())
            keys.update(identity.auth.env.keys())
        return frozenset(keys)
