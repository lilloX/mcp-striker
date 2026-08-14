"""EvidenceGenerator — produces versioned finding artifacts.

Redaction at write time is limited: it replaces the VALUE of a dict field whose
KEY name signals a credential (Authorization, cookie, password, *_token,
*_secret, api key, …), plus any ``extra_sensitive_keys`` from
``IdentityManager.sensitive_keys()`` (identity-YAML credentials).

IMPORTANT — findings are NOT sanitized evidence. Key-based redaction does NOT
cover:
  * secrets embedded in free text (e.g. a config/file body returned by a probe —
    exactly the material ``resource-enumeration`` is designed to discover);
  * the ``payload`` field;
  * anything in the raw session transcripts (``SessionRecorder`` records raw
    exchanges by design).

Finding and session artifacts therefore contain raw, potentially secret-bearing
evidence — that is the proof of the vulnerability. They are written owner-only
(0700/0600, see ``mcp_striker/fsutil``) and MUST be treated as confidential;
do not share them without reviewing/redacting their contents.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from mcp_striker.fsutil import restrict_dir
from mcp_striker.models import TransportExchange
from mcp_striker.types import JsonValue, parse_json_value

if TYPE_CHECKING:
    from mcp_striker.models import DiffResult

# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

# Redact a dict value whose KEY name signals a credential/secret. Matched as a
# substring (case-insensitive) so compound keys like `db_password`,
# `client_secret`, `AWS_SECRET_ACCESS_KEY`, `X-API-Key`, or `apiKey` are all
# covered. Over-redaction is the safe direction: the matcher already proves the
# finding, so redacting the live value in the on-disk artifact does not weaken
# the evidence. Note this redacts by KEY only — secrets embedded in free text
# are out of scope for this pass (see review finding #6 full remediation).
_SENSITIVE_KEY = re.compile(
    r"(?i)("
    r"authorization|www-authenticate|proxy-authorization|"
    r"cookie|"
    r"password|passwd|passphrase|"
    r"secret|"
    r"token|"
    r"api[_-]?key|"
    r"access[_-]?key|"
    r"private[_-]?key|"
    r"credential|"
    r"bearer|"
    r"session[_-]?id"
    r")"
)
_REDACTED = "[REDACTED]"


def _redact(
    value: JsonValue,
    extra_keys: frozenset[str] | None = None,
) -> JsonValue:
    """Recursively redact sensitive values in a ``JsonValue`` tree.

    Args:
        value:      The JSON tree to redact (in-place safe — returns new tree).
        extra_keys: Additional key names to redact beyond the built-in regex.
                    Case-sensitive.  Used for identity-profile credentials.
    """
    if isinstance(value, dict):
        result: dict[str, JsonValue] = {}
        for k, v in value.items():
            if _SENSITIVE_KEY.search(k):
                result[k] = _REDACTED
            elif extra_keys and k in extra_keys:
                result[k] = _REDACTED
            else:
                result[k] = _redact(v, extra_keys)
        return result
    if isinstance(value, list):
        return [_redact(item, extra_keys) for item in value]
    return value


def _exchange_to_dicts(
    exchange: TransportExchange,
    extra_keys: frozenset[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Serialise and redact the request and optional response of *exchange*.

    Returns:
        ``(redacted_request, redacted_response)``
    """
    req_parsed = parse_json_value(
        exchange.request.model_dump_json(exclude_none=True).encode()
    )
    assert isinstance(req_parsed, dict)
    clean_req = _redact(req_parsed, extra_keys)
    assert isinstance(clean_req, dict)

    clean_resp: dict[str, Any] | None = None
    if exchange.response is not None:
        resp_parsed = parse_json_value(
            exchange.response.model_dump_json(exclude_none=True).encode()
        )
        if isinstance(resp_parsed, dict):
            redacted = _redact(resp_parsed, extra_keys)
            if isinstance(redacted, dict):
                clean_resp = redacted

    return clean_req, clean_resp


# ---------------------------------------------------------------------------
# Finding schemas
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    schema_version: str = "mcp-striker.finding/v1"
    finding_id: str
    severity: str = "medium"
    session_id: str = ""
    type: str = "server_vulnerability"
    module: str
    transport: str
    protocol_version: str
    method: str
    payload: str
    probe_description: str = ""  # human-readable summary of what was injected and why it matters
    matchers_hit: list[str]
    raw_request: dict[str, Any]
    raw_response: dict[str, Any] | None = None


class DiffFinding(BaseModel):
    schema_version: str = "mcp-striker.finding/v1"
    finding_id: str
    severity: str = "medium"
    session_id: str = ""
    type: str = "auth_differential"
    module: str = "auth-diff"
    transport: str
    protocol_version: str
    resource_uri: str
    owner_name: str
    attacker_name: str
    verdict: str
    # True when similarity_score >= 0.8 — confirms actual data exfiltration.
    # False means access was granted but content may differ (still IDOR).
    data_leaked: bool
    similarity_score: float
    raw_owner_request: dict[str, Any]
    raw_owner_response: dict[str, Any] | None = None
    raw_attacker_request: dict[str, Any]
    raw_attacker_response: dict[str, Any] | None = None


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


def _extract_payload(method: str, params: dict[str, Any]) -> str:
    """Extract the human-readable probe payload from request params.

    For ``resources/read`` the payload is the ``uri`` param.
    For ``tools/call`` the payload is the first value in ``arguments``.
    Falls back to a compact JSON representation of the full params.
    """
    if method == "resources/read":
        return str(params.get("uri", ""))
    if method == "tools/call":
        arguments = params.get("arguments") or {}
        if isinstance(arguments, dict) and arguments:
            # Return "param=value" for the first argument
            for k, v in arguments.items():
                return f"{k}={v}"
    if params:
        import json as _json
        return _json.dumps(params, ensure_ascii=False)[:200]
    return ""


class EvidenceGenerator:
    """Promotes confirmed hits into versioned, redacted Finding files."""

    def __init__(self, findings_dir: Path) -> None:
        self._findings_dir = findings_dir
        self._findings_dir.mkdir(parents=True, exist_ok=True)
        restrict_dir(self._findings_dir)
        self._counter = self._scan_existing()

    def _scan_existing(self) -> int:
        max_num = 0
        for f in self._findings_dir.glob("MCPSTRIKE-*.json"):
            m = re.search(r"MCPSTRIKE-(\d+)", f.stem)
            if m:
                max_num = max(max_num, int(m.group(1)))
        return max_num

    def _next_id(self) -> str:
        self._counter += 1
        return f"MCPSTRIKE-{self._counter:03d}"

    def _write_artifact(self, build: Callable[[str], BaseModel]) -> str:
        """Reserve an id and write its artifact owner-only and race-safely.

        ``O_EXCL`` guarantees two concurrent processes cannot pick the same id
        and overwrite each other; on a collision the next id is tried.
        """
        while True:
            finding_id = self._next_id()
            path = self._findings_dir / f"{finding_id}.json"
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            except FileExistsError:
                continue
            with os.fdopen(fd, "w") as fh:
                fh.write(build(finding_id).model_dump_json(indent=2))
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return finding_id

    # ------------------------------------------------------------------
    # Path traversal / transport probe findings
    # ------------------------------------------------------------------

    async def promote(
        self,
        exchange: TransportExchange,
        matchers_hit: list[str],
        module: str,
        transport: str,
        protocol_version: str,
        severity: str = "medium",
        session_id: str = "",
        payload_hint: str | None = None,
        probe_description: str = "",
    ) -> str:
        """Write a ``Finding`` artifact and return its ID."""
        params = exchange.request.params or {}
        payload = payload_hint if payload_hint is not None else _extract_payload(exchange.request.method, params)
        clean_req, clean_resp = _exchange_to_dicts(exchange)

        return self._write_artifact(lambda finding_id: Finding(
            finding_id=finding_id,
            severity=severity,
            session_id=session_id,
            module=module,
            transport=transport,
            protocol_version=protocol_version,
            method=exchange.request.method,
            payload=payload,
            probe_description=probe_description,
            matchers_hit=matchers_hit,
            raw_request=clean_req,
            raw_response=clean_resp,
        ))

    # ------------------------------------------------------------------
    # Auth-Differential findings
    # ------------------------------------------------------------------

    async def promote_diff(
        self,
        diff_result: "DiffResult",
        extra_sensitive_keys: frozenset[str],
        transport: str,
        protocol_version: str,
        severity: str = "medium",
        session_id: str = "",
    ) -> str:
        """Write a ``DiffFinding`` artifact and return its ID.

        Both the owner and attacker exchanges are redacted using the built-in
        key patterns PLUS ``extra_sensitive_keys`` from
        ``IdentityManager.sensitive_keys()``.  This ensures that credentials
        defined in the identity YAML are never written to disk.
        """
        owner_req, owner_resp = _exchange_to_dicts(
            diff_result.owner_exchange, extra_sensitive_keys
        )
        attacker_req, attacker_resp = _exchange_to_dicts(
            diff_result.attacker_exchange, extra_sensitive_keys
        )

        return self._write_artifact(lambda finding_id: DiffFinding(
            finding_id=finding_id,
            severity=severity,
            session_id=session_id,
            transport=transport,
            protocol_version=protocol_version,
            resource_uri=diff_result.resource_uri,
            owner_name=diff_result.owner_name,
            attacker_name=diff_result.attacker_name,
            verdict=diff_result.verdict.value,
            data_leaked=diff_result.similarity_score >= 0.8,
            similarity_score=diff_result.similarity_score,
            raw_owner_request=owner_req,
            raw_owner_response=owner_resp,
            raw_attacker_request=attacker_req,
            raw_attacker_response=attacker_resp,
        ))
