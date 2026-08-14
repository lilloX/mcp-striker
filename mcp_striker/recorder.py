"""SessionRecorder — full audit trail of every probe exchange.

Every exchange is written to ``.mcp-striker/sessions/<session_id>/``
regardless of outcome (success, failure, blocked).  The recorder
intentionally writes raw data; redaction is the responsibility of
``EvidenceGenerator``.

Session directories and files are created owner-only (0700/0600) because raw
transcripts can contain target responses and operator credentials.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import TYPE_CHECKING

from mcp_striker.fsutil import restrict_dir, write_private
from mcp_striker.models import TransportExchange

if TYPE_CHECKING:
    from mcp_striker.models import DiffResult


class SessionRecorder:
    """Persists ``TransportExchange`` objects to the session directory."""

    def __init__(self, session_dir: Path) -> None:
        self._session_dir = session_dir
        self._session_dir.mkdir(parents=True, exist_ok=True)
        restrict_dir(self._session_dir)

    async def record(self, exchange: TransportExchange) -> None:
        """Write *exchange* to an individual JSON file in the session dir."""
        exchange_id = str(uuid.uuid4())
        path = self._session_dir / f"{exchange_id}.json"
        write_private(path, exchange.model_dump_json(indent=2))

    async def record_diff(self, diff_result: DiffResult) -> None:
        """Write a ``DiffResult`` to the session directory."""
        exchange_id = str(uuid.uuid4())
        path = self._session_dir / f"diff-{exchange_id}.json"
        write_private(path, diff_result.model_dump_json(indent=2))
