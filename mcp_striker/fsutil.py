"""Filesystem helpers for engagement artifacts.

Session transcripts and finding artifacts can contain raw target responses and
sensitive arguments, so they are created owner-only (0700 dirs, 0600 files).
chmod is best-effort: on filesystems that do not support POSIX modes it is a
no-op rather than an error.
"""

from __future__ import annotations

import os
from pathlib import Path


def restrict_dir(path: Path) -> None:
    """Best-effort: make *path* owner-only (0700)."""
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def write_private(path: Path, text: str) -> None:
    """Write *text* to *path* as an owner-only (0600) file."""
    path.write_text(text)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
