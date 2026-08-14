"""Unit tests for `_update_gitignore`.

Regression coverage for the bug where every per-server output directory
(`.mcp-striker/<server>/`) was appended to `.gitignore` even though the
canonical `.mcp-striker/` pattern already covers all of them, causing the file
to grow on every run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mcp_striker.cli import _update_gitignore


def _make_repo(tmp_path: Path, gitignore_text: str = "") -> Path:
    (tmp_path / ".git").mkdir()
    (tmp_path / ".gitignore").write_text(gitignore_text)
    return tmp_path


def test_skips_when_covered_by_parent_pattern(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_repo(tmp_path, ".mcp-striker/\n")
    monkeypatch.chdir(tmp_path)
    _update_gitignore(Path(".mcp-striker/test-server"))
    assert (tmp_path / ".gitignore").read_text() == ".mcp-striker/\n"


def test_appends_uncovered_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_repo(tmp_path, "venv/\n")
    monkeypatch.chdir(tmp_path)
    _update_gitignore(Path("custom-out"))
    text = (tmp_path / ".gitignore").read_text()
    assert "custom-out/" in text


def test_second_call_does_not_duplicate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_repo(tmp_path, "")
    monkeypatch.chdir(tmp_path)
    _update_gitignore(Path("out"))
    _update_gitignore(Path("out"))
    assert (tmp_path / ".gitignore").read_text().count("out/") == 1


def test_noop_when_output_dir_outside_repo(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _make_repo(tmp_path, "")
    monkeypatch.chdir(tmp_path)
    _update_gitignore(Path("/tmp"))  # absolute, not under the repo
    assert (tmp_path / ".gitignore").read_text() == ""


def test_noop_without_git_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / ".gitignore").write_text("")
    monkeypatch.chdir(tmp_path)  # no .git dir present
    _update_gitignore(Path("out"))
    assert (tmp_path / ".gitignore").read_text() == ""
